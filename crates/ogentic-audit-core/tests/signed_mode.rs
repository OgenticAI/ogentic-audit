//! Signed mode (format 0x0002) end to end: writer, verifier, trust,
//! checkpoints, statements, releases. Golden vectors are checked
//! separately in `signed_vectors.rs`; these tests exercise behaviour.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use ogentic_audit_core::signed::checkpoint::{self, Comparison};
use ogentic_audit_core::signed::format::{self, Frame, HEADER_LEN};
use ogentic_audit_core::signed::statements::{self, CutPoints, Head};
use ogentic_audit_core::signed::{
    unhex, verify_release, AttestationBuilder, CheckpointV2, FileSpec, Fingerprint, InMemorySigner,
    LogSpec, Part, ReleaseOptions, Scope, SignedVerifier, SignedVerifyOptions, SignedWriter,
    Signer, SuppliedCheckpoint, TrustContext,
};
use ogentic_audit_core::{PayloadValue, RecordInput, Verdict, WriterConfig, WriterError};

fn k(n: u8) -> InMemorySigner {
    let seeds = [
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5",
    ];
    InMemorySigner::from_seed(unhex(seeds[n as usize - 1]).unwrap())
}

fn input(i: u64, event: &str) -> RecordInput {
    let mut payload = BTreeMap::new();
    payload.insert("n".to_string(), PayloadValue::Uint(i));
    RecordInput {
        ts_wall: format!("2026-10-03T12:00:{:02}.000Z", i % 60),
        ts_mono_delta: i * 1000,
        actor: "user:test".into(),
        event: event.into(),
        payload,
        schema_version: 1,
    }
}

fn write_log(dir: &Path, signer: u8, n: u64, seal: bool) {
    let mut w = SignedWriter::open_signed(dir, Box::new(k(signer)), [7u8; 16]).unwrap();
    for i in 0..n {
        w.append(input(i, "page.released")).unwrap();
    }
    if seal {
        w.seal().unwrap();
    }
    w.flush().unwrap();
}

fn pin(n: u8) -> TrustContext {
    let mut t = TrustContext::new();
    t.pin_key(*k(n).public_key(), Some(&format!("k{n}")), Scope::DEFAULT)
        .unwrap();
    t
}

fn verify(dir: &Path, t: TrustContext) -> String {
    SignedVerifier::new(t)
        .verify(dir)
        .unwrap()
        .compact_verdict()
}

/// Byte ranges of each record in segment `seg`: (start, envelope, sig, body).
struct Rec {
    start: usize,
    env: (usize, usize),
    sig: usize,
    body: (usize, usize),
    end: usize,
}

fn records(path: &Path) -> Vec<Rec> {
    let bytes = std::fs::read(path).unwrap();
    let mut c = std::io::Cursor::new(&bytes);
    c.set_position(HEADER_LEN as u64);
    let mut off = HEADER_LEN as u64;
    let mut out = Vec::new();
    while let Frame::Record(r) = format::read_frame(&mut c, off, bytes.len() as u64).unwrap() {
        let s = off as usize;
        let el = r.envelope.len();
        let bl = r.body.as_ref().map_or(0, Vec::len);
        out.push(Rec {
            start: s,
            env: (s + 4, el),
            sig: s + 4 + el,
            body: (s + 4 + el + 64 + 4, bl),
            end: s + r.total_len as usize,
        });
        off += r.total_len;
    }
    out
}

fn seg(dir: &Path, n: u16) -> PathBuf {
    dir.join(format!("audit-{n:04}.cbor"))
}

fn mutate(dir: &Path, n: u16, f: impl FnOnce(&mut Vec<u8>)) {
    let p = seg(dir, n);
    let mut b = std::fs::read(&p).unwrap();
    f(&mut b);
    std::fs::write(&p, b).unwrap();
}

#[test]
fn pinned_verified_unpinned_self_consistent() {
    let d = tempfile::tempdir().unwrap();
    write_log(d.path(), 1, 3, false);
    let r = SignedVerifier::new(pin(1)).verify(d.path()).unwrap();
    assert_eq!(r.verdict, Verdict::Verified);
    assert!(!r.log.head_anchored);
    assert_eq!(verify(d.path(), TrustContext::new()), "SelfConsistent");
    // By fingerprint only.
    let mut t = TrustContext::new();
    t.pin(
        &k(1).public_key().fingerprint().to_dashed_hex(),
        None,
        Scope::DEFAULT,
    )
    .unwrap();
    assert_eq!(verify(d.path(), t), "Verified");
    // Another key.
    assert_eq!(verify(d.path(), pin(2)), "UntrustedSigner@s0");
    // Witness scope only.
    let mut t = TrustContext::new();
    t.pin_key(*k(1).public_key(), Some("w"), Scope::WITNESS)
        .unwrap();
    let r = SignedVerifier::new(t).verify(d.path()).unwrap();
    assert_eq!(r.compact_verdict(), "UntrustedSigner@s0");
    assert_eq!(r.violations[0].reason.as_deref(), Some("out_of_scope"));
}

#[test]
fn empty_log_is_not_verified() {
    let d = tempfile::tempdir().unwrap();
    write_log(d.path(), 1, 0, false);
    let r = SignedVerifier::new(pin(1)).verify(d.path()).unwrap();
    assert_eq!(r.verdict, Verdict::SelfConsistent);
    assert_eq!(r.not_verified_reason.unwrap().as_str(), "no_signed_records");
}

#[test]
fn sealed_is_anchored_and_cannot_be_extended() {
    let d = tempfile::tempdir().unwrap();
    write_log(d.path(), 1, 2, true);
    let r = SignedVerifier::new(pin(1)).verify(d.path()).unwrap();
    assert_eq!(r.verdict, Verdict::Verified);
    assert!(r.log.head_anchored && r.log.sealed);
    let e = SignedWriter::open_signed(d.path(), Box::new(k(1)), [7u8; 16]).unwrap_err();
    assert!(matches!(e, WriterError::Sealed));
}

#[test]
fn tamper_matrix() {
    type Tamper = Box<dyn Fn(&mut Vec<u8>, &[Rec])>;
    let cases: Vec<(&str, Tamper, &str)> = vec![
        (
            "envelope",
            Box::new(|b, r| b[r[2].env.0 + 5] ^= 0xff),
            "SignatureInvalid@s0r2",
        ),
        (
            "body",
            Box::new(|b, r| b[r[2].body.0 + 3] ^= 0x01),
            "SignatureInvalid@s0r2",
        ),
        (
            "signature",
            Box::new(|b, r| b[r[2].sig + 3] ^= 0x01),
            "SignatureInvalid@s0r2",
        ),
        (
            "missing",
            Box::new(|b, r| {
                b.drain(r[2].start..r[2].end);
            }),
            "ChainBreak@s0r2",
        ),
        (
            "swapped",
            Box::new(|b, r| {
                let r2 = b[r[2].start..r[2].end].to_vec();
                let r3 = b[r[3].start..r[3].end].to_vec();
                let mut tail = r3;
                tail.extend(r2);
                tail.extend_from_slice(&b[r[3].end..]);
                b.truncate(r[2].start);
                b.extend(tail);
            }),
            "ChainBreak@s0r2",
        ),
        (
            "truncated-mid-record",
            Box::new(|b, r| b.truncate(r[4].start + 10)),
            "RecordCorrupt@s0r4",
        ),
    ];
    for (name, f, expect) in cases {
        let d = tempfile::tempdir().unwrap();
        write_log(d.path(), 1, 5, false);
        let recs = records(&seg(d.path(), 0));
        mutate(d.path(), 0, |b| f(b, &recs));
        assert_eq!(verify(d.path(), pin(1)), expect, "{name}");
    }
    // Body change reason.
    let d = tempfile::tempdir().unwrap();
    write_log(d.path(), 1, 5, false);
    let recs = records(&seg(d.path(), 0));
    mutate(d.path(), 0, |b| b[recs[2].body.0 + 3] ^= 1);
    let r = SignedVerifier::new(pin(1)).verify(d.path()).unwrap();
    assert_eq!(r.violations[0].reason.as_deref(), Some("body_mismatch"));
    // Re-encoded S.
    let d = tempfile::tempdir().unwrap();
    write_log(d.path(), 1, 5, false);
    let recs = records(&seg(d.path(), 0));
    mutate(d.path(), 0, |b| {
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&b[recs[2].sig..recs[2].sig + 64]);
        let re = ogentic_audit_core::signed::ed25519::reencode_s_plus_l(&sig);
        b[recs[2].sig..recs[2].sig + 64].copy_from_slice(&re);
    });
    let r = SignedVerifier::new(pin(1)).verify(d.path()).unwrap();
    assert_eq!(r.compact_verdict(), "SignatureInvalid@s0r2");
    assert_eq!(r.violations[0].reason.as_deref(), Some("reencoded"));
}

#[test]
fn elided_bodies_still_verify() {
    let d = tempfile::tempdir().unwrap();
    write_log(d.path(), 1, 5, false);
    let recs = records(&seg(d.path(), 0));
    mutate(d.path(), 0, |b| {
        // Elide r3 then r1 (back to front keeps offsets valid).
        for i in [3usize, 1] {
            let r = &recs[i];
            let (bo, bl) = r.body;
            b.drain(bo..bo + bl);
            b[bo - 4..bo].copy_from_slice(&0u32.to_le_bytes());
        }
    });
    let r = SignedVerifier::new(pin(1)).verify(d.path()).unwrap();
    assert_eq!(r.verdict, Verdict::Verified, "{}", r.compact_verdict());
    assert_eq!(r.log.elided_records, vec![(0, 1), (0, 3)]);
}

#[test]
fn rollover_and_recovery() {
    let d = tempfile::tempdir().unwrap();
    let cfg = WriterConfig {
        segment_size_bytes: 1024,
        ..WriterConfig::default()
    };
    {
        let mut w =
            SignedWriter::open_signed_with_config(d.path(), Box::new(k(1)), [1; 16], cfg.clone())
                .unwrap();
        for i in 0..12 {
            w.append(input(i, "page.released")).unwrap();
        }
        w.flush().unwrap();
        assert!(w.segment_index() >= 2);
    }
    assert_eq!(verify(d.path(), pin(1)), "Verified");
    // Torn tail is repaired on reopen, then appends continue.
    let last = (0..100u16)
        .rev()
        .find(|i| seg(d.path(), *i).exists())
        .unwrap();
    mutate(d.path(), last, |b| b.extend_from_slice(&[1, 2, 3]));
    assert_eq!(
        verify(d.path(), pin(1)),
        format!(
            "RecordCorrupt@s{last}r{}",
            records(&seg(d.path(), last)).len()
        )
    );
    {
        let mut w =
            SignedWriter::open_signed_with_config(d.path(), Box::new(k(1)), [1; 16], cfg).unwrap();
        assert_eq!(
            w.recovery_report().truncated_bytes,
            3,
            "{:?} last={last}",
            w.recovery_report()
        );
        w.append(input(50, "page.released")).unwrap();
        w.flush().unwrap();
    }
    assert_eq!(verify(d.path(), pin(1)), "Verified");
    // A different key refuses to resume.
    assert!(SignedWriter::open_signed(d.path(), Box::new(k(2)), [1; 16]).is_err());
    // Middle segment removed.
    std::fs::remove_file(seg(d.path(), 1)).unwrap();
    assert_eq!(verify(d.path(), pin(1)), "SegmentDiscontinuity@s1");
}

#[test]
fn hmac_log_is_refused() {
    let d = tempfile::tempdir().unwrap();
    {
        let mut w = ogentic_audit_core::Writer::open(
            d.path(),
            Box::new(ogentic_audit_core::InMemoryKey::from_bytes([3u8; 32])),
            [0; 16],
        )
        .unwrap();
        w.append(input(0, "x.y")).unwrap();
        w.flush().unwrap();
    }
    let e = SignedVerifier::new(pin(1)).verify(d.path()).unwrap_err();
    assert_eq!(e.exit_code(), 3);
    assert!(matches!(
        SignedWriter::open_signed(d.path(), Box::new(k(1)), [0; 16]),
        Err(WriterError::FormatMismatch { found: 1 })
    ));
}

fn make_checkpoint(dir: &Path, signer: Option<&InMemorySigner>) -> SuppliedCheckpoint {
    let r = SignedVerifier::new(TrustContext::new())
        .verify(dir)
        .unwrap();
    let (s, rid) = r.log.head.unwrap();
    let cp = CheckpointV2 {
        alg: ogentic_audit_core::signed::SigAlg::Ed25519,
        key_id: r.log.key_id.unwrap(),
        head: Head {
            log_id: r.log.log_id.unwrap(),
            segment: s,
            record_id: rid,
            record_count: r.log.records_inspected,
            record_hash: r.log.final_record_hash.unwrap(),
        },
        head_ts_wall: r.log.head_ts_wall.clone().unwrap(),
        observed_at: Some("2026-10-03T13:00:00.000Z".into()),
    };
    let bytes = cp.to_bytes();
    let sig = signer.map(|s| CheckpointV2::sign(&bytes, s).unwrap().into_bytes());
    SuppliedCheckpoint {
        bytes,
        sig,
        witnesses: vec![],
    }
}

#[test]
fn checkpoints() {
    let d = tempfile::tempdir().unwrap();
    write_log(d.path(), 1, 5, false);
    let cp = make_checkpoint(d.path(), Some(&k(1)));
    let opts = || SignedVerifyOptions::new().checkpoint(cp.clone());
    let r = SignedVerifier::new(pin(1))
        .verify_with_options(d.path(), opts())
        .unwrap();
    assert_eq!(r.compact_verdict(), "Verified");
    assert!(r.log.head_anchored);

    // Witness.
    let (wb, ws) = checkpoint::cosign(&cp.bytes, &k(3), "2026-10-03T13:05:00.000Z").unwrap();
    let mut cpw = cp.clone();
    cpw.witnesses.push((wb, ws.into_bytes()));
    let mut t = pin(1);
    t.pin_key(*k(3).public_key(), Some("auditor"), Scope::WITNESS)
        .unwrap();
    let r = SignedVerifier::new(t)
        .verify_with_options(d.path(), SignedVerifyOptions::new().checkpoint(cpw))
        .unwrap();
    assert_eq!(r.checkpoints[0].witnesses[0].principal, "auditor");

    // Truncation.
    let recs = records(&seg(d.path(), 0));
    mutate(d.path(), 0, |b| b.truncate(recs[3].start));
    let r = SignedVerifier::new(pin(1))
        .verify_with_options(d.path(), opts())
        .unwrap();
    assert_eq!(r.compact_verdict(), "CheckpointTruncated@s0r4");

    // Untrusted checkpoint signer is an error.
    let d2 = tempfile::tempdir().unwrap();
    write_log(d2.path(), 1, 5, false);
    let bad = make_checkpoint(d2.path(), None);
    let mut bad_signed = bad.clone();
    bad_signed.sig = Some(CheckpointV2::sign(&bad.bytes, &k(2)).unwrap().into_bytes());
    let e = SignedVerifier::new(pin(1))
        .verify_with_options(d2.path(), SignedVerifyOptions::new().checkpoint(bad_signed))
        .unwrap_err();
    assert_eq!(e.exit_code(), 3);

    // Same key, other log: finding.
    let d3 = tempfile::tempdir().unwrap();
    write_log(d3.path(), 1, 5, false);
    let other = make_checkpoint(d3.path(), Some(&k(1)));
    let r = SignedVerifier::new(pin(1))
        .verify_with_options(d2.path(), SignedVerifyOptions::new().checkpoint(other))
        .unwrap();
    assert_eq!(r.compact_verdict(), "CheckpointForDifferentLog@s0");

    // Equivocation proof.
    let a = make_checkpoint(d2.path(), Some(&k(1)));
    let mut cp_b = CheckpointV2::parse(&a.bytes).unwrap();
    cp_b.head.record_hash = [9u8; 32];
    let b_bytes = cp_b.to_bytes();
    let b_sig = CheckpointV2::sign(&b_bytes, &k(1)).unwrap();
    assert!(matches!(
        checkpoint::compare(
            &a.bytes,
            a.sig.as_ref().unwrap(),
            &b_bytes,
            b_sig.as_bytes()
        )
        .unwrap(),
        Comparison::Equivocation { .. }
    ));
}

fn head_of(dir: &Path) -> Head {
    let r = SignedVerifier::new(TrustContext::new())
        .verify(dir)
        .unwrap();
    let (s, rid) = r.log.head.unwrap();
    Head {
        log_id: r.log.log_id.unwrap(),
        segment: s,
        record_id: rid,
        record_count: r.log.records_inspected,
        record_hash: r.log.final_record_hash.unwrap(),
    }
}

fn write_statement(dir: &Path, name: &str, s: &statements::SignedStatement) -> PathBuf {
    s.write(dir, name).unwrap();
    dir.join(format!("{name}.json"))
}

#[test]
fn transitions_retire_and_extend() {
    let old_log = tempfile::tempdir().unwrap();
    write_log(old_log.path(), 1, 3, true);
    let new_log = tempfile::tempdir().unwrap();
    write_log(new_log.path(), 2, 3, false);
    let st = tempfile::tempdir().unwrap();
    let t = statements::transition(
        &k(1),
        &k(2),
        &[head_of(old_log.path())],
        &[],
        "2027-01-15T09:00:00.000Z",
        Some("scheduled"),
    )
    .unwrap();
    write_statement(st.path(), "k1-to-k2", &t);

    let with = || {
        let mut c = pin(1);
        c.add_statements(st.path(), true).unwrap();
        c
    };
    let r = SignedVerifier::new(with()).verify(new_log.path()).unwrap();
    assert_eq!(r.compact_verdict(), "Verified");
    assert_eq!(r.signer.as_ref().unwrap().trust_path.len(), 2);
    assert_eq!(verify(old_log.path(), with()), "Verified");
    // A new log by the retired key.
    let late = tempfile::tempdir().unwrap();
    write_log(late.path(), 1, 2, false);
    assert_eq!(verify(late.path(), with()), "RetiredKey@s0r0");
    // Without the acceptance the transition is invalid (operator: error).
    std::fs::remove_file(st.path().join("k1-to-k2.json.accept.sig")).unwrap();
    let mut c = pin(1);
    assert!(c.add_statements(st.path(), true).is_err());
    // Found in a bundle: ignored with a warning.
    let mut c = pin(1);
    c.add_statements(st.path(), false).unwrap();
    assert_eq!(c.warnings().len(), 1);
    assert_eq!(verify(new_log.path(), c), "UntrustedSigner@s0");
}

#[test]
fn transition_equivocation_follows_neither() {
    let log = tempfile::tempdir().unwrap();
    write_log(log.path(), 2, 2, false);
    let st = tempfile::tempdir().unwrap();
    write_statement(
        st.path(),
        "a",
        &statements::transition(&k(1), &k(2), &[], &[], "2027-01-15T09:00:00.000Z", None).unwrap(),
    );
    write_statement(
        st.path(),
        "b",
        &statements::transition(&k(1), &k(3), &[], &[], "2027-01-15T09:00:00.000Z", None).unwrap(),
    );
    let mut c = pin(1);
    c.add_statements(st.path(), true).unwrap();
    let r = SignedVerifier::new(c).verify(log.path()).unwrap();
    assert_eq!(
        r.compact_verdict(),
        format!(
            "TransitionEquivocation@key:{}",
            k(1).public_key().fingerprint().to_hex()
        )
    );
    // Neither successor is trusted.
    assert!(r
        .violations
        .iter()
        .any(|v| v.compact() == "UntrustedSigner@s0"));
}

#[test]
fn stranger_signed_statement_is_rejected() {
    // K3 signs a transition claiming old_key_id = K1.
    let st = tempfile::tempdir().unwrap();
    let json = statements::transition_json(
        k(1).public_key(),
        k(2).public_key(),
        &[],
        &[],
        "2027-01-15T09:00:00.000Z",
        None,
    );
    let sig = ogentic_audit_core::signed::signer::sign_detached(
        &k(3),
        ogentic_audit_core::signed::NS_TRANSITION,
        &json,
    )
    .unwrap();
    let acc = statements::accept(&k(2), &json).unwrap();
    let s = statements::SignedStatement {
        json,
        sig,
        accept_sig: Some(acc),
    };
    let p = write_statement(st.path(), "forged", &s);
    let mut c = pin(1);
    assert!(c.add_statement_file(&p, true).is_err());
}

#[test]
fn revocations() {
    let log = tempfile::tempdir().unwrap();
    write_log(log.path(), 2, 8, false);
    // K2 pinned as principal "ops"; K1 pinned as the same principal with revocation scope.
    let trust = || {
        let mut t = TrustContext::new();
        t.pin_key(*k(2).public_key(), Some("ops"), Scope::DEFAULT)
            .unwrap();
        t.pin_key(*k(1).public_key(), Some("ops"), Scope::REVOCATION_ONLY)
            .unwrap();
        t
    };
    // Head at r4.
    // The r4 head, from a 5-record copy.
    let cut_head = {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::copy(seg(log.path(), 0), seg(tmp.path(), 0)).unwrap();
        let recs = records(&seg(tmp.path(), 0));
        mutate(tmp.path(), 0, |b| b.truncate(recs[5].start));
        head_of(tmp.path())
    };
    assert_eq!((cut_head.segment, cut_head.record_id), (0, 4));
    let st = tempfile::tempdir().unwrap();
    let cut = CutPoints {
        trusted_heads: vec![cut_head],
        ..CutPoints::default()
    };
    let rev = statements::revocation(
        &k(1),
        &k(2).public_key().fingerprint(),
        &cut,
        "2027-02-01T00:00:00.000Z",
        Some("compromised"),
    )
    .unwrap();
    let p = write_statement(st.path(), "rev", &rev);
    let mut t = trust();
    t.add_revocation(&p).unwrap();
    assert_eq!(verify(log.path(), t), "RevokedKey@s0r5");

    // Self-revocation ignores lists.
    let st2 = tempfile::tempdir().unwrap();
    let selfrev = statements::revocation(
        &k(2),
        &k(2).public_key().fingerprint(),
        &cut,
        "2027-02-01T00:00:00.000Z",
        None,
    )
    .unwrap();
    let p2 = write_statement(st2.path(), "self", &selfrev);
    let mut t = trust();
    t.add_revocation(&p2).unwrap();
    assert_eq!(verify(log.path(), t), "RevokedKey@s0r0");
    // Both: the authority's cut points apply, either order.
    for order in [[&p, &p2], [&p2, &p]] {
        let mut t = trust();
        for q in order {
            t.add_revocation(q).unwrap();
        }
        assert_eq!(verify(log.path(), t), "RevokedKey@s0r5");
    }
    // A stranger (K3) claiming to be K1: rejected.
    let json = statements::revocation_json(
        k(1).public_key(),
        &k(2).public_key().fingerprint(),
        &cut,
        "2027-02-01T00:00:00.000Z",
        None,
    );
    let sig = ogentic_audit_core::signed::signer::sign_detached(
        &k(3),
        ogentic_audit_core::signed::NS_REVOCATION,
        &json,
    )
    .unwrap();
    let st3 = tempfile::tempdir().unwrap();
    let p3 = write_statement(
        st3.path(),
        "forged",
        &statements::SignedStatement {
            json,
            sig,
            accept_sig: None,
        },
    );
    assert!(trust().add_revocation(&p3).is_err());
    // A witness-scoped key has no authority: argument error at evaluation.
    let mut t = TrustContext::new();
    t.pin_key(*k(2).public_key(), Some("ops"), Scope::DEFAULT)
        .unwrap();
    t.pin_key(*k(3).public_key(), Some("ops"), Scope::WITNESS)
        .unwrap();
    let wrev = statements::revocation(
        &k(3),
        &k(2).public_key().fingerprint(),
        &CutPoints::default(),
        "2027-02-01T00:00:00.000Z",
        None,
    )
    .unwrap();
    let st4 = tempfile::tempdir().unwrap();
    let p4 = write_statement(st4.path(), "w", &wrev);
    t.add_revocation(&p4).unwrap();
    assert!(SignedVerifier::new(t).verify(log.path()).is_err());
}

fn build_release(signer: &InMemorySigner) -> (tempfile::TempDir, tempfile::TempDir) {
    let log = tempfile::tempdir().unwrap();
    write_log(log.path(), 1, 5, true);
    let rel = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(rel.path().join("pages")).unwrap();
    std::fs::write(rel.path().join("pages/0001.pdf"), b"%PDF page one").unwrap();
    std::fs::write(rel.path().join("pages/0002.pdf"), b"%PDF page two").unwrap();
    std::fs::write(
        rel.path().join("Decisions.csv"),
        b"page,decision\n1,release\n2,withhold\n",
    )
    .unwrap();
    let mut b = AttestationBuilder::new(rel.path(), "2026-0147");
    b.created_at("2026-10-03T12:00:00.000Z");
    b.add_file(FileSpec::new("pages/0001.pdf").role("page"));
    b.add_file(FileSpec::new("pages/0002.pdf").role("page"));
    b.add_file(FileSpec::new("Decisions.csv").role("index").parts(vec![
        Part {
            name: "header".into(),
            offset: 0,
            length: 14,
        },
        Part {
            name: "row 1".into(),
            offset: 14,
            length: 10,
        },
        Part {
            name: "row 2".into(),
            offset: 24,
            length: 11,
        },
    ]));
    b.add_log(LogSpec {
        source: log.path().to_path_buf(),
        path: "Audit log".into(),
        head: None,
        elide: vec![(0, 2)],
    });
    b.write(signer).unwrap();
    (log, rel)
}

fn verify_rel(dir: &Path, t: &TrustContext, o: &ReleaseOptions) -> String {
    verify_release(dir, t, o).unwrap().compact_verdict()
}

#[test]
fn release_clean_and_altered() {
    let (_log, rel) = build_release(&k(1));
    let o = ReleaseOptions::new();
    let r = verify_release(rel.path(), &pin(1), &o).unwrap();
    assert_eq!(
        r.compact_verdict(),
        "Verified",
        "{}",
        r.render_human(false, "ogentic-audit")
    );
    assert_eq!(
        r.logs[0].report.as_ref().unwrap().log.elided_records,
        vec![(0, 2)]
    );
    assert_eq!(
        verify_rel(rel.path(), &TrustContext::new(), &o),
        "SelfConsistent"
    );
    assert_eq!(
        verify_rel(rel.path(), &pin(2), &o),
        "UntrustedSigner@attestation"
    );

    // Row 1 altered.
    let csv = rel.path().join("Decisions.csv");
    let mut b = std::fs::read(&csv).unwrap();
    b[16] = b'9';
    std::fs::write(&csv, &b).unwrap();
    // Page altered, file planted, OS litter.
    std::fs::write(rel.path().join("pages/0002.pdf"), b"%PDF page TWO").unwrap();
    std::fs::write(rel.path().join("extra.pdf"), b"x").unwrap();
    std::fs::write(rel.path().join(".DS_Store"), b"x").unwrap();
    std::fs::remove_file(rel.path().join("pages/0001.pdf")).unwrap();
    let r = verify_release(rel.path(), &pin(1), &o).unwrap();
    let got: Vec<String> = r.violations.iter().map(|v| v.compact()).collect();
    assert_eq!(
        got,
        vec![
            "FileAltered@file:Decisions.csv#row 1",
            "FileMissing@file:pages/0001.pdf",
            "FileAltered@file:pages/0002.pdf",
            "UnattestedFile@file:extra.pdf",
        ]
    );
    assert_eq!(r.ignored, vec![".DS_Store"]);
    let human = r.render_human(false, "ogentic-audit");
    assert!(
        human.contains("\"Decisions.csv\", item \"row 1\" (bytes 15–24)"),
        "{human}"
    );
    let r = verify_release(
        rel.path(),
        &pin(1),
        &ReleaseOptions::new().allow_unattested(true),
    )
    .unwrap();
    assert!(!r
        .violations
        .iter()
        .any(|v| v.compact().starts_with("Unattested")));
}

#[test]
fn release_attestation_tamper_and_forgery() {
    let (_log, rel) = build_release(&k(1));
    let att = rel.path().join("ogentic-audit-release.json");
    let orig = std::fs::read(&att).unwrap();
    let mut b = orig.clone();
    let i = b.len() / 2;
    b[i] ^= 0x01;
    std::fs::write(&att, &b).unwrap();
    assert_eq!(
        verify_rel(rel.path(), &pin(1), &ReleaseOptions::new()),
        "SignatureInvalid@attestation"
    );
    std::fs::write(&att, &orig).unwrap();
    // Re-signed by K2.
    let sig = ogentic_audit_core::signed::signer::sign_detached(
        &k(2),
        ogentic_audit_core::signed::NS_RELEASE,
        &orig,
    )
    .unwrap();
    std::fs::write(rel.path().join("ogentic-audit-release.json.sig"), sig).unwrap();
    assert_eq!(
        verify_rel(rel.path(), &pin(1), &ReleaseOptions::new()),
        "UntrustedSigner@attestation"
    );
}

#[test]
fn release_log_truncated_or_replaced() {
    let (_log, rel) = build_release(&k(1));
    let logdir = rel.path().join("Audit log");
    let recs = records(&seg(&logdir, 0));
    mutate(&logdir, 0, |b| b.truncate(recs[3].start));
    assert_eq!(
        verify_rel(rel.path(), &pin(1), &ReleaseOptions::new()),
        "CheckpointTruncated@log:Audit log/s0r5"
    );
    // Replaced by an HMAC log.
    std::fs::remove_dir_all(&logdir).unwrap();
    {
        let mut w = ogentic_audit_core::Writer::open(
            &logdir,
            Box::new(ogentic_audit_core::InMemoryKey::from_bytes([3u8; 32])),
            [0; 16],
        )
        .unwrap();
        w.append(input(0, "x.y")).unwrap();
        w.flush().unwrap();
    }
    assert_eq!(
        verify_rel(rel.path(), &pin(1), &ReleaseOptions::new()),
        "FormatDowngrade@log:Audit log/s0"
    );
}

#[test]
fn pins_refuse_weak_keys_and_bad_fingerprints() {
    let mut t = TrustContext::new();
    for enc in ogentic_audit_core::signed::ed25519::SMALL_ORDER_ENCODINGS {
        assert!(t.pin(enc, None, Scope::DEFAULT).is_err(), "{enc}");
    }
    assert!(t.pin(&"ab".repeat(31), None, Scope::DEFAULT).is_err());
    assert!(t
        .add_allowed_signers(&format!(
            "a cert-authority {}",
            k(1).public_key().to_openssh("")
        ))
        .is_err());
    t.add_allowed_signers(&format!(
        "# comment\nrelease-signer namespaces=\"ogentic-audit/v0.2/release\" {}\n",
        k(1).public_key().to_openssh("x")
    ))
    .unwrap();
    let _ = Fingerprint::parse("SHA256:bbXpuKG6zhzdmnxq256TlqzFBzRl2f6OOg722cYNbU8").unwrap();
}

// Cases git cannot carry (spec §16): generated at test time.

/// A bundle that passed through a filesystem storing names decomposed
/// (NFD) still verifies: names are looked up by NFC equality.
#[test]
fn release_nfd_name_verifies() {
    let log = tempfile::tempdir().unwrap();
    write_log(log.path(), 1, 2, true);
    let rel = tempfile::tempdir().unwrap();
    let nfc = "r\u{e9}sum\u{e9}.pdf";
    std::fs::write(rel.path().join(nfc), b"%PDF").unwrap();
    let mut b = AttestationBuilder::new(rel.path(), "nfd");
    b.add_file(FileSpec::new(nfc));
    b.add_log(LogSpec {
        source: log.path().to_path_buf(),
        path: "log".into(),
        head: None,
        elide: vec![],
    });
    b.write(&k(1)).unwrap();
    let nfd = "re\u{301}sume\u{301}.pdf";
    std::fs::rename(rel.path().join(nfc), rel.path().join(nfd)).unwrap();
    // On APFS both spellings name one file; elsewhere the rename changes it.
    assert_eq!(
        verify_rel(rel.path(), &pin(1), &ReleaseOptions::new()),
        "Verified"
    );
}

#[cfg(unix)]
#[test]
fn release_symlink_is_not_followed() {
    let (_log, rel) = build_release(&k(1));
    let page = rel.path().join("pages/0001.pdf");
    let real = rel.path().join("elsewhere.bin");
    std::fs::rename(&page, &real).unwrap();
    std::os::unix::fs::symlink(&real, &page).unwrap();
    let r = verify_release(rel.path(), &pin(1), &ReleaseOptions::new()).unwrap();
    let first = &r.violations[0];
    assert_eq!(first.compact(), "FileAltered@file:pages/0001.pdf");
    assert_eq!(first.reason.as_deref(), Some("not_regular_file"));
}

#[cfg(unix)]
#[test]
fn release_segment_symlink_is_not_followed() {
    let (_log, rel) = build_release(&k(1));
    let seg = rel.path().join("Audit log/audit-0000.cbor");
    let real = rel.path().join("elsewhere.cbor");
    std::fs::rename(&seg, &real).unwrap();
    std::os::unix::fs::symlink(&real, &seg).unwrap();
    let r = verify_release(rel.path(), &pin(1), &ReleaseOptions::new()).unwrap();
    assert!(
        r.violations
            .iter()
            .any(|v| v.compact() == "FileAltered@file:Audit log/audit-0000.cbor"),
        "{:?}",
        r.violations.iter().map(|v| v.compact()).collect::<Vec<_>>()
    );
}

/// Two names equal after case folding are ambiguous and fail closed.
/// Needs a case-sensitive filesystem (Linux; skipped where the second
/// name lands on the first).
#[test]
fn release_ambiguous_name_fails_closed() {
    let (_log, rel) = build_release(&k(1));
    let other = rel.path().join("DECISIONS.csv");
    std::fs::write(&other, b"x").unwrap();
    if std::fs::read(rel.path().join("Decisions.csv")).unwrap() == b"x" {
        eprintln!("skipping: case-insensitive filesystem");
        return;
    }
    let r = verify_release(rel.path(), &pin(1), &ReleaseOptions::new()).unwrap();
    assert!(r
        .violations
        .iter()
        .any(|v| v.compact() == "FileAltered@file:Decisions.csv"
            && v.reason.as_deref() == Some("ambiguous_name")));
}
