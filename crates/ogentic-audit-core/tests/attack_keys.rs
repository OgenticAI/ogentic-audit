//! Adversarial: key substitution and pinning (spec v0.2 §3.7, §4, §8, §9, §11.4).
//! Each test asserts the verifier REJECTS a forgery with a specific kind.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use ogentic_audit_core::signed::format::{Frame, HEADER_LEN};
use ogentic_audit_core::signed::release::{ATTESTATION_FILE, ATTESTATION_SIG_FILE, KEYS_DIR};
use ogentic_audit_core::signed::signer::sign_detached;
use ogentic_audit_core::signed::statements::{self, CutPoints, Head};
use ogentic_audit_core::signed::{
    format, sha256, sshsig, unhex, verify_release, AttestationBuilder, FileSpec, Fingerprint,
    InMemorySigner, LogSpec, ReleaseOptions, Scope, SignedVerifier, SignedVerifyOptions,
    SignedWriter, Signer, TrustContext, NS_RELEASE, NS_TRANSITION,
};
use ogentic_audit_core::{PayloadValue, RecordInput, Verdict, WriterConfig};

fn k(n: u8) -> InMemorySigner {
    let seeds = [
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5",
    ];
    InMemorySigner::from_seed(unhex(seeds[n as usize - 1]).unwrap())
}

fn input(i: u64, event: &str, tag: &str) -> RecordInput {
    let mut payload = BTreeMap::new();
    payload.insert("n".to_string(), PayloadValue::Uint(i));
    payload.insert("tag".to_string(), PayloadValue::Text(tag.into()));
    RecordInput {
        ts_wall: format!("2026-10-03T12:00:{:02}.000Z", i % 60),
        ts_mono_delta: i * 1000,
        actor: "user:test".into(),
        event: event.into(),
        payload,
        schema_version: 1,
    }
}

fn write_log_cfg(
    dir: &Path,
    signer: u8,
    n: u64,
    seal: bool,
    log_id: [u8; 16],
    cfg: WriterConfig,
    tag: &str,
) {
    let mut w =
        SignedWriter::create_with_log_id(dir, Box::new(k(signer)), [7u8; 16], cfg, log_id).unwrap();
    for i in 0..n {
        w.append(input(i, "page.released", tag)).unwrap();
    }
    if seal {
        w.seal().unwrap();
    }
    w.flush().unwrap();
}

fn write_log(dir: &Path, signer: u8, n: u64, seal: bool) {
    write_log_cfg(
        dir,
        signer,
        n,
        seal,
        [0x11; 16],
        WriterConfig::default(),
        "genuine",
    );
}

fn pin(n: u8) -> TrustContext {
    let mut t = TrustContext::new();
    t.pin_key(*k(n).public_key(), Some(&format!("k{n}")), Scope::DEFAULT)
        .unwrap();
    t
}

fn verify(dir: &Path, t: TrustContext) -> String {
    match SignedVerifier::new(t).verify(dir) {
        Ok(r) => r.compact_verdict(),
        Err(e) => format!("ERROR(exit {}): {e}", e.exit_code()),
    }
}

fn seg(dir: &Path, n: u16) -> PathBuf {
    dir.join(format!("audit-{n:04}.cbor"))
}

fn record_starts(path: &Path) -> Vec<usize> {
    let bytes = std::fs::read(path).unwrap();
    let mut c = std::io::Cursor::new(&bytes);
    c.set_position(HEADER_LEN as u64);
    let mut off = HEADER_LEN as u64;
    let mut out = Vec::new();
    while let Frame::Record(r) = format::read_frame(&mut c, off, bytes.len() as u64).unwrap() {
        out.push(off as usize);
        off += r.total_len;
    }
    out
}

fn rewrite_header(dir: &Path, n: u16, f: impl FnOnce(&mut [u8])) {
    let p = seg(dir, n);
    let mut b = std::fs::read(&p).unwrap();
    f(&mut b[..HEADER_LEN]);
    let crc = crc32fast::hash(&b[..124]);
    b[124..128].copy_from_slice(&crc.to_le_bytes());
    std::fs::write(&p, b).unwrap();
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

fn rel(dir: &Path, t: &TrustContext) -> String {
    match verify_release(dir, t, &ReleaseOptions::new()) {
        Ok(r) => r.compact_verdict(),
        Err(e) => format!("ERROR: {e}"),
    }
}

/// A release with one file, optionally one log, signed by `signer`.
fn build_release(
    signer: &InMemorySigner,
    log: Option<&Path>,
    trust: Option<TrustContext>,
) -> tempfile::TempDir {
    let r = tempfile::tempdir().unwrap();
    std::fs::write(r.path().join("page.pdf"), b"%PDF page").unwrap();
    let mut b = AttestationBuilder::new(r.path(), "rel-1");
    b.created_at("2026-10-03T12:00:00.000Z");
    b.add_file(FileSpec::new("page.pdf").role("page"));
    if let Some(l) = log {
        b.add_log(LogSpec {
            source: l.to_path_buf(),
            path: "Audit log".into(),
            head: None,
            elide: vec![],
        });
    }
    if let Some(t) = trust {
        b.trust(t);
    }
    b.write(signer).unwrap();
    r
}

// ---------------------------------------------------------------- logs

#[test]
fn a01_whole_log_resigned_with_attacker_key() {
    let d = tempfile::tempdir().unwrap();
    write_log(d.path(), 3, 4, true);
    assert_eq!(verify(d.path(), pin(1)), "UntrustedSigner@s0");
}

#[test]
fn a02_header_claims_pinned_key_records_by_attacker() {
    let d = tempfile::tempdir().unwrap();
    write_log(d.path(), 3, 4, true);
    let pk = *k(1).public_key();
    rewrite_header(d.path(), 0, |h| {
        h[28..60].copy_from_slice(&pk.fingerprint().0);
        h[92..124].copy_from_slice(pk.as_bytes());
    });
    assert_eq!(verify(d.path(), pin(1)), "SignatureInvalid@s0r0");
}

#[test]
fn a03_header_key_id_swapped_to_pinned_only() {
    let d = tempfile::tempdir().unwrap();
    write_log(d.path(), 3, 4, true);
    let fp = k(1).public_key().fingerprint();
    rewrite_header(d.path(), 0, |h| h[28..60].copy_from_slice(&fp.0));
    assert_eq!(verify(d.path(), pin(1)), "KeyIdMismatch@s0");
}

#[test]
fn a04_header_key_stripped_to_zero() {
    let d = tempfile::tempdir().unwrap();
    write_log(d.path(), 1, 4, true);
    rewrite_header(d.path(), 0, |h| h[92..124].copy_from_slice(&[0u8; 32]));
    assert_eq!(verify(d.path(), pin(1)), "SignatureInvalid@s0");
}

fn small_segments() -> WriterConfig {
    WriterConfig {
        segment_size_bytes: 700,
        ..WriterConfig::default()
    }
}

#[test]
fn a05_later_segment_swapped_for_attacker_signed_segment() {
    let g = tempfile::tempdir().unwrap();
    write_log_cfg(
        g.path(),
        1,
        12,
        true,
        [0x22; 16],
        small_segments(),
        "genuine",
    );
    let a = tempfile::tempdir().unwrap();
    write_log_cfg(
        a.path(),
        3,
        12,
        true,
        [0x22; 16],
        small_segments(),
        "forged",
    );
    assert!(
        seg(g.path(), 1).exists() && seg(a.path(), 1).exists(),
        "need ≥2 segments"
    );
    assert_eq!(verify(g.path(), pin(1)), "Verified");
    std::fs::copy(seg(a.path(), 1), seg(g.path(), 1)).unwrap();
    assert_eq!(verify(g.path(), pin(1)), "KeyIdMismatch@s1");
}

#[test]
fn a06_segment0_removed_forensic_attacker_segments_unchecked() {
    // Whole log replaced by attacker-signed segments 1.. (segment 0 deleted).
    let a = tempfile::tempdir().unwrap();
    write_log_cfg(
        a.path(),
        3,
        12,
        true,
        [0x22; 16],
        small_segments(),
        "forged",
    );
    std::fs::remove_file(seg(a.path(), 0)).unwrap();
    let r = SignedVerifier::new(pin(1))
        .verify_with_options(a.path(), SignedVerifyOptions::new().forensic(true))
        .unwrap();
    let kinds: Vec<String> = r.violations.iter().map(|v| v.compact()).collect();
    eprintln!("a06 violations: {kinds:?}; signer: {:?}", r.signer);
    assert_eq!(r.verdict, Verdict::Violation);
}

// ------------------------------------------------------ fingerprints/pins

#[test]
fn a07_prefix_and_near_fingerprints() {
    let d = tempfile::tempdir().unwrap();
    write_log(d.path(), 1, 3, false);
    let hex = k(1).public_key().fingerprint().to_hex();
    assert!(
        Fingerprint::parse(&hex[..63]).is_err(),
        "63 hex digits must be refused"
    );
    assert!(
        Fingerprint::parse(&hex[..32]).is_err(),
        "a 32-digit prefix must be refused"
    );
    assert!(Fingerprint::parse(&format!("{hex}0")).is_err());
    let b64 = k(1).public_key().fingerprint().to_openssh();
    assert!(
        Fingerprint::parse(&b64[..b64.len() - 4]).is_err(),
        "truncated SHA256: form"
    );
    // Same first and last groups, one middle nibble differs.
    let mut near = hex.clone().into_bytes();
    near[30] = if near[30] == b'0' { b'1' } else { b'0' };
    let near = Fingerprint::parse(&String::from_utf8(near).unwrap()).unwrap();
    let mut t = TrustContext::new();
    t.pin(&near.to_dashed_hex(), None, Scope::DEFAULT).unwrap();
    assert_eq!(verify(d.path(), t), "UntrustedSigner@s0");
}

#[test]
fn a08_bare_hex_fingerprint_is_a_fingerprint() {
    // §3.7: 64 hex digits with no separators is a valid fingerprint for
    // --key-fingerprint. The CLI and Python route it through TrustContext::pin.
    let d = tempfile::tempdir().unwrap();
    write_log(d.path(), 1, 3, false);
    let hex = k(1).public_key().fingerprint().to_hex();
    let mut t = TrustContext::new();
    let pinned = t.pin(&hex, None, Scope::DEFAULT);
    assert!(pinned.is_ok(), "correct fingerprint refused: {pinned:?}");
    assert_eq!(verify(d.path(), t), "Verified");
}

#[test]
fn a09_weak_key_fingerprint_pin_refused() {
    let mut t = TrustContext::new();
    let fp = Fingerprint::parse("92661cbdd8b61a43de5b107a5cb8eb641f091eccb61e6f25b87305a7d18cbea9")
        .unwrap();
    assert!(t.pin_fingerprint(fp, None, Scope::DEFAULT).is_err());
}

// ------------------------------------------------------------- releases

#[test]
fn a10_release_fully_resigned_by_attacker() {
    let log = tempfile::tempdir().unwrap();
    write_log(log.path(), 3, 3, true);
    let r = build_release(&k(3), Some(log.path()), None);
    assert_eq!(rel(r.path(), &pin(1)), "UntrustedSigner@attestation");
}

#[test]
fn a11_release_sig_swapped_keep_json_key_id() {
    let log = tempfile::tempdir().unwrap();
    write_log(log.path(), 1, 3, true);
    let r = build_release(&k(1), Some(log.path()), None);
    assert_eq!(rel(r.path(), &pin(1)), "Verified");
    let bytes = std::fs::read(r.path().join(ATTESTATION_FILE)).unwrap();
    std::fs::write(
        r.path().join(ATTESTATION_SIG_FILE),
        sign_detached(&k(3), NS_RELEASE, &bytes).unwrap(),
    )
    .unwrap();
    assert_eq!(rel(r.path(), &pin(1)), "UntrustedSigner@attestation");
}

#[test]
fn a12_release_sig_blob_names_pinned_key_attacker_signature() {
    let r = build_release(&k(1), None, None);
    let bytes = std::fs::read(r.path().join(ATTESTATION_FILE)).unwrap();
    let s = k(3)
        .sign(NS_RELEASE, &sshsig::signed_data(NS_RELEASE, &bytes))
        .unwrap();
    std::fs::write(
        r.path().join(ATTESTATION_SIG_FILE),
        sshsig::armor(k(1).public_key(), NS_RELEASE, &s.to_bytes()),
    )
    .unwrap();
    assert_eq!(rel(r.path(), &pin(1)), "SignatureInvalid@attestation");
}

#[test]
fn a13_attacker_transition_chain_in_bundle() {
    // Attacker key K3 → K4 transition (fully valid) in the bundle; release by K4.
    let r = build_release(&k(4), None, None);
    let keys = r.path().join(KEYS_DIR);
    write_statement(
        &keys,
        "k3-k4",
        &statements::transition(&k(3), &k(4), &[], &[], "2027-01-15T09:00:00.000Z", None).unwrap(),
    );
    assert_eq!(rel(r.path(), &pin(1)), "UntrustedSigner@attestation");
}

#[test]
fn a14_forged_transition_from_pinned_key_in_bundle() {
    // Claims old = K1 (pinned), new = K3 (attacker); signed by K3 itself.
    let r = build_release(&k(3), None, None);
    let json = statements::transition_json(
        k(1).public_key(),
        k(3).public_key(),
        &[],
        &[],
        "2027-01-15T09:00:00.000Z",
        None,
    );
    let s = statements::SignedStatement {
        sig: sign_detached(&k(3), NS_TRANSITION, &json).unwrap(),
        accept_sig: Some(statements::accept(&k(3), &json).unwrap()),
        json,
    };
    write_statement(&r.path().join(KEYS_DIR), "forged", &s);
    let rep = verify_release(r.path(), &pin(1), &ReleaseOptions::new()).unwrap();
    assert_eq!(rep.compact_verdict(), "UntrustedSigner@attestation");
    assert!(rep.warnings.iter().any(|w| w.kind == "IgnoredStatement"));
}

#[test]
fn a15_genuine_transition_sig_replayed_onto_edited_successor() {
    // Genuine K1→K2 transition; attacker edits new key to K3, keeps K1's .sig, adds K3 acceptance.
    let st = tempfile::tempdir().unwrap();
    let g =
        statements::transition(&k(1), &k(2), &[], &[], "2027-01-15T09:00:00.000Z", None).unwrap();
    let json = statements::transition_json(
        k(1).public_key(),
        k(3).public_key(),
        &[],
        &[],
        "2027-01-15T09:00:00.000Z",
        None,
    );
    let s = statements::SignedStatement {
        sig: g.sig.clone(),
        accept_sig: Some(statements::accept(&k(3), &json).unwrap()),
        json,
    };
    let r = build_release(&k(3), None, None);
    write_statement(&r.path().join(KEYS_DIR), "edited", &s);
    let _ = st;
    assert_eq!(rel(r.path(), &pin(1)), "UntrustedSigner@attestation");
}

#[test]
fn a16_operator_revocation_by_stranger_is_an_error() {
    let st = tempfile::tempdir().unwrap();
    let rev = statements::revocation(
        &k(3),
        &k(1).public_key().fingerprint(),
        &CutPoints::default(),
        "2027-02-01T00:00:00.000Z",
        None,
    )
    .unwrap();
    let p = write_statement(st.path(), "rev", &rev);
    let mut t = pin(1);
    t.add_revocation(&p).unwrap();
    let d = tempfile::tempdir().unwrap();
    write_log(d.path(), 1, 3, false);
    assert!(verify(d.path(), t).starts_with("ERROR(exit 3)"));
}

// ------------------------------------------------- retired / revoked keys

/// Old log by K1 (5 records + seal), transition K1→K2 naming that head.
fn retired_setup() -> (tempfile::TempDir, tempfile::TempDir, Head) {
    let old = tempfile::tempdir().unwrap();
    write_log(old.path(), 1, 5, true);
    let head = head_of(old.path());
    let st = tempfile::tempdir().unwrap();
    write_statement(
        st.path(),
        "k1-k2",
        &statements::transition(&k(1), &k(2), &[head], &[], "2027-01-15T09:00:00.000Z", None)
            .unwrap(),
    );
    (old, st, head)
}

fn with_statements(st: &Path) -> TrustContext {
    let mut t = pin(1);
    t.add_statements(st, true).unwrap();
    t
}

#[test]
fn a17_retired_key_new_log_control() {
    let (_old, st, _) = retired_setup();
    let late = tempfile::tempdir().unwrap();
    write_log_cfg(
        late.path(),
        1,
        2,
        false,
        [0x33; 16],
        WriterConfig::default(),
        "late",
    );
    assert_eq!(
        verify(late.path(), with_statements(st.path())),
        "RetiredKey@s0r0"
    );
}

#[test]
fn a18_retired_log_truncated_below_final_head_no_key() {
    // §9.3 effect 2: the final head's record_hash MUST be present at that
    // position, otherwise CheckpointMismatch. Attacker has no key: just cuts.
    let (old, st, head) = retired_setup();
    assert_eq!(verify(old.path(), with_statements(st.path())), "Verified");
    let starts = record_starts(&seg(old.path(), 0));
    let p = seg(old.path(), 0);
    let mut b = std::fs::read(&p).unwrap();
    b.truncate(starts[3]); // keep r0..r2; head is r5 (log.sealed)
    std::fs::write(&p, b).unwrap();
    assert_eq!(head.record_id, 5);
    let v = verify(old.path(), with_statements(st.path()));
    assert!(
        v.starts_with("CheckpointMismatch") || v.starts_with("CheckpointTruncated"),
        "retired key's final head is gone, got {v}"
    );
}

#[test]
fn a19_stolen_retired_key_forges_log_reusing_log_id() {
    // Old key stolen before destruction: rewrites a log with the retired
    // log's public log_id, shorter than the final head.
    let (_old, st, head) = retired_setup();
    let forged = tempfile::tempdir().unwrap();
    write_log_cfg(
        forged.path(),
        1,
        3,
        false,
        head.log_id,
        WriterConfig::default(),
        "FORGED",
    );
    let v = verify(forged.path(), with_statements(st.path()));
    assert_ne!(v, "Verified", "stolen retired key produced a Verified log");
    assert!(
        v.starts_with("CheckpointMismatch") || v.starts_with("RetiredKey"),
        "got {v}"
    );
}

#[test]
fn a20_stolen_retired_key_new_release_control() {
    let (_old, st, _) = retired_setup();
    let r = build_release(&k(1), None, None);
    assert_eq!(
        rel(r.path(), &with_statements(st.path())),
        "RetiredKey@attestation"
    );
}

#[test]
fn a21_stolen_retired_key_equivocates_to_escape_retirement_logless_release() {
    // Verifier has the genuine K1→K2 transition. Thief of K1 mints K1→K3
    // (accepted by K3) into the bundle and signs a release with no logs.
    let (_old, st, _) = retired_setup();
    let r = build_release(&k(1), None, None);
    write_statement(
        &r.path().join(KEYS_DIR),
        "k1-k3",
        &statements::transition(&k(1), &k(3), &[], &[], "2027-03-01T00:00:00.000Z", None).unwrap(),
    );
    let v = rel(r.path(), &with_statements(st.path()));
    assert_ne!(
        v, "Verified",
        "retired key escaped retirement by equivocating"
    );
    assert!(
        v.starts_with("TransitionEquivocation") || v.starts_with("RetiredKey"),
        "got {v}"
    );
}

#[test]
fn a22_equivocation_release_with_log_control() {
    let (_old, st, _) = retired_setup();
    let log = tempfile::tempdir().unwrap();
    write_log_cfg(
        log.path(),
        1,
        3,
        true,
        [0x44; 16],
        WriterConfig::default(),
        "x",
    );
    let r = build_release(&k(1), Some(log.path()), None);
    write_statement(
        &r.path().join(KEYS_DIR),
        "k1-k3",
        &statements::transition(&k(1), &k(3), &[], &[], "2027-03-01T00:00:00.000Z", None).unwrap(),
    );
    let v = rel(r.path(), &with_statements(st.path()));
    assert!(v.starts_with("TransitionEquivocation"), "got {v}");
}

/// K2 log (8 records) with id 0x55…; K2 pinned "ops", K1 "ops" revocation-only;
/// authority revocation of K2 with cut head at r4.
fn revoked_setup() -> (tempfile::TempDir, PathBuf, Head, tempfile::TempDir) {
    let log = tempfile::tempdir().unwrap();
    write_log_cfg(
        log.path(),
        2,
        8,
        false,
        [0x55; 16],
        WriterConfig::default(),
        "genuine",
    );
    let cut_head = {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::copy(seg(log.path(), 0), seg(tmp.path(), 0)).unwrap();
        let starts = record_starts(&seg(tmp.path(), 0));
        let p = seg(tmp.path(), 0);
        let mut b = std::fs::read(&p).unwrap();
        b.truncate(starts[5]);
        std::fs::write(&p, b).unwrap();
        head_of(tmp.path())
    };
    let st_dir = tempfile::tempdir().unwrap();
    let st = st_dir.path().to_path_buf();
    let rev = statements::revocation(
        &k(1),
        &k(2).public_key().fingerprint(),
        &CutPoints {
            trusted_heads: vec![cut_head],
            ..CutPoints::default()
        },
        "2027-02-01T00:00:00.000Z",
        Some("compromised"),
    )
    .unwrap();
    let p = write_statement(&st, "rev", &rev);
    (log, p, cut_head, st_dir)
}

fn revoked_trust(rev: &Path) -> TrustContext {
    let mut t = TrustContext::new();
    t.pin_key(*k(2).public_key(), Some("ops"), Scope::DEFAULT)
        .unwrap();
    t.pin_key(*k(1).public_key(), Some("ops"), Scope::REVOCATION_ONLY)
        .unwrap();
    t.add_revocation(rev).unwrap();
    t
}

#[test]
fn a23_revoked_key_after_cut_control() {
    let (log, rev, _, _st) = revoked_setup();
    assert_eq!(verify(log.path(), revoked_trust(&rev)), "RevokedKey@s0r5");
}

#[test]
fn a24_revoked_log_truncated_below_cut_head_no_key() {
    // §9.4: "with that head's record_hash present at that position
    // (otherwise CheckpointMismatch against the head)".
    let (log, rev, head, _st) = revoked_setup();
    assert_eq!(head.record_id, 4);
    let starts = record_starts(&seg(log.path(), 0));
    let p = seg(log.path(), 0);
    let mut b = std::fs::read(&p).unwrap();
    b.truncate(starts[2]);
    std::fs::write(&p, b).unwrap();
    let v = verify(log.path(), revoked_trust(&rev));
    assert!(
        v.starts_with("CheckpointMismatch") || v.starts_with("CheckpointTruncated"),
        "revocation cut head is gone, got {v}"
    );
}

#[test]
fn a25_stolen_revoked_key_forges_log_reusing_cut_log_id() {
    let (_log, rev, head, _st) = revoked_setup();
    let forged = tempfile::tempdir().unwrap();
    write_log_cfg(
        forged.path(),
        2,
        3,
        false,
        head.log_id,
        WriterConfig::default(),
        "FORGED",
    );
    let v = verify(forged.path(), revoked_trust(&rev));
    assert_ne!(v, "Verified", "stolen revoked key produced a Verified log");
    assert!(
        v.starts_with("CheckpointMismatch") || v.starts_with("RevokedKey"),
        "got {v}"
    );
}

#[test]
fn a26_stolen_revoked_key_new_release_and_successor() {
    let (_log, rev, _, _st) = revoked_setup();
    let r = build_release(&k(2), None, None);
    assert_eq!(
        rel(r.path(), &revoked_trust(&rev)),
        "RevokedKey@attestation"
    );
    // Thief mints K2→K3 in the bundle; release by K3.
    let r3 = build_release(&k(3), None, None);
    write_statement(
        &r3.path().join(KEYS_DIR),
        "k2-k3",
        &statements::transition(&k(2), &k(3), &[], &[], "2027-03-01T00:00:00.000Z", None).unwrap(),
    );
    assert_eq!(
        rel(r3.path(), &revoked_trust(&rev)),
        "UntrustedSigner@attestation"
    );
}

#[test]
fn a27_bundle_revocation_by_stranger_ignored() {
    let r = build_release(&k(1), None, None);
    let rev = statements::revocation(
        &k(3),
        &k(1).public_key().fingerprint(),
        &CutPoints::default(),
        "2027-02-01T00:00:00.000Z",
        None,
    )
    .unwrap();
    write_statement(&r.path().join(KEYS_DIR), "rev", &rev);
    let rep = verify_release(r.path(), &pin(1), &ReleaseOptions::new()).unwrap();
    // Spec §9.4: ignored with a warning (cannot reduce trust either).
    assert_eq!(rep.compact_verdict(), "Verified");
    assert!(rep.warnings.iter().any(|w| w.kind == "IgnoredStatement"));
    let _ = sha256(b"");
}

// ------------------------------------------------- control: reserved entries

#[test]
fn a28_genuine_rotation_release_with_bundled_statements_verifies() {
    // The legitimate counterpart of a13/a14/r08: a release signed by the new
    // key K2, shipping the K1→K2 transition (both signatures) and a witness
    // co-signature in the reserved folders. Pinned to K1, it must verify with
    // nothing reported as planted.
    let r = build_release(&k(2), None, None);
    write_statement(
        &r.path().join(KEYS_DIR),
        "k1-k2",
        &statements::transition(&k(1), &k(2), &[], &[], "2027-01-15T09:00:00.000Z", None).unwrap(),
    );
    let att = std::fs::read(r.path().join(ATTESTATION_FILE)).unwrap();
    let (doc, sig) =
        ogentic_audit_core::signed::checkpoint::cosign(&att, &k(3), "2027-01-16T09:00:00.000Z")
            .unwrap();
    let wd = r
        .path()
        .join(ogentic_audit_core::signed::release::WITNESS_DIR);
    std::fs::create_dir_all(&wd).unwrap();
    std::fs::write(wd.join("w1.json"), doc).unwrap();
    std::fs::write(wd.join("w1.json.sig"), sig).unwrap();
    let rep = verify_release(r.path(), &pin(1), &ReleaseOptions::new()).unwrap();
    assert_eq!(rep.compact_verdict(), "Verified", "{:?}", rep.warnings);
    // A statement whose signature does not verify is not exempt.
    let p = r.path().join(KEYS_DIR).join("k1-k2.json.sig");
    let mut b = std::fs::read(&p).unwrap();
    b.truncate(b.len() / 2);
    std::fs::write(&p, b).unwrap();
    let v = rel(r.path(), &pin(1));
    assert_ne!(v, "Verified", "{v}");
}

#[test]
fn a29_stolen_key_forges_longer_log_reusing_log_id() {
    // a19/a25 with MORE records than the statement's head: the record at the
    // head position exists but is not the one the statement names.
    let (_old, st, head) = retired_setup();
    let forged = tempfile::tempdir().unwrap();
    write_log_cfg(
        forged.path(),
        1,
        9,
        false,
        head.log_id,
        WriterConfig::default(),
        "FORGED",
    );
    let v = verify(forged.path(), with_statements(st.path()));
    assert!(
        v.starts_with("CheckpointMismatch") || v.starts_with("RetiredKey"),
        "got {v}"
    );

    let (_log, rev, head, _st) = revoked_setup();
    let forged = tempfile::tempdir().unwrap();
    write_log_cfg(
        forged.path(),
        2,
        9,
        false,
        head.log_id,
        WriterConfig::default(),
        "FORGED",
    );
    let v = verify(forged.path(), revoked_trust(&rev));
    assert!(
        v.starts_with("CheckpointMismatch") || v.starts_with("RevokedKey"),
        "got {v}"
    );
}
