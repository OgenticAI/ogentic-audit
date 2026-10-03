//! Adversarial: downgrade and confusion (v0.1 <-> v0.2), algorithm-id
//! flips, non-canonical / small-order / all-zero Ed25519 material.
//! Each test asserts that the verifier REJECTS with a specific kind.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use curve25519_dalek::edwards::CompressedEdwardsY;
use ogentic_audit_core::signed::ed25519::{reencode_s_plus_l, SMALL_ORDER_ENCODINGS};
use ogentic_audit_core::signed::format::{
    self, chain_start, encode_body, Envelope, Frame, SignedHeader, HEADER_LEN,
};
use ogentic_audit_core::signed::statements::Head;
use ogentic_audit_core::signed::{
    sshsig, unhex, verify_release, AttestationBuilder, CheckpointV2, FileSpec, InMemorySigner,
    LogSpec, PublicKey, ReleaseOptions, Scope, SigAlg, SignedVerifier, SignedVerifyError,
    SignedVerifyOptions, SignedWriter, Signer, SuppliedCheckpoint, TrustContext, NS_CHECKPOINT,
    NS_RELEASE,
};
use ogentic_audit_core::{
    InMemoryKey, PayloadValue, RecordInput, Verdict, Verifier, Writer, WriterConfig,
};

const SEEDS: [&str; 2] = [
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
];
const IDENTITY: &str = "0100000000000000000000000000000000000000000000000000000000000000";

fn k(n: usize) -> InMemorySigner {
    InMemorySigner::from_seed(unhex(SEEDS[n - 1]).unwrap())
}

fn input(i: u64) -> RecordInput {
    let mut payload = BTreeMap::new();
    payload.insert("n".to_string(), PayloadValue::Uint(i));
    RecordInput {
        ts_wall: format!("2026-10-03T12:00:{:02}.000Z", i % 60),
        ts_mono_delta: i * 1000,
        actor: "user:test".into(),
        event: "page.released".into(),
        payload,
        schema_version: 1,
    }
}

fn write_log(dir: &Path, n: u64, seal: bool) {
    let mut w = SignedWriter::open_signed(dir, Box::new(k(1)), [7u8; 16]).unwrap();
    for i in 0..n {
        w.append(input(i)).unwrap();
    }
    if seal {
        w.seal().unwrap();
    }
    w.flush().unwrap();
}

fn write_rolled_log(dir: &Path, n: u64) {
    let cfg = WriterConfig {
        segment_size_bytes: 1024,
        ..WriterConfig::default()
    };
    let mut w = SignedWriter::open_signed_with_config(dir, Box::new(k(1)), [7u8; 16], cfg).unwrap();
    for i in 0..n {
        w.append(input(i)).unwrap();
    }
    w.flush().unwrap();
}

fn write_hmac_log(dir: &Path, n: u64) {
    let mut w = Writer::open(dir, Box::new(InMemoryKey::from_bytes([3u8; 32])), [0; 16]).unwrap();
    for i in 0..n {
        w.append(input(i)).unwrap();
    }
    w.flush().unwrap();
}

fn pin(n: usize) -> TrustContext {
    let mut t = TrustContext::new();
    t.pin_key(*k(n).public_key(), Some(&format!("k{n}")), Scope::DEFAULT)
        .unwrap();
    t
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

fn fix_crc(b: &mut [u8]) {
    let crc = crc32fast::hash(&b[..124]);
    b[124..128].copy_from_slice(&crc.to_le_bytes());
}

fn sig_offsets(path: &Path) -> Vec<usize> {
    let bytes = std::fs::read(path).unwrap();
    let mut c = std::io::Cursor::new(&bytes);
    c.set_position(HEADER_LEN as u64);
    let mut off = HEADER_LEN as u64;
    let mut out = Vec::new();
    while let Frame::Record(r) = format::read_frame(&mut c, off, bytes.len() as u64).unwrap() {
        out.push(off as usize + 4 + r.envelope.len());
        off += r.total_len;
    }
    out
}

fn verify(dir: &Path, t: TrustContext) -> String {
    SignedVerifier::new(t)
        .verify(dir)
        .unwrap()
        .compact_verdict()
}

fn first_reason(dir: &Path, t: TrustContext) -> Option<String> {
    SignedVerifier::new(t).verify(dir).unwrap().violations[0]
        .reason
        .clone()
}

/// A whole log forged under `pk`, every record signed with `sig`.
fn forge_log(dir: &Path, pk: [u8; 32], sig: [u8; 64], n: u64) {
    let key = PublicKey::ed25519(pk);
    let hdr = SignedHeader::new(0, [9u8; 16], &key, [0u8; 32]).to_bytes();
    let mut out = hdr.to_vec();
    let mut prev = chain_start(&hdr);
    for i in 0..n {
        let body = encode_body("attacker", &BTreeMap::new(), &[i as u8; 32]);
        let env = Envelope {
            record_id: i,
            prev_hash: prev,
            ts_wall: format!("2026-10-03T12:00:{:02}.000Z", i),
            ts_mono_delta: i,
            session_id: [1; 16],
            event: "page.released".into(),
            key_id: key.fingerprint().0,
            schema_version: 1,
            segment_index: 0,
            sig_alg: 1,
            body_hash: format::body_hash(&body),
        }
        .encode();
        prev = format::record_hash(&env);
        out.extend(format::frame(&env, &sig, Some(&body)));
    }
    std::fs::write(seg(dir, 0), out).unwrap();
}

fn lax_forgery_sig() -> [u8; 64] {
    // R = identity, S = 0: valid under the identity key for any message
    // in OpenSSH / OpenSSL.
    let mut s = [0u8; 64];
    s[0] = 1;
    s
}

// ---------- 1. Downgrade / confusion between formats ----------

#[test]
fn a01_hmac_log_under_pin_is_hmaclog_error() {
    let d = tempfile::tempdir().unwrap();
    write_hmac_log(d.path(), 3);
    let e = SignedVerifier::new(pin(1)).verify(d.path()).unwrap_err();
    assert!(matches!(e, SignedVerifyError::HmacLog), "{e:?}");
    assert_eq!(e.exit_code(), 3);
}

#[test]
fn a02_v02_log_to_v01_verifier_is_unknown_version() {
    let d = tempfile::tempdir().unwrap();
    write_log(d.path(), 3, true);
    let r = Verifier::new(Box::new(InMemoryKey::from_bytes([3u8; 32])))
        .verify(d.path())
        .unwrap();
    assert_ne!(r.verdict, Verdict::Verified);
    assert!(
        r.compact_verdict().starts_with("UnknownVersion"),
        "{}",
        r.compact_verdict()
    );
}

#[test]
fn a03_v01_segment_spliced_after_v02_seg0_is_format_downgrade() {
    let d = tempfile::tempdir().unwrap();
    write_log(d.path(), 3, false);
    let h = tempfile::tempdir().unwrap();
    write_hmac_log(h.path(), 2);
    std::fs::copy(seg(h.path(), 0), seg(d.path(), 1)).unwrap();
    assert_eq!(verify(d.path(), pin(1)), "FormatDowngrade@s1");
}

#[test]
fn a04_v01_seg0_with_genuine_v02_tail_is_hmaclog() {
    let d = tempfile::tempdir().unwrap();
    write_rolled_log(d.path(), 12);
    assert!(seg(d.path(), 1).exists());
    let h = tempfile::tempdir().unwrap();
    write_hmac_log(h.path(), 2);
    std::fs::copy(seg(h.path(), 0), seg(d.path(), 0)).unwrap();
    let e = SignedVerifier::new(pin(1)).verify(d.path()).unwrap_err();
    assert!(matches!(e, SignedVerifyError::HmacLog), "{e:?}");
}

#[test]
fn a05_v01_verifier_on_v01_seg0_plus_v02_seg1_is_unknown_version() {
    let d = tempfile::tempdir().unwrap();
    write_hmac_log(d.path(), 2);
    let s = tempfile::tempdir().unwrap();
    write_log(s.path(), 2, false);
    std::fs::copy(seg(s.path(), 0), seg(d.path(), 1)).unwrap();
    let r = Verifier::new(Box::new(InMemoryKey::from_bytes([3u8; 32])))
        .verify(d.path())
        .unwrap();
    assert_ne!(r.verdict, Verdict::Verified);
    assert!(
        r.compact_verdict().contains("UnknownVersion"),
        "{}",
        r.compact_verdict()
    );
}

#[test]
fn a06_seg0_version_flipped_to_1_is_hmaclog() {
    let d = tempfile::tempdir().unwrap();
    write_log(d.path(), 3, true);
    mutate(d.path(), 0, |b| {
        b[4] = 1;
        fix_crc(b);
    });
    let e = SignedVerifier::new(pin(1)).verify(d.path()).unwrap_err();
    assert!(matches!(e, SignedVerifyError::HmacLog), "{e:?}");
}

#[test]
fn a07_seg0_version_zero_is_unknown_version() {
    let d = tempfile::tempdir().unwrap();
    write_log(d.path(), 3, true);
    mutate(d.path(), 0, |b| {
        b[4] = 0;
        fix_crc(b);
    });
    assert_eq!(verify(d.path(), pin(1)), "UnknownVersion@s0");
}

#[test]
fn a08_seg1_version_newer_is_unknown_version() {
    let d = tempfile::tempdir().unwrap();
    write_rolled_log(d.path(), 12);
    mutate(d.path(), 1, |b| {
        b[4] = 3;
        fix_crc(b);
    });
    assert_eq!(verify(d.path(), pin(1)), "UnknownVersion@s1");
}

#[test]
fn a09_seg0_missing_and_seg1_is_hmac_reports_discontinuity() {
    // The lowest segment present is a v0.1 one standing in for a deleted
    // segment 0 of a signed log. Expected: a violation naming s0 (gap),
    // not an argument error that calls the whole log an HMAC log.
    let d = tempfile::tempdir().unwrap();
    write_rolled_log(d.path(), 12);
    std::fs::remove_file(seg(d.path(), 0)).unwrap();
    let h = tempfile::tempdir().unwrap();
    write_hmac_log(h.path(), 2);
    std::fs::copy(seg(h.path(), 0), seg(d.path(), 1)).unwrap();
    let r = SignedVerifier::new(pin(1)).verify(d.path());
    match r {
        Ok(rep) => assert_eq!(rep.compact_verdict(), "SegmentDiscontinuity@s0"),
        Err(e) => panic!("argument error instead of a violation: {e}"),
    }
}

#[test]
fn a10_v1_checkpoint_to_signed_verifier_is_error() {
    let d = tempfile::tempdir().unwrap();
    write_log(d.path(), 3, true);
    let v1 = br#"{"format":"ogentic-audit-checkpoint/v1","hmac":"00","key_id":"00","observed_at":"2026-10-03T12:00:00.000Z","record_id":0,"segment":0}"#;
    let opts = SignedVerifyOptions::new().checkpoint(SuppliedCheckpoint {
        bytes: v1.to_vec(),
        sig: None,
        witnesses: vec![],
    });
    let e = SignedVerifier::new(pin(1))
        .verify_with_options(d.path(), opts)
        .unwrap_err();
    assert!(matches!(e, SignedVerifyError::Checkpoint { .. }), "{e:?}");
}

// ---------- 2. Algorithm identifier flips ----------

#[test]
fn b01_header_sig_alg_flips() {
    for (segn, alg) in [(0u16, 2u8), (0, 0), (0, 0xff), (1, 2), (1, 0)] {
        let d = tempfile::tempdir().unwrap();
        write_rolled_log(d.path(), 12);
        mutate(d.path(), segn, |b| {
            b[8] = alg;
            fix_crc(b);
        });
        assert_eq!(
            verify(d.path(), pin(1)),
            format!("UnsupportedAlgorithm@s{segn}"),
            "seg {segn} alg {alg}"
        );
    }
}

#[test]
fn b02_header_sig_alg_flip_without_crc_fix_is_unsupported_or_crc() {
    let d = tempfile::tempdir().unwrap();
    write_log(d.path(), 3, true);
    mutate(d.path(), 0, |b| b[8] = 2);
    let v = verify(d.path(), pin(1));
    assert!(
        v == "UnsupportedAlgorithm@s0" || v == "HeaderCorrupt@s0",
        "{v}"
    );
}

#[test]
fn b03_envelope_sig_alg_mismatch_signed_by_key_is_algorithm_mismatch() {
    // Even the key holder cannot make an envelope disagree with its header.
    let d = tempfile::tempdir().unwrap();
    let signer = k(1);
    let key = *signer.public_key();
    let hdr = SignedHeader::new(0, [9u8; 16], &key, [0u8; 32]).to_bytes();
    let body = encode_body("a", &BTreeMap::new(), &[1; 32]);
    let env = Envelope {
        record_id: 0,
        prev_hash: chain_start(&hdr),
        ts_wall: "2026-10-03T12:00:00.000Z".into(),
        ts_mono_delta: 0,
        session_id: [1; 16],
        event: "page.released".into(),
        key_id: key.fingerprint().0,
        schema_version: 1,
        segment_index: 0,
        sig_alg: 2,
        body_hash: format::body_hash(&body),
    }
    .encode();
    let sig = signer
        .sign(ogentic_audit_core::signed::NS_RECORD, &env)
        .unwrap();
    let mut out = hdr.to_vec();
    out.extend(format::frame(&env, &sig.0, Some(&body)));
    std::fs::write(seg(d.path(), 0), out).unwrap();
    assert_eq!(verify(d.path(), pin(1)), "AlgorithmMismatch@s0r0");
}

#[test]
fn b04_checkpoint_alg_flip_is_rejected() {
    let d = tempfile::tempdir().unwrap();
    write_log(d.path(), 3, true);
    let r = SignedVerifier::new(TrustContext::new())
        .verify(d.path())
        .unwrap();
    let (s, rid) = r.log.head.unwrap();
    let cp = CheckpointV2 {
        alg: SigAlg::Ed25519,
        key_id: r.log.key_id.unwrap(),
        head: Head {
            log_id: r.log.log_id.unwrap(),
            segment: s,
            record_id: rid,
            record_count: r.log.records_inspected,
            record_hash: r.log.final_record_hash.unwrap(),
        },
        head_ts_wall: r.log.head_ts_wall.clone().unwrap(),
        observed_at: Some("2026-10-03T12:00:00.000Z".into()),
    };
    let bytes = String::from_utf8(cp.to_bytes()).unwrap();
    for alt in ["ml-dsa-65", "ED25519", "ed25519 ", ""] {
        let flipped = bytes.replace("\"alg\":\"ed25519\"", &format!("\"alg\":\"{alt}\""));
        let opts = SignedVerifyOptions::new().checkpoint(SuppliedCheckpoint {
            bytes: flipped.into_bytes(),
            sig: None,
            witnesses: vec![],
        });
        let e = SignedVerifier::new(pin(1))
            .verify_with_options(d.path(), opts)
            .unwrap_err();
        assert!(
            matches!(e, SignedVerifyError::Checkpoint { .. }),
            "{alt}: {e:?}"
        );
    }
}

#[test]
fn b05_sshsig_type_strings_flipped_on_attestation() {
    let (_log, rel) = build_release();
    let sigp = rel.path().join("ogentic-audit-release.json.sig");
    let armored = std::fs::read(&sigp).unwrap();
    let blob = sshsig::dearmor(&armored).unwrap();
    let swap = |from: &[u8], to: &[u8], nth: usize| -> Vec<u8> {
        // Replace the nth occurrence of string(from) by string(to).
        let mut pat = (from.len() as u32).to_be_bytes().to_vec();
        pat.extend_from_slice(from);
        let mut rep = (to.len() as u32).to_be_bytes().to_vec();
        rep.extend_from_slice(to);
        let idx: Vec<usize> = blob
            .windows(pat.len())
            .enumerate()
            .filter(|(_, w)| *w == pat.as_slice())
            .map(|(i, _)| i)
            .collect();
        let i = idx[nth];
        let mut out = blob[..i].to_vec();
        out.extend(rep);
        out.extend_from_slice(&blob[i + pat.len()..]);
        // Fix the enclosing string lengths: only correct when sizes are equal.
        out
    };
    let cases: Vec<(Vec<u8>, &str)> = vec![
        (swap(b"sha512", b"sha256", 0), "hash_alg"),
        (swap(b"ssh-ed25519", b"ssh-ed25518", 0), "key_type"),
        (swap(b"ssh-ed25519", b"ssh-ed25518", 1), "key_type"),
        (
            swap(
                b"ogentic-audit/v0.2/release",
                b"ogentic-audit/v0.2/witness",
                0,
            ),
            "namespace",
        ),
    ];
    for (b, want) in cases {
        let text = format!(
            "-----BEGIN SSH SIGNATURE-----\n{}\n-----END SSH SIGNATURE-----\n",
            base64_encode(&b)
        );
        std::fs::write(&sigp, text).unwrap();
        let r = verify_release(rel.path(), &pin(1), &ReleaseOptions::new()).unwrap();
        assert_eq!(
            r.compact_verdict(),
            "SignatureInvalid@attestation",
            "{want}"
        );
        let reason = r.violations[0].reason.clone().unwrap_or_default();
        assert!(
            reason == want || reason == "malformed",
            "{want}: got {reason}"
        );
    }
}

fn base64_encode(b: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(b)
}

// ---------- 3. Non-canonical S (malleability) ----------

#[test]
fn c01_record_s_plus_kl_is_reencoded() {
    for k_mult in 1..=15u32 {
        let d = tempfile::tempdir().unwrap();
        write_log(d.path(), 4, true);
        let offs = sig_offsets(&seg(d.path(), 0));
        let o = offs[2];
        mutate(d.path(), 0, |b| {
            let mut s: [u8; 64] = b[o..o + 64].try_into().unwrap();
            for _ in 0..k_mult {
                s = reencode_s_plus_l(&s);
            }
            b[o..o + 64].copy_from_slice(&s);
        });
        let r = SignedVerifier::new(pin(1)).verify(d.path()).unwrap();
        // S + kL may overflow 256 bits for large k; then it is a different
        // scalar and must be a plain mismatch. Either way: SignatureInvalid@s0r2.
        assert_eq!(r.compact_verdict(), "SignatureInvalid@s0r2", "k={k_mult}");
        let reason = r.violations[0].reason.clone().unwrap();
        assert!(reason == "reencoded" || reason == "mismatch", "{reason}");
    }
}

#[test]
fn c02_record_s_plus_l_reason_is_reencoded() {
    let d = tempfile::tempdir().unwrap();
    write_log(d.path(), 4, true);
    let o = sig_offsets(&seg(d.path(), 0))[1];
    mutate(d.path(), 0, |b| {
        let s: [u8; 64] = b[o..o + 64].try_into().unwrap();
        b[o..o + 64].copy_from_slice(&reencode_s_plus_l(&s));
    });
    assert_eq!(verify(d.path(), pin(1)), "SignatureInvalid@s0r1");
    assert_eq!(first_reason(d.path(), pin(1)).as_deref(), Some("reencoded"));
    // Unpinned too: still a violation, never SelfConsistent.
    assert_eq!(
        verify(d.path(), TrustContext::new()),
        "SignatureInvalid@s0r1"
    );
}

#[test]
fn c03_record_s_high_bit_is_mismatch() {
    let d = tempfile::tempdir().unwrap();
    write_log(d.path(), 2, true);
    let o = sig_offsets(&seg(d.path(), 0))[0];
    mutate(d.path(), 0, |b| b[o + 63] |= 0x80);
    assert_eq!(verify(d.path(), pin(1)), "SignatureInvalid@s0r0");
    assert_eq!(first_reason(d.path(), pin(1)).as_deref(), Some("mismatch"));
}

#[test]
fn c04_record_r_non_canonical_encoding_is_rejected() {
    // R replaced by R' = R with sign bit set and x=0 is impossible for a
    // random R; instead replace R by a non-canonical y >= p encoding of a
    // small-y point (only those exist), keeping S.
    let d = tempfile::tempdir().unwrap();
    write_log(d.path(), 2, true);
    let o = sig_offsets(&seg(d.path(), 0))[0];
    for y in 0u8..19 {
        // y + p, little-endian: p = 2^255 - 19.
        let mut enc = [0xffu8; 32];
        enc[0] = 0xed + y;
        enc[31] = 0x7f;
        if CompressedEdwardsY(enc).decompress().is_none() {
            continue;
        }
        let dd = tempfile::tempdir().unwrap();
        for e in std::fs::read_dir(d.path()).unwrap() {
            let e = e.unwrap();
            std::fs::copy(e.path(), dd.path().join(e.file_name())).unwrap();
        }
        mutate(dd.path(), 0, |b| b[o..o + 32].copy_from_slice(&enc));
        assert_eq!(verify(dd.path(), pin(1)), "SignatureInvalid@s0r0", "y={y}");
    }
}

#[test]
fn c05_attestation_s_plus_l_is_reencoded() {
    let (_log, rel) = build_release();
    let sigp = rel.path().join("ogentic-audit-release.json.sig");
    let parsed = sshsig::parse_armored(&std::fs::read(&sigp).unwrap(), NS_RELEASE).unwrap();
    let re = reencode_s_plus_l(&parsed.signature);
    std::fs::write(&sigp, sshsig::armor(&parsed.key, NS_RELEASE, &re)).unwrap();
    let r = verify_release(rel.path(), &pin(1), &ReleaseOptions::new()).unwrap();
    assert_eq!(r.compact_verdict(), "SignatureInvalid@attestation");
    assert_eq!(r.violations[0].reason.as_deref(), Some("reencoded"));
    // Unpinned: still a violation.
    let r = verify_release(rel.path(), &TrustContext::new(), &ReleaseOptions::new()).unwrap();
    assert_eq!(r.compact_verdict(), "SignatureInvalid@attestation");
}

#[test]
fn c06_checkpoint_s_plus_l_is_signature_error() {
    let d = tempfile::tempdir().unwrap();
    write_log(d.path(), 3, false);
    let (cp_bytes, _) = checkpoint_for(d.path());
    let sig =
        ogentic_audit_core::signed::signer::sign_detached(&k(1), NS_CHECKPOINT, &cp_bytes).unwrap();
    let parsed = sshsig::parse_armored(sig.as_bytes(), NS_CHECKPOINT).unwrap();
    let re = sshsig::armor(
        &parsed.key,
        NS_CHECKPOINT,
        &reencode_s_plus_l(&parsed.signature),
    );
    let opts = SignedVerifyOptions::new().checkpoint(SuppliedCheckpoint {
        bytes: cp_bytes,
        sig: Some(re.into_bytes()),
        witnesses: vec![],
    });
    let e = SignedVerifier::new(pin(1))
        .verify_with_options(d.path(), opts)
        .unwrap_err();
    match e {
        SignedVerifyError::Checkpoint { kind, .. } => {
            assert_eq!(kind, "CheckpointSignatureInvalid")
        },
        other => panic!("{other:?}"),
    }
}

// ---------- 4. Small-order / weak / all-zero keys and signatures ----------

#[test]
fn d01_forged_log_under_each_small_order_key_is_weak_key() {
    for enc in SMALL_ORDER_ENCODINGS {
        let pk: [u8; 32] = unhex(enc).unwrap();
        for t in [TrustContext::new(), pin(1)] {
            let d = tempfile::tempdir().unwrap();
            forge_log(d.path(), pk, lax_forgery_sig(), 3);
            let r = SignedVerifier::new(t).verify(d.path()).unwrap();
            assert_eq!(r.compact_verdict(), "SignatureInvalid@s0", "{enc}");
            assert_eq!(r.violations[0].reason.as_deref(), Some("weak_key"), "{enc}");
        }
    }
}

#[test]
fn d02_forged_log_all_zero_key_and_sig() {
    let d = tempfile::tempdir().unwrap();
    forge_log(d.path(), [0u8; 32], [0u8; 64], 2);
    let r = SignedVerifier::new(TrustContext::new())
        .verify(d.path())
        .unwrap();
    assert_eq!(r.compact_verdict(), "SignatureInvalid@s0");
    assert_eq!(r.violations[0].reason.as_deref(), Some("weak_key"));
}

#[test]
fn d03_all_zero_record_signature_under_real_key_is_mismatch() {
    let d = tempfile::tempdir().unwrap();
    write_log(d.path(), 3, true);
    let o = sig_offsets(&seg(d.path(), 0))[1];
    mutate(d.path(), 0, |b| b[o..o + 64].fill(0));
    assert_eq!(verify(d.path(), pin(1)), "SignatureInvalid@s0r1");
    // R = identity, S = 0 under a strong key.
    mutate(d.path(), 0, |b| {
        b[o..o + 64].copy_from_slice(&lax_forgery_sig());
    });
    assert_eq!(verify(d.path(), pin(1)), "SignatureInvalid@s0r1");
    assert_eq!(first_reason(d.path(), pin(1)).as_deref(), Some("mismatch"));
}

fn mixed_order_key() -> (curve25519_dalek::Scalar, [u8; 32]) {
    // a from k(1)'s seed via ed25519-dalek's expanded key.
    let sk = ed25519_dalek::SigningKey::from_bytes(&unhex(SEEDS[0]).unwrap());
    let a_pt = CompressedEdwardsY(sk.verifying_key().to_bytes())
        .decompress()
        .unwrap();
    let t = CompressedEdwardsY(
        unhex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05").unwrap(),
    )
    .decompress()
    .unwrap();
    let scalar = sk.to_scalar();
    (scalar, (a_pt + t).compress().to_bytes())
}

#[test]
fn d04_mixed_order_header_key_is_weak_key_even_with_strict_valid_sigs() {
    // A' = A + T (T of order 8). Signatures (R, S = r + k a) satisfy the
    // cofactorless equation whenever k ≡ 0 (mod 8): grind body nonces until
    // verify_strict accepts every record, so only rule 3 can stop it.
    use sha2::{Digest, Sha512};
    let (a, apk) = mixed_order_key();
    let key = PublicKey::ed25519(apk);
    let hdr = SignedHeader::new(0, [9u8; 16], &key, [0u8; 32]).to_bytes();
    let mut out = hdr.to_vec();
    let mut prev = chain_start(&hdr);
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&apk).unwrap();
    let mut accepted_by_dalek_strict = 0;
    for i in 0..3u64 {
        let mut nonce_seed = 0u64;
        loop {
            nonce_seed += 1;
            let mut nb = [0u8; 32];
            nb[..8].copy_from_slice(&nonce_seed.to_le_bytes());
            nb[8] = i as u8;
            let body = encode_body("attacker", &BTreeMap::new(), &nb);
            let env = Envelope {
                record_id: i,
                prev_hash: prev,
                ts_wall: format!("2026-10-03T12:00:{:02}.000Z", i),
                ts_mono_delta: i,
                session_id: [1; 16],
                event: "page.released".into(),
                key_id: key.fingerprint().0,
                schema_version: 1,
                segment_index: 0,
                sig_alg: 1,
                body_hash: format::body_hash(&body),
            }
            .encode();
            let msg = sshsig::signed_data(ogentic_audit_core::signed::NS_RECORD, &env);
            let r = curve25519_dalek::Scalar::from_bytes_mod_order([7u8 + i as u8; 32]);
            let rp = curve25519_dalek::constants::ED25519_BASEPOINT_POINT * r;
            let rb = rp.compress().to_bytes();
            let mut h = Sha512::new();
            h.update(rb);
            h.update(apk);
            h.update(&msg);
            let kk = curve25519_dalek::Scalar::from_bytes_mod_order_wide(&h.finalize().into());
            let s = r + kk * a;
            let mut sig = [0u8; 64];
            sig[..32].copy_from_slice(&rb);
            sig[32..].copy_from_slice(s.as_bytes());
            if vk
                .verify_strict(&msg, &ed25519_dalek::Signature::from_bytes(&sig))
                .is_ok()
            {
                accepted_by_dalek_strict += 1;
                prev = format::record_hash(&env);
                out.extend(format::frame(&env, &sig, Some(&body)));
                break;
            }
            assert!(nonce_seed < 10_000);
        }
    }
    assert_eq!(accepted_by_dalek_strict, 3);
    let d = tempfile::tempdir().unwrap();
    std::fs::write(seg(d.path(), 0), out).unwrap();
    // Pin by fingerprint (a fingerprint cannot be checked for torsion).
    let mut t = TrustContext::new();
    t.pin_fingerprint(key.fingerprint(), Some("x"), Scope::DEFAULT)
        .unwrap();
    let r = SignedVerifier::new(t).verify(d.path()).unwrap();
    assert_eq!(r.compact_verdict(), "SignatureInvalid@s0");
    assert_eq!(r.violations[0].reason.as_deref(), Some("weak_key"));
    // And pinning the key itself is refused.
    assert!(TrustContext::new()
        .pin_key(key, None, Scope::DEFAULT)
        .is_err());
}

#[test]
fn d05_pins_of_weak_keys_refused_in_every_form() {
    let id = PublicKey::ed25519(unhex(IDENTITY).unwrap());
    let mut t = TrustContext::new();
    assert!(t.pin_key(id, None, Scope::DEFAULT).is_err());
    assert!(t.pin(&id.to_openssh(""), None, Scope::DEFAULT).is_err());
    assert!(t.pin(&id.to_pem(), None, Scope::DEFAULT).is_err());
    assert!(t
        .pin(&id.fingerprint().to_dashed_hex(), None, Scope::DEFAULT)
        .is_err());
    assert!(t
        .pin(&id.fingerprint().to_openssh(), None, Scope::DEFAULT)
        .is_err());
    assert!(t
        .add_allowed_signers(&format!("x {}", id.to_openssh("")))
        .is_err());
    let zero = PublicKey::ed25519([0u8; 32]);
    assert!(t
        .pin_fingerprint(zero.fingerprint(), None, Scope::DEFAULT)
        .is_err());
}

#[test]
fn d06_attestation_signed_under_identity_key_unpinned_is_weak_key() {
    let (_log, rel) = build_release();
    let id = PublicKey::ed25519(unhex(IDENTITY).unwrap());
    std::fs::write(
        rel.path().join("ogentic-audit-release.json.sig"),
        sshsig::armor(&id, NS_RELEASE, &lax_forgery_sig()),
    )
    .unwrap();
    let r = verify_release(rel.path(), &TrustContext::new(), &ReleaseOptions::new()).unwrap();
    assert_eq!(r.compact_verdict(), "SignatureInvalid@attestation");
    assert_eq!(r.violations[0].reason.as_deref(), Some("weak_key"));
    let r = verify_release(rel.path(), &pin(1), &ReleaseOptions::new()).unwrap();
    assert_eq!(r.compact_verdict(), "UntrustedSigner@attestation");
}

#[test]
fn d07_attestation_all_zero_key_and_sig_unpinned() {
    let (_log, rel) = build_release();
    std::fs::write(
        rel.path().join("ogentic-audit-release.json.sig"),
        sshsig::armor(&PublicKey::ed25519([0; 32]), NS_RELEASE, &[0u8; 64]),
    )
    .unwrap();
    let r = verify_release(rel.path(), &TrustContext::new(), &ReleaseOptions::new()).unwrap();
    assert_eq!(r.compact_verdict(), "SignatureInvalid@attestation");
    assert_eq!(r.violations[0].reason.as_deref(), Some("weak_key"));
}

#[test]
fn d08_checkpoint_sig_under_identity_key_is_error() {
    // Genuine log; operator-supplied checkpoint whose .sig is the lax
    // forgery under the identity key, and which names that key.
    let d = tempfile::tempdir().unwrap();
    write_log(d.path(), 3, false);
    let (_, mut cp) = checkpoint_for(d.path());
    let id = PublicKey::ed25519(unhex(IDENTITY).unwrap());
    cp.key_id = id.fingerprint();
    let bytes = cp.to_bytes();
    for t in [TrustContext::new(), pin(1)] {
        let opts = SignedVerifyOptions::new().checkpoint(SuppliedCheckpoint {
            bytes: bytes.clone(),
            sig: Some(sshsig::armor(&id, NS_CHECKPOINT, &lax_forgery_sig()).into_bytes()),
            witnesses: vec![],
        });
        let e = SignedVerifier::new(t)
            .verify_with_options(d.path(), opts)
            .unwrap_err();
        assert!(
            matches!(
                e,
                SignedVerifyError::Checkpoint {
                    kind: "CheckpointSignatureInvalid",
                    ..
                }
            ),
            "{e:?}"
        );
    }
}

/// A seed whose public key's fingerprint, read as 32 key bytes, is itself
/// a strong Ed25519 point (so the confusion pins a real, wrong key).
fn seed_with_strong_fingerprint() -> InMemorySigner {
    for i in 0u32.. {
        let mut seed = [0u8; 32];
        seed[..4].copy_from_slice(&i.to_le_bytes());
        let s = InMemorySigner::from_seed(seed);
        if PublicKey::ed25519(s.public_key().fingerprint().0).is_strong() {
            return s;
        }
    }
    unreachable!()
}

#[test]
fn f03_plain_hex_fingerprint_accuses_a_genuine_log() {
    let s = seed_with_strong_fingerprint();
    let d = tempfile::tempdir().unwrap();
    let mut w = SignedWriter::open_signed(d.path(), Box::new(s), [7u8; 16]).unwrap();
    w.append(input(0)).unwrap();
    w.seal().unwrap();
    w.flush().unwrap();
    let s = seed_with_strong_fingerprint();
    let fp_hex = s.public_key().fingerprint().to_hex();
    let mut t = TrustContext::new();
    t.pin(&fp_hex, None, Scope::DEFAULT).unwrap();
    // The operator supplied the right fingerprint of the right signer.
    assert_eq!(verify(d.path(), t), "Verified");
}

#[test]
fn d09_header_only_seg0_with_pinned_key_is_not_verified() {
    let d = tempfile::tempdir().unwrap();
    let hdr = SignedHeader::new(0, [9u8; 16], k(1).public_key(), [0u8; 32]).to_bytes();
    std::fs::write(seg(d.path(), 0), hdr).unwrap();
    let r = SignedVerifier::new(pin(1)).verify(d.path()).unwrap();
    assert_eq!(r.verdict, Verdict::SelfConsistent);
}

// ---------- 5. Releases: format confusion inside a bundle ----------

fn build_release() -> (tempfile::TempDir, tempfile::TempDir) {
    let log = tempfile::tempdir().unwrap();
    write_log(log.path(), 5, true);
    let rel = tempfile::tempdir().unwrap();
    std::fs::write(rel.path().join("page.pdf"), b"%PDF one").unwrap();
    let mut b = AttestationBuilder::new(rel.path(), "r1");
    b.created_at("2026-10-03T12:00:00.000Z");
    b.add_file(FileSpec::new("page.pdf").role("page"));
    b.add_log(LogSpec {
        source: log.path().to_path_buf(),
        path: "Audit log".into(),
        head: None,
        elide: vec![],
    });
    b.write(&k(1)).unwrap();
    assert_eq!(
        verify_release(rel.path(), &pin(1), &ReleaseOptions::new())
            .unwrap()
            .compact_verdict(),
        "Verified"
    );
    (log, rel)
}

fn checkpoint_for(dir: &Path) -> (Vec<u8>, CheckpointV2) {
    let r = SignedVerifier::new(TrustContext::new())
        .verify(dir)
        .unwrap();
    let (s, rid) = r.log.head.unwrap();
    let cp = CheckpointV2 {
        alg: SigAlg::Ed25519,
        key_id: r.log.key_id.unwrap(),
        head: Head {
            log_id: r.log.log_id.unwrap(),
            segment: s,
            record_id: rid,
            record_count: r.log.records_inspected,
            record_hash: r.log.final_record_hash.unwrap(),
        },
        head_ts_wall: r.log.head_ts_wall.clone().unwrap(),
        observed_at: Some("2026-10-03T12:00:00.000Z".into()),
    };
    (cp.to_bytes(), cp)
}

#[test]
fn e01_release_log_seg0_version_flipped_to_1_is_format_downgrade() {
    let (_log, rel) = build_release();
    let ld = rel.path().join("Audit log");
    mutate(&ld, 0, |b| {
        b[4] = 1;
        fix_crc(b);
    });
    let r = verify_release(rel.path(), &pin(1), &ReleaseOptions::new()).unwrap();
    assert_eq!(r.compact_verdict(), "FormatDowngrade@log:Audit log/s0");
}

#[test]
fn e02_release_log_seg0_newer_version_is_a_violation_not_an_upgrade_hint() {
    // Attacker alters a page AND flips the bundled log's version to 0x0003.
    let (_log, rel) = build_release();
    std::fs::write(rel.path().join("page.pdf"), b"%PDF TWO").unwrap();
    let ld = rel.path().join("Audit log");
    mutate(&ld, 0, |b| {
        b[4] = 3;
        fix_crc(b);
    });
    let r = verify_release(rel.path(), &pin(1), &ReleaseOptions::new());
    match r {
        Ok(rep) => {
            assert_eq!(rep.verdict, Verdict::Violation);
            assert!(rep
                .violations
                .iter()
                .any(|v| v.compact() == "FileAltered@file:page.pdf"));
            assert!(rep
                .violations
                .iter()
                .any(|v| v.compact().starts_with("log:") || v.compact().contains("@log:")));
        },
        Err(e) => panic!(
            "BYPASS-ish: the whole release report is replaced by an error ({e}); the altered page is never named"
        ),
    }
}

#[test]
fn e03_release_log_replaced_by_rolled_v02_with_hmac_seg0() {
    let (_log, rel) = build_release();
    let ld = rel.path().join("Audit log");
    let h = tempfile::tempdir().unwrap();
    write_hmac_log(h.path(), 2);
    std::fs::copy(seg(h.path(), 0), seg(&ld, 0)).unwrap();
    let r = verify_release(rel.path(), &pin(1), &ReleaseOptions::new()).unwrap();
    assert_eq!(r.compact_verdict(), "FormatDowngrade@log:Audit log/s0");
}

#[test]
fn e04_release_log_v01_segment_appended() {
    let (_log, rel) = build_release();
    let ld = rel.path().join("Audit log");
    let h = tempfile::tempdir().unwrap();
    write_hmac_log(h.path(), 2);
    std::fs::copy(seg(h.path(), 0), seg(&ld, 1)).unwrap();
    let r = verify_release(rel.path(), &pin(1), &ReleaseOptions::new()).unwrap();
    assert_eq!(r.verdict, Verdict::Violation);
    assert_eq!(r.compact_verdict(), "FormatDowngrade@log:Audit log/s1");
}

#[test]
fn e05_release_checkpoint_sig_replayed_as_attestation_sig_is_namespace() {
    let (_log, rel) = build_release();
    let att = std::fs::read(rel.path().join("ogentic-audit-release.json")).unwrap();
    // A genuine K1 signature over the same bytes, in the checkpoint namespace.
    let sig =
        ogentic_audit_core::signed::signer::sign_detached(&k(1), NS_CHECKPOINT, &att).unwrap();
    std::fs::write(rel.path().join("ogentic-audit-release.json.sig"), sig).unwrap();
    let r = verify_release(rel.path(), &pin(1), &ReleaseOptions::new()).unwrap();
    assert_eq!(r.compact_verdict(), "SignatureInvalid@attestation");
    assert_eq!(r.violations[0].reason.as_deref(), Some("namespace"));
}

// ---------- 6. Fingerprint / key confusion ----------

#[test]
fn f01_fingerprint_as_plain_64_hex_pins_the_fingerprint() {
    // Spec §3.7: a fingerprint is 64 hex digits after removing spaces, '-'
    // and ':'. The CLI's --key-fingerprint and Python's key_fingerprint call
    // TrustContext::pin, which tries PublicKey::parse first: 64 hex digits
    // are taken as RAW KEY BYTES, not as a fingerprint.
    let d = tempfile::tempdir().unwrap();
    write_log(d.path(), 3, true);
    for n in [1usize, 2] {
        let dd = tempfile::tempdir().unwrap();
        let mut w = SignedWriter::open_signed(dd.path(), Box::new(k(n)), [7u8; 16]).unwrap();
        w.append(input(0)).unwrap();
        w.flush().unwrap();
        let fp_hex = k(n).public_key().fingerprint().to_hex();
        let mut t = TrustContext::new();
        let pinned = t.pin(&fp_hex, None, Scope::DEFAULT);
        assert!(
            pinned.is_ok(),
            "k{n}: plain-hex fingerprint refused: {pinned:?}"
        );
        assert_eq!(verify(dd.path(), t), "Verified", "k{n}");
    }
}

#[test]
fn f02_fingerprint_uppercase_and_colon_forms_pin_the_fingerprint() {
    let d = tempfile::tempdir().unwrap();
    write_log(d.path(), 3, true);
    let fp = k(1).public_key().fingerprint().to_hex();
    let colon: String = fp
        .as_bytes()
        .chunks(2)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect::<Vec<_>>()
        .join(":");
    for form in [fp.to_uppercase(), colon, format!(" {fp} ")] {
        let mut t = TrustContext::new();
        let pinned = t.pin(&form, None, Scope::DEFAULT);
        assert!(pinned.is_ok(), "{form}: {pinned:?}");
        assert_eq!(verify(d.path(), t), "Verified", "{form}");
    }
}

#[test]
fn e06_release_segment_replaced_by_directory_still_reports() {
    let (_log, rel) = build_release();
    std::fs::write(rel.path().join("page.pdf"), b"%PDF TWO").unwrap();
    let ld = rel.path().join("Audit log");
    let h = tempfile::tempdir().unwrap();
    // seg 1 as a directory (seg 0 untouched).
    let _ = h;
    std::fs::create_dir(seg(&ld, 1)).unwrap();
    let r = verify_release(rel.path(), &pin(1), &ReleaseOptions::new());
    match r {
        Ok(rep) => assert!(rep
            .violations
            .iter()
            .any(|v| v.compact() == "FileAltered@file:page.pdf")),
        Err(e) => panic!("whole report replaced by an error: {e}"),
    }
}
