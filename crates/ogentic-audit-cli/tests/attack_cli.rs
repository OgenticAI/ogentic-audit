//! Adversarial CLI checks: format downgrade/confusion and fingerprint forms.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use ogentic_audit_core::signed::format::SignedHeader;
use ogentic_audit_core::signed::{
    unhex, AttestationBuilder, FileSpec, InMemorySigner, LogSpec, SignedWriter, Signer,
};
use ogentic_audit_core::{InMemoryKey, PayloadValue, RecordInput, Writer};
use predicates::prelude::*;

const K1: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const K1_FP: &str =
    "6db5-e9b8-a1ba-ce1c-dd9a-7c6a-db9e-9396-acc5-0734-65d9-fe8e-3a0e-f6d9-c60d-6d4f";

fn cmd() -> Command {
    let mut c = Command::cargo_bin("ogentic-audit").unwrap();
    c.env_remove("OGENTIC_AUDIT_KEY_HEX");
    c
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

fn signed_log_with(dir: &Path, s: InMemorySigner, n: u64) {
    let mut w = SignedWriter::open_signed(dir, Box::new(s), [1; 16]).unwrap();
    for i in 0..n {
        w.append(input(i)).unwrap();
    }
    w.seal().unwrap();
    w.flush().unwrap();
}

fn set_version(seg: &Path, v: u16) {
    let mut b = std::fs::read(seg).unwrap();
    let mut h = SignedHeader::from_bytes_unchecked(&b[..128].try_into().unwrap());
    h.version = v;
    b[..128].copy_from_slice(&h.to_bytes());
    std::fs::write(seg, b).unwrap();
}

fn build_release(root: &Path) -> PathBuf {
    let log = root.join("live-log");
    signed_log_with(&log, InMemorySigner::from_seed(unhex(K1).unwrap()), 5);
    let rel = root.join("release");
    std::fs::create_dir_all(&rel).unwrap();
    std::fs::write(rel.join("page.pdf"), b"%PDF one").unwrap();
    let mut b = AttestationBuilder::new(&rel, "r1");
    b.add_file(FileSpec::new("page.pdf").role("page"));
    b.add_log(LogSpec {
        source: log,
        path: "Audit log".into(),
        head: None,
        elide: vec![],
    });
    b.write(&InMemorySigner::from_seed(unhex(K1).unwrap()))
        .unwrap();
    rel
}

#[test]
fn cli01_plain_hex_fingerprint_verifies_genuine_log() {
    let t = tempfile::tempdir().unwrap();
    let log = t.path().join("log");
    signed_log_with(&log, InMemorySigner::from_seed(unhex(K1).unwrap()), 3);
    let plain: String = K1_FP.chars().filter(|c| *c != '-').collect();
    for fp in [plain.clone(), plain.to_uppercase()] {
        cmd()
            .arg("verify")
            .arg(&log)
            .args(["--key-fingerprint", &fp])
            .assert()
            .code(0);
    }
}

#[test]
fn cli02_plain_hex_fingerprint_of_strong_looking_key_not_untrusted() {
    // Seed chosen so the fingerprint bytes are a valid strong point: the
    // CLI then pins a *different key* and accuses the genuine log.
    let s = (0u32..)
        .map(|i| {
            let mut seed = [0u8; 32];
            seed[..4].copy_from_slice(&i.to_le_bytes());
            InMemorySigner::from_seed(seed)
        })
        .find(|s| {
            ogentic_audit_core::signed::PublicKey::ed25519(s.public_key().fingerprint().0)
                .is_strong()
        })
        .unwrap();
    let fp = s.public_key().fingerprint().to_hex();
    let t = tempfile::tempdir().unwrap();
    let log = t.path().join("log");
    signed_log_with(&log, s, 3);
    cmd()
        .arg("verify")
        .arg(&log)
        .args(["--key-fingerprint", &fp])
        .assert()
        .code(0);
}

#[test]
fn cli03_verify_release_newer_log_version_still_names_altered_file() {
    let t = tempfile::tempdir().unwrap();
    let rel = build_release(t.path());
    std::fs::write(rel.join("page.pdf"), b"%PDF TWO").unwrap();
    set_version(&rel.join("Audit log/audit-0000.cbor"), 3);
    cmd()
        .arg("verify-release")
        .arg(&rel)
        .args(["--key-fingerprint", K1_FP])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("page.pdf"));
}

#[test]
fn cli04_verify_release_hmac_version_flip_is_downgrade() {
    let t = tempfile::tempdir().unwrap();
    let rel = build_release(t.path());
    set_version(&rel.join("Audit log/audit-0000.cbor"), 1);
    cmd()
        .arg("verify-release")
        .arg(&rel)
        .args(["--key-fingerprint", K1_FP, "--format", "json"])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("FormatDowngrade"));
}

#[test]
fn cli05_hmac_log_with_pin_is_exit3_never_verified() {
    let t = tempfile::tempdir().unwrap();
    let log = t.path().join("log");
    let mut w = Writer::open(&log, Box::new(InMemoryKey::from_bytes([3; 32])), [0; 16]).unwrap();
    w.append(input(0)).unwrap();
    w.flush().unwrap();
    drop(w);
    for extra in [
        vec!["--key-fingerprint", K1_FP],
        vec!["--expect-log-id", "00000000000000000000000000000000"],
    ] {
        cmd()
            .env("OGENTIC_AUDIT_KEY_HEX", "03".repeat(32))
            .arg("verify")
            .arg(&log)
            .args(&extra)
            .assert()
            .code(3);
    }
    // Key only in the environment: never selected implicitly.
    cmd()
        .env("OGENTIC_AUDIT_KEY_HEX", "03".repeat(32))
        .arg("verify")
        .arg(&log)
        .assert()
        .code(3);
    // export and checkpoint: same rule.
    cmd()
        .env("OGENTIC_AUDIT_KEY_HEX", "03".repeat(32))
        .arg("export")
        .arg(&log)
        .args(["--pdf", t.path().join("x.pdf").to_str().unwrap()])
        .assert()
        .code(3);
    cmd()
        .env("OGENTIC_AUDIT_KEY_HEX", "03".repeat(32))
        .arg("checkpoint")
        .arg(&log)
        .assert()
        .code(3);
}

#[test]
fn cli06_signed_log_with_hmac_key_is_exit3_everywhere() {
    let t = tempfile::tempdir().unwrap();
    let log = t.path().join("log");
    signed_log_with(&log, InMemorySigner::from_seed(unhex(K1).unwrap()), 2);
    for sub in [vec!["verify"], vec!["checkpoint"]] {
        cmd()
            .args(["--key-source", "env"])
            .env("OGENTIC_AUDIT_KEY_HEX", "00".repeat(32))
            .args(&sub)
            .arg(&log)
            .assert()
            .code(3);
    }
}

#[test]
fn cli07_seg0_version_newer_is_exit3_not_verified() {
    let t = tempfile::tempdir().unwrap();
    let log = t.path().join("log");
    signed_log_with(&log, InMemorySigner::from_seed(unhex(K1).unwrap()), 2);
    set_version(&log.join("audit-0000.cbor"), 0xffff);
    cmd()
        .arg("verify")
        .arg(&log)
        .args(["--key-fingerprint", K1_FP])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("upgrade the verifier"));
}
