//! `ogentic-audit checkpoint` / `verify --checkpoint` — OGE-1671.
//!
//! Exercises the operator-facing half of checkpoint anchoring. The
//! cryptographic behaviour (rewrite and truncation detection) is covered
//! in `ogentic-audit-core/tests/checkpoint_anchor.rs`; these tests cover
//! the artifact round-trip and the exit codes automation depends on.

use std::fs;
use std::path::PathBuf;

use assert_cmd::Command;
use predicates::prelude::*;

fn vectors_dir() -> PathBuf {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    PathBuf::from(manifest).join("../../tests/vectors/v0.1")
}

fn vector_key_hex(name: &str) -> String {
    let inputs: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(vectors_dir().join(name).join("inputs.json")).unwrap(),
    )
    .unwrap();
    inputs["key_hex"].as_str().unwrap().to_string()
}

fn cmd() -> Command {
    Command::cargo_bin("ogentic-audit").unwrap()
}

/// A checkpoint over a clean log emits the documented v1 shape.
#[test]
fn checkpoint_emits_v1_artifact() {
    let key_hex = vector_key_hex("single-record");
    let out = cmd()
        .env("OGENTIC_AUDIT_KEY_HEX", key_hex)
        .arg("checkpoint")
        .arg(vectors_dir().join("single-record"))
        .arg("--observed-at")
        .arg("2026-07-20T20:00:00Z")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let parsed: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(parsed["format"], "ogentic-audit-checkpoint/v1");
    assert_eq!(parsed["observed_at"], "2026-07-20T20:00:00Z");
    assert_eq!(parsed["segment"], 0);
    // 32-byte values, lowercase hex.
    assert_eq!(parsed["hmac"].as_str().unwrap().len(), 64);
    assert_eq!(parsed["key_id"].as_str().unwrap().len(), 64);
}

/// Round-trip: a checkpoint taken from a log verifies against that log.
#[test]
fn verify_accepts_a_checkpoint_from_the_same_log() {
    let key_hex = vector_key_hex("single-record");
    let tmp = tempfile::tempdir().unwrap();
    let cp_path = tmp.path().join("cp.json");

    cmd()
        .env("OGENTIC_AUDIT_KEY_HEX", &key_hex)
        .arg("checkpoint")
        .arg(vectors_dir().join("single-record"))
        .arg("--out")
        .arg(&cp_path)
        .assert()
        .success();

    cmd()
        .env("OGENTIC_AUDIT_KEY_HEX", &key_hex)
        .arg("verify")
        .arg(vectors_dir().join("single-record"))
        .arg("--checkpoint")
        .arg(&cp_path)
        .assert()
        .success();
}

/// A checkpoint from a different log is an operator mistake: exit 3
/// (argument error), not exit 1 (tamper). Confusing the two would teach
/// operators that a wrong filename looks like an attack.
#[test]
fn verify_rejects_a_checkpoint_from_another_log() {
    let key_hex = vector_key_hex("single-record");
    let tmp = tempfile::tempdir().unwrap();
    let cp_path = tmp.path().join("cp.json");

    cmd()
        .env("OGENTIC_AUDIT_KEY_HEX", &key_hex)
        .arg("checkpoint")
        .arg(vectors_dir().join("single-record"))
        .arg("--out")
        .arg(&cp_path)
        .assert()
        .success();

    // Re-point the checkpoint at a different key's log.
    let mut json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&cp_path).unwrap()).unwrap();
    json["key_id"] = serde_json::Value::String("aa".repeat(32));
    fs::write(&cp_path, serde_json::to_string(&json).unwrap()).unwrap();

    cmd()
        .env("OGENTIC_AUDIT_KEY_HEX", &key_hex)
        .arg("verify")
        .arg(vectors_dir().join("single-record"))
        .arg("--checkpoint")
        .arg(&cp_path)
        .assert()
        .code(3)
        .stderr(predicate::str::contains("different log"));
}

/// A malformed checkpoint must not be silently ignored — that would
/// render a `--checkpoint` run indistinguishable from a plain one while
/// looking stricter.
#[test]
fn verify_rejects_a_malformed_checkpoint() {
    let key_hex = vector_key_hex("single-record");
    let tmp = tempfile::tempdir().unwrap();
    let cp_path = tmp.path().join("cp.json");
    fs::write(&cp_path, "{\"format\":\"nope\"}").unwrap();

    cmd()
        .env("OGENTIC_AUDIT_KEY_HEX", key_hex)
        .arg("verify")
        .arg(vectors_dir().join("single-record"))
        .arg("--checkpoint")
        .arg(&cp_path)
        .assert()
        .code(3);
}

/// Refuse to anchor a chain that does not verify: a checkpoint over a
/// broken chain would launder the break into trusted history.
#[test]
fn checkpoint_refuses_a_tampered_log() {
    let name = "tampered-byte";
    let dir = vectors_dir().join(name);
    assert!(
        dir.exists(),
        "the tampered-byte vector is required by this test; if it was renamed, \
         update this test rather than skipping it"
    );

    cmd()
        .env("OGENTIC_AUDIT_KEY_HEX", vector_key_hex(name))
        .arg("checkpoint")
        .arg(&dir)
        .assert()
        .code(1)
        .stderr(predicate::str::contains("refusing to checkpoint"));
}
