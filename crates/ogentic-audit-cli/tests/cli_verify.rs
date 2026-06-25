//! `ogentic-audit verify` integration tests — OGE-1063.
//!
//! Covers the new `--segment` flag, the updated JSON shape (`status`
//! instead of `verdict` / `compact`), and stderr routing for violation
//! detail text.
//!
//! Test style mirrors `cli_vectors.rs`: drives the binary via
//! `assert_cmd`, loads the HMAC key from each vector's `inputs.json`.

use std::fs;
use std::path::PathBuf;

use assert_cmd::Command;
use predicates::prelude::*;

// ---------------------------------------------------------------------------
// helpers (same pattern as cli_vectors.rs)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// 1. verify_clean_exits_zero
// ---------------------------------------------------------------------------

#[test]
fn verify_clean_exits_zero() {
    let key_hex = vector_key_hex("single-record");
    cmd()
        .env("OGENTIC_AUDIT_KEY_HEX", key_hex)
        .arg("verify")
        .arg(vectors_dir().join("single-record"))
        .assert()
        .success();
}

// ---------------------------------------------------------------------------
// 2. verify_tampered_exits_one
// ---------------------------------------------------------------------------

#[test]
fn verify_tampered_exits_one() {
    let key_hex = vector_key_hex("tampered-byte");
    cmd()
        .env("OGENTIC_AUDIT_KEY_HEX", key_hex)
        .arg("verify")
        .arg(vectors_dir().join("tampered-byte"))
        .assert()
        .code(1);
}

// ---------------------------------------------------------------------------
// 3. verify_missing_dir_exits_two
// ---------------------------------------------------------------------------

#[test]
fn verify_missing_dir_exits_two() {
    cmd()
        .env("OGENTIC_AUDIT_KEY_HEX", "00".repeat(32))
        .arg("verify")
        .arg("/tmp/nonexistent_audit_dir_xyz_oge1063")
        .assert()
        .code(2);
}

// ---------------------------------------------------------------------------
// 4. verify_json_status_ok
// ---------------------------------------------------------------------------

#[test]
fn verify_json_status_ok() {
    let key_hex = vector_key_hex("single-record");
    let assert = cmd()
        .env("OGENTIC_AUDIT_KEY_HEX", key_hex)
        .arg("verify")
        .arg("--format")
        .arg("json")
        .arg(vectors_dir().join("single-record"))
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("JSON parses");
    assert_eq!(value["status"], "ok", "expected status=ok, got {value}");
    assert!(
        value["segments_verified"].is_number(),
        "expected segments_verified to be a number, got {value}"
    );
}

// ---------------------------------------------------------------------------
// 5. verify_json_status_tampered
// ---------------------------------------------------------------------------

#[test]
fn verify_json_status_tampered() {
    let key_hex = vector_key_hex("tampered-byte");
    let assert = cmd()
        .env("OGENTIC_AUDIT_KEY_HEX", key_hex)
        .arg("verify")
        .arg("--format")
        .arg("json")
        .arg(vectors_dir().join("tampered-byte"))
        .assert()
        .code(1);
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("JSON parses");
    assert_eq!(
        value["status"], "tampered",
        "expected status=tampered, got {value}"
    );
    assert!(
        value["violation"]["kind"].is_string(),
        "expected violation.kind to be a string, got {value}"
    );
}

// ---------------------------------------------------------------------------
// 6. verify_json_no_verdict_key
// ---------------------------------------------------------------------------

#[test]
fn verify_json_no_verdict_key() {
    let key_hex = vector_key_hex("single-record");
    let assert = cmd()
        .env("OGENTIC_AUDIT_KEY_HEX", key_hex)
        .arg("verify")
        .arg("--format")
        .arg("json")
        .arg(vectors_dir().join("single-record"))
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("JSON parses");
    assert!(
        value["verdict"].is_null(),
        "expected no 'verdict' key in JSON output, got {value}"
    );
}

// ---------------------------------------------------------------------------
// 7. verify_json_no_compact_key
// ---------------------------------------------------------------------------

#[test]
fn verify_json_no_compact_key() {
    let key_hex = vector_key_hex("single-record");
    let assert = cmd()
        .env("OGENTIC_AUDIT_KEY_HEX", key_hex)
        .arg("verify")
        .arg("--format")
        .arg("json")
        .arg(vectors_dir().join("single-record"))
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("JSON parses");
    assert!(
        value["compact"].is_null(),
        "expected no 'compact' key in JSON output, got {value}"
    );
}

// ---------------------------------------------------------------------------
// 8. verify_segment_valid_exits_zero
//    segment-rollover vector has segments 0, 1, 2; --segment 0 → exit 0
// ---------------------------------------------------------------------------

#[test]
fn verify_segment_valid_exits_zero() {
    let key_hex = vector_key_hex("segment-rollover");
    cmd()
        .env("OGENTIC_AUDIT_KEY_HEX", key_hex)
        .arg("verify")
        .arg("--segment")
        .arg("0")
        .arg(vectors_dir().join("segment-rollover"))
        .assert()
        .success();
}

// ---------------------------------------------------------------------------
// 9. verify_segment_invalid_exits_two
//    single-record vector only has segment 0; --segment 99 → exit 2
// ---------------------------------------------------------------------------

#[test]
fn verify_segment_invalid_exits_two() {
    let key_hex = vector_key_hex("single-record");
    cmd()
        .env("OGENTIC_AUDIT_KEY_HEX", key_hex)
        .arg("verify")
        .arg("--segment")
        .arg("99")
        .arg(vectors_dir().join("single-record"))
        .assert()
        .code(2);
}

// ---------------------------------------------------------------------------
// 10. verify_segment_zero_is_valid
//     --segment 0 must work (guard against falsy-zero being treated as
//     "no segment specified").
// ---------------------------------------------------------------------------

#[test]
fn verify_segment_zero_is_valid() {
    let key_hex = vector_key_hex("single-record");
    cmd()
        .env("OGENTIC_AUDIT_KEY_HEX", key_hex)
        .arg("verify")
        .arg("--segment")
        .arg("0")
        .arg(vectors_dir().join("single-record"))
        .assert()
        .success();
}

// ---------------------------------------------------------------------------
// 11. verify_segment_and_forensic_compatible
//     --segment and --forensic may be combined.
// ---------------------------------------------------------------------------

#[test]
fn verify_segment_and_forensic_compatible() {
    let key_hex = vector_key_hex("single-record");
    cmd()
        .env("OGENTIC_AUDIT_KEY_HEX", key_hex)
        .arg("verify")
        .arg("--segment")
        .arg("0")
        .arg("--forensic")
        .arg(vectors_dir().join("single-record"))
        .assert()
        .success();
}

// ---------------------------------------------------------------------------
// 12. verify_text_violation_on_stderr
//     Tampered-byte vector; violation detail text MUST appear on stderr,
//     NOT stdout. Accepts "TAMPER", "HmacMismatch", or any violation
//     indicator on stderr.
// ---------------------------------------------------------------------------

#[test]
fn verify_text_violation_on_stderr() {
    let key_hex = vector_key_hex("tampered-byte");
    let assert = cmd()
        .env("OGENTIC_AUDIT_KEY_HEX", key_hex)
        .arg("verify")
        .arg(vectors_dir().join("tampered-byte"))
        .assert()
        .code(1);

    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    let has_violation_info = stderr.contains("TAMPER")
        || stderr.contains("HmacMismatch")
        || stderr.contains("violation")
        || stderr.contains("kind:");
    assert!(
        has_violation_info,
        "expected violation detail on stderr, got stderr={stderr:?}"
    );
}

// ---------------------------------------------------------------------------
// 13. verify_summary_on_stdout
//     Clean single-record vector with --summary; stdout must contain the
//     verified indicator.
// ---------------------------------------------------------------------------

#[test]
fn verify_summary_on_stdout() {
    let key_hex = vector_key_hex("single-record");
    cmd()
        .env("OGENTIC_AUDIT_KEY_HEX", key_hex)
        .arg("verify")
        .arg("--summary")
        .arg(vectors_dir().join("single-record"))
        .assert()
        .success()
        .stdout(predicate::str::contains("Verified"));
}

// ---------------------------------------------------------------------------
// 14. verify_tenant_isolation
//     Dir A holds a clean log segment; dir B holds a tampered segment.
//     Verifying A must return exit 0 regardless of what B contains, and
//     verifying A again after B proves no shared-state contamination.
// ---------------------------------------------------------------------------

#[test]
fn verify_tenant_isolation() {
    let key_hex = vector_key_hex("single-record");

    // Dir A — clean copy of the single-record vector.
    let tmp_a = tempfile::tempdir().unwrap();
    let clean_src = vectors_dir().join("single-record").join("audit-0000.cbor");
    fs::copy(&clean_src, tmp_a.path().join("audit-0000.cbor")).unwrap();

    // Dir B — tampered copy (use the tampered-byte vector's segment).
    // The key for tampered-byte is the same family, but the payload has
    // a flipped byte so the verifier reports HmacMismatch on it.
    let tampered_key_hex = vector_key_hex("tampered-byte");
    let tmp_b = tempfile::tempdir().unwrap();
    let tampered_src = vectors_dir().join("tampered-byte").join("audit-0000.cbor");
    fs::copy(&tampered_src, tmp_b.path().join("audit-0000.cbor")).unwrap();

    // 1. Verify A (clean) → must succeed (exit 0).
    cmd()
        .env("OGENTIC_AUDIT_KEY_HEX", &key_hex)
        .arg("verify")
        .arg(tmp_a.path())
        .assert()
        .success();

    // 2. Verify B (tampered) → must fail (exit 1).
    cmd()
        .env("OGENTIC_AUDIT_KEY_HEX", &tampered_key_hex)
        .arg("verify")
        .arg(tmp_b.path())
        .assert()
        .code(1);

    // 3. Verify A again → must still succeed (no state contamination from B).
    cmd()
        .env("OGENTIC_AUDIT_KEY_HEX", &key_hex)
        .arg("verify")
        .arg(tmp_a.path())
        .assert()
        .success();
}

// ---------------------------------------------------------------------------
// 15. verify_segment_nonzero_valid_exits_zero  (C2 fix)
//     segment-rollover has segments 0, 1, 2. Verifying --segment 1 on a
//     fully intact multi-segment log must exit 0, not produce a false
//     HmacMismatch from the old tempdir-as-genesis hack.
// ---------------------------------------------------------------------------

#[test]
fn verify_segment_nonzero_valid_exits_zero() {
    let key_hex = vector_key_hex("segment-rollover");
    cmd()
        .env("OGENTIC_AUDIT_KEY_HEX", key_hex)
        .arg("verify")
        .arg("--segment")
        .arg("1")
        .arg(vectors_dir().join("segment-rollover"))
        .assert()
        .success();
}

// ---------------------------------------------------------------------------
// 16. verify_segment_two_valid_exits_zero
//     --segment 2 on the same multi-segment log must also exit 0.
// ---------------------------------------------------------------------------

#[test]
fn verify_segment_two_valid_exits_zero() {
    let key_hex = vector_key_hex("segment-rollover");
    cmd()
        .env("OGENTIC_AUDIT_KEY_HEX", key_hex)
        .arg("verify")
        .arg("--segment")
        .arg("2")
        .arg(vectors_dir().join("segment-rollover"))
        .assert()
        .success();
}

// ---------------------------------------------------------------------------
// 17. verify_segment_overflow_exits_three  (I1 fix)
//     --segment 65536 exceeds the u16 max; must be an ArgumentError (exit 3),
//     not an IoError (exit 2).
// ---------------------------------------------------------------------------

#[test]
fn verify_segment_overflow_exits_three() {
    cmd()
        .env("OGENTIC_AUDIT_KEY_HEX", "00".repeat(32))
        .arg("verify")
        .arg("--segment")
        .arg("65536")
        .arg(vectors_dir().join("single-record"))
        .assert()
        .code(3);
}
