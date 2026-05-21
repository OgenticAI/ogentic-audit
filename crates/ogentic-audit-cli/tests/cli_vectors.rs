//! CLI integration tests against the v0.1 golden vectors.
//!
//! Drives the `ogentic-audit` binary via `assert_cmd` and asserts the
//! observable surface: exit codes, stdout content, JSON shape. These
//! are the end-to-end correctness gate for C1 + C2.

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

#[test]
fn verify_clean_vector_exits_zero() {
    let key_hex = vector_key_hex("single-record");
    cmd()
        .env("OGENTIC_AUDIT_KEY_HEX", key_hex)
        .arg("verify")
        .arg(vectors_dir().join("single-record"))
        .assert()
        .success()
        .stdout(predicate::str::contains("verdict:           Verified"));
}

#[test]
fn verify_tampered_vector_exits_one_and_reports_hmac_mismatch() {
    let key_hex = vector_key_hex("tampered-byte");
    cmd()
        .env("OGENTIC_AUDIT_KEY_HEX", key_hex)
        .arg("verify")
        .arg(vectors_dir().join("tampered-byte"))
        .assert()
        .code(1)
        .stdout(predicate::str::contains("HmacMismatch@s0r2"));
}

#[test]
fn verify_missing_record_vector_reports_chain_break() {
    let key_hex = vector_key_hex("missing-record");
    cmd()
        .env("OGENTIC_AUDIT_KEY_HEX", key_hex)
        .arg("verify")
        .arg(vectors_dir().join("missing-record"))
        .assert()
        .code(1)
        .stdout(predicate::str::contains("ChainBreak@s0r3"));
}

#[test]
fn verify_json_format_emits_parseable_object() {
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
    assert_eq!(value["verdict"], "Verified");
    assert_eq!(value["compact"], "Verified");
    assert_eq!(value["log"]["segments_inspected"], 1);
}

#[test]
fn head_single_record_prints_one_line_summary() {
    cmd()
        .arg("head")
        .arg(vectors_dir().join("single-record"))
        .assert()
        .success()
        .stdout(predicate::str::contains("records=1 segments=1"));
}

#[test]
fn head_json_format_includes_head_hmac_hex() {
    let assert = cmd()
        .arg("head")
        .arg("--format")
        .arg("json")
        .arg(vectors_dir().join("single-record"))
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("JSON parses");
    assert_eq!(value["record_count"], 1);
    assert!(value["head_hmac_hex"].is_string());
}

#[test]
fn head_empty_vector_reports_empty() {
    cmd()
        .arg("head")
        .arg(vectors_dir().join("empty"))
        .assert()
        .success()
        .stdout(predicate::str::contains("(empty log; no records)"));
}

#[test]
fn show_single_record_prints_event() {
    cmd()
        .arg("show")
        .arg(vectors_dir().join("single-record"))
        .assert()
        .success()
        .stdout(predicate::str::contains("vault.unlocked"));
}

#[test]
fn show_from_to_range_filters() {
    // 1k-records vector has record_ids 0..1000; --from 5 --to 10
    // should print exactly 5 records (5,6,7,8,9).
    let assert = cmd()
        .arg("show")
        .arg("--from")
        .arg("5")
        .arg("--to")
        .arg("10")
        .arg("--format")
        .arg("json")
        .arg(vectors_dir().join("1k-records"))
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(
        lines.len(),
        5,
        "expected 5 records in stdout, got {}",
        lines.len()
    );
}

#[test]
fn show_event_glob_filters() {
    // 1k-records vector has thousands of records; a non-matching glob
    // must return zero lines.
    let assert = cmd()
        .arg("show")
        .arg("--event-glob")
        .arg("nope.*")
        .arg("--format")
        .arg("json")
        .arg(vectors_dir().join("1k-records"))
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(
        stdout.trim().is_empty(),
        "expected no records for non-matching glob"
    );
}

#[test]
fn missing_log_dir_exits_io_error() {
    cmd()
        .arg("verify")
        .arg("/nonexistent-path-for-cli-test")
        .env("OGENTIC_AUDIT_KEY_HEX", "00".repeat(32))
        .assert()
        .code(2);
}

#[test]
fn unset_key_env_returns_argument_error_for_verify() {
    cmd()
        .env_remove("OGENTIC_AUDIT_KEY_HEX")
        .arg("verify")
        .arg(vectors_dir().join("single-record"))
        .assert()
        .code(3);
}

#[test]
fn help_text_lists_subcommands() {
    cmd()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("verify"))
        .stdout(predicate::str::contains("show"))
        .stdout(predicate::str::contains("head"))
        .stdout(predicate::str::contains("export"));
}

#[test]
fn verify_subcommand_help_shows_examples() {
    cmd()
        .arg("verify")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Examples:"))
        .stdout(predicate::str::contains("--format json"));
}

#[test]
fn version_subcommand_prints_versions() {
    cmd()
        .arg("version")
        .assert()
        .success()
        .stdout(predicate::str::contains("ogentic-audit"))
        .stdout(predicate::str::contains("format v0x0001"));
}

#[test]
fn export_stub_exits_zero_with_message() {
    let tmp = tempfile::tempdir().unwrap();
    let pdf_path = tmp.path().join("out.pdf");
    cmd()
        .arg("export")
        .arg(vectors_dir().join("single-record"))
        .arg("--pdf")
        .arg(&pdf_path)
        .assert()
        .success()
        .stderr(predicate::str::contains("not yet implemented"))
        .stderr(predicate::str::contains("OGE-438"));
}
