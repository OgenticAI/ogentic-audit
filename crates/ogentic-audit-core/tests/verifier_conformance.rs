//! Verifier conformance against the v0.1 golden vectors.
//!
//! For every committed vector, drive the Verifier against the on-disk
//! segment files and assert the compact verdict matches the vector's
//! `expected_verdict` field. This is the load-bearing correctness gate
//! for [OGE-437 R3] AC 5 ("All golden vectors pass; tampered vectors
//! return the expected violation kind").
//!
//! [OGE-437 R3]: https://linear.app/ogenticai/issue/OGE-437

use std::fs;
use std::path::{Path, PathBuf};

use ogentic_audit_core::{InMemoryKey, Verifier};
use serde::Deserialize;

fn vectors_dir() -> PathBuf {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest.join("../../tests/vectors/v0.1")
}

#[derive(Deserialize)]
struct VectorInputs {
    key_hex: String,
    expected_verdict: String,
}

fn decode_hex_32(s: &str) -> [u8; 32] {
    assert_eq!(s.len(), 64, "expected 64-char hex; got {s:?}");
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}

fn verify_vector(name: &str) {
    let vec_dir = vectors_dir().join(name);
    let inputs_text = fs::read_to_string(vec_dir.join("inputs.json")).expect("read inputs.json");
    let spec: VectorInputs = serde_json::from_str(&inputs_text).expect("parse inputs.json");

    let key = InMemoryKey::from_bytes(decode_hex_32(&spec.key_hex));
    let verifier = Verifier::new(Box::new(key));
    let report = verifier.verify(&vec_dir).expect("verifier ran");

    assert_eq!(
        report.compact_verdict(),
        spec.expected_verdict,
        "vector {name}: report = {:#?}",
        report,
    );
}

#[test]
fn verify_empty_vector() {
    verify_vector("empty");
}

#[test]
fn verify_single_record_vector() {
    verify_vector("single-record");
}

#[test]
fn verify_one_thousand_records_vector() {
    verify_vector("1k-records");
}

#[test]
fn verify_segment_rollover_vector() {
    verify_vector("segment-rollover");
}

// A record carrying a policy attestation (OGE-1674) in its payload is an
// ordinary v0.1 record: the verifier is unaware of the convention and the
// chain verifies clean, because the policy data is inside the HMAC'd bytes.
#[test]
fn verify_policy_permit_vector() {
    verify_vector("policy-permit");
}

#[test]
fn verify_policy_deny_vector() {
    verify_vector("policy-deny");
}

#[test]
fn verify_tampered_byte_vector_reports_hmac_mismatch() {
    verify_vector("tampered-byte");
}

#[test]
fn verify_missing_record_vector_reports_chain_break() {
    verify_vector("missing-record");
}

/// A directory with no segment files is not a verified log. 0.3.0 returned
/// `Verified` with zero records inspected, so a deleted log, or a typo in the
/// path, read as intact.
#[test]
fn a_directory_with_no_segments_is_an_error_not_verified() {
    let dir = tempfile::TempDir::new().unwrap();
    let verifier = Verifier::new(Box::new(InMemoryKey::from_bytes([0u8; 32])));
    match verifier.verify(dir.path()) {
        Err(ogentic_audit_core::VerifyError::NoSegments { log_dir }) => {
            assert_eq!(log_dir, dir.path());
        },
        other => panic!("expected NoSegments, got {other:?}"),
    }
}

/// Deleting every segment of a real log must not verify either.
#[test]
fn a_log_whose_segments_were_deleted_does_not_verify() {
    let src = vectors_dir().join("single-record");
    let dir = tempfile::TempDir::new().unwrap();
    for entry in fs::read_dir(&src).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|e| e != "cbor") {
            fs::copy(&path, dir.path().join(path.file_name().unwrap())).unwrap();
        }
    }
    let spec: VectorInputs =
        serde_json::from_str(&fs::read_to_string(src.join("inputs.json")).unwrap()).unwrap();
    let verifier = Verifier::new(Box::new(InMemoryKey::from_bytes(decode_hex_32(
        &spec.key_hex,
    ))));
    assert!(matches!(
        verifier.verify(dir.path()),
        Err(ogentic_audit_core::VerifyError::NoSegments { .. })
    ));
}
