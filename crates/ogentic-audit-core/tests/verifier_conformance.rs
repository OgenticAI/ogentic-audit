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

#[test]
fn verify_tampered_byte_vector_reports_hmac_mismatch() {
    verify_vector("tampered-byte");
}

#[test]
fn verify_missing_record_vector_reports_chain_break() {
    verify_vector("missing-record");
}
