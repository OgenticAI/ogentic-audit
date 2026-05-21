//! Shared fixtures for the integration test suite (Q1 / OGE-440).
//!
//! Lives at `tests/common/mod.rs` so every integration test can pull it
//! in via `mod common;` without recompiling helpers per test binary.
//!
//! Intentionally narrow: just the pieces multiple test files actually
//! share (key + session hex, sample record builder, hex decoders).
//! Anything test-specific stays inside the test that owns it.

#![allow(dead_code)] // some helpers are only used by some test binaries

use std::collections::BTreeMap;

use ogentic_audit_core::{PayloadValue, RecordInput, SESSION_ID_LEN};

/// Stable 32-byte HMAC-SHA256 key used across every Q1 / Q2 test.
pub const KEY_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

/// Stable 16-byte session_id used across every Q1 / Q2 test.
pub const SESSION_HEX: &str = "00112233445566778899aabbccddeeff";

/// Decode a 64-char hex string into a `[u8; 32]`.
pub fn hex32(s: &str) -> [u8; 32] {
    assert_eq!(s.len(), 64);
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}

/// Decode a 32-char hex string into a `[u8; 16]`.
pub fn hex16(s: &str) -> [u8; SESSION_ID_LEN] {
    assert_eq!(s.len(), 32);
    let mut out = [0u8; SESSION_ID_LEN];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}

/// Build a small deterministic `RecordInput` keyed off the integer
/// `record_id` — used by the property tests and the tamper matrix.
pub fn sample_record(record_id: u64) -> RecordInput {
    let mut payload = BTreeMap::new();
    payload.insert("i".to_string(), PayloadValue::Uint(record_id));
    payload.insert(
        "decision".to_string(),
        PayloadValue::Text(if record_id % 2 == 0 { "allow" } else { "deny" }.into()),
    );
    RecordInput {
        ts_wall: format!("2026-05-21T05:00:{:02}.000Z", (record_id % 60) as u32),
        ts_mono_delta: record_id * 1000,
        actor: "user:q1".into(),
        event: "q1.tick".into(),
        payload,
        schema_version: 1,
    }
}
