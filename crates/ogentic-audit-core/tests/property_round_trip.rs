//! Property-based round-trip tests (Q1 / OGE-440 AC 1).
//!
//! Generate random sequences of records via `proptest`, drive them
//! through R1 Writer, R2 Reader, and R3 Verifier, and assert the
//! chain invariants always hold:
//!
//! * Every record we wrote appears back from the reader in the same
//!   order, with the same fields the caller supplied.
//! * The verifier returns "Verified" on the resulting log.
//! * Re-opening the writer on the directory and appending more records
//!   keeps the chain verifiable.
//!
//! AC requirement: ≥1000 sequences per CI run. We set
//! `ProptestConfig::cases = 1024` which gives proptest 1024 generated
//! cases per #[test] (and proptest does additional shrinking work on
//! failure).
//!
//! Deterministic: proptest seeds its RNG from
//! `PROPTEST_REPLAY` / `PROPTEST_SEED` env vars (or `RUST_TEST_*`).
//! Failures emit a regression to `proptest-regressions/` which we
//! commit as needed.

mod common;

use std::collections::BTreeMap;

use ogentic_audit_core::{
    InMemoryKey, PayloadValue, Reader, RecordInput, Verifier, Writer, WriterConfig,
};
use proptest::prelude::*;

use common::{hex16, hex32, KEY_HEX, SESSION_HEX};

/// Strategy for a single record's caller-supplied payload value. We
/// stick to leaf scalars to keep the search space tractable; map /
/// list nesting is exercised separately by unit tests inside cbor.rs.
fn payload_value_strategy() -> impl Strategy<Value = PayloadValue> {
    prop_oneof![
        any::<u64>().prop_map(PayloadValue::Uint),
        any::<bool>().prop_map(PayloadValue::Bool),
        ".{0,32}".prop_map(PayloadValue::Text),
        proptest::collection::vec(any::<u8>(), 0..32).prop_map(PayloadValue::Bytes),
        // Negative ints constrained to negative half to keep canonical
        // encoder happy.
        (i64::MIN..=-1i64).prop_map(PayloadValue::Nint),
    ]
}

/// Strategy for the small payload map every record carries.
fn payload_map_strategy() -> impl Strategy<Value = BTreeMap<String, PayloadValue>> {
    proptest::collection::btree_map("[a-z]{1,8}", payload_value_strategy(), 0..4)
}

/// Strategy for a sequence of N caller-supplied record inputs. Wall
/// clocks are derived from the index so the verifier's monotonicity
/// check is happy.
fn record_inputs_strategy(min: usize, max: usize) -> impl Strategy<Value = Vec<RecordInput>> {
    proptest::collection::vec(
        (payload_map_strategy(), "[a-z]{1,12}", 0u64..1_000_000u64),
        min..=max,
    )
    .prop_map(|specs| {
        specs
            .into_iter()
            .enumerate()
            .map(|(i, (payload, event_suffix, mono_extra))| {
                let i_u = i as u64;
                RecordInput {
                    ts_wall: format!("2026-05-21T05:00:{:02}.000Z", (i_u % 60) as u32),
                    ts_mono_delta: i_u * 1000 + mono_extra,
                    actor: "user:proptest".into(),
                    event: format!("proptest.{event_suffix}"),
                    payload,
                    schema_version: 1,
                }
            })
            .collect::<Vec<_>>()
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1024))]

    /// AC 1: ≥1000 sequences per CI run; each round-trips and verifies.
    #[test]
    fn random_sequence_writes_reads_and_verifies(
        inputs in record_inputs_strategy(1, 16),
    ) {
        let tmp = tempfile::tempdir().unwrap();
        let key = InMemoryKey::from_bytes(hex32(KEY_HEX));
        let session_id = hex16(SESSION_HEX);

        // 1. Write.
        let mut writer = Writer::open(tmp.path(), Box::new(key), session_id).unwrap();
        let mut written_ids = Vec::with_capacity(inputs.len());
        for input in inputs.iter().cloned() {
            let id = writer.append(input).unwrap();
            written_ids.push(id);
        }
        writer.flush().unwrap();
        drop(writer);

        // 2. Read.
        let reader = Reader::open(tmp.path()).unwrap();
        let mut iter = reader.iter();
        for (i, expected) in inputs.iter().enumerate() {
            let record = iter.next_record().unwrap().expect("record present");
            prop_assert_eq!(record.record_id, written_ids[i]);
            prop_assert_eq!(record.ts_wall.clone(), expected.ts_wall.clone());
            prop_assert_eq!(record.ts_mono_delta, expected.ts_mono_delta);
            prop_assert_eq!(record.actor.clone(), expected.actor.clone());
            prop_assert_eq!(record.event.clone(), expected.event.clone());
            prop_assert_eq!(record.payload.clone(), expected.payload.clone());
            prop_assert_eq!(record.schema_version, expected.schema_version);
        }
        prop_assert!(iter.next_record().unwrap().is_none(), "extra records");

        // 3. Verify.
        let key = InMemoryKey::from_bytes(hex32(KEY_HEX));
        let verifier = Verifier::new(Box::new(key));
        let report = verifier.verify(tmp.path()).unwrap();
        prop_assert_eq!(report.compact_verdict(), "Verified");
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Bonus: after a random write, re-open the writer (exercising R5
    /// recovery) and append more records. Verifier still passes.
    #[test]
    fn reopen_and_extend_keeps_chain_verifiable(
        first in record_inputs_strategy(1, 8),
        second in record_inputs_strategy(1, 8),
    ) {
        let tmp = tempfile::tempdir().unwrap();
        let session_id = hex16(SESSION_HEX);
        {
            let key = InMemoryKey::from_bytes(hex32(KEY_HEX));
            let mut writer = Writer::open(tmp.path(), Box::new(key), session_id).unwrap();
            for input in first {
                writer.append(input).unwrap();
            }
            writer.flush().unwrap();
        }
        {
            let key = InMemoryKey::from_bytes(hex32(KEY_HEX));
            let mut writer = Writer::open(tmp.path(), Box::new(key), session_id).unwrap();
            for input in second {
                writer.append(input).unwrap();
            }
            writer.flush().unwrap();
        }
        let key = InMemoryKey::from_bytes(hex32(KEY_HEX));
        let verifier = Verifier::new(Box::new(key));
        let report = verifier.verify(tmp.path()).unwrap();
        prop_assert_eq!(report.compact_verdict(), "Verified");
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Bonus: small segment_size_bytes forces rollovers. Sequences that
    /// cross multiple segments must still verify clean.
    #[test]
    fn random_sequence_across_segments_verifies(
        inputs in record_inputs_strategy(4, 32),
    ) {
        let tmp = tempfile::tempdir().unwrap();
        let key = InMemoryKey::from_bytes(hex32(KEY_HEX));
        let cfg = WriterConfig { segment_size_bytes: 512, finalize_on_rollover: true };
        let mut writer = Writer::with_config(tmp.path(), Box::new(key), hex16(SESSION_HEX), cfg)
            .unwrap();
        for input in inputs {
            writer.append(input).unwrap();
        }
        writer.flush().unwrap();
        drop(writer);

        let key = InMemoryKey::from_bytes(hex32(KEY_HEX));
        let verifier = Verifier::new(Box::new(key));
        let report = verifier.verify(tmp.path()).unwrap();
        prop_assert_eq!(report.compact_verdict(), "Verified");
    }
}
