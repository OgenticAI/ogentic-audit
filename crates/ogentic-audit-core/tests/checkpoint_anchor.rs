//! Checkpoint anchoring (OGE-1671) — the attack internal verification
//! cannot see.
//!
//! Motivated by [NousResearch/hermes-agent#487], where the same class of
//! hash-chained audit log was picked apart:
//!
//! > `verify_chain()` checks internal consistency only. If an attacker
//! > has write access to the audit log, they can fork the chain at any
//! > point, rewrite everything after it, and verification still passes.
//! > […] They truncate after B, write a forged C' with
//! > `prev_hash = hash(B)`, recompute D' through G'. Every link is valid.
//!
//! These tests reproduce exactly that. `verifies_rewritten_chain_without_
//! checkpoint` asserts the **gap is real** — a rewritten log passes plain
//! verification — so that if someone later "fixes" it accidentally, the
//! test fails loudly and we learn why. The rest assert the checkpoint
//! catches what plain verification cannot.
//!
//! [NousResearch/hermes-agent#487]: https://github.com/NousResearch/hermes-agent/issues/487

mod common;

use std::collections::BTreeMap;

use ogentic_audit_core::{
    Checkpoint, InMemoryKey, KeyHandle, PayloadValue, Reader, RecordInput, Verdict, Verifier,
    VerifyError, VerifyOptions, ViolationKind, Writer, HMAC_LEN, KEY_ID_LEN,
};

use common::{hex16, hex32, KEY_HEX, SESSION_HEX};

/// A record whose content is a function of `(record_id, decision)`, so a
/// "forged" record is byte-different from the honest one at the same
/// position while everything else about the log stays identical.
fn record(record_id: u64, decision: &str) -> RecordInput {
    let mut payload = BTreeMap::new();
    payload.insert("i".to_string(), PayloadValue::Uint(record_id));
    payload.insert(
        "decision".to_string(),
        PayloadValue::Text(decision.to_string()),
    );
    RecordInput {
        ts_wall: format!("2026-07-20T20:00:{:02}.000Z", (record_id % 60) as u32),
        ts_mono_delta: record_id * 1000,
        actor: "agent:zing".into(),
        event: "tool.exec".into(),
        payload,
        schema_version: 1,
    }
}

/// Write `decisions.len()` records, the i-th carrying `decisions[i]`.
fn build_log(dir: &std::path::Path, decisions: &[&str]) {
    let key = InMemoryKey::from_bytes(hex32(KEY_HEX));
    let mut writer = Writer::open(dir, Box::new(key), hex16(SESSION_HEX)).unwrap();
    for (i, decision) in decisions.iter().enumerate() {
        writer.append(record(i as u64, decision)).unwrap();
    }
    writer.flush().unwrap();
}

fn verifier() -> Verifier {
    Verifier::new(Box::new(InMemoryKey::from_bytes(hex32(KEY_HEX))))
}

fn key_id_bytes() -> [u8; KEY_ID_LEN] {
    *InMemoryKey::from_bytes(hex32(KEY_HEX)).key_id().as_bytes()
}

/// Observe the HMAC currently at `(segment, record_id)` and pin it.
fn checkpoint_at(dir: &std::path::Path, segment: u16, record_id: u64) -> Checkpoint {
    let reader = Reader::open(dir).unwrap();
    let mut iter = reader.iter();
    let mut hmac: Option<[u8; HMAC_LEN]> = None;
    while let Some(r) = iter.next_record().unwrap() {
        if r.segment_index == segment && r.record_id == record_id {
            hmac = Some(r.hmac);
            break;
        }
    }
    Checkpoint {
        key_id: key_id_bytes(),
        segment,
        record_id,
        hmac: hmac.expect("record to checkpoint must exist"),
        observed_at: "2026-07-20T20:00:00Z".to_string(),
    }
}

fn with_checkpoint(cp: Checkpoint) -> VerifyOptions {
    VerifyOptions {
        forensic_mode: false,
        checkpoint: Some(cp),
    }
}

/// The honest log, re-verified against a checkpoint taken from itself,
/// must still verify. A checkpoint must never produce a false positive —
/// that would be worse than not having one, because operators would
/// learn to ignore it.
#[test]
fn clean_log_verifies_against_its_own_checkpoint() {
    let tmp = tempfile::tempdir().unwrap();
    build_log(tmp.path(), &["allow", "allow", "deny", "allow", "deny"]);

    let cp = checkpoint_at(tmp.path(), 0, 2);
    let report = verifier()
        .verify_with_options(tmp.path(), with_checkpoint(cp))
        .unwrap();

    assert_eq!(report.verdict, Verdict::Verified, "{:?}", report.violation);
}

/// Appending after the checkpoint is normal operation, not tampering:
/// the log *extends* the observed history rather than contradicting it.
#[test]
fn checkpoint_still_matches_after_honest_appends() {
    let tmp = tempfile::tempdir().unwrap();
    build_log(tmp.path(), &["allow", "allow", "deny"]);
    let cp = checkpoint_at(tmp.path(), 0, 2);

    // More history happens.
    let key = InMemoryKey::from_bytes(hex32(KEY_HEX));
    let mut writer = Writer::open(tmp.path(), Box::new(key), hex16(SESSION_HEX)).unwrap();
    for i in 3..6u64 {
        writer.append(record(i, "allow")).unwrap();
    }
    writer.flush().unwrap();

    let report = verifier()
        .verify_with_options(tmp.path(), with_checkpoint(cp))
        .unwrap();
    assert_eq!(report.verdict, Verdict::Verified, "{:?}", report.violation);
}

/// **The gap.** A rewritten chain passes plain verification. This test
/// documents the limitation rather than hiding it — if it ever starts
/// failing, internal verification gained a property it never had, and
/// the threat model needs revisiting.
#[test]
fn verifies_rewritten_chain_without_checkpoint() {
    let tmp = tempfile::tempdir().unwrap();
    build_log(tmp.path(), &["allow", "allow", "deny", "allow", "deny"]);

    rewrite_history(tmp.path());

    let report = verifier().verify(tmp.path()).unwrap();
    assert_eq!(
        report.verdict,
        Verdict::Verified,
        "plain verification is self-referential and cannot see a rewrite; \
         if this now fails, update docs/security/threat-model.md"
    );
}

/// The same rewritten chain, checked against a head observed before the
/// rewrite, is caught.
#[test]
fn checkpoint_catches_rewritten_history() {
    let tmp = tempfile::tempdir().unwrap();
    build_log(tmp.path(), &["allow", "allow", "deny", "allow", "deny"]);

    // Observed while the log was still honest, and stored somewhere the
    // attacker cannot reach — that last part is the whole ballgame.
    let cp = checkpoint_at(tmp.path(), 0, 3);

    rewrite_history(tmp.path());

    let report = verifier()
        .verify_with_options(tmp.path(), with_checkpoint(cp))
        .unwrap();

    assert_eq!(report.verdict, Verdict::Violation);
    let v = report.violation.expect("violation");
    assert_eq!(v.kind, ViolationKind::CheckpointMismatch);
    assert_eq!(v.location.segment_index, 0);
    assert_eq!(v.location.record_id, Some(3));
}

/// History cut short of the checkpoint is a different failure from
/// history altered at the checkpoint, and reports as such — an operator
/// needs to know whether records were changed or removed.
#[test]
fn checkpoint_catches_truncated_history() {
    let tmp = tempfile::tempdir().unwrap();
    build_log(tmp.path(), &["allow", "allow", "deny", "allow", "deny"]);
    let cp = checkpoint_at(tmp.path(), 0, 4);

    // Attacker keeps only the first three records and re-chains a
    // shorter, internally-consistent log.
    std::fs::remove_dir_all(tmp.path()).unwrap();
    std::fs::create_dir_all(tmp.path()).unwrap();
    build_log(tmp.path(), &["allow", "allow", "deny"]);

    // Plain verification is content.
    assert_eq!(
        verifier().verify(tmp.path()).unwrap().verdict,
        Verdict::Verified
    );

    let report = verifier()
        .verify_with_options(tmp.path(), with_checkpoint(cp))
        .unwrap();
    assert_eq!(report.verdict, Verdict::Violation);
    let v = report.violation.expect("violation");
    assert_eq!(v.kind, ViolationKind::CheckpointTruncated);
    assert_eq!(v.location.record_id, Some(4));
}

/// A checkpoint from someone else's log is an operator mistake. It must
/// be refused outright, never silently ignored (which would let a bad
/// checkpoint masquerade as a passing check) and never reported as a
/// violation (which would accuse an innocent log).
#[test]
fn checkpoint_from_a_different_log_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    build_log(tmp.path(), &["allow", "allow"]);

    let mut cp = checkpoint_at(tmp.path(), 0, 1);
    cp.key_id = [0xAA; KEY_ID_LEN];

    let err = verifier()
        .verify_with_options(tmp.path(), with_checkpoint(cp))
        .expect_err("must refuse a checkpoint from another log");

    assert!(
        matches!(err, VerifyError::CheckpointKeyMismatch { .. }),
        "unexpected error: {err}"
    );
}

/// An unrelated violation before the checkpoint position must not be
/// masked by, or reported as, a checkpoint failure — the first real
/// violation is still the headline.
#[test]
fn earlier_violation_takes_precedence_over_truncation() {
    let tmp = tempfile::tempdir().unwrap();
    build_log(tmp.path(), &["allow", "allow", "deny", "allow"]);
    let cp = checkpoint_at(tmp.path(), 0, 3);

    // Corrupt a byte in the first record's payload region.
    let seg = tmp.path().join("audit-0000.cbor");
    let mut bytes = std::fs::read(&seg).unwrap();
    let offset = bytes.len() / 2;
    bytes[offset] ^= 0xff;
    std::fs::write(&seg, &bytes).unwrap();

    let report = verifier()
        .verify_with_options(tmp.path(), with_checkpoint(cp))
        .unwrap();

    assert_eq!(report.verdict, Verdict::Violation);
    let kind = report.violation.expect("violation").kind;
    assert!(
        kind != ViolationKind::CheckpointTruncated,
        "a corrupted record must report as corruption, not as a missing checkpoint"
    );
}

/// The hermes-agent#487 attack: keep the early history, replace
/// everything from the fork point forward, re-chaining as you go so
/// every internal link is valid.
fn rewrite_history(dir: &std::path::Path) {
    std::fs::remove_dir_all(dir).unwrap();
    std::fs::create_dir_all(dir).unwrap();
    // Records 0-2 as before; record 3 onward fabricated. The attacker
    // holds the key, so each forged record gets a valid HMAC and a
    // valid prev_hash — exactly the scenario the thread describes.
    build_log(dir, &["allow", "allow", "deny", "deny", "deny"]);
}
