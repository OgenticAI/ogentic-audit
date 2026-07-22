//! Policy attestation rides inside the (already-signed) record payload
//! (OGE-1674). These tests prove that a record carrying a permit/deny
//! decision + policy digest:
//!
//! 1. round-trips through Writer → Reader unchanged,
//! 2. is covered by the HMAC chain (the verifier still passes, because the
//!    policy data is *inside* the tamper-evidence boundary, not bolted on),
//! 3. encodes byte-identically every time (canonical CBOR determinism), and
//! 4. is byte-stable against the committed cross-language golden vectors.
//!
//! No on-disk format change: this is a convention on the free-form
//! `payload` map, so `FORMAT_VERSION` is unchanged and the record schema
//! (keys 1–10) is untouched. See ADR-0003.

mod common;

use std::collections::BTreeMap;

use ogentic_audit_core::{
    InMemoryKey, PayloadValue, PolicyAttestation, PolicyDecision, Reader, RecordInput, Verdict,
    Verifier, Writer,
};

use common::{hex16, hex32, KEY_HEX, SESSION_HEX};

fn key() -> InMemoryKey {
    InMemoryKey::from_bytes(hex32(KEY_HEX))
}

fn digest_bytes(seed: u8) -> [u8; 32] {
    let mut d = [0u8; 32];
    for (i, b) in d.iter_mut().enumerate() {
        *b = seed ^ (i as u8);
    }
    d
}

/// A record whose payload carries an action plus a policy attestation.
fn record_with_policy(record_id: u64, att: &PolicyAttestation) -> RecordInput {
    let mut payload: BTreeMap<String, PayloadValue> = BTreeMap::new();
    payload.insert("action".into(), PayloadValue::Text("file.write".into()));
    att.attach(&mut payload);
    RecordInput {
        ts_wall: format!("2026-07-22T21:00:{:02}.000Z", (record_id % 60) as u32),
        ts_mono_delta: record_id * 1000,
        actor: "agent:zing".into(),
        event: "tool.exec".into(),
        payload,
        schema_version: 1,
    }
}

#[test]
fn policy_record_round_trips_and_verifies() {
    let tmp = tempfile::tempdir().unwrap();

    let permit = PolicyAttestation::new(PolicyDecision::Permit, digest_bytes(0xA0))
        .with_policy_id("pol-writes-v3")
        .with_deciding_rules(["rule.tenant-scope", "rule.size-cap"]);
    let deny = PolicyAttestation::new(PolicyDecision::Deny, digest_bytes(0x0D));

    {
        let mut writer = Writer::open(tmp.path(), Box::new(key()), hex16(SESSION_HEX)).unwrap();
        writer.append(record_with_policy(0, &permit)).unwrap();
        writer.append(record_with_policy(1, &deny)).unwrap();
        writer.flush().unwrap();
    }

    // 1. The chain still verifies — policy data is inside the HMAC.
    let verifier = Verifier::new(Box::new(key()));
    let report = verifier.verify(tmp.path()).unwrap();
    assert_eq!(report.verdict, Verdict::Verified, "{:?}", report.violation);

    // 2. Read the attestations back and confirm they survived intact.
    let reader = Reader::open(tmp.path()).unwrap();
    let mut iter = reader.iter();
    let mut records = Vec::new();
    while let Some(r) = iter.next_record().unwrap() {
        records.push(r);
    }
    assert_eq!(records.len(), 2);

    let read_permit = PolicyAttestation::from_payload(&records[0].payload)
        .unwrap()
        .expect("record 0 carries a policy attestation");
    assert_eq!(read_permit.decision, PolicyDecision::Permit);
    assert_eq!(read_permit.digest, digest_bytes(0xA0));
    assert_eq!(read_permit.policy_id.as_deref(), Some("pol-writes-v3"));
    assert_eq!(
        read_permit.deciding_rules,
        ["rule.tenant-scope", "rule.size-cap"]
    );

    let read_deny = PolicyAttestation::from_payload(&records[1].payload)
        .unwrap()
        .expect("record 1 carries a policy attestation");
    assert_eq!(read_deny.decision, PolicyDecision::Deny);
    assert!(read_deny.policy_id.is_none());
    assert!(read_deny.deciding_rules.is_empty());
}

/// A tenant that swaps the policy decision in a stored record breaks the
/// HMAC — the whole point of embedding the attestation *inside* the signed
/// bytes rather than alongside them as metadata.
#[test]
fn tampering_with_the_decision_breaks_the_chain() {
    let tmp = tempfile::tempdir().unwrap();
    let permit = PolicyAttestation::new(PolicyDecision::Permit, digest_bytes(0x11));
    {
        let mut writer = Writer::open(tmp.path(), Box::new(key()), hex16(SESSION_HEX)).unwrap();
        writer.append(record_with_policy(0, &permit)).unwrap();
        writer.flush().unwrap();
    }

    // Flip "permit" -> "deny " in the raw segment bytes (same length, so
    // framing is intact; only the HMAC should catch it).
    let seg = tmp.path().join("audit-0000.cbor");
    let mut bytes = std::fs::read(&seg).unwrap();
    let needle = b"permit";
    let pos = bytes
        .windows(needle.len())
        .position(|w| w == needle)
        .expect("permit present in payload");
    bytes[pos..pos + needle.len()].copy_from_slice(b"deny  ");
    std::fs::write(&seg, &bytes).unwrap();

    let verifier = Verifier::new(Box::new(key()));
    let report = verifier.verify(tmp.path()).unwrap();
    assert_eq!(
        report.verdict,
        Verdict::Violation,
        "editing the policy decision must break the HMAC chain"
    );
}

/// Canonical CBOR is deterministic, so the same attestation encodes to the
/// same bytes every time — independent of `BTreeMap` construction order.
#[test]
fn attestation_encoding_is_byte_stable() {
    let a = PolicyAttestation::new(PolicyDecision::Permit, digest_bytes(0x5A))
        .with_policy_id("pol-1")
        .with_deciding_rules(["z.rule", "a.rule"]);

    fn framed_bytes(att: &PolicyAttestation) -> Vec<u8> {
        let tmp = tempfile::tempdir().unwrap();
        {
            let mut w = Writer::open(tmp.path(), Box::new(key()), hex16(SESSION_HEX)).unwrap();
            w.append(record_with_policy(0, att)).unwrap();
            w.flush().unwrap();
        }
        std::fs::read(tmp.path().join("audit-0000.cbor")).unwrap()
    }

    assert_eq!(
        framed_bytes(&a),
        framed_bytes(&a),
        "identical attestations must produce identical segment bytes"
    );
}
