//! Writer crash-recovery integration tests (R5 / OGE-432).
//!
//! Cover the four `RecoveryAction` outcomes — Fresh, Resumed, Repaired,
//! OpenedNextAfterFinalized — plus the two refuse-to-extend cases
//! (HMAC mismatch, key_id mismatch). Pair with `crash_recovery.rs`
//! for the randomized 100-iteration torn-tail stress test.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;

use ogentic_audit_core::{
    InMemoryKey, PayloadValue, RecordInput, RecoveryAction, RecoveryFailure, Verifier, Writer,
    WriterConfig, WriterError, HEADER_TOTAL_LEN, SESSION_ID_LEN,
};

const KEY_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const ALT_KEY_HEX: &str = "ff112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
const SESSION_HEX: &str = "00112233445566778899aabbccddeeff";

fn hex32(s: &str) -> [u8; 32] {
    assert_eq!(s.len(), 64);
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}

fn hex16(s: &str) -> [u8; SESSION_ID_LEN] {
    assert_eq!(s.len(), 32);
    let mut out = [0u8; SESSION_ID_LEN];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}

fn sample(record_id: u64) -> RecordInput {
    let mut payload = BTreeMap::new();
    payload.insert("i".to_string(), PayloadValue::Uint(record_id));
    RecordInput {
        ts_wall: format!("2026-05-21T05:00:{:02}.000Z", (record_id % 60) as u32),
        ts_mono_delta: record_id * 1000,
        actor: "user:test".into(),
        event: "test.tick".into(),
        payload,
        schema_version: 1,
    }
}

fn open_writer(path: &std::path::Path) -> Writer {
    let key = InMemoryKey::from_bytes(hex32(KEY_HEX));
    Writer::open(path, Box::new(key), hex16(SESSION_HEX)).unwrap()
}

fn open_writer_small_segments(path: &std::path::Path) -> Writer {
    let key = InMemoryKey::from_bytes(hex32(KEY_HEX));
    let cfg = WriterConfig {
        segment_size_bytes: 512,
        finalize_on_rollover: true,
    };
    Writer::with_config(path, Box::new(key), hex16(SESSION_HEX), cfg).unwrap()
}

#[test]
fn fresh_open_reports_fresh_action() {
    let tmp = tempfile::tempdir().unwrap();
    let writer = open_writer(tmp.path());
    let report = writer.recovery_report();
    assert!(matches!(report.action, RecoveryAction::Fresh));
    assert_eq!(report.current_segment_index, 0);
    assert!(report.last_record_id.is_none());
    assert_eq!(report.records_in_current_segment, 0);
    assert_eq!(report.truncated_bytes, 0);
}

#[test]
fn clean_resume_reports_resumed_action() {
    let tmp = tempfile::tempdir().unwrap();
    {
        let mut writer = open_writer(tmp.path());
        for i in 0..5 {
            writer.append(sample(i)).unwrap();
        }
        writer.flush().unwrap();
    }
    // Drop + reopen: no truncation, last record valid.
    let writer = open_writer(tmp.path());
    let report = writer.recovery_report();
    assert!(matches!(report.action, RecoveryAction::Resumed));
    assert_eq!(report.current_segment_index, 0);
    assert_eq!(report.last_record_id, Some(4));
    assert_eq!(report.records_in_current_segment, 5);
    assert_eq!(report.truncated_bytes, 0);
}

#[test]
fn resume_continues_chain_correctly() {
    let tmp = tempfile::tempdir().unwrap();
    {
        let mut writer = open_writer(tmp.path());
        for i in 0..3 {
            writer.append(sample(i)).unwrap();
        }
        writer.flush().unwrap();
    }
    // Reopen and append more.
    {
        let mut writer = open_writer(tmp.path());
        for i in 3..6 {
            writer.append(sample(i)).unwrap();
        }
        writer.flush().unwrap();
    }
    // Verify the whole log via R3.
    let key = InMemoryKey::from_bytes(hex32(KEY_HEX));
    let verifier = Verifier::new(Box::new(key));
    let report = verifier.verify(tmp.path()).expect("verifier ran");
    assert_eq!(report.compact_verdict(), "Verified");
}

#[test]
fn torn_tail_is_repaired() {
    let tmp = tempfile::tempdir().unwrap();
    {
        let mut writer = open_writer(tmp.path());
        for i in 0..4 {
            writer.append(sample(i)).unwrap();
        }
        writer.flush().unwrap();
    }
    // Chop 5 bytes off the tail to simulate a mid-flush truncation.
    let path = tmp.path().join("audit-0000.cbor");
    let len = fs::metadata(&path).unwrap().len();
    let f = fs::OpenOptions::new().write(true).open(&path).unwrap();
    f.set_len(len - 5).unwrap();
    drop(f);

    let writer = open_writer(tmp.path());
    let report = writer.recovery_report();
    assert!(matches!(report.action, RecoveryAction::Repaired));
    // Some bytes were lopped (at least 5 — could be more if the partial
    // record's framing was incomplete).
    assert!(report.truncated_bytes >= 5);
    // Last valid record id should be 2 (record 3 was torn).
    assert_eq!(report.last_record_id, Some(2));
    assert_eq!(report.records_in_current_segment, 3);
}

#[test]
fn repaired_log_verifies_clean_after_recovery() {
    let tmp = tempfile::tempdir().unwrap();
    {
        let mut writer = open_writer(tmp.path());
        for i in 0..6 {
            writer.append(sample(i)).unwrap();
        }
        writer.flush().unwrap();
    }
    // Chop the last record entirely (40-byte framing + payload roughly).
    let path = tmp.path().join("audit-0000.cbor");
    let len = fs::metadata(&path).unwrap().len();
    fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(len - 80)
        .unwrap();

    // Recover.
    {
        let writer = open_writer(tmp.path());
        assert!(matches!(
            writer.recovery_report().action,
            RecoveryAction::Repaired
        ));
    }

    // R3 verifies the recovered log end-to-end.
    let key = InMemoryKey::from_bytes(hex32(KEY_HEX));
    let verifier = Verifier::new(Box::new(key));
    let report = verifier.verify(tmp.path()).expect("verifier ran");
    assert_eq!(report.compact_verdict(), "Verified");
}

#[test]
fn header_only_segment_resumes_at_record_zero() {
    let tmp = tempfile::tempdir().unwrap();
    {
        // Create + flush + drop a writer with zero records (just the
        // header gets written by `Writer::open`).
        let writer = open_writer(tmp.path());
        drop(writer);
    }

    let writer = open_writer(tmp.path());
    let report = writer.recovery_report();
    assert!(matches!(report.action, RecoveryAction::Resumed));
    assert!(report.last_record_id.is_none());
    assert_eq!(report.records_in_current_segment, 0);
    assert_eq!(report.truncated_bytes, 0);
}

#[test]
fn finalized_segment_opens_next() {
    let tmp = tempfile::tempdir().unwrap();
    {
        let mut writer = open_writer_small_segments(tmp.path());
        // segment_size_bytes=512 forces a rollover after one record:
        // record(~192B) + header(80B) + finalize-estimate(~190B) > 512.
        for i in 0..3 {
            writer.append(sample(i)).unwrap();
        }
        writer.flush().unwrap();
    }
    // Segment 0 is now finalized. Delete every segment past 0 so
    // segment 0 becomes the latest. Recovery should detect the
    // `segment.finalized` tail and open segment 1 fresh again.
    let mut paths: Vec<_> = fs::read_dir(tmp.path())
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    paths.sort();
    for path in paths.into_iter().skip(1) {
        fs::remove_file(&path).unwrap();
    }

    let writer = open_writer_small_segments(tmp.path());
    let report = writer.recovery_report();
    assert!(
        matches!(report.action, RecoveryAction::OpenedNextAfterFinalized),
        "expected OpenedNextAfterFinalized, got {:?}",
        report.action
    );
    assert_eq!(report.current_segment_index, 1);
    assert_eq!(report.records_in_current_segment, 0);
}

#[test]
fn refuses_to_recover_from_in_place_hmac_tampering() {
    let tmp = tempfile::tempdir().unwrap();
    {
        let mut writer = open_writer(tmp.path());
        for i in 0..3 {
            writer.append(sample(i)).unwrap();
        }
        writer.flush().unwrap();
    }

    // Flip a single byte deep inside record 1's payload (skip the
    // header and the first record's frame; flip something at offset
    // ~200 which is firmly inside the file).
    let path = tmp.path().join("audit-0000.cbor");
    let mut bytes = fs::read(&path).unwrap();
    let idx = HEADER_TOTAL_LEN + 50; // inside record 0's payload
    bytes[idx] ^= 0xff;
    let mut f = fs::OpenOptions::new().write(true).open(&path).unwrap();
    use std::io::Seek;
    f.seek(std::io::SeekFrom::Start(0)).unwrap();
    f.write_all(&bytes).unwrap();
    drop(f);

    let key = InMemoryKey::from_bytes(hex32(KEY_HEX));
    let result = Writer::open(tmp.path(), Box::new(key), hex16(SESSION_HEX));
    match result {
        Err(WriterError::Recovery {
            reason: RecoveryFailure::HmacMismatch { segment_index, .. },
        }) => {
            assert_eq!(segment_index, 0);
        },
        other => panic!("expected HmacMismatch recovery failure, got {other:?}"),
    }
}

#[test]
fn refuses_to_recover_when_key_id_doesnt_match() {
    let tmp = tempfile::tempdir().unwrap();
    {
        let mut writer = open_writer(tmp.path());
        for i in 0..2 {
            writer.append(sample(i)).unwrap();
        }
        writer.flush().unwrap();
    }

    // Try to reopen with a DIFFERENT key. The segment header's key_id
    // belongs to KEY_HEX, but we hand the writer a key for ALT_KEY_HEX.
    let alt_key = InMemoryKey::from_bytes(hex32(ALT_KEY_HEX));
    let result = Writer::open(tmp.path(), Box::new(alt_key), hex16(SESSION_HEX));
    match result {
        Err(WriterError::Recovery {
            reason: RecoveryFailure::KeyIdMismatch { segment_index, .. },
        }) => {
            assert_eq!(segment_index, 0);
        },
        other => panic!("expected KeyIdMismatch recovery failure, got {other:?}"),
    }
}
