//! Reader round-trip tests against R1 Writer output.
//!
//! Pairs with `vector_conformance.rs` (which exercises R1's bytes). This
//! suite drives R1 to produce records, then verifies R2 decodes them
//! back identically and surfaces the same field values the caller
//! supplied. Lives in `tests/` (integration, not unit) so the Reader
//! sees only the crate's public API surface.

use std::collections::BTreeMap;

use ogentic_audit_core::{
    InMemoryKey, PayloadValue, ReadStrategy, Reader, ReaderConfig, ReaderError, RecordInput,
    Writer, WriterConfig, HMAC_LEN, SESSION_ID_LEN,
};

const KEY_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
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
    payload.insert(
        "decision".to_string(),
        PayloadValue::Text(if record_id % 2 == 0 { "allow" } else { "deny" }.into()),
    );
    RecordInput {
        ts_wall: format!("2026-05-21T04:00:{:02}.000Z", (record_id % 60) as u32),
        ts_mono_delta: record_id * 1000,
        actor: "user:test".into(),
        event: "test.tick".into(),
        payload,
        schema_version: 1,
    }
}

#[test]
fn reader_round_trip_single_segment() {
    let tmp = tempfile::tempdir().unwrap();
    let key = InMemoryKey::from_bytes(hex32(KEY_HEX));
    let session_id = hex16(SESSION_HEX);

    let mut writer = Writer::open(tmp.path(), Box::new(key), session_id).unwrap();
    let inputs: Vec<RecordInput> = (0..5).map(sample).collect();
    for input in inputs.iter().cloned() {
        writer.append(input).unwrap();
    }
    writer.flush().unwrap();
    drop(writer);

    let reader = Reader::open(tmp.path()).unwrap();
    assert_eq!(reader.segments().unwrap(), vec![0]);
    assert_eq!(reader.read_strategy(), ReadStrategy::Buffered);

    let mut iter = reader.iter();
    for expected in inputs.iter() {
        let record = iter
            .next_record()
            .expect("iter ok")
            .expect("record present");
        assert_eq!(record.segment_index, 0);
        assert_eq!(record.ts_wall, expected.ts_wall);
        assert_eq!(record.ts_mono_delta, expected.ts_mono_delta);
        assert_eq!(record.actor, expected.actor);
        assert_eq!(record.event, expected.event);
        assert_eq!(record.payload, expected.payload);
        assert_eq!(record.schema_version, expected.schema_version);
        assert_eq!(record.session_id, session_id);
        assert_eq!(record.hmac.len(), HMAC_LEN);
        assert_eq!(record.prev_hash.len(), HMAC_LEN);
    }
    assert!(iter.next_record().unwrap().is_none(), "no more records");
}

#[test]
fn reader_seek_returns_targeted_record() {
    let tmp = tempfile::tempdir().unwrap();
    let key = InMemoryKey::from_bytes(hex32(KEY_HEX));
    let session_id = hex16(SESSION_HEX);
    let mut writer = Writer::open(tmp.path(), Box::new(key), session_id).unwrap();
    for input in (0..7).map(sample) {
        writer.append(input).unwrap();
    }
    writer.flush().unwrap();
    drop(writer);

    let reader = Reader::open(tmp.path()).unwrap();
    let record = reader.seek(0, 4).unwrap();
    assert_eq!(record.record_id, 4);
    assert_eq!(record.event, "test.tick");
    assert_eq!(record.payload.get("i"), Some(&PayloadValue::Uint(4)));

    // Out-of-range record_id within an existing segment.
    match reader.seek(0, 999) {
        Err(ReaderError::NotFound {
            segment_index,
            record_id,
        }) => {
            assert_eq!(segment_index, 0);
            assert_eq!(record_id, 999);
        },
        other => panic!("expected NotFound, got {other:?}"),
    }

    // Non-existent segment.
    match reader.seek(99, 0) {
        Err(ReaderError::NotFound { segment_index, .. }) => assert_eq!(segment_index, 99),
        other => panic!("expected NotFound for missing segment, got {other:?}"),
    }
}

#[test]
fn reader_cooperates_with_live_writer() {
    // Writer appends records WHILE the iterator is being polled. Each
    // poll picks up whatever's currently on disk; subsequent polls
    // pick up appended records.

    let tmp = tempfile::tempdir().unwrap();
    let key = InMemoryKey::from_bytes(hex32(KEY_HEX));
    let session_id = hex16(SESSION_HEX);
    let mut writer = Writer::open(tmp.path(), Box::new(key), session_id).unwrap();
    writer.append(sample(0)).unwrap();
    writer.append(sample(1)).unwrap();
    writer.flush().unwrap();

    let reader = Reader::open(tmp.path()).unwrap();
    let mut iter = reader.iter();

    let r0 = iter.next_record().unwrap().expect("r0");
    assert_eq!(r0.record_id, 0);
    let r1 = iter.next_record().unwrap().expect("r1");
    assert_eq!(r1.record_id, 1);
    assert!(
        iter.next_record().unwrap().is_none(),
        "no records yet for record_id 2"
    );

    // Writer appends more.
    writer.append(sample(2)).unwrap();
    writer.append(sample(3)).unwrap();
    writer.flush().unwrap();

    // Iterator picks them up on next poll.
    let r2 = iter.next_record().unwrap().expect("r2");
    assert_eq!(r2.record_id, 2);
    let r3 = iter.next_record().unwrap().expect("r3");
    assert_eq!(r3.record_id, 3);
    assert!(iter.next_record().unwrap().is_none());
}

#[test]
fn reader_walks_across_segment_rollover() {
    let tmp = tempfile::tempdir().unwrap();
    let key = InMemoryKey::from_bytes(hex32(KEY_HEX));
    let session_id = hex16(SESSION_HEX);
    // Small segment size to force a rollover.
    let config = WriterConfig {
        segment_size_bytes: 512,
        finalize_on_rollover: true,
    };
    let mut writer = Writer::with_config(tmp.path(), Box::new(key), session_id, config).unwrap();
    for input in (0..8).map(sample) {
        writer.append(input).unwrap();
    }
    writer.flush().unwrap();
    drop(writer);

    let reader = Reader::open(tmp.path()).unwrap();
    let segs = reader.segments().unwrap();
    assert!(
        segs.len() >= 2,
        "expected at least 2 segments; got {segs:?}"
    );

    // Iterate the entire log; verify segments and record_ids progress
    // in the canonical (segment_index, record_id) lexicographic order.
    let mut iter = reader.iter();
    let mut prev: Option<(u16, u64)> = None;
    let mut total = 0usize;
    while let Some(record) = iter.next_record().unwrap() {
        let cursor = (record.segment_index, record.record_id);
        if let Some(p) = prev {
            assert!(p < cursor, "records out of order: {p:?} -> {cursor:?}");
        }
        prev = Some(cursor);
        total += 1;
    }
    assert!(total >= 8, "missed records: only saw {total}");
}

#[test]
fn reader_torn_tail_surfaces_clean_error() {
    // Build a log, then physically truncate the trailing record's
    // len_trailer to simulate a power-loss-between-bytes torn tail.

    let tmp = tempfile::tempdir().unwrap();
    let key = InMemoryKey::from_bytes(hex32(KEY_HEX));
    let session_id = hex16(SESSION_HEX);
    let mut writer = Writer::open(tmp.path(), Box::new(key), session_id).unwrap();
    writer.append(sample(0)).unwrap();
    writer.append(sample(1)).unwrap();
    writer.flush().unwrap();
    drop(writer);

    // Truncate the last 6 bytes of segment 0 (eats the len_trailer +
    // 2 bytes of the HMAC). This MUST appear as a torn tail, not a
    // decode error.
    let path = tmp.path().join("audit-0000.cbor");
    let len = std::fs::metadata(&path).unwrap().len();
    let f = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
    f.set_len(len - 6).unwrap();
    drop(f);

    let reader = Reader::open(tmp.path()).unwrap();
    let mut iter = reader.iter();
    // First record decodes cleanly.
    let r0 = iter.next_record().unwrap().expect("r0");
    assert_eq!(r0.record_id, 0);
    // Second record's tail is torn. Iterator surfaces TornTail.
    match iter.next_record() {
        Err(ReaderError::TornTail { segment_index, .. }) => assert_eq!(segment_index, 0),
        other => panic!("expected TornTail, got {other:?}"),
    }
}

#[test]
fn reader_with_buffered_strategy_explicit() {
    let tmp = tempfile::tempdir().unwrap();
    let key = InMemoryKey::from_bytes(hex32(KEY_HEX));
    let mut writer = Writer::open(tmp.path(), Box::new(key), hex16(SESSION_HEX)).unwrap();
    writer.append(sample(0)).unwrap();
    writer.flush().unwrap();
    drop(writer);

    let cfg = ReaderConfig {
        read_strategy: ReadStrategy::Buffered,
    };
    let reader = Reader::with_config(tmp.path(), cfg).unwrap();
    assert_eq!(reader.read_strategy(), ReadStrategy::Buffered);
    let r0 = reader.iter().next_record().unwrap().expect("r0");
    assert_eq!(r0.record_id, 0);
}

#[test]
fn reader_open_fails_on_missing_dir() {
    let result = Reader::open("/nonexistent-path-for-reader-test");
    assert!(matches!(result, Err(ReaderError::Io(_))));
}
