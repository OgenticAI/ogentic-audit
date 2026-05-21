//! Randomized crash-recovery stress test for [R5 / OGE-432] AC 5
//! ("kill -9 mid-flush across 100 iterations; every recovered log
//! passes verifier R3").
//!
//! We simulate `kill -9 mid-flush` by writing a clean log, randomly
//! truncating a tail of variable length, then driving the Writer's
//! recovery scan and verifying the result with R3. Pure-Rust simulation
//! is preferable to actually fork-and-kill: it covers every byte-offset
//! truncation point uniformly, runs in <100ms per iteration, and stays
//! reproducible from a seed.
//!
//! [R5 / OGE-432]: https://linear.app/ogenticai/issue/OGE-432

use std::collections::BTreeMap;
use std::fs;

use ogentic_audit_core::{
    InMemoryKey, PayloadValue, RecordInput, RecoveryAction, Verifier, Writer, WriterConfig,
    SESSION_ID_LEN,
};

const KEY_HEX: &str = "abcdef0011223344556677889900aabbccddeeff0011223344556677889900aa";
const SESSION_HEX: &str = "deadbeef0000000011112222deadbeef";

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

/// Tiny deterministic PRNG (xorshift64) so the test is reproducible.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed.max(1))
    }
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn range(&mut self, lo: u64, hi: u64) -> u64 {
        lo + self.next() % (hi - lo)
    }
}

fn sample(i: u64) -> RecordInput {
    let mut payload = BTreeMap::new();
    payload.insert("i".to_string(), PayloadValue::Uint(i));
    payload.insert("tag".to_string(), PayloadValue::Text(format!("rec-{i:04}")));
    RecordInput {
        ts_wall: format!("2026-05-21T05:00:{:02}.000Z", (i % 60) as u32),
        ts_mono_delta: i * 1000,
        actor: "user:stress".into(),
        event: "stress.tick".into(),
        payload,
        schema_version: 1,
    }
}

/// One iteration of the crash simulation:
///
/// 1. Build a log of `n_records` records.
/// 2. Randomly truncate `t` bytes off the tail of the latest segment
///    (`t` chosen uniformly in `[1, max_truncate]`).
/// 3. Re-open the writer; assert the recovery action is either
///    `Repaired` (torn tail was actually inside a record's framing) or
///    `Resumed` (truncation happened to land exactly on a record
///    boundary — rare but legal).
/// 4. Run R3 verifier; assert the recovered log is "Verified".
/// 5. Append a few more records, flush, and re-verify; confirm the
///    Writer can extend the recovered chain without breakage.
fn one_iteration(rng: &mut Rng, n_records: u64, segment_size_bytes: u64) {
    let tmp = tempfile::tempdir().unwrap();

    // 1. Build a clean log.
    {
        let key = InMemoryKey::from_bytes(hex32(KEY_HEX));
        let cfg = WriterConfig {
            segment_size_bytes,
            finalize_on_rollover: true,
        };
        let mut writer = Writer::with_config(tmp.path(), Box::new(key), hex16(SESSION_HEX), cfg)
            .expect("writer opens");
        for i in 0..n_records {
            writer.append(sample(i)).expect("append");
        }
        writer.flush().expect("flush");
    }

    // 2. Truncate the latest segment by a random amount.
    let mut entries: Vec<_> = fs::read_dir(tmp.path())
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    entries.sort();
    let latest = entries.last().expect("at least one segment exists").clone();
    let len_before = fs::metadata(&latest).unwrap().len();
    // Cap truncation so we don't wipe the header (80 bytes). Anywhere
    // from 1..= (file_len - 80) is a valid "kill -9 mid-flush" point.
    let max_t = (len_before - 80).max(1);
    let t = rng.range(1, max_t.min(2048) + 1);
    let new_len = len_before - t;
    fs::OpenOptions::new()
        .write(true)
        .open(&latest)
        .unwrap()
        .set_len(new_len)
        .unwrap();

    // 3. Recover.
    let key = InMemoryKey::from_bytes(hex32(KEY_HEX));
    let writer =
        Writer::open(tmp.path(), Box::new(key), hex16(SESSION_HEX)).expect("recovery succeeds");
    let report = writer.recovery_report();
    assert!(
        matches!(
            report.action,
            RecoveryAction::Repaired | RecoveryAction::Resumed
        ),
        "iter: expected Repaired or Resumed; got {:?} (truncated {t} of {len_before})",
        report.action,
    );
    drop(writer);

    // 4. R3 verify.
    let key = InMemoryKey::from_bytes(hex32(KEY_HEX));
    let verifier = Verifier::new(Box::new(key));
    let verdict = verifier.verify(tmp.path()).expect("verify ran");
    assert_eq!(
        verdict.compact_verdict(),
        "Verified",
        "post-recovery verifier disagreed: {verdict:#?}"
    );

    // 5. Extend + reverify.
    {
        let key = InMemoryKey::from_bytes(hex32(KEY_HEX));
        let cfg = WriterConfig {
            segment_size_bytes,
            finalize_on_rollover: true,
        };
        let mut writer = Writer::with_config(tmp.path(), Box::new(key), hex16(SESSION_HEX), cfg)
            .expect("re-open");
        let base = writer.recovery_report().last_record_id.map_or(0, |r| r + 1);
        let seg_base = writer.recovery_report().current_segment_index as u64;
        for j in 0..3 {
            writer
                .append(sample(seg_base * 1_000_000 + base + j))
                .unwrap();
        }
        writer.flush().unwrap();
    }
    let key = InMemoryKey::from_bytes(hex32(KEY_HEX));
    let verifier = Verifier::new(Box::new(key));
    let verdict = verifier.verify(tmp.path()).expect("post-extend verify");
    assert_eq!(
        verdict.compact_verdict(),
        "Verified",
        "post-extend verifier disagreed: {verdict:#?}"
    );
}

#[test]
fn crash_recovery_100_random_truncations_single_segment() {
    let mut rng = Rng::new(0xC04A_FE17);
    for iter in 0..100 {
        let n = rng.range(5, 32);
        one_iteration(&mut rng, n, 64 * 1024 * 1024);
        eprintln!("iter {iter}: ok");
    }
}

#[test]
fn crash_recovery_100_random_truncations_with_rollover() {
    // Force segment rollovers by using a small segment_size_bytes.
    let mut rng = Rng::new(0xDEAD_C0DE);
    for iter in 0..100 {
        let n = rng.range(8, 48);
        one_iteration(&mut rng, n, 1024);
        eprintln!("iter {iter}: ok");
    }
}
