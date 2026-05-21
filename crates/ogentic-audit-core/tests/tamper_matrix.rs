//! Single-byte tamper-matrix test (Q1 / OGE-440 AC 2).
//!
//! For every byte position in a known log, mutate the byte with each
//! of {flip, zero, random} and assert the R3 verifier flags the log as
//! not-verified. Across the matrix every mutation must produce some
//! `Verdict::Violation(_)` — the specific `ViolationKind` depends on
//! which region was touched (header bytes → `HeaderCorrupt`; record
//! payload bytes → `HmacMismatch` or `RecordCorrupt`; HMAC bytes →
//! `HmacMismatch`; len_prefix / len_trailer → `RecordCorrupt::TornTail`).
//!
//! Deterministic: the "random" mutation uses a fixed-seed xorshift64
//! PRNG so the regression case can be reproduced from CI logs.

mod common;

use std::fs;

use ogentic_audit_core::{InMemoryKey, Verdict, Verifier, Writer};

use common::{hex16, hex32, sample_record, KEY_HEX, SESSION_HEX};

/// Fixed-seed xorshift64.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed.max(1))
    }
    fn next_byte(&mut self) -> u8 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        (x & 0xff) as u8
    }
}

#[derive(Copy, Clone, Debug)]
enum Mutation {
    /// XOR the byte with 0xff. Always changes the byte.
    Flip,
    /// Set the byte to 0x00.
    Zero,
    /// Replace with a PRNG-supplied byte (resampled if equal to orig).
    Random,
}

impl Mutation {
    fn apply(self, orig: u8, rng: &mut Rng) -> u8 {
        match self {
            Mutation::Flip => orig ^ 0xff,
            Mutation::Zero => 0,
            Mutation::Random => {
                let mut b = rng.next_byte();
                while b == orig {
                    b = rng.next_byte();
                }
                b
            },
        }
    }
}

fn build_short_log(dir: &std::path::Path) {
    let key = InMemoryKey::from_bytes(hex32(KEY_HEX));
    let mut writer = Writer::open(dir, Box::new(key), hex16(SESSION_HEX)).unwrap();
    // 3 records — enough to exercise the chain transition and keep the
    // matrix tractable (~600 bytes × 3 mutations ≈ 1800 verifies).
    for i in 0..3 {
        writer.append(sample_record(i)).unwrap();
    }
    writer.flush().unwrap();
}

/// Run the full mutation matrix against the in-memory copy of the
/// segment file at `path`. For each (offset, Mutation) pair: mutate,
/// write to disk, R3 verify, assert non-verified, restore.
fn run_matrix(path: &std::path::Path) {
    let original = fs::read(path).unwrap();
    let mut mutated = original.clone();
    let mut rng = Rng::new(0xF1A6_C0DE_C0DE_F00D);

    let mutations = [Mutation::Flip, Mutation::Zero, Mutation::Random];
    let mut total = 0usize;
    let mut zero_skipped = 0usize;

    for offset in 0..original.len() {
        let orig = original[offset];
        for m in mutations {
            // `Zero` on a byte that's already zero is a no-op; skip.
            if let Mutation::Zero = m {
                if orig == 0 {
                    zero_skipped += 1;
                    continue;
                }
            }
            let new = m.apply(orig, &mut rng);
            assert_ne!(new, orig, "mutation must change the byte");
            mutated[offset] = new;
            fs::write(path, &mutated).unwrap();

            // Verify.
            let key = InMemoryKey::from_bytes(hex32(KEY_HEX));
            let verifier = Verifier::new(Box::new(key));
            let report_res = verifier.verify(path.parent().unwrap());
            let report = match report_res {
                Ok(r) => r,
                Err(e) => panic!(
                    "verifier returned a top-level error at offset {offset} (mutation {m:?}): {e}"
                ),
            };
            assert!(
                !matches!(report.verdict, Verdict::Verified),
                "verifier accepted a tampered log: offset={offset} mutation={m:?} \
                 orig=0x{orig:02x} new=0x{new:02x}\n  verdict={:?}\n",
                report.verdict,
            );

            // Restore for the next iteration.
            mutated[offset] = orig;
            fs::write(path, &mutated).unwrap();
            total += 1;
        }
    }
    eprintln!(
        "tamper-matrix: {total} verified, {zero_skipped} Zero-mutations skipped (byte already 0)"
    );
}

#[test]
fn every_byte_position_every_mutation_caught_by_verifier() {
    let tmp = tempfile::tempdir().unwrap();
    build_short_log(tmp.path());
    let seg_path = tmp.path().join("audit-0000.cbor");
    run_matrix(&seg_path);
}
