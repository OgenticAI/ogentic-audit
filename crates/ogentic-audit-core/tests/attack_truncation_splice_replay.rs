//! Adversarial: truncation, splice, replay, one-byte alteration.
//! Attacker: full write access to the log / release folder, no signing key.
//! Every test asserts the verifier REJECTS (or, where the spec sanctions
//! acceptance, asserts exactly the spec'd outcome).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use ogentic_audit_core::signed::format::{self, Frame, SignedHeader, HEADER_LEN};
use ogentic_audit_core::signed::statements::Head;
use ogentic_audit_core::signed::{
    unhex, verify_release, AttestationBuilder, CheckpointV2, FileSpec, InMemorySigner, LogSpec,
    Part, ReleaseOptions, Scope, SignedVerifier, SignedVerifyOptions, SignedWriter, Signer,
    SuppliedCheckpoint, TrustContext,
};
use ogentic_audit_core::{PayloadValue, RecordInput, Verdict, WriterConfig};

fn k(n: u8) -> InMemorySigner {
    let seeds = [
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
    ];
    InMemorySigner::from_seed(unhex(seeds[n as usize - 1]).unwrap())
}

fn input(i: u64) -> RecordInput {
    let mut payload = BTreeMap::new();
    payload.insert("n".to_string(), PayloadValue::Uint(i));
    RecordInput {
        ts_wall: format!("2026-10-03T12:{:02}:{:02}.000Z", i / 60, i % 60),
        ts_mono_delta: i * 1000,
        actor: "user:test".into(),
        event: "page.released".into(),
        payload,
        schema_version: 1,
    }
}

fn small() -> WriterConfig {
    WriterConfig {
        segment_size_bytes: 1024,
        ..WriterConfig::default()
    }
}

/// Write `n` records (starting at `from`) to `dir`, optionally sealing.
fn append(dir: &Path, session: u8, from: u64, n: u64, seal: bool, cfg: WriterConfig) {
    let mut w =
        SignedWriter::open_signed_with_config(dir, Box::new(k(1)), [session; 16], cfg).unwrap();
    for i in from..from + n {
        w.append(input(i)).unwrap();
    }
    if seal {
        w.seal().unwrap();
    }
    w.flush().unwrap();
}

fn pin() -> TrustContext {
    let mut t = TrustContext::new();
    t.pin_key(*k(1).public_key(), Some("k1"), Scope::DEFAULT)
        .unwrap();
    t
}

fn seg(dir: &Path, n: u16) -> PathBuf {
    dir.join(format!("audit-{n:04}.cbor"))
}

fn nsegs(dir: &Path) -> u16 {
    (0..1000u16).take_while(|i| seg(dir, *i).exists()).count() as u16
}

/// (start, end) byte ranges of the records of a segment file.
fn records(path: &Path) -> Vec<(usize, usize)> {
    let bytes = std::fs::read(path).unwrap();
    let mut c = std::io::Cursor::new(&bytes);
    c.set_position(HEADER_LEN as u64);
    let mut off = HEADER_LEN as u64;
    let mut out = Vec::new();
    while let Frame::Record(r) = format::read_frame(&mut c, off, bytes.len() as u64).unwrap() {
        out.push((off as usize, (off + r.total_len) as usize));
        off += r.total_len;
    }
    out
}

fn mutate(p: &Path, f: impl FnOnce(&mut Vec<u8>)) {
    let mut b = std::fs::read(p).unwrap();
    f(&mut b);
    std::fs::write(p, b).unwrap();
}

fn head_of(dir: &Path) -> (Head, String) {
    let r = SignedVerifier::new(TrustContext::new())
        .verify(dir)
        .unwrap();
    let (s, rid) = r.log.head.unwrap();
    (
        Head {
            log_id: r.log.log_id.unwrap(),
            segment: s,
            record_id: rid,
            record_count: r.log.records_inspected,
            record_hash: r.log.final_record_hash.unwrap(),
        },
        r.log.head_ts_wall.clone().unwrap(),
    )
}

fn signed_checkpoint(dir: &Path, observed_at: &str) -> SuppliedCheckpoint {
    let (head, ts) = head_of(dir);
    let cp = CheckpointV2 {
        alg: ogentic_audit_core::signed::SigAlg::Ed25519,
        key_id: k(1).public_key().fingerprint(),
        head,
        head_ts_wall: ts,
        observed_at: Some(observed_at.into()),
    };
    let bytes = cp.to_bytes();
    let sig = CheckpointV2::sign(&bytes, &k(1)).unwrap().into_bytes();
    SuppliedCheckpoint {
        bytes,
        sig: Some(sig),
        witnesses: vec![],
    }
}

fn verify(dir: &Path) -> ogentic_audit_core::signed::SignedVerifyReport {
    SignedVerifier::new(pin()).verify(dir).unwrap()
}

fn verify_cp(dir: &Path, cp: SuppliedCheckpoint) -> ogentic_audit_core::signed::SignedVerifyReport {
    SignedVerifier::new(pin())
        .verify_with_options(dir, SignedVerifyOptions::new().checkpoint(cp))
        .unwrap()
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        std::fs::copy(e.path(), to.join(e.file_name())).unwrap();
    }
}

/// A 3+-segment log (rolled over), not sealed.
fn multi(dir: &Path) {
    append(dir, 1, 0, 14, false, small());
    assert!(nsegs(dir) >= 3, "need >= 3 segments");
}

// ---------------------------------------------------------------- logs

#[test]
fn l01_drop_tail_records_no_checkpoint_is_unanchored() {
    let d = tempfile::tempdir().unwrap();
    append(d.path(), 1, 0, 6, false, WriterConfig::default());
    let recs = records(&seg(d.path(), 0));
    mutate(&seg(d.path(), 0), |b| b.truncate(recs[3].0));
    let r = verify(d.path());
    assert_eq!(r.verdict, Verdict::Verified);
    assert!(!r.log.head_anchored, "a cut tail must not be anchored");
}

#[test]
fn l02_drop_tail_of_sealed_log_loses_seal() {
    let d = tempfile::tempdir().unwrap();
    append(d.path(), 1, 0, 6, true, WriterConfig::default());
    assert!(verify(d.path()).log.head_anchored);
    let recs = records(&seg(d.path(), 0));
    mutate(&seg(d.path(), 0), |b| b.truncate(recs[4].0));
    let r = verify(d.path());
    assert_eq!(r.verdict, Verdict::Verified);
    assert!(!r.log.head_anchored && !r.log.sealed);
}

#[test]
fn l03_drop_tail_records_with_signed_checkpoint() {
    let d = tempfile::tempdir().unwrap();
    append(d.path(), 1, 0, 6, false, WriterConfig::default());
    let cp = signed_checkpoint(d.path(), "2026-10-03T13:00:00.000Z");
    let recs = records(&seg(d.path(), 0));
    mutate(&seg(d.path(), 0), |b| b.truncate(recs[5].0));
    assert_eq!(
        verify_cp(d.path(), cp).compact_verdict(),
        "CheckpointTruncated@s0r5"
    );
}

#[test]
fn l04_drop_trailing_segments_no_checkpoint() {
    let d = tempfile::tempdir().unwrap();
    multi(d.path());
    let n = nsegs(d.path());
    std::fs::remove_file(seg(d.path(), n - 1)).unwrap();
    let r = verify(d.path());
    assert_eq!(r.verdict, Verdict::Verified);
    assert!(!r.log.head_anchored);
    assert!(
        r.warnings
            .iter()
            .any(|w| w.kind == "RolledOverWithoutSuccessor"),
        "{:?}",
        r.warnings
    );
}

#[test]
fn l05_drop_trailing_segments_with_signed_checkpoint() {
    let d = tempfile::tempdir().unwrap();
    multi(d.path());
    let cp = signed_checkpoint(d.path(), "2026-10-03T13:00:00.000Z");
    let (h, _) = head_of(d.path());
    let n = nsegs(d.path());
    std::fs::remove_file(seg(d.path(), n - 1)).unwrap();
    assert_eq!(
        verify_cp(d.path(), cp).compact_verdict(),
        format!("CheckpointTruncated@s{}r{}", h.segment, h.record_id)
    );
}

#[test]
fn l06_strip_last_segment_to_header_with_checkpoint() {
    let d = tempfile::tempdir().unwrap();
    multi(d.path());
    let cp = signed_checkpoint(d.path(), "2026-10-03T13:00:00.000Z");
    let (h, _) = head_of(d.path());
    let n = nsegs(d.path());
    mutate(&seg(d.path(), n - 1), |b| b.truncate(HEADER_LEN));
    assert_eq!(
        verify_cp(d.path(), cp).compact_verdict(),
        format!("CheckpointTruncated@s{}r{}", h.segment, h.record_id)
    );
}

#[test]
fn l07_delete_middle_segment() {
    let d = tempfile::tempdir().unwrap();
    multi(d.path());
    std::fs::remove_file(seg(d.path(), 1)).unwrap();
    assert_eq!(
        verify(d.path()).compact_verdict(),
        "SegmentDiscontinuity@s1"
    );
}

#[test]
fn l08_reorder_segments() {
    let d = tempfile::tempdir().unwrap();
    multi(d.path());
    let tmp = d.path().join("x");
    std::fs::rename(seg(d.path(), 1), &tmp).unwrap();
    std::fs::rename(seg(d.path(), 2), seg(d.path(), 1)).unwrap();
    std::fs::rename(&tmp, seg(d.path(), 2)).unwrap();
    assert_eq!(
        verify(d.path()).compact_verdict(),
        "SegmentDiscontinuity@s1"
    );
}

#[test]
fn l09_splice_record_from_other_log_same_key_same_session() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    append(a.path(), 7, 0, 5, false, WriterConfig::default());
    append(b.path(), 7, 0, 5, false, WriterConfig::default());
    let ra = records(&seg(a.path(), 0));
    let rb = records(&seg(b.path(), 0));
    let bb = std::fs::read(seg(b.path(), 0)).unwrap();
    mutate(&seg(a.path(), 0), |x| {
        x.splice(ra[2].0..ra[2].1, bb[rb[2].0..rb[2].1].iter().copied());
    });
    assert_eq!(verify(a.path()).compact_verdict(), "ChainBreak@s0r2");
}

#[test]
fn l10_splice_record_from_later_session_of_same_log() {
    // Session 1 writes r0..r2, session 2 reopens and writes r3..r5.
    // Move r4 (session 2) in front of r3.
    let d = tempfile::tempdir().unwrap();
    append(d.path(), 1, 0, 3, false, WriterConfig::default());
    append(d.path(), 2, 3, 3, false, WriterConfig::default());
    let r = records(&seg(d.path(), 0));
    mutate(&seg(d.path(), 0), |x| {
        let r3 = x[r[3].0..r[3].1].to_vec();
        let r4 = x[r[4].0..r[4].1].to_vec();
        let mut swapped = r4;
        swapped.extend(r3);
        x.splice(r[3].0..r[4].1, swapped);
    });
    assert_eq!(verify(d.path()).compact_verdict(), "ChainBreak@s0r3");
}

#[test]
fn l11_splice_segment_from_other_log_same_key() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    multi(a.path());
    multi(b.path());
    std::fs::copy(seg(b.path(), 1), seg(a.path(), 1)).unwrap();
    assert_eq!(verify(a.path()).compact_verdict(), "LogIdMismatch@s1");
}

#[test]
fn l12_whole_log_swapped_for_other_log_same_key() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    append(a.path(), 1, 0, 5, true, WriterConfig::default());
    append(b.path(), 1, 0, 5, true, WriterConfig::default());
    let a_id = head_of(a.path()).0.log_id;
    let cp_a = signed_checkpoint(a.path(), "2026-10-03T13:00:00.000Z");
    let r = SignedVerifier::new(pin())
        .verify_with_options(b.path(), SignedVerifyOptions::new().expect_log_id(a_id))
        .unwrap();
    assert_eq!(r.compact_verdict(), "LogIdMismatch@s0");
    assert_eq!(
        verify_cp(b.path(), cp_a).compact_verdict(),
        "CheckpointForDifferentLog@s0"
    );
}

#[test]
fn l13_duplicate_record_replayed_in_place() {
    let d = tempfile::tempdir().unwrap();
    append(d.path(), 1, 0, 5, false, WriterConfig::default());
    let r = records(&seg(d.path(), 0));
    mutate(&seg(d.path(), 0), |x| {
        let dup = x[r[1].0..r[1].1].to_vec();
        x.splice(r[2].0..r[2].0, dup);
    });
    assert_eq!(verify(d.path()).compact_verdict(), "ChainBreak@s0r2");
}

#[test]
fn l14_remove_last_record_of_non_last_segment() {
    let d = tempfile::tempdir().unwrap();
    multi(d.path());
    let r = records(&seg(d.path(), 0));
    let last = r.len() - 1;
    mutate(&seg(d.path(), 0), |x| x.truncate(r[last].0));
    // Spec 8.3 table: "record removed -> ChainBreak at the removed record's position".
    // The verifier can only see it at the next segment's link.
    assert_eq!(
        verify(d.path()).compact_verdict(),
        "SegmentDiscontinuity@s1"
    );
}

#[test]
fn l15_replay_old_signed_checkpoint_after_truncating_to_it() {
    // A genuine, older signed checkpoint at r4; the log later grew to r9.
    // The attacker cuts r5..r9 and hands over the old checkpoint.
    let d = tempfile::tempdir().unwrap();
    append(d.path(), 1, 0, 5, false, WriterConfig::default());
    let old = signed_checkpoint(d.path(), "2026-10-03T13:00:00.000Z");
    append(d.path(), 1, 5, 5, false, WriterConfig::default());
    let recs = records(&seg(d.path(), 0));
    mutate(&seg(d.path(), 0), |b| b.truncate(recs[5].0));
    let r = verify_cp(d.path(), old);
    assert_eq!(r.verdict, Verdict::Verified);
    let human = r.render_human(false, "ogentic-audit");
    // DESIRED: an old checkpoint must not let the report say the end is confirmed.
    assert!(
        !human.contains("the end of the log is confirmed"),
        "BYPASS: replayed old checkpoint anchors a truncated log:\n{human}"
    );
}

#[test]
fn l16_header_only_segment_after_sealed_log() {
    let d = tempfile::tempdir().unwrap();
    append(d.path(), 1, 0, 3, true, WriterConfig::default());
    let (h, _) = head_of(d.path());
    let hdr = SignedHeader::new(1, h.log_id, k(1).public_key(), h.record_hash).to_bytes();
    std::fs::write(seg(d.path(), 1), hdr).unwrap();
    let r = verify(d.path());
    // Spec 6.3: nothing may follow log.sealed, "in that segment or in a later one".
    assert_eq!(
        r.compact_verdict(),
        "SealedLogExtended@s1",
        "warnings: {:?}, anchored={}, sealed={}",
        r.warnings.iter().map(|w| &w.kind).collect::<Vec<_>>(),
        r.log.head_anchored,
        r.log.sealed
    );
}

#[test]
fn l17_one_byte_envelope_sig_body_in_middle_segment() {
    for (what, pick) in [("envelope", 6usize), ("signature", 70), ("body", 0)] {
        let d = tempfile::tempdir().unwrap();
        multi(d.path());
        let r = records(&seg(d.path(), 1));
        let (s, e) = r[1];
        mutate(&seg(d.path(), 1), |b| {
            let i = if what == "body" { e - 10 } else { s + pick };
            b[i] ^= 1;
        });
        assert_eq!(
            verify(d.path()).compact_verdict(),
            "SignatureInvalid@s1r1",
            "{what}"
        );
    }
}

#[test]
fn l18_header_byte_without_and_with_crc_fix() {
    let d = tempfile::tempdir().unwrap();
    multi(d.path());
    mutate(&seg(d.path(), 1), |b| b[20] ^= 1);
    assert_eq!(verify(d.path()).compact_verdict(), "HeaderCorrupt@s1");

    // Segment 1 log_id changed and CRC recomputed.
    let d = tempfile::tempdir().unwrap();
    multi(d.path());
    mutate(&seg(d.path(), 1), |b| {
        b[20] ^= 1;
        let crc = crc32fast::hash(&b[..124]);
        b[124..128].copy_from_slice(&crc.to_le_bytes());
    });
    assert_eq!(verify(d.path()).compact_verdict(), "LogIdMismatch@s1");

    // Segment 0 log_id changed in EVERY segment, CRCs recomputed.
    let d = tempfile::tempdir().unwrap();
    multi(d.path());
    for n in 0..nsegs(d.path()) {
        mutate(&seg(d.path(), n), |b| {
            b[20] ^= 1;
            let crc = crc32fast::hash(&b[..124]);
            b[124..128].copy_from_slice(&crc.to_le_bytes());
        });
    }
    assert_eq!(verify(d.path()).compact_verdict(), "ChainBreak@s0r0");
}

#[test]
fn l19_directory_planted_as_segment() {
    let d = tempfile::tempdir().unwrap();
    append(d.path(), 1, 0, 3, false, WriterConfig::default());
    std::fs::create_dir(seg(d.path(), 1)).unwrap();
    let r = SignedVerifier::new(pin()).verify(d.path());
    // DESIRED: a violation at s1 (HeaderCorrupt), not an I/O error.
    match r {
        Ok(r) => assert!(r.verdict == Verdict::Violation, "{}", r.compact_verdict()),
        Err(e) => panic!("error instead of a finding (exit {}): {e}", e.exit_code()),
    }
}

#[test]
fn l20_segment0_version_bumped() {
    let d = tempfile::tempdir().unwrap();
    append(d.path(), 1, 0, 3, false, WriterConfig::default());
    mutate(&seg(d.path(), 0), |b| b[4] = 3);
    // Spec 4: a newer format is an argument error (exit 3) for a plain log.
    let e = SignedVerifier::new(pin()).verify(d.path()).unwrap_err();
    assert_eq!(e.exit_code(), 3);
}

// ------------------------------------------------------------- releases

struct Rel {
    _log: tempfile::TempDir,
    rel: tempfile::TempDir,
}

fn build_release(id: &str, multi_seg: bool, head: Option<(u16, u64)>) -> Rel {
    let log = tempfile::tempdir().unwrap();
    if multi_seg {
        append(log.path(), 1, 0, 14, head.is_none(), small());
    } else {
        append(log.path(), 1, 0, 5, head.is_none(), WriterConfig::default());
    }
    let rel = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(rel.path().join("pages")).unwrap();
    std::fs::write(rel.path().join("pages/0001.pdf"), b"%PDF page one").unwrap();
    std::fs::write(
        rel.path().join("Decisions.csv"),
        b"page,decision\n1,release\n2,withhold\n",
    )
    .unwrap();
    let mut b = AttestationBuilder::new(rel.path(), id);
    b.created_at("2026-10-03T12:00:00.000Z");
    b.add_file(FileSpec::new("pages/0001.pdf").role("page"));
    b.add_file(FileSpec::new("Decisions.csv").role("index").parts(vec![
        Part {
            name: "header".into(),
            offset: 0,
            length: 14,
        },
        Part {
            name: "row 1".into(),
            offset: 14,
            length: 10,
        },
        Part {
            name: "row 2".into(),
            offset: 24,
            length: 11,
        },
    ]));
    b.add_log(LogSpec {
        source: log.path().to_path_buf(),
        path: "Audit log".into(),
        head,
        elide: vec![],
    });
    b.write(&k(1)).unwrap();
    Rel { _log: log, rel }
}

fn vr(dir: &Path) -> Vec<String> {
    let r = verify_release(dir, &pin(), &ReleaseOptions::new()).unwrap();
    if r.verdict == Verdict::Verified {
        return vec!["Verified".into()];
    }
    r.violations.iter().map(|v| v.compact()).collect()
}

#[test]
fn r01_baseline_verified() {
    let r = build_release("2026-0147", true, None);
    assert_eq!(vr(r.rel.path()), vec!["Verified"]);
}

#[test]
fn r02_one_byte_page_index_attestation_sig() {
    let r = build_release("2026-0147", false, None);
    let p = r.rel.path();
    mutate(&p.join("pages/0001.pdf"), |b| b[3] ^= 1);
    mutate(&p.join("Decisions.csv"), |b| b[30] ^= 1);
    assert_eq!(
        vr(p),
        vec![
            "FileAltered@file:Decisions.csv#row 2",
            "FileAltered@file:pages/0001.pdf"
        ]
    );
    let r = build_release("2026-0147", false, None);
    let p = r.rel.path();
    mutate(&p.join("ogentic-audit-release.json"), |b| b[40] ^= 1);
    assert_eq!(vr(p), vec!["SignatureInvalid@attestation"]);
    let r = build_release("2026-0147", false, None);
    let p = r.rel.path();
    mutate(&p.join("ogentic-audit-release.json.sig"), |b| {
        let i = b.len() - 60; // inside the base64 signature
        b[i] = if b[i] == b'A' { b'B' } else { b'A' };
    });
    assert_eq!(vr(p), vec!["SignatureInvalid@attestation"]);
}

#[test]
fn r03_one_byte_in_released_log() {
    let r = build_release("2026-0147", true, None);
    let ld = r.rel.path().join("Audit log");
    let recs = records(&seg(&ld, 1));
    mutate(&seg(&ld, 1), |b| b[recs[1].0 + 8] ^= 1);
    assert_eq!(vr(r.rel.path())[0], "SignatureInvalid@log:Audit log/s1r1");
}

#[test]
fn r04_drop_tail_and_segments_in_release() {
    let r = build_release("2026-0147", true, None);
    let ld = r.rel.path().join("Audit log");
    let n = nsegs(&ld);
    let (h, _) = head_of(&ld);
    std::fs::remove_file(seg(&ld, n - 1)).unwrap();
    assert_eq!(
        vr(r.rel.path()),
        vec![format!(
            "CheckpointTruncated@log:Audit log/s{}r{}",
            h.segment, h.record_id
        )]
    );
}

#[test]
fn r05_reorder_and_delete_middle_segment_in_release() {
    let r = build_release("2026-0147", true, None);
    let ld = r.rel.path().join("Audit log");
    let tmp = r.rel.path().join("tmpx");
    std::fs::rename(seg(&ld, 1), &tmp).unwrap();
    std::fs::rename(seg(&ld, 2), seg(&ld, 1)).unwrap();
    std::fs::rename(&tmp, seg(&ld, 2)).unwrap();
    assert_eq!(vr(r.rel.path())[0], "SegmentDiscontinuity@log:Audit log/s1");
    let r = build_release("2026-0147", true, None);
    let ld = r.rel.path().join("Audit log");
    std::fs::remove_file(seg(&ld, 1)).unwrap();
    assert_eq!(vr(r.rel.path())[0], "SegmentDiscontinuity@log:Audit log/s1");
}

#[test]
fn r06_swap_log_for_other_log_same_key() {
    let a = build_release("A", false, None);
    let b = build_release("B", false, None);
    let la = a.rel.path().join("Audit log");
    std::fs::remove_dir_all(&la).unwrap();
    copy_dir(&b.rel.path().join("Audit log"), &la);
    assert_eq!(
        vr(a.rel.path()),
        vec!["CheckpointMismatch@log:Audit log/s0"]
    );
}

#[test]
fn r07_replay_older_attestation_of_same_files() {
    // Release v1 attests the log at s0r2; v2 (same files, same log) is sealed at r5.
    // The attacker replaces v2's attestation+sig with v1's.
    let v2 = build_release("2026-0147", false, None);
    let log_src = v2._log.path();
    let v1 = tempfile::tempdir().unwrap();
    for f in ["pages", "Decisions.csv"] {
        let s = v2.rel.path().join(f);
        if s.is_dir() {
            copy_dir(&s, &v1.path().join(f));
        } else {
            std::fs::copy(&s, v1.path().join(f)).unwrap();
        }
    }
    let mut b = AttestationBuilder::new(v1.path(), "2026-0147");
    b.created_at("2026-10-01T12:00:00.000Z");
    b.add_file(FileSpec::new("pages/0001.pdf").role("page"));
    b.add_file(FileSpec::new("Decisions.csv").role("index").parts(vec![
        Part {
            name: "header".into(),
            offset: 0,
            length: 14,
        },
        Part {
            name: "row 1".into(),
            offset: 14,
            length: 10,
        },
        Part {
            name: "row 2".into(),
            offset: 24,
            length: 11,
        },
    ]));
    b.add_log(LogSpec {
        source: log_src.to_path_buf(),
        path: "Audit log".into(),
        head: Some((0, 2)),
        elide: vec![],
    });
    b.write(&k(1)).unwrap();
    for f in [
        "ogentic-audit-release.json",
        "ogentic-audit-release.json.sig",
        "HOW-TO-VERIFY.txt",
    ] {
        std::fs::copy(v1.path().join(f), v2.rel.path().join(f)).unwrap();
    }
    let rep = verify_release(v2.rel.path(), &pin(), &ReleaseOptions::new()).unwrap();
    // Spec L4: records after the attested head are counted, not a failure.
    assert_eq!(rep.compact_verdict(), "Verified");
    let lr = rep.logs[0].report.as_ref().unwrap();
    assert_eq!(lr.log.records_after_head, 3);
}

#[test]
fn r08_plant_files_inside_reserved_dirs() {
    let r = build_release("2026-0147", false, None);
    let p = r.rel.path();
    std::fs::create_dir_all(p.join("ogentic-audit-witness")).unwrap();
    std::fs::create_dir_all(p.join("ogentic-audit-keys/sub")).unwrap();
    std::fs::write(
        p.join("ogentic-audit-witness/0002-unredacted.pdf"),
        b"%PDF secret",
    )
    .unwrap();
    std::fs::write(
        p.join("ogentic-audit-keys/sub/run-me.sh"),
        b"#!/bin/sh\necho Verified\n",
    )
    .unwrap();
    let got = vr(p);
    // DESIRED (spec 11.4 U1 / 11.1): a planted file that is neither a statement nor a
    // witness co-signature must not pass the headline verdict.
    assert!(
        got.iter()
            .any(|v| v.starts_with("UnattestedFile@file:ogentic-audit-witness/"))
            && got
                .iter()
                .any(|v| v.starts_with("UnattestedFile@file:ogentic-audit-keys/")),
        "BYPASS: planted files in reserved dirs accepted: {got:?}"
    );
}

#[test]
fn r09_plant_unlisted_log_dir() {
    let r = build_release("2026-0147", false, None);
    let other = r.rel.path().join("Other log");
    copy_dir(&r.rel.path().join("Audit log"), &other);
    let got = vr(r.rel.path());
    assert!(
        got.iter()
            .all(|v| v.starts_with("UnattestedFile@file:Other log/"))
            && !got.is_empty(),
        "{got:?}"
    );
}

#[test]
fn r10_segment0_version_byte_in_release_names_log() {
    let r = build_release("2026-0147", false, None);
    let ld = r.rel.path().join("Audit log");
    mutate(&seg(&ld, 0), |b| b[4] = 3);
    // DESIRED: one changed byte in an attested log is a violation naming it.
    match verify_release(r.rel.path(), &pin(), &ReleaseOptions::new()) {
        Ok(rep) => assert!(
            rep.violations
                .iter()
                .any(|v| v.compact().starts_with("log:Audit log")
                    || v.compact().contains("@log:Audit log")),
            "{}",
            rep.compact_verdict()
        ),
        Err(e) => panic!(
            "BYPASS (wrong item): error instead of a finding naming the log (exit {}): {e}",
            e.exit_code()
        ),
    }
}

#[test]
fn r11_directory_planted_as_segment_in_release() {
    let r = build_release("2026-0147", false, None);
    std::fs::create_dir(seg(&r.rel.path().join("Audit log"), 1)).unwrap();
    match verify_release(r.rel.path(), &pin(), &ReleaseOptions::new()) {
        Ok(rep) => assert_eq!(rep.verdict, Verdict::Violation, "{}", rep.compact_verdict()),
        Err(e) => panic!("error instead of a finding (exit {}): {e}", e.exit_code()),
    }
}

#[test]
fn r12_header_only_and_torn_tail_after_attested_head() {
    let r = build_release("2026-0147", false, None);
    let ld = r.rel.path().join("Audit log");
    let (h, _) = head_of(&ld);
    let hdr = SignedHeader::new(1, h.log_id, k(1).public_key(), h.record_hash).to_bytes();
    std::fs::write(seg(&ld, 1), hdr).unwrap();
    let rep = verify_release(r.rel.path(), &pin(), &ReleaseOptions::new()).unwrap();
    // The bundled log is sealed: nothing may follow log.sealed, not even an
    // unsigned header (spec §6.3, E3).
    assert_eq!(rep.compact_verdict(), "SealedLogExtended@log:Audit log/s1");

    // Unsealed log with an attested head: a header after it is L4, a warning.
    let r = build_release("2026-0147", false, Some((0, 4)));
    let ld = r.rel.path().join("Audit log");
    let (h, _) = head_of(&ld);
    let hdr = SignedHeader::new(1, h.log_id, k(1).public_key(), h.record_hash).to_bytes();
    std::fs::write(seg(&ld, 1), hdr).unwrap();
    let rep = verify_release(r.rel.path(), &pin(), &ReleaseOptions::new()).unwrap();
    assert_eq!(rep.compact_verdict(), "Verified", "{:?}", rep.warnings);
    assert!(rep.warnings.iter().any(|w| w.kind == "UnsignedLastSegment"));
}

#[test]
fn r13_swap_two_logs_between_attested_paths() {
    let la = tempfile::tempdir().unwrap();
    let lb = tempfile::tempdir().unwrap();
    append(la.path(), 1, 0, 4, true, WriterConfig::default());
    append(lb.path(), 1, 0, 4, true, WriterConfig::default());
    let rel = tempfile::tempdir().unwrap();
    let mut b = AttestationBuilder::new(rel.path(), "two");
    b.created_at("2026-10-03T12:00:00.000Z");
    for (src, p) in [(la.path(), "A"), (lb.path(), "B")] {
        b.add_log(LogSpec {
            source: src.to_path_buf(),
            path: p.into(),
            head: None,
            elide: vec![],
        });
    }
    b.write(&k(1)).unwrap();
    assert_eq!(vr(rel.path()), vec!["Verified"]);
    std::fs::rename(rel.path().join("A"), rel.path().join("tmp")).unwrap();
    std::fs::rename(rel.path().join("B"), rel.path().join("A")).unwrap();
    std::fs::rename(rel.path().join("tmp"), rel.path().join("B")).unwrap();
    assert_eq!(
        vr(rel.path()),
        vec!["CheckpointMismatch@log:A/s0", "CheckpointMismatch@log:B/s0"]
    );
}

#[test]
fn r14_strip_record_body_in_released_log() {
    // Elide a body the builder did not elide: rewrite body_len to 0.
    let r = build_release("2026-0147", false, None);
    let ld = r.rel.path().join("Audit log");
    let recs = records(&seg(&ld, 0));
    mutate(&seg(&ld, 0), |b| {
        let (s, e) = recs[1];
        let el = u32::from_le_bytes(b[s..s + 4].try_into().unwrap()) as usize;
        let bl_at = s + 4 + el + 64;
        let mut rec = b[s..bl_at].to_vec();
        rec.extend_from_slice(&0u32.to_le_bytes());
        rec.extend_from_slice(&(el as u32).to_le_bytes());
        b.splice(s..e, rec);
    });
    let rep = verify_release(r.rel.path(), &pin(), &ReleaseOptions::new()).unwrap();
    // Spec 5 / 8.3: an elided body is not a violation; it is counted and listed.
    assert_eq!(rep.compact_verdict(), "Verified");
    assert_eq!(
        rep.logs[0].report.as_ref().unwrap().log.elided_records,
        vec![(0, 1)]
    );
}

#[test]
fn l21_forged_header_only_successor_flips_anchoring() {
    // Genuine signed checkpoint at the segment.finalized record of s0 (the
    // moment of rollover). The log later grew into s1, s2. The attacker deletes
    // s1.. and checks anchoring with and without a forged header-only s1.
    let d = tempfile::tempdir().unwrap();
    multi(d.path());
    let s0only = tempfile::tempdir().unwrap();
    std::fs::copy(seg(d.path(), 0), seg(s0only.path(), 0)).unwrap();
    let cp = signed_checkpoint(s0only.path(), "2026-10-03T13:00:00.000Z");
    let (h0, _) = head_of(s0only.path());
    let r = verify_cp(s0only.path(), cp.clone());
    assert_eq!(r.verdict, Verdict::Verified);
    assert!(
        !r.log.head_anchored,
        "finalized without successor: not anchored"
    );
    let hdr = SignedHeader::new(1, h0.log_id, k(1).public_key(), h0.record_hash).to_bytes();
    std::fs::write(seg(s0only.path(), 1), hdr).unwrap();
    let r = verify_cp(s0only.path(), cp);
    assert_eq!(r.verdict, Verdict::Verified);
    // DESIRED: an unsigned, publicly forgeable header must not change anchoring.
    assert!(
        !r.log.head_anchored,
        "BYPASS: forged header-only successor turned anchoring on; warnings {:?}",
        r.warnings.iter().map(|w| &w.kind).collect::<Vec<_>>()
    );
}

#[test]
fn l22_witness_signature_passed_as_checkpoint_signature() {
    let d = tempfile::tempdir().unwrap();
    append(d.path(), 1, 0, 5, false, WriterConfig::default());
    let mut cp = signed_checkpoint(d.path(), "2026-10-03T13:00:00.000Z");
    // The log key's witness-namespace signature over the same bytes.
    let wsig = ogentic_audit_core::signed::signer::sign_detached(
        &k(1),
        ogentic_audit_core::signed::NS_WITNESS,
        &cp.bytes,
    )
    .unwrap();
    cp.sig = Some(wsig.into_bytes());
    let e = SignedVerifier::new(pin())
        .verify_with_options(d.path(), SignedVerifyOptions::new().checkpoint(cp))
        .unwrap_err();
    assert!(
        e.to_string().starts_with("CheckpointSignatureInvalid"),
        "{e}"
    );
}

#[test]
fn l23_checkpoint_record_count_lies() {
    // Attacker edits record_count of a signed checkpoint: sig breaks -> error;
    // unsigned copy with a wrong count -> CheckpointMismatch.
    let d = tempfile::tempdir().unwrap();
    append(d.path(), 1, 0, 5, false, WriterConfig::default());
    let cp = signed_checkpoint(d.path(), "2026-10-03T13:00:00.000Z");
    let mut c = CheckpointV2::parse(&cp.bytes).unwrap();
    c.head.record_count += 1;
    let forged = SuppliedCheckpoint {
        bytes: c.to_bytes(),
        sig: cp.sig.clone(),
        witnesses: vec![],
    };
    assert!(SignedVerifier::new(pin())
        .verify_with_options(d.path(), SignedVerifyOptions::new().checkpoint(forged))
        .is_err());
    let unsigned = SuppliedCheckpoint {
        bytes: c.to_bytes(),
        sig: None,
        witnesses: vec![],
    };
    assert_eq!(
        verify_cp(d.path(), unsigned).compact_verdict(),
        "CheckpointMismatch@s0r4"
    );
}
