//! Byte-for-byte vector conformance for the v0.1 Writer.
//!
//! For each clean v0.1 golden vector (no `post_process` step), this test
//! drives the Writer through the same record sequence the reference
//! generator at `tools/gen_vectors.py` does, then asserts the resulting
//! `audit-NNNN.cbor` file(s) are byte-identical to what's committed in
//! the vector directory.
//!
//! Tamper vectors (`tampered-byte`, `missing-record`) are R3 / OGE-437
//! territory — the on-disk bytes there are *post-tamper* by design and
//! a conforming writer is supposed to produce the *pre-tamper* bytes.
//! Skipped here.
//!
//! This is the load-bearing correctness gate for [OGE-429 R1] AC 6 and
//! the first foothold for [OGE-441 Q2]'s cross-language conformance
//! suite.
//!
//! [OGE-429 R1]: https://linear.app/ogenticai/issue/OGE-429
//! [OGE-441 Q2]: https://linear.app/ogenticai/issue/OGE-441

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use ogentic_audit_core::{
    InMemoryKey, PayloadValue, RecordInput, Writer, WriterConfig, SESSION_ID_LEN,
};
use serde::Deserialize;

/// Repo path: where the committed vectors live.
fn vectors_dir() -> PathBuf {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    // ogentic-audit-core/Cargo.toml -> repo root -> tests/vectors/v0.1
    manifest.join("../../tests/vectors/v0.1")
}

#[derive(Deserialize)]
struct VectorInputs {
    key_hex: String,
    session_id_hex: String,
    #[serde(default)]
    writer_config: Option<ConfigJson>,
    records: RecordsField,
    #[serde(default)]
    post_process: Option<serde_json::Value>,
    #[serde(default)]
    expected_verdict: Option<String>,
}

#[derive(Deserialize)]
struct ConfigJson {
    #[serde(default)]
    segment_size_bytes: Option<u64>,
    #[serde(default)]
    finalize_on_rollover: Option<bool>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum RecordsField {
    Explicit(Vec<RecordJson>),
    Generated(GeneratedSpec),
}

#[derive(Deserialize)]
struct GeneratedSpec {
    mode: String,
    count: u64,
    template: GenTemplate,
}

#[derive(Deserialize)]
struct GenTemplate {
    ts_wall_base: String,
    #[serde(default)]
    ts_wall_step_ms: Option<u64>,
    #[serde(default)]
    ts_mono_step_ms: Option<u64>,
    actor: String,
    event: String,
    #[serde(default)]
    schema_version: Option<u8>,
    payload: serde_json::Value,
}

#[derive(Deserialize)]
struct RecordJson {
    ts_wall: String,
    ts_mono_delta: u64,
    actor: String,
    event: String,
    schema_version: u8,
    payload: serde_json::Value,
}

fn expand_records(spec: &VectorInputs) -> Vec<RecordInput> {
    match &spec.records {
        RecordsField::Explicit(list) => list.iter().map(to_record_input).collect(),
        RecordsField::Generated(gen) => {
            assert_eq!(gen.mode, "generated", "unknown generator mode");
            let step_ms = gen.template.ts_wall_step_ms.unwrap_or(1000);
            let mono_step_ms = gen.template.ts_mono_step_ms.unwrap_or(step_ms);
            let base_ms = iso_to_ms(&gen.template.ts_wall_base);
            let schema_version = gen.template.schema_version.unwrap_or(1);
            (0..gen.count)
                .map(|i| {
                    let wall_ms = base_ms + i * step_ms;
                    RecordInput {
                        ts_wall: ms_to_iso(wall_ms),
                        ts_mono_delta: i * mono_step_ms,
                        actor: gen.template.actor.clone(),
                        event: gen.template.event.clone(),
                        schema_version,
                        payload: resolve_payload_map(&gen.template.payload, i),
                    }
                })
                .collect()
        },
    }
}

fn to_record_input(j: &RecordJson) -> RecordInput {
    RecordInput {
        ts_wall: j.ts_wall.clone(),
        ts_mono_delta: j.ts_mono_delta,
        actor: j.actor.clone(),
        event: j.event.clone(),
        schema_version: j.schema_version,
        payload: resolve_payload_map(&j.payload, 0),
    }
}

/// Convert a serde_json::Value into our PayloadValue tree. Mirrors
/// `gen_vectors.py`'s `cbor_value` switch.
fn resolve_payload_map(v: &serde_json::Value, i: u64) -> BTreeMap<String, PayloadValue> {
    let serde_json::Value::Object(map) = v else {
        panic!("payload root must be a JSON object; got {v:?}");
    };
    let mut out = BTreeMap::new();
    for (k, val) in map {
        out.insert(k.clone(), resolve_payload_value(val, i));
    }
    out
}

fn resolve_payload_value(v: &serde_json::Value, i: u64) -> PayloadValue {
    match v {
        serde_json::Value::Bool(b) => PayloadValue::Bool(*b),
        serde_json::Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                PayloadValue::Uint(u)
            } else if let Some(s) = n.as_i64() {
                if s >= 0 {
                    PayloadValue::Uint(s as u64)
                } else {
                    PayloadValue::Nint(s)
                }
            } else {
                panic!("non-integer number in payload not supported at v0.1: {n:?}");
            }
        },
        serde_json::Value::String(s) => {
            if s == "$i" {
                PayloadValue::Uint(i)
            } else {
                PayloadValue::Text(s.clone())
            }
        },
        serde_json::Value::Array(items) => {
            PayloadValue::List(items.iter().map(|x| resolve_payload_value(x, i)).collect())
        },
        serde_json::Value::Object(_) => PayloadValue::Map(resolve_payload_map(v, i)),
        serde_json::Value::Null => {
            panic!("null in payload not supported at v0.1; gen_vectors.py rejects it too")
        },
    }
}

fn iso_to_ms(s: &str) -> u64 {
    // Format: YYYY-MM-DDTHH:MM:SS.mmmZ
    assert_eq!(s.len(), "2026-05-10T12:00:00.000Z".len(), "bad iso: {s}");
    let b = s.as_bytes();
    let parse = |from: usize, len: usize| -> i64 {
        std::str::from_utf8(&b[from..from + len])
            .unwrap()
            .parse()
            .unwrap()
    };
    let year = parse(0, 4);
    let month = parse(5, 2);
    let day = parse(8, 2);
    let hour = parse(11, 2);
    let minute = parse(14, 2);
    let second = parse(17, 2);
    let ms = parse(20, 3);
    let total = days_from_ymd(year, month as u32, day as u32) * 86_400_000
        + hour * 3_600_000
        + minute * 60_000
        + second * 1_000
        + ms;
    assert!(total >= 0, "negative epoch ms for {s}");
    total as u64
}

fn ms_to_iso(ms_total: u64) -> String {
    let ms = (ms_total % 1000) as u32;
    let total_secs = ms_total / 1000;
    let second = (total_secs % 60) as u32;
    let total_min = total_secs / 60;
    let minute = (total_min % 60) as u32;
    let total_hours = total_min / 60;
    let hour = (total_hours % 24) as u32;
    let total_days = (total_hours / 24) as i64;
    let (year, month, day) = ymd_from_days(total_days);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        year, month, day, hour, minute, second, ms
    )
}

fn days_from_ymd(year: i64, month: u32, day: u32) -> i64 {
    // Howard Hinnant's days_from_civil. Returns days since 1970-01-01.
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u32;
    let m = month;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe as i64 - 719_468
}

fn ymd_from_days(days_since_epoch: i64) -> (i64, u32, u32) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d)
}

fn build_writer_config(spec: &VectorInputs) -> WriterConfig {
    let mut cfg = WriterConfig::default();
    if let Some(j) = &spec.writer_config {
        if let Some(s) = j.segment_size_bytes {
            cfg.segment_size_bytes = s;
        }
        if let Some(f) = j.finalize_on_rollover {
            cfg.finalize_on_rollover = f;
        }
    }
    cfg
}

fn decode_hex_32(s: &str) -> [u8; 32] {
    assert_eq!(s.len(), 64, "expected 64-char hex; got {s:?}");
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}

fn decode_hex_16(s: &str) -> [u8; SESSION_ID_LEN] {
    assert_eq!(s.len(), 32, "expected 32-char hex; got {s:?}");
    let mut out = [0u8; SESSION_ID_LEN];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}

/// Run a single vector end-to-end. Returns Ok(()) on byte-for-byte
/// match; panics with a useful diff on mismatch.
fn run_vector(name: &str) {
    let vec_dir = vectors_dir().join(name);
    let inputs_text = fs::read_to_string(vec_dir.join("inputs.json")).expect("read inputs.json");
    let spec: VectorInputs = serde_json::from_str(&inputs_text).expect("parse inputs.json");

    if spec.post_process.is_some() {
        panic!(
            "vector {name} has post_process; tamper vectors are not in scope for R1, \
             skip it from the test list rather than calling run_vector"
        );
    }
    let _ = spec.expected_verdict; // unused for R1; the verifier (R3) consumes it

    let key = InMemoryKey::from_bytes(decode_hex_32(&spec.key_hex));
    let session_id = decode_hex_16(&spec.session_id_hex);
    let config = build_writer_config(&spec);
    let records = expand_records(&spec);

    let tmp = tempfile::tempdir().expect("tempdir");
    let mut writer = Writer::with_config(tmp.path(), Box::new(key), session_id, config)
        .expect("Writer::with_config");

    for input in records {
        writer.append(input).expect("append");
    }
    writer.flush().expect("flush");
    drop(writer);

    // Diff every audit-*.cbor in the temp dir against the committed
    // expected file.
    let mut expected_files: Vec<PathBuf> = fs::read_dir(&vec_dir)
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|f| f.to_str())
                .is_some_and(|name| name.starts_with("audit-") && name.ends_with(".cbor"))
        })
        .collect();
    expected_files.sort();

    let mut produced_files: Vec<PathBuf> = fs::read_dir(tmp.path())
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|f| f.to_str())
                .is_some_and(|name| name.starts_with("audit-") && name.ends_with(".cbor"))
        })
        .collect();
    produced_files.sort();

    assert_eq!(
        expected_files.len(),
        produced_files.len(),
        "vector {name}: expected {} segment files, writer produced {}",
        expected_files.len(),
        produced_files.len()
    );

    for (e, p) in expected_files.iter().zip(produced_files.iter()) {
        assert_eq!(
            e.file_name(),
            p.file_name(),
            "vector {name}: segment filenames diverged"
        );
        let expected = fs::read(e).expect("read expected");
        let produced = fs::read(p).expect("read produced");
        if expected != produced {
            let first_diff = expected
                .iter()
                .zip(produced.iter())
                .position(|(a, b)| a != b);
            // Persist the produced bytes for offline diffing — temp dir
            // gets cleaned up after panic otherwise.
            let dump_path = std::env::temp_dir().join(format!(
                "ogentic-audit-r1-{name}-{}",
                e.file_name().unwrap().to_string_lossy()
            ));
            let _ = fs::write(&dump_path, &produced);
            let win = first_diff.unwrap_or(0);
            let lo = win.saturating_sub(8);
            let hi = (win + 16).min(expected.len()).min(produced.len());
            let exp_slice: Vec<String> = expected[lo..hi]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            let prod_slice: Vec<String> = produced[lo..hi]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            panic!(
                "vector {name} ({}): byte mismatch\n\
                 expected {} bytes, produced {} bytes, first diff at byte {:?}\n\
                 expected[{lo}..{hi}]: {}\n\
                 produced[{lo}..{hi}]: {}\n\
                 produced bytes dumped to {}",
                e.file_name().unwrap().to_string_lossy(),
                expected.len(),
                produced.len(),
                first_diff,
                exp_slice.join(" "),
                prod_slice.join(" "),
                dump_path.display(),
            );
        }
    }
}

#[test]
fn empty_vector() {
    run_vector("empty");
}

#[test]
fn single_record_vector() {
    run_vector("single-record");
}

#[test]
fn one_thousand_records_vector() {
    run_vector("1k-records");
}

#[test]
fn segment_rollover_vector() {
    run_vector("segment-rollover");
}
