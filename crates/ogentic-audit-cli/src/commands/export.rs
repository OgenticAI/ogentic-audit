//! `ogentic-audit export <log_dir> --pdf <out>` — court-ready PDF.
//!
//! Self-contained PDF an attorney or compliance officer hands to a
//! court or auditor. Bit-reproducible given the same log + key +
//! generator version (the export emits a SHA-256 of the produced PDF
//! to stderr for hash-stable verification).
//!
//! PDF layout matches the OGE-438 spec:
//!
//! 1. Cover — log path, generation date (default 1970-01-01 for
//!    reproducibility; pass `--source-date` to override), generator
//!    version, custodian
//! 2. Integrity — verdict (verbatim from R3), key_id, chain head,
//!    record count, first/last record
//! 3. Provenance — cryptographic primitives, key source, format version
//! 4. Sample events — head 50 + tail 50 by default; all records under
//!    `--full`
//! 5. Format reference — one-page summary of the v0.1 spec
//!
//! [OGE-438]: https://linear.app/ogenticai/issue/OGE-438

use std::collections::BTreeMap;
use std::fs;
use std::io::BufWriter;

use anyhow::anyhow;
use ogentic_audit_core::{PayloadValue, Reader, Verdict, Verifier, VerifyOptions, FORMAT_VERSION};

use crate::cli::{ExportArgs, GlobalArgs};
use crate::exit::ExitCodeKind;
use crate::keysource::{load_key, AppError};
use crate::output::hex;
use crate::pdf::PdfBuilder;

pub fn run(global: &GlobalArgs, args: ExportArgs) -> Result<ExitCodeKind, AppError> {
    let key = load_key(global)?;
    let verifier = Verifier::new(key);
    let report = verifier
        .verify_with_options(&args.log_dir, VerifyOptions::default())
        .map_err(|e| AppError::io(anyhow!("verifier could not open log: {e}")))?;

    // Re-open the Reader to collect record metadata (the Verifier
    // consumed its own copy).
    let records = collect_records(&args.log_dir).map_err(AppError::io)?;

    let title = format!("Audit log verification: {}", args.log_dir.display());
    let producer = format!(
        "ogentic-audit/{} format v{:#06x}",
        ogentic_audit_core::VERSION,
        FORMAT_VERSION
    );
    let mut pdf = PdfBuilder::new(&title, &producer);

    let custodian = args.custodian.clone().unwrap_or_else(hostname_or_unknown);
    let generation_date = args
        .source_date
        .clone()
        .unwrap_or_else(|| "1970-01-01T00:00:00Z".into());

    // ---- Page 1: Cover ----
    pdf.new_page();
    pdf.h1("Audit Log Verification Report");
    pdf.skip();
    pdf.body(&format!("Log directory:   {}", args.log_dir.display()));
    pdf.body(&format!("Generated:       {generation_date}"));
    pdf.body(&format!("Generator:       {producer}"));
    pdf.body(&format!("Custodian:       {custodian}"));
    pdf.body(&format!("Total records:   {}", records.len()));
    pdf.body(&format!(
        "Segments:        {}",
        report.log.segments_inspected
    ));
    pdf.skip();
    pdf.body("This PDF is a self-contained, bit-reproducible report. The");
    pdf.body("verifier output is included verbatim. Recipients may");
    pdf.body("independently re-verify the underlying log against the");
    pdf.body("format specification documented at:");
    pdf.body("  https://github.com/OgenticAI/ogentic-audit/blob/main/docs/spec/v0.1.md");

    // ---- Page 2: Integrity verdict ----
    pdf.new_page();
    pdf.h1("Integrity verdict");
    pdf.skip();
    let verdict_line = match &report.verdict {
        Verdict::Verified => "VERIFIED".to_string(),
        Verdict::Violation => format!("VIOLATION - {}", report.compact_verdict()),
    };
    pdf.h2(&format!("Verdict: {verdict_line}"));
    pdf.skip();
    pdf.body("Key id (BLAKE3-256 of key material):");
    pdf.mono(&format!("  {}", report.log.key_id_hex));
    pdf.skip();
    if let Some(final_hmac) = &report.log.final_hmac_hex {
        pdf.body("Final chain HMAC:");
        pdf.mono(&format!("  {final_hmac}"));
    } else {
        pdf.body("Final chain HMAC: (log empty)");
    }
    pdf.skip();
    pdf.body(&format!(
        "Records inspected: {}",
        report.log.records_inspected
    ));
    if let Some(first) = records.first() {
        pdf.body(&format!(
            "First record:     {} {}",
            first.ts_wall, first.event
        ));
    }
    if let Some(last) = records.last() {
        pdf.body(&format!(
            "Last  record:     {} {}",
            last.ts_wall, last.event
        ));
    }

    if let Some(v) = &report.violation {
        pdf.skip();
        pdf.h2("Violation details (verbatim)");
        pdf.body(&format!("Kind:          {:?}", v.kind));
        pdf.body(&format!("Segment:       {}", v.location.segment_index));
        if let Some(rid) = v.location.record_id {
            pdf.body(&format!("Record id:     {rid}"));
        }
        pdf.body(&format!("Byte offset:   {}", v.location.byte_offset));
        pdf.body("Message:");
        for line in wrap(&v.message, 90) {
            pdf.body(&format!("  {line}"));
        }
    }

    // ---- Page 3: Provenance ----
    pdf.new_page();
    pdf.h1("Provenance");
    pdf.skip();
    pdf.body("Cryptographic primitives:");
    pdf.body("  HMAC-SHA256 (FIPS 198-1) for every record's MAC");
    pdf.body("  Canonical CBOR (RFC 8949 sec 4.2) for record payloads");
    pdf.body("  CRC32 (IEEE 802.3) for segment-header integrity");
    pdf.body("  BLAKE3-256 for key fingerprint (key_id)");
    pdf.skip();
    pdf.body("Key source:");
    pdf.body(&format!("  {}", describe_key_source(global)));
    pdf.skip();
    pdf.body(&format!("Format version:    0x{FORMAT_VERSION:04x} (v0.1)",));
    pdf.body(&format!(
        "Generator version: ogentic-audit/{}",
        ogentic_audit_core::VERSION
    ));

    // ---- Page 4+: Sample events ----
    pdf.new_page();
    pdf.h1("Sample events");
    pdf.skip();
    let (head, tail) = sample_slice(&records, 50, args.full);
    if head.is_empty() && tail.is_empty() {
        pdf.body("(no records in this log)");
    } else {
        if !head.is_empty() {
            pdf.h2(&format!(
                "Head ({} record{})",
                head.len(),
                if head.len() == 1 { "" } else { "s" }
            ));
            for r in head {
                emit_record_line(&mut pdf, r);
            }
        }
        if !tail.is_empty() {
            pdf.skip();
            pdf.h2(&format!(
                "Tail ({} record{})",
                tail.len(),
                if tail.len() == 1 { "" } else { "s" }
            ));
            for r in tail {
                emit_record_line(&mut pdf, r);
            }
        }
    }

    // ---- Final page: Format reference ----
    pdf.new_page();
    pdf.h1("v0.1 format reference (summary)");
    pdf.skip();
    pdf.body("This is a one-page summary; the full spec is at the URL on the cover.");
    pdf.skip();
    pdf.h2("Segment header (80 bytes)");
    pdf.body("  magic:        \"OGAU\"     (4 bytes, offset 0)");
    pdf.body("  version:      0x0001    (u16 LE, offset 4)");
    pdf.body("  segment_idx:  u16 LE    (offset 6)");
    pdf.body("  key_id:       32 bytes  (BLAKE3-256, offset 8)");
    pdf.body("  prev_final:   32 bytes  (HMAC of prev seg last record, offset 40)");
    pdf.body("  header_crc:   u32 LE    (CRC32 over [0,72), offset 72)");
    pdf.body("  reserved:     4 bytes   (zero-filled, offset 76)");
    pdf.skip();
    pdf.h2("Record framing");
    pdf.body("  len_prefix:   u32 LE (byte length of payload)");
    pdf.body("  payload:      canonical CBOR (record map, see below)");
    pdf.body("  hmac:         32 bytes (HMAC-SHA256 of payload)");
    pdf.body("  len_trailer:  u32 LE - MUST equal len_prefix");
    pdf.skip();
    pdf.h2("Record schema (CBOR map with int keys)");
    pdf.body("  1: record_id          (u64, monotonic per segment)");
    pdf.body("  2: prev_hash          (32 bytes, HMAC of preceding record)");
    pdf.body("  3: ts_wall            (RFC 3339 UTC, ms precision)");
    pdf.body("  4: ts_mono_delta      (u64 ms since session start)");
    pdf.body("  5: session_id         (16 bytes UUIDv4)");
    pdf.body("  6: actor              (text)");
    pdf.body("  7: event              (text, category.action)");
    pdf.body("  8: payload            (CBOR map, text keys)");
    pdf.body("  9: key_id             (32 bytes; must match header)");
    pdf.body(" 10: schema_version    (u8)");

    let bytes = pdf.finish();

    // Write to disk + emit SHA-256 to stderr (for the hash-stable AC).
    let pdf_path = &args.pdf;
    if let Some(parent) = pdf_path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .map_err(|e| AppError::io(anyhow!("creating {parent:?}: {e}")))?;
        }
    }
    let file = fs::File::create(pdf_path)
        .map_err(|e| AppError::io(anyhow!("creating {}: {e}", pdf_path.display())))?;
    let mut buf = BufWriter::new(file);
    crate::pdf::write_pdf(&mut buf, &bytes)
        .map_err(|e| AppError::io(anyhow!("writing PDF: {e}")))?;

    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let digest = hasher.finalize();
    let digest_hex = hex(&digest);
    if !global.quiet {
        eprintln!(
            "Wrote {} ({} bytes; sha256={})",
            pdf_path.display(),
            bytes.len(),
            digest_hex,
        );
    }

    Ok(ExitCodeKind::Success)
}

fn collect_records(log_dir: &std::path::Path) -> Result<Vec<RecordSummary>, anyhow::Error> {
    let reader = Reader::open(log_dir).map_err(|e| anyhow!("reading log: {e}"))?;
    let mut iter = reader.iter();
    let mut out = Vec::new();
    loop {
        match iter.next_record() {
            Ok(Some(record)) => {
                out.push(RecordSummary {
                    segment_index: record.segment_index,
                    record_id: record.record_id,
                    ts_wall: record.ts_wall.clone(),
                    actor: record.actor.clone(),
                    event: record.event.clone(),
                    hmac_hex: hex(&record.hmac),
                    payload_summary: summarize_payload(&record.payload),
                });
            },
            Ok(None) => break,
            // Tampered logs can fail to decode mid-walk (HMAC mismatch
            // would have been caught by the verifier already). Stop
            // at the first decode failure and return what we have —
            // the PDF still gets the verdict + provenance pages, and
            // the sample section truncates honestly at the broken
            // record.
            Err(_) => break,
        }
    }
    Ok(out)
}

struct RecordSummary {
    segment_index: u16,
    record_id: u64,
    ts_wall: String,
    actor: String,
    event: String,
    hmac_hex: String,
    payload_summary: String,
}

fn summarize_payload(p: &BTreeMap<String, PayloadValue>) -> String {
    if p.is_empty() {
        return String::new();
    }
    let mut parts = Vec::with_capacity(p.len());
    for (k, v) in p {
        let val = match v {
            PayloadValue::Uint(n) => n.to_string(),
            PayloadValue::Nint(n) => n.to_string(),
            PayloadValue::Text(s) => format!("\"{s}\""),
            PayloadValue::Bool(b) => b.to_string(),
            PayloadValue::Bytes(_) => "<bytes>".into(),
            PayloadValue::Map(_) => "{...}".into(),
            PayloadValue::List(_) => "[...]".into(),
        };
        parts.push(format!("{k}={val}"));
    }
    parts.join(", ")
}

fn sample_slice(
    records: &[RecordSummary],
    n: usize,
    full: bool,
) -> (&[RecordSummary], &[RecordSummary]) {
    if full || records.len() <= 2 * n {
        (records, &[])
    } else {
        let head = &records[..n];
        let tail = &records[records.len() - n..];
        (head, tail)
    }
}

fn emit_record_line(pdf: &mut PdfBuilder, r: &RecordSummary) {
    pdf.body(&format!(
        "[s{}r{}] {} {} {}",
        r.segment_index, r.record_id, r.ts_wall, r.actor, r.event
    ));
    if !r.payload_summary.is_empty() {
        pdf.body(&format!("    payload: {}", r.payload_summary));
    }
    pdf.mono(&format!("    hmac:    {}", r.hmac_hex));
}

fn describe_key_source(global: &GlobalArgs) -> String {
    use crate::cli::KeySource;
    match global.key_source {
        KeySource::Env => format!("env var {}", global.key_env),
        KeySource::File => match &global.key_file {
            Some(p) => format!("file {}", p.display()),
            None => "file (--key-file unset)".into(),
        },
        KeySource::Keychain => format!(
            "OS keychain, service={:?} account={:?}",
            global.keychain_service, global.keychain_account
        ),
    }
}

fn hostname_or_unknown() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "(unknown host)".into())
}

fn wrap(text: &str, max: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    for word in text.split_whitespace() {
        if current.is_empty() {
            current.push_str(word);
        } else if current.len() + 1 + word.len() <= max {
            current.push(' ');
            current.push_str(word);
        } else {
            out.push(std::mem::take(&mut current));
            current.push_str(word);
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}
