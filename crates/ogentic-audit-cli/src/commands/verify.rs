//! `ogentic-audit verify <log_dir>` — chain-integrity check via R3.

use anyhow::anyhow;
use ogentic_audit_core::{Verdict, Verifier, VerifyOptions, VerifyReport};
use serde_json::json;

use crate::cli::{GlobalArgs, OutputFormat, VerifyArgs};
use crate::exit::ExitCodeKind;
use crate::keysource::{load_key, AppError};

pub fn run(global: &GlobalArgs, args: VerifyArgs) -> Result<ExitCodeKind, AppError> {
    let key = load_key(global)?;
    let verifier = Verifier::new(key);
    let opts = VerifyOptions {
        forensic_mode: args.forensic,
    };

    // --segment scoping: validate the argument range first.
    // Values > 65535 are user errors (ArgumentError, exit 3), not I/O errors.
    let segment_filter = match args.segment {
        Some(n) if n > 65535 => {
            eprintln!("error: --segment {n} exceeds the maximum segment index 65535");
            return Ok(ExitCodeKind::ArgumentError);
        },
        Some(n) => Some(n as u16),
        None => None,
    };

    if let Some(seg_idx) = segment_filter {
        // Check that the requested segment file exists before running the full
        // verifier — gives a clear IoError (exit 2) rather than a spurious
        // violation from an empty directory.
        let seg_path = args.log_dir.join(format!("audit-{seg_idx:04}.cbor"));
        if !seg_path.exists() {
            eprintln!(
                "error: segment {seg_idx} not found in {}",
                args.log_dir.display()
            );
            return Ok(ExitCodeKind::IoError);
        }
    }

    // Run the full verifier against the real log directory.
    // For segment-scoped mode we filter the resulting report rather than
    // copying a segment into a temp dir and pretending it is genesis —
    // that approach incorrectly triggered genesis-HMAC logic for any
    // segment N > 0, causing false HmacMismatch / ChainBreak violations.
    let mut report = verifier
        .verify_with_options(&args.log_dir, opts)
        .map_err(|e| AppError::io(anyhow!("verifier could not open log: {e}")))?;

    // When a segment filter is active, restrict the report to violations
    // that belong to that segment. Violations in other segments are
    // irrelevant to the caller's question ("is segment N intact?").
    if let Some(seg_idx) = segment_filter {
        report = filter_report_to_segment(report, seg_idx);
    }

    if args.summary {
        print_summary(&report);
    } else {
        match args.format {
            OutputFormat::Text => print_text(&report, global.quiet),
            OutputFormat::Json => print_json(&report)?,
        }
    }

    match report.verdict {
        Verdict::Verified => Ok(ExitCodeKind::Success),
        Verdict::Violation => Ok(ExitCodeKind::VerificationFailed),
    }
}

/// One-line verdict output, suitable for embedding in homepage demos
/// and CI status checks. Mutually exclusive with `--format json`.
fn print_summary(report: &ogentic_audit_core::VerifyReport) {
    match (&report.verdict, &report.violation) {
        (Verdict::Verified, _) => {
            let head_prefix = report
                .log
                .final_hmac_hex
                .as_deref()
                .map(|h| &h[..h.len().min(8)])
                .unwrap_or("-");
            println!(
                "✓ Verified · {} events · chain head {}",
                report.log.records_inspected, head_prefix
            );
        },
        (Verdict::Violation, Some(v)) => {
            let rid = v
                .location
                .record_id
                .map(|r| r.to_string())
                .unwrap_or_else(|| "-".to_string());
            println!(
                "✗ Verification failed · {:?} at segment {} record {}",
                v.kind, v.location.segment_index, rid
            );
        },
        (Verdict::Violation, None) => {
            println!("✗ Verification failed · Unknown violation");
        },
    }
}

fn print_text(report: &ogentic_audit_core::VerifyReport, quiet: bool) {
    if !quiet {
        println!("log_dir:           {}", report.log.log_dir.display());
        println!("key_id:            {}", report.log.key_id_hex);
        println!("segments_inspected: {}", report.log.segments_inspected);
        println!("records_inspected:  {}", report.log.records_inspected);
        if let Some(final_hex) = &report.log.final_hmac_hex {
            println!("final_hmac:        {final_hex}");
        }
    }
    println!("verdict:           {}", report.compact_verdict());
    if let Some(violation) = &report.violation {
        // Violation detail goes to stderr — machine consumers parse stdout only.
        eprintln!();
        eprintln!("violation:");
        eprintln!("  kind:           {:?}", violation.kind);
        eprintln!("  segment:        {}", violation.location.segment_index);
        if let Some(rid) = violation.location.record_id {
            eprintln!("  record_id:      {rid}");
        }
        eprintln!("  byte_offset:    {}", violation.location.byte_offset);
        eprintln!("  message:        {}", violation.message);
        if !report.additional_violations.is_empty() {
            eprintln!();
            eprintln!(
                "additional violations: {}",
                report.additional_violations.len()
            );
            for v in &report.additional_violations {
                eprintln!(
                    "  - {:?} @ s{}r{:?}",
                    v.kind, v.location.segment_index, v.location.record_id
                );
            }
        }
    }
}

fn print_json(report: &ogentic_audit_core::VerifyReport) -> Result<(), AppError> {
    // JSON shape (new — v0.2 of the CLI JSON surface):
    //
    //   status: "ok" | "tampered"
    //   format_version: number
    //   segments_verified: number
    //   log: { … }                        (always)
    //   violation: { … }                  (only when status == "tampered")
    //   additional_violations: [ … ]      (only when status == "tampered")
    //
    // The old "verdict" and "compact" keys are removed. Any consumer
    // relying on those keys must update to "status".
    let status = match report.verdict {
        Verdict::Verified => "ok",
        Verdict::Violation => "tampered",
    };

    let log_block = json!({
        "log_dir": report.log.log_dir.to_string_lossy(),
        "key_id_hex": report.log.key_id_hex,
        "segments_inspected": report.log.segments_inspected,
        "records_inspected": report.log.records_inspected,
        "first_segment_index": report.log.first_segment_index,
        "last_segment_index": report.log.last_segment_index,
        "final_hmac_hex": report.log.final_hmac_hex,
    });

    let summary = match (&report.verdict, &report.violation) {
        (Verdict::Verified, _) => {
            json!({
                "status": status,
                "format_version": report.format_version,
                "segments_verified": report.log.segments_inspected,
                "log": log_block,
            })
        },
        (Verdict::Violation, Some(v)) => {
            // Violation detail also goes to stderr in JSON mode so
            // `jq`-based pipelines can parse stdout cleanly.
            eprintln!(
                "violation: {:?} at s{}r{:?} — {}",
                v.kind, v.location.segment_index, v.location.record_id, v.message
            );

            let violation_obj = json!({
                "kind": format!("{:?}", v.kind),
                "segment_index": v.location.segment_index,
                "record_id": v.location.record_id,
                "byte_offset": v.location.byte_offset,
                "message": v.message,
            });
            let additional = report
                .additional_violations
                .iter()
                .map(|v| {
                    json!({
                        "kind": format!("{:?}", v.kind),
                        "segment_index": v.location.segment_index,
                        "record_id": v.location.record_id,
                        "byte_offset": v.location.byte_offset,
                        "message": v.message,
                    })
                })
                .collect::<Vec<_>>();
            json!({
                "status": status,
                "format_version": report.format_version,
                "segments_verified": report.log.segments_inspected,
                "violation": violation_obj,
                "additional_violations": additional,
                "log": log_block,
            })
        },
        (Verdict::Violation, None) => {
            eprintln!("violation: unknown — verdict was Violation but no violation populated");
            json!({
                "status": status,
                "format_version": report.format_version,
                "segments_verified": report.log.segments_inspected,
                "violation": {
                    "kind": "Unknown",
                    "message": "verdict was Violation but no violation populated",
                },
                "additional_violations": [],
                "log": log_block,
            })
        },
    };

    let mut out = serde_json::to_string_pretty(&summary)
        .map_err(|e| AppError::io(anyhow!("serializing verify JSON: {e}")))?;
    out.push('\n');
    print!("{out}");
    Ok(())
}

/// Rebuild a `VerifyReport` keeping only violations that belong to
/// `target_seg`. If no violations remain after filtering the verdict
/// is upgraded to `Verified`.
///
/// Called when `--segment N` is active: cross-segment violations and
/// violations from segments other than N are irrelevant to whether
/// segment N itself is intact.
fn filter_report_to_segment(mut report: VerifyReport, target_seg: u16) -> VerifyReport {
    let primary_in_target = report
        .violation
        .as_ref()
        .map(|v| v.location.segment_index == target_seg)
        .unwrap_or(false);

    // Keep additional violations that belong to target_seg.
    let additional_in_target: Vec<_> = report
        .additional_violations
        .into_iter()
        .filter(|v| v.location.segment_index == target_seg)
        .collect();

    if primary_in_target {
        // Primary violation is from target — keep it; replace additional
        // with only those also from target.
        report.additional_violations = additional_in_target;
    } else {
        // Primary violation (if any) is not from target_seg.
        // Promote the first additional-from-target to primary, if there is one.
        let mut iter = additional_in_target.into_iter();
        report.violation = iter.next();
        report.additional_violations = iter.collect();
        if report.violation.is_none() {
            // No violations in target segment at all — it is clean.
            report.verdict = Verdict::Verified;
        }
    }

    report
}
