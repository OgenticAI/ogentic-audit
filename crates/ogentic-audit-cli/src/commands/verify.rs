//! `ogentic-audit verify <log_dir>` — chain-integrity check via R3.

use anyhow::anyhow;
use ogentic_audit_core::{Verdict, Verifier, VerifyOptions};
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
    let report = verifier
        .verify_with_options(&args.log_dir, opts)
        .map_err(|e| AppError::io(anyhow!("verifier could not open log: {e}")))?;

    match args.format {
        OutputFormat::Text => print_text(&report, global.quiet),
        OutputFormat::Json => print_json(&report)?,
    }

    match report.verdict {
        Verdict::Verified => Ok(ExitCodeKind::Success),
        Verdict::Violation => Ok(ExitCodeKind::VerificationFailed),
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
        println!();
        println!("violation:");
        println!("  kind:           {:?}", violation.kind);
        println!("  segment:        {}", violation.location.segment_index);
        if let Some(rid) = violation.location.record_id {
            println!("  record_id:      {rid}");
        }
        println!("  byte_offset:    {}", violation.location.byte_offset);
        println!("  message:        {}", violation.message);
        if !report.additional_violations.is_empty() {
            println!();
            println!(
                "additional violations: {}",
                report.additional_violations.len()
            );
            for v in &report.additional_violations {
                println!(
                    "  - {:?} @ s{}r{:?}",
                    v.kind, v.location.segment_index, v.location.record_id
                );
            }
        }
    }
}

fn print_json(report: &ogentic_audit_core::VerifyReport) -> Result<(), AppError> {
    let verdict_json = match (&report.verdict, &report.violation) {
        (Verdict::Verified, _) => json!("Verified"),
        (Verdict::Violation, Some(v)) => json!({
            "kind": format!("{:?}", v.kind),
            "segment_index": v.location.segment_index,
            "record_id": v.location.record_id,
            "byte_offset": v.location.byte_offset,
            "message": v.message,
        }),
        (Verdict::Violation, None) => json!({
            "kind": "Unknown",
            "message": "verdict was Violation but no violation populated",
        }),
    };
    let summary = json!({
        "format_version": report.format_version,
        "verdict": verdict_json,
        "compact": report.compact_verdict(),
        "log": {
            "log_dir": report.log.log_dir.to_string_lossy(),
            "key_id_hex": report.log.key_id_hex,
            "segments_inspected": report.log.segments_inspected,
            "records_inspected": report.log.records_inspected,
            "first_segment_index": report.log.first_segment_index,
            "last_segment_index": report.log.last_segment_index,
            "final_hmac_hex": report.log.final_hmac_hex,
        },
        "additional_violations": report
            .additional_violations
            .iter()
            .map(|v| json!({
                "kind": format!("{:?}", v.kind),
                "segment_index": v.location.segment_index,
                "record_id": v.location.record_id,
                "byte_offset": v.location.byte_offset,
                "message": v.message,
            }))
            .collect::<Vec<_>>(),
    });
    let mut out = serde_json::to_string_pretty(&summary)
        .map_err(|e| AppError::io(anyhow!("serializing verify JSON: {e}")))?;
    out.push('\n');
    print!("{out}");
    Ok(())
}
