//! `ogentic-audit verify <log_dir>` — format-aware log verification.
//!
//! The log's format is read **before** any key is loaded (spec v0.2
//! §8.1):
//!
//! | format | caller supplied | result |
//! |---|---|---|
//! | 0x0002 | signed-mode input, or nothing | signed verification (nothing: at best "not verified", exit 4) |
//! | 0x0002 | an HMAC key | argument error (exit 3) |
//! | 0x0001 | any signed-mode input | `HmacLog` error (exit 3), never "verified" |
//! | 0x0001 | an HMAC key on the command line | v0.1 verification, labelled shared-key |
//! | 0x0001 | nothing | argument error (exit 3): no implicit key source |
//! | newer | anything | argument error (exit 3): upgrade the verifier |

use std::path::Path;

use anyhow::anyhow;
use ogentic_audit_core::signed::{
    log_format, unhex, SignedVerifier, SignedVerifyError, SignedVerifyOptions, SuppliedCheckpoint,
    FORMAT_VERSION_SIGNED,
};
use ogentic_audit_core::{Verdict, Verifier, VerifyOptions, VerifyReport};
use serde_json::json;

use crate::cli::{GlobalArgs, OutputFormat, VerifyArgs};
use crate::exit::ExitCodeKind;
use crate::keysource::{load_key, AppError};
use crate::signedargs;

/// Map a signed-verifier error onto the CLI's exit codes.
pub fn signed_error(e: SignedVerifyError) -> AppError {
    match e.exit_code() {
        2 => AppError::io(anyhow!("{e}")),
        _ => AppError::argument(anyhow!("{e}")),
    }
}

/// The format of the log in `dir`, or an error: no segments (exit 2), a
/// newer format than this verifier (exit 3).
pub fn detect_format(dir: &Path) -> Result<u16, AppError> {
    match log_format(dir) {
        Err(e) => Err(AppError::io(anyhow!("{}: {e}", dir.display()))),
        Ok(None) => Err(AppError::io(anyhow!(
            "no audit segments (audit-NNNN.cbor) in {}: nothing to verify",
            dir.display()
        ))),
        Ok(Some(v)) if v > FORMAT_VERSION_SIGNED => Err(AppError::argument(anyhow!(
            "this log uses format 0x{v:04x}; upgrade the verifier"
        ))),
        Ok(Some(v)) => Ok(v),
    }
}

fn checkpoint_is_v1(path: &Path) -> bool {
    std::fs::read_to_string(path)
        .map(|t| t.contains("ogentic-audit-checkpoint/v1"))
        .unwrap_or(false)
}

pub fn run(global: &GlobalArgs, args: VerifyArgs) -> Result<ExitCodeKind, AppError> {
    // --segment range: > 65535 is an argument error.
    let segment_filter = match args.segment {
        Some(n) if n > 65535 => {
            return Err(AppError::argument(anyhow!(
                "--segment {n} exceeds the maximum segment index 65535"
            )))
        },
        Some(n) => Some(n as u16),
        None => None,
    };
    let format = detect_format(&args.log_dir)?;
    let v1_checkpoint = args.checkpoint.iter().any(|p| checkpoint_is_v1(p));
    let signed_inputs = args.trust.any()
        || args.expect_log_id.is_some()
        || !args.witness.is_empty()
        || args.checkpoint.iter().any(|p| !checkpoint_is_v1(p));
    if let Some(seg_idx) = segment_filter {
        let seg_path = args.log_dir.join(format!("audit-{seg_idx:04}.cbor"));
        if !seg_path.exists() {
            return Err(AppError::io(anyhow!(
                "segment {seg_idx} not found in {}",
                args.log_dir.display()
            )));
        }
    }

    if format == 1 {
        if signed_inputs {
            return Err(signed_error(SignedVerifyError::HmacLog));
        }
        if !global.hmac_key_given() {
            return Err(AppError::argument(anyhow!(
                "this is an HMAC log; pass its key with --key-source or --key-file"
            )));
        }
        return run_v1(global, &args, segment_filter);
    }
    if global.hmac_key_given() {
        if format == FORMAT_VERSION_SIGNED {
            return Err(AppError::argument(anyhow!(
                "this is a signed log; pass the signer's public key or fingerprint (--public-key, --key-fingerprint, --trust), not an HMAC key"
            )));
        }
        return run_v1(global, &args, segment_filter);
    }
    if v1_checkpoint {
        return Err(AppError::argument(anyhow!(
            "a v1 (HMAC) checkpoint applies only to format 0x0001 logs; this log is signed"
        )));
    }
    run_signed(global, &args, segment_filter)
}

fn run_signed(
    global: &GlobalArgs,
    args: &VerifyArgs,
    segment_filter: Option<u16>,
) -> Result<ExitCodeKind, AppError> {
    let trust = signedargs::trust_context(&args.trust)?;
    let mut opts = SignedVerifyOptions::new().forensic(args.forensic || segment_filter.is_some());
    let mut cps = Vec::new();
    for p in &args.checkpoint {
        cps.push(
            SuppliedCheckpoint::load(p)
                .map_err(|e| AppError::argument(anyhow!("--checkpoint {}: {e}", p.display())))?,
        );
    }
    for w in &args.witness {
        let bytes = std::fs::read(w)
            .map_err(|e| AppError::argument(anyhow!("--witness {}: {e}", w.display())))?;
        let parsed = ogentic_audit_core::signed::WitnessCosignature::parse(&bytes)
            .map_err(|e| AppError::argument(anyhow!("--witness {}: {e}", w.display())))?;
        let target = cps
            .iter_mut()
            .find(|c| ogentic_audit_core::signed::sha256(&c.bytes) == parsed.checkpoint_sha256)
            .ok_or_else(|| {
                AppError::argument(anyhow!(
                    "--witness {}: it co-signs none of the supplied checkpoints",
                    w.display()
                ))
            })?;
        target
            .add_witness(w)
            .map_err(|e| AppError::argument(anyhow!("--witness {}: {e}", w.display())))?;
    }
    for c in cps {
        opts = opts.checkpoint(c);
    }
    if let Some(id) = &args.expect_log_id {
        let parsed: [u8; 16] = unhex(id.trim())
            .ok_or_else(|| AppError::argument(anyhow!("--expect-log-id must be 32 hex digits")))?;
        opts = opts.expect_log_id(parsed);
    }
    let mut report = SignedVerifier::new(trust)
        .verify_with_options(&args.log_dir, opts)
        .map_err(signed_error)?;
    if let Some(n) = segment_filter {
        report = report.filter_segment(n);
    }
    let marks = ogentic_audit_core::signed::report::Marks::new(signedargs::ascii(global));
    if args.summary {
        let l = &report.log;
        match report.verdict {
            Verdict::Verified => println!(
                "{} Verified · {} records · head {} · {}",
                marks.ok,
                l.records_inspected,
                l.final_record_hash
                    .map(|h| ogentic_audit_core::signed::hex(&h[..4]))
                    .unwrap_or_default(),
                if l.head_anchored {
                    "anchored"
                } else {
                    "tail not anchored"
                }
            ),
            Verdict::SelfConsistent => println!(
                "{} Not verified · {}",
                marks.warn,
                if report.not_verified_reason.map(|r| r.as_str()) == Some("no_signed_records") {
                    "no records to check"
                } else {
                    "no key supplied"
                }
            ),
            _ => println!(
                "{} Verification failed · {}",
                marks.fail,
                report.compact_verdict()
            ),
        }
    } else {
        match args.format {
            OutputFormat::Json => signedargs::print_json(&report.to_json()),
            OutputFormat::Text => print!(
                "{}",
                report.render_human(signedargs::ascii(global), "ogentic-audit")
            ),
        }
    }
    Ok(match report.verdict {
        Verdict::Verified => ExitCodeKind::Success,
        Verdict::SelfConsistent => ExitCodeKind::NotVerified,
        _ => ExitCodeKind::VerificationFailed,
    })
}

fn run_v1(
    global: &GlobalArgs,
    args: &VerifyArgs,
    segment_filter: Option<u16>,
) -> Result<ExitCodeKind, AppError> {
    let key = load_key(global)?;
    let verifier = Verifier::new(key);
    if args.checkpoint.len() > 1 {
        return Err(AppError::argument(anyhow!(
            "an HMAC log takes at most one --checkpoint"
        )));
    }
    let checkpoint = match args.checkpoint.first() {
        Some(path) => Some(crate::checkpoint_file::load(path)?),
        None => None,
    };
    // --segment narrows the report; it never improves the verdict, so
    // every segment is checked (forensic mode) before filtering.
    let opts = VerifyOptions::new()
        .forensic(args.forensic || segment_filter.is_some())
        .checkpoint(checkpoint);
    let mut report = verifier
        .verify_with_options(&args.log_dir, opts)
        .map_err(|e| match e {
            ogentic_audit_core::VerifyError::CheckpointKeyMismatch { .. } => {
                AppError::argument(anyhow!("{e}"))
            },
            other => AppError::io(anyhow!("verifier could not open log: {other}")),
        })?;
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
        _ => Ok(ExitCodeKind::VerificationFailed),
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
                "✓ Verified · {} events · chain head {} · shared key: anyone holding it could have written this log",
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
        _ => {
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
    if report.verdict == Verdict::Verified {
        println!(
            "Verified with a shared key: anyone holding this key could have written this log."
        );
    }
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
        _ => "tampered",
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
                "authentication": "shared-key",
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
                "authentication": "shared-key",
                "segments_verified": report.log.segments_inspected,
                "violation": violation_obj,
                "additional_violations": additional,
                "log": log_block,
            })
        },
        _ => {
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
/// `target_seg`. The report must come from a forensic run, so every
/// segment was actually checked: a segment the walk never reached can
/// not be reported clean.
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
