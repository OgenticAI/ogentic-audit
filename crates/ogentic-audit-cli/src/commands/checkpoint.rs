//! `ogentic-audit checkpoint <log_dir>` — pin the current chain head.
//!
//! Signed logs (0x0002) get a v2 checkpoint (spec v0.2 §10.1), unsigned
//! (anyone's own observation) or signed by the log's key with `--sign`.
//! HMAC logs (0x0001) get the v1 checkpoint below, and need the HMAC key
//! named explicitly. `checkpoint compare` proves equivocation.
//!
//! Emits a `(segment, record_id, hmac)` triple for an external observer
//! to store. Later, `verify --checkpoint` can prove the log still
//! contains that history — the one question internal verification cannot
//! answer, because a keyholder who rewrites the chain also satisfies
//! every internal check.
//!
//! Two deliberate properties:
//!
//! 1. **Verify before emitting.** A checkpoint taken over a chain that
//!    is already broken would launder the break into a trusted anchor.
//! 2. **Refuse to checkpoint an empty log.** There is no history to pin,
//!    and a checkpoint at "nothing" would later match any log that also
//!    contains nothing.

use std::path::Path;

use anyhow::anyhow;
use ogentic_audit_core::signed::checkpoint::{self, Comparison};
use ogentic_audit_core::signed::{hex, CheckpointV2, Head, SignedVerifier};
use ogentic_audit_core::{Verdict, Verifier, VerifyOptions};

use crate::checkpoint_file::{now_rfc3339, CheckpointJson};
use crate::cli::{CheckpointArgs, CheckpointSub, GlobalArgs};
use crate::commands::verify::signed_error;
use crate::exit::ExitCodeKind;
use crate::keysource::{load_key, AppError};

pub fn run(global: &GlobalArgs, args: CheckpointArgs) -> Result<ExitCodeKind, AppError> {
    if let Some(CheckpointSub::Compare { a, b }) = &args.sub {
        return compare(a, b);
    }
    let log_dir = args
        .log_dir
        .clone()
        .ok_or_else(|| AppError::argument(anyhow!("checkpoint needs a log directory")))?;
    let format = crate::commands::verify::detect_format(&log_dir)?;
    if format == ogentic_audit_core::signed::FORMAT_VERSION_SIGNED {
        if global.hmac_key_given() {
            return Err(AppError::argument(anyhow!(
                "this is a signed log; an HMAC key does not apply"
            )));
        }
        return run_signed(global, &args, &log_dir);
    }
    if args.sign.is_some() || args.trust.any() {
        return Err(signed_error(
            ogentic_audit_core::signed::SignedVerifyError::HmacLog,
        ));
    }
    run_v1(
        global,
        CheckpointArgs {
            log_dir: Some(log_dir),
            ..args
        },
    )
}

fn read_with_sig(p: &Path) -> Result<(Vec<u8>, Vec<u8>), AppError> {
    let bytes =
        std::fs::read(p).map_err(|e| AppError::argument(anyhow!("{}: {e}", p.display())))?;
    let mut sig = p.as_os_str().to_os_string();
    sig.push(".sig");
    let sig = std::fs::read(&sig).map_err(|e| {
        AppError::argument(anyhow!(
            "{}.sig: {e} (a signed checkpoint is needed)",
            p.display()
        ))
    })?;
    Ok((bytes, sig))
}

fn compare(a: &Path, b: &Path) -> Result<ExitCodeKind, AppError> {
    let (ab, asig) = read_with_sig(a)?;
    let (bb, bsig) = read_with_sig(b)?;
    match checkpoint::compare(&ab, &asig, &bb, &bsig).map_err(|e| AppError::argument(anyhow!(e)))? {
        Comparison::Equivocation {
            key_id,
            head,
            other_record_hash,
        } => {
            println!(
                "Equivocation proven: the same key signed two different histories of one log."
            );
            println!("  Signer:   {}", key_id.to_grouped_hex());
            println!("  Log:      {}", hex(&head.log_id));
            println!("  Position: s{}r{}", head.segment, head.record_id);
            println!(
                "  First:    {} ({} records)",
                hex(&head.record_hash),
                head.record_count
            );
            println!("  Second:   {}", hex(&other_record_hash));
            println!("Both checkpoints and their signatures are the evidence; keep them together.");
            Ok(ExitCodeKind::VerificationFailed)
        },
        Comparison::NoEquivocation { reason } => {
            println!("No equivocation proven: {reason}.");
            Ok(ExitCodeKind::Success)
        },
        _ => Ok(ExitCodeKind::Success),
    }
}

fn run_signed(
    global: &GlobalArgs,
    args: &CheckpointArgs,
    log_dir: &Path,
) -> Result<ExitCodeKind, AppError> {
    let trust = crate::signedargs::trust_context(&args.trust)?;
    let report = SignedVerifier::new(trust)
        .verify(log_dir)
        .map_err(signed_error)?;
    if report.verdict == Verdict::Violation {
        eprintln!(
            "error: refusing to checkpoint a log that does not verify: {}",
            report.compact_verdict()
        );
        eprintln!("       a checkpoint over a broken chain would anchor the break as if it were trusted history.");
        return Ok(ExitCodeKind::VerificationFailed);
    }
    let (Some((segment, record_id)), Some(hash), Some(key_id), Some(log_id), Some(ts)) = (
        report.log.head,
        report.log.final_record_hash,
        report.log.key_id,
        report.log.log_id,
        report.log.head_ts_wall.clone(),
    ) else {
        return Err(AppError::argument(anyhow!(
            "log has no records — nothing to checkpoint"
        )));
    };
    let observed_at = match &args.observed_at {
        Some(o) => o.clone(),
        None => ogentic_audit_core::signed::now_rfc3339(),
    };
    if ogentic_audit_core::signed::parse_rfc3339_millis(&observed_at).is_none() {
        return Err(AppError::argument(anyhow!(
            "--observed-at must be RFC 3339 UTC with milliseconds, like 2026-10-03T12:00:00.000Z"
        )));
    }
    let cp = CheckpointV2 {
        alg: report
            .signer
            .as_ref()
            .map_or(ogentic_audit_core::signed::SigAlg::Ed25519, |s| s.alg),
        key_id,
        head: Head {
            log_id,
            segment,
            record_id,
            record_count: report.log.records_inspected,
            record_hash: hash,
        },
        head_ts_wall: ts,
        observed_at: Some(observed_at),
    };
    let bytes = cp.to_bytes();
    let sig = match &args.sign {
        Some(spec) => {
            let signer = crate::signedargs::load_signer(spec)?;
            if signer.public_key().fingerprint() != key_id {
                return Err(AppError::argument(anyhow!(
                    "only the log's own key signs its checkpoints; {spec} is {}, the log is signed by {}",
                    signer.public_key().fingerprint().to_grouped_hex(),
                    key_id.to_grouped_hex()
                )));
            }
            Some(
                CheckpointV2::sign(&bytes, signer.as_ref())
                    .map_err(|e| AppError::io(anyhow!("signing: {e}")))?,
            )
        },
        None => None,
    };
    match (&args.out, sig) {
        (Some(path), sig) => {
            std::fs::write(path, &bytes)
                .map_err(|e| AppError::io(anyhow!("writing {}: {e}", path.display())))?;
            if let Some(sig) = sig {
                let mut sp = path.as_os_str().to_os_string();
                sp.push(".sig");
                std::fs::write(&sp, sig)
                    .map_err(|e| AppError::io(anyhow!("writing signature: {e}")))?;
            }
            if !global.quiet {
                eprintln!(
                    "checkpoint written to {} (s{segment}r{record_id})",
                    path.display()
                );
                eprintln!("store it somewhere the writer of this log cannot reach — a copy kept");
                eprintln!("beside the log proves nothing, because both can be rewritten together.");
            }
        },
        (None, Some(_)) => {
            return Err(AppError::argument(anyhow!(
                "--sign needs --out (the signature goes to <out>.sig)"
            )))
        },
        (None, None) => println!("{}", String::from_utf8_lossy(&bytes)),
    }
    Ok(ExitCodeKind::Success)
}

fn run_v1(global: &GlobalArgs, args: CheckpointArgs) -> Result<ExitCodeKind, AppError> {
    if !global.hmac_key_given() {
        return Err(AppError::argument(anyhow!(
            "this is an HMAC log; pass its key with --key-source or --key-file"
        )));
    }
    let log_dir = args.log_dir.clone().unwrap_or_default();
    let key = load_key(global)?;
    let key_id = *key.key_id().as_bytes();
    let verifier = Verifier::new(key);

    let report = verifier
        .verify_with_options(&log_dir, VerifyOptions::default())
        .map_err(|e| AppError::io(anyhow!("verifier could not open log: {e}")))?;

    // Property 1: never anchor a broken chain.
    if report.verdict != Verdict::Verified {
        let detail = report
            .violation
            .as_ref()
            .map(|v| v.message.clone())
            .unwrap_or_else(|| "chain verification failed".to_string());
        eprintln!("error: refusing to checkpoint a log that does not verify: {detail}");
        eprintln!("       fix or preserve the log first; a checkpoint over a broken chain");
        eprintln!("       would anchor the break as if it were trusted history.");
        return Ok(ExitCodeKind::VerificationFailed);
    }

    // Property 2: nothing to pin.
    let (Some(segment), Some(head_hex)) = (
        report.log.last_segment_index,
        report.log.final_hmac_hex.as_deref(),
    ) else {
        eprintln!("error: log has no records — nothing to checkpoint");
        return Ok(ExitCodeKind::ArgumentError);
    };

    // `records_inspected` counts every record across all segments, but
    // `record_id` is per-segment, so derive the head's record id from
    // the last segment's own count rather than the global total.
    let record_id = last_record_id_in_segment(&log_dir, segment)?;

    let hmac = decode_head(head_hex)?;
    let observed_at = args.observed_at.unwrap_or_else(now_rfc3339);
    let json = CheckpointJson::from_parts(&key_id, segment, record_id, &hmac, observed_at);

    let mut text = serde_json::to_string_pretty(&json)
        .map_err(|e| AppError::io(anyhow!("serializing checkpoint: {e}")))?;
    text.push('\n');

    match &args.out {
        Some(path) => {
            std::fs::write(path, &text)
                .map_err(|e| AppError::io(anyhow!("writing {}: {e}", path.display())))?;
            if !global.quiet {
                eprintln!(
                    "checkpoint written to {} (s{segment}r{record_id})",
                    path.display()
                );
                eprintln!("store it somewhere the writer of this log cannot reach — a copy kept");
                eprintln!("beside the log proves nothing, because both can be rewritten together.");
            }
        },
        None => print!("{text}"),
    }

    Ok(ExitCodeKind::Success)
}

/// Count the records in `segment` to find the head's per-segment
/// `record_id`. The log verified clean immediately above, so a
/// read failure here is a genuine I/O problem.
fn last_record_id_in_segment(log_dir: &std::path::Path, segment: u16) -> Result<u64, AppError> {
    use ogentic_audit_core::Reader;

    let reader = Reader::open(log_dir).map_err(|e| AppError::io(anyhow!("opening log: {e}")))?;
    let mut iter = reader.iter();
    let mut last: Option<u64> = None;
    while let Some(record) = iter
        .next_record()
        .map_err(|e| AppError::io(anyhow!("reading record: {e}")))?
    {
        if record.segment_index == segment {
            last = Some(record.record_id);
        }
    }
    last.ok_or_else(|| AppError::io(anyhow!("segment {segment} contained no records")))
}

fn decode_head(head_hex: &str) -> Result<[u8; ogentic_audit_core::HMAC_LEN], AppError> {
    let bytes = hex::decode(head_hex)
        .map_err(|e| AppError::io(anyhow!("chain head is not valid hex: {e}")))?;
    bytes
        .try_into()
        .map_err(|_| AppError::io(anyhow!("chain head has unexpected length")))
}
