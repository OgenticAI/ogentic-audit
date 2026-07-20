//! `ogentic-audit checkpoint <log_dir>` — pin the current chain head.
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

use anyhow::anyhow;
use ogentic_audit_core::{Verdict, Verifier, VerifyOptions};

use crate::checkpoint_file::{now_rfc3339, CheckpointJson};
use crate::cli::{CheckpointArgs, GlobalArgs};
use crate::exit::ExitCodeKind;
use crate::keysource::{load_key, AppError};

pub fn run(global: &GlobalArgs, args: CheckpointArgs) -> Result<ExitCodeKind, AppError> {
    let key = load_key(global)?;
    let key_id = *key.key_id().as_bytes();
    let verifier = Verifier::new(key);

    let report = verifier
        .verify_with_options(&args.log_dir, VerifyOptions::default())
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
    let record_id = last_record_id_in_segment(&args.log_dir, segment)?;

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
