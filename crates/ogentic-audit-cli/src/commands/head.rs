//! `ogentic-audit head <log_dir>` — print the chain head + summary.
//!
//! Walks every record (via the Reader) so we can return the last
//! record's HMAC. Does NOT HMAC-verify the chain — `verify` is the
//! command for that. This is intentionally fast and key-free so
//! engineers can quickly spot-check a log's growth in CI.

use anyhow::anyhow;
use ogentic_audit_core::{Reader, HMAC_LEN};
use serde_json::json;

use crate::cli::{GlobalArgs, HeadArgs, OutputFormat};
use crate::exit::ExitCodeKind;
use crate::keysource::AppError;
use crate::output::hex;

pub fn run(_global: &GlobalArgs, args: HeadArgs) -> Result<ExitCodeKind, AppError> {
    let reader =
        Reader::open(&args.log_dir).map_err(|e| AppError::io(anyhow!("opening log: {e}")))?;
    let segments = reader
        .segments()
        .map_err(|e| AppError::io(anyhow!("listing segments: {e}")))?;
    let mut iter = reader.iter();

    let mut record_count: u64 = 0;
    let mut last_hmac = [0u8; HMAC_LEN];
    let mut last_segment: Option<u16> = None;
    let mut last_record_id: Option<u64> = None;
    let mut last_event: Option<String> = None;
    let mut last_actor: Option<String> = None;
    let mut last_key_id = [0u8; HMAC_LEN];
    let mut last_session = [0u8; ogentic_audit_core::SESSION_ID_LEN];

    while let Some(record) = iter
        .next_record()
        .map_err(|e| AppError::io(anyhow!("reading record: {e}")))?
    {
        record_count += 1;
        last_hmac = record.hmac;
        last_segment = Some(record.segment_index);
        last_record_id = Some(record.record_id);
        last_event = Some(record.event);
        last_actor = Some(record.actor);
        last_key_id = record.key_id;
        last_session = record.session_id;
    }

    match args.format {
        OutputFormat::Text => {
            if record_count == 0 {
                println!("(empty log; no records)");
                println!("segments: {}", segments.len());
            } else {
                // One-line plain output per AC.
                println!(
                    "{} records={} segments={} key_id={}",
                    hex(&last_hmac),
                    record_count,
                    segments.len(),
                    hex(&last_key_id),
                );
                println!(
                    "    last_segment={} last_record_id={} session_id={}",
                    last_segment.unwrap(),
                    last_record_id.unwrap(),
                    hex(&last_session),
                );
                if let (Some(actor), Some(event)) = (&last_actor, &last_event) {
                    println!("    last_actor={actor:?} last_event={event:?}");
                }
            }
        },
        OutputFormat::Json => {
            let value = json!({
                "record_count": record_count,
                "segments": segments.len(),
                "head_hmac_hex": if record_count == 0 { None } else { Some(hex(&last_hmac)) },
                "last_segment_index": last_segment,
                "last_record_id": last_record_id,
                "last_actor": last_actor,
                "last_event": last_event,
                "key_id_hex": if record_count == 0 { None } else { Some(hex(&last_key_id)) },
                "session_id_hex": if record_count == 0 { None } else { Some(hex(&last_session)) },
            });
            let mut text = serde_json::to_string_pretty(&value)
                .map_err(|e| AppError::io(anyhow!("serializing head JSON: {e}")))?;
            text.push('\n');
            print!("{text}");
        },
    }

    Ok(ExitCodeKind::Success)
}
