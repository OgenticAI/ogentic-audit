//! `ogentic-audit show <log_dir>` — pretty-print records.

use anyhow::anyhow;
use ogentic_audit_core::{PayloadValue, Reader};
use serde_json::{json, Value};

use crate::cli::{GlobalArgs, OutputFormat, ShowArgs};
use crate::exit::ExitCodeKind;
use crate::keysource::AppError;
use crate::output::{glob_match, hex};

pub fn run(_global: &GlobalArgs, args: ShowArgs) -> Result<ExitCodeKind, AppError> {
    let reader =
        Reader::open(&args.log_dir).map_err(|e| AppError::io(anyhow!("opening log: {e}")))?;
    let mut iter = reader.iter();

    let mut count: u64 = 0;
    while let Some(record) = iter
        .next_record()
        .map_err(|e| AppError::io(anyhow!("reading record: {e}")))?
    {
        // record_id range filter — applies inside each segment.
        if let Some(from) = args.from {
            if record.record_id < from {
                continue;
            }
        }
        if let Some(to) = args.to {
            if record.record_id >= to {
                continue;
            }
        }
        if let Some(actor_filter) = &args.actor {
            if !record.actor.contains(actor_filter) {
                continue;
            }
        }
        if let Some(glob) = &args.event_glob {
            if !glob_match(glob, &record.event) {
                continue;
            }
        }
        match args.format {
            OutputFormat::Text => print_text(&record),
            OutputFormat::Json => print_json(&record)?,
        }
        count += 1;
    }
    if !_global.quiet && matches!(args.format, OutputFormat::Text) {
        eprintln!(
            "({count} record{} shown)",
            if count == 1 { "" } else { "s" }
        );
    }
    Ok(ExitCodeKind::Success)
}

fn print_text(record: &ogentic_audit_core::Record) {
    println!(
        "[s{}r{}] {} {} {}",
        record.segment_index, record.record_id, record.ts_wall, record.actor, record.event
    );
    if !record.payload.is_empty() {
        println!("    payload: {}", payload_to_inline(&record.payload));
    }
    println!("    hmac:    {}", hex(&record.hmac));
}

fn payload_to_inline(payload: &std::collections::BTreeMap<String, PayloadValue>) -> String {
    let mut parts = Vec::with_capacity(payload.len());
    for (k, v) in payload {
        parts.push(format!("{k}={}", payload_value_to_inline(v)));
    }
    parts.join(", ")
}

fn payload_value_to_inline(v: &PayloadValue) -> String {
    match v {
        PayloadValue::Uint(n) => n.to_string(),
        PayloadValue::Nint(n) => n.to_string(),
        PayloadValue::Text(s) => format!("\"{s}\""),
        PayloadValue::Bytes(b) => format!("0x{}", hex(b)),
        PayloadValue::Bool(b) => b.to_string(),
        PayloadValue::Map(_) => "{...}".into(),
        PayloadValue::List(_) => "[...]".into(),
    }
}

fn print_json(record: &ogentic_audit_core::Record) -> Result<(), AppError> {
    let value = json!({
        "segment_index": record.segment_index,
        "record_id": record.record_id,
        "ts_wall": record.ts_wall,
        "ts_mono_delta": record.ts_mono_delta,
        "session_id_hex": hex(&record.session_id),
        "actor": record.actor,
        "event": record.event,
        "payload": payload_to_json(&record.payload),
        "key_id_hex": hex(&record.key_id),
        "schema_version": record.schema_version,
        "prev_hash_hex": hex(&record.prev_hash),
        "hmac_hex": hex(&record.hmac),
    });
    let line = serde_json::to_string(&value)
        .map_err(|e| AppError::io(anyhow!("serializing show JSON: {e}")))?;
    println!("{line}");
    Ok(())
}

fn payload_to_json(payload: &std::collections::BTreeMap<String, PayloadValue>) -> Value {
    let mut map = serde_json::Map::with_capacity(payload.len());
    for (k, v) in payload {
        map.insert(k.clone(), payload_value_to_json(v));
    }
    Value::Object(map)
}

fn payload_value_to_json(v: &PayloadValue) -> Value {
    match v {
        PayloadValue::Uint(n) => json!(n),
        PayloadValue::Nint(n) => json!(n),
        PayloadValue::Text(s) => json!(s),
        PayloadValue::Bytes(b) => json!(format!("0x{}", hex(b))),
        PayloadValue::Bool(b) => json!(b),
        PayloadValue::Map(m) => payload_to_json(m),
        PayloadValue::List(items) => {
            Value::Array(items.iter().map(payload_value_to_json).collect())
        },
    }
}
