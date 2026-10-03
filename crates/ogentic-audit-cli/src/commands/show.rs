//! `ogentic-audit show <log_dir>` — pretty-print records.

use anyhow::anyhow;
use ogentic_audit_core::{PayloadValue, Reader};
use serde_json::{json, Value};

use crate::cli::{GlobalArgs, OutputFormat, ShowArgs};
use crate::exit::ExitCodeKind;
use crate::keysource::AppError;
use crate::output::{glob_match, hex};

pub fn run(_global: &GlobalArgs, args: ShowArgs) -> Result<ExitCodeKind, AppError> {
    if crate::commands::verify::detect_format(&args.log_dir)?
        == ogentic_audit_core::signed::FORMAT_VERSION_SIGNED
    {
        return show_signed(_global, &args);
    }
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

/// Show a signed (0x0002) log. Nothing is verified here; use `verify`.
fn show_signed(global: &GlobalArgs, args: &ShowArgs) -> Result<ExitCodeKind, AppError> {
    use ogentic_audit_core::signed::{names::escape, visit_records};
    let mut count = 0u64;
    let mut out_err: Option<AppError> = None;
    visit_records(&args.log_dir, |r| {
        if args.from.is_some_and(|f| r.position < f) || args.to.is_some_and(|t| r.position >= t) {
            return true;
        }
        let Ok(env) = &r.envelope else {
            println!("[s{}r{}] (envelope does not decode)", r.segment, r.position);
            return true;
        };
        let actor = match (&r.body, r.elided) {
            (_, true) => "(withheld)".to_string(),
            (Some(b), _) => b.actor.clone(),
            (None, _) => "(undecodable)".to_string(),
        };
        if args
            .actor
            .as_ref()
            .is_some_and(|a| !actor.contains(a.as_str()))
        {
            return true;
        }
        if args
            .event_glob
            .as_ref()
            .is_some_and(|g| !glob_match(g, &env.event))
        {
            return true;
        }
        let payload = r.body.as_ref().map(|b| cbor_to_json(&b.payload));
        match args.format {
            OutputFormat::Text => {
                println!(
                    "[s{}r{}] {} {} {}",
                    r.segment,
                    r.position,
                    escape(&env.ts_wall),
                    escape(&actor),
                    env.event
                );
                if let Some(Value::Object(m)) = &payload {
                    if !m.is_empty() {
                        println!(
                            "    payload: {}",
                            escape(&Value::Object(m.clone()).to_string())
                        );
                    }
                }
                println!("    record_hash: {}", hex(&r.record_hash));
            },
            OutputFormat::Json => {
                let v = json!({
                    "segment_index": r.segment,
                    "record_id": r.position,
                    "ts_wall": env.ts_wall,
                    "ts_mono_delta": env.ts_mono_delta,
                    "session_id_hex": hex(&env.session_id),
                    "actor": if r.elided { Value::Null } else { json!(actor) },
                    "event": env.event,
                    "payload": payload,
                    "elided": r.elided,
                    "key_id_hex": hex(&env.key_id),
                    "schema_version": env.schema_version,
                    "prev_hash_hex": hex(&env.prev_hash),
                    "record_hash_hex": hex(&r.record_hash),
                    "body_hash_hex": hex(&env.body_hash),
                    "signature_hex": hex(&r.signature),
                });
                match serde_json::to_string(&v) {
                    Ok(line) => println!("{line}"),
                    Err(e) => {
                        out_err = Some(AppError::io(anyhow!("serializing show JSON: {e}")));
                        return false;
                    },
                }
            },
        }
        count += 1;
        true
    })
    .map_err(|e| AppError::io(anyhow!("reading log: {e}")))?;
    if let Some(e) = out_err {
        return Err(e);
    }
    if !global.quiet && matches!(args.format, OutputFormat::Text) {
        eprintln!(
            "({count} record{} shown; nothing was verified)",
            if count == 1 { "" } else { "s" }
        );
    }
    Ok(ExitCodeKind::Success)
}

/// CBOR payload → JSON for display (bytes as `0x…`).
pub fn cbor_to_json(v: &ogentic_audit_core::cbor::Value) -> Value {
    use ogentic_audit_core::cbor::Value as C;
    match v {
        C::Uint(n) => json!(n),
        C::Nint(n) => json!(n),
        C::Bytes(b) => json!(format!("0x{}", hex(b))),
        C::Text(s) => json!(s),
        C::Bool(b) => json!(b),
        C::Array(items) => Value::Array(items.iter().map(cbor_to_json).collect()),
        C::Map(pairs) => {
            let mut m = serde_json::Map::new();
            for (k, val) in pairs {
                let key = match k {
                    C::Text(t) => t.clone(),
                    other => format!("{other:?}"),
                };
                m.insert(key, cbor_to_json(val));
            }
            Value::Object(m)
        },
    }
}
