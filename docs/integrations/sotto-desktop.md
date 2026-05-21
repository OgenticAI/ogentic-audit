# Sotto Desktop integration guide

How to embed `ogentic-audit-core` inside Sotto Desktop's Tauri shell so user-facing actions produce a tamper-evident audit log.

Pairs with:

- **[OGE-59 — Sotto writer integration](https://linear.app/ogenticai/issue/OGE-59)** — wiring the Writer into Sotto's Rust main process.
- **[OGE-60 — Sotto verifier CLI requirement](https://linear.app/ogenticai/issue/OGE-60)** — covered by `ogentic-audit verify` / `export`.
- **[OGE-411 — Sotto Audit ledger surface](https://linear.app/ogenticai/issue/OGE-411)** — the in-app "Verify chain" / "Export PDF" UI.

> **Status:** v0.1 alpha. APIs may shift up to the v0.1.0 tag; the on-disk format is stable (pinned by [golden vectors](../../tests/vectors/v0.1)).

## Architecture at a glance

```
+-----------------------------------------------------------+
|  Sotto Desktop (Tauri)                                    |
|                                                           |
|  +--------------------------+   +---------------------+   |
|  |  WebView (UI)            |   |  Tauri main (Rust)  |   |
|  |  - Audit ledger view     |   |                     |   |
|  |  - "Verify chain" button |<->|  ogentic-audit-core |   |
|  |  - "Export PDF" button   |   |  (Writer, Verifier) |   |
|  +--------------------------+   |                     |   |
|                                 |  +-----------------+|   |
|                                 |  | KeyHandle via   ||   |
|                                 |  | OS Keychain     ||   |
|                                 |  | (ogentic-audit- ||   |
|                                 |  |  keychain)      ||   |
|                                 |  +-----------------+|   |
|                                 +---------------------+   |
|                                          |                |
|                                          v                |
|              ~/Library/Application Support/sotto/audit/   |
|              audit-0000.cbor                              |
+-----------------------------------------------------------+
```

**The writer lives in the Tauri main process, NOT in the WebView.** The WebView talks to the writer via `tauri::command` functions. Reasons:

1. **Key material never crosses the WebView boundary.** `KeyHandle` is consumed in Rust; the WebView only sees opaque results (record_id, verdict, PDF path).
2. **`F_FULLFSYNC` requires a native syscall** that the WebView can't make.
3. **The Writer is single-threaded** (`&mut self` on `append` / `flush`). Tauri commands serialize naturally via a `Mutex<Writer>` held in the app state.

## 1. Key acquisition (OS Keychain)

On macOS, `ogentic-audit-keychain::KeychainKey::load_or_generate` reads the key from `Login.keychain` under the named service / account, or generates + stores 32 random bytes if missing. The keychain entry is per-user, ACL-locked to the calling app, and survives app re-installs.

```rust
use ogentic_audit_keychain::KeychainKey;

// On first launch: 32 random bytes generated + stored.
// On every subsequent launch: same bytes returned.
let key = KeychainKey::load_or_generate("com.ogenticai.sotto", "audit-v1")?;
```

On Linux, the equivalent backend is Secret Service (libsecret); on Windows, Credential Manager.

## 2. App state holds a Mutex-wrapped Writer

```rust
use std::sync::Mutex;
use ogentic_audit_core::Writer;

pub struct AuditState {
    pub writer: Mutex<Writer>,
}

#[tauri::command]
fn audit_append(
    state: tauri::State<'_, AuditState>,
    actor: String,
    event: String,
    payload: serde_json::Value,
) -> Result<u64, String> {
    let mut w = state.writer.lock().map_err(|e| e.to_string())?;
    // Build RecordInput from caller-supplied fields. Real code would
    // sanitize `actor` / `event` and constrain `payload` to the
    // event-specific schema.
    use ogentic_audit_core::{RecordInput, PayloadValue};
    use std::collections::BTreeMap;
    let mut p = BTreeMap::new();
    if let Some(obj) = payload.as_object() {
        for (k, v) in obj {
            if let Some(s) = v.as_str() {
                p.insert(k.clone(), PayloadValue::Text(s.into()));
            } else if let Some(n) = v.as_u64() {
                p.insert(k.clone(), PayloadValue::Uint(n));
            } else if let Some(b) = v.as_bool() {
                p.insert(k.clone(), PayloadValue::Bool(b));
            }
            // Extend with int/list/map as needed.
        }
    }
    let id = w.append(RecordInput {
        ts_wall: now_rfc3339(),
        ts_mono_delta: monotonic_delta_ms(),
        actor,
        event,
        payload: p,
        schema_version: 1,
    }).map_err(|e| e.to_string())?;
    w.flush().map_err(|e| e.to_string())?;
    Ok(id)
}
```

`flush` on every append is the right default for the Sotto threat model: a user action is small enough that the fsync cost is amortized by the user's wait already, and we never want to lose an audit record because we batched.

## 3. Lifecycle — open at app start

```rust
fn setup(app: &mut tauri::App) -> Result<(), Box<dyn std::error::Error>> {
    use ogentic_audit_core::Writer;
    use ogentic_audit_keychain::KeychainKey;

    let key = KeychainKey::load_or_generate("com.ogenticai.sotto", "audit-v1")?;
    let audit_dir = app.path()
        .app_data_dir()?
        .join("audit");
    std::fs::create_dir_all(&audit_dir)?;

    let session_id = uuid::Uuid::new_v4().into_bytes();
    let writer = Writer::open(&audit_dir, Box::new(key), session_id)?;

    // Surface the recovery event to the UI if the previous session
    // ended unexpectedly.
    match writer.recovery_report().action {
        ogentic_audit_core::RecoveryAction::Repaired => {
            let report = writer.recovery_report().clone();
            app.emit("audit-recovery", serde_json::json!({
                "truncated_bytes": report.truncated_bytes,
                "last_record_id": report.last_record_id,
                "message": format!(
                    "Previous session ended unexpectedly; recovered to record {}",
                    report.last_record_id.unwrap_or(0)
                ),
            }))?;
        },
        _ => {}
    }

    app.manage(AuditState { writer: Mutex::new(writer) });
    Ok(())
}
```

The WebView listens for the `audit-recovery` event and shows a toast: *"Previous session ended unexpectedly; recovered to record 1234."*

## 4. Verifier UI — call the core directly

When the user clicks **"Verify chain"** in the Audit ledger view, the Tauri command runs the verifier in-process. No shelling out to a CLI binary.

```rust
#[tauri::command]
fn audit_verify(
    state: tauri::State<'_, AuditState>,
    app_handle: tauri::AppHandle,
) -> Result<serde_json::Value, String> {
    use ogentic_audit_core::{Verifier, VerifyOptions, Verdict};
    use ogentic_audit_keychain::KeychainKey;

    let key = KeychainKey::load_or_generate("com.ogenticai.sotto", "audit-v1")
        .map_err(|e| e.to_string())?;
    let audit_dir = app_handle.path()
        .app_data_dir()
        .map_err(|e| e.to_string())?
        .join("audit");

    let verifier = Verifier::new(Box::new(key));
    let report = verifier
        .verify_with_options(&audit_dir, VerifyOptions::default())
        .map_err(|e| e.to_string())?;

    Ok(serde_json::json!({
        "ok": matches!(report.verdict, Verdict::Verified),
        "compact": report.compact_verdict(),
        "records": report.log.records_inspected,
        "segments": report.log.segments_inspected,
        "violation": report.violation.map(|v| serde_json::json!({
            "kind": format!("{:?}", v.kind),
            "segment_index": v.location.segment_index,
            "record_id": v.location.record_id,
            "message": v.message,
        })),
    }))
}
```

The WebView gets back a JSON object it can render in the existing ledger UI. No subprocess overhead, no PATH dependency, no temp files.

## 5. Court-ready export — shell out OR use the library

For **"Export PDF"**, there are two equivalent options:

### Option A: Shell out to the CLI (simpler)

```rust
#[tauri::command]
async fn audit_export_pdf(
    app_handle: tauri::AppHandle,
    output_path: String,
    custodian: String,
) -> Result<String, String> {
    let audit_dir = app_handle.path()
        .app_data_dir()
        .map_err(|e| e.to_string())?
        .join("audit");

    let status = tokio::process::Command::new("ogentic-audit")
        .arg("export")
        .arg(&audit_dir)
        .arg("--pdf")
        .arg(&output_path)
        .arg("--custodian")
        .arg(&custodian)
        .arg("--source-date")
        .arg(chrono::Utc::now().to_rfc3339())
        .status()
        .await
        .map_err(|e| format!("spawning ogentic-audit: {e}"))?;

    if !status.success() {
        return Err(format!("ogentic-audit exited {}", status.code().unwrap_or(-1)));
    }
    Ok(output_path)
}
```

Pros: no extra Sotto Rust code; the binary is the canonical PDF generator. Cons: requires the user to have the `ogentic-audit` CLI installed (Sotto installer should bundle it).

### Option B: Use the library directly

Pull `crates/ogentic-audit-cli/src/pdf.rs`'s `PdfBuilder` (currently private) into a small library, or wait for v0.2 where we'll expose `ogentic_audit_export::pdf_report(log_dir, key, options)` as a stable surface. Recommended approach for v0.1: option A.

## 6. Crash recovery — let the library handle it

`Writer::open` does the recovery scan automatically. Sotto only needs to surface the result. The example in §3 emits an `audit-recovery` event on `RecoveryAction::Repaired`; the WebView shows a toast.

If recovery returns `WriterError::Recovery { reason: HmacMismatch / KeyIdMismatch / ChainBreak }`, that's structural tampering — Sotto should treat it as a critical incident:

```rust
match Writer::open(&audit_dir, Box::new(key), session_id) {
    Ok(writer) => writer,
    Err(WriterError::Recovery { reason }) => {
        // Archive the broken log to a side directory and start fresh.
        // DO NOT silently overwrite.
        let backup = audit_dir.with_file_name(format!(
            "audit-corrupt-{}",
            chrono::Utc::now().format("%Y%m%dT%H%M%S")
        ));
        std::fs::rename(&audit_dir, &backup)?;
        std::fs::create_dir_all(&audit_dir)?;
        log::error!(
            "audit log refused recovery ({reason:?}); archived to {} and starting fresh",
            backup.display()
        );
        // Notify the user, file a bug, ship the archive to support.
        let new_key = KeychainKey::load_or_generate("com.ogenticai.sotto", "audit-v1")?;
        let new_session = uuid::Uuid::new_v4().into_bytes();
        Writer::open(&audit_dir, Box::new(new_key), new_session)?
    },
    Err(e) => return Err(e.into()),
}
```

## Sample code

A minimal but complete Tauri example lives under [`examples/sotto-desktop-tauri/`](../../examples/sotto-desktop-tauri/) in this repo. It compiles standalone and demonstrates all four commands (`audit_append`, `audit_verify`, `audit_export_pdf`, plus recovery-event emission).

## Cross-reference

- [On-disk format spec](../spec/v0.1.md)
- [Threat model](../security/threat-model.md)
- [Court-defensibility brief](../legal/court-defensibility.md)
- [Key rotation policy](../security/key-rotation.md)
