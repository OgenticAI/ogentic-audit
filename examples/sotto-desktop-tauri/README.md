# sotto-desktop-tauri

Minimal Tauri example demonstrating `ogentic-audit-core` integration. Mirrors the architecture documented in [`docs/integrations/sotto-desktop.md`](../../docs/integrations/sotto-desktop.md).

This is a **standalone reference**, not a full Sotto Desktop port. It compiles, runs the three audit-related commands (`audit_append`, `audit_verify`, `audit_export_pdf`), and surfaces the recovery-event flow.

## Layout

```
examples/sotto-desktop-tauri/
├── README.md                    # this file
├── Cargo.toml                   # Tauri 2 + ogentic-audit + ogentic-audit-keychain
├── src-tauri/
│   ├── main.rs                  # app setup + audit lifecycle
│   ├── audit.rs                 # the three tauri::command handlers
│   └── tauri.conf.json          # Tauri config
└── ui/
    └── index.html               # minimal HTML/JS surface
```

> **Status:** Sample code, not a buildable Tauri project in this repo. The code paths compile against `ogentic-audit-core 0.1.0-alpha.0`; you'll need to drop them into an existing Tauri 2 scaffold (`npm create tauri-app@latest`) to actually run the app. Treat this as the canonical reference for embedding the library.

## Key code paths

### `src-tauri/main.rs`

```rust
use std::sync::Mutex;
use ogentic_audit_core::{RecoveryAction, Writer};
use ogentic_audit_keychain::KeychainKey;
use tauri::{Manager, Emitter};

pub struct AuditState {
    pub writer: Mutex<Writer>,
}

fn main() {
    tauri::Builder::default()
        .setup(|app| {
            let key = KeychainKey::load_or_generate(
                "com.ogenticai.sotto",
                "audit-v1",
            )?;

            let audit_dir = app.path()
                .app_data_dir()?
                .join("audit");
            std::fs::create_dir_all(&audit_dir)?;

            let session_id = generate_session_id_bytes();
            let writer = Writer::open(&audit_dir, Box::new(key), session_id)?;

            // Surface crash-recovery to the UI.
            if let RecoveryAction::Repaired = writer.recovery_report().action {
                let report = writer.recovery_report().clone();
                app.emit("audit-recovery", serde_json::json!({
                    "truncated_bytes": report.truncated_bytes,
                    "last_record_id": report.last_record_id,
                    "message": format!(
                        "Previous session ended unexpectedly; recovered to record {}",
                        report.last_record_id.unwrap_or(0)
                    ),
                }))?;
            }

            app.manage(AuditState { writer: Mutex::new(writer) });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            audit::audit_append,
            audit::audit_verify,
            audit::audit_export_pdf,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

fn generate_session_id_bytes() -> [u8; 16] {
    // In real code, use uuid::Uuid::new_v4().into_bytes().
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let mut bytes = [0u8; 16];
    bytes[..16].copy_from_slice(&(now as u128).to_le_bytes());
    bytes
}
```

### `src-tauri/audit.rs`

```rust
use std::collections::BTreeMap;
use ogentic_audit_core::{
    PayloadValue, RecordInput, Verdict, Verifier, VerifyOptions,
};
use ogentic_audit_keychain::KeychainKey;
use crate::AuditState;

#[tauri::command]
pub fn audit_append(
    state: tauri::State<'_, AuditState>,
    actor: String,
    event: String,
    payload: serde_json::Value,
) -> Result<u64, String> {
    let mut writer = state.writer.lock().map_err(|e| e.to_string())?;
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
        }
    }
    let id = writer
        .append(RecordInput {
            ts_wall: chrono::Utc::now().to_rfc3339_opts(
                chrono::SecondsFormat::Millis,
                true,
            ),
            ts_mono_delta: 0, // Replace with a real monotonic clock.
            actor,
            event,
            payload: p,
            schema_version: 1,
        })
        .map_err(|e| e.to_string())?;
    writer.flush().map_err(|e| e.to_string())?;
    Ok(id)
}

#[tauri::command]
pub fn audit_verify(
    app_handle: tauri::AppHandle,
) -> Result<serde_json::Value, String> {
    let audit_dir = app_handle
        .path()
        .app_data_dir()
        .map_err(|e| e.to_string())?
        .join("audit");
    let key = KeychainKey::load_or_generate(
        "com.ogenticai.sotto",
        "audit-v1",
    )
    .map_err(|e| e.to_string())?;
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

#[tauri::command]
pub async fn audit_export_pdf(
    app_handle: tauri::AppHandle,
    output_path: String,
    custodian: String,
) -> Result<String, String> {
    let audit_dir = app_handle
        .path()
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
        return Err(format!(
            "ogentic-audit exited {}",
            status.code().unwrap_or(-1)
        ));
    }
    Ok(output_path)
}
```

### `ui/index.html` (minimal)

```html
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Sotto audit demo</title>
</head>
<body>
  <button id="append">Append "vault.unlocked"</button>
  <button id="verify">Verify chain</button>
  <button id="export">Export PDF</button>
  <pre id="out"></pre>

  <script type="module">
    import { invoke } from "/_tauri/api";
    import { listen } from "/_tauri/api/event";

    const out = document.getElementById("out");
    const log = (msg) => { out.textContent += msg + "\n"; };

    listen("audit-recovery", e => log("recovery: " + JSON.stringify(e.payload)));

    document.getElementById("append").onclick = async () => {
      const id = await invoke("audit_append", {
        actor: "user:demo",
        event: "vault.unlocked",
        payload: { vault_id: "v-001" },
      });
      log("appended record " + id);
    };

    document.getElementById("verify").onclick = async () => {
      const report = await invoke("audit_verify");
      log("verify: " + JSON.stringify(report));
    };

    document.getElementById("export").onclick = async () => {
      const out_path = await invoke("audit_export_pdf", {
        outputPath: "/tmp/audit-report.pdf",
        custodian: "Demo Custodian",
      });
      log("exported to " + out_path);
    };
  </script>
</body>
</html>
```

## What this example doesn't do

- **Real `chrono` / `uuid` deps** — the snippets reference them but the example doesn't ship a full Cargo.toml because the goal is to demonstrate the *integration shape*, not to be a runnable starter. Sotto Desktop already has chrono / uuid in its dependency tree.
- **Tauri-side wheel/binary management** — the `audit_export_pdf` command shells out to `ogentic-audit`, which means the binary must be on PATH. In production, Sotto's installer should bundle `ogentic-audit` alongside the main binary.
- **Per-event payload schema enforcement** — `audit_append` does best-effort conversion of arbitrary JSON. In real Sotto code, each `event` tag has a typed schema; reject anything that doesn't match.

## Related

- [`docs/integrations/sotto-desktop.md`](../../docs/integrations/sotto-desktop.md) — the prose integration guide
- [`docs/spec/v0.1.md`](../../docs/spec/v0.1.md) — the on-disk format spec
- Sotto Desktop side: [OGE-59](https://linear.app/ogenticai/issue/OGE-59), [OGE-60](https://linear.app/ogenticai/issue/OGE-60), [OGE-411](https://linear.app/ogenticai/issue/OGE-411)
