//! Serialization for the checkpoint artifact.
//!
//! The core crate keeps [`Checkpoint`] as plain data and stays
//! dependency-free (no serde). The on-the-wire JSON shape lives here,
//! next to the CLI that reads and writes it.
//!
//! ```json
//! {
//!   "format": "ogentic-audit-checkpoint/v1",
//!   "key_id": "<64 hex chars>",
//!   "segment": 0,
//!   "record_id": 3,
//!   "hmac": "<64 hex chars>",
//!   "observed_at": "2026-07-20T20:00:00Z"
//! }
//! ```
//!
//! The artifact is deliberately small and boring: an external observer
//! should be able to store it in a ticket, a commit, an email, or a
//! transparency log without tooling.

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::anyhow;
use ogentic_audit_core::{Checkpoint, CHECKPOINT_FORMAT, HMAC_LEN, KEY_ID_LEN};
use serde::{Deserialize, Serialize};

use crate::keysource::AppError;
use crate::output::hex;

#[derive(Debug, Serialize, Deserialize)]
pub struct CheckpointJson {
    pub format: String,
    pub key_id: String,
    pub segment: u16,
    pub record_id: u64,
    pub hmac: String,
    pub observed_at: String,
}

impl CheckpointJson {
    pub fn from_parts(
        key_id: &[u8; KEY_ID_LEN],
        segment: u16,
        record_id: u64,
        hmac: &[u8; HMAC_LEN],
        observed_at: String,
    ) -> Self {
        Self {
            format: CHECKPOINT_FORMAT.to_string(),
            key_id: hex(key_id),
            segment,
            record_id,
            hmac: hex(hmac),
            observed_at,
        }
    }

    /// Parse into the core type, rejecting anything malformed.
    ///
    /// Every failure here is an argument error, not a violation: a
    /// checkpoint we cannot read tells us nothing about the log.
    pub fn into_checkpoint(self) -> Result<Checkpoint, AppError> {
        if self.format != CHECKPOINT_FORMAT {
            return Err(AppError::argument(anyhow!(
                "unsupported checkpoint format {:?} (expected {CHECKPOINT_FORMAT})",
                self.format
            )));
        }
        let key_id = decode_fixed::<KEY_ID_LEN>(&self.key_id, "key_id")?;
        let hmac = decode_fixed::<HMAC_LEN>(&self.hmac, "hmac")?;
        Ok(Checkpoint {
            key_id,
            segment: self.segment,
            record_id: self.record_id,
            hmac,
            observed_at: self.observed_at,
        })
    }
}

fn decode_fixed<const N: usize>(value: &str, field: &str) -> Result<[u8; N], AppError> {
    let bytes = hex::decode(value)
        .map_err(|e| AppError::argument(anyhow!("checkpoint {field} is not valid hex: {e}")))?;
    let len = bytes.len();
    bytes
        .try_into()
        .map_err(|_| AppError::argument(anyhow!("checkpoint {field} must be {N} bytes, got {len}")))
}

/// Read and parse a checkpoint file.
pub fn load(path: &std::path::Path) -> Result<Checkpoint, AppError> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| AppError::io(anyhow!("reading checkpoint {}: {e}", path.display())))?;
    let parsed: CheckpointJson = serde_json::from_str(&text)
        .map_err(|e| AppError::argument(anyhow!("parsing checkpoint {}: {e}", path.display())))?;
    parsed.into_checkpoint()
}

/// Current UTC time as RFC 3339 with second precision.
///
/// Hand-rolled rather than pulling in a date crate: the workspace has no
/// time dependency and this is the only place that needs one.
///
/// `clippy.toml` disallows `SystemTime::now` so that **audit records**
/// anchor time through the writer's wall + monotonic + session_id path
/// rather than sampling the clock ad-hoc. That rationale does not reach
/// here: a checkpoint is not a record, it never enters the chain, and
/// `observed_at` is descriptive only — it is deliberately excluded from
/// the comparison, because a timestamp an attacker can edit proves
/// nothing. Narrowly allowed for that reason.
#[allow(clippy::disallowed_methods)]
pub fn now_rfc3339() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    format_rfc3339(secs)
}

fn format_rfc3339(unix_secs: i64) -> String {
    let days = unix_secs.div_euclid(86_400);
    let secs_of_day = unix_secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60
    )
}

/// Howard Hinnant's `civil_from_days` — the inverse of the
/// `days_from_civil` the core verifier already uses for timestamp
/// parsing, so the two directions agree by construction.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_known_instants() {
        assert_eq!(format_rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_rfc3339(1_000_000_000), "2001-09-09T01:46:40Z");
        // Leap day.
        assert_eq!(format_rfc3339(1_709_164_800), "2024-02-29T00:00:00Z");
    }

    #[test]
    fn round_trips_through_json() {
        let json = CheckpointJson::from_parts(
            &[3u8; KEY_ID_LEN],
            2,
            41,
            &[4u8; HMAC_LEN],
            "2026-07-20T20:00:00Z".to_string(),
        );
        let text = serde_json::to_string(&json).unwrap();
        let back: CheckpointJson = serde_json::from_str(&text).unwrap();
        let cp = back.into_checkpoint().unwrap();
        assert_eq!(cp.segment, 2);
        assert_eq!(cp.record_id, 41);
        assert_eq!(cp.key_id, [3u8; KEY_ID_LEN]);
        assert_eq!(cp.hmac, [4u8; HMAC_LEN]);
    }

    #[test]
    fn rejects_wrong_format_tag() {
        let mut json = CheckpointJson::from_parts(
            &[0u8; KEY_ID_LEN],
            0,
            0,
            &[0u8; HMAC_LEN],
            "2026-07-20T20:00:00Z".to_string(),
        );
        json.format = "ogentic-audit-checkpoint/v99".to_string();
        assert!(json.into_checkpoint().is_err());
    }

    #[test]
    fn rejects_short_hmac() {
        let mut json = CheckpointJson::from_parts(
            &[0u8; KEY_ID_LEN],
            0,
            0,
            &[0u8; HMAC_LEN],
            "2026-07-20T20:00:00Z".to_string(),
        );
        json.hmac = "abcd".to_string();
        assert!(json.into_checkpoint().is_err());
    }
}
