//! Checkpoint v2 and witness co-signatures (spec v0.2 §10).
//!
//! A v2 checkpoint pins `(log_id, segment, record_id, record_count,
//! record_hash)` of a signed log. Signed by the log's own key it is the
//! signer's non-repudiable statement of its head; two of them for one
//! position with different hashes prove equivocation ([`compare`]). A
//! witness co-signs a checkpoint with its own key, time and envelope.

use std::collections::BTreeSet;

use super::json::Value;
use super::keys::{Fingerprint, SigAlg};
use super::signer::{sign_detached, SignError, Signer};
use super::statements::{check_timestamp, hex_field, int, string, Head};
use super::trust::{check_members, verify_detached_by};
use super::{hex, sha256, NS_CHECKPOINT, NS_WITNESS};

/// Format string of a v2 checkpoint.
pub const CHECKPOINT_V2_FORMAT: &str = "ogentic-audit-checkpoint/v2";
/// Format string of a witness co-signature.
pub const WITNESS_FORMAT: &str = "ogentic-audit-witness/v1";

/// A v2 checkpoint (spec §10.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointV2 {
    /// The log signer's algorithm.
    pub alg: SigAlg,
    /// The log signer.
    pub key_id: Fingerprint,
    /// The head.
    pub head: Head,
    /// The head record's `ts_wall` (signer's clock).
    pub head_ts_wall: String,
    /// When the checkpoint was made (maker's clock). Absent in the copy
    /// embedded in a release attestation.
    pub observed_at: Option<String>,
}

impl CheckpointV2 {
    /// The JSON object. With `standalone`, includes `format` and
    /// `observed_at` (a checkpoint file); without, the form embedded in a
    /// release attestation's `logs[]`.
    #[must_use]
    pub fn to_json(&self, standalone: bool) -> Value {
        let mut m = vec![
            ("alg", Value::str(self.alg.json_name())),
            ("head_ts_wall", Value::str(&self.head_ts_wall)),
            ("key_id", Value::str(self.key_id.to_hex())),
            ("log_id", Value::str(hex(&self.head.log_id))),
            ("record_count", Value::Int(self.head.record_count)),
            ("record_hash", Value::str(hex(&self.head.record_hash))),
            ("record_id", Value::Int(self.head.record_id)),
            ("segment", Value::Int(u64::from(self.head.segment))),
        ];
        if standalone {
            m.push(("format", Value::str(CHECKPOINT_V2_FORMAT)));
            if let Some(o) = &self.observed_at {
                m.push(("observed_at", Value::str(o)));
            }
        }
        Value::object(m)
    }

    /// Canonical bytes of a checkpoint file.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.to_json(true).to_canonical().into_bytes()
    }

    /// Parse a checkpoint file (canonical JSON, schema of §10.1).
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > 64 * 1024 {
            return Err("checkpoint larger than 64 KiB".into());
        }
        let doc = super::json::parse_canonical(bytes, 1).map_err(|e| e.to_string())?;
        match doc.get("format").and_then(Value::as_str) {
            Some(CHECKPOINT_V2_FORMAT) => {},
            Some("ogentic-audit-checkpoint/v1") => {
                return Err(
                    "this is a v1 (HMAC) checkpoint; it applies only to format 0x0001 logs".into(),
                )
            },
            _ => return Err("not an ogentic-audit-checkpoint/v2 document".into()),
        }
        Self::from_json(&doc, true)
    }

    /// Parse the object form; `standalone` as in [`CheckpointV2::to_json`].
    pub fn from_json(doc: &Value, standalone: bool) -> Result<Self, String> {
        let mut allowed: BTreeSet<&str> = [
            "alg",
            "head_ts_wall",
            "key_id",
            "log_id",
            "record_count",
            "record_hash",
            "record_id",
            "segment",
        ]
        .into();
        if standalone {
            allowed.insert("format");
            allowed.insert("observed_at");
        }
        check_members(doc, &allowed)?;
        let alg = SigAlg::from_json_name(string(doc, "alg")?).ok_or("unknown alg")?;
        let segment = u16::try_from(int(doc, "segment")?).map_err(|_| "segment out of range")?;
        let record_count = int(doc, "record_count")?;
        if record_count == 0 {
            return Err("record_count must be at least 1".into());
        }
        let observed_at = if standalone {
            Some(check_timestamp(doc, "observed_at")?)
        } else {
            None
        };
        Ok(Self {
            alg,
            key_id: Fingerprint(hex_field(doc, "key_id")?),
            head: Head {
                log_id: hex_field(doc, "log_id")?,
                segment,
                record_id: int(doc, "record_id")?,
                record_count,
                record_hash: hex_field(doc, "record_hash")?,
            },
            head_ts_wall: string(doc, "head_ts_wall")?.to_string(),
            observed_at,
        })
    }

    /// Sign the checkpoint file bytes with the log's key.
    pub fn sign(bytes: &[u8], signer: &dyn Signer) -> Result<String, SignError> {
        sign_detached(signer, NS_CHECKPOINT, bytes)
    }
}

/// A witness co-signature (spec §10.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessCosignature {
    /// SHA-256 of the checkpoint file's bytes.
    pub checkpoint_sha256: [u8; 32],
    /// The witness's clock.
    pub observed_at: String,
    /// The witness key.
    pub witness_key_id: Fingerprint,
}

impl WitnessCosignature {
    /// Canonical bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        Value::object([
            (
                "checkpoint_sha256",
                Value::str(hex(&self.checkpoint_sha256)),
            ),
            ("format", Value::str(WITNESS_FORMAT)),
            ("observed_at", Value::str(&self.observed_at)),
            ("witness_key_id", Value::str(self.witness_key_id.to_hex())),
        ])
        .to_canonical()
        .into_bytes()
    }

    /// Parse a witness file.
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > 64 * 1024 {
            return Err("witness co-signature larger than 64 KiB".into());
        }
        let doc = super::json::parse_canonical(bytes, 1).map_err(|e| e.to_string())?;
        check_members(
            &doc,
            &[
                "checkpoint_sha256",
                "format",
                "observed_at",
                "witness_key_id",
            ]
            .into(),
        )?;
        if string(&doc, "format")? != WITNESS_FORMAT {
            return Err("not an ogentic-audit-witness/v1 document".into());
        }
        Ok(Self {
            checkpoint_sha256: hex_field(&doc, "checkpoint_sha256")?,
            observed_at: check_timestamp(&doc, "observed_at")?,
            witness_key_id: Fingerprint(hex_field(&doc, "witness_key_id")?),
        })
    }
}

/// Co-sign the checkpoint file `checkpoint_bytes` as a witness. Returns
/// the witness file bytes and its armored signature.
pub fn cosign(
    checkpoint_bytes: &[u8],
    witness: &dyn Signer,
    observed_at: &str,
) -> Result<(Vec<u8>, String), SignError> {
    let doc = WitnessCosignature {
        checkpoint_sha256: sha256(checkpoint_bytes),
        observed_at: observed_at.to_string(),
        witness_key_id: witness.public_key().fingerprint(),
    }
    .to_bytes();
    let sig = sign_detached(witness, NS_WITNESS, &doc)?;
    Ok((doc, sig))
}

/// Result of comparing two signed checkpoints (spec §10.5).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Comparison {
    /// Same key, same log and position, different hash or count: the
    /// signer published two histories of one log.
    Equivocation {
        /// The signer.
        key_id: Fingerprint,
        /// The position.
        head: Head,
        /// The other checkpoint's hash at that position.
        other_record_hash: [u8; 32],
    },
    /// Consistent at that position, or different positions or logs (no
    /// conclusion).
    NoEquivocation {
        /// Why no equivocation is proven.
        reason: String,
    },
}

/// Compare two checkpoints, each with its detached signature by the key
/// it names. Both signatures must verify; the result needs no trust
/// context: it is self-contained evidence about whoever holds that key.
pub fn compare(a: &[u8], a_sig: &[u8], b: &[u8], b_sig: &[u8]) -> Result<Comparison, String> {
    let ca = CheckpointV2::parse(a).map_err(|e| format!("first checkpoint: {e}"))?;
    let cb = CheckpointV2::parse(b).map_err(|e| format!("second checkpoint: {e}"))?;
    verify_detached_by(a_sig, NS_CHECKPOINT, a, &ca.key_id)
        .map_err(|e| format!("first checkpoint: {e}"))?;
    verify_detached_by(b_sig, NS_CHECKPOINT, b, &cb.key_id)
        .map_err(|e| format!("second checkpoint: {e}"))?;
    if ca.key_id != cb.key_id {
        return Ok(Comparison::NoEquivocation {
            reason: "signed by different keys".into(),
        });
    }
    if ca.head.log_id != cb.head.log_id {
        return Ok(Comparison::NoEquivocation {
            reason: "checkpoints of different logs".into(),
        });
    }
    if (ca.head.segment, ca.head.record_id) != (cb.head.segment, cb.head.record_id) {
        return Ok(Comparison::NoEquivocation {
            reason: "checkpoints of different positions; compare each against the log".into(),
        });
    }
    if ca.head.record_hash != cb.head.record_hash || ca.head.record_count != cb.head.record_count {
        return Ok(Comparison::Equivocation {
            key_id: ca.key_id,
            head: ca.head,
            other_record_hash: cb.head.record_hash,
        });
    }
    Ok(Comparison::NoEquivocation {
        reason: "the checkpoints agree".into(),
    })
}
