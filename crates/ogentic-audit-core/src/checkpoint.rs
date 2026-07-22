//! External chain-head checkpoints — the anchor that makes rewrite
//! detectable.
//!
//! ## Why this exists
//!
//! [`crate::verifier::Verifier`] proves **internal** consistency: every
//! record's HMAC recomputes, every `prev_hash` links, every segment's
//! `prev_final` is continuous. That catches an edit made by someone who
//! does *not* hold the HMAC key.
//!
//! It does **not** catch a rewrite by someone who does. An attacker with
//! the key and write access can truncate the log at any record, re-chain
//! forward with fabricated content, and every internal check passes —
//! because the chain is being validated against itself. The verifier has
//! nothing outside the log to compare against.
//!
//! A checkpoint is that outside thing. It is a `(segment, record_id,
//! hmac)` triple observed at some point in the past and stored somewhere
//! the log's writer cannot reach. Replaying verification with the
//! checkpoint in hand answers a question internal verification cannot:
//! *is this still the same history I saw before, or merely a
//! self-consistent one?*
//!
//! ## What it does not do
//!
//! A checkpoint held by the same party that holds the log buys nothing —
//! whoever rewrites the log rewrites the checkpoint beside it. The
//! security property comes entirely from **where the checkpoint is
//! stored**, not from this code. Publishing it to a party with different
//! interests (a customer, a regulator, a transparency log, a counterpart
//! agent) is what converts it into evidence. See
//! `docs/security/threat-model.md`.
//!
//! Deliberately **not** an on-disk format change: the checkpoint lives
//! outside the log, so `FORMAT_VERSION` stays `0x0001` and the v0.1
//! record schema is untouched. Serialization is the caller's business —
//! the CLI writes the canonical JSON shape; this crate stays
//! dependency-free.

use crate::key::{KeyId, HMAC_LEN, KEY_ID_LEN};

/// Format tag written into the serialized checkpoint artifact. Bump this
/// if the triple's meaning ever changes.
pub const CHECKPOINT_FORMAT: &str = "ogentic-audit-checkpoint/v1";

/// A previously-observed chain head.
///
/// `record_id` is **per-segment** monotonic (`docs/spec/v0.1.md` § record
/// schema), so a position is only meaningful as the `(segment,
/// record_id)` pair — a bare record id is ambiguous across segments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    /// `key_id` of the log this checkpoint was taken from. Binds the
    /// checkpoint to one log so a checkpoint from a *different* log
    /// cannot be presented as evidence about this one.
    pub key_id: [u8; KEY_ID_LEN],
    /// Segment index the observed record lived in.
    pub segment: u16,
    /// Per-segment record id of the observed record.
    pub record_id: u64,
    /// The observed record's HMAC — the value that must still be there.
    pub hmac: [u8; HMAC_LEN],
    /// RFC 3339 timestamp of when the observation was made. Carried for
    /// the auditor's benefit; never used in the comparison, because a
    /// timestamp an attacker can edit proves nothing.
    pub observed_at: String,
}

impl Checkpoint {
    /// True if this checkpoint was taken from a log signed with `key_id`.
    ///
    /// A checkpoint that fails this is not evidence of tampering — it is
    /// an operator presenting the wrong file, and callers should say so
    /// rather than reporting a violation.
    #[must_use]
    pub fn matches_key(&self, key_id: &KeyId) -> bool {
        self.key_id == *key_id.as_bytes()
    }

    /// True if `(segment, record_id)` names the record this checkpoint
    /// pins.
    #[must_use]
    pub fn is_position(&self, segment: u16, record_id: u64) -> bool {
        self.segment == segment && self.record_id == record_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cp() -> Checkpoint {
        Checkpoint {
            key_id: [7u8; KEY_ID_LEN],
            segment: 2,
            record_id: 41,
            hmac: [9u8; HMAC_LEN],
            observed_at: "2026-07-20T20:00:00Z".to_string(),
        }
    }

    #[test]
    fn matches_key_is_exact() {
        let c = cp();
        assert!(c.matches_key(&KeyId::from_bytes([7u8; KEY_ID_LEN])));
        assert!(!c.matches_key(&KeyId::from_bytes([8u8; KEY_ID_LEN])));
    }

    #[test]
    fn position_requires_both_segment_and_record_id() {
        let c = cp();
        assert!(c.is_position(2, 41));
        // Same record id in a different segment is a different record —
        // record_id is per-segment monotonic, so this must not match.
        assert!(!c.is_position(3, 41));
        assert!(!c.is_position(2, 42));
    }
}
