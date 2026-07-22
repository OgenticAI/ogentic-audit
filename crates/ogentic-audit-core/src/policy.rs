//! Policy attestation — recording *what rule permitted* an audited
//! action, not merely that it happened.
//!
//! ## Why this is a payload convention, not a schema change
//!
//! An `ogentic-audit` record already answers "this happened": actor,
//! event, timestamp, and a free-form [`payload`](crate::RecordInput::payload)
//! map — all inside the HMAC'd record bytes, so all tamper-evident and
//! chain-linked. What it did not carry is "…and it was permitted under
//! policy P, decision D". That is the difference between a tamper-evident
//! log and a compliance artifact.
//!
//! Because `payload` is a caller-defined map that is *already signed*, a
//! policy decision can ride inside it with **no on-disk format change**:
//! `FORMAT_VERSION` stays `0x0001`, the record schema (keys 1–10) is
//! untouched, and every existing golden vector still passes. This module
//! defines the reserved shape so independent implementations agree on it.
//! See ADR-0003.
//!
//! ## The convention (`ogentic-audit-policy/v1`)
//!
//! A record whose outcome was determined by a policy MAY carry a reserved
//! [`POLICY_KEY`] (`"policy"`) inside its `payload`, holding a CBOR map:
//!
//! | key | type | notes |
//! |-----|------|-------|
//! | `format` | text | [`POLICY_FORMAT`] — `"ogentic-audit-policy/v1"` |
//! | `decision` | text | `"permit"` or `"deny"` (binary core, per the LangChain RFC #35691 core profile) |
//! | `digest` | text | `"sha256:<64 hex>"` — SHA-256 over the caller's **canonicalized** policy artifact |
//! | `policy_id` | text | *optional* — a stable id an auditor uses to locate the retained policy |
//! | `deciding_rules` | array of text | *optional* — stable rule ids sufficient to determine the decision |
//!
//! ## What the digest is — and what this library does NOT do
//!
//! `digest` is computed by the **caller** over their own policy document,
//! using whatever canonicalization their policy engine's interop contract
//! demands — RFC 8785 (JCS) for a JSON policy, RFC 8949 canonical CBOR for
//! a CBOR one. `ogentic-audit` never parses, canonicalizes, or hashes the
//! policy itself; it treats the digest as an opaque value and makes it
//! tamper-evident via the same HMAC chain that covers every other field.
//! This mirrors how `key_id` is a caller-supplied BLAKE3 projection, not
//! something the writer computes from raw material.
//!
//! Consequently the digest only *binds* the decision to a policy if the
//! policy artifact itself is **retained and retrievable** — a digest of a
//! document nobody kept proves nothing. See `docs/security/threat-model.md`.
//!
//! ## Python
//!
//! Python callers build the same shape as a plain dict under
//! `payload["policy"]` (the binding passes `payload` through unchanged);
//! the field names and `"sha256:<hex>"` digest form are identical.

use std::collections::BTreeMap;

use crate::writer::PayloadValue;

/// The reserved key inside a record's `payload` map that carries a policy
/// attestation object. Applications using this convention MUST NOT reuse
/// `payload["policy"]` for anything else.
pub const POLICY_KEY: &str = "policy";

/// Format tag stamped into every attestation object. Bump if the shape
/// changes.
pub const POLICY_FORMAT: &str = "ogentic-audit-policy/v1";

/// The digest algorithm the v1 convention pins. The on-disk `digest`
/// string is `"<DIGEST_ALG>:<hex>"`.
pub const DIGEST_ALG: &str = "sha256";

/// The binary decision core. Systems with richer outcomes
/// (`require_approval`, `indeterminate`, …) should record the *effective*
/// binary outcome here and carry the nuance in their own payload fields;
/// widening this is a future profile decision, deliberately out of v1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyDecision {
    /// The action was allowed by policy.
    Permit,
    /// The action was denied by policy. A denied action is still worth an
    /// audit record — "the agent tried X and policy stopped it" is exactly
    /// the accountability signal an autonomous fleet needs.
    Deny,
}

impl PolicyDecision {
    /// The on-disk string form.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            PolicyDecision::Permit => "permit",
            PolicyDecision::Deny => "deny",
        }
    }

    fn parse(s: &str) -> Result<Self, PolicyError> {
        match s {
            "permit" => Ok(PolicyDecision::Permit),
            "deny" => Ok(PolicyDecision::Deny),
            other => Err(PolicyError::BadDecision(other.to_string())),
        }
    }
}

/// A policy attestation, ready to attach to a record's `payload`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyAttestation {
    /// Whether the action was permitted or denied.
    pub decision: PolicyDecision,
    /// SHA-256 over the caller's canonicalized policy artifact. Opaque to
    /// this library — see the module docs.
    pub digest: [u8; 32],
    /// Optional stable identifier for the policy artifact, so an auditor
    /// can locate the retained document the digest was taken over.
    pub policy_id: Option<String>,
    /// Optional stable identifiers of the rules sufficient to determine
    /// the decision. Use ids that survive reformatting (authored id, UUID,
    /// or a semantic hash) — never source-line numbers.
    pub deciding_rules: Vec<String>,
}

impl PolicyAttestation {
    /// A minimal permit/deny attestation over `digest`, no optional fields.
    #[must_use]
    pub fn new(decision: PolicyDecision, digest: [u8; 32]) -> Self {
        Self {
            decision,
            digest,
            policy_id: None,
            deciding_rules: Vec::new(),
        }
    }

    /// Set the optional policy identifier (builder style).
    #[must_use]
    pub fn with_policy_id(mut self, policy_id: impl Into<String>) -> Self {
        self.policy_id = Some(policy_id.into());
        self
    }

    /// Set the optional deciding-rule identifiers (builder style).
    #[must_use]
    pub fn with_deciding_rules<I, S>(mut self, rules: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.deciding_rules = rules.into_iter().map(Into::into).collect();
        self
    }

    /// Render as the `policy` sub-map (a [`PayloadValue::Map`]). Insert it
    /// into a record's payload under [`POLICY_KEY`], or use [`Self::attach`].
    #[must_use]
    pub fn to_payload_value(&self) -> PayloadValue {
        let mut map: BTreeMap<String, PayloadValue> = BTreeMap::new();
        map.insert("format".into(), PayloadValue::Text(POLICY_FORMAT.into()));
        map.insert(
            "decision".into(),
            PayloadValue::Text(self.decision.as_str().into()),
        );
        map.insert("digest".into(), PayloadValue::Text(self.digest_string()));
        if let Some(id) = &self.policy_id {
            map.insert("policy_id".into(), PayloadValue::Text(id.clone()));
        }
        if !self.deciding_rules.is_empty() {
            map.insert(
                "deciding_rules".into(),
                PayloadValue::List(
                    self.deciding_rules
                        .iter()
                        .map(|r| PayloadValue::Text(r.clone()))
                        .collect(),
                ),
            );
        }
        PayloadValue::Map(map)
    }

    /// Insert this attestation into `payload` under [`POLICY_KEY`],
    /// replacing any existing `policy` entry.
    pub fn attach(&self, payload: &mut BTreeMap<String, PayloadValue>) {
        payload.insert(POLICY_KEY.to_string(), self.to_payload_value());
    }

    /// The `"sha256:<hex>"` on-disk digest string.
    #[must_use]
    pub fn digest_string(&self) -> String {
        format!("{DIGEST_ALG}:{}", to_hex(&self.digest))
    }

    /// Read a policy attestation back out of a decoded `payload` map.
    ///
    /// - `Ok(None)` — no `policy` key (attestation is optional; not an error)
    /// - `Ok(Some(_))` — a well-formed v1 attestation
    /// - `Err(_)` — a `policy` key is present but malformed
    ///
    /// Verifiers and auditors use this to inspect an already-verified
    /// record; it does **not** re-derive or check the digest against any
    /// policy (this library never sees the policy).
    pub fn from_payload(
        payload: &BTreeMap<String, PayloadValue>,
    ) -> Result<Option<Self>, PolicyError> {
        let Some(value) = payload.get(POLICY_KEY) else {
            return Ok(None);
        };
        let PayloadValue::Map(map) = value else {
            return Err(PolicyError::NotAMap);
        };

        match map.get("format") {
            Some(PayloadValue::Text(f)) if f == POLICY_FORMAT => {},
            Some(PayloadValue::Text(f)) => {
                return Err(PolicyError::UnknownFormat(f.clone()));
            },
            _ => return Err(PolicyError::MissingField("format")),
        }

        let decision = match map.get("decision") {
            Some(PayloadValue::Text(d)) => PolicyDecision::parse(d)?,
            _ => return Err(PolicyError::MissingField("decision")),
        };

        let digest = match map.get("digest") {
            Some(PayloadValue::Text(d)) => parse_digest(d)?,
            _ => return Err(PolicyError::MissingField("digest")),
        };

        let policy_id = match map.get("policy_id") {
            None => None,
            Some(PayloadValue::Text(id)) => Some(id.clone()),
            Some(_) => return Err(PolicyError::BadField("policy_id")),
        };

        let deciding_rules = match map.get("deciding_rules") {
            None => Vec::new(),
            Some(PayloadValue::List(items)) => {
                let mut out = Vec::with_capacity(items.len());
                for item in items {
                    match item {
                        PayloadValue::Text(r) => out.push(r.clone()),
                        _ => return Err(PolicyError::BadField("deciding_rules")),
                    }
                }
                out
            },
            Some(_) => return Err(PolicyError::BadField("deciding_rules")),
        };

        Ok(Some(Self {
            decision,
            digest,
            policy_id,
            deciding_rules,
        }))
    }
}

/// What went wrong reading a `policy` attestation out of a payload.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    /// The `policy` key is present but is not a map.
    #[error("payload \"policy\" is not a map")]
    NotAMap,
    /// A required field is absent.
    #[error("policy attestation missing field {0:?}")]
    MissingField(&'static str),
    /// A present field has the wrong type.
    #[error("policy attestation field {0:?} has the wrong type")]
    BadField(&'static str),
    /// The `format` tag is not one this version understands.
    #[error("unknown policy attestation format {0:?} (expected {POLICY_FORMAT})")]
    UnknownFormat(String),
    /// `decision` was neither `permit` nor `deny`.
    #[error("policy decision must be \"permit\" or \"deny\", got {0:?}")]
    BadDecision(String),
    /// `digest` was not `"sha256:<64 hex>"`.
    #[error("policy digest malformed: {0}")]
    BadDigest(String),
}

fn parse_digest(s: &str) -> Result<[u8; 32], PolicyError> {
    let prefix = format!("{DIGEST_ALG}:");
    let hex = s
        .strip_prefix(&prefix)
        .ok_or_else(|| PolicyError::BadDigest(format!("expected a \"{prefix}\" prefix")))?;
    if hex.len() != 64 {
        return Err(PolicyError::BadDigest(format!(
            "expected 64 hex chars after \"{prefix}\", got {}",
            hex.len()
        )));
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|e| PolicyError::BadDigest(format!("bad hex at byte {i}: {e}")))?;
    }
    Ok(out)
}

fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest() -> [u8; 32] {
        let mut d = [0u8; 32];
        for (i, b) in d.iter_mut().enumerate() {
            *b = i as u8;
        }
        d
    }

    #[test]
    fn round_trips_through_payload_map() {
        let att = PolicyAttestation::new(PolicyDecision::Permit, digest())
            .with_policy_id("pol-42")
            .with_deciding_rules(["rule.a", "rule.b"]);

        let mut payload: BTreeMap<String, PayloadValue> = BTreeMap::new();
        payload.insert("action".into(), PayloadValue::Text("file.write".into()));
        att.attach(&mut payload);

        let read = PolicyAttestation::from_payload(&payload)
            .unwrap()
            .expect("attestation present");
        assert_eq!(read, att);
    }

    #[test]
    fn digest_string_is_rfc_shaped() {
        let att = PolicyAttestation::new(PolicyDecision::Deny, digest());
        assert_eq!(
            att.digest_string(),
            "sha256:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        );
    }

    #[test]
    fn absent_policy_is_ok_none() {
        let mut payload: BTreeMap<String, PayloadValue> = BTreeMap::new();
        payload.insert("action".into(), PayloadValue::Text("noop".into()));
        assert_eq!(PolicyAttestation::from_payload(&payload).unwrap(), None);
    }

    #[test]
    fn deny_with_no_optional_fields_round_trips() {
        let att = PolicyAttestation::new(PolicyDecision::Deny, digest());
        let mut payload = BTreeMap::new();
        att.attach(&mut payload);
        let read = PolicyAttestation::from_payload(&payload).unwrap().unwrap();
        assert_eq!(read.decision, PolicyDecision::Deny);
        assert!(read.policy_id.is_none());
        assert!(read.deciding_rules.is_empty());
    }

    #[test]
    fn malformed_is_error_not_silently_ignored() {
        // Present but not a map.
        let mut p = BTreeMap::new();
        p.insert(POLICY_KEY.to_string(), PayloadValue::Text("nope".into()));
        assert!(matches!(
            PolicyAttestation::from_payload(&p),
            Err(PolicyError::NotAMap)
        ));

        // Wrong format tag.
        let mut m = BTreeMap::new();
        m.insert(
            "format".to_string(),
            PayloadValue::Text("ogentic-audit-policy/v99".into()),
        );
        let mut p = BTreeMap::new();
        p.insert(POLICY_KEY.to_string(), PayloadValue::Map(m));
        assert!(matches!(
            PolicyAttestation::from_payload(&p),
            Err(PolicyError::UnknownFormat(_))
        ));

        // Bad decision.
        let att = PolicyAttestation::new(PolicyDecision::Permit, digest());
        if let PayloadValue::Map(mut m) = att.to_payload_value() {
            m.insert("decision".into(), PayloadValue::Text("maybe".into()));
            let mut p = BTreeMap::new();
            p.insert(POLICY_KEY.to_string(), PayloadValue::Map(m));
            assert!(matches!(
                PolicyAttestation::from_payload(&p),
                Err(PolicyError::BadDecision(_))
            ));
        }
    }

    #[test]
    fn bad_digest_shapes_are_rejected() {
        for bad in ["deadbeef", "sha256:xyz", "sha256:00", "md5:0011"] {
            let mut m = BTreeMap::new();
            m.insert("format".into(), PayloadValue::Text(POLICY_FORMAT.into()));
            m.insert("decision".into(), PayloadValue::Text("permit".into()));
            m.insert("digest".into(), PayloadValue::Text(bad.into()));
            let mut p = BTreeMap::new();
            p.insert(POLICY_KEY.to_string(), PayloadValue::Map(m));
            assert!(
                matches!(
                    PolicyAttestation::from_payload(&p),
                    Err(PolicyError::BadDigest(_))
                ),
                "expected {bad:?} to be rejected"
            );
        }
    }
}
