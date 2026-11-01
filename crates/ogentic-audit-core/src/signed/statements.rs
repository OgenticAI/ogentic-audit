//! Key statements (spec v0.2 §9.3, §9.4): transitions with acceptance,
//! revocations with cut points, and OpenSSH key revocation lists.
//!
//! Builders live here; parsing and verification live in
//! [`super::trust`], which decides what a statement means for trust.

use super::json::{self, Value};
use super::keys::{Fingerprint, PublicKey};
use super::signer::{sign_detached, SignError, Signer};
use super::{hex, unhex_lower, NS_REVOCATION, NS_TRANSITION, NS_TRANSITION_ACCEPT};

/// Format string of a key transition.
pub const TRANSITION_FORMAT: &str = "ogentic-audit-key-transition/v1";
/// Format string of a key revocation.
pub const REVOCATION_FORMAT: &str = "ogentic-audit-key-revocation/v1";

/// A log head named by a statement or attestation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Head {
    /// The log's random id.
    pub log_id: [u8; 16],
    /// Segment of the head record.
    pub segment: u16,
    /// Position of the head record in its segment.
    pub record_id: u64,
    /// Records from s0r0 through the head, inclusive.
    pub record_count: u64,
    /// The head's `record_hash`.
    pub record_hash: [u8; 32],
}

impl Head {
    /// The JSON object of spec §9.3.
    #[must_use]
    pub fn to_json(&self) -> Value {
        Value::object([
            ("log_id", Value::str(hex(&self.log_id))),
            ("record_count", Value::Int(self.record_count)),
            ("record_hash", Value::str(hex(&self.record_hash))),
            ("record_id", Value::Int(self.record_id)),
            ("segment", Value::Int(u64::from(self.segment))),
        ])
    }

    /// Parse the JSON object of spec §9.3.
    pub fn from_json(v: &Value) -> Result<Self, String> {
        let obj = v.as_object().ok_or("a head must be an object")?;
        if obj.len() != 5 {
            return Err(
                "a head has exactly log_id, record_count, record_hash, record_id, segment".into(),
            );
        }
        let segment = int(v, "segment")?;
        Ok(Self {
            log_id: hex_field(v, "log_id")?,
            segment: u16::try_from(segment).map_err(|_| "segment out of range")?,
            record_id: int(v, "record_id")?,
            record_count: int(v, "record_count")?,
            record_hash: hex_field(v, "record_hash")?,
        })
    }

    /// Whether `(segment, record_id)` is at or before this head.
    #[must_use]
    pub fn covers(&self, segment: u16, record_id: u64) -> bool {
        (segment, record_id) <= (self.segment, self.record_id)
    }
}

pub(crate) fn int(v: &Value, key: &str) -> Result<u64, String> {
    v.get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("{key} must be an integer"))
}

pub(crate) fn string<'a>(v: &'a Value, key: &str) -> Result<&'a str, String> {
    v.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{key} must be a string"))
}

pub(crate) fn hex_field<const N: usize>(v: &Value, key: &str) -> Result<[u8; N], String> {
    unhex_lower::<N>(string(v, key)?)
        .ok_or_else(|| format!("{key} must be {} lowercase hex digits", N * 2))
}

pub(crate) fn hex_list(v: &Value, key: &str) -> Result<Vec<[u8; 32]>, String> {
    v.get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{key} must be an array"))?
        .iter()
        .map(|x| {
            x.as_str()
                .and_then(unhex_lower::<32>)
                .ok_or_else(|| format!("{key} entries must be 64 lowercase hex digits"))
        })
        .collect()
}

/// A statement's bytes and detached signatures, ready to write as
/// `<name>.json`, `<name>.json.sig` and (transitions) `<name>.json.accept.sig`.
#[derive(Debug, Clone)]
pub struct SignedStatement {
    /// Canonical JSON bytes.
    pub json: Vec<u8>,
    /// Armored SSHSIG by the statement's signer.
    pub sig: String,
    /// Armored SSHSIG of acceptance by the new key (transitions only).
    pub accept_sig: Option<String>,
}

impl SignedStatement {
    /// Write the statement as `<dir>/<name>.json` plus its signatures.
    pub fn write(&self, dir: &std::path::Path, name: &str) -> std::io::Result<()> {
        std::fs::create_dir_all(dir)?;
        let json_path = dir.join(format!("{name}.json"));
        std::fs::write(&json_path, &self.json)?;
        std::fs::write(dir.join(format!("{name}.json.sig")), &self.sig)?;
        if let Some(a) = &self.accept_sig {
            std::fs::write(dir.join(format!("{name}.json.accept.sig")), a)?;
        }
        Ok(())
    }
}

/// Unsigned transition document.
#[must_use]
pub fn transition_json(
    old: &PublicKey,
    new: &PublicKey,
    final_heads: &[Head],
    final_releases: &[[u8; 32]],
    issued_at: &str,
    reason: Option<&str>,
) -> Vec<u8> {
    let mut m = vec![
        (
            "final_heads",
            Value::Array(final_heads.iter().map(Head::to_json).collect()),
        ),
        (
            "final_releases",
            Value::Array(final_releases.iter().map(|h| Value::str(hex(h))).collect()),
        ),
        ("format", Value::str(TRANSITION_FORMAT)),
        ("issued_at", Value::str(issued_at)),
        ("new_key_id", Value::str(new.fingerprint().to_hex())),
        ("new_public_key", Value::str(new.to_openssh(""))),
        ("old_key_id", Value::str(old.fingerprint().to_hex())),
    ];
    if let Some(r) = reason {
        m.push(("reason", Value::str(r)));
    }
    Value::object(m).to_canonical().into_bytes()
}

/// Sign a transition with the old key and accept it with the new one
/// (spec §9.3). Both signatures are over the same bytes.
pub fn transition(
    old: &dyn Signer,
    new: &dyn Signer,
    final_heads: &[Head],
    final_releases: &[[u8; 32]],
    issued_at: &str,
    reason: Option<&str>,
) -> Result<SignedStatement, SignError> {
    let json = transition_json(
        old.public_key(),
        new.public_key(),
        final_heads,
        final_releases,
        issued_at,
        reason,
    );
    let sig = sign_detached(old, NS_TRANSITION, &json)?;
    let accept_sig = Some(accept(new, &json)?);
    Ok(SignedStatement {
        json,
        sig,
        accept_sig,
    })
}

/// The new key's acceptance signature over a transition's bytes.
pub fn accept(new: &dyn Signer, transition_json: &[u8]) -> Result<String, SignError> {
    sign_detached(new, NS_TRANSITION_ACCEPT, transition_json)
}

/// Cut points of a revocation: what the revoked key signed that is still
/// vouched for.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CutPoints {
    /// Log heads still trusted.
    pub trusted_heads: Vec<Head>,
    /// SHA-256 of release attestations still trusted.
    pub trusted_releases: Vec<[u8; 32]>,
    /// Successor keys still trusted.
    pub trusted_successors: Vec<Fingerprint>,
}

/// Unsigned revocation document. A self-revocation (`revoker` is the
/// revoked key) is written with empty cut points: they would be ignored.
#[must_use]
pub fn revocation_json(
    revoker: &PublicKey,
    revoked: &Fingerprint,
    cut: &CutPoints,
    issued_at: &str,
    reason: Option<&str>,
) -> Vec<u8> {
    let self_revocation = revoker.fingerprint() == *revoked;
    let empty = CutPoints::default();
    let cut = if self_revocation { &empty } else { cut };
    let mut m = vec![
        ("format", Value::str(REVOCATION_FORMAT)),
        ("issued_at", Value::str(issued_at)),
        ("revoked_key_id", Value::str(revoked.to_hex())),
        ("revoker_key_id", Value::str(revoker.fingerprint().to_hex())),
        (
            "trusted_heads",
            Value::Array(cut.trusted_heads.iter().map(Head::to_json).collect()),
        ),
        (
            "trusted_releases",
            Value::Array(
                cut.trusted_releases
                    .iter()
                    .map(|h| Value::str(hex(h)))
                    .collect(),
            ),
        ),
        (
            "trusted_successors",
            Value::Array(
                cut.trusted_successors
                    .iter()
                    .map(|f| Value::str(f.to_hex()))
                    .collect(),
            ),
        ),
    ];
    if let Some(r) = reason {
        m.push(("reason", Value::str(r)));
    }
    Value::object(m).to_canonical().into_bytes()
}

/// Sign a revocation (spec §9.4).
pub fn revocation(
    revoker: &dyn Signer,
    revoked: &Fingerprint,
    cut: &CutPoints,
    issued_at: &str,
    reason: Option<&str>,
) -> Result<SignedStatement, SignError> {
    let json = revocation_json(revoker.public_key(), revoked, cut, issued_at, reason);
    let sig = sign_detached(revoker, NS_REVOCATION, &json)?;
    Ok(SignedStatement {
        json,
        sig,
        accept_sig: None,
    })
}

/// An OpenSSH key revocation list (`PROTOCOL.krl`) revoking every key
/// whose SHA-256 fingerprint is listed, for `ssh-keygen -Y verify -r`.
/// All or nothing: stock tools then reject every signature by these keys.
#[must_use]
pub fn krl(revoked: &[Fingerprint], comment: &str, generated_unix: u64) -> Vec<u8> {
    fn put_string(out: &mut Vec<u8>, s: &[u8]) {
        out.extend_from_slice(&(s.len() as u32).to_be_bytes());
        out.extend_from_slice(s);
    }
    let mut hashes: Vec<[u8; 32]> = revoked.iter().map(|f| f.0).collect();
    hashes.sort_unstable();
    hashes.dedup();
    let mut out = Vec::new();
    out.extend_from_slice(b"SSHKRL\n\0");
    out.extend_from_slice(&1u32.to_be_bytes()); // format version
    out.extend_from_slice(&1u64.to_be_bytes()); // krl_version
    out.extend_from_slice(&generated_unix.to_be_bytes());
    out.extend_from_slice(&0u64.to_be_bytes()); // flags
    put_string(&mut out, b""); // reserved
    put_string(&mut out, comment.as_bytes());
    if !hashes.is_empty() {
        let mut section = Vec::new();
        for h in &hashes {
            put_string(&mut section, h);
        }
        out.push(5); // KRL_SECTION_FINGERPRINT_SHA256
        put_string(&mut out, &section);
    }
    out
}

/// Parse a statement's `issued_at` / timestamps and string fields.
pub(crate) fn check_reason(v: &Value) -> Result<Option<String>, String> {
    match v.get("reason") {
        None => Ok(None),
        Some(Value::String(s)) => {
            super::names::check_string(s).map_err(|e| format!("reason {e}"))?;
            Ok(Some(s.clone()))
        },
        Some(_) => Err("reason must be a string".into()),
    }
}

pub(crate) fn check_timestamp(v: &Value, key: &str) -> Result<String, String> {
    let s = string(v, key)?;
    super::parse_rfc3339_millis(s)
        .ok_or_else(|| format!("{key} must be RFC 3339 UTC with milliseconds"))?;
    Ok(s.to_string())
}

/// Parse canonical JSON with the statement limits (spec §3.8).
pub(crate) fn parse_doc(bytes: &[u8], max_depth: usize) -> Result<Value, String> {
    if bytes.len() > MAX_STATEMENT_BYTES {
        return Err("statement larger than 16 MiB".into());
    }
    json::parse_canonical(bytes, max_depth).map_err(|e| e.to_string())
}

/// Maximum size of a key statement (spec §3.8).
pub const MAX_STATEMENT_BYTES: usize = 16 * 1024 * 1024;
/// Maximum number of key statements per run (spec §3.8).
pub const MAX_STATEMENTS: usize = 1024;
