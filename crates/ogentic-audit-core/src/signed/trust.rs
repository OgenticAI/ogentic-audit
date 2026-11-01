//! Trust: pins and scopes, key transitions, revocations, and how they
//! combine (spec v0.2 §9).
//!
//! A [`TrustContext`] holds what the verifier obtained **outside** the
//! artefact: pins (each with a principal and a scope), plus key statements
//! and revocations, which are self-authenticating and may also come from a
//! bundle. [`TrustContext::evaluate`] turns them into an [`Evaluated`]
//! trust state that answers one question: is a signature by key K in
//! namespace `ns` on this object accepted?
//!
//! The result depends only on the set of inputs, never on their order or
//! on a signer-chosen `issued_at`.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;

use super::ed25519;
use super::json::Value;
use super::keys::{Fingerprint, KeyParseError, PublicKey};
use super::sshsig::{self, SshSigError};
use super::statements::{
    check_reason, check_timestamp, hex_field, hex_list, parse_doc, string, Head, MAX_STATEMENTS,
    REVOCATION_FORMAT, TRANSITION_FORMAT,
};
use super::{sha256, ALL_NAMESPACES, NS_REVOCATION, NS_TRANSITION, NS_TRANSITION_ACCEPT};

/// The namespaces in which a pinned key's signatures are accepted.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Scope(u8);

impl std::fmt::Debug for Scope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list().entries(self.namespaces()).finish()
    }
}

fn ns_bit(ns: &str) -> Option<u8> {
    ALL_NAMESPACES
        .iter()
        .position(|n| *n == ns)
        .map(|i| 1u8 << i)
}

impl Scope {
    /// Record, checkpoint, release, key-transition and key-revocation:
    /// what a line without options, `--public-key` and `--key-fingerprint`
    /// get (spec §9.1).
    pub const DEFAULT: Scope = Scope(0b101_1011);
    /// The witness namespace only.
    pub const WITNESS: Scope = Scope(0b000_0100);
    /// Key revocation only (an offline backup key).
    pub const REVOCATION_ONLY: Scope = Scope(0b100_0000);

    /// A scope from exact namespace names. The acceptance namespace is not
    /// a scope: an accepting key need not be trusted yet (spec §9.3).
    pub fn from_namespaces<'a>(names: impl IntoIterator<Item = &'a str>) -> Result<Self, String> {
        let mut bits = 0u8;
        for n in names {
            if n == NS_TRANSITION_ACCEPT {
                return Err(format!("{n} cannot be part of a scope"));
            }
            bits |= ns_bit(n).ok_or_else(|| format!("unknown namespace {n:?}"))?;
        }
        if bits == 0 {
            return Err("empty scope".into());
        }
        Ok(Self(bits))
    }

    /// Whether `ns` is in this scope.
    #[must_use]
    pub fn contains(&self, ns: &str) -> bool {
        ns_bit(ns).is_some_and(|b| self.0 & b != 0)
    }

    /// The namespaces, in spec order.
    #[must_use]
    pub fn namespaces(&self) -> Vec<&'static str> {
        ALL_NAMESPACES
            .iter()
            .copied()
            .filter(|n| self.contains(n))
            .collect()
    }
}

/// Errors in the operator's trust inputs: always argument errors (exit 3).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TrustError {
    /// A pin that is not a key or fingerprint, or a weak key.
    #[error("{0}")]
    Key(#[from] KeyParseError),
    /// A malformed trust file line.
    #[error("trust file line {line}: {message}")]
    TrustFile {
        /// 1-based line number.
        line: usize,
        /// What was wrong.
        message: String,
    },
    /// A statement or revocation passed by the operator that does not
    /// parse or verify.
    #[error("{path}: {message}")]
    Statement {
        /// The statement file.
        path: String,
        /// What was wrong.
        message: String,
    },
    /// A revocation passed by the operator whose signer has no authority
    /// over the key it revokes (spec §9.4).
    #[error("{path}: the signer of this revocation has no authority over the key it revokes (only the key itself, or a directly pinned key of the same principal with key-revocation in its scope)")]
    NoAuthority {
        /// The revocation file.
        path: String,
    },
    /// Over a §3.8 limit.
    #[error("{0}")]
    Limit(String),
    /// I/O reading a trust input.
    #[error("{path}: {message}")]
    Io {
        /// The path.
        path: String,
        /// The error.
        message: String,
    },
}

/// Where a statement came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// Passed by the operator: failures are argument errors.
    Operator(String),
    /// Found in a bundle: failures are warnings and add no trust.
    Bundle(String),
}

impl Source {
    /// The statement file path.
    #[must_use]
    pub fn path(&self) -> &str {
        match self {
            Source::Operator(p) | Source::Bundle(p) => p,
        }
    }
}

#[derive(Debug, Clone)]
struct Pin {
    key_id: Fingerprint,
    key: Option<PublicKey>,
    principal: String,
    auto_principal: bool,
    scope: Scope,
}

/// A cryptographically verified key transition (spec §9.3).
#[derive(Debug, Clone)]
pub struct Transition {
    /// SHA-256 of the statement bytes.
    pub sha256: [u8; 32],
    /// The retired key.
    pub old_key_id: Fingerprint,
    /// The retired key's bytes (from its signature blob).
    pub old_key: PublicKey,
    /// The successor.
    pub new_key: PublicKey,
    /// Heads of every log the old key signed.
    pub final_heads: Vec<Head>,
    /// SHA-256 of every attestation the old key signed.
    pub final_releases: Vec<[u8; 32]>,
    /// The old signer's clock.
    pub issued_at: String,
    /// Where it came from.
    pub source: Source,
}

/// A cryptographically verified revocation (spec §9.4).
#[derive(Debug, Clone)]
pub struct Revocation {
    /// SHA-256 of the statement bytes.
    pub sha256: [u8; 32],
    /// The revoked key.
    pub revoked: Fingerprint,
    /// Who signed it.
    pub revoker: Fingerprint,
    /// Log heads still vouched for.
    pub trusted_heads: Vec<Head>,
    /// Attestations still vouched for.
    pub trusted_releases: Vec<[u8; 32]>,
    /// Successors still vouched for.
    pub trusted_successors: Vec<Fingerprint>,
    /// The revoker's clock.
    pub issued_at: String,
    /// Where it came from.
    pub source: Source,
}

/// The verifier's pins, statements, and revocations.
#[derive(Debug, Clone, Default)]
pub struct TrustContext {
    pins: Vec<Pin>,
    transitions: Vec<Transition>,
    revocations: Vec<Revocation>,
    warnings: Vec<String>,
    statements_seen: usize,
}

const PRINCIPAL_CHARS: &str = "._@-";

fn valid_principal(p: &str) -> bool {
    !p.is_empty()
        && p.len() <= 256
        && p.chars()
            .all(|c| c.is_ascii_alphanumeric() || PRINCIPAL_CHARS.contains(c))
}

impl TrustContext {
    /// An empty context: no pins. Verification can at best be
    /// `SelfConsistent`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether any key was pinned.
    #[must_use]
    pub fn has_pins(&self) -> bool {
        !self.pins.is_empty()
    }

    /// Warnings from statements found in bundles that were ignored.
    #[must_use]
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    fn auto_principal(&self) -> String {
        format!("supplied-key-{}", self.pins.len() + 1)
    }

    /// Pin a public key. Refuses a weak key (spec §3.5 rules 1–3).
    pub fn pin_key(
        &mut self,
        key: PublicKey,
        principal: Option<&str>,
        scope: Scope,
    ) -> Result<(), TrustError> {
        if !key.is_strong() {
            return Err(KeyParseError::WeakKey.into());
        }
        self.push_pin(key.fingerprint(), Some(key), principal, scope)
    }

    /// Pin a fingerprint. The key bytes then come from the artefact and
    /// are accepted only if they hash to it (and pass the strength checks).
    pub fn pin_fingerprint(
        &mut self,
        fingerprint: Fingerprint,
        principal: Option<&str>,
        scope: Scope,
    ) -> Result<(), TrustError> {
        if super::ed25519::SMALL_ORDER_ENCODINGS.iter().any(|enc| {
            super::unhex::<32>(enc)
                .is_some_and(|k| PublicKey::ed25519(k).fingerprint() == fingerprint)
        }) {
            return Err(KeyParseError::WeakKey.into());
        }
        self.push_pin(fingerprint, None, principal, scope)
    }

    /// Pin `text`: an OpenSSH or PEM public key, or a fingerprint in any
    /// §3.7 form. Plain 64 hex digits are read as a **fingerprint**, the
    /// form people are given to check; a raw-hex public key is pinned
    /// with [`pin_key`](Self::pin_key) after [`PublicKey::parse`].
    pub fn pin(
        &mut self,
        text: &str,
        principal: Option<&str>,
        scope: Scope,
    ) -> Result<(), TrustError> {
        let t = text.trim();
        if t.starts_with("ssh-ed25519 ") || t.starts_with("-----BEGIN") {
            self.pin_key(PublicKey::parse(t)?, principal, scope)
        } else {
            self.pin_fingerprint(Fingerprint::parse(t)?, principal, scope)
        }
    }

    fn push_pin(
        &mut self,
        key_id: Fingerprint,
        key: Option<PublicKey>,
        principal: Option<&str>,
        scope: Scope,
    ) -> Result<(), TrustError> {
        if self.pins.len() >= 1024 {
            return Err(TrustError::Limit("more than 1024 pinned keys".into()));
        }
        let (principal, auto) = match principal {
            Some(p) if valid_principal(p) => (p.to_string(), false),
            Some(p) => {
                return Err(TrustError::TrustFile {
                    line: 0,
                    message: format!("invalid principal {p:?}"),
                })
            },
            None => (self.auto_principal(), true),
        };
        self.pins.push(Pin {
            key_id,
            key,
            principal,
            auto_principal: auto,
            scope,
        });
        Ok(())
    }

    /// Add the pins of a trust file: OpenSSH `allowed_signers`, restricted
    /// to `<principal> [namespaces="…"] ssh-ed25519 <base64> [comment]`.
    pub fn add_allowed_signers(&mut self, text: &str) -> Result<(), TrustError> {
        if text.len() > 1024 * 1024 {
            return Err(TrustError::Limit("trust file larger than 1 MiB".into()));
        }
        for (i, raw) in text.lines().enumerate() {
            let line = i + 1;
            let err = |m: &str| TrustError::TrustFile {
                line,
                message: m.to_string(),
            };
            let l = raw.trim();
            if l.is_empty() || l.starts_with('#') {
                continue;
            }
            let mut tokens = l.split_whitespace();
            let principal = tokens.next().ok_or_else(|| err("missing principal"))?;
            if !valid_principal(principal) {
                return Err(err(
                    "principal must be one name of letters, digits and . _ @ -",
                ));
            }
            let mut next = tokens.next().ok_or_else(|| err("missing key"))?;
            let mut scope = Scope::DEFAULT;
            if next != "ssh-ed25519" {
                let value = next
                    .strip_prefix("namespaces=\"")
                    .and_then(|v| v.strip_suffix('"'))
                    .ok_or_else(|| {
                        err(&format!(
                            "unsupported option {next:?}: only namespaces=\"…\" is allowed"
                        ))
                    })?;
                scope = Scope::from_namespaces(value.split(','))
                    .map_err(|m| err(&format!("namespaces: {m}")))?;
                next = tokens.next().ok_or_else(|| err("missing key"))?;
            }
            if next != "ssh-ed25519" {
                return Err(err(&format!(
                    "unsupported option or key type {next:?}: only one namespaces=\"…\" option and ssh-ed25519 keys are allowed"
                )));
            }
            let b64 = tokens.next().ok_or_else(|| err("missing key data"))?;
            let blob = STANDARD
                .decode(b64.as_bytes())
                .map_err(|e| err(&format!("key base64: {e}")))?;
            let key = PublicKey::from_key_blob(&blob).map_err(|e| err(&e.to_string()))?;
            if !key.is_strong() {
                return Err(err(&KeyParseError::WeakKey.to_string()));
            }
            self.push_pin(key.fingerprint(), Some(key), Some(principal), scope)?;
        }
        Ok(())
    }

    /// A context from a trust file's text.
    pub fn from_allowed_signers(text: &str) -> Result<Self, TrustError> {
        let mut t = Self::new();
        t.add_allowed_signers(text)?;
        Ok(t)
    }

    /// Load every statement (`*.json` with its `.sig`) in `dir`. With
    /// `operator`, an invalid statement is an error; otherwise (a bundle's
    /// `ogentic-audit-keys/`) it is ignored with a warning.
    pub fn add_statements(&mut self, dir: &Path, operator: bool) -> Result<(), TrustError> {
        let io_err = |e: std::io::Error| TrustError::Io {
            path: dir.display().to_string(),
            message: e.to_string(),
        };
        let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
            .map_err(io_err)?
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "json"))
            .collect();
        files.sort();
        for f in files {
            self.add_statement_file(&f, operator)?;
        }
        Ok(())
    }

    /// Load one statement file (a transition or a revocation, decided by
    /// its `format`) with its sibling signatures.
    pub fn add_statement_file(&mut self, path: &Path, operator: bool) -> Result<(), TrustError> {
        let shown = path.display().to_string();
        let source = if operator {
            Source::Operator(shown.clone())
        } else {
            Source::Bundle(shown.clone())
        };
        self.statements_seen += 1;
        if self.statements_seen > MAX_STATEMENTS {
            let m = "more than 1024 key statements".to_string();
            if operator {
                return Err(TrustError::Limit(m));
            }
            self.warnings.push(format!("{shown}: ignored: {m}"));
            return Ok(());
        }
        match load_statement(path, source.clone()) {
            Ok(Statement::Transition(t)) => self.transitions.push(t),
            Ok(Statement::Revocation(r)) => self.revocations.push(r),
            Err(message) if operator => {
                return Err(TrustError::Statement {
                    path: shown,
                    message,
                })
            },
            Err(message) => self
                .warnings
                .push(format!("{shown}: key statement ignored: {message}")),
        }
        Ok(())
    }

    /// Add a revocation passed by the operator (`--revocations`).
    pub fn add_revocation(&mut self, path: &Path) -> Result<(), TrustError> {
        self.add_statement_file(path, true)
    }

    /// A copy with the statements in a bundle's `ogentic-audit-keys/`
    /// added as bundle statements.
    pub fn with_bundle_statements(&self, dir: &Path) -> Result<Self, TrustError> {
        let mut t = self.clone();
        if dir.is_dir() {
            t.add_statements(dir, false)?;
        }
        Ok(t)
    }

    /// Paths of the statements loaded from a bundle, each parsed with
    /// every signature verified (ignored ones are not listed).
    #[must_use]
    pub fn bundle_statement_paths(&self) -> BTreeSet<&str> {
        let t = self.transitions.iter().map(|t| &t.source);
        let r = self.revocations.iter().map(|r| &r.source);
        t.chain(r)
            .filter_map(|s| match s {
                Source::Bundle(p) => Some(p.as_str()),
                Source::Operator(_) => None,
            })
            .collect()
    }

    /// Evaluate the trust state (spec §9.5).
    pub fn evaluate(&self) -> Result<Evaluated, TrustError> {
        evaluate(self)
    }
}

enum Statement {
    Transition(Transition),
    Revocation(Revocation),
}

fn read_limited(path: &Path, max: u64) -> Result<Vec<u8>, String> {
    let meta = std::fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !meta.is_file() {
        return Err("not a regular file".into());
    }
    if meta.len() > max {
        return Err(format!("larger than {max} bytes"));
    }
    std::fs::read(path).map_err(|e| e.to_string())
}

fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(suffix);
    PathBuf::from(s)
}

/// Verify a detached signature whose signer is the key `expected`: parse
/// the blob strictly, require its key to hash to `expected` and pass the
/// strength checks, and verify. Returns the blob key.
pub fn verify_detached_by(
    sig_text: &[u8],
    namespace: &str,
    message: &[u8],
    expected: &Fingerprint,
) -> Result<PublicKey, String> {
    let sig = sshsig::parse_armored(sig_text, namespace).map_err(|e: SshSigError| e.to_string())?;
    if sig.key.fingerprint() != *expected {
        return Err(format!(
            "signed by {}, not by the key the statement names ({})",
            sig.key.fingerprint().to_grouped_hex(),
            expected.to_grouped_hex()
        ));
    }
    let data = sshsig::signed_data(namespace, message);
    ed25519::verify(sig.key.as_bytes(), &data, &sig.signature)
        .map_err(|f| format!("signature invalid ({})", f.reason()))?;
    Ok(sig.key)
}

fn heads(v: &Value, key: &str) -> Result<Vec<Head>, String> {
    v.get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{key} must be an array"))?
        .iter()
        .map(Head::from_json)
        .collect()
}

fn load_statement(path: &Path, source: Source) -> Result<Statement, String> {
    let bytes = read_limited(path, super::statements::MAX_STATEMENT_BYTES as u64)?;
    let doc = parse_doc(&bytes, 3)?;
    let sig = read_limited(&sibling(path, ".sig"), sshsig::MAX_SIG_FILE as u64)
        .map_err(|e| format!("signature file: {e}"))?;
    let format = string(&doc, "format")?;
    let sha = sha256(&bytes);
    match format {
        TRANSITION_FORMAT => {
            let allowed: BTreeSet<&str> = [
                "final_heads",
                "final_releases",
                "format",
                "issued_at",
                "new_key_id",
                "new_public_key",
                "old_key_id",
                "reason",
            ]
            .into();
            check_members(&doc, &allowed)?;
            let old_key_id = Fingerprint(hex_field(&doc, "old_key_id")?);
            let new_key_id = Fingerprint(hex_field(&doc, "new_key_id")?);
            let new_key = PublicKey::parse(string(&doc, "new_public_key")?)
                .map_err(|e| format!("new_public_key: {e}"))?;
            if new_key.fingerprint() != new_key_id {
                return Err("new_key_id does not match new_public_key".into());
            }
            if !new_key.is_strong() {
                return Err("new_public_key is a weak key".into());
            }
            let issued_at = check_timestamp(&doc, "issued_at")?;
            check_reason(&doc)?;
            let final_heads = heads(&doc, "final_heads")?;
            let final_releases = hex_list(&doc, "final_releases")?;
            let old_key = verify_detached_by(&sig, NS_TRANSITION, &bytes, &old_key_id)
                .map_err(|e| format!("transition signature: {e}"))?;
            if new_key.alg().strength() < old_key.alg().strength() {
                return Err("a transition never goes to a weaker algorithm".into());
            }
            let accept = read_limited(&sibling(path, ".accept.sig"), sshsig::MAX_SIG_FILE as u64)
                .map_err(|e| format!("acceptance by the new key is missing: {e}"))?;
            verify_detached_by(&accept, NS_TRANSITION_ACCEPT, &bytes, &new_key_id)
                .map_err(|e| format!("acceptance signature: {e}"))?;
            Ok(Statement::Transition(Transition {
                sha256: sha,
                old_key_id,
                old_key,
                new_key,
                final_heads,
                final_releases,
                issued_at,
                source,
            }))
        },
        REVOCATION_FORMAT => {
            let allowed: BTreeSet<&str> = [
                "format",
                "issued_at",
                "reason",
                "revoked_key_id",
                "revoker_key_id",
                "trusted_heads",
                "trusted_releases",
                "trusted_successors",
            ]
            .into();
            check_members(&doc, &allowed)?;
            let revoked = Fingerprint(hex_field(&doc, "revoked_key_id")?);
            let revoker = Fingerprint(hex_field(&doc, "revoker_key_id")?);
            let issued_at = check_timestamp(&doc, "issued_at")?;
            check_reason(&doc)?;
            let trusted_heads = heads(&doc, "trusted_heads")?;
            let trusted_releases = hex_list(&doc, "trusted_releases")?;
            let trusted_successors = hex_list(&doc, "trusted_successors")?
                .into_iter()
                .map(Fingerprint)
                .collect();
            verify_detached_by(&sig, NS_REVOCATION, &bytes, &revoker)
                .map_err(|e| format!("revocation signature: {e}"))?;
            Ok(Statement::Revocation(Revocation {
                sha256: sha,
                revoked,
                revoker,
                trusted_heads,
                trusted_releases,
                trusted_successors,
                issued_at,
                source,
            }))
        },
        other => Err(format!("unknown statement format {other:?}")),
    }
}

pub(crate) fn check_members(doc: &Value, allowed: &BTreeSet<&str>) -> Result<(), String> {
    let obj = doc.as_object().ok_or("a statement must be a JSON object")?;
    for k in obj.keys() {
        if !allowed.contains(k.as_str()) {
            return Err(format!("unexpected member {k:?}"));
        }
    }
    Ok(())
}

/// One way a key is trusted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The principal (signing party) it belongs to.
    pub principal: String,
    /// Whether the principal name was made up for an option-less pin.
    pub auto_principal: bool,
    /// Namespaces its signatures are accepted in.
    pub scope: Scope,
    /// Pinned key first, then each successor.
    pub trust_path: Vec<Fingerprint>,
    /// Pinned directly (not reached through a transition).
    pub pinned: bool,
}

/// What a signature is on, for retirement and revocation (spec §9.3, §9.4).
#[derive(Debug, Clone, Copy)]
pub enum Object<'a> {
    /// A log record.
    Record {
        /// The log.
        log_id: &'a [u8; 16],
        /// Segment.
        segment: u16,
        /// Position.
        record_id: u64,
        /// Its `record_hash`.
        record_hash: &'a [u8; 32],
    },
    /// A checkpoint of a log at a position.
    Checkpoint {
        /// The log.
        log_id: &'a [u8; 16],
        /// Segment.
        segment: u16,
        /// Position.
        record_id: u64,
    },
    /// A release attestation with this SHA-256.
    Release {
        /// SHA-256 of the attestation bytes.
        sha256: &'a [u8; 32],
    },
    /// A transition to this key.
    Transition {
        /// The successor.
        new_key_id: &'a Fingerprint,
    },
    /// A witness co-signature.
    Witness,
}

/// Why a signature is not accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reject {
    /// The key is not trusted at all.
    NotTrusted,
    /// Trusted, but not for this namespace.
    OutOfScope,
    /// Retired by a transition and this object is not among its final
    /// heads or releases.
    Retired {
        /// The transition's `issued_at`.
        issued_at: String,
        /// The successor.
        successor: Fingerprint,
    },
    /// Revoked and this object is not among the cut points.
    Revoked {
        /// The earliest `issued_at` among the honoured revocations (for
        /// display only; never used to decide).
        issued_at: String,
        /// Whether any authority revocation applies (cut points exist).
        authority: bool,
    },
    /// A retirement or revocation head names this position, but the
    /// record there has a different `record_hash`.
    HeadMismatch {
        /// The head the statement names.
        head: Head,
    },
}

#[derive(Debug, Clone)]
struct Retirement {
    heads: Vec<Head>,
    releases: Vec<[u8; 32]>,
    issued_at: String,
    successor: Fingerprint,
}

#[derive(Debug, Clone)]
struct Cut {
    heads: Vec<Head>,
    releases: Vec<[u8; 32]>,
    successors: Vec<Fingerprint>,
    issued_at: String,
    authority: bool,
}

/// An evaluated trust state.
#[derive(Debug, Clone, Default)]
pub struct Evaluated {
    has_pins: bool,
    entries: HashMap<Fingerprint, Vec<Entry>>,
    keys: HashMap<Fingerprint, PublicKey>,
    retired: HashMap<Fingerprint, Retirement>,
    revoked: HashMap<Fingerprint, Cut>,
    /// Keys with two verified transitions, and the two statements' hashes.
    pub equivocations: Vec<(Fingerprint, [u8; 32], [u8; 32])>,
    /// Statements found in bundles that were ignored, and why.
    pub warnings: Vec<String>,
}

fn head_check(heads: &[Head], obj: &Object<'_>) -> Option<Result<(), Head>> {
    match obj {
        Object::Record {
            log_id,
            segment,
            record_id,
            record_hash,
        } => heads
            .iter()
            .find(|h| &h.log_id == *log_id && h.covers(*segment, *record_id))
            .map(|h| {
                if (h.segment, h.record_id) == (*segment, *record_id)
                    && &h.record_hash != *record_hash
                {
                    Err(*h)
                } else {
                    Ok(())
                }
            }),
        Object::Checkpoint {
            log_id,
            segment,
            record_id,
        } => heads
            .iter()
            .any(|h| &h.log_id == *log_id && h.covers(*segment, *record_id))
            .then_some(Ok(())),
        _ => None,
    }
}

impl Evaluated {
    /// Whether any key was pinned.
    #[must_use]
    pub fn has_pins(&self) -> bool {
        self.has_pins
    }

    /// Every way `key_id` is trusted.
    #[must_use]
    pub fn entries(&self, key_id: &Fingerprint) -> &[Entry] {
        self.entries.get(key_id).map_or(&[], Vec::as_slice)
    }

    /// A known copy of the key's bytes (from a pin or a statement).
    #[must_use]
    pub fn known_key(&self, key_id: &Fingerprint) -> Option<&PublicKey> {
        self.keys.get(key_id)
    }

    /// The log heads that `key_id`'s retirement and authority revocation
    /// name. Each must be in its log with that `record_hash` (spec §9.3
    /// item 2, §9.4), or the key's records there are not accepted.
    #[must_use]
    pub fn statement_heads(&self, key_id: &Fingerprint) -> Vec<Head> {
        let retired = self.retired.get(key_id).into_iter().flat_map(|r| &r.heads);
        let revoked = self.revoked.get(key_id).into_iter().flat_map(|c| &c.heads);
        retired.chain(revoked).copied().collect()
    }

    /// Whether the key was retired by a followed transition.
    #[must_use]
    pub fn is_retired(&self, key_id: &Fingerprint) -> bool {
        self.retired.contains_key(key_id)
    }

    /// Whether the key is revoked.
    #[must_use]
    pub fn is_revoked(&self, key_id: &Fingerprint) -> bool {
        self.revoked.contains_key(key_id)
    }

    /// Is a signature by `key_id` in namespace `ns` on `obj` accepted?
    /// Returns the entry it is accepted under.
    pub fn accept(
        &self,
        key_id: &Fingerprint,
        ns: &str,
        obj: &Object<'_>,
    ) -> Result<&Entry, Reject> {
        let entries = self.entries(key_id);
        if entries.is_empty() {
            return Err(Reject::NotTrusted);
        }
        let entry = entries
            .iter()
            .find(|e| e.scope.contains(ns))
            .ok_or(Reject::OutOfScope)?;
        if let Some(r) = self.retired.get(key_id) {
            let allowed = match obj {
                Object::Release { sha256 } => r.releases.contains(sha256),
                Object::Transition { .. } => true,
                Object::Witness => false,
                _ => match head_check(&r.heads, obj) {
                    Some(Ok(())) => true,
                    Some(Err(head)) => return Err(Reject::HeadMismatch { head }),
                    None => false,
                },
            };
            if !allowed {
                return Err(Reject::Retired {
                    issued_at: r.issued_at.clone(),
                    successor: r.successor,
                });
            }
        }
        if let Some(c) = self.revoked.get(key_id) {
            let allowed = match obj {
                Object::Release { sha256 } => c.releases.contains(sha256),
                Object::Transition { new_key_id } => c.successors.contains(new_key_id),
                Object::Witness => false,
                _ => match head_check(&c.heads, obj) {
                    Some(Ok(())) => true,
                    Some(Err(head)) => return Err(Reject::HeadMismatch { head }),
                    None => false,
                },
            };
            if !allowed {
                return Err(Reject::Revoked {
                    issued_at: c.issued_at.clone(),
                    authority: c.authority,
                });
            }
        }
        Ok(entry)
    }
}

fn evaluate(ctx: &TrustContext) -> Result<Evaluated, TrustError> {
    let mut out = Evaluated {
        has_pins: !ctx.pins.is_empty(),
        warnings: ctx.warnings.clone(),
        ..Evaluated::default()
    };
    let mut base: HashMap<Fingerprint, Vec<Entry>> = HashMap::new();
    for p in &ctx.pins {
        if let Some(k) = p.key {
            out.keys.insert(p.key_id, k);
        }
        let e = Entry {
            principal: p.principal.clone(),
            auto_principal: p.auto_principal,
            scope: p.scope,
            trust_path: vec![p.key_id],
            pinned: true,
        };
        let list = base.entry(p.key_id).or_default();
        if !list.contains(&e) {
            list.push(e);
        }
    }

    // Equivocation: two different verified transitions from one key.
    let mut by_old: BTreeMap<Fingerprint, Vec<&Transition>> = BTreeMap::new();
    for t in &ctx.transitions {
        let list = by_old.entry(t.old_key_id).or_default();
        if !list.iter().any(|x| x.sha256 == t.sha256) {
            list.push(t);
        }
    }
    let equivocating: BTreeSet<Fingerprint> = by_old
        .iter()
        .filter(|(_, l)| l.len() > 1)
        .map(|(k, _)| *k)
        .collect();

    // Step A: principals of each key, following transitions without
    // regard to revocation. Used only to decide revocation authority, so
    // that authority is a fixed property of who a key belongs to.
    let principals_entries = extend(&base, &by_old, &|t| !equivocating.contains(&t.old_key_id));

    // Step B: honoured revocations, and cut points.
    let pinned_by_key: HashMap<Fingerprint, Vec<&Pin>> =
        ctx.pins.iter().fold(HashMap::new(), |mut m, p| {
            m.entry(p.key_id).or_default().push(p);
            m
        });
    let mut revoked_any: BTreeSet<Fingerprint> = BTreeSet::new();
    let mut authority_cuts: BTreeMap<Fingerprint, Vec<&Revocation>> = BTreeMap::new();
    let mut revocations: Vec<&Revocation> = ctx.revocations.iter().collect();
    revocations.sort_by_key(|r| r.sha256);
    revocations.dedup_by_key(|r| r.sha256);
    for r in revocations {
        if r.revoker == r.revoked {
            revoked_any.insert(r.revoked);
            continue;
        }
        let k_principals: BTreeSet<&str> = principals_entries
            .get(&r.revoked)
            .map(|es| es.iter().map(|e| e.principal.as_str()).collect())
            .unwrap_or_default();
        let authority = pinned_by_key.get(&r.revoker).is_some_and(|pins| {
            pins.iter().any(|p| {
                p.scope.contains(NS_REVOCATION) && k_principals.contains(p.principal.as_str())
            })
        });
        if authority {
            revoked_any.insert(r.revoked);
            authority_cuts.entry(r.revoked).or_default().push(r);
        } else {
            match &r.source {
                Source::Operator(p) => return Err(TrustError::NoAuthority { path: p.clone() }),
                Source::Bundle(p) => out.warnings.push(format!(
                    "{p}: revocation ignored: its signer has no authority over the key it revokes"
                )),
            }
        }
    }
    let all_revocations = &ctx.revocations;
    for k in &revoked_any {
        let auth = authority_cuts.get(k);
        let earliest = all_revocations
            .iter()
            .filter(|r| r.revoked == *k)
            .map(|r| r.issued_at.clone())
            .min()
            .unwrap_or_default();
        let cut = match auth {
            None => Cut {
                heads: vec![],
                releases: vec![],
                successors: vec![],
                issued_at: earliest,
                authority: false,
            },
            Some(list) => {
                let mut heads = list[0].trusted_heads.clone();
                let mut releases = list[0].trusted_releases.clone();
                let mut successors = list[0].trusted_successors.clone();
                for r in &list[1..] {
                    heads.retain(|h| r.trusted_heads.contains(h));
                    releases.retain(|h| r.trusted_releases.contains(h));
                    successors.retain(|h| r.trusted_successors.contains(h));
                }
                Cut {
                    heads,
                    releases,
                    successors,
                    issued_at: earliest,
                    authority: true,
                }
            },
        };
        out.revoked.insert(*k, cut);
    }

    // Step C: entries, following transitions allowed under revocation.
    // A revoked old key is followed only to a successor its cut points
    // list; an equivocating one only to a successor an authority
    // revocation lists (spec §9.3 item 3, §9.4).
    let revoked = out.revoked.clone();
    let follow = |t: &Transition| -> bool {
        match revoked.get(&t.old_key_id) {
            Some(c) => c.successors.contains(&t.new_key.fingerprint()),
            None => !equivocating.contains(&t.old_key_id),
        }
    };
    let entries = extend(&base, &by_old, &follow);

    // Retirement: every followed transition retires its old key.
    for (old, list) in &by_old {
        if equivocating.contains(old) {
            if entries.contains_key(old) {
                out.equivocations
                    .push((*old, list[0].sha256, list[1].sha256));
            }
            continue;
        }
        let t = list[0];
        let followed = entries
            .get(old)
            .is_some_and(|es| es.iter().any(|e| e.scope.contains(NS_TRANSITION)))
            && follow(t);
        if followed {
            out.retired.insert(
                *old,
                Retirement {
                    heads: t.final_heads.clone(),
                    releases: t.final_releases.clone(),
                    issued_at: t.issued_at.clone(),
                    successor: t.new_key.fingerprint(),
                },
            );
            out.keys.insert(t.old_key_id, t.old_key);
            out.keys.insert(t.new_key.fingerprint(), t.new_key);
        }
    }
    out.entries = entries;
    Ok(out)
}

/// Follow transitions from `base` to a fixpoint. Each `(key, principal)`
/// pair is added at most once, so this ends after at most one pass per
/// statement. `follow` decides whether a transition may extend trust.
fn extend(
    base: &HashMap<Fingerprint, Vec<Entry>>,
    by_old: &BTreeMap<Fingerprint, Vec<&Transition>>,
    follow: &dyn Fn(&Transition) -> bool,
) -> HashMap<Fingerprint, Vec<Entry>> {
    let mut entries = base.clone();
    loop {
        let mut added = false;
        for (old, list) in by_old {
            for t in list {
                if !follow(t) {
                    continue;
                }
                let new_id = t.new_key.fingerprint();
                let sources: Vec<Entry> = entries
                    .get(old)
                    .map(|es| {
                        es.iter()
                            .filter(|e| e.scope.contains(NS_TRANSITION))
                            .cloned()
                            .collect()
                    })
                    .unwrap_or_default();
                for e in sources {
                    let list = entries.entry(new_id).or_default();
                    if list.iter().any(|x| x.principal == e.principal) {
                        continue;
                    }
                    let mut path = e.trust_path.clone();
                    path.push(new_id);
                    list.push(Entry {
                        principal: e.principal.clone(),
                        auto_principal: e.auto_principal,
                        scope: e.scope,
                        trust_path: path,
                        pinned: false,
                    });
                    added = true;
                }
            }
        }
        if !added {
            return entries;
        }
    }
}
