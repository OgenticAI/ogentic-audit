//! Release attestations: the offline verifier bundle (spec v0.2 §11).
//!
//! A release is a folder of released files plus one or more signed logs,
//! and a canonical-JSON attestation listing every file (size, SHA-256,
//! optional named byte ranges) and every log head, with a detached SSHSIG
//! that `ssh-keygen -Y verify` can check. [`AttestationBuilder`] writes
//! one; [`verify_release`] checks one and reports **every** problem,
//! naming each altered file, row, or record.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::File;
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use unicase::UniCase;

use super::checkpoint::{CheckpointV2, WitnessCosignature};
use super::ed25519;
use super::format::{self, record_hash, Envelope, Frame, HEADER_LEN};
use super::json::{self, Value};
use super::keys::{Fingerprint, PublicKey, SigAlg};
use super::names::{self, escape};
use super::report::{
    describe, thousands, Marks, NotVerifiedReason, SignedVerifyReport, SignerInfo, SignerReason,
    Warning,
};
use super::signer::{sign_detached, SignError, Signer};
use super::sshsig;
use super::statements::{hex_field, int, string, Head};
use super::trust::{check_members, verify_detached_by, Object, Reject, TrustContext, TrustError};
use super::verify::{verify_log, SignedVerifyError, SignedVerifyOptions};
use super::{hex, now_rfc3339, sha256, Scope, NS_RELEASE, NS_WITNESS};
use crate::verifier::{Verdict, ViolationKind};

/// Format string of a release attestation.
pub const RELEASE_FORMAT: &str = "ogentic-audit-release/v1";
/// The attestation file name.
pub const ATTESTATION_FILE: &str = "ogentic-audit-release.json";
/// The attestation signature file name.
pub const ATTESTATION_SIG_FILE: &str = "ogentic-audit-release.json.sig";
/// The informational public key file.
pub const SIGNER_PUB_FILE: &str = "ogentic-audit-signer.pub";
/// Directory of key statements in a bundle.
pub const KEYS_DIR: &str = "ogentic-audit-keys";
/// Directory of witness co-signatures in a bundle.
pub const WITNESS_DIR: &str = "ogentic-audit-witness";
/// The instructions file.
pub const INSTRUCTIONS_FILE: &str = "HOW-TO-VERIFY.txt";
/// Minimum verifier version named in instructions.
pub const MIN_VERIFIER_VERSION: &str = "0.4.0";

const MAX_ATTESTATION: u64 = 64 * 1024 * 1024;
const MAX_FILES: usize = 1_048_576;
const MAX_PARTS: usize = 1_048_576;
const MAX_LOGS: usize = 1024;

/// A named byte range inside a file, such as one row of an index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Part {
    /// Unique within the file.
    pub name: String,
    /// 0-based offset.
    pub offset: u64,
    /// Length, at least 1.
    pub length: u64,
}

/// A released file, relative to the release folder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileSpec {
    /// `/`-separated relative path, NFC.
    pub path: String,
    /// Optional caller-defined role (`page`, `index`, `verifier`, …).
    pub role: Option<String>,
    /// Optional named byte ranges.
    pub parts: Vec<Part>,
}

impl FileSpec {
    /// A file with no role and no parts.
    #[must_use]
    pub fn new(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            role: None,
            parts: Vec::new(),
        }
    }

    /// Set the role.
    #[must_use]
    pub fn role(mut self, role: impl Into<String>) -> Self {
        self.role = Some(role.into());
        self
    }

    /// Set the parts.
    #[must_use]
    pub fn parts(mut self, parts: Vec<Part>) -> Self {
        self.parts = parts;
        self
    }
}

/// A log to include in a release.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogSpec {
    /// The live log directory to copy from.
    pub source: PathBuf,
    /// Destination path inside the release (`/`-separated).
    pub path: String,
    /// The head to attest. `None`: the log must end in `log.sealed`.
    pub head: Option<(u16, u64)>,
    /// Records whose bodies are withheld (elided) in the released copy.
    pub elide: Vec<(u16, u64)>,
}

/// SHA-256 of the attestation bytes: what `final_releases` and
/// `trusted_releases` name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttestationDigest(pub [u8; 32]);

impl AttestationDigest {
    /// Lowercase hex.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex(&self.0)
    }
}

/// Errors building or verifying a release that are not findings.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ReleaseError {
    /// I/O (exit 2).
    #[error("{0}")]
    Io(String),
    /// Invalid caller input (exit 3).
    #[error("{0}")]
    Invalid(String),
    /// Invalid trust inputs (exit 3).
    #[error("{0}")]
    Trust(#[from] TrustError),
    /// A log to include does not verify under the signer's key.
    #[error("log {path} does not verify under the signer's key: {verdict}")]
    LogDoesNotVerify {
        /// The log.
        path: String,
        /// The compact verdict.
        verdict: String,
    },
    /// Signing failed.
    #[error("signing failed: {0}")]
    Sign(#[from] SignError),
}

impl From<io::Error> for ReleaseError {
    fn from(e: io::Error) -> Self {
        ReleaseError::Io(e.to_string())
    }
}

impl ReleaseError {
    /// CLI exit code.
    #[must_use]
    pub fn exit_code(&self) -> u8 {
        match self {
            ReleaseError::Io(_) => 2,
            _ => 3,
        }
    }
}

/// Builds and signs a release attestation (spec §11.3).
#[derive(Debug, Clone)]
pub struct AttestationBuilder {
    dir: PathBuf,
    release_id: String,
    files: Vec<FileSpec>,
    logs: Vec<LogSpec>,
    statements: Vec<PathBuf>,
    witnesses: Vec<PathBuf>,
    created_at: Option<String>,
    trust: Option<TrustContext>,
}

fn validate_parts(path: &str, parts: &[Part], size: u64) -> Result<(), String> {
    let mut names = BTreeSet::new();
    let mut end = 0u64;
    for (i, p) in parts.iter().enumerate() {
        names::check_string(&p.name).map_err(|e| format!("{path}: part name {e}"))?;
        if p.name.is_empty() || !names.insert(p.name.as_str()) {
            return Err(format!("{path}: part names must be non-empty and unique"));
        }
        if p.length == 0 {
            return Err(format!("{path}: part {:?} has length 0", p.name));
        }
        if i > 0 && p.offset < end {
            return Err(format!(
                "{path}: parts must be sorted by offset and not overlap"
            ));
        }
        end = p
            .offset
            .checked_add(p.length)
            .ok_or_else(|| format!("{path}: part out of range"))?;
        if end > size {
            return Err(format!(
                "{path}: part {:?} extends past the end of the file",
                p.name
            ));
        }
    }
    Ok(())
}

/// SHA-256 of a whole file and of each part, in one streaming pass.
fn hash_file(file: &mut impl Read, parts: &[Part]) -> io::Result<(u64, [u8; 32], Vec<[u8; 32]>)> {
    let mut whole = Sha256::new();
    let mut part_hashers: Vec<Sha256> = parts.iter().map(|_| Sha256::new()).collect();
    let mut buf = vec![0u8; 64 * 1024];
    let mut pos = 0u64;
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        let chunk = &buf[..n];
        whole.update(chunk);
        let (c0, c1) = (pos, pos + n as u64);
        for (p, h) in parts.iter().zip(part_hashers.iter_mut()) {
            let (p0, p1) = (p.offset, p.offset + p.length);
            let (a, b) = (c0.max(p0), c1.min(p1));
            if a < b {
                h.update(&chunk[(a - c0) as usize..(b - c0) as usize]);
            }
        }
        pos = c1;
    }
    Ok((
        pos,
        whole.finalize().into(),
        part_hashers
            .into_iter()
            .map(|h| h.finalize().into())
            .collect(),
    ))
}

/// The instructions text (spec §11.9).
#[must_use]
pub fn instructions_text(release_id: &str) -> String {
    format!(
        "How to check this release

This folder was signed when it was released. You can check that nothing in it has been
changed, without trusting whoever gave it to you and without any secret.

1. Get the signer's key fingerprint FROM THE SIGNER, not from this folder: from their
   website, a letter, a filing, or by phone. It is 64 characters long, usually written
   in 16 groups of 4. Any fingerprint printed inside this folder could have been replaced.

2. Check the signature and every file with standard tools, as described at
   https://github.com/OgenticAI/ogentic-audit/blob/main/docs/guides/verifying-a-release.md
   This needs only OpenSSH and Python, which most computers already have.

3. To also check the audit log, use ogentic-audit version {MIN_VERIFIER_VERSION} or later. Download it
   from https://github.com/OgenticAI/ogentic-audit/releases and check it as that page
   explains. Do not run a verifier from this folder until step 2 has passed. Then run:

     ogentic-audit verify-release . --key-fingerprint \"<the fingerprint from step 1>\"

   \"Verified\" means every file and the audit log are exactly as signed. \"Not verified:
   you did not supply the signer's key\" means you skipped step 1. Anything else names
   what changed, what is missing, or what was added.

Release: {release_id}
"
    )
}

struct CopiedLog {
    path: String,
    checkpoint: CheckpointV2,
}

impl AttestationBuilder {
    /// A builder for the release folder `dir` (which must exist and hold
    /// the released files).
    #[must_use]
    pub fn new(dir: impl Into<PathBuf>, release_id: impl Into<String>) -> Self {
        Self {
            dir: dir.into(),
            release_id: release_id.into(),
            files: Vec::new(),
            logs: Vec::new(),
            statements: Vec::new(),
            witnesses: Vec::new(),
            created_at: None,
            trust: None,
        }
    }

    /// Attest a file already in the release folder.
    pub fn add_file(&mut self, file: FileSpec) -> &mut Self {
        self.files.push(file);
        self
    }

    /// Copy a log into the release (through its head, eliding the given
    /// bodies) and attest its head.
    pub fn add_log(&mut self, log: LogSpec) -> &mut Self {
        self.logs.push(log);
        self
    }

    /// Ship a key statement (`<name>.json` and its signatures) in
    /// `ogentic-audit-keys/`.
    pub fn add_statement(&mut self, json_path: impl Into<PathBuf>) -> &mut Self {
        self.statements.push(json_path.into());
        self
    }

    /// Ship a witness co-signature (`<name>.json` and `.sig`) in
    /// `ogentic-audit-witness/`.
    pub fn add_witness(&mut self, json_path: impl Into<PathBuf>) -> &mut Self {
        self.witnesses.push(json_path.into());
        self
    }

    /// Fix `created_at` (reproducible vectors); default is now.
    pub fn created_at(&mut self, ts: impl Into<String>) -> &mut Self {
        self.created_at = Some(ts.into());
        self
    }

    /// Trust used to verify included logs before attesting them. Default:
    /// the signer's own key only. Needed when a log was written under an
    /// earlier key.
    pub fn trust(&mut self, trust: TrustContext) -> &mut Self {
        self.trust = Some(trust);
        self
    }

    /// Copy logs, write the instructions, public key and statements, hash
    /// every file, and sign. Returns the attestation's SHA-256.
    pub fn write(&self, signer: &dyn Signer) -> Result<AttestationDigest, ReleaseError> {
        let invalid = |m: String| ReleaseError::Invalid(m);
        if self.release_id.is_empty() || self.release_id.chars().count() > 256 {
            return Err(invalid("release_id must be 1–256 characters".into()));
        }
        names::check_string(&self.release_id).map_err(|e| invalid(format!("release_id {e}")))?;
        if !self.dir.is_dir() {
            return Err(invalid(format!(
                "{} is not a directory",
                self.dir.display()
            )));
        }
        if self.logs.len() > MAX_LOGS {
            return Err(invalid("more than 1024 logs".into()));
        }
        let pk = *signer.public_key();
        let trust = match &self.trust {
            Some(t) => t.clone(),
            None => {
                let mut t = TrustContext::new();
                t.pin_key(pk, Some("release-signer"), Scope::DEFAULT)?;
                t
            },
        };
        let eval = trust.evaluate()?;

        // Logs.
        let mut copied = Vec::new();
        for l in &self.logs {
            names::check_path(&l.path)
                .map_err(|e| invalid(format!("log path {:?}: {e}", l.path)))?;
            let report = verify_log(&l.source, &eval, &SignedVerifyOptions::default())
                .map_err(|e| invalid(format!("log {}: {e}", l.source.display())))?;
            if report.verdict != Verdict::Verified {
                return Err(ReleaseError::LogDoesNotVerify {
                    path: l.source.display().to_string(),
                    verdict: report.compact_verdict(),
                });
            }
            let dest = self.dir.join(&l.path);
            copied.push(copy_log(
                &l.source, &dest, &l.path, l.head, &l.elide, &report,
            )?);
        }

        // Instructions, public key, statements, witnesses.
        std::fs::write(
            self.dir.join(INSTRUCTIONS_FILE),
            instructions_text(&self.release_id),
        )?;
        std::fs::write(
            self.dir.join(SIGNER_PUB_FILE),
            format!("{}\n", pk.to_openssh("ogentic-audit-release-signer")),
        )?;
        for (list, sub, suffixes) in [
            (&self.statements, KEYS_DIR, &[".sig", ".accept.sig"][..]),
            (&self.witnesses, WITNESS_DIR, &[".sig"][..]),
        ] {
            for src in list {
                let d = self.dir.join(sub);
                std::fs::create_dir_all(&d)?;
                let name = src
                    .file_name()
                    .ok_or_else(|| invalid(format!("{}: not a file", src.display())))?;
                std::fs::copy(src, d.join(name))?;
                for suf in suffixes {
                    let mut s = src.as_os_str().to_os_string();
                    s.push(suf);
                    let s = PathBuf::from(s);
                    if s.exists() {
                        let mut n = name.to_os_string();
                        n.push(suf);
                        std::fs::copy(&s, d.join(n))?;
                    }
                }
            }
        }

        // Files.
        let mut files: Vec<FileSpec> = self.files.clone();
        if !files.iter().any(|f| f.path == INSTRUCTIONS_FILE) {
            files.push(FileSpec::new(INSTRUCTIONS_FILE).role("instructions"));
        }
        files.sort_by(|a, b| a.path.as_bytes().cmp(b.path.as_bytes()));
        if files.len() > MAX_FILES {
            return Err(invalid("too many files".into()));
        }
        let log_dirs: BTreeSet<&str> = self.logs.iter().map(|l| l.path.as_str()).collect();
        let mut seen_fold = BTreeSet::new();
        let mut file_values = Vec::new();
        let mut total_parts = 0usize;
        for (i, f) in files.iter().enumerate() {
            names::check_path(&f.path).map_err(|e| invalid(format!("file {:?}: {e}", f.path)))?;
            if i > 0 && files[i - 1].path == f.path {
                return Err(invalid(format!("file {:?} listed twice", f.path)));
            }
            if !seen_fold.insert(UniCase::unicode(f.path.clone())) {
                return Err(invalid(format!(
                    "file {:?} collides with another path on a case-insensitive filesystem",
                    f.path
                )));
            }
            if is_segment_of(&f.path, &log_dirs) {
                return Err(invalid(format!(
                    "{:?} is a segment file of a listed log",
                    f.path
                )));
            }
            if let Some(r) = &f.role {
                names::check_string(r).map_err(|e| invalid(format!("role {e}")))?;
            }
            total_parts += f.parts.len();
            let full = self.dir.join(&f.path);
            let meta = std::fs::symlink_metadata(&full)
                .map_err(|e| invalid(format!("{}: {e}", f.path)))?;
            if !meta.is_file() {
                return Err(invalid(format!("{}: not a regular file", f.path)));
            }
            validate_parts(&f.path, &f.parts, meta.len()).map_err(invalid)?;
            let (size, digest, part_digests) = hash_file(&mut File::open(&full)?, &f.parts)?;
            let mut m = vec![
                ("path", Value::str(&f.path)),
                ("sha256", Value::str(hex(&digest))),
                ("size", Value::Int(size)),
            ];
            if let Some(r) = &f.role {
                m.push(("role", Value::str(r)));
            }
            if !f.parts.is_empty() {
                m.push((
                    "parts",
                    Value::Array(
                        f.parts
                            .iter()
                            .zip(part_digests)
                            .map(|(p, d)| {
                                Value::object([
                                    ("length", Value::Int(p.length)),
                                    ("name", Value::str(&p.name)),
                                    ("offset", Value::Int(p.offset)),
                                    ("sha256", Value::str(hex(&d))),
                                ])
                            })
                            .collect(),
                    ),
                ));
            }
            file_values.push(Value::object(m));
        }
        if total_parts > MAX_PARTS {
            return Err(invalid("too many parts".into()));
        }
        copied.sort_by(|a, b| a.path.as_bytes().cmp(b.path.as_bytes()));
        let logs: Vec<Value> = copied
            .iter()
            .map(|c| {
                Value::object([
                    ("checkpoint", c.checkpoint.to_json(false)),
                    ("path", Value::str(&c.path)),
                ])
            })
            .collect();
        let doc = Value::object([
            ("alg", Value::str(pk.alg().json_name())),
            (
                "created_at",
                Value::str(self.created_at.clone().unwrap_or_else(now_rfc3339)),
            ),
            ("files", Value::Array(file_values)),
            ("format", Value::str(RELEASE_FORMAT)),
            ("key_id", Value::str(pk.fingerprint().to_hex())),
            ("logs", Value::Array(logs)),
            ("release_id", Value::str(&self.release_id)),
        ]);
        let bytes = doc.to_canonical().into_bytes();
        let sig = sign_detached(signer, NS_RELEASE, &bytes)?;
        std::fs::write(self.dir.join(ATTESTATION_FILE), &bytes)?;
        std::fs::write(self.dir.join(ATTESTATION_SIG_FILE), sig)?;
        Ok(AttestationDigest(sha256(&bytes)))
    }
}

fn is_segment_of(path: &str, log_dirs: &BTreeSet<&str>) -> bool {
    match path.rsplit_once('/') {
        Some((dir, name)) => log_dirs.contains(dir) && names::segment_index(name).is_some(),
        None => false,
    }
}

/// Copy `src` through the head into `dest`, eliding bodies.
fn copy_log(
    src: &Path,
    dest: &Path,
    rel: &str,
    head: Option<(u16, u64)>,
    elide: &[(u16, u64)],
    report: &SignedVerifyReport,
) -> Result<CopiedLog, ReleaseError> {
    let invalid = |m: String| ReleaseError::Invalid(m);
    let last = report
        .log
        .head
        .ok_or_else(|| invalid(format!("log {} has no records", src.display())))?;
    let head = match head {
        Some(h) => h,
        None => {
            if !report.log.sealed {
                return Err(invalid(format!(
                    "log {} is not sealed: seal it, or name the head to attest explicitly",
                    src.display()
                )));
            }
            last
        },
    };
    if head > last {
        return Err(invalid(format!(
            "head s{}r{} is past the end of the log",
            head.0, head.1
        )));
    }
    let elide: BTreeSet<(u16, u64)> = elide.iter().copied().collect();
    if let Some(&(s, r)) = elide.iter().find(|&&p| p > head) {
        return Err(invalid(format!(
            "cannot elide s{s}r{r}: it is after the attested head"
        )));
    }
    if dest.exists() && std::fs::read_dir(dest)?.next().is_some() {
        return Err(invalid(format!(
            "{} already exists and is not empty",
            dest.display()
        )));
    }
    std::fs::create_dir_all(dest)?;
    let mut count = 0u64;
    let mut out: Option<(Head, String, SigAlg, Fingerprint)> = None;
    'segments: for seg in 0..=head.0 {
        let name = format!("audit-{seg:04}.cbor");
        let mut f = File::open(src.join(&name))?;
        let len = f.metadata()?.len();
        let mut hb = [0u8; HEADER_LEN];
        f.read_exact(&mut hb)?;
        let h = format::SignedHeader::from_bytes_unchecked(&hb);
        let mut w = std::io::BufWriter::new(File::create(dest.join(&name))?);
        w.write_all(&hb)?;
        let mut r = BufReader::new(f);
        r.seek(SeekFrom::Start(HEADER_LEN as u64))?;
        let mut off = HEADER_LEN as u64;
        let mut p = 0u64;
        while let Frame::Record(raw) = format::read_frame(&mut r, off, len)? {
            off += raw.total_len;
            let env = Envelope::decode(&raw.envelope).map_err(invalid)?;
            let withhold = elide.contains(&(seg, p));
            if withhold && format::is_structural(&env.event) {
                return Err(invalid(format!(
                    "cannot elide s{seg}r{p}: {} is a structural record",
                    env.event
                )));
            }
            let body = if withhold { None } else { raw.body.as_deref() };
            w.write_all(&format::frame(&raw.envelope, &raw.signature, body))?;
            count += 1;
            if (seg, p) == head {
                out = Some((
                    Head {
                        log_id: h.log_id,
                        segment: seg,
                        record_id: p,
                        record_count: count,
                        record_hash: record_hash(&raw.envelope),
                    },
                    env.ts_wall.clone(),
                    SigAlg::from_code(h.sig_alg).unwrap_or(SigAlg::Ed25519),
                    Fingerprint(h.key_id),
                ));
                w.flush()?;
                break 'segments;
            }
            p += 1;
        }
        w.flush()?;
    }
    let (head, ts, alg, kid) =
        out.ok_or_else(|| invalid(format!("head not found in {}", src.display())))?;
    Ok(CopiedLog {
        path: rel.to_string(),
        checkpoint: CheckpointV2 {
            alg,
            key_id: kid,
            head,
            head_ts_wall: ts,
            observed_at: None,
        },
    })
}

// ---------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------

/// What a release finding is about (spec §11.4 "Item").
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReleaseItem {
    /// The attestation itself.
    Attestation,
    /// A released file, or a named part of it.
    File {
        /// Attested path.
        path: String,
        /// Part name.
        part: Option<String>,
    },
    /// A bundled log, optionally a segment or record of it.
    Log {
        /// Attested log path.
        path: String,
        /// Segment.
        segment: Option<u16>,
        /// Record.
        record: Option<u64>,
    },
    /// A key.
    Key {
        /// The key.
        key_id: Fingerprint,
    },
}

impl ReleaseItem {
    /// `attestation`, `file:<path>[#part]`, `log:<path>[/sNrP]`, `key:<hex>`.
    #[must_use]
    pub fn compact(&self) -> String {
        match self {
            ReleaseItem::Attestation => "attestation".into(),
            ReleaseItem::File { path, part: None } => format!("file:{path}"),
            ReleaseItem::File {
                path,
                part: Some(p),
            } => format!("file:{path}#{p}"),
            ReleaseItem::Log {
                path,
                segment: Some(s),
                record: Some(r),
            } => format!("log:{path}/s{s}r{r}"),
            ReleaseItem::Log {
                path,
                segment: Some(s),
                record: None,
            } => format!("log:{path}/s{s}"),
            ReleaseItem::Log { path, .. } => format!("log:{path}"),
            ReleaseItem::Key { key_id } => format!("key:{}", key_id.to_hex()),
        }
    }
}

/// One release violation.
#[derive(Debug, Clone)]
pub struct ReleaseFinding {
    /// What it is about.
    pub item: ReleaseItem,
    /// The kind.
    pub kind: ViolationKind,
    /// Reason or sub-kind.
    pub reason: Option<String>,
    /// Evidence (JSON object).
    pub evidence: Value,
    /// Human summary.
    pub message: String,
}

impl ReleaseFinding {
    /// `Kind@item`.
    #[must_use]
    pub fn compact(&self) -> String {
        format!("{}@{}", self.kind.as_str(), self.item.compact())
    }

    fn to_json(&self) -> Value {
        Value::object([
            ("item", Value::str(escape(&self.item.compact()))),
            ("kind", Value::str(self.kind.as_str())),
            ("reason", self.reason.clone().into()),
            ("evidence", self.evidence.clone()),
            ("message", Value::str(escape(&self.message))),
        ])
    }
}

/// A bundled log's result.
#[derive(Debug, Clone)]
pub struct ReleaseLog {
    /// Attested path.
    pub path: String,
    /// The log report, when the log could be read.
    pub report: Option<SignedVerifyReport>,
}

/// Options for [`verify_release`].
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct ReleaseOptions {
    /// `--expect-release-id`.
    pub expect_release_id: Option<String>,
    /// `--allow-unattested`: unattested files become warnings.
    pub allow_unattested: bool,
    /// Extra witness co-signature files (`--witness`).
    pub witnesses: Vec<PathBuf>,
}

impl ReleaseOptions {
    /// Default options.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    /// Expect this release id.
    #[must_use]
    pub fn expect_release_id(mut self, id: impl Into<String>) -> Self {
        self.expect_release_id = Some(id.into());
        self
    }
    /// Allow unattested files.
    #[must_use]
    pub fn allow_unattested(mut self, on: bool) -> Self {
        self.allow_unattested = on;
        self
    }
}

/// The result of verifying a release (spec §11.6).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ReleaseReport {
    /// Release folder.
    pub release_dir: PathBuf,
    /// `Verified`, `SelfConsistent`, or `Violation`.
    pub verdict: Verdict,
    /// Why `SelfConsistent`.
    pub not_verified_reason: Option<NotVerifiedReason>,
    /// From the attestation.
    pub release_id: Option<String>,
    /// SHA-256 of the attestation bytes.
    pub attestation_sha256: Option<[u8; 32]>,
    /// The attestation signer.
    pub signer: Option<SignerInfo>,
    /// Files listed in the attestation.
    pub files_attested: u64,
    /// Files that matched.
    pub files_verified: u64,
    /// Files not covered by the signature.
    pub unattested: Vec<String>,
    /// Operating-system litter that was ignored.
    pub ignored: Vec<String>,
    /// Bundled logs.
    pub logs: Vec<ReleaseLog>,
    /// Every violation, in §11.4 order.
    pub violations: Vec<ReleaseFinding>,
    /// Warnings.
    pub warnings: Vec<Warning>,
    /// Valid witness co-signatures found.
    pub witnesses: Vec<(String, WitnessCosignature)>,
}

struct Entry {
    rel: String,
    regular: bool,
}

/// Enumerate the release folder without following symlinks or reparse
/// points.
fn enumerate(root: &Path) -> io::Result<Vec<Entry>> {
    let mut out = Vec::new();
    let mut stack = vec![(root.to_path_buf(), String::new())];
    while let Some((dir, prefix)) = stack.pop() {
        for e in std::fs::read_dir(&dir)? {
            let e = e?;
            let name = e.file_name().to_string_lossy().into_owned();
            let rel = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}/{name}")
            };
            let meta = std::fs::symlink_metadata(e.path())?;
            if meta.is_dir() && !is_reparse(&meta) {
                stack.push((e.path(), rel));
            } else {
                out.push(Entry {
                    rel,
                    regular: meta.is_file() && !is_reparse(&meta),
                });
            }
        }
    }
    out.sort_by(|a, b| a.rel.cmp(&b.rel));
    Ok(out)
}

#[cfg(windows)]
fn is_reparse(meta: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    meta.file_attributes() & 0x400 != 0
}

#[cfg(not(windows))]
fn is_reparse(_meta: &std::fs::Metadata) -> bool {
    false
}

/// An attested file: spec, size, SHA-256, part SHA-256s.
type AttFile = (FileSpec, u64, [u8; 32], Vec<[u8; 32]>);

struct Att {
    release_id: String,
    files: Vec<AttFile>,
    logs: Vec<(String, CheckpointV2)>,
}

fn parse_attestation(bytes: &[u8], key: &PublicKey) -> Result<Att, (ViolationKind, String)> {
    let mal = |m: String| (ViolationKind::AttestationMalformed, m);
    let doc = json::parse_canonical(bytes, 5).map_err(|e| mal(e.to_string()))?;
    check_members(
        &doc,
        &[
            "alg",
            "created_at",
            "files",
            "format",
            "key_id",
            "logs",
            "release_id",
        ]
        .into(),
    )
    .map_err(mal)?;
    if string(&doc, "format").map_err(mal)? != RELEASE_FORMAT {
        return Err(mal("not an ogentic-audit-release/v1 document".into()));
    }
    let key_id = Fingerprint(hex_field(&doc, "key_id").map_err(mal)?);
    let alg = string(&doc, "alg").map_err(mal)?;
    if key_id != key.fingerprint() || alg != key.alg().json_name() {
        return Err((
            ViolationKind::KeyIdMismatch,
            "key_id or alg does not name the key that signed the attestation".into(),
        ));
    }
    super::statements::check_timestamp(&doc, "created_at").map_err(mal)?;
    let release_id = string(&doc, "release_id").map_err(mal)?.to_string();
    if release_id.is_empty() || release_id.chars().count() > 256 {
        return Err(mal("release_id must be 1–256 characters".into()));
    }
    names::check_string(&release_id).map_err(|e| mal(format!("release_id {e}")))?;
    let files_v = doc
        .get("files")
        .and_then(Value::as_array)
        .ok_or_else(|| mal("files must be an array".into()))?;
    if files_v.len() > MAX_FILES {
        return Err(mal("limit: too many files".into()));
    }
    let logs_v = doc
        .get("logs")
        .and_then(Value::as_array)
        .ok_or_else(|| mal("logs must be an array".into()))?;
    if logs_v.len() > MAX_LOGS {
        return Err(mal("limit: too many logs".into()));
    }
    let mut logs = Vec::new();
    for l in logs_v {
        check_members(l, &["checkpoint", "path"].into()).map_err(mal)?;
        let path = string(l, "path").map_err(mal)?.to_string();
        names::check_path(&path).map_err(|e| mal(format!("log path {:?}: {e}", escape(&path))))?;
        let cp = CheckpointV2::from_json(l.get("checkpoint").unwrap_or(&Value::Null), false)
            .map_err(|e| mal(format!("log {}: {e}", escape(&path))))?;
        logs.push((path, cp));
    }
    if logs
        .windows(2)
        .any(|w| w[0].0.as_bytes() >= w[1].0.as_bytes())
    {
        return Err(mal("logs must be sorted by path, without duplicates".into()));
    }
    let log_dirs: BTreeSet<&str> = logs.iter().map(|(p, _)| p.as_str()).collect();
    let mut files = Vec::new();
    let mut fold = BTreeSet::new();
    let mut total_parts = 0usize;
    for f in files_v {
        check_members(f, &["parts", "path", "role", "sha256", "size"].into()).map_err(mal)?;
        let path = string(f, "path").map_err(mal)?.to_string();
        names::check_path(&path).map_err(|e| mal(format!("path {:?}: {e}", escape(&path))))?;
        if is_segment_of(&path, &log_dirs) {
            return Err(mal(format!(
                "{:?} is a segment file of a listed log",
                escape(&path)
            )));
        }
        if !fold.insert(UniCase::unicode(path.clone())) {
            return Err(mal(format!(
                "{:?} collides with another path",
                escape(&path)
            )));
        }
        let role = match f.get("role") {
            None => None,
            Some(Value::String(r)) => {
                names::check_string(r).map_err(|e| mal(format!("role {e}")))?;
                Some(r.clone())
            },
            Some(_) => return Err(mal("role must be a string".into())),
        };
        let size = int(f, "size").map_err(mal)?;
        let sha: [u8; 32] = hex_field(f, "sha256").map_err(mal)?;
        let mut parts = Vec::new();
        let mut part_hashes = Vec::new();
        if let Some(pv) = f.get("parts") {
            let arr = pv
                .as_array()
                .ok_or_else(|| mal("parts must be an array".into()))?;
            if arr.is_empty() {
                return Err(mal("parts, when present, must not be empty".into()));
            }
            for p in arr {
                check_members(p, &["length", "name", "offset", "sha256"].into()).map_err(mal)?;
                parts.push(Part {
                    name: string(p, "name").map_err(mal)?.to_string(),
                    offset: int(p, "offset").map_err(mal)?,
                    length: int(p, "length").map_err(mal)?,
                });
                part_hashes.push(hex_field::<32>(p, "sha256").map_err(mal)?);
            }
        }
        total_parts += parts.len();
        if total_parts > MAX_PARTS {
            return Err(mal("limit: too many parts".into()));
        }
        validate_parts(&escape(&path), &parts, size).map_err(mal)?;
        files.push((FileSpec { path, role, parts }, size, sha, part_hashes));
    }
    if files
        .windows(2)
        .any(|w| w[0].0.path.as_bytes() >= w[1].0.path.as_bytes())
    {
        return Err(mal(
            "files must be sorted by path, without duplicates".into()
        ));
    }
    Ok(Att {
        release_id,
        files,
        logs,
    })
}

/// Verify a release folder (spec §11.4).
pub fn verify_release(
    dir: impl AsRef<Path>,
    trust: &TrustContext,
    opts: &ReleaseOptions,
) -> Result<ReleaseReport, ReleaseError> {
    let dir = dir.as_ref();
    if !dir.is_dir() {
        return Err(ReleaseError::Io(format!(
            "{} is not a directory",
            dir.display()
        )));
    }
    let trust = trust.with_bundle_statements(&dir.join(KEYS_DIR))?;
    let eval = trust.evaluate()?;
    let mut rep = ReleaseReport {
        release_dir: dir.to_path_buf(),
        verdict: Verdict::Violation,
        not_verified_reason: None,
        release_id: None,
        attestation_sha256: None,
        signer: None,
        files_attested: 0,
        files_verified: 0,
        unattested: Vec::new(),
        ignored: Vec::new(),
        logs: Vec::new(),
        violations: Vec::new(),
        warnings: eval
            .warnings
            .iter()
            .map(|w| Warning {
                kind: "IgnoredStatement".into(),
                item: KEYS_DIR.into(),
                message: w.clone(),
            })
            .collect(),
        witnesses: Vec::new(),
    };
    let fail = |rep: &mut ReleaseReport, kind, reason: Option<&str>, msg: String| {
        rep.violations.push(ReleaseFinding {
            item: ReleaseItem::Attestation,
            kind,
            reason: reason.map(str::to_string),
            evidence: Value::object([]),
            message: msg,
        });
    };
    // A1.
    let att_path = dir.join(ATTESTATION_FILE);
    let meta = match std::fs::symlink_metadata(&att_path) {
        Ok(m) if m.is_file() => m,
        _ => {
            fail(
                &mut rep,
                ViolationKind::AttestationMissing,
                None,
                "the release index (ogentic-audit-release.json) is missing".into(),
            );
            return Ok(rep);
        },
    };
    if meta.len() > MAX_ATTESTATION {
        fail(
            &mut rep,
            ViolationKind::AttestationMalformed,
            Some("limit"),
            "the release index is larger than 64 MiB".into(),
        );
        return Ok(rep);
    }
    let bytes = std::fs::read(&att_path)?;
    let att_sha = sha256(&bytes);
    rep.attestation_sha256 = Some(att_sha);
    // A2.
    let sig_path = dir.join(ATTESTATION_SIG_FILE);
    let sig_bytes = match std::fs::symlink_metadata(&sig_path) {
        Ok(m) if m.is_file() && m.len() <= sshsig::MAX_SIG_FILE as u64 => std::fs::read(&sig_path)?,
        Ok(m) if m.is_file() => {
            fail(
                &mut rep,
                ViolationKind::SignatureInvalid,
                Some("malformed"),
                "the signature file is larger than 64 KiB".into(),
            );
            return Ok(rep);
        },
        _ => {
            fail(
                &mut rep,
                ViolationKind::SignatureInvalid,
                Some("missing"),
                "the signature file (ogentic-audit-release.json.sig) is missing".into(),
            );
            return Ok(rep);
        },
    };
    let sig = match sshsig::parse_armored(&sig_bytes, NS_RELEASE) {
        Ok(s) => s,
        Err(e) => {
            fail(
                &mut rep,
                ViolationKind::SignatureInvalid,
                Some(e.reason()),
                e.to_string(),
            );
            return Ok(rep);
        },
    };
    let signer_fp = sig.key.fingerprint();
    // A3.
    let entries = eval.entries(&signer_fp);
    let release_entry = entries.iter().find(|e| e.scope.contains(NS_RELEASE));
    rep.signer = Some(SignerInfo {
        principal: release_entry
            .filter(|e| !e.auto_principal)
            .map(|e| e.principal.clone()),
        alg: sig.key.alg(),
        key_id: signer_fp,
        trusted: release_entry.is_some(),
        trust_path: release_entry
            .map(|e| e.trust_path.clone())
            .unwrap_or_default(),
        reason: match release_entry {
            Some(e) if e.pinned => SignerReason::Pinned,
            Some(_) => SignerReason::Transition,
            None if eval.has_pins() => SignerReason::NotTrusted,
            None => SignerReason::NotPinned,
        },
    });
    if eval.has_pins() {
        if let Err(rej) = eval.accept(
            &signer_fp,
            NS_RELEASE,
            &Object::Release { sha256: &att_sha },
        ) {
            let (kind, reason, msg) = match rej {
                Reject::NotTrusted => (
                    ViolationKind::UntrustedSigner,
                    Some("not_trusted"),
                    format!("the release is signed by {}, which is not the key you supplied", signer_fp.to_grouped_hex()),
                ),
                Reject::OutOfScope => (
                    ViolationKind::UntrustedSigner,
                    Some("out_of_scope"),
                    "the key you supplied is not trusted to sign releases".into(),
                ),
                Reject::Retired { .. } => (
                    ViolationKind::RetiredKey,
                    None,
                    "signed by a retired key, and this release is not among those it vouched for when retired".into(),
                ),
                Reject::Revoked { .. } | Reject::HeadMismatch { .. } => (
                    ViolationKind::RevokedKey,
                    None,
                    "signed by a revoked key, and this release is not among those its revocation still vouches for".into(),
                ),
            };
            fail(&mut rep, kind, reason, msg);
            return Ok(rep);
        }
    }
    // A4.
    let data = sshsig::signed_data(NS_RELEASE, &bytes);
    if let Err(f) = ed25519::verify(sig.key.as_bytes(), &data, &sig.signature) {
        fail(
            &mut rep,
            ViolationKind::SignatureInvalid,
            Some(f.reason()),
            describe(ViolationKind::SignatureInvalid, Some(f.reason())).into(),
        );
        return Ok(rep);
    }
    // A5.
    let att = match parse_attestation(&bytes, &sig.key) {
        Ok(a) => a,
        Err((kind, m)) => {
            fail(&mut rep, kind, None, m);
            return Ok(rep);
        },
    };
    rep.release_id = Some(att.release_id.clone());
    // A6.
    if let Some(expect) = &opts.expect_release_id {
        if *expect != att.release_id {
            fail(
                &mut rep,
                ViolationKind::ReleaseIdMismatch,
                None,
                format!(
                    "this is release {:?}, not {:?}",
                    escape(&att.release_id),
                    escape(expect)
                ),
            );
            return Ok(rep);
        }
    }

    // Name lookup.
    let entries = enumerate(dir)?;
    let mut by_nfc: HashMap<String, Vec<&Entry>> = HashMap::new();
    let mut by_fold: HashMap<UniCase<String>, BTreeSet<String>> = HashMap::new();
    for e in &entries {
        let n = names::nfc(&e.rel);
        by_fold
            .entry(UniCase::unicode(n.clone()))
            .or_default()
            .insert(e.rel.clone());
        by_nfc.entry(n).or_default().push(e);
    }
    let ambiguous = |nfc: &str| -> bool {
        by_nfc.get(nfc).is_some_and(|v| v.len() > 1)
            || by_fold
                .get(&UniCase::unicode(nfc.to_string()))
                .is_some_and(|s| s.len() > 1)
    };

    // F1–F3.
    rep.files_attested = att.files.len() as u64;
    let mut covered: BTreeSet<String> = BTreeSet::new();
    for (spec, size, sha, part_hashes) in &att.files {
        covered.insert(spec.path.clone());
        let item = ReleaseItem::File {
            path: spec.path.clone(),
            part: None,
        };
        let push = |rep: &mut ReleaseReport,
                    item: ReleaseItem,
                    kind,
                    reason: &str,
                    ev: Value,
                    msg: String| {
            rep.violations.push(ReleaseFinding {
                item,
                kind,
                reason: Some(reason.to_string()),
                evidence: ev,
                message: msg,
            });
        };
        let Some(found) = by_nfc.get(&spec.path) else {
            rep.violations.push(ReleaseFinding {
                item,
                kind: ViolationKind::FileMissing,
                reason: None,
                evidence: Value::object([]),
                message: "missing".into(),
            });
            continue;
        };
        if ambiguous(&spec.path) {
            push(
                &mut rep,
                item,
                ViolationKind::FileAltered,
                "ambiguous_name",
                Value::object([]),
                "more than one file has this name (after Unicode normalization or case folding)"
                    .into(),
            );
            continue;
        }
        let e = found[0];
        if !e.regular {
            push(
                &mut rep,
                item,
                ViolationKind::FileAltered,
                "not_regular_file",
                Value::object([]),
                "not a regular file (a link or special file)".into(),
            );
            continue;
        }
        let (asize, asha, aparts) = hash_file(&mut File::open(dir.join(&e.rel))?, &spec.parts)?;
        let mut ev = vec![
            ("expected_sha256", Value::str(hex(sha))),
            ("actual_sha256", Value::str(hex(&asha))),
            ("expected_size", Value::Int(*size)),
            ("actual_size", Value::Int(asize)),
        ];
        if asize == *size && asha == *sha {
            rep.files_verified += 1;
            continue;
        }
        if asize != *size {
            ev.push(("part", Value::Null));
            push(
                &mut rep,
                item,
                ViolationKind::FileAltered,
                "size",
                Value::object(ev),
                format!(
                    "the size changed ({} bytes, signed {} bytes)",
                    thousands(asize),
                    thousands(*size)
                ),
            );
            continue;
        }
        match spec
            .parts
            .iter()
            .zip(part_hashes)
            .zip(&aparts)
            .find(|((_, e), a)| e != a)
        {
            Some(((p, _), _)) => {
                ev.push((
                    "part",
                    Value::object([
                        ("name", Value::str(&p.name)),
                        ("offset", Value::Int(p.offset)),
                        ("length", Value::Int(p.length)),
                    ]),
                ));
                push(
                    &mut rep,
                    ReleaseItem::File {
                        path: spec.path.clone(),
                        part: Some(p.name.clone()),
                    },
                    ViolationKind::FileAltered,
                    "part",
                    Value::object(ev),
                    format!(
                        "item {:?} (bytes {}–{}) changed",
                        escape(&p.name),
                        p.offset + 1,
                        p.offset + p.length
                    ),
                );
            },
            None if !spec.parts.is_empty() => {
                ev.push(("part", Value::Null));
                push(
                    &mut rep,
                    item,
                    ViolationKind::FileAltered,
                    "outside_parts",
                    Value::object(ev),
                    "changed outside any named item (for example, data added at the end)".into(),
                );
            },
            None => {
                ev.push(("part", Value::Null));
                push(
                    &mut rep,
                    item,
                    ViolationKind::FileAltered,
                    "content",
                    Value::object(ev),
                    "the content changed".into(),
                );
            },
        }
    }

    // L1–L4.
    let mut all_logs_trusted = true;
    for (path, cp) in &att.logs {
        let log_dir = dir.join(path);
        let li = |s: Option<u16>, r: Option<u64>| ReleaseItem::Log {
            path: path.clone(),
            segment: s,
            record: r,
        };
        if !log_dir.is_dir()
            || std::fs::symlink_metadata(&log_dir).is_ok_and(|m| m.file_type().is_symlink())
        {
            rep.violations.push(ReleaseFinding {
                item: li(None, None),
                kind: ViolationKind::FileMissing,
                reason: None,
                evidence: Value::object([]),
                message: "the audit log folder is missing".into(),
            });
            rep.logs.push(ReleaseLog {
                path: path.clone(),
                report: None,
            });
            all_logs_trusted = false;
            continue;
        }
        let opts = SignedVerifyOptions {
            forensic_mode: true,
            attested: Some(cp.clone()),
            ..SignedVerifyOptions::default()
        };
        match verify_log(&log_dir, &eval, &opts) {
            Ok(r) => {
                for v in &r.violations {
                    let (s, rec) = match &v.location {
                        super::report::Location::Segment { segment } => (Some(*segment), None),
                        super::report::Location::Record {
                            segment, record, ..
                        } => (Some(*segment), Some(*record)),
                        _ => (None, None),
                    };
                    let item = match &v.location {
                        super::report::Location::Key { key_id } => {
                            ReleaseItem::Key { key_id: *key_id }
                        },
                        _ => li(s, rec),
                    };
                    rep.violations.push(ReleaseFinding {
                        item,
                        kind: v.kind,
                        reason: v.reason.clone(),
                        evidence: v.evidence.clone(),
                        message: v.message.clone(),
                    });
                }
                for w in &r.warnings {
                    rep.warnings.push(Warning {
                        kind: w.kind.clone(),
                        item: format!("log:{path}/{}", w.item),
                        message: w.message.clone(),
                    });
                }
                if r.verdict != Verdict::Verified {
                    all_logs_trusted = false;
                }
                rep.logs.push(ReleaseLog {
                    path: path.clone(),
                    report: Some(r),
                });
            },
            Err(SignedVerifyError::HmacLog) => {
                rep.violations.push(ReleaseFinding {
                    item: li(Some(0), None),
                    kind: ViolationKind::FormatDowngrade,
                    reason: None,
                    evidence: Value::object([
                        ("expected_version", Value::Int(2)),
                        ("actual_version", Value::Int(1)),
                    ]),
                    message: "the attestation names a signed log, but this log is protected only by a shared secret key (format 0x0001)".into(),
                });
                rep.logs.push(ReleaseLog {
                    path: path.clone(),
                    report: None,
                });
                all_logs_trusted = false;
            },
            Err(SignedVerifyError::NoSegments(_)) => {
                rep.violations.push(ReleaseFinding {
                    item: li(None, None),
                    kind: ViolationKind::FileMissing,
                    reason: None,
                    evidence: Value::object([]),
                    message: "the audit log has no segment files".into(),
                });
                rep.logs.push(ReleaseLog {
                    path: path.clone(),
                    report: None,
                });
                all_logs_trusted = false;
            },
            Err(SignedVerifyError::Io(m)) => return Err(ReleaseError::Io(m)),
            Err(e) => return Err(ReleaseError::Invalid(e.to_string())),
        }
    }

    // U1.
    let log_dirs: BTreeSet<&str> = att.logs.iter().map(|(p, _)| p.as_str()).collect();
    for e in &entries {
        let n = names::nfc(&e.rel);
        if covered.contains(&n) || names::is_reserved(&n) || is_segment_of(&n, &log_dirs) {
            continue;
        }
        if names::is_os_litter(&n) {
            rep.ignored.push(e.rel.clone());
            continue;
        }
        rep.unattested.push(e.rel.clone());
        if opts.allow_unattested {
            rep.warnings.push(Warning {
                kind: "UnattestedFile".into(),
                item: format!("file:{}", e.rel),
                message: "not covered by the signature (allowed with --allow-unattested)".into(),
            });
        } else {
            rep.violations.push(ReleaseFinding {
                item: ReleaseItem::File {
                    path: e.rel.clone(),
                    part: None,
                },
                kind: ViolationKind::UnattestedFile,
                reason: None,
                evidence: Value::object([]),
                message: "not covered by the signature".into(),
            });
        }
    }

    // Witness co-signatures (informational).
    let mut witness_files: Vec<PathBuf> = opts.witnesses.clone();
    if let Ok(rd) = std::fs::read_dir(dir.join(WITNESS_DIR)) {
        let mut found: Vec<PathBuf> = rd
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "json"))
            .collect();
        found.sort();
        witness_files.extend(found);
    }
    for wf in witness_files {
        let shown = wf.display().to_string();
        let res = (|| -> Result<(String, WitnessCosignature), String> {
            let b = std::fs::read(&wf).map_err(|e| e.to_string())?;
            let w = WitnessCosignature::parse(&b)?;
            let mut s = wf.as_os_str().to_os_string();
            s.push(".sig");
            let sig = std::fs::read(PathBuf::from(s)).map_err(|e| format!("signature: {e}"))?;
            verify_detached_by(&sig, NS_WITNESS, &b, &w.witness_key_id)?;
            let principal = eval
                .accept(&w.witness_key_id, NS_WITNESS, &Object::Witness)
                .map(|e| e.principal.clone())
                .map_err(|_| "the witness key is not trusted as a witness".to_string())?;
            Ok((principal, w))
        })();
        match res {
            Ok(w) => rep.witnesses.push(w),
            Err(m) => rep.warnings.push(Warning {
                kind: "IgnoredWitness".into(),
                item: shown,
                message: m,
            }),
        }
    }

    rep.verdict = if !rep.violations.is_empty() {
        Verdict::Violation
    } else if eval.has_pins() && all_logs_trusted {
        Verdict::Verified
    } else {
        rep.not_verified_reason = Some(NotVerifiedReason::NotPinned);
        Verdict::SelfConsistent
    };
    Ok(rep)
}

impl ReleaseReport {
    /// `Verified`, `SelfConsistent`, or `Kind@item` of the first violation.
    #[must_use]
    pub fn compact_verdict(&self) -> String {
        match self.verdict {
            Verdict::Verified => "Verified".into(),
            Verdict::SelfConsistent => "SelfConsistent".into(),
            _ => self
                .violations
                .first()
                .map_or_else(|| "Violation".into(), ReleaseFinding::compact),
        }
    }

    /// The JSON report (`ogentic-audit-release-report/v1`, spec §11.6).
    #[must_use]
    pub fn to_json(&self) -> Value {
        Value::object([
            ("format", Value::str("ogentic-audit-release-report/v1")),
            (
                "verdict",
                Value::str(super::report::verdict_str(self.verdict)),
            ),
            (
                "status",
                Value::str(match self.verdict {
                    Verdict::Verified => "ok",
                    Verdict::SelfConsistent => "unpinned",
                    _ => "tampered",
                }),
            ),
            (
                "reason",
                self.not_verified_reason.map(|r| r.as_str()).into(),
            ),
            ("release_id", self.release_id.as_deref().map(escape).into()),
            (
                "attestation_sha256",
                self.attestation_sha256.map(|h| hex(&h)).into(),
            ),
            (
                "signer",
                self.signer
                    .as_ref()
                    .map_or(Value::Null, SignerInfo::to_json),
            ),
            (
                "files",
                Value::object([
                    ("attested", Value::Int(self.files_attested)),
                    ("verified", Value::Int(self.files_verified)),
                    (
                        "unattested",
                        Value::Array(
                            self.unattested
                                .iter()
                                .map(|p| Value::str(escape(p)))
                                .collect(),
                        ),
                    ),
                    (
                        "ignored",
                        Value::Array(self.ignored.iter().map(|p| Value::str(escape(p))).collect()),
                    ),
                ]),
            ),
            (
                "logs",
                Value::Array(
                    self.logs
                        .iter()
                        .map(|l| {
                            let mut m: BTreeMap<String, Value> = BTreeMap::new();
                            m.insert("path".into(), Value::str(escape(&l.path)));
                            if let Some(r) = &l.report {
                                m.insert("report".into(), r.to_json());
                                m.insert("head_anchored".into(), Value::Bool(r.log.head_anchored));
                                m.insert(
                                    "records_after_head".into(),
                                    Value::Int(r.log.records_after_head),
                                );
                                m.insert(
                                    "elided_records".into(),
                                    Value::Int(r.log.elided_records.len() as u64),
                                );
                            }
                            Value::Object(m)
                        })
                        .collect(),
                ),
            ),
            (
                "violations",
                Value::Array(
                    self.violations
                        .iter()
                        .map(ReleaseFinding::to_json)
                        .collect(),
                ),
            ),
            (
                "warnings",
                Value::Array(
                    self.warnings
                        .iter()
                        .map(|w| {
                            Value::object([
                                ("item", Value::str(escape(&w.item))),
                                ("kind", Value::str(&w.kind)),
                                ("message", Value::str(escape(&w.message))),
                            ])
                        })
                        .collect(),
                ),
            ),
            (
                "witnesses",
                Value::Array(
                    self.witnesses
                        .iter()
                        .map(|(p, w)| {
                            Value::object([
                                ("principal", Value::str(escape(p))),
                                ("key_id_hex", Value::str(w.witness_key_id.to_hex())),
                                ("observed_at", Value::str(escape(&w.observed_at))),
                                ("checkpoint_sha256", Value::str(hex(&w.checkpoint_sha256))),
                            ])
                        })
                        .collect(),
                ),
            ),
        ])
    }

    /// The human report (spec §11.6).
    #[must_use]
    pub fn render_human(&self, ascii: bool, program: &str) -> String {
        let marks = Marks::new(ascii);
        let mut out = String::new();
        let rid = self.release_id.as_deref().map(escape).unwrap_or_default();
        let dir = escape(&self.release_dir.to_string_lossy());
        let (segs, recs, elided): (u32, u64, usize) = self
            .logs
            .iter()
            .filter_map(|l| l.report.as_ref())
            .fold((0, 0, 0), |a, r| {
                (
                    a.0 + r.log.segments_inspected,
                    a.1 + r.log.records_inspected,
                    a.2 + r.log.elided_records.len(),
                )
            });
        let summary = format!(
            "{} file{}, {} audit log{}{}",
            thousands(self.files_attested),
            if self.files_attested == 1 { "" } else { "s" },
            self.logs.len(),
            if self.logs.len() == 1 { "" } else { "s" },
            if self.logs.is_empty() {
                String::new()
            } else {
                format!(
                    " ({segs} segment{}, {} records{})",
                    if segs == 1 { "" } else { "s" },
                    thousands(recs),
                    if elided > 0 {
                        format!(", {} with withheld content", thousands(elided as u64))
                    } else {
                        String::new()
                    }
                )
            }
        );
        match self.verdict {
            Verdict::Verified => {
                out.push_str(&format!(
                    "{} Verified: release \"{rid}\", {summary}\n",
                    marks.ok
                ));
                if let Some(s) = &self.signer {
                    signer_lines(s, &mut out);
                }
                out.push_str(&format!(
                    "  {} file{} not covered by the signature.\n",
                    self.unattested.len(),
                    if self.unattested.len() == 1 { "" } else { "s" }
                ));
            },
            Verdict::SelfConsistent => {
                out.push_str(&format!(
                    "{} Not verified: you did not supply the signer's key.\n",
                    marks.warn
                ));
                out.push_str("  The files match the signature, but without the signer's key anyone could have made that signature.\n");
                if let Some(s) = &self.signer {
                    out.push_str("  This release says it was signed by\n");
                    out.push_str(&format!("    {}\n", s.key_id.to_grouped_hex()));
                }
                out.push_str("  Do not take that number from the release itself. Get the signer's fingerprint from the signer\n");
                out.push_str("  directly (their website, a letter, a phone call), then run:\n");
                out.push_str(&format!(
                    "    {program} verify-release {dir} --key-fingerprint \"<the fingerprint you were given>\"\n"
                ));
            },
            _ => {
                let n = self.violations.len();
                out.push_str(&format!(
                    "{} Verification failed: {n} problem{}\n",
                    marks.fail,
                    if n == 1 { "" } else { "s" }
                ));
                let mut groups: BTreeMap<u8, (&str, Vec<String>)> = BTreeMap::new();
                for v in &self.violations {
                    let (g, title) = match v.kind {
                        ViolationKind::UnattestedFile => (4, "Not covered by the signature"),
                        ViolationKind::FileMissing => (2, "Missing"),
                        ViolationKind::FileAltered => (1, "Altered"),
                        _ => match &v.item {
                            ReleaseItem::Log { .. } | ReleaseItem::Key { .. } => (3, "Audit log"),
                            _ => (0, "Signature and index"),
                        },
                    };
                    let line = match (&v.item, v.kind) {
                        (
                            ReleaseItem::File {
                                path,
                                part: Some(p),
                            },
                            _,
                        ) => {
                            let range = v
                                .evidence
                                .get("part")
                                .and_then(|pp| {
                                    Some((pp.get("offset")?.as_u64()?, pp.get("length")?.as_u64()?))
                                })
                                .map(|(o, l)| format!(" (bytes {}–{})", o + 1, o + l))
                                .unwrap_or_default();
                            format!("\"{}\", item \"{}\"{range}", escape(path), escape(p))
                        },
                        (ReleaseItem::File { path, part: None }, ViolationKind::FileAltered) => {
                            let what = match v.reason.as_deref() {
                                Some("size") => "the size changed".to_string(),
                                Some("outside_parts") => "changed outside any named item (for example, data added at the end)".into(),
                                Some("not_regular_file") => "not a regular file (a link or special file)".into(),
                                Some("ambiguous_name") => "more than one file has this name".into(),
                                _ => "the content changed".into(),
                            };
                            format!("\"{}\": {what}", escape(path))
                        },
                        (ReleaseItem::File { path, .. }, _) => format!("\"{}\"", escape(path)),
                        (ReleaseItem::Attestation, k) => format!(
                            "the release index: {} ({})",
                            describe(k, v.reason.as_deref()),
                            k.as_str()
                        ),
                        (item, k) => format!(
                            "{}: {} ({})",
                            escape(&item.compact()),
                            describe(k, v.reason.as_deref()),
                            k.as_str()
                        ),
                    };
                    groups.entry(g).or_insert((title, Vec::new())).1.push(line);
                }
                for (_, (title, lines)) in groups {
                    out.push_str(&format!("  {title}\n"));
                    for l in lines {
                        out.push_str(&format!("    {l}\n"));
                    }
                }
            },
        }
        if !self.witnesses.is_empty() {
            out.push_str("  Witnesses\n");
            for (p, w) in &self.witnesses {
                out.push_str(&format!(
                    "    {} at {} (the witness's clock)\n",
                    escape(p),
                    escape(&w.observed_at)
                ));
            }
        }
        if !self.ignored.is_empty() {
            out.push_str("  Ignored (operating-system files)\n");
            for i in &self.ignored {
                out.push_str(&format!("    \"{}\"\n", escape(i)));
            }
        }
        if !self.warnings.is_empty() {
            out.push_str("  Warnings\n");
            for w in &self.warnings {
                out.push_str(&format!(
                    "    {} {}: {}\n",
                    marks.warn,
                    escape(&w.item),
                    escape(&w.message)
                ));
            }
        }
        out
    }
}

fn signer_lines(s: &SignerInfo, out: &mut String) {
    let who = match &s.principal {
        Some(p) => format!("Signed by {}, ", escape(p)),
        None => "Signed by ".to_string(),
    };
    match s.reason {
        SignerReason::Transition => out.push_str(&format!(
            "  {who}reached from the key you supplied through key transitions:\n"
        )),
        _ => out.push_str(&format!("  {who}the key you supplied:\n")),
    }
    out.push_str(&format!("    {}\n", s.key_id.to_grouped_hex()));
}
