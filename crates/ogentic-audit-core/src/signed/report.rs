//! Signed-log reports (spec v0.2 §8.5, §14): types, JSON, and the human
//! output that the CLI and `python -m ogentic_audit` both print.

use std::path::PathBuf;

use super::json::Value;
use super::keys::{Fingerprint, SigAlg};
use super::names::escape;
use super::{hex, FORMAT_VERSION_SIGNED};
use crate::verifier::{Verdict, ViolationKind};

/// Why a clean log is only `SelfConsistent`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NotVerifiedReason {
    /// No key was supplied.
    NotPinned,
    /// The log has no records to check a key against.
    NoSignedRecords,
}

impl NotVerifiedReason {
    /// The JSON `reason` string.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            NotVerifiedReason::NotPinned => "not_pinned",
            NotVerifiedReason::NoSignedRecords => "no_signed_records",
        }
    }
}

/// Where in a log a finding is.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Location {
    /// A segment (its header, or the segment as a whole).
    Segment {
        /// Segment index.
        segment: u16,
    },
    /// A record.
    Record {
        /// Segment index.
        segment: u16,
        /// Position in the segment.
        record: u64,
        /// 1-based record number across the log, for people.
        ordinal: u64,
        /// Offset of the record's `len_prefix` in its segment file.
        byte_offset: u64,
    },
    /// A key (for example `TransitionEquivocation`).
    Key {
        /// The key.
        key_id: Fingerprint,
    },
}

impl Location {
    /// `s0`, `s0r2`, or `key:<hex>`.
    #[must_use]
    pub fn compact(&self) -> String {
        match self {
            Location::Segment { segment } => format!("s{segment}"),
            Location::Record {
                segment, record, ..
            } => format!("s{segment}r{record}"),
            Location::Key { key_id } => format!("key:{}", key_id.to_hex()),
        }
    }

    /// The segment, if the finding is inside one.
    #[must_use]
    pub fn segment(&self) -> Option<u16> {
        match self {
            Location::Segment { segment } | Location::Record { segment, .. } => Some(*segment),
            Location::Key { .. } => None,
        }
    }

    fn human(&self) -> String {
        match self {
            Location::Segment { segment } => format!("segment {segment} (s{segment})"),
            Location::Record {
                segment,
                record,
                ordinal,
                ..
            } => format!("record {} (s{segment}r{record})", thousands(*ordinal)),
            Location::Key { key_id } => format!("key {}", key_id.to_grouped_hex()),
        }
    }

    fn to_json(&self) -> Value {
        match self {
            Location::Segment { segment } => Value::object([
                ("segment_index", Value::Int(u64::from(*segment))),
                ("record_id", Value::Null),
                ("item", Value::str(self.compact())),
            ]),
            Location::Record {
                segment,
                record,
                byte_offset,
                ..
            } => Value::object([
                ("segment_index", Value::Int(u64::from(*segment))),
                ("record_id", Value::Int(*record)),
                ("byte_offset", Value::Int(*byte_offset)),
                ("item", Value::str(self.compact())),
            ]),
            Location::Key { key_id } => Value::object([
                ("key_id_hex", Value::str(key_id.to_hex())),
                ("item", Value::str(self.compact())),
            ]),
        }
    }
}

/// One violation in a signed log.
#[derive(Debug, Clone)]
pub struct Finding {
    /// The kind.
    pub kind: ViolationKind,
    /// Kind-specific reason or sub-kind (`body_mismatch`, `TornTail`, …).
    pub reason: Option<String>,
    /// Where.
    pub location: Location,
    /// Evidence, a JSON object.
    pub evidence: Value,
    /// Short human-readable summary. Tooling must not parse it.
    pub message: String,
}

impl Finding {
    /// `Kind@location`.
    #[must_use]
    pub fn compact(&self) -> String {
        format!("{}@{}", self.kind.as_str(), self.location.compact())
    }

    /// The JSON object.
    #[must_use]
    pub fn to_json(&self) -> Value {
        Value::object([
            ("kind", Value::str(self.kind.as_str())),
            ("reason", self.reason.clone().into()),
            ("location", self.location.to_json()),
            ("evidence", self.evidence.clone()),
            ("message", Value::str(&self.message)),
        ])
    }

    /// Whether the kind concerns the whole log, so `--segment` never
    /// filters it out (spec §13.4).
    #[must_use]
    pub fn is_log_level(&self) -> bool {
        matches!(
            self.kind,
            ViolationKind::UntrustedSigner
                | ViolationKind::FormatDowngrade
                | ViolationKind::UnsupportedAlgorithm
                | ViolationKind::RevokedKey
                | ViolationKind::RetiredKey
                | ViolationKind::LogIdMismatch
                | ViolationKind::TransitionEquivocation
                | ViolationKind::CheckpointForDifferentLog
        )
    }
}

/// A warning: not a failure, but something the reader should know.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Warning {
    /// `UnsignedLastSegment`, `RolledOverWithoutSuccessor`,
    /// `NearMissSegmentName`, `TornTailAfterHead`, `IgnoredStatement`, …
    pub kind: String,
    /// The item (`s3`, a file name, a statement path).
    pub item: String,
    /// What it means.
    pub message: String,
}

impl Warning {
    fn to_json(&self) -> Value {
        Value::object([
            ("kind", Value::str(&self.kind)),
            ("item", Value::str(&self.item)),
            ("message", Value::str(&self.message)),
        ])
    }
}

/// How the signer came to be trusted, or not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SignerReason {
    /// The key itself was supplied.
    Pinned,
    /// Reached from a supplied key through key transitions.
    Transition,
    /// No key was supplied.
    NotPinned,
    /// Nothing was signed.
    NoSignedRecords,
    /// A key was supplied, but this signer is not it.
    NotTrusted,
}

impl SignerReason {
    /// The JSON `reason` string.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            SignerReason::Pinned => "pinned",
            SignerReason::Transition => "transition",
            SignerReason::NotPinned => "not_pinned",
            SignerReason::NoSignedRecords => "no_signed_records",
            SignerReason::NotTrusted => "not_trusted",
        }
    }
}

/// Who signed, and whether the verifier trusts them.
#[derive(Debug, Clone)]
pub struct SignerInfo {
    /// Principal name from the trust input; `None` when the key was given
    /// without a name or is not trusted.
    pub principal: Option<String>,
    /// Algorithm.
    pub alg: SigAlg,
    /// Fingerprint.
    pub key_id: Fingerprint,
    /// Whether the signer is trusted for what it signed.
    pub trusted: bool,
    /// Pinned key first, then each successor.
    pub trust_path: Vec<Fingerprint>,
    /// How.
    pub reason: SignerReason,
}

impl SignerInfo {
    /// The JSON object of spec §14.
    #[must_use]
    pub fn to_json(&self) -> Value {
        Value::object([
            ("principal", self.principal.clone().into()),
            ("alg", Value::str(self.alg.json_name())),
            ("key_id_hex", Value::str(self.key_id.to_hex())),
            (
                "fingerprint_grouped",
                Value::str(self.key_id.to_grouped_hex()),
            ),
            ("fingerprint_openssh", Value::str(self.key_id.to_openssh())),
            ("trusted", Value::Bool(self.trusted)),
            (
                "trust_path",
                Value::Array(
                    self.trust_path
                        .iter()
                        .map(|f| Value::str(f.to_hex()))
                        .collect(),
                ),
            ),
            ("reason", Value::str(self.reason.as_str())),
        ])
    }

    fn human_lines(&self, out: &mut String) {
        match (&self.principal, self.reason) {
            (Some(p), SignerReason::Transition) => out.push_str(&format!(
                "  Signed by {}, reached from the key you supplied through {} key transition(s):\n",
                escape(p),
                self.trust_path.len().saturating_sub(1)
            )),
            (Some(p), _) => out.push_str(&format!(
                "  Signed by {}, the key you supplied:\n",
                escape(p)
            )),
            (None, SignerReason::Transition) => out.push_str(
                "  Signed by a key reached from the key you supplied through key transitions:\n",
            ),
            (None, _) => out.push_str("  Signed by the key you supplied:\n"),
        }
        out.push_str(&format!("    {}\n", self.key_id.to_grouped_hex()));
        if self.trust_path.len() > 1 {
            out.push_str("  Trust path (the key you supplied first):\n");
            for k in &self.trust_path {
                out.push_str(&format!("    {}\n", k.to_grouped_hex()));
            }
        }
    }
}

/// A witness listed in a report.
#[derive(Debug, Clone)]
pub struct WitnessInfo {
    /// Principal of the witness key.
    pub principal: String,
    /// The witness key.
    pub key_id: Fingerprint,
    /// The witness's clock.
    pub observed_at: String,
}

/// A checkpoint the verifier checked the log against.
#[derive(Debug, Clone)]
pub struct CheckpointInfo {
    /// Whether it carried a valid signature by the log's signer.
    pub signed: bool,
    /// The checkpoint's `key_id`.
    pub signer_key_id: Fingerprint,
    /// Position it names (`s0r4`).
    pub position: String,
    /// When it was made (its maker's clock).
    pub observed_at: Option<String>,
    /// Witness co-signatures.
    pub witnesses: Vec<WitnessInfo>,
    /// Whether it names the last record.
    pub anchors_head: bool,
}

impl CheckpointInfo {
    fn to_json(&self) -> Value {
        Value::object([
            ("signed", Value::Bool(self.signed)),
            ("signer_key_id_hex", Value::str(self.signer_key_id.to_hex())),
            ("position", Value::str(&self.position)),
            ("observed_at", self.observed_at.clone().into()),
            (
                "witnesses",
                Value::Array(
                    self.witnesses
                        .iter()
                        .map(|w| {
                            Value::object([
                                ("principal", Value::str(&w.principal)),
                                ("key_id_hex", Value::str(w.key_id.to_hex())),
                                ("observed_at", Value::str(&w.observed_at)),
                            ])
                        })
                        .collect(),
                ),
            ),
            ("anchors_head", Value::Bool(self.anchors_head)),
        ])
    }
}

/// Summary of the log walked.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct SignedLogSummary {
    /// Log directory.
    pub log_dir: PathBuf,
    /// The log's random id, once read from segment 0.
    pub log_id: Option<[u8; 16]>,
    /// Header `key_id` of segment 0.
    pub key_id: Option<Fingerprint>,
    /// Segments opened (a header-only last segment is not counted).
    pub segments_inspected: u32,
    /// Records walked, including a failing one.
    pub records_inspected: u64,
    /// Smallest segment index present.
    pub first_segment_index: Option<u16>,
    /// Largest segment index reached.
    pub last_segment_index: Option<u16>,
    /// `record_hash` of the last record walked.
    pub final_record_hash: Option<[u8; 32]>,
    /// Position of the last record walked.
    pub head: Option<(u16, u64)>,
    /// Whether the last record is known to be the end (spec §8.5).
    pub head_anchored: bool,
    /// Whether the log ends in `log.sealed`.
    pub sealed: bool,
    /// Positions of records carried without their bodies.
    pub elided_records: Vec<(u16, u64)>,
    /// Whether a header-only last segment was found (unsigned; ignored).
    pub unsigned_last_segment: bool,
    /// In a release: records after the attested head.
    pub records_after_head: u64,
    /// `ts_wall` of the last record walked (the signer's clock).
    pub head_ts_wall: Option<String>,
}

/// The result of verifying a signed log.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SignedVerifyReport {
    /// Always `0x0002`.
    pub format_version: u16,
    /// `Verified`, `SelfConsistent`, or `Violation`.
    pub verdict: Verdict,
    /// Why `SelfConsistent`, when it is.
    pub not_verified_reason: Option<NotVerifiedReason>,
    /// Summary of what was walked.
    pub log: SignedLogSummary,
    /// The signer, once segment 0's header was read.
    pub signer: Option<SignerInfo>,
    /// Checkpoints checked.
    pub checkpoints: Vec<CheckpointInfo>,
    /// Every violation, first one first.
    pub violations: Vec<Finding>,
    /// Warnings.
    pub warnings: Vec<Warning>,
}

pub(crate) fn thousands(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// Status marks, with an ASCII fallback for consoles that are not UTF-8.
#[derive(Debug, Clone, Copy)]
pub struct Marks {
    /// Verified.
    pub ok: &'static str,
    /// Failed.
    pub fail: &'static str,
    /// Not verified.
    pub warn: &'static str,
}

impl Marks {
    /// `✓ ✗ !`, or `[OK] [FAILED] [!]` when `ascii`.
    #[must_use]
    pub fn new(ascii: bool) -> Self {
        if ascii {
            Self {
                ok: "[OK]",
                fail: "[FAILED]",
                warn: "[!]",
            }
        } else {
            Self {
                ok: "✓",
                fail: "✗",
                warn: "!",
            }
        }
    }
}

/// What a violation means, in a sentence a non-specialist can read.
#[must_use]
pub fn describe(kind: ViolationKind, reason: Option<&str>) -> &'static str {
    use ViolationKind as K;
    match (kind, reason) {
        (K::SignatureInvalid, Some("body_mismatch")) => {
            "the record's content was changed after it was signed"
        },
        (K::SignatureInvalid, Some("reencoded")) => {
            "a valid signature, re-encoded after signing: the signed content is unchanged, but someone changed the signature bytes afterwards"
        },
        (K::SignatureInvalid, Some("weak_key")) => {
            "the signing key is one under which anyone can make signatures"
        },
        (K::SignatureInvalid, Some("missing")) => "the signature file is missing",
        (K::SignatureInvalid, Some("malformed" | "hash_alg" | "key_type")) => {
            "the signature file is malformed or uses an encoding this format does not allow"
        },
        (K::SignatureInvalid, Some("namespace")) => {
            "the signature was made for a different purpose"
        },
        (K::SignatureInvalid, _) => "the signature does not match the signed content",
        (K::ChainBreak, _) => {
            "a genuine record in the wrong place: a record before it was removed, or records were reordered or spliced in"
        },
        (K::RecordCorrupt, Some("TornTail")) => {
            "the log ends part-way through a record (an interrupted write, or a cut)"
        },
        (K::RecordCorrupt, Some("TooLarge")) => "a record declares a length larger than allowed",
        (K::RecordCorrupt, Some("ElidedStructural")) => {
            "a structural record's content was removed, which is never allowed"
        },
        (K::RecordCorrupt, Some("BadRollover")) => {
            "a segment-end record does not match the segment it ends"
        },
        (K::RecordCorrupt, _) => "a record is not well-formed",
        (K::SegmentDiscontinuity, _) => "a segment is missing, empty, or out of sequence",
        (K::KeyIdMismatch, _) => "a key identifier does not match the key",
        (K::HeaderCorrupt, _) => "a segment header is damaged",
        (K::UnknownVersion, _) => "a segment uses an unknown format version",
        (K::UntrustedSigner, Some("out_of_scope")) => {
            "signed by a key you supplied, but that key is not trusted to sign this kind of object"
        },
        (K::UntrustedSigner, _) => "signed by a key other than the one you supplied",
        (K::RevokedKey, _) => "signed by a revoked key, outside what its revocation still vouches for",
        (K::RetiredKey, _) => {
            "signed by a retired key after it was replaced, outside what it vouched for when retired"
        },
        (K::TransitionEquivocation, _) => {
            "this key signed two different successions; neither is followed"
        },
        (K::AlgorithmMismatch, _) => "the signature algorithm changes within the log",
        (K::UnsupportedAlgorithm, _) => "the log uses a signature algorithm this verifier does not implement",
        (K::LogIdMismatch, _) => "this is not the log that was expected",
        (K::SealedLogExtended, _) => "records were added after the log was sealed",
        (K::CheckpointForDifferentLog, _) => {
            "a checkpoint by this log's signer names a different log: either the wrong log was supplied, or the log it describes was replaced by another of the signer's logs"
        },
        (K::CheckpointMismatch, _) => "history was rewritten: the record differs from the one observed earlier",
        (K::CheckpointTruncated, _) => "history that was observed earlier is gone",
        (K::FormatDowngrade, _) => {
            "a part protected only by a shared secret key was substituted for a signed one"
        },
        (K::TimestampRegression | K::TimestampInconsistency, _) => "timestamps go backwards",
        _ => "verification failed",
    }
}

impl SignedVerifyReport {
    /// The first violation.
    #[must_use]
    pub fn violation(&self) -> Option<&Finding> {
        self.violations.first()
    }

    /// `Verified`, `SelfConsistent`, or `Kind@location` of the first
    /// violation.
    #[must_use]
    pub fn compact_verdict(&self) -> String {
        match self.verdict {
            Verdict::Verified => "Verified".into(),
            Verdict::SelfConsistent => "SelfConsistent".into(),
            _ => self
                .violation()
                .map_or_else(|| "Violation".into(), Finding::compact),
        }
    }

    /// JSON `status`: `ok`, `unpinned`, or `tampered`.
    #[must_use]
    pub fn status(&self) -> &'static str {
        match self.verdict {
            Verdict::Verified => "ok",
            Verdict::SelfConsistent => "unpinned",
            _ => "tampered",
        }
    }

    /// Narrow to segment `n` (spec §13.4): remove violations located in
    /// other segments, keep every log-level kind, and never improve the
    /// verdict beyond what the log-level result allows.
    #[must_use]
    pub fn filter_segment(mut self, n: u16) -> Self {
        self.violations
            .retain(|v| v.is_log_level() || v.location.segment().is_none_or(|s| s == n));
        if self.violations.is_empty() && self.verdict == Verdict::Violation {
            // Only violations elsewhere: the filtered segment is clean, but
            // without a trusted signature the log-level verdict stays
            // SelfConsistent.
            let signer_trusted = self.signer.as_ref().is_some_and(|s| s.trusted);
            self.verdict = if signer_trusted {
                Verdict::Verified
            } else {
                Verdict::SelfConsistent
            };
            if self.verdict == Verdict::SelfConsistent && self.not_verified_reason.is_none() {
                self.not_verified_reason = Some(NotVerifiedReason::NotPinned);
            }
        }
        self
    }

    /// The report as JSON (spec §14, `format_version` 2).
    #[must_use]
    pub fn to_json(&self) -> Value {
        let l = &self.log;
        let elided = Value::object([
            ("count", Value::Int(l.elided_records.len() as u64)),
            (
                "positions",
                Value::Array(
                    l.elided_records
                        .iter()
                        .map(|(s, r)| Value::str(format!("s{s}r{r}")))
                        .collect(),
                ),
            ),
        ]);
        let log = Value::object([
            ("log_dir", Value::str(l.log_dir.to_string_lossy())),
            ("log_id_hex", l.log_id.map(|i| hex(&i)).into()),
            ("key_id_hex", l.key_id.map(|k| k.to_hex()).into()),
            (
                "segments_inspected",
                Value::Int(u64::from(l.segments_inspected)),
            ),
            ("records_inspected", Value::Int(l.records_inspected)),
            (
                "first_segment_index",
                l.first_segment_index.map(u64::from).into(),
            ),
            (
                "last_segment_index",
                l.last_segment_index.map(u64::from).into(),
            ),
            (
                "final_record_hash_hex",
                l.final_record_hash.map(|h| hex(&h)).into(),
            ),
            ("head", l.head.map(|(s, r)| format!("s{s}r{r}")).into()),
            ("head_anchored", Value::Bool(l.head_anchored)),
            ("sealed", Value::Bool(l.sealed)),
            ("elided_records", elided),
            (
                "unsigned_last_segment",
                Value::Bool(l.unsigned_last_segment),
            ),
        ]);
        let mut m = vec![
            ("format_version", Value::Int(u64::from(self.format_version))),
            ("verdict", Value::str(verdict_str(self.verdict))),
            ("status", Value::str(self.status())),
            (
                "reason",
                self.not_verified_reason.map(|r| r.as_str()).into(),
            ),
            ("log", log),
            (
                "signer",
                self.signer
                    .as_ref()
                    .map_or(Value::Null, SignerInfo::to_json),
            ),
            (
                "violation",
                self.violation().map_or(Value::Null, Finding::to_json),
            ),
            (
                "additional_violations",
                Value::Array(
                    self.violations
                        .iter()
                        .skip(1)
                        .map(Finding::to_json)
                        .collect(),
                ),
            ),
            (
                "warnings",
                Value::Array(self.warnings.iter().map(Warning::to_json).collect()),
            ),
        ];
        if !self.checkpoints.is_empty() {
            m.push((
                "checkpoints",
                Value::Array(
                    self.checkpoints
                        .iter()
                        .map(CheckpointInfo::to_json)
                        .collect(),
                ),
            ));
        }
        Value::object(m)
    }

    /// The human report (spec §11.6 style). `program` is how the reader
    /// invokes the verifier, for the re-run hint.
    #[must_use]
    pub fn render_human(&self, ascii: bool, program: &str) -> String {
        let marks = Marks::new(ascii);
        let mut out = String::new();
        let l = &self.log;
        let dir = escape(&l.log_dir.to_string_lossy());
        let head = l.head.map(|(s, r)| (s, r, l.records_inspected));
        match self.verdict {
            Verdict::Verified => {
                let (s, r, n) = head.unwrap_or((0, 0, 0));
                out.push_str(&format!(
                    "{} Verified through record {} (s{s}r{r})",
                    marks.ok,
                    thousands(n)
                ));
                if l.head_anchored {
                    if l.sealed {
                        out.push_str(" · sealed: this is the end of the log\n");
                    } else {
                        out.push_str(" · the end of the log is confirmed\n");
                    }
                } else {
                    out.push_str(
                        " · tail not anchored: later records may have been removed\n",
                    );
                }
                out.push_str(&format!(
                    "  Audit log {dir}: {} segment(s), {} record(s)",
                    l.segments_inspected,
                    thousands(l.records_inspected)
                ));
                if !l.elided_records.is_empty() {
                    out.push_str(&format!(
                        ", {} with withheld content",
                        thousands(l.elided_records.len() as u64)
                    ));
                }
                out.push('\n');
                if let Some(s) = &self.signer {
                    s.human_lines(&mut out);
                }
            },
            Verdict::SelfConsistent => match self.not_verified_reason {
                Some(NotVerifiedReason::NoSignedRecords) => out.push_str(&format!(
                    "{} Not verified: the audit log has no records, so there is nothing to check the key against.\n",
                    marks.warn
                )),
                _ => {
                    out.push_str(&format!(
                        "{} Not verified: you did not supply the signer's key.\n",
                        marks.warn
                    ));
                    out.push_str(
                        "  The records match their signatures, but without the signer's key anyone could have made those signatures.\n",
                    );
                    if let Some(s) = &self.signer {
                        out.push_str("  This log says it was signed by\n");
                        out.push_str(&format!("    {}\n", s.key_id.to_grouped_hex()));
                    }
                    out.push_str("  Do not take that number from the log itself. Get the signer's fingerprint from the signer\n");
                    out.push_str("  directly (their website, a letter, a phone call), then run:\n");
                    out.push_str(&format!(
                        "    {program} verify {dir} --key-fingerprint \"<the fingerprint you were given>\"\n"
                    ));
                },
            },
            _ => {
                out.push_str(&format!(
                    "{} Verification failed: {} problem{}\n",
                    marks.fail,
                    self.violations.len(),
                    if self.violations.len() == 1 { "" } else { "s" }
                ));
                for v in &self.violations {
                    out.push_str(&format!(
                        "  {} at {}: {}\n",
                        v.kind.as_str(),
                        v.location.human(),
                        describe(v.kind, v.reason.as_deref())
                    ));
                }
                if let Some(s) = &self.signer {
                    out.push_str("  The log says it was signed by\n");
                    out.push_str(&format!("    {}\n", s.key_id.to_grouped_hex()));
                }
            },
        }
        if !self.checkpoints.is_empty() {
            out.push_str("  Checkpoints\n");
            for c in &self.checkpoints {
                out.push_str(&format!(
                    "    {} {}{}\n",
                    c.position,
                    if c.signed {
                        "signed by the log's signer"
                    } else {
                        "unsigned (your own observation)"
                    },
                    c.observed_at
                        .as_deref()
                        .map(|o| format!(", observed {} (its maker's clock)", escape(o)))
                        .unwrap_or_default()
                ));
                for w in &c.witnesses {
                    out.push_str(&format!(
                        "      witnessed by {} at {} (the witness's clock)\n",
                        escape(&w.principal),
                        escape(&w.observed_at)
                    ));
                }
            }
        }
        if !self.warnings.is_empty() {
            out.push_str("  Warnings\n");
            for w in &self.warnings {
                out.push_str(&format!(
                    "    {} {}: {}\n",
                    marks.warn,
                    escape(&w.item),
                    w.message
                ));
            }
        }
        if ascii {
            out = out.replace(['–', '·'], "-");
        }
        out
    }
}

/// The verdict string used in reports.
#[must_use]
pub fn verdict_str(v: Verdict) -> &'static str {
    match v {
        Verdict::Verified => "Verified",
        Verdict::SelfConsistent => "SelfConsistent",
        _ => "Violation",
    }
}

/// A report for an empty `format_version`; used by builders of reports.
pub(crate) fn empty_report(log_dir: PathBuf) -> SignedVerifyReport {
    SignedVerifyReport {
        format_version: FORMAT_VERSION_SIGNED,
        verdict: Verdict::Verified,
        not_verified_reason: None,
        log: SignedLogSummary {
            log_dir,
            ..SignedLogSummary::default()
        },
        signer: None,
        checkpoints: Vec::new(),
        violations: Vec::new(),
        warnings: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thousands_sep() {
        assert_eq!(thousands(0), "0");
        assert_eq!(thousands(999), "999");
        assert_eq!(thousands(1207), "1,207");
        assert_eq!(thousands(1_234_567), "1,234,567");
    }
}
