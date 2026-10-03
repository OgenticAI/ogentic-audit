//! Verifying a signed log (spec v0.2 §8, §10.4).
//!
//! Per record the order is: framing, **signature**, body hash, decode,
//! chain, trust, structure, time. A changed byte anywhere in a record is
//! therefore reported as `SignatureInvalid` at that record; a validly
//! signed record in the wrong place is `ChainBreak`.

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use super::checkpoint::{CheckpointV2, WitnessCosignature};
use super::ed25519;
use super::format::{
    self, chain_start, record_hash, Body, Envelope, Frame, SignedHeader, EVENT_FINALIZED,
    EVENT_SEALED, HEADER_HASHED_LEN, HEADER_LEN,
};
use super::json::Value;
use super::keys::{Fingerprint, PublicKey, SigAlg};
use super::names;
use super::report::{
    empty_report, CheckpointInfo, Finding, Location, NotVerifiedReason, SignedVerifyReport,
    SignerInfo, SignerReason, Warning, WitnessInfo,
};
use super::sshsig;
use super::statements::Head;
use super::trust::{verify_detached_by, Evaluated, Object, Reject, TrustContext, TrustError};
use super::{hex, sha256, FORMAT_VERSION_SIGNED, NS_CHECKPOINT, NS_RECORD, NS_WITNESS};
use crate::cbor::Value as Cbor;
use crate::verifier::{Verdict, ViolationKind, MAX_TS_DRIFT_MS};

/// The format version of the log in `dir`: the `version` field of its
/// lowest-numbered segment. `None` when there are no segment files;
/// `Some(0)` when the first segment is too short or lacks the magic.
pub fn log_format(dir: impl AsRef<Path>) -> io::Result<Option<u16>> {
    let (segments, _) = list_segments(dir.as_ref())?;
    let Some(first) = segments.first() else {
        return Ok(None);
    };
    let mut buf = [0u8; 6];
    let mut f = File::open(segment_path(dir.as_ref(), *first))?;
    let n = read_up_to(&mut f, &mut buf)?;
    if n < 6 || &buf[..4] != crate::segment::FORMAT_MAGIC {
        return Ok(Some(0));
    }
    Ok(Some(u16::from_le_bytes([buf[4], buf[5]])))
}

fn read_up_to(r: &mut impl Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        let k = r.read(&mut buf[n..])?;
        if k == 0 {
            break;
        }
        n += k;
    }
    Ok(n)
}

fn segment_path(dir: &Path, index: u16) -> PathBuf {
    dir.join(format!("audit-{index:04}.cbor"))
}

/// Segment indices present (sorted) and near-miss names.
pub(crate) fn list_segments(dir: &Path) -> io::Result<(Vec<u16>, Vec<String>)> {
    let mut idx = Vec::new();
    let mut near = Vec::new();
    for e in std::fs::read_dir(dir)? {
        let e = e?;
        let Some(name) = e.file_name().to_str().map(str::to_string) else {
            continue;
        };
        if let Some(i) = names::segment_index(&name) {
            idx.push(i);
        } else if names::is_near_miss_segment(&name) {
            near.push(name);
        }
    }
    idx.sort_unstable();
    near.sort();
    Ok((idx, near))
}

/// A checkpoint supplied by the caller, with optional signature and
/// witness co-signatures (file bytes).
#[derive(Debug, Clone, Default)]
pub struct SuppliedCheckpoint {
    /// The checkpoint file bytes.
    pub bytes: Vec<u8>,
    /// Its `.sig`, if any.
    pub sig: Option<Vec<u8>>,
    /// Witness co-signatures: `(file bytes, .sig bytes)`.
    pub witnesses: Vec<(Vec<u8>, Vec<u8>)>,
}

impl SuppliedCheckpoint {
    /// Load `path` and, if present, `path.sig`.
    pub fn load(path: &Path) -> io::Result<Self> {
        let bytes = std::fs::read(path)?;
        let mut sig_path = path.as_os_str().to_os_string();
        sig_path.push(".sig");
        let sig = std::fs::read(PathBuf::from(sig_path)).ok();
        Ok(Self {
            bytes,
            sig,
            witnesses: Vec::new(),
        })
    }

    /// Attach a witness file (and its `.sig`).
    pub fn add_witness(&mut self, path: &Path) -> io::Result<()> {
        let bytes = std::fs::read(path)?;
        let mut sig_path = path.as_os_str().to_os_string();
        sig_path.push(".sig");
        let sig = std::fs::read(PathBuf::from(sig_path))?;
        self.witnesses.push((bytes, sig));
        Ok(())
    }
}

/// Options for [`SignedVerifier::verify_with_options`].
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct SignedVerifyOptions {
    /// Continue past the first violation.
    pub forensic_mode: bool,
    /// Checkpoints to check the log against.
    pub checkpoints: Vec<SuppliedCheckpoint>,
    /// The log the caller means; another `log_id` is `LogIdMismatch@s0`.
    pub expect_log_id: Option<[u8; 16]>,
    /// In a release: the attested head (spec §11.4 L3).
    pub(crate) attested: Option<CheckpointV2>,
}

impl SignedVerifyOptions {
    /// Default options.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    /// Set forensic mode.
    #[must_use]
    pub fn forensic(mut self, on: bool) -> Self {
        self.forensic_mode = on;
        self
    }
    /// Add a checkpoint.
    #[must_use]
    pub fn checkpoint(mut self, cp: SuppliedCheckpoint) -> Self {
        self.checkpoints.push(cp);
        self
    }
    /// Expect this `log_id`.
    #[must_use]
    pub fn expect_log_id(mut self, id: [u8; 16]) -> Self {
        self.expect_log_id = Some(id);
        self
    }
}

/// Errors that prevent a report: never accusations (spec §8.4).
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum SignedVerifyError {
    /// No segment files (exit 2).
    #[error("no audit-NNNN.cbor segment files in {0}")]
    NoSegments(String),
    /// I/O (exit 2).
    #[error("{0}")]
    Io(String),
    /// An HMAC log given signed-mode inputs (exit 3).
    #[error("this log is protected by a shared secret key (format 0x0001). It cannot be checked with a public key, and whoever holds its key could also have written it")]
    HmacLog,
    /// A newer format than this verifier implements (exit 3).
    #[error("this log uses format 0x{0:04x}; upgrade the verifier")]
    NewerFormat(u16),
    /// The trust inputs are invalid (exit 3).
    #[error("{0}")]
    Trust(#[from] TrustError),
    /// A supplied checkpoint is unusable (exit 3).
    #[error("{kind}: {message}")]
    Checkpoint {
        /// `CheckpointSignatureInvalid`, `CheckpointSignerUntrusted`,
        /// `CheckpointForDifferentSigner`, or `CheckpointFormat`.
        kind: &'static str,
        /// Details.
        message: String,
    },
}

impl SignedVerifyError {
    /// CLI exit code: 2 for I/O, 3 for the caller's inputs.
    #[must_use]
    pub fn exit_code(&self) -> u8 {
        match self {
            SignedVerifyError::NoSegments(_) | SignedVerifyError::Io(_) => 2,
            _ => 3,
        }
    }
}

fn io_err(e: io::Error) -> SignedVerifyError {
    SignedVerifyError::Io(e.to_string())
}

/// Verifies signed logs under a [`TrustContext`].
#[derive(Debug, Clone)]
pub struct SignedVerifier {
    trust: TrustContext,
}

struct ParsedCheckpoint {
    cp: CheckpointV2,
    supplied: SuppliedCheckpoint,
}

impl SignedVerifier {
    /// A verifier with these pins and statements. With an empty context
    /// the best verdict is `SelfConsistent`.
    #[must_use]
    pub fn new(trust: TrustContext) -> Self {
        Self { trust }
    }

    /// Verify with default options.
    pub fn verify(&self, dir: impl AsRef<Path>) -> Result<SignedVerifyReport, SignedVerifyError> {
        self.verify_with_options(dir, SignedVerifyOptions::default())
    }

    /// Verify a signed log.
    pub fn verify_with_options(
        &self,
        dir: impl AsRef<Path>,
        opts: SignedVerifyOptions,
    ) -> Result<SignedVerifyReport, SignedVerifyError> {
        let eval = self.trust.evaluate()?;
        verify_log(dir.as_ref(), &eval, &opts)
    }
}

pub(crate) fn verify_log(
    dir: &Path,
    eval: &Evaluated,
    opts: &SignedVerifyOptions,
) -> Result<SignedVerifyReport, SignedVerifyError> {
    let (segments, near) = list_segments(dir).map_err(io_err)?;
    if segments.is_empty() {
        return Err(SignedVerifyError::NoSegments(dir.display().to_string()));
    }
    match log_format(dir).map_err(io_err)? {
        Some(1) => return Err(SignedVerifyError::HmacLog),
        Some(v) if v > FORMAT_VERSION_SIGNED => return Err(SignedVerifyError::NewerFormat(v)),
        _ => {},
    }
    let mut checkpoints = Vec::new();
    for s in &opts.checkpoints {
        let cp = CheckpointV2::parse(&s.bytes).map_err(|m| SignedVerifyError::Checkpoint {
            kind: "CheckpointFormat",
            message: m,
        })?;
        checkpoints.push(ParsedCheckpoint {
            cp,
            supplied: s.clone(),
        });
    }

    let mut w = Walk::new(dir, eval, opts);
    w.report.log.first_segment_index = segments.first().copied();
    for name in near {
        w.report.warnings.push(Warning {
            kind: "NearMissSegmentName".into(),
            item: name.clone(),
            message: "this file looks like a segment but is not named audit-NNNN.cbor; it was not checked".into(),
        });
    }
    for pos in checkpoints
        .iter()
        .map(|c| (c.cp.head.segment, c.cp.head.record_id))
    {
        w.interesting.insert(pos, None);
    }
    if let Some(a) = &opts.attested {
        w.interesting
            .insert((a.head.segment, a.head.record_id), None);
    }
    w.run(&segments).map_err(io_err)?;

    for (k, _, _) in &eval.equivocations {
        w.violation(Finding {
            kind: ViolationKind::TransitionEquivocation,
            reason: None,
            location: Location::Key { key_id: *k },
            evidence: Value::object([("key_id_hex", Value::str(k.to_hex()))]),
            message: "two different verified transitions from one key".into(),
        });
    }

    let anchored_by_cp = w.check_checkpoints(&checkpoints)?;
    w.check_attested();
    w.finish(anchored_by_cp);
    Ok(w.report)
}

type Position = (u16, u64);

#[derive(Debug, Clone)]
struct LastRecord {
    segment: u16,
    record: u64,
    hash: [u8; 32],
    event: String,
    ts_wall: String,
}

struct Walk<'a> {
    dir: &'a Path,
    eval: &'a Evaluated,
    opts: &'a SignedVerifyOptions,
    report: SignedVerifyReport,
    stopped: bool,
    seg0: Option<SignedHeader>,
    signer_ok: bool,
    trusted_sig: bool,
    ordinal: u64,
    sealed_at: Option<(u16, u64)>,
    last_ts_ms: Option<i64>,
    last: Option<LastRecord>,
    /// Positions named by checkpoints or the attested head, filled in
    /// with `(record_hash, ordinal)` as the walk reaches them.
    interesting: HashMap<Position, Option<([u8; 32], u64)>>,
    last_segment_had_records: bool,
    walk_complete: bool,
    ended_in_finalized_without_successor: bool,
    attested_anchor: Option<Head>,
}

fn rec_loc(segment: u16, record: u64, ordinal: u64, byte_offset: u64) -> Location {
    Location::Record {
        segment,
        record,
        ordinal,
        byte_offset,
    }
}

impl<'a> Walk<'a> {
    fn new(dir: &'a Path, eval: &'a Evaluated, opts: &'a SignedVerifyOptions) -> Self {
        Self {
            dir,
            eval,
            opts,
            report: empty_report(dir.to_path_buf()),
            stopped: false,
            seg0: None,
            signer_ok: false,
            trusted_sig: false,
            ordinal: 0,
            sealed_at: None,
            last_ts_ms: None,
            last: None,
            interesting: HashMap::new(),
            last_segment_had_records: true,
            walk_complete: false,
            ended_in_finalized_without_successor: false,
            attested_anchor: None,
        }
    }

    /// Record a violation; returns whether to continue.
    fn violation(&mut self, f: Finding) -> bool {
        self.report.violations.push(f);
        if !self.opts.forensic_mode {
            self.stopped = true;
        }
        !self.stopped
    }

    fn after_head(&self, segment: u16, record: u64) -> bool {
        self.opts
            .attested
            .as_ref()
            .is_some_and(|a| (segment, record) > (a.head.segment, a.head.record_id))
    }

    fn run(&mut self, segments: &[u16]) -> io::Result<()> {
        let mut prev_final: Option<[u8; 32]> = Some([0u8; 32]);
        let mut expected: u16 = 0;
        for (i, &n) in segments.iter().enumerate() {
            if self.stopped {
                return Ok(());
            }
            let is_last = i + 1 == segments.len();
            if n != expected {
                let ok = self.violation(Finding {
                    kind: ViolationKind::SegmentDiscontinuity,
                    reason: None,
                    location: Location::Segment { segment: expected },
                    evidence: Value::object([
                        ("expected_index", Value::Int(u64::from(expected))),
                        ("actual_index", Value::Int(u64::from(n))),
                    ]),
                    message: format!("segment {expected} is missing"),
                });
                if !ok {
                    return Ok(());
                }
                prev_final = None;
            } else if n > 0 && !self.last_segment_had_records {
                let ok = self.violation(Finding {
                    kind: ViolationKind::SegmentDiscontinuity,
                    reason: None,
                    location: Location::Segment { segment: n },
                    evidence: Value::object([(
                        "empty_segment_index",
                        Value::Int(u64::from(n - 1)),
                    )]),
                    message: format!(
                        "segment {} has no records but is followed by segment {n}",
                        n - 1
                    ),
                });
                if !ok {
                    return Ok(());
                }
                prev_final = None;
            }
            expected = n.saturating_add(1);
            self.report.log.segments_inspected += 1;
            self.report.log.last_segment_index = Some(n);
            match self.segment(n, prev_final, is_last)? {
                Some(final_hash) => prev_final = Some(final_hash),
                None => prev_final = None,
            }
        }
        if !self.stopped {
            self.walk_complete = true;
        }
        Ok(())
    }

    /// Check one segment. Returns its final `record_hash` (or chain start
    /// if empty), or `None` if the segment could not be followed.
    fn segment(
        &mut self,
        n: u16,
        prev_final: Option<[u8; 32]>,
        is_last: bool,
    ) -> io::Result<Option<[u8; 32]>> {
        let path = segment_path(self.dir, n);
        let mut file = File::open(&path)?;
        let file_len = file.metadata()?.len();
        let mut hb = [0u8; HEADER_LEN];
        let got = read_up_to(&mut file, &mut hb)?;
        let header = match self.header(n, &hb, got, prev_final) {
            Ok(h) => h,
            Err(f) => {
                self.violation(f);
                return Ok(None);
            },
        };
        if n == 0 {
            self.seg0 = Some(header.clone());
            self.report.log.log_id = Some(header.log_id);
            self.report.log.key_id = Some(Fingerprint(header.key_id));
            if !self.segment0_trust(&header) {
                return Ok(None);
            }
        }

        let mut prev = chain_start(&hb);
        let mut reader = BufReader::new(file);
        reader.seek(SeekFrom::Start(HEADER_LEN as u64))?;
        let mut offset = HEADER_LEN as u64;
        let mut p: u64 = 0;
        let mut finalized_at: Option<(u64, u64)> = None;
        let pk = header.public_key;
        let log_id = header.log_id;
        loop {
            if self.stopped {
                return Ok(None);
            }
            let frame = format::read_frame(&mut reader, offset, file_len)?;
            let raw = match frame {
                Frame::End => break,
                Frame::TooLarge { offset: o, len } => {
                    self.framing_problem(
                        n,
                        p,
                        o,
                        "TooLarge",
                        &format!("declared envelope length {len} exceeds 4096"),
                    );
                    return Ok(None);
                },
                Frame::Torn { offset: o } => {
                    self.framing_problem(
                        n,
                        p,
                        o,
                        "TornTail",
                        "the segment ends part-way through a record",
                    );
                    return Ok(None);
                },
                Frame::Record(r) => r,
            };
            offset += raw.total_len;
            self.ordinal += 1;
            self.report.log.records_inspected += 1;
            let ordinal = self.ordinal;
            let loc = rec_loc(n, p, ordinal, raw.offset);
            let rh = record_hash(&raw.envelope);
            if self.after_head(n, p) {
                self.report.log.records_after_head += 1;
            }

            if let Some((fp, foff)) = finalized_at {
                // A record after segment.finalized in the same segment.
                if !self.violation(Finding {
                    kind: ViolationKind::RecordCorrupt,
                    reason: Some("BadRollover".into()),
                    location: rec_loc(n, fp, ordinal - 1, foff),
                    evidence: Value::object([(
                        "message",
                        Value::str("segment.finalized is not the last record of its segment"),
                    )]),
                    message: format!("s{n}r{fp}: segment.finalized is followed by another record"),
                }) {
                    return Ok(None);
                }
                finalized_at = None;
            }

            // R2: signature first.
            let data = sshsig::signed_data(NS_RECORD, &raw.envelope);
            if let Err(fail) = ed25519::verify(&pk, &data, &raw.signature) {
                let ok = self.violation(Finding {
                    kind: ViolationKind::SignatureInvalid,
                    reason: Some(fail.reason().into()),
                    location: loc.clone(),
                    evidence: Value::object([
                        ("envelope_offset", Value::Int(raw.offset + 4)),
                        ("envelope_len", Value::Int(raw.envelope.len() as u64)),
                        ("signature_hex", Value::str(hex(&raw.signature))),
                        ("key_id_hex", Value::str(hex(&header.key_id))),
                    ]),
                    message: format!(
                        "s{n}r{p}: {}",
                        super::report::describe(
                            ViolationKind::SignatureInvalid,
                            Some(fail.reason())
                        )
                    ),
                });
                if !ok {
                    return Ok(None);
                }
                prev = rh;
                p += 1;
                continue;
            }
            // R4 (envelope), needed for R3.
            let env = match Envelope::decode(&raw.envelope) {
                Ok(e) => e,
                Err(m) => {
                    if !self.decode_error(loc, &m) {
                        return Ok(None);
                    }
                    prev = rh;
                    p += 1;
                    continue;
                },
            };
            // R3: body hash.
            let mut body: Option<Body> = None;
            match &raw.body {
                Some(b) => {
                    let actual = format::body_hash(b);
                    if actual != env.body_hash {
                        let ok = self.violation(Finding {
                            kind: ViolationKind::SignatureInvalid,
                            reason: Some("body_mismatch".into()),
                            location: loc.clone(),
                            evidence: Value::object([
                                ("expected_body_hash_hex", Value::str(hex(&env.body_hash))),
                                ("actual_body_hash_hex", Value::str(hex(&actual))),
                            ]),
                            message: format!(
                                "s{n}r{p}: the record's content was changed after it was signed"
                            ),
                        });
                        if !ok {
                            return Ok(None);
                        }
                    } else {
                        match Body::decode(b) {
                            Ok(bd) => body = Some(bd),
                            Err(m) => {
                                if !self.decode_error(loc.clone(), &m) {
                                    return Ok(None);
                                }
                            },
                        }
                    }
                },
                None => self.report.log.elided_records.push((n, p)),
            }
            // R5, R6.
            if env.key_id != header.key_id {
                let ok = self.violation(Finding {
                    kind: ViolationKind::KeyIdMismatch,
                    reason: None,
                    location: loc.clone(),
                    evidence: Value::object([
                        ("header_key_id_hex", Value::str(hex(&header.key_id))),
                        ("record_key_id_hex", Value::str(hex(&env.key_id))),
                    ]),
                    message: format!("s{n}r{p}: record key_id differs from its segment header"),
                });
                if !ok {
                    return Ok(None);
                }
            }
            if env.sig_alg != header.sig_alg {
                let ok = self.violation(Finding {
                    kind: ViolationKind::AlgorithmMismatch,
                    reason: None,
                    location: loc.clone(),
                    evidence: Value::object([
                        ("header_sig_alg", Value::Int(u64::from(header.sig_alg))),
                        ("record_sig_alg", Value::Int(u64::from(env.sig_alg))),
                    ]),
                    message: format!("s{n}r{p}: record sig_alg differs from its segment header"),
                });
                if !ok {
                    return Ok(None);
                }
            }
            // R7: chain.
            if env.segment_index != n || env.record_id != p || env.prev_hash != prev {
                let ok = self.violation(Finding {
                    kind: ViolationKind::ChainBreak,
                    reason: None,
                    location: loc.clone(),
                    evidence: Value::object([
                        ("expected_prev_hash_hex", Value::str(hex(&prev))),
                        ("actual_prev_hash_hex", Value::str(hex(&env.prev_hash))),
                        ("expected_position", Value::str(format!("s{n}r{p}"))),
                        (
                            "actual_position",
                            Value::str(format!("s{}r{}", env.segment_index, env.record_id)),
                        ),
                        ("is_segment_start", Value::Bool(p == 0)),
                    ]),
                    message: format!("s{n}r{p}: a genuine record in the wrong place (a record before it is missing, or records were moved)"),
                });
                if !ok {
                    return Ok(None);
                }
            }
            // R8: trust at this position.
            if self.eval.has_pins() && self.signer_ok {
                let obj = Object::Record {
                    log_id: &log_id,
                    segment: n,
                    record_id: p,
                    record_hash: &rh,
                };
                match self
                    .eval
                    .accept(&Fingerprint(header.key_id), NS_RECORD, &obj)
                {
                    Ok(_) => self.trusted_sig = true,
                    Err(rej) => {
                        if !self.reject_finding(rej, loc.clone(), &rh) {
                            return Ok(None);
                        }
                    },
                }
            }
            // R9: structural records.
            if format::is_structural(&env.event) && raw.body.is_none() {
                let ok = self.violation(Finding {
                    kind: ViolationKind::RecordCorrupt,
                    reason: Some("ElidedStructural".into()),
                    location: loc.clone(),
                    evidence: Value::object([("event", Value::str(&env.event))]),
                    message: format!("s{n}r{p}: structural record {} was elided", env.event),
                });
                if !ok {
                    return Ok(None);
                }
            }
            if env.event == EVENT_FINALIZED {
                if let Some(b) = &body {
                    let records_ok =
                        matches!(b.payload_get("records"), Some(Cbor::Uint(r)) if *r == p);
                    let hash_ok = matches!(b.payload_get("final_hash"), Some(Cbor::Bytes(h)) if h.as_slice() == env.prev_hash);
                    if !(records_ok && hash_ok) {
                        let ok = self.violation(Finding {
                            kind: ViolationKind::RecordCorrupt,
                            reason: Some("BadRollover".into()),
                            location: loc.clone(),
                            evidence: Value::object([
                                ("expected_records", Value::Int(p)),
                                ("expected_final_hash_hex", Value::str(hex(&env.prev_hash))),
                            ]),
                            message: format!(
                                "s{n}r{p}: segment.finalized payload does not match its segment"
                            ),
                        });
                        if !ok {
                            return Ok(None);
                        }
                    }
                }
                finalized_at = Some((p, raw.offset));
            }
            // R10: nothing after log.sealed.
            if let Some((ss, sr)) = self.sealed_at {
                let ok = self.violation(Finding {
                    kind: ViolationKind::SealedLogExtended,
                    reason: None,
                    location: loc.clone(),
                    evidence: Value::object([("sealed_at", Value::str(format!("s{ss}r{sr}")))]),
                    message: format!("s{n}r{p}: a record after the log was sealed at s{ss}r{sr}"),
                });
                if !ok {
                    return Ok(None);
                }
            }
            if env.event == EVENT_SEALED && self.sealed_at.is_none() {
                self.sealed_at = Some((n, p));
            }
            // R11: time.
            if let Some(ms) = super::parse_rfc3339_millis(&env.ts_wall) {
                if let Some(prev_ms) = self.last_ts_ms {
                    let delta = ms - prev_ms;
                    if delta < -MAX_TS_DRIFT_MS {
                        let ok = self.violation(Finding {
                            kind: ViolationKind::TimestampRegression,
                            reason: None,
                            location: loc.clone(),
                            evidence: Value::object([
                                ("current_ts_wall", Value::str(&env.ts_wall)),
                                ("delta_ms", Value::str(delta.to_string())),
                            ]),
                            message: format!("s{n}r{p}: ts_wall regressed {delta} ms"),
                        });
                        if !ok {
                            return Ok(None);
                        }
                    }
                }
                self.last_ts_ms = Some(ms);
            }

            if let Some(slot) = self.interesting.get_mut(&(n, p)) {
                *slot = Some((rh, ordinal));
            }
            self.last = Some(LastRecord {
                segment: n,
                record: p,
                hash: rh,
                event: env.event.clone(),
                ts_wall: env.ts_wall.clone(),
            });
            self.report.log.final_record_hash = Some(rh);
            self.report.log.head = Some((n, p));
            prev = rh;
            p += 1;
        }

        self.last_segment_had_records = p > 0;
        if p == 0 && n > 0 && is_last {
            self.report.log.unsigned_last_segment = true;
            self.report.log.segments_inspected -= 1;
            self.report.warnings.push(Warning {
                kind: "UnsignedLastSegment".into(),
                item: format!("s{n}"),
                message: "the last segment has a header but no records; a header is not signed, so it was not counted".into(),
            });
        }
        if finalized_at.is_some() && is_last {
            self.ended_in_finalized_without_successor = true;
            self.report.warnings.push(Warning {
                kind: "RolledOverWithoutSuccessor".into(),
                item: format!("s{n}"),
                message: format!(
                    "segment {n} was rolled over, but segment {} is missing",
                    n + 1
                ),
            });
        }
        Ok(Some(prev))
    }

    fn framing_problem(&mut self, n: u16, p: u64, offset: u64, subkind: &str, msg: &str) {
        if self.after_head(n, p) {
            self.report.warnings.push(Warning {
                kind: "TornTailAfterHead".into(),
                item: format!("s{n}r{p}"),
                message: format!("after the attested head: {msg}"),
            });
            return;
        }
        let ordinal = self.ordinal + 1;
        self.violation(Finding {
            kind: ViolationKind::RecordCorrupt,
            reason: Some(subkind.into()),
            location: rec_loc(n, p, ordinal, offset),
            evidence: Value::object([("byte_offset", Value::Int(offset))]),
            message: format!("s{n}r{p}: {msg}"),
        });
    }

    fn decode_error(&mut self, loc: Location, m: &str) -> bool {
        self.violation(Finding {
            kind: ViolationKind::RecordCorrupt,
            reason: Some("DecodeError".into()),
            location: loc,
            evidence: Value::object([("message", Value::str(m))]),
            message: format!("record does not decode: {m}"),
        })
    }

    fn reject_finding(&mut self, rej: Reject, loc: Location, rh: &[u8; 32]) -> bool {
        let f = match rej {
            Reject::Retired {
                issued_at,
                successor,
            } => Finding {
                kind: ViolationKind::RetiredKey,
                reason: None,
                location: loc,
                evidence: Value::object([
                    ("transition_issued_at", Value::str(issued_at)),
                    ("successor_key_id_hex", Value::str(successor.to_hex())),
                ]),
                message: "signed by a retired key outside its final heads".into(),
            },
            Reject::Revoked {
                issued_at,
                authority,
            } => Finding {
                kind: ViolationKind::RevokedKey,
                reason: None,
                location: loc,
                evidence: Value::object([
                    ("revocation_issued_at", Value::str(issued_at)),
                    ("cut_points", Value::Bool(authority)),
                ]),
                message: "signed by a revoked key outside its cut points".into(),
            },
            Reject::HeadMismatch { head } => Finding {
                kind: ViolationKind::CheckpointMismatch,
                reason: None,
                location: loc,
                evidence: Value::object([
                    (
                        "statement_record_hash_hex",
                        Value::str(hex(&head.record_hash)),
                    ),
                    ("actual_record_hash_hex", Value::str(hex(rh))),
                ]),
                message: "a key statement names a different record at this position".into(),
            },
            Reject::NotTrusted | Reject::OutOfScope => Finding {
                kind: ViolationKind::UntrustedSigner,
                reason: Some(
                    if rej == Reject::OutOfScope {
                        "out_of_scope"
                    } else {
                        "not_trusted"
                    }
                    .into(),
                ),
                location: loc,
                evidence: Value::Null,
                message: "signer not trusted".into(),
            },
        };
        self.violation(f)
    }

    /// Segment 0: `--expect-log-id`, then the signer against the pins.
    fn segment0_trust(&mut self, h: &SignedHeader) -> bool {
        let key_id = Fingerprint(h.key_id);
        let alg = SigAlg::from_code(h.sig_alg).unwrap_or(SigAlg::Ed25519);
        let entries = self.eval.entries(&key_id);
        let record_entry = entries.iter().find(|e| e.scope.contains(NS_RECORD));
        self.report.signer = Some(SignerInfo {
            principal: record_entry
                .filter(|e| !e.auto_principal)
                .map(|e| e.principal.clone()),
            alg,
            key_id,
            trusted: record_entry.is_some(),
            trust_path: record_entry
                .map(|e| e.trust_path.clone())
                .unwrap_or_default(),
            reason: match record_entry {
                Some(e) if e.pinned => SignerReason::Pinned,
                Some(_) => SignerReason::Transition,
                None if self.eval.has_pins() => SignerReason::NotTrusted,
                None => SignerReason::NotPinned,
            },
        });
        if let Some(expect) = self.opts.expect_log_id {
            if expect != h.log_id
                && !self.violation(Finding {
                    kind: ViolationKind::LogIdMismatch,
                    reason: None,
                    location: Location::Segment { segment: 0 },
                    evidence: Value::object([
                        ("expected_log_id_hex", Value::str(hex(&expect))),
                        ("actual_log_id_hex", Value::str(hex(&h.log_id))),
                    ]),
                    message: "this is not the log that was expected".into(),
                })
            {
                return false;
            }
        }
        if self.eval.has_pins() && record_entry.is_none() {
            let reason = if entries.is_empty() {
                "not_trusted"
            } else {
                "out_of_scope"
            };
            self.report.violations.push(Finding {
                kind: ViolationKind::UntrustedSigner,
                reason: Some(reason.into()),
                location: Location::Segment { segment: 0 },
                evidence: Value::object([
                    ("actual_key_id_hex", Value::str(key_id.to_hex())),
                    ("actual_fingerprint", Value::str(key_id.to_grouped_hex())),
                ]),
                message: format!(
                    "the log is signed by {}, which is not a key you supplied for signing logs",
                    key_id.to_grouped_hex()
                ),
            });
            self.stopped = true;
            return false;
        }
        self.signer_ok = self.eval.has_pins();
        true
    }

    /// H1–H12 for segment `n`. The error is built once per segment, so
    /// its size is not on a hot path.
    #[allow(clippy::result_large_err)]
    fn header(
        &mut self,
        n: u16,
        hb: &[u8; HEADER_LEN],
        got: usize,
        prev_final: Option<[u8; 32]>,
    ) -> Result<SignedHeader, Finding> {
        let seg = Location::Segment { segment: n };
        let corrupt = |sub: &str, ev: Value, msg: String| Finding {
            kind: ViolationKind::HeaderCorrupt,
            reason: Some(sub.into()),
            location: Location::Segment { segment: n },
            evidence: ev,
            message: msg,
        };
        if got < 12 {
            return Err(corrupt(
                "Truncated",
                Value::object([("length", Value::Int(got as u64))]),
                format!("segment {n} is shorter than a header"),
            ));
        }
        if &hb[..4] != crate::segment::FORMAT_MAGIC {
            return Err(corrupt(
                "BadMagic",
                Value::object([("actual_magic_hex", Value::str(hex(&hb[..4])))]),
                format!("segment {n} does not start with OGAU"),
            ));
        }
        let version = u16::from_le_bytes([hb[4], hb[5]]);
        if version != FORMAT_VERSION_SIGNED {
            let downgrade = version == 1 && n > 0;
            return Err(Finding {
                kind: if downgrade {
                    ViolationKind::FormatDowngrade
                } else {
                    ViolationKind::UnknownVersion
                },
                reason: None,
                location: seg,
                evidence: Value::object([
                    ("actual_version", Value::Int(u64::from(version))),
                    (
                        "expected_version",
                        Value::Int(u64::from(FORMAT_VERSION_SIGNED)),
                    ),
                ]),
                message: format!("segment {n} declares format 0x{version:04x} inside a signed log"),
            });
        }
        let sig_alg = u16::from_le_bytes([hb[8], hb[9]]);
        if SigAlg::from_code(sig_alg).is_none() {
            return Err(Finding {
                kind: ViolationKind::UnsupportedAlgorithm,
                reason: None,
                location: seg,
                evidence: Value::object([
                    ("actual_sig_alg", Value::Int(u64::from(sig_alg))),
                    ("supported", Value::Array(vec![Value::Int(1)])),
                ]),
                message: format!("segment {n} uses sig_alg 0x{sig_alg:04x}, which this verifier does not implement"),
            });
        }
        if got < HEADER_LEN {
            return Err(corrupt(
                "Truncated",
                Value::object([("length", Value::Int(got as u64))]),
                format!("segment {n} header is truncated"),
            ));
        }
        let stored = u32::from_le_bytes([hb[124], hb[125], hb[126], hb[127]]);
        let computed = crc32fast::hash(&hb[..HEADER_HASHED_LEN]);
        if stored != computed {
            return Err(corrupt(
                "CrcMismatch",
                Value::object([
                    ("expected_crc32", Value::Int(u64::from(computed))),
                    ("actual_crc32", Value::Int(u64::from(stored))),
                ]),
                format!("segment {n} header CRC mismatch"),
            ));
        }
        let h = SignedHeader::from_bytes_unchecked(hb);
        if h.reserved != 0 {
            return Err(corrupt(
                "ReservedBytesNonZero",
                Value::object([("actual_hex", Value::str(hex(&hb[10..12])))]),
                format!("segment {n} header reserved bytes are not zero"),
            ));
        }
        let pk = PublicKey::ed25519(h.public_key);
        if !pk.is_strong() {
            return Err(Finding {
                kind: ViolationKind::SignatureInvalid,
                reason: Some("weak_key".into()),
                location: seg,
                evidence: Value::object([("public_key_hex", Value::str(pk.to_hex()))]),
                message: format!("segment {n} names a key under which anyone can make signatures"),
            });
        }
        if pk.fingerprint().0 != h.key_id {
            return Err(Finding {
                kind: ViolationKind::KeyIdMismatch,
                reason: None,
                location: seg,
                evidence: Value::object([
                    ("header_key_id_hex", Value::str(hex(&h.key_id))),
                    ("computed_key_id_hex", Value::str(pk.fingerprint().to_hex())),
                ]),
                message: format!("segment {n} key_id does not match its public key"),
            });
        }
        if let Some(s0) = &self.seg0 {
            if n > 0 {
                let mismatch = |kind, field: &str, a: String, b: String| Finding {
                    kind,
                    reason: None,
                    location: Location::Segment { segment: n },
                    evidence: Value::object([
                        ("segment0", Value::str(a)),
                        ("this_segment", Value::str(b)),
                    ]),
                    message: format!("segment {n} {field} differs from segment 0"),
                };
                if h.sig_alg != s0.sig_alg {
                    return Err(mismatch(
                        ViolationKind::AlgorithmMismatch,
                        "sig_alg",
                        s0.sig_alg.to_string(),
                        h.sig_alg.to_string(),
                    ));
                }
                if h.log_id != s0.log_id {
                    return Err(mismatch(
                        ViolationKind::LogIdMismatch,
                        "log_id",
                        hex(&s0.log_id),
                        hex(&h.log_id),
                    ));
                }
                if h.key_id != s0.key_id || h.public_key != s0.public_key {
                    return Err(mismatch(
                        ViolationKind::KeyIdMismatch,
                        "key",
                        hex(&s0.key_id),
                        hex(&h.key_id),
                    ));
                }
            }
        }
        if h.segment_index != n {
            return Err(Finding {
                kind: ViolationKind::SegmentDiscontinuity,
                reason: None,
                location: seg,
                evidence: Value::object([
                    ("expected_index", Value::Int(u64::from(n))),
                    ("actual_index", Value::Int(u64::from(h.segment_index))),
                ]),
                message: format!("segment file {n} says it is segment {}", h.segment_index),
            });
        }
        if n == 0 {
            if h.prev_final != [0u8; 32] {
                return Err(corrupt(
                    "GenesisPrevFinalNonZero",
                    Value::object([("actual_hex", Value::str(hex(&h.prev_final)))]),
                    "segment 0 prev_final is not zero".into(),
                ));
            }
        } else if let Some(expected) = prev_final {
            if h.prev_final != expected {
                return Err(Finding {
                    kind: ViolationKind::SegmentDiscontinuity,
                    reason: None,
                    location: seg,
                    evidence: Value::object([
                        ("expected_prev_final_hex", Value::str(hex(&expected))),
                        ("actual_prev_final_hex", Value::str(hex(&h.prev_final))),
                    ]),
                    message: format!("segment {n} does not continue segment {}", n - 1),
                });
            }
        }
        Ok(h)
    }

    /// Spec §10.4. Returns whether a checkpoint anchors the last record.
    fn check_checkpoints(
        &mut self,
        checkpoints: &[ParsedCheckpoint],
    ) -> Result<bool, SignedVerifyError> {
        let mut anchors = false;
        let Some(h) = self.seg0.clone() else {
            return Ok(false);
        };
        for pc in checkpoints {
            let cp = &pc.cp;
            let err = |kind: &'static str, message: String| SignedVerifyError::Checkpoint {
                kind,
                message,
            };
            let obj = Object::Checkpoint {
                log_id: &cp.head.log_id,
                segment: cp.head.segment,
                record_id: cp.head.record_id,
            };
            // 1. The signature, by the key the checkpoint names.
            let signed = if let Some(sig) = &pc.supplied.sig {
                verify_detached_by(sig, NS_CHECKPOINT, &pc.supplied.bytes, &cp.key_id)
                    .map_err(|m| err("CheckpointSignatureInvalid", m))?;
                if self.eval.has_pins() {
                    self.eval
                        .accept(&cp.key_id, NS_CHECKPOINT, &obj)
                        .map_err(|r| {
                            err(
                                "CheckpointSignerUntrusted",
                                format!("the checkpoint's signer is not trusted to sign checkpoints for this log ({r:?})"),
                            )
                        })?;
                }
                true
            } else {
                false
            };
            // 2. Witnesses.
            let mut witnesses = Vec::new();
            for (wb, ws) in &pc.supplied.witnesses {
                let w = WitnessCosignature::parse(wb)
                    .map_err(|m| err("CheckpointSignatureInvalid", format!("witness: {m}")))?;
                verify_detached_by(ws, NS_WITNESS, wb, &w.witness_key_id)
                    .map_err(|m| err("CheckpointSignatureInvalid", format!("witness: {m}")))?;
                if w.checkpoint_sha256 != sha256(&pc.supplied.bytes) {
                    return Err(err(
                        "CheckpointSignatureInvalid",
                        "the witness co-signature names a different checkpoint".into(),
                    ));
                }
                let principal = if self.eval.has_pins() {
                    self.eval
                        .accept(&w.witness_key_id, NS_WITNESS, &Object::Witness)
                        .map_err(|r| {
                            err(
                                "CheckpointSignerUntrusted",
                                format!("the witness key is not trusted as a witness ({r:?})"),
                            )
                        })?
                        .principal
                        .clone()
                } else {
                    "(not pinned)".into()
                };
                witnesses.push(WitnessInfo {
                    principal,
                    key_id: w.witness_key_id,
                    observed_at: w.observed_at,
                });
            }
            // 3. Another signer's checkpoint: operator error.
            if cp.key_id.0 != h.key_id || cp.alg.code() != h.sig_alg {
                return Err(err(
                    "CheckpointForDifferentSigner",
                    format!(
                        "this checkpoint is for a log signed by {}, but this log is signed by {}",
                        cp.key_id.to_grouped_hex(),
                        Fingerprint(h.key_id).to_grouped_hex()
                    ),
                ));
            }
            let position = format!("s{}r{}", cp.head.segment, cp.head.record_id);
            let mut info = CheckpointInfo {
                signed,
                signer_key_id: cp.key_id,
                position: position.clone(),
                observed_at: cp.observed_at.clone(),
                witnesses,
                anchors_head: false,
            };
            // 4. Same signer, different log.
            if cp.head.log_id != h.log_id {
                self.violation_nostop(Finding {
                    kind: ViolationKind::CheckpointForDifferentLog,
                    reason: None,
                    location: Location::Segment { segment: 0 },
                    evidence: Value::object([
                        ("checkpoint_log_id_hex", Value::str(hex(&cp.head.log_id))),
                        ("actual_log_id_hex", Value::str(hex(&h.log_id))),
                    ]),
                    message: "the checkpoint, by this log's own signer, names a different log: either the wrong log was supplied, or the log it describes was replaced by another of the signer's logs".into(),
                });
                self.report.checkpoints.push(info);
                continue;
            }
            // 5–6.
            if self.position_check(&cp.head, cp.observed_at.as_deref(), "checkpoint") {
                info.anchors_head = self.is_last(&cp.head);
                anchors |= info.anchors_head;
            }
            self.report.checkpoints.push(info);
        }
        Ok(anchors)
    }

    fn violation_nostop(&mut self, f: Finding) {
        self.report.violations.push(f);
    }

    fn is_last(&self, head: &Head) -> bool {
        self.last.as_ref().is_some_and(|l| {
            (l.segment, l.record) == (head.segment, head.record_id) && l.hash == head.record_hash
        })
    }

    /// §10.4 steps 5–6 for `head`. Returns whether it matched.
    fn position_check(&mut self, head: &Head, observed_at: Option<&str>, what: &str) -> bool {
        let pos = (head.segment, head.record_id);
        let loc_ordinal = head.record_count;
        match self.interesting.get(&pos).copied().flatten() {
            None => {
                if self.walk_complete || self.report.violations.is_empty() {
                    self.violation_nostop(Finding {
                        kind: ViolationKind::CheckpointTruncated,
                        reason: None,
                        location: rec_loc(head.segment, head.record_id, loc_ordinal, 0),
                        evidence: Value::object([
                            (
                                "checkpoint_record_hash_hex",
                                Value::str(hex(&head.record_hash)),
                            ),
                            ("observed_at", observed_at.map(str::to_string).into()),
                            (
                                "records_inspected",
                                Value::Int(self.report.log.records_inspected),
                            ),
                        ]),
                        message: format!("the record named by the {what} is gone: history was cut"),
                    });
                }
                false
            },
            Some((hash, ordinal)) => {
                if hash != head.record_hash || ordinal != head.record_count {
                    self.violation_nostop(Finding {
                        kind: ViolationKind::CheckpointMismatch,
                        reason: None,
                        location: rec_loc(head.segment, head.record_id, ordinal, 0),
                        evidence: Value::object([
                            ("checkpoint_record_hash_hex", Value::str(hex(&head.record_hash))),
                            ("actual_record_hash_hex", Value::str(hex(&hash))),
                            ("checkpoint_record_count", Value::Int(head.record_count)),
                            ("actual_record_count", Value::Int(ordinal)),
                            ("observed_at", observed_at.map(str::to_string).into()),
                        ]),
                        message: format!("the record differs from the one the {what} names: history was rewritten"),
                    });
                    false
                } else {
                    true
                }
            },
        }
    }

    /// Spec §11.4 L3: the attested head.
    fn check_attested(&mut self) {
        let Some(a) = self.opts.attested.clone() else {
            return;
        };
        let Some(h) = self.seg0.clone() else {
            return;
        };
        if a.key_id.0 != h.key_id || a.alg.code() != h.sig_alg || a.head.log_id != h.log_id {
            self.violation_nostop(Finding {
                kind: ViolationKind::CheckpointMismatch,
                reason: None,
                location: Location::Segment { segment: 0 },
                evidence: Value::object([
                    ("attested_key_id_hex", Value::str(a.key_id.to_hex())),
                    ("actual_key_id_hex", Value::str(hex(&h.key_id))),
                    ("attested_log_id_hex", Value::str(hex(&a.head.log_id))),
                    ("actual_log_id_hex", Value::str(hex(&h.log_id))),
                ]),
                message: "this is not the log the release attests".into(),
            });
            return;
        }
        if self.position_check(&a.head, None, "release attestation") {
            self.attested_anchor = Some(a.head);
        }
    }

    fn finish(&mut self, anchored_by_cp: bool) {
        let attested_anchors = self.attested_anchor.is_some_and(|h| {
            self.last
                .as_ref()
                .is_some_and(|l| (l.segment, l.record) >= (h.segment, h.record_id))
        });
        let sealed_last = self.last.as_ref().is_some_and(|l| l.event == EVENT_SEALED);
        self.report.log.sealed = sealed_last;
        self.report.log.head_anchored = !self.ended_in_finalized_without_successor
            && (sealed_last || anchored_by_cp || attested_anchors);
        if self.attested_anchor.is_some() {
            // In a release, the attested head is the end that matters.
            self.report.log.head_anchored = true;
        }
        let records = self.report.log.records_inspected;
        self.report.verdict = if !self.report.violations.is_empty() {
            Verdict::Violation
        } else if self.trusted_sig {
            Verdict::Verified
        } else {
            self.report.not_verified_reason = Some(if records == 0 {
                NotVerifiedReason::NoSignedRecords
            } else {
                NotVerifiedReason::NotPinned
            });
            if let Some(s) = &mut self.report.signer {
                if records == 0 {
                    s.reason = SignerReason::NoSignedRecords;
                }
            }
            Verdict::SelfConsistent
        };
        self.report.log.head_ts_wall = self.last.as_ref().map(|l| l.ts_wall.clone());
    }
}
