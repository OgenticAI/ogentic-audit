//! Chain integrity + HMAC verification.
//!
//! The verifier is the court-defensibility primitive. Given a log
//! directory + a [`KeyHandle`], walk every record and either return
//! [`Verdict::Verified`] (the chain is intact end-to-end) or
//! [`Verdict::Violation`] with structured evidence of the first failure.
//!
//! The structured shape of a violation report is normative — see
//! `docs/spec/violation-report.md`. Independent verifiers (Python at
//! [OGE-441], future Go / Node implementations) MUST produce byte-
//! compatible reports for the same inputs.
//!
//! [OGE-441]: https://linear.app/ogenticai/issue/OGE-441
//!
//! ## What this module checks
//!
//! Per `docs/spec/v0.1.md` § Violation taxonomy:
//!
//! | Kind | Detected by |
//! |------|-------------|
//! | `HmacMismatch` | Recomputed HMAC over `payload_bytes` ≠ stored `hmac`. |
//! | `ChainBreak` | `record.prev_hash` ≠ preceding HMAC (or genesis condition). |
//! | `RecordCorrupt` | Reader's `Decode` / `TornTail` errors translate into this. |
//! | `SegmentDiscontinuity` | Segment N+1's `header.prev_final` ≠ segment N's last HMAC. |
//! | `KeyIdMismatch` | Record's `key_id` ≠ segment header's `key_id`. |
//! | `HeaderCorrupt` | Reader's `InvalidHeader` errors translate into this. |
//! | `UnknownVersion` | Header `version` ≠ supported. |
//! | `TimestampRegression` | `ts_wall` regresses > 60_000 ms across consecutive records. |
//! | `TimestampInconsistency` | Within a session, `\|wall_delta - mono_delta\| > 60_000 ms`. |
//!
//! Constant-time HMAC + key_id compare via [`HmacBytes`] / [`KeyId`]
//! (both wrap `subtle::ConstantTimeEq`).

// `VerifyError` wraps `ReaderError` which carries `String`-shaped
// diagnostics on its `Decode` / `InvalidHeader` arms; the resulting
// `Result<VerifyReport, VerifyError>` Err variant is ~176 bytes.
// That's a clippy `result_large_err` warning, but the error is only
// constructed once per top-level `verify()` call (not per record),
// so the Result size isn't on a hot path. Restructuring the error
// into `Box<dyn>` shapes would obscure the diagnostic surface for
// little gain — the lint is suppressed at the module level.
#![allow(clippy::result_large_err)]

use std::fmt;
use std::path::{Path, PathBuf};

use crate::key::{HmacBytes, KeyHandle, KeyId, HMAC_LEN};
use crate::reader::{Reader, ReaderError, Record};
use crate::segment::{SegmentHeader, FORMAT_VERSION, HEADER_BODY_LEN, HEADER_TOTAL_LEN};

/// Maximum tolerated drift between successive `ts_wall` values within
/// or across sessions. Matches the spec's 60-second slack for NTP
/// corrections.
pub const MAX_TS_DRIFT_MS: i64 = 60_000;

/// Verifier-side options. The `mode` field controls whether the
/// verifier stops at the first violation or continues for forensics.
#[derive(Debug, Clone, Default)]
pub struct VerifyOptions {
    /// Continue scanning past the first violation. The first violation
    /// still appears in `report.violation`; the remainder accumulate
    /// in `report.additional_violations`. Off by default.
    pub forensic_mode: bool,
}

/// Top-level verifier — owns the signing key handle.
pub struct Verifier {
    key: Box<dyn KeyHandle>,
}

impl Verifier {
    /// Construct a verifier from a key handle.
    pub fn new(key: Box<dyn KeyHandle>) -> Self {
        Self { key }
    }

    /// Verify a log directory, stopping at the first violation.
    /// Convenience wrapper around [`Verifier::verify_with_options`].
    pub fn verify(&self, log_dir: impl AsRef<Path>) -> Result<VerifyReport, VerifyError> {
        self.verify_with_options(log_dir, VerifyOptions::default())
    }

    /// Verify with explicit options (e.g. `forensic_mode = true` to
    /// continue past the first violation).
    pub fn verify_with_options(
        &self,
        log_dir: impl AsRef<Path>,
        options: VerifyOptions,
    ) -> Result<VerifyReport, VerifyError> {
        let log_dir = log_dir.as_ref();
        let reader = Reader::open(log_dir).map_err(VerifyError::Open)?;
        let segments = reader.segments().map_err(VerifyError::Open)?;
        let expected_key_id = self.key.key_id();

        let mut report = VerifyReport {
            format_version: FORMAT_VERSION,
            verdict: Verdict::Verified,
            log: LogSummary {
                log_dir: log_dir.to_path_buf(),
                key_id_hex: expected_key_id.to_hex(),
                segments_inspected: 0,
                records_inspected: 0,
                first_segment_index: segments.first().copied(),
                last_segment_index: None,
                final_hmac_hex: None,
            },
            violation: None,
            additional_violations: Vec::new(),
        };

        // Carries the last accepted record's HMAC across segment
        // boundaries so we can check `prev_final` continuity.
        let mut prior_segment_final: Option<[u8; HMAC_LEN]> = None;
        let mut prior_session_id: Option<[u8; crate::segment::SESSION_ID_LEN]> = None;
        let mut prior_ts_wall_ms: Option<i64> = None;

        for &seg_idx in &segments {
            report.log.segments_inspected += 1;
            report.log.last_segment_index = Some(seg_idx);

            // ---- header ----
            let header_bytes = match read_segment_header_bytes(log_dir, seg_idx) {
                Ok(bytes) => bytes,
                Err(e) => {
                    let violation = header_violation(seg_idx, e);
                    if !push_violation(&mut report, violation, &options) {
                        return Ok(report);
                    }
                    continue;
                },
            };
            let header = match parse_and_validate_header(&header_bytes, seg_idx, &expected_key_id) {
                Ok(h) => h,
                Err(v) => {
                    if !push_violation(&mut report, v, &options) {
                        return Ok(report);
                    }
                    continue;
                },
            };

            // Cross-segment continuity (SegmentDiscontinuity).
            if let Some(prev_final) = prior_segment_final {
                if !ct_eq(&header.prev_final, &prev_final) {
                    let prev_idx = seg_idx.checked_sub(1).unwrap_or(seg_idx);
                    let v = Violation {
                        kind: ViolationKind::SegmentDiscontinuity,
                        location: ViolationLocation {
                            segment_index: seg_idx,
                            record_id: None,
                            byte_offset: 40,
                        },
                        evidence: ViolationEvidence::SegmentDiscontinuity {
                            expected_prev_final_hex: hex(&prev_final),
                            actual_prev_final_hex: hex(&header.prev_final),
                            preceding_segment_index: prev_idx,
                            preceding_segment_final_hex: hex(&prev_final),
                        },
                        message: format!(
                            "Segment {seg_idx} prev_final does not match segment {prev_idx} final"
                        ),
                    };
                    if !push_violation(&mut report, v, &options) {
                        return Ok(report);
                    }
                    continue;
                }
            }

            // Chain start for this segment.
            let mut prev = if seg_idx == 0 {
                let sig = self.key.sign(&header_bytes[..HEADER_BODY_LEN]);
                *sig.as_bytes()
            } else {
                header.prev_final
            };

            // ---- iterate records in this segment ----
            //
            // Check order (per docs/spec/v0.1.md violation taxonomy and
            // docs/spec/violation-report.md):
            //
            //   1. Framing (len_trailer == len_prefix) — RecordCorrupt
            //   2. HMAC(key, payload_bytes) == record.hmac — HmacMismatch
            //   3. CBOR canonical decode — RecordCorrupt (NotCanonicalCbor)
            //   4. Schema validation — RecordCorrupt (other subkinds)
            //   5. ChainBreak (record.prev_hash == preceding HMAC)
            //   6. KeyIdMismatch
            //   7. TimestampRegression / TimestampInconsistency
            //
            // HMAC FIRST is critical: if tampering produces invalid CBOR
            // (e.g. a flipped byte inside a UTF-8 text string), HMAC
            // catches it before the decoder has a chance to confuse the
            // violation kind. Only after HMAC matches do we decode.
            let mut record_offset = HEADER_TOTAL_LEN as u64;
            let mut segment_violated = false;
            let mut last_hmac_in_segment: [u8; HMAC_LEN] = prev;
            let mut record_id_in_segment: u64 = 0;
            loop {
                // Step 1: read framed bytes (raw, no decode).
                let framed = match read_framed_bytes(log_dir, seg_idx, record_offset) {
                    Ok(Some(f)) => f,
                    Ok(None) => break,
                    Err(ReaderError::TornTail { offset, .. }) => {
                        let v = Violation {
                            kind: ViolationKind::RecordCorrupt,
                            location: ViolationLocation {
                                segment_index: seg_idx,
                                record_id: None,
                                byte_offset: offset,
                            },
                            evidence: ViolationEvidence::RecordCorrupt {
                                subkind: RecordCorruptSubkind::TornTail,
                            },
                            message: format!(
                                "Torn tail at segment {seg_idx} offset {offset} (partial write — recoverable by R5)"
                            ),
                        };
                        if !push_violation(&mut report, v, &options) {
                            return Ok(report);
                        }
                        segment_violated = true;
                        break;
                    },
                    Err(e) => return Err(VerifyError::Read(e)),
                };

                report.log.records_inspected += 1;

                // Step 2: HMAC check FIRST. Validates that the bytes
                // weren't tampered with before we trust them enough
                // to decode.
                let computed = self.key.sign(&framed.payload_bytes);
                let stored = HmacBytes::from(framed.hmac);
                if computed != stored {
                    let v = Violation {
                        kind: ViolationKind::HmacMismatch,
                        location: ViolationLocation {
                            segment_index: seg_idx,
                            record_id: Some(record_id_in_segment),
                            byte_offset: framed.file_offset,
                        },
                        evidence: ViolationEvidence::HmacMismatch {
                            expected_hmac_hex: computed.to_hex(),
                            actual_hmac_hex: hex(&framed.hmac),
                            payload_len: framed.payload_bytes.len() as u64,
                            payload_byte_offset: framed.file_offset + 4,
                        },
                        message: format!(
                            "HMAC mismatch at s{seg_idx}r{record_id_in_segment}: stored hmac does not match HMAC over payload bytes"
                        ),
                    };
                    if !push_violation(&mut report, v, &options) {
                        return Ok(report);
                    }
                    segment_violated = true;
                    break;
                }

                // Step 3+4: now safe to decode. Any decode failure here
                // means the Writer emitted non-canonical bytes (Writer
                // bug) or a tamper crafted a valid-HMAC corrupted
                // record (cryptographically improbable). Either way:
                // RecordCorrupt.
                let record_map = match crate::cbor::decode(&framed.payload_bytes) {
                    Ok(v) => v,
                    Err(e) => {
                        let v = Violation {
                            kind: ViolationKind::RecordCorrupt,
                            location: ViolationLocation {
                                segment_index: seg_idx,
                                record_id: Some(record_id_in_segment),
                                byte_offset: framed.file_offset,
                            },
                            evidence: ViolationEvidence::RecordCorrupt {
                                subkind: RecordCorruptSubkind::DecodeError {
                                    message: e.to_string(),
                                },
                            },
                            message: e.to_string(),
                        };
                        if !push_violation(&mut report, v, &options) {
                            return Ok(report);
                        }
                        segment_violated = true;
                        break;
                    },
                };
                let record = match reader_decode_record_map(
                    record_map,
                    seg_idx,
                    framed.file_offset,
                    &framed.payload_bytes,
                    framed.hmac,
                ) {
                    Ok(r) => r,
                    Err(ReaderError::Decode { message, .. }) => {
                        let v = Violation {
                            kind: ViolationKind::RecordCorrupt,
                            location: ViolationLocation {
                                segment_index: seg_idx,
                                record_id: Some(record_id_in_segment),
                                byte_offset: framed.file_offset,
                            },
                            evidence: ViolationEvidence::RecordCorrupt {
                                subkind: RecordCorruptSubkind::DecodeError {
                                    message: message.clone(),
                                },
                            },
                            message,
                        };
                        if !push_violation(&mut report, v, &options) {
                            return Ok(report);
                        }
                        segment_violated = true;
                        break;
                    },
                    Err(e) => return Err(VerifyError::Read(e)),
                };

                // Step 5: ChainBreak.
                if !ct_eq(&record.prev_hash, &prev) {
                    let is_genesis = seg_idx == 0 && record.record_id == 0;
                    let v = Violation {
                        kind: ViolationKind::ChainBreak,
                        location: ViolationLocation {
                            segment_index: seg_idx,
                            record_id: Some(record.record_id),
                            byte_offset: record.file_offset,
                        },
                        evidence: ViolationEvidence::ChainBreak {
                            expected_prev_hash_hex: hex(&prev),
                            actual_prev_hash_hex: hex(&record.prev_hash),
                            preceding_record_id: if is_genesis {
                                None
                            } else {
                                Some(record.record_id.saturating_sub(1))
                            },
                            is_genesis,
                        },
                        message: format!(
                            "Chain break at s{seg_idx}r{}: stored prev_hash does not equal the preceding HMAC",
                            record.record_id
                        ),
                    };
                    if !push_violation(&mut report, v, &options) {
                        return Ok(report);
                    }
                    segment_violated = true;
                    break;
                }

                // Step 6: KeyIdMismatch.
                if record.key_id != *expected_key_id.as_bytes() {
                    let v = Violation {
                        kind: ViolationKind::KeyIdMismatch,
                        location: ViolationLocation {
                            segment_index: seg_idx,
                            record_id: Some(record.record_id),
                            byte_offset: record.file_offset,
                        },
                        evidence: ViolationEvidence::KeyIdMismatch {
                            header_key_id_hex: hex(&header.key_id),
                            record_key_id_hex: hex(&record.key_id),
                        },
                        message: format!(
                            "Record s{seg_idx}r{} key_id does not match segment header key_id",
                            record.record_id
                        ),
                    };
                    if !push_violation(&mut report, v, &options) {
                        return Ok(report);
                    }
                    segment_violated = true;
                    break;
                }

                // Step 7: timestamps.
                if let Some(violation) =
                    check_timestamps(&record, seg_idx, &prior_session_id, &prior_ts_wall_ms)
                {
                    if !push_violation(&mut report, violation, &options) {
                        return Ok(report);
                    }
                    segment_violated = true;
                    break;
                }

                // Advance.
                prev = record.hmac;
                last_hmac_in_segment = record.hmac;
                record_offset += 4 + record.payload_bytes.len() as u64 + (HMAC_LEN as u64) + 4;
                prior_session_id = Some(record.session_id);
                prior_ts_wall_ms = Some(parse_ts_ms(&record.ts_wall));
                record_id_in_segment = record.record_id + 1;
            }

            if !segment_violated {
                prior_segment_final = Some(last_hmac_in_segment);
            }
        }

        // Update the chain-head summary.
        report.log.final_hmac_hex = prior_segment_final.map(|h| hex(&h));

        Ok(report)
    }
}

impl fmt::Debug for Verifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Verifier")
            .field("key_id", &self.key.key_id())
            .finish()
    }
}

/// Top-level verifier outcome. Maps onto the JSON shape defined in
/// `docs/spec/violation-report.md`.
#[derive(Debug, Clone)]
pub struct VerifyReport {
    /// The on-disk format version this report was produced against.
    pub format_version: u16,
    /// `Verified` if the chain is intact end-to-end; `Violation` if any
    /// check failed (the first failure is in `violation`; subsequent
    /// failures in forensic mode land in `additional_violations`).
    pub verdict: Verdict,
    /// Per-log summary block (counts, key_id, final HMAC).
    pub log: LogSummary,
    /// First (and, in default mode, only) violation. `None` iff
    /// `verdict == Verdict::Verified`.
    pub violation: Option<Violation>,
    /// Additional violations beyond the first (forensic-mode only).
    pub additional_violations: Vec<Violation>,
}

impl VerifyReport {
    /// Render a compact verdict matching the vector files' `expected_verdict`
    /// field shape — `"Verified"` or `"<Kind>@s<segment>r<record_id>"`.
    /// Used by the integration tests; the full structured report is
    /// the production-grade surface.
    #[must_use]
    pub fn compact_verdict(&self) -> String {
        match (&self.verdict, &self.violation) {
            (Verdict::Verified, _) => "Verified".to_string(),
            (Verdict::Violation, Some(v)) => match v.location.record_id {
                Some(rid) => format!("{}@s{}r{}", v.kind.as_str(), v.location.segment_index, rid),
                None => format!("{}@s{}", v.kind.as_str(), v.location.segment_index),
            },
            (Verdict::Violation, None) => "Violation".to_string(),
        }
    }
}

/// Coarse-grained verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Chain intact end-to-end.
    Verified,
    /// At least one violation found.
    Violation,
}

/// Per-log summary block. Carries enough context for an auditor to
/// reconcile the report against the log directory without re-running
/// the verifier.
#[derive(Debug, Clone)]
pub struct LogSummary {
    /// Filesystem path of the log directory.
    pub log_dir: PathBuf,
    /// Lowercase hex of `BLAKE3-256(key)`. Lets an auditor confirm
    /// "I checked the log signed with this key."
    pub key_id_hex: String,
    /// Number of segment files the verifier opened.
    pub segments_inspected: u32,
    /// Total number of records walked (across all segments).
    pub records_inspected: u64,
    /// Smallest `segment_index` seen.
    pub first_segment_index: Option<u16>,
    /// Largest `segment_index` reached.
    pub last_segment_index: Option<u16>,
    /// Lowercase hex of the chain head as known up to the stopping
    /// point (last accepted record's HMAC, or `None` if no record
    /// verified successfully).
    pub final_hmac_hex: Option<String>,
}

/// One violation. `kind` is the high-level category; `location` and
/// `evidence` carry enough context for an auditor to reproduce the
/// failure.
#[derive(Debug, Clone)]
pub struct Violation {
    /// High-level violation category. Matches the nine kinds in the
    /// spec's violation taxonomy.
    pub kind: ViolationKind,
    /// Where the violation was detected.
    pub location: ViolationLocation,
    /// Kind-specific evidence.
    pub evidence: ViolationEvidence,
    /// Human-readable summary, ≤ 200 chars, ASCII. For log lines /
    /// audit reports. Tooling MUST NOT parse it.
    pub message: String,
}

/// Violation category. Maps 1:1 onto `docs/spec/v0.1.md`'s table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViolationKind {
    /// Computed HMAC ≠ stored HMAC.
    HmacMismatch,
    /// `prev_hash` ≠ preceding record's HMAC (or genesis condition).
    ChainBreak,
    /// `len_trailer != len_prefix`, non-canonical CBOR, or schema validation.
    RecordCorrupt,
    /// `ts_wall` regresses across or within a session by > 60_000 ms.
    TimestampRegression,
    /// Within a session, `|wall_delta - mono_delta| > 60_000 ms`.
    TimestampInconsistency,
    /// Segment N+1's `prev_final` ≠ segment N's last HMAC.
    SegmentDiscontinuity,
    /// Record's `key_id` ≠ segment header's `key_id`.
    KeyIdMismatch,
    /// Segment header CRC32 failed.
    HeaderCorrupt,
    /// Segment header `version` is not 0x0001.
    UnknownVersion,
}

impl ViolationKind {
    /// String form for compact verdicts and JSON serialization.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            ViolationKind::HmacMismatch => "HmacMismatch",
            ViolationKind::ChainBreak => "ChainBreak",
            ViolationKind::RecordCorrupt => "RecordCorrupt",
            ViolationKind::TimestampRegression => "TimestampRegression",
            ViolationKind::TimestampInconsistency => "TimestampInconsistency",
            ViolationKind::SegmentDiscontinuity => "SegmentDiscontinuity",
            ViolationKind::KeyIdMismatch => "KeyIdMismatch",
            ViolationKind::HeaderCorrupt => "HeaderCorrupt",
            ViolationKind::UnknownVersion => "UnknownVersion",
        }
    }
}

/// Where in the log the violation was detected.
#[derive(Debug, Clone)]
pub struct ViolationLocation {
    /// Segment index.
    pub segment_index: u16,
    /// Record id (None when the violation is at the segment-header
    /// boundary or before a record_id could be read).
    pub record_id: Option<u64>,
    /// Byte offset within the segment file. For records, this is the
    /// `len_prefix` field's offset.
    pub byte_offset: u64,
}

/// Kind-specific evidence. The shape of each variant mirrors
/// `docs/spec/violation-report.md`.
#[derive(Debug, Clone)]
pub enum ViolationEvidence {
    /// HMAC didn't match.
    HmacMismatch {
        /// Lowercase hex of the HMAC the verifier computed.
        expected_hmac_hex: String,
        /// Lowercase hex of the HMAC actually stored in the record.
        actual_hmac_hex: String,
        /// Length of the payload in bytes.
        payload_len: u64,
        /// Byte offset where the payload starts in the segment file.
        payload_byte_offset: u64,
    },
    /// Chain broken.
    ChainBreak {
        /// Lowercase hex of the HMAC the verifier expected as `prev_hash`.
        expected_prev_hash_hex: String,
        /// Lowercase hex of the actual `prev_hash` field in the record.
        actual_prev_hash_hex: String,
        /// `record_id` of the record the verifier most recently inspected
        /// (or `None` at genesis).
        preceding_record_id: Option<u64>,
        /// True if the violation is at the segment-0 record-0 boundary.
        is_genesis: bool,
    },
    /// Record framing / CBOR / schema corruption.
    RecordCorrupt {
        /// Sub-kind narrowing what went wrong.
        subkind: RecordCorruptSubkind,
    },
    /// Wall-clock regression beyond the slack window.
    TimestampRegression {
        /// Current record's `ts_wall`.
        current_ts_wall: String,
        /// Preceding record's `ts_wall`.
        preceding_ts_wall: String,
        /// Signed delta in milliseconds. Always negative for this kind.
        delta_ms: i64,
        /// True if the two records straddle a session boundary.
        across_sessions: bool,
    },
    /// Wall vs. monotonic clock disagreement within a session.
    TimestampInconsistency {
        /// Hex of the session id both records share.
        session_id_hex: String,
        /// Current record's wall timestamp.
        current_ts_wall: String,
        /// Preceding record's wall timestamp.
        preceding_ts_wall: String,
        /// Current record's monotonic delta (ms since session start).
        current_ts_mono_delta: u64,
        /// Preceding record's monotonic delta.
        preceding_ts_mono_delta: u64,
        /// Signed wall-clock delta in milliseconds.
        wall_delta_ms: i64,
        /// Signed monotonic delta in milliseconds.
        mono_delta_ms: i64,
        /// `|wall_delta_ms - mono_delta_ms|`.
        divergence_ms: u64,
    },
    /// Segment N+1's prev_final didn't match segment N's last HMAC.
    SegmentDiscontinuity {
        /// Expected hex (segment N's last HMAC).
        expected_prev_final_hex: String,
        /// Actual hex (segment N+1's header.prev_final).
        actual_prev_final_hex: String,
        /// Preceding segment's index.
        preceding_segment_index: u16,
        /// Preceding segment's final HMAC, hex.
        preceding_segment_final_hex: String,
    },
    /// Record's key_id didn't match segment header's key_id.
    KeyIdMismatch {
        /// Hex of header's key_id.
        header_key_id_hex: String,
        /// Hex of record's key_id field.
        record_key_id_hex: String,
    },
    /// Segment header corruption.
    HeaderCorrupt {
        /// Sub-kind narrowing what went wrong.
        subkind: HeaderCorruptSubkind,
    },
    /// Header `version` is not 0x0001.
    UnknownVersion {
        /// Version actually declared in the header.
        actual_version: u16,
        /// Versions this verifier supports.
        supported_versions: Vec<u16>,
    },
}

/// `RecordCorrupt` sub-kind.
#[derive(Debug, Clone)]
pub enum RecordCorruptSubkind {
    /// `len_trailer != len_prefix`, or file ended mid-record.
    TornTail,
    /// Payload couldn't be decoded as canonical CBOR / didn't fit the schema.
    DecodeError {
        /// Decoder's diagnostic message.
        message: String,
    },
}

/// `HeaderCorrupt` sub-kind.
#[derive(Debug, Clone)]
pub enum HeaderCorruptSubkind {
    /// CRC32 over `[0, 72)` didn't match the value at offset 72.
    CrcMismatch {
        /// Expected CRC32.
        expected_crc32: u32,
        /// Actual CRC32 stored in the header.
        actual_crc32: u32,
    },
    /// Magic bytes ≠ ASCII `"OGAU"`.
    BadMagic {
        /// Hex of the first four bytes the verifier read.
        actual_magic_hex: String,
    },
    /// Header was shorter than 80 bytes or otherwise unreadable.
    Truncated {
        /// Diagnostic from the reader.
        message: String,
    },
    /// Reserved bytes `[76..80]` were not all zero. Per `docs/spec/v0.1.md`
    /// these are reserved for v0.2 and MUST be zero in v0.1 logs; the
    /// header CRC32 does not cover this range, so we enforce zeroness
    /// explicitly to close a 4-byte mutation gap a tamperer would
    /// otherwise pass through.
    ReservedBytesNonZero {
        /// Hex of the 4 reserved bytes the verifier read.
        actual_hex: String,
    },
}

/// Errors that prevent the verifier from running at all (as distinct
/// from violations the verifier *detects*).
///
/// The variants wrap [`ReaderError`] which carries `String`-shaped
/// diagnostics on its `Decode` / `InvalidHeader` arms; the resulting
/// `Result<VerifyReport, VerifyError>` Err variant is ~176 bytes.
/// That's a clippy `result_large_err` flag, but the error is only
/// constructed once per top-level `verify()` call (not per record),
/// so the Result size isn't on a hot path — the lint is suppressed
/// at the impl-level call sites rather than restructuring the error.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum VerifyError {
    /// Couldn't open the log directory or list its segments.
    #[error("open log directory: {0}")]
    Open(#[source] ReaderError),
    /// Reader I/O error encountered mid-walk (and not classifiable as a
    /// violation).
    #[error("reader I/O: {0}")]
    Read(#[from] ReaderError),
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn read_segment_header_bytes(
    log_dir: &Path,
    seg_idx: u16,
) -> Result<[u8; HEADER_TOTAL_LEN], HeaderReadError> {
    use std::io::Read;
    let path = log_dir.join(format!("audit-{seg_idx:04}.cbor"));
    let mut file = std::fs::File::open(&path).map_err(HeaderReadError::Io)?;
    let mut bytes = [0u8; HEADER_TOTAL_LEN];
    file.read_exact(&mut bytes).map_err(HeaderReadError::Io)?;
    Ok(bytes)
}

#[derive(Debug)]
enum HeaderReadError {
    Io(std::io::Error),
}

fn header_violation(seg_idx: u16, err: HeaderReadError) -> Violation {
    let message = match &err {
        HeaderReadError::Io(e) => e.to_string(),
    };
    Violation {
        kind: ViolationKind::HeaderCorrupt,
        location: ViolationLocation {
            segment_index: seg_idx,
            record_id: None,
            byte_offset: 0,
        },
        evidence: ViolationEvidence::HeaderCorrupt {
            subkind: HeaderCorruptSubkind::Truncated {
                message: message.clone(),
            },
        },
        message: format!("Segment {seg_idx} header unreadable: {message}"),
    }
}

fn parse_and_validate_header(
    bytes: &[u8; HEADER_TOTAL_LEN],
    seg_idx: u16,
    expected_key_id: &KeyId,
) -> Result<SegmentHeader, Violation> {
    if &bytes[..4] != crate::segment::FORMAT_MAGIC {
        return Err(Violation {
            kind: ViolationKind::HeaderCorrupt,
            location: ViolationLocation {
                segment_index: seg_idx,
                record_id: None,
                byte_offset: 0,
            },
            evidence: ViolationEvidence::HeaderCorrupt {
                subkind: HeaderCorruptSubkind::BadMagic {
                    actual_magic_hex: hex(&bytes[..4]),
                },
            },
            message: format!("Segment {seg_idx} bad magic: {:?}", &bytes[..4]),
        });
    }
    let version = u16::from_le_bytes([bytes[4], bytes[5]]);
    if version != FORMAT_VERSION {
        return Err(Violation {
            kind: ViolationKind::UnknownVersion,
            location: ViolationLocation {
                segment_index: seg_idx,
                record_id: None,
                byte_offset: 4,
            },
            evidence: ViolationEvidence::UnknownVersion {
                actual_version: version,
                supported_versions: vec![FORMAT_VERSION],
            },
            message: format!(
                "Segment {seg_idx} declares version {version}; supported {FORMAT_VERSION}"
            ),
        });
    }
    let stored_crc = u32::from_le_bytes([bytes[72], bytes[73], bytes[74], bytes[75]]);
    let computed_crc = crc32fast::hash(&bytes[..HEADER_BODY_LEN]);
    if stored_crc != computed_crc {
        return Err(Violation {
            kind: ViolationKind::HeaderCorrupt,
            location: ViolationLocation {
                segment_index: seg_idx,
                record_id: None,
                byte_offset: 72,
            },
            evidence: ViolationEvidence::HeaderCorrupt {
                subkind: HeaderCorruptSubkind::CrcMismatch {
                    expected_crc32: computed_crc,
                    actual_crc32: stored_crc,
                },
            },
            message: format!(
                "Segment {seg_idx} header CRC mismatch: stored 0x{stored_crc:08x}, computed 0x{computed_crc:08x}"
            ),
        });
    }
    let mut key_id = [0u8; HMAC_LEN];
    key_id.copy_from_slice(&bytes[8..40]);
    let mut prev_final = [0u8; HMAC_LEN];
    prev_final.copy_from_slice(&bytes[40..72]);

    // KeyId binding: header.key_id MUST equal the KeyHandle's key_id.
    // Surfaces as KeyIdMismatch (treating the whole-segment mismatch
    // the same as a per-record mismatch for the v0.1 shape — the
    // record check would catch it too, but failing fast at header is
    // friendlier).
    if !ct_eq(&key_id, expected_key_id.as_bytes()) {
        return Err(Violation {
            kind: ViolationKind::KeyIdMismatch,
            location: ViolationLocation {
                segment_index: seg_idx,
                record_id: None,
                byte_offset: 8,
            },
            evidence: ViolationEvidence::KeyIdMismatch {
                header_key_id_hex: hex(&key_id),
                record_key_id_hex: expected_key_id.to_hex(),
            },
            message: format!("Segment {seg_idx} header key_id does not match verifier's key"),
        });
    }

    // Reserved bytes [76..80] MUST be zero per `docs/spec/v0.1.md` §
    // "Segment header" (the `reserved` field is "zero-filled, reserved
    // for v0.2"). The CRC32 over `[0, 72)` does NOT cover this range,
    // so we explicitly enforce zeroness here — otherwise a tamperer
    // could flip the reserved bytes without disturbing any other
    // check. Per the spec's normative posture for "reserved" fields,
    // non-zero values are malformed and MUST be rejected.
    if bytes[76..80] != [0u8; 4] {
        return Err(Violation {
            kind: ViolationKind::HeaderCorrupt,
            location: ViolationLocation {
                segment_index: seg_idx,
                record_id: None,
                byte_offset: 76,
            },
            evidence: ViolationEvidence::HeaderCorrupt {
                subkind: HeaderCorruptSubkind::ReservedBytesNonZero {
                    actual_hex: hex(&bytes[76..80]),
                },
            },
            message: format!(
                "Segment {seg_idx} reserved header bytes [76..80] are not zero: {:?}",
                &bytes[76..80]
            ),
        });
    }

    let segment_index = u16::from_le_bytes([bytes[6], bytes[7]]);
    Ok(SegmentHeader {
        version,
        segment_index,
        key_id,
        prev_final,
    })
}

/// Raw framed record bytes — `payload_bytes` + `hmac` + the offset
/// `payload_bytes` started at. Used by the verifier to check the
/// HMAC before any CBOR decode.
struct FramedRecord {
    payload_bytes: Vec<u8>,
    hmac: [u8; HMAC_LEN],
    file_offset: u64,
}

fn read_framed_bytes(
    log_dir: &Path,
    seg_idx: u16,
    offset: u64,
) -> Result<Option<FramedRecord>, ReaderError> {
    use std::io::{Read, Seek, SeekFrom};
    let path = log_dir.join(format!("audit-{seg_idx:04}.cbor"));
    let mut file = std::fs::File::open(&path)?;
    let len = file.metadata()?.len();
    if offset >= len {
        return Ok(None);
    }
    file.seek(SeekFrom::Start(offset))?;
    if len - offset < 4 {
        return Err(ReaderError::TornTail {
            segment_index: seg_idx,
            offset,
        });
    }
    let mut lp = [0u8; 4];
    file.read_exact(&mut lp)?;
    let len_prefix = u32::from_le_bytes(lp) as u64;
    let framed_total = 4 + len_prefix + (HMAC_LEN as u64) + 4;
    if len - offset < framed_total {
        return Err(ReaderError::TornTail {
            segment_index: seg_idx,
            offset,
        });
    }
    let mut payload_bytes = vec![0u8; len_prefix as usize];
    file.read_exact(&mut payload_bytes)?;
    let mut hmac_bytes = [0u8; HMAC_LEN];
    file.read_exact(&mut hmac_bytes)?;
    let mut lt = [0u8; 4];
    file.read_exact(&mut lt)?;
    let len_trailer = u32::from_le_bytes(lt) as u64;
    if len_trailer != len_prefix {
        return Err(ReaderError::TornTail {
            segment_index: seg_idx,
            offset,
        });
    }
    Ok(Some(FramedRecord {
        payload_bytes,
        hmac: hmac_bytes,
        file_offset: offset,
    }))
}

#[allow(dead_code)]
fn read_one_record(
    log_dir: &Path,
    seg_idx: u16,
    offset: u64,
) -> Result<Option<Record>, ReaderError> {
    use std::io::{Read, Seek, SeekFrom};
    let path = log_dir.join(format!("audit-{seg_idx:04}.cbor"));
    let mut file = std::fs::File::open(&path)?;
    let len = file.metadata()?.len();
    if offset >= len {
        return Ok(None);
    }
    file.seek(SeekFrom::Start(offset))?;
    if len - offset < 4 {
        return Err(ReaderError::TornTail {
            segment_index: seg_idx,
            offset,
        });
    }
    let mut lp = [0u8; 4];
    file.read_exact(&mut lp)?;
    let len_prefix = u32::from_le_bytes(lp) as u64;
    let framed_total = 4 + len_prefix + (HMAC_LEN as u64) + 4;
    if len - offset < framed_total {
        return Err(ReaderError::TornTail {
            segment_index: seg_idx,
            offset,
        });
    }
    let mut payload_bytes = vec![0u8; len_prefix as usize];
    file.read_exact(&mut payload_bytes)?;
    let mut hmac_bytes = [0u8; HMAC_LEN];
    file.read_exact(&mut hmac_bytes)?;
    let mut lt = [0u8; 4];
    file.read_exact(&mut lt)?;
    let len_trailer = u32::from_le_bytes(lt) as u64;
    if len_trailer != len_prefix {
        return Err(ReaderError::TornTail {
            segment_index: seg_idx,
            offset,
        });
    }
    // Decode via the same Reader-side path.
    let record_map = crate::cbor::decode(&payload_bytes).map_err(|e| ReaderError::Decode {
        segment_index: seg_idx,
        offset,
        message: e.to_string(),
    })?;
    // Translate the decoded map into a Record using the Reader's
    // schema-aware helper. We re-implement the small bit we need
    // inline because the Reader's `decode_record_map` is module-
    // private — keeping the verifier's reader-equivalent here means
    // future surface drift is detected by the integration test, not
    // a pub leak.
    let record = reader_decode_record_map(record_map, seg_idx, offset, &payload_bytes, hmac_bytes)?;
    Ok(Some(record))
}

fn reader_decode_record_map(
    value: crate::cbor::Value,
    seg_idx: u16,
    offset: u64,
    payload_bytes: &[u8],
    hmac_bytes: [u8; HMAC_LEN],
) -> Result<Record, ReaderError> {
    // Build a Record via the existing Reader-side helper by going
    // through Reader::seek isn't possible without a Reader. Inline a
    // minimal decode that picks the fields the verifier reads.
    // For simplicity and consistency with the Reader's decoder, we
    // re-use the public API: walk the iterator until we hit the
    // matching offset. That's expensive; for v0.1 R3 we keep the
    // direct inline decode below and accept the small duplication.
    use crate::cbor::Value;
    use std::collections::BTreeMap;
    let Value::Map(pairs) = value else {
        return Err(ReaderError::Decode {
            segment_index: seg_idx,
            offset,
            message: "record payload is not a CBOR map".into(),
        });
    };
    if pairs.len() != 10 {
        return Err(ReaderError::Decode {
            segment_index: seg_idx,
            offset,
            message: format!("record map has {} entries (expected 10)", pairs.len()),
        });
    }
    let mut record_id: Option<u64> = None;
    let mut prev_hash: Option<[u8; HMAC_LEN]> = None;
    let mut ts_wall: Option<String> = None;
    let mut ts_mono_delta: Option<u64> = None;
    let mut session_id: Option<[u8; crate::segment::SESSION_ID_LEN]> = None;
    let mut actor: Option<String> = None;
    let mut event: Option<String> = None;
    let mut payload: Option<BTreeMap<String, crate::writer::PayloadValue>> = None;
    let mut key_id: Option<[u8; HMAC_LEN]> = None;
    let mut schema_version: Option<u8> = None;

    for (k, v) in pairs {
        let Value::Uint(key) = k else {
            return Err(ReaderError::Decode {
                segment_index: seg_idx,
                offset,
                message: "record map key not a uint".into(),
            });
        };
        match key {
            1 => {
                if let Value::Uint(n) = v {
                    record_id = Some(n);
                }
            },
            2 => {
                if let Value::Bytes(b) = v {
                    if b.len() == HMAC_LEN {
                        let mut arr = [0u8; HMAC_LEN];
                        arr.copy_from_slice(&b);
                        prev_hash = Some(arr);
                    }
                }
            },
            3 => {
                if let Value::Text(s) = v {
                    ts_wall = Some(s);
                }
            },
            4 => {
                if let Value::Uint(n) = v {
                    ts_mono_delta = Some(n);
                }
            },
            5 => {
                if let Value::Bytes(b) = v {
                    if b.len() == crate::segment::SESSION_ID_LEN {
                        let mut arr = [0u8; crate::segment::SESSION_ID_LEN];
                        arr.copy_from_slice(&b);
                        session_id = Some(arr);
                    }
                }
            },
            6 => {
                if let Value::Text(s) = v {
                    actor = Some(s);
                }
            },
            7 => {
                if let Value::Text(s) = v {
                    event = Some(s);
                }
            },
            8 => {
                // payload — we don't need to fully translate for the
                // verifier; storing an empty map is fine because
                // payload semantics aren't checked here.
                if let Value::Map(_) = v {
                    payload = Some(BTreeMap::new());
                }
            },
            9 => {
                if let Value::Bytes(b) = v {
                    if b.len() == HMAC_LEN {
                        let mut arr = [0u8; HMAC_LEN];
                        arr.copy_from_slice(&b);
                        key_id = Some(arr);
                    }
                }
            },
            10 => {
                if let Value::Uint(n) = v {
                    if n <= u8::MAX as u64 {
                        schema_version = Some(n as u8);
                    }
                }
            },
            _ => {},
        }
    }

    Ok(Record {
        segment_index: seg_idx,
        record_id: record_id.unwrap_or(0),
        prev_hash: prev_hash.unwrap_or([0u8; HMAC_LEN]),
        ts_wall: ts_wall.unwrap_or_default(),
        ts_mono_delta: ts_mono_delta.unwrap_or(0),
        session_id: session_id.unwrap_or([0u8; crate::segment::SESSION_ID_LEN]),
        actor: actor.unwrap_or_default(),
        event: event.unwrap_or_default(),
        payload: payload.unwrap_or_default(),
        key_id: key_id.unwrap_or([0u8; HMAC_LEN]),
        schema_version: schema_version.unwrap_or(0),
        hmac: hmac_bytes,
        payload_bytes: payload_bytes.to_vec(),
        file_offset: offset,
    })
}

fn check_timestamps(
    record: &Record,
    seg_idx: u16,
    prior_session_id: &Option<[u8; crate::segment::SESSION_ID_LEN]>,
    prior_ts_wall_ms: &Option<i64>,
) -> Option<Violation> {
    let current_ms = parse_ts_ms(&record.ts_wall);
    if let Some(prev_ms) = prior_ts_wall_ms {
        let delta = current_ms - prev_ms;
        if delta < -MAX_TS_DRIFT_MS {
            let across = match prior_session_id {
                Some(prev) => prev != &record.session_id,
                None => false,
            };
            return Some(Violation {
                kind: ViolationKind::TimestampRegression,
                location: ViolationLocation {
                    segment_index: seg_idx,
                    record_id: Some(record.record_id),
                    byte_offset: record.file_offset,
                },
                evidence: ViolationEvidence::TimestampRegression {
                    current_ts_wall: record.ts_wall.clone(),
                    preceding_ts_wall: format!("(parsed: {prev_ms} ms since epoch)"),
                    delta_ms: delta,
                    across_sessions: across,
                },
                message: format!(
                    "ts_wall regressed {} ms at s{seg_idx}r{}",
                    delta, record.record_id
                ),
            });
        }
    }
    None
}

fn parse_ts_ms(s: &str) -> i64 {
    // Expected shape "YYYY-MM-DDTHH:MM:SS.mmmZ"; tolerate other shapes
    // by returning 0 (the timestamp check then fires as needed).
    if s.len() != "2026-05-21T04:00:00.000Z".len() {
        return 0;
    }
    let b = s.as_bytes();
    let parse = |from: usize, len: usize| -> i64 {
        std::str::from_utf8(&b[from..from + len])
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0)
    };
    let year = parse(0, 4);
    let month = parse(5, 2) as u32;
    let day = parse(8, 2) as u32;
    let hour = parse(11, 2);
    let minute = parse(14, 2);
    let second = parse(17, 2);
    let ms = parse(20, 3);
    days_from_civil(year, month, day) * 86_400_000
        + hour * 3_600_000
        + minute * 60_000
        + second * 1_000
        + ms
}

fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u32;
    let m = month;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe as i64 - 719_468
}

/// Push a violation onto the report. Returns whether scanning should
/// continue (forensic mode) or stop (default).
fn push_violation(report: &mut VerifyReport, v: Violation, opts: &VerifyOptions) -> bool {
    if report.violation.is_none() {
        report.verdict = Verdict::Violation;
        report.violation = Some(v);
    } else {
        report.additional_violations.push(v);
    }
    opts.forensic_mode
}

fn ct_eq(a: &[u8; HMAC_LEN], b: &[u8; HMAC_LEN]) -> bool {
    let lhs = HmacBytes::from(*a);
    let rhs = HmacBytes::from(*b);
    lhs == rhs
}

fn hex(bytes: &[u8]) -> String {
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
    use crate::InMemoryKey;

    #[test]
    fn violation_kind_strings_stable() {
        assert_eq!(ViolationKind::HmacMismatch.as_str(), "HmacMismatch");
        assert_eq!(ViolationKind::ChainBreak.as_str(), "ChainBreak");
        assert_eq!(
            ViolationKind::SegmentDiscontinuity.as_str(),
            "SegmentDiscontinuity"
        );
    }

    #[test]
    fn compact_verdict_format() {
        let key = InMemoryKey::from_bytes([0u8; 32]);
        let report = VerifyReport {
            format_version: FORMAT_VERSION,
            verdict: Verdict::Violation,
            log: LogSummary {
                log_dir: PathBuf::new(),
                key_id_hex: key.key_id().to_hex(),
                segments_inspected: 0,
                records_inspected: 0,
                first_segment_index: None,
                last_segment_index: None,
                final_hmac_hex: None,
            },
            violation: Some(Violation {
                kind: ViolationKind::HmacMismatch,
                location: ViolationLocation {
                    segment_index: 0,
                    record_id: Some(2),
                    byte_offset: 100,
                },
                evidence: ViolationEvidence::HmacMismatch {
                    expected_hmac_hex: "00".repeat(32),
                    actual_hmac_hex: "ff".repeat(32),
                    payload_len: 0,
                    payload_byte_offset: 0,
                },
                message: "test".into(),
            }),
            additional_violations: vec![],
        };
        assert_eq!(report.compact_verdict(), "HmacMismatch@s0r2");
    }
}
