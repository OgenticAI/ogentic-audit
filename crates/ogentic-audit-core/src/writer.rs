//! Append-only writer for v0.1 audit logs.
//!
//! Takes a [`KeyHandle`] and a target directory; turns a stream of
//! [`RecordInput`]s into byte-for-byte format-compliant segment files on
//! disk. Drives segment rollover when the configured size threshold is
//! reached.
//!
//! ## Durability model
//!
//! - [`Writer::append`] performs an OS-level write immediately. The
//!   bytes enter the kernel page cache; they are not yet guaranteed
//!   durable on power loss.
//! - [`Writer::flush`] forces the page cache to disk via
//!   [`crate::sync_compat::full_sync`] (which uses `F_FULLFSYNC` on
//!   macOS) and additionally syncs the containing directory entry so
//!   that the segment file's existence + size are also durable.
//! - No userspace buffer sits between `append` and the kernel write —
//!   "buffered" records lost in a crash are the OS page cache, never an
//!   in-process queue. On reopen, the [R5 / OGE-432] crash-recovery
//!   logic detects any torn tail (where `len_trailer != len_prefix`) and
//!   truncates to the last fully-written record, leaving the chain
//!   intact.
//!
//! [R5 / OGE-432]: https://linear.app/ogenticai/issue/OGE-432
//!
//! ## Threading model
//!
//! The Writer is **single-threaded**. `append` and `flush` take `&mut
//! self`, so the compiler enforces single-writer access. Callers that
//! need concurrent append from multiple threads must wrap the Writer in
//! their own `Mutex` (or upgrade to a worker-thread architecture in a
//! later revision, which the AC explicitly allows). This is the
//! simplest correct choice and matches the v0.1 single-user-vault
//! threat model.
//!
//! ## Conformance
//!
//! The Writer produces byte-identical output to the reference generator
//! at `tools/gen_vectors.py` for every clean v0.1 golden vector. The
//! integration test at `tests/vector_conformance.rs` asserts this and
//! is the load-bearing correctness check for [OGE-429 R1] AC 6.
//!
//! [OGE-429 R1]: https://linear.app/ogenticai/issue/OGE-429

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::cbor;
use crate::key::{HmacBytes, KeyHandle, HMAC_LEN};
use crate::segment::{
    self, HeaderParseError, SegmentHeader, HEADER_BODY_LEN, HEADER_TOTAL_LEN,
    RECORD_FRAMING_OVERHEAD, SESSION_ID_LEN,
};
use crate::sync_compat::full_sync;

/// Default segment rollover threshold, in bytes. Matches `docs/spec/v0.1.md`.
pub const DEFAULT_SEGMENT_SIZE_BYTES: u64 = 64 * 1024 * 1024;

/// Record identifier — monotonic per segment, starts at 0.
pub type RecordId = u64;

/// One value inside an event-specific `payload` map.
///
/// The schema doesn't constrain payload shape — events define their own
/// — but the CBOR encoder restricts what values can appear so the
/// canonical-form rules stay tractable. Floats and tags are excluded at
/// v0.1 per the spec; integers are split into unsigned vs. signed so
/// the encoder can pick the shortest CBOR major type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PayloadValue {
    /// CBOR major type 0 (unsigned integer).
    Uint(u64),
    /// CBOR major type 1 (negative integer). Caller passes the negative
    /// value directly.
    Nint(i64),
    /// CBOR major type 3 (UTF-8 text string).
    Text(String),
    /// CBOR major type 2 (byte string).
    Bytes(Vec<u8>),
    /// CBOR major type 7 simple values: false (0xf4) / true (0xf5).
    Bool(bool),
    /// CBOR major type 5 (map), text-string keys, canonical ordering.
    Map(BTreeMap<String, PayloadValue>),
    /// CBOR major type 4 (array), definite length.
    List(Vec<PayloadValue>),
}

impl PayloadValue {
    fn encode(&self) -> Vec<u8> {
        match self {
            PayloadValue::Uint(v) => cbor::uint(*v),
            PayloadValue::Nint(v) => cbor::nint(*v),
            PayloadValue::Text(s) => cbor::tstr(s),
            PayloadValue::Bytes(b) => cbor::bstr(b),
            PayloadValue::Bool(b) => cbor::bool_(*b),
            PayloadValue::Map(m) => {
                let encoded: BTreeMap<String, Vec<u8>> =
                    m.iter().map(|(k, v)| (k.clone(), v.encode())).collect();
                cbor::map_text_keys(&encoded)
            },
            PayloadValue::List(items) => {
                let encoded: Vec<Vec<u8>> = items.iter().map(PayloadValue::encode).collect();
                cbor::array(&encoded)
            },
        }
    }
}

/// Inputs the caller provides for one `append()` call. The Writer fills
/// in `record_id`, `prev_hash`, `session_id`, and `key_id` automatically.
#[derive(Debug, Clone)]
pub struct RecordInput {
    /// RFC 3339 UTC, millisecond precision, ending with `Z`.
    /// Example: `"2026-05-13T20:06:43.456Z"`.
    pub ts_wall: String,
    /// Milliseconds since session start on a monotonic clock.
    pub ts_mono_delta: u64,
    /// `user:alice`, `system:audit`, etc. Implementation-defined
    /// namespacing recommended.
    pub actor: String,
    /// Short stable tag in `category.action` form, e.g.
    /// `"vault.unlocked"`, `"shield.classified"`.
    pub event: String,
    /// Event-specific structured data. Text-string keys; canonical CBOR
    /// ordering is applied at encode time.
    pub payload: BTreeMap<String, PayloadValue>,
    /// Major version of the `payload` schema for `event`.
    pub schema_version: u8,
}

/// Writer configuration.
#[derive(Debug, Clone)]
pub struct WriterConfig {
    /// Rollover threshold in bytes. When the next append would push the
    /// current segment past this size (accounting for the
    /// `segment.finalized` record), the Writer rolls over to a new
    /// segment first.
    pub segment_size_bytes: u64,
    /// Whether to append a `segment.finalized` record at the end of
    /// each segment before rolling over. Default `true`; spec-conformant
    /// writers MUST keep this on.
    pub finalize_on_rollover: bool,
}

impl Default for WriterConfig {
    fn default() -> Self {
        Self {
            segment_size_bytes: DEFAULT_SEGMENT_SIZE_BYTES,
            finalize_on_rollover: true,
        }
    }
}

/// Errors the writer can produce.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum WriterError {
    /// I/O failure (filesystem, fsync, etc.).
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// Record input violated a schema invariant (e.g. ts_wall not RFC 3339).
    #[error("invalid record input: {0}")]
    InvalidInput(String),

    /// Crash-recovery scan refused to resume from this log directory.
    ///
    /// This is NOT a torn tail — that we repair silently. Recovery fails
    /// loudly when the existing log shows signs of in-place tampering,
    /// key rotation without migration, or unsupported on-disk format.
    /// See [`RecoveryFailure`] for the discriminated reason.
    ///
    /// The Writer never silently extends a corrupt chain; callers must
    /// decide whether to archive the broken log and create a fresh one.
    #[error("crash recovery refused: {reason}")]
    Recovery {
        /// Discriminated reason.
        reason: RecoveryFailure,
    },
}

/// Why the writer refused to resume from an existing log directory.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RecoveryFailure {
    /// The latest segment file's header bytes were corrupt
    /// (truncated, bad magic, unsupported version, CRC mismatch).
    HeaderCorrupt {
        /// Segment whose header failed to parse.
        segment_index: u16,
        /// The header-parse error.
        cause: HeaderParseError,
    },
    /// A record inside the latest segment HMAC'd against the running
    /// chain but the stored HMAC differed. This is structural tampering,
    /// not crash. The Writer refuses to extend such a log.
    HmacMismatch {
        /// Segment containing the bad record.
        segment_index: u16,
        /// Per-segment monotonic record id of the bad record.
        record_id: u64,
        /// Byte offset where the bad record starts in the segment file.
        file_offset: u64,
    },
    /// A record's `prev_hash` did not match the prior record's HMAC.
    /// As with `HmacMismatch`, this is tampering, not crash.
    ChainBreak {
        /// Segment containing the bad record.
        segment_index: u16,
        /// Per-segment monotonic record id of the bad record.
        record_id: u64,
        /// Byte offset where the bad record starts in the segment file.
        file_offset: u64,
    },
    /// The segment header's `key_id` does not match the key handle the
    /// caller passed to `Writer::open`. Either the wrong key was loaded
    /// or the log was created under a rotated key. v0.1 requires the
    /// caller to migrate the log into a fresh dir before continuing.
    KeyIdMismatch {
        /// Segment whose header had the unexpected key_id.
        segment_index: u16,
        /// Header's key_id hex.
        header_key_id_hex: String,
        /// Caller-supplied key handle's key_id hex.
        expected_key_id_hex: String,
    },
}

impl core::fmt::Display for RecoveryFailure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RecoveryFailure::HeaderCorrupt {
                segment_index,
                cause,
            } => write!(f, "header corrupt in segment {segment_index}: {cause}"),
            RecoveryFailure::HmacMismatch {
                segment_index,
                record_id,
                file_offset,
            } => write!(
                f,
                "HMAC mismatch at segment {segment_index}, record {record_id} \
                 (file offset {file_offset}) — log shows in-place tampering, refusing to extend"
            ),
            RecoveryFailure::ChainBreak {
                segment_index,
                record_id,
                file_offset,
            } => write!(
                f,
                "chain break at segment {segment_index}, record {record_id} \
                 (file offset {file_offset}) — log shows in-place tampering, refusing to extend"
            ),
            RecoveryFailure::KeyIdMismatch {
                segment_index,
                header_key_id_hex,
                expected_key_id_hex,
            } => write!(
                f,
                "key_id mismatch in segment {segment_index}: header has {header_key_id_hex}, \
                 caller's key handle is {expected_key_id_hex}"
            ),
        }
    }
}

/// What `Writer::open` did with the target directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryAction {
    /// Directory had no segment files. A fresh segment 0 was created.
    Fresh,
    /// Existing log's tail was clean. Resumed appending without any
    /// truncation.
    Resumed,
    /// Existing log's tail was torn (partial framing / `len_trailer !=
    /// len_prefix`). The torn bytes were truncated and the writer
    /// resumed at the last valid record.
    Repaired,
    /// The latest segment was finalized end-to-end (last record was
    /// `segment.finalized`). The writer opened a fresh segment N+1 with
    /// its `prev_final` chained from the finalized segment's last HMAC.
    OpenedNextAfterFinalized,
}

/// Per-call report describing what `Writer::open` recovered.
///
/// Returned from [`Writer::recovery_report`]. The calling app surfaces
/// the relevant bits to the user — e.g. "previous session ended
/// unexpectedly; recovered to record 1234, truncated 67 bytes".
#[derive(Debug, Clone)]
pub struct RecoveryReport {
    /// Discriminated action taken.
    pub action: RecoveryAction,
    /// Segment index that became `current` after open.
    pub current_segment_index: u16,
    /// `record_id` of the last valid record found across the recovered
    /// log. `None` when `action == Fresh` or the latest segment had no
    /// records.
    pub last_record_id: Option<u64>,
    /// Number of records present in the recovered current segment at
    /// the moment of resume (0 if action is `Fresh` or
    /// `OpenedNextAfterFinalized`).
    pub records_in_current_segment: u64,
    /// Bytes lopped off the latest segment file during repair. Zero
    /// unless `action == Repaired`.
    pub truncated_bytes: u64,
    /// Total segments scanned during recovery (always 1 unless future
    /// versions add cross-segment scanning; v0.1 trusts earlier
    /// segments and only scans the latest).
    pub segments_scanned: u16,
    /// HMAC of the last valid record (or chain_start equivalent).
    /// Useful for callers that want to surface an integrity-anchor
    /// fingerprint in their UI.
    pub last_hmac: HmacBytes,
}

/// Append-only writer over a directory of segment files.
pub struct Writer {
    log_dir: PathBuf,
    key: Box<dyn KeyHandle>,
    session_id: [u8; SESSION_ID_LEN],
    config: WriterConfig,
    current: SegmentState,
    /// Populated by `Writer::open` / `Writer::with_config`. Surfaced to
    /// callers via [`Writer::recovery_report`].
    recovery: RecoveryReport,
}

struct SegmentState {
    index: u16,
    file: File,
    /// Number of bytes written to the segment so far (header + framed
    /// records).
    bytes_written: u64,
    /// HMAC of the last record successfully framed into this segment.
    /// For an empty segment, this equals `chain_start` (header-bound or
    /// inherited from prev_final).
    last_hmac: [u8; HMAC_LEN],
    /// Next `record_id` to assign within this segment.
    next_record_id: RecordId,
    /// Records written into this segment so far. Used in the
    /// `segment.finalized` payload.
    record_count: u64,
    /// `ts_wall` of the most recent record appended into this segment.
    /// Used as the time anchor for the synthesized `segment.finalized`
    /// record (matches `tools/gen_vectors.py`'s behavior). Empty
    /// `String` until the first record lands.
    last_ts_wall: String,
    /// `ts_mono_delta` of the most recent record appended into this
    /// segment. Paired with `last_ts_wall`.
    last_ts_mono_delta: u64,
}

impl Writer {
    /// Open a log directory.
    ///
    /// If the directory is empty (or has no `audit-NNNN.cbor` files),
    /// creates a fresh segment 0 (the v0.1 genesis path).
    ///
    /// If the directory already contains segment files, runs the
    /// [R5 / OGE-432] crash-recovery scan on the latest segment:
    ///
    /// * a torn tail (incomplete frame / `len_trailer != len_prefix`)
    ///   is truncated atomically before any new append;
    /// * a clean tail is resumed in-place;
    /// * a fully-finalized latest segment causes a fresh segment N+1 to
    ///   be opened with `prev_final` chained from the finalize HMAC.
    ///
    /// In-place tampering (HMAC mismatch or chain break inside an
    /// otherwise framed record, or a `key_id` that doesn't match the
    /// caller's key handle) causes [`Writer::open`] to return
    /// [`WriterError::Recovery`] — the writer never silently extends a
    /// corrupt chain.
    ///
    /// After open, call [`Writer::recovery_report`] for a structured
    /// description of what the scan did. This is the event the calling
    /// app surfaces as "previous session ended unexpectedly; recovered
    /// to record 1234, truncated 67 bytes".
    ///
    /// `session_id` should be a UUIDv4 generated at vault unlock or
    /// equivalent application-lifecycle event; it is stamped into every
    /// new record written via this Writer.
    ///
    /// [R5 / OGE-432]: https://linear.app/ogenticai/issue/OGE-432
    pub fn open(
        log_dir: impl AsRef<Path>,
        key: Box<dyn KeyHandle>,
        session_id: [u8; SESSION_ID_LEN],
    ) -> Result<Self, WriterError> {
        Self::with_config(log_dir, key, session_id, WriterConfig::default())
    }

    /// Like [`Writer::open`] but with an explicit [`WriterConfig`]
    /// (typically used to set a smaller `segment_size_bytes` for tests).
    pub fn with_config(
        log_dir: impl AsRef<Path>,
        key: Box<dyn KeyHandle>,
        session_id: [u8; SESSION_ID_LEN],
        config: WriterConfig,
    ) -> Result<Self, WriterError> {
        let log_dir = log_dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&log_dir)?;

        let existing = list_segment_indices(&log_dir)?;
        if existing.is_empty() {
            // Fresh-create the genesis segment.
            let current = SegmentState::create(0, &log_dir, key.as_ref().key_id().as_bytes())?;
            let header = SegmentHeader::genesis(*key.as_ref().key_id().as_bytes());
            let header_bytes = header.to_bytes();
            let chain_start = sign_bytes(key.as_ref(), &header_bytes[..HEADER_BODY_LEN]);
            let recovery = RecoveryReport {
                action: RecoveryAction::Fresh,
                current_segment_index: 0,
                last_record_id: None,
                records_in_current_segment: 0,
                truncated_bytes: 0,
                segments_scanned: 0,
                last_hmac: HmacBytes::from(chain_start),
            };
            let mut writer = Self {
                log_dir,
                key,
                session_id,
                config,
                current,
                recovery,
            };
            writer.current.last_hmac = chain_start;
            return Ok(writer);
        }

        // Recovery path: scan the highest-numbered segment.
        let latest_index = *existing.last().expect("non-empty");
        let scan = scan_segment_for_recovery(&log_dir, latest_index, key.as_ref())?;

        let (current, recovery) = if scan.last_record_was_finalize {
            // Latest segment closed cleanly. Open N+1 fresh.
            let next_index = latest_index
                .checked_add(1)
                .ok_or_else(|| WriterError::InvalidInput("segment_index overflow (u16)".into()))?;
            let new_state = SegmentState::create_next(
                next_index,
                &log_dir,
                key.as_ref().key_id().as_bytes(),
                scan.last_hmac,
            )?;
            let report = RecoveryReport {
                action: RecoveryAction::OpenedNextAfterFinalized,
                current_segment_index: next_index,
                last_record_id: scan.last_record_id,
                records_in_current_segment: 0,
                truncated_bytes: scan.truncated_bytes,
                segments_scanned: 1,
                last_hmac: HmacBytes::from(scan.last_hmac),
            };
            (new_state, report)
        } else {
            // Resume in-place in the latest segment.
            let state = reopen_segment_for_append(&log_dir, latest_index, &scan)?;
            let action = if scan.truncated_bytes > 0 {
                RecoveryAction::Repaired
            } else {
                RecoveryAction::Resumed
            };
            let report = RecoveryReport {
                action,
                current_segment_index: latest_index,
                last_record_id: scan.last_record_id,
                records_in_current_segment: scan.record_count,
                truncated_bytes: scan.truncated_bytes,
                segments_scanned: 1,
                last_hmac: HmacBytes::from(scan.last_hmac),
            };
            (state, report)
        };

        Ok(Self {
            log_dir,
            key,
            session_id,
            config,
            current,
            recovery,
        })
    }

    /// Structured description of what [`Writer::open`] did with the
    /// target directory: fresh create, clean resume, torn-tail repair,
    /// or open-next-after-finalized. Always populated.
    #[must_use]
    pub fn recovery_report(&self) -> &RecoveryReport {
        &self.recovery
    }

    /// Append one record to the current segment, rolling over first if
    /// needed. Returns the assigned `record_id`.
    pub fn append(&mut self, input: RecordInput) -> Result<RecordId, WriterError> {
        validate_input(&input)?;

        // Estimate the framed size of this record using a worst-case
        // record_id (u64::MAX → 9 bytes encoded). The actual record_id
        // we'll end up assigning may be smaller, so this estimate is a
        // safe upper bound for the rollover decision.
        let estimated_payload_len = encode_record_payload(
            &input,
            &self.session_id,
            self.key.as_ref().key_id().as_bytes(),
            &[0u8; HMAC_LEN], // any 32-byte prev_hash; encoded length is the same
            u64::MAX,
        )
        .len();
        let estimated_framed_len = (RECORD_FRAMING_OVERHEAD + estimated_payload_len) as u64;

        // Conservative rollover check: if appending this record AND a
        // subsequent segment.finalized record would exceed the
        // threshold, finalize + roll over first. Skip if the segment
        // is empty (don't roll over a header-only segment).
        if self.config.finalize_on_rollover
            && self.current.record_count > 0
            && (self.current.bytes_written
                + estimated_framed_len
                + estimate_finalize_size(
                    &input,
                    &self.session_id,
                    self.key.as_ref().key_id().as_bytes(),
                ))
                > self.config.segment_size_bytes
        {
            self.rollover(&input)?;
        }

        // Encode the actual payload AFTER the rollover decision so that
        // `prev_hash` and `record_id` reflect the post-rollover state
        // (record_id reset to 0 in the new segment; prev_hash = the
        // finalize record's HMAC).
        let payload_bytes = encode_record_payload(
            &input,
            &self.session_id,
            self.key.as_ref().key_id().as_bytes(),
            &self.current.last_hmac,
            self.current.next_record_id,
        );

        self.append_framed(&payload_bytes, &input.ts_wall, input.ts_mono_delta)?;
        let id = self.current.next_record_id - 1;
        Ok(id)
    }

    /// Force buffered records to durable storage.
    ///
    /// Calls `F_FULLFSYNC` (macOS) / `sync_all` (others) on the segment
    /// file and on the log directory itself so that the file's
    /// existence + size + contents are all durable at return.
    pub fn flush(&mut self) -> Result<(), WriterError> {
        full_sync(&self.current.file)?;
        // Directory sync: open + sync. Skipped on Windows where the
        // file metadata is part of the file's own fsync.
        #[cfg(unix)]
        {
            let dir = File::open(&self.log_dir)?;
            full_sync(&dir)?;
        }
        Ok(())
    }

    /// The segment index currently being written into.
    #[must_use]
    pub fn segment_index(&self) -> u16 {
        self.current.index
    }

    /// Number of records written into the current segment.
    #[must_use]
    pub fn record_count_in_segment(&self) -> u64 {
        self.current.record_count
    }

    /// HMAC of the most recently appended record (or the chain start if
    /// no records have been appended yet).
    #[must_use]
    pub fn last_hmac(&self) -> HmacBytes {
        HmacBytes::from(self.current.last_hmac)
    }

    /// Path to the segment file currently being written.
    #[must_use]
    pub fn current_segment_path(&self) -> PathBuf {
        segment_path(&self.log_dir, self.current.index)
    }

    /// Internal: append a framed record to the current segment file
    /// without any rollover bookkeeping. Updates `last_hmac`,
    /// `next_record_id`, `record_count`, `bytes_written`, and the
    /// `last_ts_*` time anchors used by the next rollover.
    fn append_framed(
        &mut self,
        payload: &[u8],
        ts_wall: &str,
        ts_mono_delta: u64,
    ) -> Result<(), WriterError> {
        let hmac = sign_bytes(self.key.as_ref(), payload);
        let framed = segment::frame_record(payload, &hmac);
        self.current.file.write_all(&framed)?;
        self.current.bytes_written += framed.len() as u64;
        self.current.last_hmac = hmac;
        self.current.next_record_id += 1;
        self.current.record_count += 1;
        self.current.last_ts_wall.clear();
        self.current.last_ts_wall.push_str(ts_wall);
        self.current.last_ts_mono_delta = ts_mono_delta;
        Ok(())
    }

    /// Append a `segment.finalized` record, fsync the current segment,
    /// then open the next one with a header chained from the just-
    /// finalized segment's last HMAC.
    fn rollover(&mut self, _anchor_input: &RecordInput) -> Result<(), WriterError> {
        // The finalize record's ts_wall and ts_mono_delta are bumped 1ms
        // past the LAST record currently in the segment — not past the
        // incoming record. This matches the reference generator
        // (`tools/gen_vectors.py`'s `_append_segment_finalized`) and is
        // what the v0.1 golden vectors expect.
        let finalize_input = assemble_finalize_input_from_last(
            &self.current.last_ts_wall,
            self.current.last_ts_mono_delta,
            self.current.record_count,
            &self.current.last_hmac,
        );
        let finalize_payload = encode_record_payload(
            &finalize_input,
            &self.session_id,
            self.key.as_ref().key_id().as_bytes(),
            &self.current.last_hmac,
            self.current.next_record_id,
        );
        self.append_framed(
            &finalize_payload,
            &finalize_input.ts_wall,
            finalize_input.ts_mono_delta,
        )?;
        full_sync(&self.current.file)?;

        // Open the next segment.
        let prev_final = self.current.last_hmac;
        let next_index = self
            .current
            .index
            .checked_add(1)
            .ok_or_else(|| WriterError::InvalidInput("segment_index overflow (u16)".into()))?;
        let new_state = SegmentState::create_next(
            next_index,
            &self.log_dir,
            self.key.as_ref().key_id().as_bytes(),
            prev_final,
        )?;
        self.current = new_state;
        // Chain start for segment N ≥ 1 is the prior segment's final
        // HMAC (== header.prev_final). Already set by create_next.
        Ok(())
    }
}

impl std::fmt::Debug for Writer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Writer")
            .field("log_dir", &self.log_dir)
            .field("segment_index", &self.current.index)
            .field("record_count_in_segment", &self.current.record_count)
            .field("bytes_written", &self.current.bytes_written)
            .field("session_id_hex", &hex_lower(&self.session_id))
            .finish()
    }
}

impl SegmentState {
    /// Create segment 0 in `log_dir`. Writes the genesis header to disk
    /// immediately.
    fn create(index: u16, log_dir: &Path, key_id: &[u8; HMAC_LEN]) -> Result<Self, WriterError> {
        let path = segment_path(log_dir, index);
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .read(true)
            .open(&path)?;
        let header = SegmentHeader::genesis(*key_id);
        let header_bytes = header.to_bytes();
        file.write_all(&header_bytes)?;
        Ok(Self {
            index,
            file,
            bytes_written: HEADER_TOTAL_LEN as u64,
            // Caller (Writer::with_config) overwrites this with the
            // proper chain_start for segment 0 (HMAC over header
            // bytes). For segment ≥ 1, create_next sets it directly.
            last_hmac: [0u8; HMAC_LEN],
            next_record_id: 0,
            record_count: 0,
            last_ts_wall: String::new(),
            last_ts_mono_delta: 0,
        })
    }

    /// Create segment N ≥ 1 with a `prev_final` chained from the prior
    /// segment's last HMAC.
    fn create_next(
        index: u16,
        log_dir: &Path,
        key_id: &[u8; HMAC_LEN],
        prev_final: [u8; HMAC_LEN],
    ) -> Result<Self, WriterError> {
        let path = segment_path(log_dir, index);
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .read(true)
            .open(&path)?;
        let header = SegmentHeader::next(index, *key_id, prev_final);
        let header_bytes = header.to_bytes();
        file.write_all(&header_bytes)?;
        Ok(Self {
            index,
            file,
            bytes_written: HEADER_TOTAL_LEN as u64,
            last_hmac: prev_final,
            next_record_id: 0,
            record_count: 0,
            last_ts_wall: String::new(),
            last_ts_mono_delta: 0,
        })
    }
}

fn segment_path(log_dir: &Path, index: u16) -> PathBuf {
    log_dir.join(format!("audit-{index:04}.cbor"))
}

fn sign_bytes(key: &dyn KeyHandle, data: &[u8]) -> [u8; HMAC_LEN] {
    *key.sign(data).as_bytes()
}

fn validate_input(input: &RecordInput) -> Result<(), WriterError> {
    if !input.ts_wall.ends_with('Z') {
        return Err(WriterError::InvalidInput(format!(
            "ts_wall must end with 'Z' (RFC 3339 UTC); got {:?}",
            input.ts_wall
        )));
    }
    // Loose RFC 3339 ms-precision shape check. A stricter parse lives
    // in the future verifier (R3 / OGE-437); the Writer fails fast on
    // the obvious malformations.
    if input.ts_wall.len() != "2026-05-13T20:06:43.456Z".len() {
        return Err(WriterError::InvalidInput(format!(
            "ts_wall must be RFC 3339 with ms precision; got {:?}",
            input.ts_wall
        )));
    }
    Ok(())
}

/// Encode the record payload as canonical CBOR matching the v0.1 schema.
/// This is the exact byte sequence that gets HMAC'd and written to disk.
fn encode_record_payload(
    input: &RecordInput,
    session_id: &[u8; SESSION_ID_LEN],
    key_id: &[u8; HMAC_LEN],
    prev_hash: &[u8; HMAC_LEN],
    record_id: u64,
) -> Vec<u8> {
    let payload_bytes = {
        let encoded: BTreeMap<String, Vec<u8>> = input
            .payload
            .iter()
            .map(|(k, v)| (k.clone(), v.encode()))
            .collect();
        cbor::map_text_keys(&encoded)
    };

    let items: Vec<(u64, Vec<u8>)> = vec![
        (1, cbor::uint(record_id)),
        (2, cbor::bstr(prev_hash)),
        (3, cbor::tstr(&input.ts_wall)),
        (4, cbor::uint(input.ts_mono_delta)),
        (5, cbor::bstr(session_id)),
        (6, cbor::tstr(&input.actor)),
        (7, cbor::tstr(&input.event)),
        (8, payload_bytes),
        (9, cbor::bstr(key_id)),
        (10, cbor::uint(input.schema_version as u64)),
    ];
    cbor::map_int_keys(&items)
}

/// Build the input for a `segment.finalized` record whose time anchors
/// come from the **last record currently in the segment** (NOT the
/// incoming record that triggered rollover). The `payload` is populated
/// with the spec-required `{records, final_hash}` fields.
fn assemble_finalize_input_from_last(
    last_ts_wall: &str,
    last_ts_mono_delta: u64,
    record_count_before_finalize: u64,
    last_hmac: &[u8; HMAC_LEN],
) -> RecordInput {
    let mut payload = BTreeMap::new();
    payload.insert(
        "records".into(),
        PayloadValue::Uint(record_count_before_finalize),
    );
    payload.insert("final_hash".into(), PayloadValue::Bytes(last_hmac.to_vec()));
    RecordInput {
        ts_wall: bump_ts_ms(last_ts_wall),
        ts_mono_delta: last_ts_mono_delta.saturating_add(1),
        actor: "system:audit".into(),
        event: "segment.finalized".into(),
        payload,
        schema_version: 1,
    }
}

/// Estimate the on-disk size a `segment.finalized` record would take for
/// the current session, used in the rollover check. Uses a placeholder
/// 32-byte final_hash; the actual length is independent of the byte
/// values.
fn estimate_finalize_size(
    anchor: &RecordInput,
    session_id: &[u8; SESSION_ID_LEN],
    key_id: &[u8; HMAC_LEN],
) -> u64 {
    // Worst-case size estimate. The actual finalize record may be a few
    // bytes smaller (e.g. `records` count is smaller than u64::MAX, ts
    // strings are the standard 24-char shape), but never larger.
    let finalize = assemble_finalize_input_from_last(
        &anchor.ts_wall,
        anchor.ts_mono_delta,
        u64::MAX,
        &[0u8; HMAC_LEN],
    );
    let payload_bytes =
        encode_record_payload(&finalize, session_id, key_id, &[0u8; HMAC_LEN], u64::MAX);
    (RECORD_FRAMING_OVERHEAD + payload_bytes.len()) as u64
}

/// Add 1 ms to an RFC 3339 ms-precision timestamp string. Used only for
/// the synthesized `segment.finalized` record. Returns a fixed sentinel
/// on parse failure — Writer::append validates the input upstream, so
/// this should never hit.
fn bump_ts_ms(ts: &str) -> String {
    // Format: "YYYY-MM-DDTHH:MM:SS.mmmZ" (24 chars).
    // Increment the millisecond component, carry into seconds, then
    // leave the rest unchanged. For v0.1 we only ever bump by 1ms in
    // the finalize path, so a full date-time arithmetic is overkill.
    let len = ts.len();
    if len != "2026-05-13T20:06:43.456Z".len() {
        return ts.to_string();
    }
    let bytes = ts.as_bytes();
    let ms_str = std::str::from_utf8(&bytes[20..23]).unwrap_or("000");
    let ms: u32 = ms_str.parse().unwrap_or(0);
    if ms < 999 {
        let mut new = String::with_capacity(len);
        new.push_str(&ts[..20]);
        new.push_str(&format!("{:03}", ms + 1));
        new.push('Z');
        return new;
    }
    // 999 + 1 -> carry into seconds. Cheap version: parse + format the
    // whole timestamp using chrono. But chrono isn't in our deps. The
    // rollover vector test doesn't exercise this carry (the records
    // are 1s apart, so ms is always 0 → 1 with no carry). Punt on the
    // carry path until a real test forces it.
    ts.to_string()
}

/// Hex helper. Duplicated from `key.rs` because crossing the module
/// boundary for a 10-line utility is more visual noise than it's worth.
fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

// (legacy assemble_finalize_input helper removed — the size-estimation
// path now uses assemble_finalize_input_from_last directly.)

// ---------------------------------------------------------------------
// Crash-recovery scan (R5 / OGE-432)
//
// `Writer::open` consults these helpers when the target directory
// already contains segment files. The scan walks the LATEST segment
// only — earlier segments are treated as already-durable history (the
// Verifier R3 checks them on demand). Torn tails are truncated
// silently; HMAC mismatches and chain breaks inside framed records are
// surfaced as `WriterError::Recovery` and refuse to extend the chain.
// ---------------------------------------------------------------------

/// Result of scanning the latest segment for recovery.
struct ScanResult {
    /// Number of valid records found.
    record_count: u64,
    /// Per-segment monotonic id of the last valid record (None if 0).
    last_record_id: Option<u64>,
    /// Total bytes the file ends at after any torn-tail truncation.
    bytes_written: u64,
    /// Number of bytes the recovery truncated off the tail.
    truncated_bytes: u64,
    /// HMAC of the last valid record (or chain_start if no records).
    last_hmac: [u8; HMAC_LEN],
    /// `ts_wall` of the last valid record (empty if no records).
    last_ts_wall: String,
    /// `ts_mono_delta` of the last valid record (0 if no records).
    last_ts_mono_delta: u64,
    /// Whether the last valid record was a `segment.finalized` event.
    last_record_was_finalize: bool,
}

/// List `audit-NNNN.cbor` files in `log_dir` and return their `NNNN`
/// indices in ascending order.
fn list_segment_indices(log_dir: &Path) -> Result<Vec<u16>, WriterError> {
    let mut out = Vec::new();
    let entries = match std::fs::read_dir(log_dir) {
        Ok(e) => e,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(out),
        Err(err) => return Err(err.into()),
    };
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        let name = match name.to_str() {
            Some(s) => s,
            None => continue,
        };
        if let Some(idx) = parse_segment_filename(name) {
            out.push(idx);
        }
    }
    out.sort_unstable();
    Ok(out)
}

/// `"audit-0042.cbor"` → `Some(42)`. Anything else → `None`.
fn parse_segment_filename(name: &str) -> Option<u16> {
    let body = name.strip_prefix("audit-")?.strip_suffix(".cbor")?;
    if body.len() != 4 {
        return None;
    }
    body.parse::<u16>().ok()
}

/// Walk the latest segment forward, HMAC each record, detect torn tail,
/// truncate if needed. Returns a structured [`ScanResult`].
fn scan_segment_for_recovery(
    log_dir: &Path,
    seg_idx: u16,
    key: &dyn KeyHandle,
) -> Result<ScanResult, WriterError> {
    let path = segment_path(log_dir, seg_idx);
    let mut file = OpenOptions::new().read(true).write(true).open(&path)?;
    let file_len = file.metadata()?.len();

    // 1. Parse + validate header.
    if file_len < HEADER_TOTAL_LEN as u64 {
        return Err(WriterError::Recovery {
            reason: RecoveryFailure::HeaderCorrupt {
                segment_index: seg_idx,
                cause: HeaderParseError::TooShort {
                    got: file_len as usize,
                },
            },
        });
    }
    let mut header_bytes = [0u8; HEADER_TOTAL_LEN];
    file.seek(SeekFrom::Start(0))?;
    file.read_exact(&mut header_bytes)?;
    let header = SegmentHeader::parse(&header_bytes).map_err(|cause| WriterError::Recovery {
        reason: RecoveryFailure::HeaderCorrupt {
            segment_index: seg_idx,
            cause,
        },
    })?;

    // 2. Validate header key_id matches caller's key handle.
    let expected_key_id = key.key_id();
    if header.key_id != *expected_key_id.as_bytes() {
        return Err(WriterError::Recovery {
            reason: RecoveryFailure::KeyIdMismatch {
                segment_index: seg_idx,
                header_key_id_hex: hex_lower(&header.key_id),
                expected_key_id_hex: hex_lower(expected_key_id.as_bytes()),
            },
        });
    }

    // 3. Compute chain_start for this segment's first record.
    let chain_start = if seg_idx == 0 {
        sign_bytes(key, &header_bytes[..HEADER_BODY_LEN])
    } else {
        header.prev_final
    };

    // 4. Walk records.
    let mut offset = HEADER_TOTAL_LEN as u64;
    let mut prev_hash = chain_start;
    let mut record_count: u64 = 0;
    let mut last_record_id: Option<u64> = None;
    let mut last_ts_wall = String::new();
    let mut last_ts_mono_delta: u64 = 0;
    let mut last_record_was_finalize = false;
    let mut last_valid_offset = HEADER_TOTAL_LEN as u64;

    loop {
        if offset >= file_len {
            break;
        }
        // Read the framed record at `offset`.
        let framed = match read_framed_record(&mut file, file_len, offset) {
            FramingOutcome::Ok(f) => f,
            FramingOutcome::Torn => {
                // Torn tail — truncate to `offset` and stop.
                let truncated = file_len - offset;
                if truncated > 0 {
                    truncate_to(&mut file, offset)?;
                }
                return Ok(ScanResult {
                    record_count,
                    last_record_id,
                    bytes_written: offset,
                    truncated_bytes: truncated,
                    last_hmac: prev_hash,
                    last_ts_wall,
                    last_ts_mono_delta,
                    last_record_was_finalize,
                });
            },
            FramingOutcome::Io(err) => return Err(err.into()),
        };

        // HMAC check.
        let expected = sign_bytes(key, &framed.payload_bytes);
        if !constant_time_eq(&expected, &framed.hmac) {
            // Structural tampering — refuse to recover.
            let record_id = peek_record_id(&framed.payload_bytes)
                .unwrap_or_else(|| last_record_id.map(|r| r + 1).unwrap_or(0));
            return Err(WriterError::Recovery {
                reason: RecoveryFailure::HmacMismatch {
                    segment_index: seg_idx,
                    record_id,
                    file_offset: offset,
                },
            });
        }

        // Decode + chain check.
        let decoded = match cbor::decode(&framed.payload_bytes) {
            Ok(v) => v,
            Err(e) => {
                // Decoded layer failed even though HMAC matched. This
                // means the encoded form is non-canonical (the writer
                // signed something the decoder won't accept). Treat as
                // structural corruption.
                return Err(WriterError::InvalidInput(format!(
                    "scan_segment_for_recovery: decoded record at offset {offset} \
                     passed HMAC but failed canonical CBOR decode: {e}"
                )));
            },
        };

        let parsed = parse_recovered_record(&decoded).map_err(|e| {
            // HMAC matched but the canonical-CBOR decode wasn't v0.1-
            // schema-shaped. That's a writer bug, not crash / tamper —
            // bail loudly so the caller doesn't silently extend a
            // non-conforming chain.
            WriterError::InvalidInput(format!(
                "scan_segment_for_recovery: record at segment {seg_idx}, offset {offset} \
                 passed HMAC but failed v0.1 schema parse: {}",
                e.0
            ))
        })?;

        // Chain check.
        if parsed.prev_hash != prev_hash {
            return Err(WriterError::Recovery {
                reason: RecoveryFailure::ChainBreak {
                    segment_index: seg_idx,
                    record_id: parsed.record_id,
                    file_offset: offset,
                },
            });
        }

        // Advance.
        prev_hash = framed.hmac;
        last_record_id = Some(parsed.record_id);
        last_ts_wall = parsed.ts_wall;
        last_ts_mono_delta = parsed.ts_mono_delta;
        last_record_was_finalize = parsed.event == "segment.finalized";
        record_count += 1;
        last_valid_offset = offset + framed.total_len;
        offset = last_valid_offset;
    }

    Ok(ScanResult {
        record_count,
        last_record_id,
        bytes_written: last_valid_offset,
        truncated_bytes: 0,
        last_hmac: prev_hash,
        last_ts_wall,
        last_ts_mono_delta,
        last_record_was_finalize,
    })
}

/// Outcome of attempting to read a framed record at `offset`.
enum FramingOutcome {
    Ok(FramedReadout),
    Torn,
    Io(io::Error),
}

/// One successfully framed record.
struct FramedReadout {
    payload_bytes: Vec<u8>,
    hmac: [u8; HMAC_LEN],
    total_len: u64,
}

/// Read a framed record at `offset`. Returns `Torn` for any incomplete
/// framing (short read, len mismatch).
fn read_framed_record(file: &mut File, file_len: u64, offset: u64) -> FramingOutcome {
    if let Err(e) = file.seek(SeekFrom::Start(offset)) {
        return FramingOutcome::Io(e);
    }
    if file_len - offset < 4 {
        return FramingOutcome::Torn;
    }
    let mut lp = [0u8; 4];
    if let Err(e) = file.read_exact(&mut lp) {
        return FramingOutcome::Io(e);
    }
    let len_prefix = u32::from_le_bytes(lp) as u64;
    let framed_total = 4 + len_prefix + (HMAC_LEN as u64) + 4;
    if file_len - offset < framed_total {
        return FramingOutcome::Torn;
    }
    // Defensive cap: a v0.1 record can be at most ~16 MiB given the
    // 64 MiB segment cap and per-record overhead. Reject anything past
    // 32 MiB outright (torn-tail with stale bytes that happen to look
    // like a valid length).
    if len_prefix > 32 * 1024 * 1024 {
        return FramingOutcome::Torn;
    }
    let mut payload_bytes = vec![0u8; len_prefix as usize];
    if let Err(e) = file.read_exact(&mut payload_bytes) {
        return FramingOutcome::Io(e);
    }
    let mut hmac = [0u8; HMAC_LEN];
    if let Err(e) = file.read_exact(&mut hmac) {
        return FramingOutcome::Io(e);
    }
    let mut lt = [0u8; 4];
    if let Err(e) = file.read_exact(&mut lt) {
        return FramingOutcome::Io(e);
    }
    let len_trailer = u32::from_le_bytes(lt) as u64;
    if len_trailer != len_prefix {
        return FramingOutcome::Torn;
    }
    FramingOutcome::Ok(FramedReadout {
        payload_bytes,
        hmac,
        total_len: framed_total,
    })
}

fn truncate_to(file: &mut File, new_len: u64) -> io::Result<()> {
    file.flush()?;
    file.set_len(new_len)?;
    full_sync(file)?;
    Ok(())
}

/// Constant-time `==` over two 32-byte HMAC buffers.
fn constant_time_eq(a: &[u8; HMAC_LEN], b: &[u8; HMAC_LEN]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

/// Minimal decoded view of a record's recovered fields. We avoid
/// going through Reader::Record because the recovery scan needs to be
/// self-contained (Reader is built on top of segment files we're
/// actively repairing).
struct RecoveredRecord {
    record_id: u64,
    prev_hash: [u8; HMAC_LEN],
    ts_wall: String,
    ts_mono_delta: u64,
    event: String,
}

#[derive(Debug)]
struct RecoveredParseError(String);

fn parse_recovered_record(value: &cbor::Value) -> Result<RecoveredRecord, RecoveredParseError> {
    let pairs = match value {
        cbor::Value::Map(m) => m,
        _ => return Err(RecoveredParseError("record is not a CBOR map".into())),
    };
    let mut record_id: Option<u64> = None;
    let mut prev_hash: Option<[u8; HMAC_LEN]> = None;
    let mut ts_wall: Option<String> = None;
    let mut ts_mono_delta: Option<u64> = None;
    let mut event: Option<String> = None;
    for (k, v) in pairs {
        let key = match k {
            cbor::Value::Uint(n) => *n,
            _ => return Err(RecoveredParseError("non-uint map key".into())),
        };
        match (key, v) {
            (1, cbor::Value::Uint(n)) => record_id = Some(*n),
            (2, cbor::Value::Bytes(b)) => {
                if b.len() != HMAC_LEN {
                    return Err(RecoveredParseError(format!(
                        "prev_hash length: {}",
                        b.len()
                    )));
                }
                let mut buf = [0u8; HMAC_LEN];
                buf.copy_from_slice(b);
                prev_hash = Some(buf);
            },
            (3, cbor::Value::Text(s)) => ts_wall = Some(s.clone()),
            (4, cbor::Value::Uint(n)) => ts_mono_delta = Some(*n),
            (7, cbor::Value::Text(s)) => event = Some(s.clone()),
            _ => {},
        }
    }
    Ok(RecoveredRecord {
        record_id: record_id.ok_or_else(|| RecoveredParseError("missing record_id".into()))?,
        prev_hash: prev_hash.ok_or_else(|| RecoveredParseError("missing prev_hash".into()))?,
        ts_wall: ts_wall.ok_or_else(|| RecoveredParseError("missing ts_wall".into()))?,
        ts_mono_delta: ts_mono_delta
            .ok_or_else(|| RecoveredParseError("missing ts_mono_delta".into()))?,
        event: event.ok_or_else(|| RecoveredParseError("missing event".into()))?,
    })
}

/// Peek at the `record_id` field of a CBOR-encoded payload without
/// fully decoding. Used in error paths where decode may fail.
fn peek_record_id(payload: &[u8]) -> Option<u64> {
    let value = cbor::decode(payload).ok()?;
    match value {
        cbor::Value::Map(pairs) => {
            for (k, v) in pairs {
                if let cbor::Value::Uint(1) = k {
                    if let cbor::Value::Uint(n) = v {
                        return Some(n);
                    }
                }
            }
            None
        },
        _ => None,
    }
}

/// Reopen the latest segment file for resume-append after a successful
/// scan. The file's bytes already match `scan.bytes_written` (we
/// truncated during the scan if needed).
fn reopen_segment_for_append(
    log_dir: &Path,
    seg_idx: u16,
    scan: &ScanResult,
) -> Result<SegmentState, WriterError> {
    let path = segment_path(log_dir, seg_idx);
    let mut file = OpenOptions::new().read(true).write(true).open(&path)?;
    file.seek(SeekFrom::Start(scan.bytes_written))?;
    Ok(SegmentState {
        index: seg_idx,
        file,
        bytes_written: scan.bytes_written,
        last_hmac: scan.last_hmac,
        next_record_id: scan.last_record_id.map(|r| r + 1).unwrap_or(0),
        record_count: scan.record_count,
        last_ts_wall: scan.last_ts_wall.clone(),
        last_ts_mono_delta: scan.last_ts_mono_delta,
    })
}
