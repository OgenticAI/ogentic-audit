//! Read access to v0.1 audit logs.
//!
//! The [`Reader`] consumes what [`crate::writer::Writer`] produces.
//! Two access patterns are exposed:
//!
//! 1. **Sequential iteration** via [`Reader::iter`] — yields records in
//!    append order across every segment in the log directory. Cooperates
//!    with a live writer: if the writer is still appending, the iterator
//!    returns [`None`](RecordIterator::next_record) at the current end
//!    and a subsequent call picks up whatever was appended in between.
//! 2. **Indexed random access** via [`Reader::seek`] — jumps to a
//!    `(segment_index, record_id)` pair. Used by the CLI's `show`
//!    subcommand and the verifier's evidence path.
//!
//! ## What this module does NOT do
//!
//! - **No HMAC verification.** That's the verifier's job ([R3 / OGE-437]).
//!   Reading and verifying are kept separate so the CLI's `show`,
//!   `head`, and `export` paths can consume records without paying the
//!   verifier's cost.
//! - **No truncation.** Crash recovery — including the `len_trailer !=
//!   len_prefix` torn-tail truncation — is [R5 / OGE-432]. The Reader
//!   detects the torn tail (returns [`ReaderError::TornTail`]) and
//!   stops gracefully; rewriting the file is somebody else's job.
//!
//! [R3 / OGE-437]: https://linear.app/ogenticai/issue/OGE-437
//! [R5 / OGE-432]: https://linear.app/ogenticai/issue/OGE-432
//!
//! ## Durability model
//!
//! The Reader sees whatever the kernel has made visible to read syscalls
//! on this filesystem. Records that the Writer wrote-but-didn't-flush
//! are still readable from the page cache during a process lifetime;
//! they are *not* yet durable across a power-loss event. That's the
//! Writer's `flush()` semantics, documented in [`crate::writer`].

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use crate::cbor::{self, CborError, Value};
use crate::key::HMAC_LEN;
use crate::segment::{
    FORMAT_MAGIC, FORMAT_VERSION, HEADER_BODY_LEN, HEADER_TOTAL_LEN, RECORD_FRAMING_OVERHEAD,
    SESSION_ID_LEN,
};
use crate::writer::PayloadValue;

/// Read strategy. Configurable so analytical / batch consumers can opt
/// into memory-mapping when their workload justifies it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ReadStrategy {
    /// Plain buffered file I/O. Simple, works everywhere, default.
    #[default]
    Buffered,
    /// `mmap(2)`-backed read. Faster for very large logs that fit in
    /// virtual memory and that the reader scans more than once. Unix +
    /// Windows; the underlying [`memmap2`] crate handles the platform
    /// differences.
    Mmap,
}

/// Reader configuration.
#[derive(Debug, Clone, Default)]
pub struct ReaderConfig {
    /// Which read strategy to use. Default: [`ReadStrategy::Buffered`].
    /// The default is documented choice — most consumers stream
    /// records once and gain nothing from mmap; mmap is opt-in for
    /// analytical workloads that scan repeatedly.
    pub read_strategy: ReadStrategy,
}

/// A fully-decoded record from disk.
///
/// `payload_bytes` is the canonical CBOR encoding of the record map —
/// the exact bytes that were HMAC'd at write time. R3 / OGE-437's
/// verifier consumes this directly to recompute the chain without
/// re-encoding the record. Without it, the verifier would have to
/// trust the Reader's decode-then-re-encode round-trip to be
/// byte-identical, which is exactly the kind of assumption a
/// court-defensibility tool should not make.
#[derive(Debug, Clone)]
pub struct Record {
    /// Which segment file this record lives in (matches the file name
    /// `audit-NNNN.cbor`'s `NNNN`).
    pub segment_index: u16,
    /// Record id, monotonic per segment, starts at 0.
    pub record_id: u64,
    /// HMAC of the preceding record (or the segment's `chain_start` for
    /// record 0 of segment 0).
    pub prev_hash: [u8; HMAC_LEN],
    /// RFC 3339 UTC, millisecond precision, ending with `Z`.
    pub ts_wall: String,
    /// Milliseconds since session start on a monotonic clock.
    pub ts_mono_delta: u64,
    /// Per-session UUID (16 bytes).
    pub session_id: [u8; SESSION_ID_LEN],
    /// Actor identifier (`user:alice`, `system:audit`, etc.).
    pub actor: String,
    /// Event name in `category.action` form.
    pub event: String,
    /// Event-specific structured payload.
    pub payload: BTreeMap<String, PayloadValue>,
    /// Signing-key fingerprint (must match the segment header's `key_id`).
    pub key_id: [u8; HMAC_LEN],
    /// Major version of the event's payload schema.
    pub schema_version: u8,
    /// HMAC-SHA256 of `payload_bytes` (consumed by the verifier).
    pub hmac: [u8; HMAC_LEN],
    /// Canonical CBOR encoding of the record map. Exactly the bytes the
    /// HMAC was computed over. The verifier consumes these directly.
    pub payload_bytes: Vec<u8>,
    /// Byte offset of this record's `len_prefix` field within its segment file.
    pub file_offset: u64,
}

/// Errors the Reader can produce.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ReaderError {
    /// I/O failure (open, read, seek, file metadata).
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Segment header CRC32 failed, magic bytes wrong, version
    /// unsupported, or other header-level corruption.
    #[error("invalid segment header in segment {segment_index}: {message}")]
    InvalidHeader {
        /// Segment whose header failed validation.
        segment_index: u16,
        /// Human-readable description of what was wrong.
        message: String,
    },

    /// Record payload could not be canonical-decoded (bad CBOR or
    /// schema violation). The corresponding violation kind in the
    /// verifier's report is `RecordCorrupt`.
    #[error("record decode error at segment {segment_index} offset {offset}: {message}")]
    Decode {
        /// Segment whose record failed to decode.
        segment_index: u16,
        /// Byte offset of the bad record's `len_prefix` field.
        offset: u64,
        /// Human-readable description of the decoder failure.
        message: String,
    },

    /// `len_trailer` did not match `len_prefix`, or the file ended
    /// before the trailer was fully written. Recoverable via R5 /
    /// OGE-432; the Reader stops gracefully here and surfaces the
    /// position so the caller (or R5) can truncate cleanly.
    #[error("torn tail in segment {segment_index} at offset {offset}; partial write")]
    TornTail {
        /// Segment whose tail was torn.
        segment_index: u16,
        /// Byte offset of the partial record's `len_prefix` field.
        offset: u64,
    },

    /// Asked for a `(segment_index, record_id)` that does not exist in
    /// the log directory or whose segment ended before reaching it.
    #[error("record not found: segment {segment_index} record_id {record_id}")]
    NotFound {
        /// Segment that was searched.
        segment_index: u16,
        /// Record id that was searched for.
        record_id: u64,
    },
}

/// Append-only reader over a directory of segment files.
#[derive(Debug)]
pub struct Reader {
    log_dir: PathBuf,
    config: ReaderConfig,
}

impl Reader {
    /// Open a log directory for reading. Does not require the signing
    /// key — HMAC verification is the verifier's job ([R3 / OGE-437]).
    ///
    /// Fails fast if the directory does not exist or if `read_dir`
    /// returns an error; segments themselves are not validated here.
    /// Invalid segments surface as iterator / seek errors at call time.
    ///
    /// [R3 / OGE-437]: https://linear.app/ogenticai/issue/OGE-437
    pub fn open(log_dir: impl AsRef<Path>) -> Result<Self, ReaderError> {
        Self::with_config(log_dir, ReaderConfig::default())
    }

    /// Like [`Reader::open`] but with an explicit [`ReaderConfig`].
    pub fn with_config(
        log_dir: impl AsRef<Path>,
        config: ReaderConfig,
    ) -> Result<Self, ReaderError> {
        let log_dir = log_dir.as_ref().to_path_buf();
        // Validate the directory exists and is readable now so callers
        // get a clear error early rather than on the first iter() call.
        let _ = std::fs::read_dir(&log_dir)?;
        Ok(Self { log_dir, config })
    }

    /// Return a fresh iterator positioned at the start of segment 0.
    /// Multiple iterators may be active simultaneously; they don't
    /// interfere.
    #[must_use]
    pub fn iter(&self) -> RecordIterator<'_> {
        RecordIterator::new(self)
    }

    /// Jump to `(segment_index, record_id)`. Returns the record or
    /// [`ReaderError::NotFound`] if either the segment does not exist
    /// or the segment ends before reaching `record_id`.
    pub fn seek(&self, segment_index: u16, record_id: u64) -> Result<Record, ReaderError> {
        let path = self.segment_path(segment_index);
        let metadata = std::fs::metadata(&path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                ReaderError::NotFound {
                    segment_index,
                    record_id,
                }
            } else {
                ReaderError::Io(e)
            }
        })?;
        let len = metadata.len();
        let mut file = File::open(&path)?;

        // Validate the header before scanning records.
        let header = read_header(&mut file, segment_index)?;
        debug_assert_eq!(header.segment_index, segment_index);

        let mut offset: u64 = HEADER_TOTAL_LEN as u64;
        loop {
            if offset >= len {
                return Err(ReaderError::NotFound {
                    segment_index,
                    record_id,
                });
            }
            let record = read_record(&mut file, segment_index, offset, len)?;
            let next_offset =
                offset + (RECORD_FRAMING_OVERHEAD as u64) + (record.payload_bytes.len() as u64);
            if record.record_id == record_id {
                return Ok(record);
            }
            offset = next_offset;
        }
    }

    /// List the segment indices currently visible in the log directory.
    /// Re-reads the directory each call, so cooperates with a live
    /// writer that rolls over to new segments.
    pub fn segments(&self) -> Result<Vec<u16>, ReaderError> {
        let mut out = Vec::new();
        for entry in std::fs::read_dir(&self.log_dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            let Some(idx) = parse_segment_filename(name) else {
                continue;
            };
            out.push(idx);
        }
        out.sort_unstable();
        Ok(out)
    }

    /// Configured read strategy.
    #[must_use]
    pub fn read_strategy(&self) -> ReadStrategy {
        self.config.read_strategy
    }

    fn segment_path(&self, segment_index: u16) -> PathBuf {
        self.log_dir.join(format!("audit-{segment_index:04}.cbor"))
    }
}

/// Iterator state. Yields records in append order, cooperates with a
/// live writer (returns `Ok(None)` at EOF; a subsequent call may yield
/// more if the writer has appended in between).
#[derive(Debug)]
pub struct RecordIterator<'a> {
    reader: &'a Reader,
    /// Current segment being scanned. `None` means we're between
    /// segments and the next call will pick the next one up.
    current_segment: Option<u16>,
    /// Byte offset within the current segment to read next from.
    /// Initialized to `HEADER_TOTAL_LEN` when a new segment is opened.
    current_offset: u64,
    /// Cached open handle on the current segment. Avoids re-opening
    /// every call for the common-case sequential read.
    current_file: Option<File>,
    /// Whether we've validated the current segment's header.
    header_verified: bool,
}

impl<'a> RecordIterator<'a> {
    fn new(reader: &'a Reader) -> Self {
        Self {
            reader,
            current_segment: None,
            current_offset: 0,
            current_file: None,
            header_verified: false,
        }
    }

    /// Read the next available record. Returns:
    ///
    /// - `Ok(Some(record))` — next record yielded.
    /// - `Ok(None)` — no more records *right now*. A subsequent call
    ///   may yield more if the writer appended in between (this is the
    ///   live-writer cooperation path).
    /// - `Err(...)` — I/O failure, decode failure, or a torn tail.
    pub fn next_record(&mut self) -> Result<Option<Record>, ReaderError> {
        loop {
            // Pick up where we left off, opening the next segment if
            // we don't currently have one.
            if self.current_file.is_none() {
                let next_idx = match self.current_segment {
                    None => 0,
                    Some(prev) => prev + 1,
                };
                let path = self.reader.segment_path(next_idx);
                match File::open(&path) {
                    Ok(file) => {
                        self.current_file = Some(file);
                        self.current_segment = Some(next_idx);
                        self.current_offset = HEADER_TOTAL_LEN as u64;
                        self.header_verified = false;
                    },
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        // No further segments visible. Could be live
                        // writer in the middle of rolling over; we
                        // return None and the caller can retry.
                        return Ok(None);
                    },
                    Err(e) => return Err(ReaderError::Io(e)),
                }
            }

            let segment_index = self.current_segment.expect("file opened ⇒ segment set");
            let file = self.current_file.as_mut().expect("file opened above");

            // Validate header once per segment.
            if !self.header_verified {
                let _header = read_header(file, segment_index)?;
                self.header_verified = true;
            }

            let len = file.metadata()?.len();
            if self.current_offset >= len {
                // Hit current EOF for this segment. Two cases:
                //   1. Writer rolled over → look for next segment.
                //   2. Live writer is mid-segment → return None and let
                //      the caller retry.
                //
                // We disambiguate by checking whether `segment_index + 1`
                // exists. If yes, advance; if no, return None.
                let next_path = self.reader.segment_path(segment_index + 1);
                if next_path.exists() {
                    self.current_file = None;
                    self.header_verified = false;
                    continue; // outer loop opens the next segment
                }
                return Ok(None);
            }

            let record = read_record(file, segment_index, self.current_offset, len)?;
            self.current_offset +=
                (RECORD_FRAMING_OVERHEAD as u64) + (record.payload_bytes.len() as u64);
            return Ok(Some(record));
        }
    }
}

/// Parse `audit-NNNN.cbor` -> `Some(NNNN)`. Returns `None` for anything
/// that doesn't fit the v0.1 naming convention.
fn parse_segment_filename(name: &str) -> Option<u16> {
    let stripped = name.strip_prefix("audit-")?.strip_suffix(".cbor")?;
    if stripped.len() != 4 {
        return None;
    }
    stripped.parse().ok()
}

/// Internal: open + parse a segment header from the start of `file`.
fn read_header(file: &mut File, segment_index: u16) -> Result<HeaderView, ReaderError> {
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = [0u8; HEADER_TOTAL_LEN];
    file.read_exact(&mut bytes).map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            ReaderError::InvalidHeader {
                segment_index,
                message: "file shorter than 80-byte header".into(),
            }
        } else {
            ReaderError::Io(e)
        }
    })?;
    if &bytes[..4] != FORMAT_MAGIC {
        return Err(ReaderError::InvalidHeader {
            segment_index,
            message: format!("magic mismatch: {:?}", &bytes[..4]),
        });
    }
    let version = u16::from_le_bytes([bytes[4], bytes[5]]);
    if version != FORMAT_VERSION {
        return Err(ReaderError::InvalidHeader {
            segment_index,
            message: format!("unsupported version 0x{version:04x}"),
        });
    }
    let on_disk_idx = u16::from_le_bytes([bytes[6], bytes[7]]);
    if on_disk_idx != segment_index {
        return Err(ReaderError::InvalidHeader {
            segment_index,
            message: format!(
                "filename indicates segment {segment_index} but header says {on_disk_idx}"
            ),
        });
    }
    let stored_crc = u32::from_le_bytes([bytes[72], bytes[73], bytes[74], bytes[75]]);
    let computed_crc = crc32fast::hash(&bytes[..HEADER_BODY_LEN]);
    if stored_crc != computed_crc {
        return Err(ReaderError::InvalidHeader {
            segment_index,
            message: format!(
                "CRC32 mismatch: stored 0x{stored_crc:08x}, computed 0x{computed_crc:08x}"
            ),
        });
    }
    let mut key_id = [0u8; HMAC_LEN];
    key_id.copy_from_slice(&bytes[8..40]);
    let mut prev_final = [0u8; HMAC_LEN];
    prev_final.copy_from_slice(&bytes[40..72]);
    Ok(HeaderView {
        segment_index,
        key_id,
        prev_final,
    })
}

#[derive(Debug, Clone, Copy)]
struct HeaderView {
    #[allow(dead_code)] // surfaced by the verifier, not this module
    segment_index: u16,
    #[allow(dead_code)]
    key_id: [u8; HMAC_LEN],
    #[allow(dead_code)]
    prev_final: [u8; HMAC_LEN],
}

/// Internal: read one framed record starting at `offset`. Handles
/// torn-tail detection; converts decode errors into `ReaderError::Decode`.
fn read_record(
    file: &mut File,
    segment_index: u16,
    offset: u64,
    len: u64,
) -> Result<Record, ReaderError> {
    // len_prefix (4 bytes).
    if len - offset < 4 {
        return Err(ReaderError::TornTail {
            segment_index,
            offset,
        });
    }
    file.seek(SeekFrom::Start(offset))?;
    let mut lp_bytes = [0u8; 4];
    file.read_exact(&mut lp_bytes)?;
    let len_prefix = u32::from_le_bytes(lp_bytes) as u64;
    let framed_total = 4u64 + len_prefix + (HMAC_LEN as u64) + 4u64;
    if len - offset < framed_total {
        return Err(ReaderError::TornTail {
            segment_index,
            offset,
        });
    }
    let mut payload_bytes = vec![0u8; len_prefix as usize];
    file.read_exact(&mut payload_bytes)?;
    let mut hmac_bytes = [0u8; HMAC_LEN];
    file.read_exact(&mut hmac_bytes)?;
    let mut lt_bytes = [0u8; 4];
    file.read_exact(&mut lt_bytes)?;
    let len_trailer = u32::from_le_bytes(lt_bytes) as u64;
    if len_trailer != len_prefix {
        return Err(ReaderError::TornTail {
            segment_index,
            offset,
        });
    }

    let record_map =
        cbor::decode(&payload_bytes).map_err(|e| record_decode_err(segment_index, offset, e))?;
    let record = decode_record_map(
        record_map,
        segment_index,
        offset,
        &payload_bytes,
        hmac_bytes,
    )?;
    Ok(record)
}

fn record_decode_err(segment_index: u16, offset: u64, err: CborError) -> ReaderError {
    ReaderError::Decode {
        segment_index,
        offset,
        message: err.to_string(),
    }
}

/// Convert a decoded CBOR `Map` into a [`Record`].
fn decode_record_map(
    value: Value,
    segment_index: u16,
    offset: u64,
    payload_bytes: &[u8],
    hmac_bytes: [u8; HMAC_LEN],
) -> Result<Record, ReaderError> {
    let Value::Map(pairs) = value else {
        return Err(ReaderError::Decode {
            segment_index,
            offset,
            message: "record payload is not a CBOR map".into(),
        });
    };
    if pairs.len() != 10 {
        return Err(ReaderError::Decode {
            segment_index,
            offset,
            message: format!("record map has {} entries (expected 10)", pairs.len()),
        });
    }
    let mut record_id: Option<u64> = None;
    let mut prev_hash: Option<[u8; HMAC_LEN]> = None;
    let mut ts_wall: Option<String> = None;
    let mut ts_mono_delta: Option<u64> = None;
    let mut session_id: Option<[u8; SESSION_ID_LEN]> = None;
    let mut actor: Option<String> = None;
    let mut event: Option<String> = None;
    let mut payload: Option<BTreeMap<String, PayloadValue>> = None;
    let mut key_id: Option<[u8; HMAC_LEN]> = None;
    let mut schema_version: Option<u8> = None;

    for (k, v) in pairs {
        let Value::Uint(key) = k else {
            return Err(ReaderError::Decode {
                segment_index,
                offset,
                message: "record map key not an unsigned integer".into(),
            });
        };
        match key {
            1 => record_id = Some(expect_u64(v, "record_id", segment_index, offset)?),
            2 => {
                prev_hash = Some(expect_fixed_bstr(
                    v,
                    HMAC_LEN,
                    "prev_hash",
                    segment_index,
                    offset,
                )?)
            },
            3 => ts_wall = Some(expect_text(v, "ts_wall", segment_index, offset)?),
            4 => ts_mono_delta = Some(expect_u64(v, "ts_mono_delta", segment_index, offset)?),
            5 => {
                session_id = Some(expect_fixed_bstr(
                    v,
                    SESSION_ID_LEN,
                    "session_id",
                    segment_index,
                    offset,
                )?)
            },
            6 => actor = Some(expect_text(v, "actor", segment_index, offset)?),
            7 => event = Some(expect_text(v, "event", segment_index, offset)?),
            8 => payload = Some(expect_payload_map(v, segment_index, offset)?),
            9 => {
                key_id = Some(expect_fixed_bstr(
                    v,
                    HMAC_LEN,
                    "key_id",
                    segment_index,
                    offset,
                )?)
            },
            10 => {
                let raw = expect_u64(v, "schema_version", segment_index, offset)?;
                if raw > u8::MAX as u64 {
                    return Err(ReaderError::Decode {
                        segment_index,
                        offset,
                        message: format!("schema_version {raw} exceeds u8::MAX"),
                    });
                }
                schema_version = Some(raw as u8);
            },
            other => {
                return Err(ReaderError::Decode {
                    segment_index,
                    offset,
                    message: format!("unknown record-map key {other} (v0.1 reserves 1..=10)"),
                });
            },
        }
    }

    let record_id = required(record_id, "record_id", segment_index, offset)?;
    let prev_hash = required(prev_hash, "prev_hash", segment_index, offset)?;
    let ts_wall = required(ts_wall, "ts_wall", segment_index, offset)?;
    let ts_mono_delta = required(ts_mono_delta, "ts_mono_delta", segment_index, offset)?;
    let session_id = required(session_id, "session_id", segment_index, offset)?;
    let actor = required(actor, "actor", segment_index, offset)?;
    let event = required(event, "event", segment_index, offset)?;
    let payload = required(payload, "payload", segment_index, offset)?;
    let key_id = required(key_id, "key_id", segment_index, offset)?;
    let schema_version = required(schema_version, "schema_version", segment_index, offset)?;

    Ok(Record {
        segment_index,
        record_id,
        prev_hash,
        ts_wall,
        ts_mono_delta,
        session_id,
        actor,
        event,
        payload,
        key_id,
        schema_version,
        hmac: hmac_bytes,
        payload_bytes: payload_bytes.to_vec(),
        file_offset: offset,
    })
}

fn required<T>(
    opt: Option<T>,
    name: &str,
    segment_index: u16,
    offset: u64,
) -> Result<T, ReaderError> {
    opt.ok_or_else(|| ReaderError::Decode {
        segment_index,
        offset,
        message: format!("required field `{name}` missing"),
    })
}

fn expect_u64(v: Value, field: &str, segment_index: u16, offset: u64) -> Result<u64, ReaderError> {
    if let Value::Uint(n) = v {
        Ok(n)
    } else {
        Err(ReaderError::Decode {
            segment_index,
            offset,
            message: format!("field `{field}` expected u64, got {v:?}"),
        })
    }
}

fn expect_text(
    v: Value,
    field: &str,
    segment_index: u16,
    offset: u64,
) -> Result<String, ReaderError> {
    if let Value::Text(s) = v {
        Ok(s)
    } else {
        Err(ReaderError::Decode {
            segment_index,
            offset,
            message: format!("field `{field}` expected text string, got {v:?}"),
        })
    }
}

fn expect_fixed_bstr<const N: usize>(
    v: Value,
    n: usize,
    field: &str,
    segment_index: u16,
    offset: u64,
) -> Result<[u8; N], ReaderError> {
    debug_assert_eq!(n, N);
    if let Value::Bytes(b) = v {
        if b.len() != N {
            return Err(ReaderError::Decode {
                segment_index,
                offset,
                message: format!(
                    "field `{field}` expected {N}-byte bstr, got {} bytes",
                    b.len()
                ),
            });
        }
        let mut out = [0u8; N];
        out.copy_from_slice(&b);
        Ok(out)
    } else {
        Err(ReaderError::Decode {
            segment_index,
            offset,
            message: format!("field `{field}` expected byte string, got {v:?}"),
        })
    }
}

fn expect_payload_map(
    v: Value,
    segment_index: u16,
    offset: u64,
) -> Result<BTreeMap<String, PayloadValue>, ReaderError> {
    let Value::Map(pairs) = v else {
        return Err(ReaderError::Decode {
            segment_index,
            offset,
            message: format!("payload expected map, got {v:?}"),
        });
    };
    let mut out: BTreeMap<String, PayloadValue> = BTreeMap::new();
    for (k, val) in pairs {
        let Value::Text(key) = k else {
            return Err(ReaderError::Decode {
                segment_index,
                offset,
                message: "payload map key not a text string".into(),
            });
        };
        out.insert(key, cbor_value_to_payload(val, segment_index, offset)?);
    }
    Ok(out)
}

fn cbor_value_to_payload(
    v: Value,
    segment_index: u16,
    offset: u64,
) -> Result<PayloadValue, ReaderError> {
    Ok(match v {
        Value::Uint(n) => PayloadValue::Uint(n),
        Value::Nint(n) => PayloadValue::Nint(n),
        Value::Bytes(b) => PayloadValue::Bytes(b),
        Value::Text(s) => PayloadValue::Text(s),
        Value::Bool(b) => PayloadValue::Bool(b),
        Value::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                out.push(cbor_value_to_payload(item, segment_index, offset)?);
            }
            PayloadValue::List(out)
        },
        Value::Map(pairs) => {
            let mut out = BTreeMap::new();
            for (k, val) in pairs {
                let Value::Text(key) = k else {
                    return Err(ReaderError::Decode {
                        segment_index,
                        offset,
                        message: "nested payload map key not text".into(),
                    });
                };
                out.insert(key, cbor_value_to_payload(val, segment_index, offset)?);
            }
            PayloadValue::Map(out)
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_segment_filename_accepts_valid() {
        assert_eq!(parse_segment_filename("audit-0000.cbor"), Some(0));
        assert_eq!(parse_segment_filename("audit-0042.cbor"), Some(42));
        assert_eq!(parse_segment_filename("audit-9999.cbor"), Some(9999));
    }

    #[test]
    fn parse_segment_filename_rejects_invalid() {
        assert_eq!(parse_segment_filename("audit-0.cbor"), None);
        assert_eq!(parse_segment_filename("audit-00000.cbor"), None);
        assert_eq!(parse_segment_filename("audit-0000.txt"), None);
        assert_eq!(parse_segment_filename("foo-0000.cbor"), None);
        assert_eq!(parse_segment_filename(".audit-0000.cbor"), None);
    }

    #[test]
    fn read_strategy_default_is_buffered() {
        assert_eq!(ReadStrategy::default(), ReadStrategy::Buffered);
    }
}
