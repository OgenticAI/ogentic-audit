//! Append-only writer for signed logs (spec v0.2 §7.1).
//!
//! Same durability and crash-recovery model as the v0.1 [`crate::Writer`]:
//! appends go straight to the OS, [`SignedWriter::flush`] makes them
//! durable, and reopening truncates a torn tail. On reopen the writer
//! walks the hash links of the last segment and verifies the signature of
//! its last complete record; since each signature covers `prev_hash`, that
//! one signature authenticates the segment's earlier envelopes.
//!
//! Every signature is verified before it is written (a fault during
//! signing must never reach disk), and the writer refuses to append to a
//! log in another format, under another key or `log_id`, or that is
//! sealed.

use std::collections::BTreeMap;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use super::ed25519;
use super::format::{
    self, body_hash, chain_start, encode_body, record_hash, Envelope, Frame, SignedHeader,
    EVENT_FINALIZED, EVENT_SEALED, HEADER_LEN, LOG_ID_LEN, MAX_ENVELOPE_LEN,
};
use super::keys::PublicKey;
use super::signer::{sign_checked, Signer};
use super::sshsig;
use super::{
    parse_rfc3339_millis, random_nonce, rfc3339_from_millis, FORMAT_VERSION_SIGNED, NS_RECORD,
};
use crate::key::HmacBytes;
use crate::segment::SESSION_ID_LEN;
use crate::sync_compat::full_sync;
use crate::writer::{
    PayloadValue, RecordId, RecordInput, RecoveryAction, RecoveryFailure, RecoveryReport,
    WriterConfig, WriterError,
};

type NonceSource = Box<dyn FnMut() -> [u8; 32] + Send>;

/// Append-only writer for format `0x0002`.
pub struct SignedWriter {
    log_dir: PathBuf,
    signer: Box<dyn Signer>,
    session_id: [u8; SESSION_ID_LEN],
    config: WriterConfig,
    log_id: [u8; LOG_ID_LEN],
    current: Seg,
    last_ts: Option<(String, u64)>,
    sealed: bool,
    recovery: RecoveryReport,
    nonces: Option<NonceSource>,
}

struct Seg {
    index: u16,
    file: File,
    bytes_written: u64,
    last_hash: [u8; 32],
    next_record_id: RecordId,
}

impl fmt::Debug for SignedWriter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignedWriter")
            .field("log_dir", &self.log_dir)
            .field("log_id", &super::hex(&self.log_id))
            .field("public_key", self.signer.public_key())
            .field("segment_index", &self.current.index)
            .field("next_record_id", &self.current.next_record_id)
            .field("sealed", &self.sealed)
            .finish_non_exhaustive()
    }
}

fn segment_path(dir: &Path, index: u16) -> PathBuf {
    dir.join(format!("audit-{index:04}.cbor"))
}

fn bump_ms(ts: &str, ms: u64) -> (String, u64) {
    let t = parse_rfc3339_millis(ts).unwrap_or(0);
    (rfc3339_from_millis(t + 1), ms.saturating_add(1))
}

fn recovery(reason: RecoveryFailure) -> WriterError {
    WriterError::Recovery { reason }
}

impl SignedWriter {
    /// Open (or create) a signed log in `dir`. Creating draws a random
    /// `log_id`; reopening checks the existing log is a signed log under
    /// the same key and resumes it.
    pub fn open_signed(
        dir: impl AsRef<Path>,
        signer: Box<dyn Signer>,
        session_id: [u8; SESSION_ID_LEN],
    ) -> Result<Self, WriterError> {
        Self::open_signed_with_config(dir, signer, session_id, WriterConfig::default())
    }

    /// [`SignedWriter::open_signed`] with an explicit configuration.
    pub fn open_signed_with_config(
        dir: impl AsRef<Path>,
        signer: Box<dyn Signer>,
        session_id: [u8; SESSION_ID_LEN],
        config: WriterConfig,
    ) -> Result<Self, WriterError> {
        let mut log_id = [0u8; LOG_ID_LEN];
        getrandom::getrandom(&mut log_id).map_err(|e| WriterError::InvalidInput(e.to_string()))?;
        Self::open_inner(dir.as_ref(), signer, session_id, config, log_id)
    }

    /// Create a log with a caller-chosen `log_id`. **For reproducible test
    /// vectors only**: a real log's `log_id` comes from the OS CSPRNG.
    /// Fails if the directory already holds segments.
    pub fn create_with_log_id(
        dir: impl AsRef<Path>,
        signer: Box<dyn Signer>,
        session_id: [u8; SESSION_ID_LEN],
        config: WriterConfig,
        log_id: [u8; LOG_ID_LEN],
    ) -> Result<Self, WriterError> {
        let dir = dir.as_ref();
        if super::log_format(dir).ok().flatten().is_some() {
            return Err(WriterError::InvalidInput(
                "create_with_log_id needs an empty directory".into(),
            ));
        }
        Self::open_inner(dir, signer, session_id, config, log_id)
    }

    /// Replace the body-nonce source. **For reproducible test vectors
    /// only**: real nonces come from the OS CSPRNG, and a predictable
    /// nonce lets anyone confirm a guess about an elided body.
    #[must_use]
    pub fn with_nonce_source(mut self, f: impl FnMut() -> [u8; 32] + Send + 'static) -> Self {
        self.nonces = Some(Box::new(f));
        self
    }

    fn open_inner(
        dir: &Path,
        signer: Box<dyn Signer>,
        session_id: [u8; SESSION_ID_LEN],
        config: WriterConfig,
        fresh_log_id: [u8; LOG_ID_LEN],
    ) -> Result<Self, WriterError> {
        std::fs::create_dir_all(dir)?;
        let pk = *signer.public_key();
        let (segments, _) = super::verify::list_segments(dir)?;
        if segments.is_empty() {
            let current = create_segment(dir, 0, fresh_log_id, &pk, [0u8; 32])?;
            let last = current.last_hash;
            return Ok(Self {
                log_dir: dir.to_path_buf(),
                signer,
                session_id,
                config,
                log_id: fresh_log_id,
                current,
                last_ts: None,
                sealed: false,
                recovery: RecoveryReport {
                    action: RecoveryAction::Fresh,
                    current_segment_index: 0,
                    last_record_id: None,
                    records_in_current_segment: 0,
                    truncated_bytes: 0,
                    segments_scanned: 0,
                    last_hmac: HmacBytes::from(last),
                },
                nonces: None,
            });
        }
        match super::log_format(dir)? {
            Some(FORMAT_VERSION_SIGNED) => {},
            Some(v) => return Err(WriterError::FormatMismatch { found: v }),
            None => unreachable!("segments listed"),
        }
        let first = segments[0];
        let (h0, _) = read_header(dir, first)?;
        check_header_key(&h0, &pk, first)?;
        let latest = *segments.last().unwrap_or(&first);
        let scan = scan_segment(dir, latest, &h0, &pk, true)?;

        let mut last_ts = scan.last_ts.clone();
        if scan.records == 0 && latest > 0 {
            // Header-only latest segment: take the time anchor from the
            // previous one.
            let prev = scan_segment(dir, latest - 1, &h0, &pk, false)?;
            if prev.last_event.as_deref() == Some(EVENT_SEALED) {
                return Err(WriterError::Sealed);
            }
            last_ts = prev.last_ts;
        }
        if scan.last_event.as_deref() == Some(EVENT_SEALED) {
            return Err(WriterError::Sealed);
        }
        let (current, action) = if scan.last_event.as_deref() == Some(EVENT_FINALIZED) {
            let next = latest
                .checked_add(1)
                .ok_or_else(|| WriterError::InvalidInput("segment_index overflow (u16)".into()))?;
            (
                create_segment(dir, next, h0.log_id, &pk, scan.last_hash)?,
                RecoveryAction::OpenedNextAfterFinalized,
            )
        } else {
            let mut file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(segment_path(dir, latest))?;
            file.seek(SeekFrom::Start(scan.end))?;
            (
                Seg {
                    index: latest,
                    file,
                    bytes_written: scan.end,
                    last_hash: scan.last_hash,
                    next_record_id: scan.records,
                },
                if scan.truncated > 0 {
                    RecoveryAction::Repaired
                } else {
                    RecoveryAction::Resumed
                },
            )
        };
        let recovery = RecoveryReport {
            action,
            current_segment_index: current.index,
            last_record_id: scan.records.checked_sub(1),
            records_in_current_segment: current.next_record_id,
            truncated_bytes: scan.truncated,
            segments_scanned: 1,
            last_hmac: HmacBytes::from(current.last_hash),
        };
        Ok(Self {
            log_dir: dir.to_path_buf(),
            signer,
            session_id,
            config,
            log_id: h0.log_id,
            current,
            last_ts,
            sealed: false,
            recovery,
            nonces: None,
        })
    }

    /// What opening did (fresh, resumed, repaired, next segment).
    /// `last_hmac` carries the last `record_hash` in signed mode.
    #[must_use]
    pub fn recovery_report(&self) -> &RecoveryReport {
        &self.recovery
    }

    /// The log's random id.
    #[must_use]
    pub fn log_id(&self) -> [u8; LOG_ID_LEN] {
        self.log_id
    }

    /// The signer's public key.
    #[must_use]
    pub fn public_key(&self) -> &PublicKey {
        self.signer.public_key()
    }

    /// `record_hash` of the last record (or the current segment's chain
    /// start if it has no records yet).
    #[must_use]
    pub fn last_record_hash(&self) -> [u8; 32] {
        self.current.last_hash
    }

    /// The segment being written.
    #[must_use]
    pub fn segment_index(&self) -> u16 {
        self.current.index
    }

    /// Records written to the current segment.
    #[must_use]
    pub fn record_count_in_segment(&self) -> u64 {
        self.current.next_record_id
    }

    /// Path of the current segment file.
    #[must_use]
    pub fn current_segment_path(&self) -> PathBuf {
        segment_path(&self.log_dir, self.current.index)
    }

    fn next_nonce(&mut self) -> [u8; 32] {
        match &mut self.nonces {
            Some(f) => f(),
            None => random_nonce(),
        }
    }

    /// Append a record. Returns its position in the current segment.
    pub fn append(&mut self, input: RecordInput) -> Result<RecordId, WriterError> {
        if self.sealed {
            return Err(WriterError::Sealed);
        }
        validate(&input)?;
        if matches!(input.event.as_str(), EVENT_FINALIZED | EVENT_SEALED) {
            return Err(WriterError::InvalidInput(format!(
                "{} records are written by the writer itself",
                input.event
            )));
        }
        let nonce = self.next_nonce();
        let body = encode_body(&input.actor, &input.payload, &nonce);
        if self.config.finalize_on_rollover && self.current.next_record_id > 0 {
            let this = self.framed_len(&input, &body);
            let fin = self.framed_len(
                &finalize_input(&input.ts_wall, input.ts_mono_delta, u64::MAX, &[0; 32]),
                &[0u8; 160],
            );
            if self.current.bytes_written + this + fin > self.config.segment_size_bytes {
                self.rollover()?;
            }
        }
        self.write_record(&input, &body)
    }

    fn framed_len(&self, input: &RecordInput, body: &[u8]) -> u64 {
        let env = self.envelope(input, u64::MAX, &[0u8; 32]);
        (4 + env.encode().len() + 64 + 4 + body.len() + 4) as u64
    }

    fn envelope(&self, input: &RecordInput, record_id: u64, body_hash: &[u8; 32]) -> Envelope {
        let pk = self.signer.public_key();
        Envelope {
            record_id,
            prev_hash: self.current.last_hash,
            ts_wall: input.ts_wall.clone(),
            ts_mono_delta: input.ts_mono_delta,
            session_id: self.session_id,
            event: input.event.clone(),
            key_id: pk.fingerprint().0,
            schema_version: input.schema_version,
            segment_index: self.current.index,
            sig_alg: pk.alg().code(),
            body_hash: *body_hash,
        }
    }

    fn write_record(&mut self, input: &RecordInput, body: &[u8]) -> Result<RecordId, WriterError> {
        let id = self.current.next_record_id;
        let env = self.envelope(input, id, &body_hash(body)).encode();
        if env.len() > MAX_ENVELOPE_LEN as usize {
            return Err(WriterError::InvalidInput(format!(
                "envelope of {} bytes exceeds the 4096-byte limit (event name or timestamps too long)",
                env.len()
            )));
        }
        let sig = sign_checked(self.signer.as_ref(), NS_RECORD, &env)?;
        let framed = format::frame(&env, &sig.0, Some(body));
        self.current.file.write_all(&framed)?;
        self.current.bytes_written += framed.len() as u64;
        self.current.last_hash = record_hash(&env);
        self.current.next_record_id += 1;
        self.last_ts = Some((input.ts_wall.clone(), input.ts_mono_delta));
        Ok(id)
    }

    fn rollover(&mut self) -> Result<(), WriterError> {
        let (ts, mono) = self
            .last_ts
            .clone()
            .ok_or_else(|| WriterError::InvalidInput("rollover before any record".into()))?;
        let (ts, mono) = bump_ms(&ts, mono);
        let fin = finalize_input(
            &ts,
            mono,
            self.current.next_record_id,
            &self.current.last_hash,
        );
        let nonce = self.next_nonce();
        let body = encode_body(&fin.actor, &fin.payload, &nonce);
        self.write_record(&fin, &body)?;
        full_sync(&self.current.file)?;
        let next = self
            .current
            .index
            .checked_add(1)
            .ok_or_else(|| WriterError::InvalidInput("segment_index overflow (u16)".into()))?;
        let pk = *self.signer.public_key();
        self.current = create_segment(
            &self.log_dir,
            next,
            self.log_id,
            &pk,
            self.current.last_hash,
        )?;
        Ok(())
    }

    /// Close the log for good: write `log.sealed` (1 ms after the last
    /// record, on the signer's clock) and flush. Nothing can be appended
    /// afterwards, by this writer or a later one.
    pub fn seal(&mut self) -> Result<RecordId, WriterError> {
        if self.sealed {
            return Err(WriterError::Sealed);
        }
        let (ts, mono) = self
            .last_ts
            .clone()
            .ok_or_else(|| WriterError::InvalidInput("cannot seal a log with no records".into()))?;
        let (ts, mono) = bump_ms(&ts, mono);
        let input = RecordInput {
            ts_wall: ts,
            ts_mono_delta: mono,
            actor: "system:audit".into(),
            event: EVENT_SEALED.into(),
            payload: BTreeMap::new(),
            schema_version: 1,
        };
        let nonce = self.next_nonce();
        let body = encode_body(&input.actor, &input.payload, &nonce);
        let id = self.write_record(&input, &body)?;
        self.flush()?;
        self.sealed = true;
        Ok(id)
    }

    /// Make every appended record durable (`F_FULLFSYNC` on macOS).
    pub fn flush(&mut self) -> Result<(), WriterError> {
        full_sync(&self.current.file)?;
        #[cfg(unix)]
        {
            let dir = File::open(&self.log_dir)?;
            full_sync(&dir)?;
        }
        Ok(())
    }
}

fn finalize_input(ts: &str, mono: u64, records: u64, final_hash: &[u8; 32]) -> RecordInput {
    let mut payload = BTreeMap::new();
    payload.insert("records".into(), PayloadValue::Uint(records));
    payload.insert(
        "final_hash".into(),
        PayloadValue::Bytes(final_hash.to_vec()),
    );
    RecordInput {
        ts_wall: ts.to_string(),
        ts_mono_delta: mono,
        actor: "system:audit".into(),
        event: EVENT_FINALIZED.into(),
        payload,
        schema_version: 1,
    }
}

fn validate(input: &RecordInput) -> Result<(), WriterError> {
    if parse_rfc3339_millis(&input.ts_wall).is_none() {
        return Err(WriterError::InvalidInput(format!(
            "ts_wall must be RFC 3339 UTC with milliseconds, like 2026-10-03T12:00:00.000Z; got {:?}",
            input.ts_wall
        )));
    }
    let e = &input.event;
    if e.is_empty() || e.len() > 128 || !e.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
        return Err(WriterError::InvalidInput(
            "event must be 1–128 bytes of printable ASCII from a fixed vocabulary (it stays visible when a body is withheld, so it must not carry content)".into(),
        ));
    }
    Ok(())
}

fn create_segment(
    dir: &Path,
    index: u16,
    log_id: [u8; LOG_ID_LEN],
    pk: &PublicKey,
    prev_final: [u8; 32],
) -> Result<Seg, WriterError> {
    let header = SignedHeader::new(index, log_id, pk, prev_final).to_bytes();
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .read(true)
        .open(segment_path(dir, index))?;
    file.write_all(&header)?;
    Ok(Seg {
        index,
        file,
        bytes_written: HEADER_LEN as u64,
        last_hash: chain_start(&header),
        next_record_id: 0,
    })
}

fn read_header(dir: &Path, index: u16) -> Result<(SignedHeader, [u8; HEADER_LEN]), WriterError> {
    use crate::segment::HeaderParseError as E;
    let corrupt = |cause: E| {
        recovery(RecoveryFailure::HeaderCorrupt {
            segment_index: index,
            cause,
        })
    };
    let mut f = File::open(segment_path(dir, index))?;
    let mut b = [0u8; HEADER_LEN];
    let got = f.read(&mut b)?;
    if got < HEADER_LEN {
        return Err(corrupt(E::TooShort { got }));
    }
    let h = SignedHeader::from_bytes_unchecked(&b);
    if &b[..4] != crate::segment::FORMAT_MAGIC {
        return Err(corrupt(E::BadMagic {
            got: [b[0], b[1], b[2], b[3]],
        }));
    }
    if h.version != FORMAT_VERSION_SIGNED {
        return Err(WriterError::FormatMismatch { found: h.version });
    }
    let stored = u32::from_le_bytes([b[124], b[125], b[126], b[127]]);
    let computed = crc32fast::hash(&b[..124]);
    if stored != computed {
        return Err(corrupt(E::CrcMismatch {
            expected: computed,
            got: stored,
        }));
    }
    if h.reserved != 0 || h.segment_index != index {
        return Err(recovery(RecoveryFailure::ChainBreak {
            segment_index: index,
            record_id: 0,
            file_offset: 0,
        }));
    }
    Ok((h, b))
}

fn check_header_key(h: &SignedHeader, pk: &PublicKey, index: u16) -> Result<(), WriterError> {
    if h.key_id != pk.fingerprint().0
        || h.public_key != *pk.as_bytes()
        || h.sig_alg != pk.alg().code()
    {
        return Err(recovery(RecoveryFailure::KeyIdMismatch {
            segment_index: index,
            header_key_id_hex: super::hex(&h.key_id),
            expected_key_id_hex: pk.fingerprint().to_hex(),
        }));
    }
    Ok(())
}

struct Scan {
    records: u64,
    end: u64,
    truncated: u64,
    last_hash: [u8; 32],
    last_event: Option<String>,
    last_ts: Option<(String, u64)>,
}

/// Walk segment `index`: hash links from its chain start, then the last
/// complete record's signature. With `repair`, truncate a torn tail.
fn scan_segment(
    dir: &Path,
    index: u16,
    h0: &SignedHeader,
    pk: &PublicKey,
    repair: bool,
) -> Result<Scan, WriterError> {
    let (h, hb) = read_header(dir, index)?;
    check_header_key(&h, pk, index)?;
    if h.log_id != h0.log_id {
        return Err(recovery(RecoveryFailure::LogIdMismatch {
            segment_index: index,
        }));
    }
    let path = segment_path(dir, index);
    let file = OpenOptions::new().read(true).write(repair).open(&path)?;
    let file_len = file.metadata()?.len();
    let mut r = BufReader::new(file);
    r.seek(SeekFrom::Start(HEADER_LEN as u64))?;
    let mut offset = HEADER_LEN as u64;
    let mut prev = chain_start(&hb);
    let mut records = 0u64;
    let mut last: Option<(format::RawRecord, Envelope)> = None;
    let mut truncated = 0u64;
    loop {
        match format::read_frame(&mut r, offset, file_len)? {
            Frame::End => break,
            Frame::Torn { .. } | Frame::TooLarge { .. } => {
                truncated = file_len - offset;
                if repair {
                    let mut f = r.into_inner();
                    f.flush()?;
                    f.set_len(offset)?;
                    full_sync(&f)?;
                }
                break;
            },
            Frame::Record(raw) => {
                let env = Envelope::decode(&raw.envelope).map_err(|_| {
                    recovery(RecoveryFailure::SignatureInvalid {
                        segment_index: index,
                        record_id: records,
                        file_offset: raw.offset,
                    })
                })?;
                if env.prev_hash != prev || env.record_id != records || env.segment_index != index {
                    return Err(recovery(RecoveryFailure::ChainBreak {
                        segment_index: index,
                        record_id: records,
                        file_offset: raw.offset,
                    }));
                }
                prev = record_hash(&raw.envelope);
                offset += raw.total_len;
                records += 1;
                last = Some((raw, env));
            },
        }
    }
    if let Some((raw, env)) = &last {
        let data = sshsig::signed_data(NS_RECORD, &raw.envelope);
        let body_ok = raw
            .body
            .as_ref()
            .is_none_or(|b| body_hash(b) == env.body_hash);
        if ed25519::verify(pk.as_bytes(), &data, &raw.signature).is_err() || !body_ok {
            return Err(recovery(RecoveryFailure::SignatureInvalid {
                segment_index: index,
                record_id: env.record_id,
                file_offset: raw.offset,
            }));
        }
    }
    Ok(Scan {
        records,
        end: offset,
        truncated,
        last_hash: prev,
        last_event: last.as_ref().map(|(_, e)| e.event.clone()),
        last_ts: last.map(|(_, e)| (e.ts_wall, e.ts_mono_delta)),
    })
}
