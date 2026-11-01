//! Byte layouts of format `0x0002` (spec v0.2 §4–§6).
//!
//! ```text
//! segment  = header(128) ‖ record*
//! header   = "OGAU" ‖ version u16 ‖ segment_index u16 ‖ sig_alg u16 ‖ reserved u16
//!          ‖ log_id(16) ‖ key_id(32) ‖ prev_final(32) ‖ public_key(32) ‖ crc32 u32
//! record   = len_prefix u32 ‖ envelope ‖ signature(64) ‖ body_len u32 ‖ body ‖ len_trailer u32
//! ```
//!
//! All integers little-endian. The envelope and body are canonical CBOR
//! maps with integer keys.

use std::collections::BTreeMap;
use std::io::{self, Read};

use crate::cbor::{self, Value as Cbor};
use crate::segment::SESSION_ID_LEN;
use crate::writer::PayloadValue;

use super::keys::PublicKey;
use super::{th, FORMAT_VERSION_SIGNED, TAG_BODY, TAG_HEADER, TAG_RECORD};

/// Header length for Ed25519 (`H = 96 + P`, `P = 32`).
pub const HEADER_LEN: usize = 128;
/// Bytes covered by the header CRC and hashed into `chain_start`.
pub const HEADER_HASHED_LEN: usize = 124;
/// Maximum envelope length (spec §3.8).
pub const MAX_ENVELOPE_LEN: u32 = 4096;
/// Ed25519 signature length.
pub const SIG_LEN: usize = 64;
/// `log_id` length.
pub const LOG_ID_LEN: usize = 16;

/// Event of the record that ends a segment before rollover.
pub const EVENT_FINALIZED: &str = "segment.finalized";
/// Event of the record that closes a log for good.
pub const EVENT_SEALED: &str = "log.sealed";
/// Event of the optional first record naming the log this one follows.
pub const EVENT_CONTINUED: &str = "log.continued";

/// Whether `event` names a structural record, which may never be elided.
#[must_use]
pub fn is_structural(event: &str) -> bool {
    matches!(event, EVENT_FINALIZED | EVENT_SEALED | EVENT_CONTINUED)
}

/// A signed-mode segment header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedHeader {
    /// Format version (`0x0002`).
    pub version: u16,
    /// Segment index; equals the file-name index.
    pub segment_index: u16,
    /// `sig_alg` code.
    pub sig_alg: u16,
    /// Reserved, zero.
    pub reserved: u16,
    /// Random id of the log, the same in every segment.
    pub log_id: [u8; LOG_ID_LEN],
    /// `SHA-256(key blob)` of `public_key`.
    pub key_id: [u8; 32],
    /// Zero for segment 0; otherwise the last `record_hash` of the
    /// previous segment.
    pub prev_final: [u8; 32],
    /// The signer's public key. Informational until pinned.
    pub public_key: [u8; 32],
}

impl SignedHeader {
    /// A header for `public_key` at `segment_index`.
    #[must_use]
    pub fn new(
        segment_index: u16,
        log_id: [u8; LOG_ID_LEN],
        public_key: &PublicKey,
        prev_final: [u8; 32],
    ) -> Self {
        Self {
            version: FORMAT_VERSION_SIGNED,
            segment_index,
            sig_alg: public_key.alg().code(),
            reserved: 0,
            log_id,
            key_id: public_key.fingerprint().0,
            prev_final,
            public_key: *public_key.as_bytes(),
        }
    }

    /// The 128 header bytes, CRC included.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; HEADER_LEN] {
        let mut b = [0u8; HEADER_LEN];
        b[0..4].copy_from_slice(crate::segment::FORMAT_MAGIC);
        b[4..6].copy_from_slice(&self.version.to_le_bytes());
        b[6..8].copy_from_slice(&self.segment_index.to_le_bytes());
        b[8..10].copy_from_slice(&self.sig_alg.to_le_bytes());
        b[10..12].copy_from_slice(&self.reserved.to_le_bytes());
        b[12..28].copy_from_slice(&self.log_id);
        b[28..60].copy_from_slice(&self.key_id);
        b[60..92].copy_from_slice(&self.prev_final);
        b[92..124].copy_from_slice(&self.public_key);
        let crc = crc32fast::hash(&b[..HEADER_HASHED_LEN]);
        b[124..128].copy_from_slice(&crc.to_le_bytes());
        b
    }

    /// Decode the fields of a 128-byte header without validating them.
    /// The verifier validates field by field (H1–H12).
    #[must_use]
    pub fn from_bytes_unchecked(b: &[u8; HEADER_LEN]) -> Self {
        let u16_at = |i: usize| u16::from_le_bytes([b[i], b[i + 1]]);
        let mut log_id = [0u8; LOG_ID_LEN];
        log_id.copy_from_slice(&b[12..28]);
        let mut key_id = [0u8; 32];
        key_id.copy_from_slice(&b[28..60]);
        let mut prev_final = [0u8; 32];
        prev_final.copy_from_slice(&b[60..92]);
        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(&b[92..124]);
        Self {
            version: u16_at(4),
            segment_index: u16_at(6),
            sig_alg: u16_at(8),
            reserved: u16_at(10),
            log_id,
            key_id,
            prev_final,
            public_key,
        }
    }
}

/// `chain_start_N = TH("ogentic-audit/v0.2/header", header[0..124))`.
#[must_use]
pub fn chain_start(header: &[u8; HEADER_LEN]) -> [u8; 32] {
    th(TAG_HEADER, &header[..HEADER_HASHED_LEN])
}

/// `record_hash = TH("ogentic-audit/v0.2/record", envelope_bytes)`.
#[must_use]
pub fn record_hash(envelope: &[u8]) -> [u8; 32] {
    th(TAG_RECORD, envelope)
}

/// `body_hash = TH("ogentic-audit/v0.2/body", body_bytes)`.
#[must_use]
pub fn body_hash(body: &[u8]) -> [u8; 32] {
    th(TAG_BODY, body)
}

/// The signed, chained part of a record (spec §6.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    /// Position in the segment (key 1).
    pub record_id: u64,
    /// Chain link (key 2).
    pub prev_hash: [u8; 32],
    /// Signer's wall clock, RFC 3339 ms (key 3).
    pub ts_wall: String,
    /// Monotonic ms since session start (key 4).
    pub ts_mono_delta: u64,
    /// Session id (key 5).
    pub session_id: [u8; SESSION_ID_LEN],
    /// Event name from a fixed vocabulary; never content (key 7).
    pub event: String,
    /// Header `key_id` (key 9).
    pub key_id: [u8; 32],
    /// Payload schema version (key 10).
    pub schema_version: u8,
    /// Header `segment_index` (key 11).
    pub segment_index: u16,
    /// Header `sig_alg` (key 12).
    pub sig_alg: u16,
    /// `TH(body tag, body_bytes)` (key 13).
    pub body_hash: [u8; 32],
}

impl Envelope {
    /// Canonical CBOR bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        cbor::map_int_keys(&[
            (1, cbor::uint(self.record_id)),
            (2, cbor::bstr(&self.prev_hash)),
            (3, cbor::tstr(&self.ts_wall)),
            (4, cbor::uint(self.ts_mono_delta)),
            (5, cbor::bstr(&self.session_id)),
            (7, cbor::tstr(&self.event)),
            (9, cbor::bstr(&self.key_id)),
            (10, cbor::uint(u64::from(self.schema_version))),
            (11, cbor::uint(u64::from(self.segment_index))),
            (12, cbor::uint(u64::from(self.sig_alg))),
            (13, cbor::bstr(&self.body_hash)),
        ])
    }

    /// Decode and validate canonical CBOR against the §6.1 schema.
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        let pairs = int_map(bytes)?;
        let mut f: BTreeMap<u64, Cbor> = BTreeMap::new();
        for (k, v) in pairs {
            if matches!(k, 6 | 8) || (14..100).contains(&k) || k == 0 {
                return Err(format!("envelope key {k} is not allowed"));
            }
            if k < 100 {
                f.insert(k, v);
            }
        }
        let uint = |k: u64| -> Result<u64, String> {
            match f.get(&k) {
                Some(Cbor::Uint(n)) => Ok(*n),
                Some(_) => Err(format!("envelope key {k} must be an unsigned integer")),
                None => Err(format!("envelope key {k} missing")),
            }
        };
        let text = |k: u64| -> Result<String, String> {
            match f.get(&k) {
                Some(Cbor::Text(s)) => Ok(s.clone()),
                Some(_) => Err(format!("envelope key {k} must be a text string")),
                None => Err(format!("envelope key {k} missing")),
            }
        };
        let event = text(7)?;
        if event.is_empty()
            || event.len() > 128
            || !event.bytes().all(|b| (0x21..=0x7e).contains(&b))
        {
            return Err("event must be 1–128 bytes of printable ASCII".into());
        }
        let small = |k: u64, max: u64| -> Result<u64, String> {
            let n = uint(k)?;
            if n > max {
                return Err(format!("envelope key {k} out of range"));
            }
            Ok(n)
        };
        Ok(Self {
            record_id: uint(1)?,
            prev_hash: fixed_bytes(f.get(&2), 2)?,
            ts_wall: text(3)?,
            ts_mono_delta: uint(4)?,
            session_id: fixed_bytes(f.get(&5), 5)?,
            event,
            key_id: fixed_bytes(f.get(&9), 9)?,
            schema_version: small(10, 255)? as u8,
            segment_index: small(11, 65_535)? as u16,
            sig_alg: small(12, 65_535)? as u16,
            body_hash: fixed_bytes(f.get(&13), 13)?,
        })
    }
}

fn int_map(bytes: &[u8]) -> Result<Vec<(u64, Cbor)>, String> {
    let v = cbor::decode(bytes).map_err(|e| e.to_string())?;
    let Cbor::Map(pairs) = v else {
        return Err("not a CBOR map".into());
    };
    pairs
        .into_iter()
        .map(|(k, v)| match k {
            Cbor::Uint(n) => Ok((n, v)),
            _ => Err("map key is not an unsigned integer".into()),
        })
        .collect()
}

fn fixed_bytes<const N: usize>(v: Option<&Cbor>, key: u64) -> Result<[u8; N], String> {
    match v {
        Some(Cbor::Bytes(b)) if b.len() == N => {
            let mut out = [0u8; N];
            out.copy_from_slice(b);
            Ok(out)
        },
        Some(_) => Err(format!("key {key} must be a {N}-byte string")),
        None => Err(format!("key {key} missing")),
    }
}

/// The elidable part of a record (spec §6.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Body {
    /// Who acted (key 6).
    pub actor: String,
    /// Event payload, a CBOR map with text keys (key 8).
    pub payload: Cbor,
    /// Fresh random nonce making `body_hash` hiding (key 14).
    pub nonce: [u8; 32],
}

/// Encode a body from writer inputs.
#[must_use]
pub fn encode_body(
    actor: &str,
    payload: &BTreeMap<String, PayloadValue>,
    nonce: &[u8; 32],
) -> Vec<u8> {
    let encoded: BTreeMap<String, Vec<u8>> = payload
        .iter()
        .map(|(k, v)| (k.clone(), v.encode()))
        .collect();
    cbor::map_int_keys(&[
        (6, cbor::tstr(actor)),
        (8, cbor::map_text_keys(&encoded)),
        (14, cbor::bstr(nonce)),
    ])
}

impl Body {
    /// Decode and validate canonical CBOR against the §6.2 schema.
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        let pairs = int_map(bytes)?;
        let mut actor = None;
        let mut payload = None;
        let mut nonce = None;
        for (k, v) in pairs {
            match (k, v) {
                (6, Cbor::Text(s)) => actor = Some(s),
                (8, m @ Cbor::Map(_)) => {
                    if let Cbor::Map(entries) = &m {
                        if entries.iter().any(|(k, _)| !matches!(k, Cbor::Text(_))) {
                            return Err("payload keys must be text strings".into());
                        }
                    }
                    payload = Some(m);
                },
                (14, v) => nonce = Some(fixed_bytes::<32>(Some(&v), 14)?),
                (k, _) => return Err(format!("body key {k} is not allowed or has the wrong type")),
            }
        }
        Ok(Self {
            actor: actor.ok_or("body key 6 (actor) missing")?,
            payload: payload.ok_or("body key 8 (payload) missing")?,
            nonce: nonce.ok_or("body key 14 (nonce) missing")?,
        })
    }

    /// A payload member, if present.
    #[must_use]
    pub fn payload_get(&self, key: &str) -> Option<&Cbor> {
        match &self.payload {
            Cbor::Map(entries) => entries
                .iter()
                .find(|(k, _)| matches!(k, Cbor::Text(t) if t == key))
                .map(|(_, v)| v),
            _ => None,
        }
    }
}

/// Frame a record: `len ‖ envelope ‖ sig ‖ body_len ‖ body ‖ len`. A
/// `None` body is an elided record (`body_len = 0`).
#[must_use]
pub fn frame(envelope: &[u8], signature: &[u8; SIG_LEN], body: Option<&[u8]>) -> Vec<u8> {
    let body = body.unwrap_or(&[]);
    let len = (envelope.len() as u32).to_le_bytes();
    let mut out = Vec::with_capacity(4 + envelope.len() + SIG_LEN + 4 + body.len() + 4);
    out.extend_from_slice(&len);
    out.extend_from_slice(envelope);
    out.extend_from_slice(signature);
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(body);
    out.extend_from_slice(&len);
    out
}

/// One record as stored, before any check.
#[derive(Debug, Clone)]
pub struct RawRecord {
    /// Offset of `len_prefix` in the segment file.
    pub offset: u64,
    /// Envelope bytes.
    pub envelope: Vec<u8>,
    /// Signature bytes.
    pub signature: [u8; SIG_LEN],
    /// Body bytes; `None` when elided.
    pub body: Option<Vec<u8>>,
    /// Framed length on disk.
    pub total_len: u64,
}

/// Result of reading one frame.
#[derive(Debug)]
pub enum Frame {
    /// A complete frame.
    Record(RawRecord),
    /// No bytes left.
    End,
    /// `len_prefix` over the §3.8 limit.
    TooLarge {
        /// Offset of the frame.
        offset: u64,
        /// The declared length.
        len: u32,
    },
    /// Incomplete framing (the file ends mid-record, or the trailer does
    /// not mirror the prefix).
    Torn {
        /// Offset of the frame.
        offset: u64,
    },
}

/// Read the frame at `offset` from `r`, which is positioned there.
/// `file_len` bounds every length before it is used.
pub fn read_frame<R: Read>(r: &mut R, offset: u64, file_len: u64) -> io::Result<Frame> {
    let remaining = file_len.saturating_sub(offset);
    if remaining == 0 {
        return Ok(Frame::End);
    }
    let torn = Ok(Frame::Torn { offset });
    if remaining < 4 {
        return torn;
    }
    let mut b4 = [0u8; 4];
    r.read_exact(&mut b4)?;
    let len = u32::from_le_bytes(b4);
    if len > MAX_ENVELOPE_LEN {
        return Ok(Frame::TooLarge { offset, len });
    }
    let fixed = 4 + u64::from(len) + SIG_LEN as u64 + 4;
    if remaining < fixed + 4 {
        return torn;
    }
    let mut envelope = vec![0u8; len as usize];
    r.read_exact(&mut envelope)?;
    let mut signature = [0u8; SIG_LEN];
    r.read_exact(&mut signature)?;
    r.read_exact(&mut b4)?;
    let body_len = u64::from(u32::from_le_bytes(b4));
    if remaining < fixed + body_len + 4 {
        return torn;
    }
    let mut body = vec![0u8; body_len as usize];
    r.read_exact(&mut body)?;
    r.read_exact(&mut b4)?;
    if u32::from_le_bytes(b4) != len {
        return torn;
    }
    Ok(Frame::Record(RawRecord {
        offset,
        envelope,
        signature,
        body: (body_len > 0).then_some(body),
        total_len: fixed + body_len + 4,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signed::unhex;

    #[test]
    fn spec_header_example() {
        let pk = PublicKey::ed25519(
            unhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a").unwrap(),
        );
        let log_id: [u8; 16] = unhex("000102030405060708090a0b0c0d0e0f").unwrap();
        let h = SignedHeader::new(0, log_id, &pk, [0u8; 32]).to_bytes();
        assert_eq!(&h[124..], &[0x52, 0x2d, 0x04, 0xb2]);
        assert_eq!(
            crate::signed::hex(&chain_start(&h)),
            "377d85f15f810e761308e18230717c9b7a58554a611ef77df2a5822e1fd977dc"
        );
        assert_eq!(SignedHeader::from_bytes_unchecked(&h).log_id, log_id);
    }

    #[test]
    fn envelope_round_trip_and_schema() {
        let e = Envelope {
            record_id: 3,
            prev_hash: [1; 32],
            ts_wall: "2026-10-03T12:00:00.000Z".into(),
            ts_mono_delta: 5,
            session_id: [2; 16],
            event: "page.released".into(),
            key_id: [3; 32],
            schema_version: 1,
            segment_index: 0,
            sig_alg: 1,
            body_hash: [4; 32],
        };
        assert_eq!(Envelope::decode(&e.encode()).unwrap(), e);
        let bad = Envelope {
            event: "has space".into(),
            ..e
        };
        assert!(Envelope::decode(&bad.encode()).is_err());
    }

    #[test]
    fn frames() {
        let f = frame(b"env", &[9; 64], Some(b"body"));
        let mut c = std::io::Cursor::new(&f);
        match read_frame(&mut c, 0, f.len() as u64).unwrap() {
            Frame::Record(r) => {
                assert_eq!(r.envelope, b"env");
                assert_eq!(r.body.as_deref(), Some(&b"body"[..]));
                assert_eq!(r.total_len, f.len() as u64);
            },
            other => panic!("{other:?}"),
        }
        let mut c = std::io::Cursor::new(&f);
        assert!(matches!(
            read_frame(&mut c, 0, f.len() as u64 - 1).unwrap(),
            Frame::Torn { .. }
        ));
    }
}
