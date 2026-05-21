//! Segment-file primitives: 80-byte header, record framing, byte-level
//! layout per `docs/spec/v0.1.md`.
//!
//! This module is the byte-level interface to the v0.1 format. The
//! [`Writer`](crate::writer::Writer) drives it forward (build header,
//! frame records, write to disk); the future
//! [`Reader`](https://linear.app/ogenticai/issue/OGE-430) and
//! [`Verifier`](https://linear.app/ogenticai/issue/OGE-437) consume the
//! same primitives in reverse.
//!
//! ## Why low-level
//!
//! Everything in this module is `pub` and operates on `&[u8]` /
//! `Vec<u8>` rather than typed records. That's deliberate — the
//! segment-header layout and record framing are exhibits in the
//! court-defensibility narrative, and the most direct way to keep them
//! correct is to expose the bytes themselves. The schema-aware encoders
//! live one layer up in [`crate::writer`].

use crate::key::{HMAC_LEN, KEY_ID_LEN};

/// Magic-bytes prefix in every segment header. ASCII `"OGAU"`.
pub const FORMAT_MAGIC: &[u8; 4] = b"OGAU";

/// On-disk format version this crate writes. `0x0001` for v0.1.
pub const FORMAT_VERSION: u16 = 0x0001;

/// Length, in bytes, of the segment-header CRC-covered region (every
/// byte before the CRC field itself).
pub const HEADER_BODY_LEN: usize = 72;

/// Total length of a segment header in bytes. Fixed at v0.1.
pub const HEADER_TOTAL_LEN: usize = 80;

/// Length, in bytes, of every `session_id` field. UUIDv4.
pub const SESSION_ID_LEN: usize = 16;

/// Decoded view of the 80-byte segment header. Constructed via
/// [`SegmentHeader::build`] (writer side) or, in the future,
/// [`SegmentHeader::parse`] (reader side; lands with OGE-430).
#[derive(Debug, Clone)]
pub struct SegmentHeader {
    /// Format version. Must equal [`FORMAT_VERSION`] (0x0001) at v0.1.
    pub version: u16,

    /// Zero-indexed segment index. Matches the segment filename
    /// `audit-NNNN.cbor`.
    pub segment_index: u16,

    /// 32-byte BLAKE3-256 fingerprint of the signing key. Must equal
    /// every record's `key_id` field in this segment.
    pub key_id: [u8; KEY_ID_LEN],

    /// For genesis (`segment_index == 0`): 32 zero bytes.
    /// For segment N ≥ 1: the HMAC of the last record in segment N-1.
    pub prev_final: [u8; HMAC_LEN],
}

impl SegmentHeader {
    /// Build the genesis-segment header.
    #[must_use]
    pub fn genesis(key_id: [u8; KEY_ID_LEN]) -> Self {
        Self {
            version: FORMAT_VERSION,
            segment_index: 0,
            key_id,
            prev_final: [0u8; HMAC_LEN],
        }
    }

    /// Build a header for segment N ≥ 1 with the prior segment's final
    /// HMAC.
    #[must_use]
    pub fn next(segment_index: u16, key_id: [u8; KEY_ID_LEN], prev_final: [u8; HMAC_LEN]) -> Self {
        Self {
            version: FORMAT_VERSION,
            segment_index,
            key_id,
            prev_final,
        }
    }

    /// Serialize the header to its 80-byte on-disk form, including the
    /// CRC32 over bytes `[0, 72)` at offset 72 and four trailing
    /// reserved zero bytes.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; HEADER_TOTAL_LEN] {
        let mut body = [0u8; HEADER_BODY_LEN];
        body[..4].copy_from_slice(FORMAT_MAGIC);
        body[4..6].copy_from_slice(&self.version.to_le_bytes());
        body[6..8].copy_from_slice(&self.segment_index.to_le_bytes());
        body[8..40].copy_from_slice(&self.key_id);
        body[40..72].copy_from_slice(&self.prev_final);

        let crc = crc32fast::hash(&body);

        let mut out = [0u8; HEADER_TOTAL_LEN];
        out[..HEADER_BODY_LEN].copy_from_slice(&body);
        out[HEADER_BODY_LEN..HEADER_BODY_LEN + 4].copy_from_slice(&crc.to_le_bytes());
        // bytes [76..80] are reserved zeros (already zero from
        // `let mut out = [0u8; ...]`).
        out
    }
}

/// Length, in bytes, of the record framing overhead: `len_prefix` (4) +
/// `hmac` (32) + `len_trailer` (4) = 40 bytes per record.
pub const RECORD_FRAMING_OVERHEAD: usize = 4 + HMAC_LEN + 4;

/// Frame a single record's payload bytes with the v0.1 record envelope.
///
/// On-disk layout:
///
/// ```text
/// | 4 bytes len_prefix (u32 LE) | payload | 32 bytes hmac | 4 bytes len_trailer (u32 LE) |
/// ```
///
/// `len_trailer` always equals `len_prefix` — that mirror is what the
/// reader / verifier ([R5 / OGE-432]) uses to detect a torn tail.
///
/// [R5 / OGE-432]: https://linear.app/ogenticai/issue/OGE-432
#[must_use]
pub fn frame_record(payload: &[u8], hmac: &[u8; HMAC_LEN]) -> Vec<u8> {
    let len = payload.len() as u32;
    let mut out = Vec::with_capacity(4 + payload.len() + HMAC_LEN + 4);
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(payload);
    out.extend_from_slice(hmac);
    out.extend_from_slice(&len.to_le_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genesis_header_round_trip() {
        let key_id = [0xabu8; KEY_ID_LEN];
        let header = SegmentHeader::genesis(key_id);
        let bytes = header.to_bytes();

        assert_eq!(bytes.len(), HEADER_TOTAL_LEN);
        assert_eq!(&bytes[..4], FORMAT_MAGIC);
        assert_eq!(u16::from_le_bytes([bytes[4], bytes[5]]), FORMAT_VERSION);
        assert_eq!(u16::from_le_bytes([bytes[6], bytes[7]]), 0);
        assert_eq!(&bytes[8..40], &key_id);
        assert_eq!(&bytes[40..72], &[0u8; HMAC_LEN]);

        // CRC32 over [0..72) at offset 72.
        let expected_crc = crc32fast::hash(&bytes[..HEADER_BODY_LEN]);
        let stored_crc = u32::from_le_bytes([bytes[72], bytes[73], bytes[74], bytes[75]]);
        assert_eq!(stored_crc, expected_crc);

        // Reserved bytes are zero.
        assert_eq!(&bytes[76..80], &[0u8; 4]);
    }

    #[test]
    fn next_header_carries_prev_final() {
        let key_id = [1u8; KEY_ID_LEN];
        let prev_final = [2u8; HMAC_LEN];
        let header = SegmentHeader::next(7, key_id, prev_final);
        let bytes = header.to_bytes();
        assert_eq!(u16::from_le_bytes([bytes[6], bytes[7]]), 7);
        assert_eq!(&bytes[8..40], &key_id);
        assert_eq!(&bytes[40..72], &prev_final);
    }

    #[test]
    fn frame_record_layout() {
        let payload = b"hello";
        let hmac = [0u8; HMAC_LEN];
        let framed = frame_record(payload, &hmac);
        // 4 + 5 + 32 + 4 = 45
        assert_eq!(framed.len(), 4 + payload.len() + HMAC_LEN + 4);
        let lp = u32::from_le_bytes([framed[0], framed[1], framed[2], framed[3]]);
        let lt_off = 4 + payload.len() + HMAC_LEN;
        let lt = u32::from_le_bytes([
            framed[lt_off],
            framed[lt_off + 1],
            framed[lt_off + 2],
            framed[lt_off + 3],
        ]);
        assert_eq!(lp, lt);
        assert_eq!(lp as usize, payload.len());
        assert_eq!(&framed[4..4 + payload.len()], payload);
        assert_eq!(
            &framed[4 + payload.len()..4 + payload.len() + HMAC_LEN],
            &hmac
        );
    }
}
