//! Canonical CBOR encoder for the v0.1 record schema.
//!
//! Implements the subset of RFC 8949 §4.2 deterministic encoding used by
//! `docs/spec/v0.1.md`:
//!
//! - Unsigned integers (major type 0), shortest-length form.
//! - Negative integers (major type 1), shortest-length form.
//! - Byte strings (major type 2), definite length.
//! - Text strings (major type 3), definite length, UTF-8.
//! - Maps (major type 5), definite length, keys sorted by encoded length
//!   then by lexicographic byte order.
//! - Arrays (major type 4), definite length.
//! - Booleans (major type 7, simple 20/21).
//!
//! Indefinite-length items, floats, tags, undefined, and null are NOT
//! supported at v0.1 — the schema doesn't use them. Attempting to encode
//! one yields a debug-time assertion or compile error depending on the
//! call site.
//!
//! This is deliberately hand-rolled rather than delegating to `ciborium`'s
//! canonical mode. Two reasons:
//!
//! 1. The encoder is the source of truth for vector bytes. Audited code
//!    here is what an opposing expert checks, not a third-party crate's
//!    canonical-mode behavior. This is the same reasoning that makes
//!    `tools/gen_vectors.py` hand-rolled.
//! 2. `ciborium`'s canonical-mode parity with `cbor2` is enforced as a
//!    hard gate by [OGE-441 (Q2)], not assumed. Until that lands we
//!    don't depend on it.
//!
//! [OGE-441 (Q2)]: https://linear.app/ogenticai/issue/OGE-441

use std::collections::BTreeMap;

/// CBOR major-type 0 (unsigned integer), shortest form.
#[must_use]
pub fn uint(value: u64) -> Vec<u8> {
    head(0, value)
}

/// CBOR major-type 1 (negative integer), shortest form. Caller passes the
/// negative value directly (e.g. `nint(-5)` yields the CBOR encoding of
/// `-5`).
#[must_use]
pub fn nint(value: i64) -> Vec<u8> {
    assert!(value < 0, "nint requires a negative value; got {value}");
    // CBOR encodes -n - 1 as the head argument for major type 1.
    let arg: u64 = (-(value + 1)) as u64;
    head(1, arg)
}

/// CBOR major-type 2 (byte string).
#[must_use]
pub fn bstr(value: &[u8]) -> Vec<u8> {
    let mut out = head(2, value.len() as u64);
    out.extend_from_slice(value);
    out
}

/// CBOR major-type 3 (text string).
#[must_use]
pub fn tstr(value: &str) -> Vec<u8> {
    let bytes = value.as_bytes();
    let mut out = head(3, bytes.len() as u64);
    out.extend_from_slice(bytes);
    out
}

/// CBOR major-type 7 simple value: `false` (0xf4) or `true` (0xf5).
#[must_use]
pub fn bool_(value: bool) -> Vec<u8> {
    vec![if value { 0xf5 } else { 0xf4 }]
}

/// Encode a map whose keys are unsigned integers. Used for the record
/// schema (integer keys 1..=10). Caller provides `(key, encoded_value)`
/// pairs; this function emits the canonical key ordering and the map
/// header.
#[must_use]
pub fn map_int_keys(items: &[(u64, Vec<u8>)]) -> Vec<u8> {
    let mut encoded: Vec<(Vec<u8>, &[u8])> = items
        .iter()
        .map(|(k, v)| (uint(*k), v.as_slice()))
        .collect();
    encoded.sort_by(|a, b| (a.0.len(), &a.0).cmp(&(b.0.len(), &b.0)));
    let mut out = head(5, encoded.len() as u64);
    for (k, v) in encoded {
        out.extend_from_slice(&k);
        out.extend_from_slice(v);
    }
    out
}

/// Encode a map whose keys are text strings. Used inside the
/// event-specific `payload` map. Keys are sorted canonically (encoded
/// length first, then byte order).
#[must_use]
pub fn map_text_keys(items: &BTreeMap<String, Vec<u8>>) -> Vec<u8> {
    // BTreeMap iterates in lexicographic key order, which is NOT
    // canonical CBOR order. Re-sort by encoded-key length then bytes.
    let mut encoded: Vec<(Vec<u8>, &[u8])> =
        items.iter().map(|(k, v)| (tstr(k), v.as_slice())).collect();
    encoded.sort_by(|a, b| (a.0.len(), &a.0).cmp(&(b.0.len(), &b.0)));
    let mut out = head(5, encoded.len() as u64);
    for (k, v) in encoded {
        out.extend_from_slice(&k);
        out.extend_from_slice(v);
    }
    out
}

/// CBOR major-type 4 (array), definite length.
#[must_use]
pub fn array(items: &[Vec<u8>]) -> Vec<u8> {
    let mut out = head(4, items.len() as u64);
    for item in items {
        out.extend_from_slice(item);
    }
    out
}

// ---------------------------------------------------------------------------
// Canonical CBOR decoder (RFC 8949 §4.2 — covering the subset we need)
// ---------------------------------------------------------------------------

/// Decoded CBOR value. Mirrors the encoder's [`PayloadValue`](crate::writer::PayloadValue)
/// surface but kept independent of the writer's typed `Record` so the
/// decoder can be exercised from the verifier path without pulling in
/// writer-specific traits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// Major type 0: unsigned integer.
    Uint(u64),
    /// Major type 1: negative integer (caller stores the negative value).
    Nint(i64),
    /// Major type 2: byte string.
    Bytes(Vec<u8>),
    /// Major type 3: text string (UTF-8).
    Text(String),
    /// Major type 4: array, definite length.
    Array(Vec<Value>),
    /// Major type 5: map, definite length. Keyed by an opaque encoded-key
    /// representation alongside its decoded form so callers can validate
    /// canonical ordering without re-encoding.
    Map(Vec<(Value, Value)>),
    /// Major type 7 simple values 20 (false) / 21 (true).
    Bool(bool),
}

/// Errors decoding canonical CBOR. Distinguishes truncation (recoverable
/// — see R5 / OGE-432) from non-canonical encoding (a `RecordCorrupt`
/// violation, per the spec's violation taxonomy).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CborError {
    /// Input ran out mid-item.
    #[error("CBOR truncated at offset {offset}: needed {needed} more bytes")]
    Truncated {
        /// Byte offset within the input where decoding stopped.
        offset: usize,
        /// Number of additional bytes required to finish the item.
        needed: usize,
    },
    /// A length / argument was encoded in a longer form than the
    /// shortest one that fits — violates RFC 8949 §4.2.
    #[error("CBOR non-canonical at offset {offset}: {message}")]
    NonCanonical {
        /// Byte offset within the input where the violation was detected.
        offset: usize,
        /// Human-readable description of the rule violated.
        message: String,
    },
    /// Map keys were not sorted canonically (length, then byte order).
    #[error("CBOR map keys not in canonical order at offset {offset}")]
    MapKeyOrder {
        /// Byte offset within the input where the out-of-order pair starts.
        offset: usize,
    },
    /// An item used a major type or simple value not supported at v0.1.
    #[error("CBOR unsupported item at offset {offset}: {message}")]
    Unsupported {
        /// Byte offset within the input where the unsupported item starts.
        offset: usize,
        /// Human-readable description of the unsupported construct.
        message: String,
    },
    /// Trailing bytes remain after the top-level item — indicates a framing bug.
    #[error("CBOR trailing bytes at offset {offset}: {extra} bytes unconsumed")]
    TrailingBytes {
        /// Byte offset within the input where decoding finished.
        offset: usize,
        /// Number of bytes left unconsumed.
        extra: usize,
    },
    /// Text string contained invalid UTF-8.
    #[error("CBOR text string not valid UTF-8 at offset {offset}")]
    InvalidUtf8 {
        /// Byte offset within the input where the bad text-string started.
        offset: usize,
    },
}

/// Maximum CBOR nesting depth accepted by the decoder.
///
/// The v0.1 record schema's deepest legitimate nesting is ~4 (record map →
/// payload map → arrays/maps inside payload values). 16 leaves comfortable
/// headroom for future schema evolution while preventing a malicious log
/// producer (who, per the threat model, holds the HMAC key and can mint
/// records that pass the HMAC gate) from minting a deeply-nested payload
/// that would otherwise blow the verifier's stack — particularly under
/// Linux musl's ~80 KiB default thread stack. See OGE-833.
pub const MAX_CBOR_DEPTH: usize = 16;

/// Decode a single canonical CBOR item from `bytes`. The whole input
/// must be consumed; trailing bytes yield [`CborError::TrailingBytes`].
pub fn decode(bytes: &[u8]) -> Result<Value, CborError> {
    let mut cursor = 0usize;
    let value = decode_value(bytes, &mut cursor)?;
    if cursor != bytes.len() {
        return Err(CborError::TrailingBytes {
            offset: cursor,
            extra: bytes.len() - cursor,
        });
    }
    Ok(value)
}

fn decode_value(bytes: &[u8], cursor: &mut usize) -> Result<Value, CborError> {
    decode_value_inner(bytes, cursor, 0)
}

fn decode_value_inner(bytes: &[u8], cursor: &mut usize, depth: usize) -> Result<Value, CborError> {
    if depth >= MAX_CBOR_DEPTH {
        return Err(CborError::Unsupported {
            offset: *cursor,
            message: format!("CBOR nesting depth exceeded MAX_CBOR_DEPTH={MAX_CBOR_DEPTH}"),
        });
    }
    if *cursor >= bytes.len() {
        return Err(CborError::Truncated {
            offset: *cursor,
            needed: 1,
        });
    }
    let initial = bytes[*cursor];
    let major = initial >> 5;
    let additional = initial & 0x1f;
    let start_offset = *cursor;

    match major {
        0 => {
            let v = decode_argument(bytes, cursor, additional)?;
            Ok(Value::Uint(v))
        },
        1 => {
            let arg = decode_argument(bytes, cursor, additional)?;
            let v = -(arg as i128) - 1;
            if v < i64::MIN as i128 {
                return Err(CborError::Unsupported {
                    offset: start_offset,
                    message: "negative integer below i64::MIN".into(),
                });
            }
            Ok(Value::Nint(v as i64))
        },
        2 => {
            let len = decode_argument(bytes, cursor, additional)? as usize;
            ensure(bytes, *cursor, len)?;
            let out = bytes[*cursor..*cursor + len].to_vec();
            *cursor += len;
            Ok(Value::Bytes(out))
        },
        3 => {
            let len = decode_argument(bytes, cursor, additional)? as usize;
            ensure(bytes, *cursor, len)?;
            let slice = &bytes[*cursor..*cursor + len];
            let s = std::str::from_utf8(slice)
                .map_err(|_| CborError::InvalidUtf8 { offset: *cursor })?;
            let owned = s.to_owned();
            *cursor += len;
            Ok(Value::Text(owned))
        },
        4 => {
            let len = decode_argument(bytes, cursor, additional)? as usize;
            let mut items = Vec::with_capacity(len.min(1024));
            for _ in 0..len {
                items.push(decode_value_inner(bytes, cursor, depth + 1)?);
            }
            Ok(Value::Array(items))
        },
        5 => {
            let len = decode_argument(bytes, cursor, additional)? as usize;
            let mut items: Vec<(Value, Value)> = Vec::with_capacity(len.min(1024));
            let mut prev_key_encoded: Option<Vec<u8>> = None;
            for _ in 0..len {
                let key_start = *cursor;
                let key = decode_value_inner(bytes, cursor, depth + 1)?;
                let key_encoded = bytes[key_start..*cursor].to_vec();
                if let Some(prev) = prev_key_encoded.as_ref() {
                    if !key_order_canonical(prev, &key_encoded) {
                        return Err(CborError::MapKeyOrder { offset: key_start });
                    }
                }
                prev_key_encoded = Some(key_encoded);
                let value = decode_value_inner(bytes, cursor, depth + 1)?;
                items.push((key, value));
            }
            Ok(Value::Map(items))
        },
        7 => match additional {
            20 => {
                *cursor += 1;
                Ok(Value::Bool(false))
            },
            21 => {
                *cursor += 1;
                Ok(Value::Bool(true))
            },
            other => Err(CborError::Unsupported {
                offset: start_offset,
                message: format!("major 7 simple value {other} unsupported at v0.1"),
            }),
        },
        _ => Err(CborError::Unsupported {
            offset: start_offset,
            message: format!("major type {major} unsupported at v0.1"),
        }),
    }
}

/// Decode the head argument for `additional` and advance the cursor.
/// Enforces shortest-form encoding (RFC 8949 §4.2.1).
fn decode_argument(bytes: &[u8], cursor: &mut usize, additional: u8) -> Result<u64, CborError> {
    let start_offset = *cursor;
    *cursor += 1;
    match additional {
        n if n < 24 => Ok(n as u64),
        24 => {
            ensure(bytes, *cursor, 1)?;
            let v = bytes[*cursor] as u64;
            *cursor += 1;
            if v < 24 {
                return Err(CborError::NonCanonical {
                    offset: start_offset,
                    message: format!("u8 arg {v} should fit in inline form"),
                });
            }
            Ok(v)
        },
        25 => {
            ensure(bytes, *cursor, 2)?;
            let v = u16::from_be_bytes([bytes[*cursor], bytes[*cursor + 1]]) as u64;
            *cursor += 2;
            if v < 1 << 8 {
                return Err(CborError::NonCanonical {
                    offset: start_offset,
                    message: format!("u16 arg {v} should fit in u8 form"),
                });
            }
            Ok(v)
        },
        26 => {
            ensure(bytes, *cursor, 4)?;
            let v = u32::from_be_bytes([
                bytes[*cursor],
                bytes[*cursor + 1],
                bytes[*cursor + 2],
                bytes[*cursor + 3],
            ]) as u64;
            *cursor += 4;
            if v < 1 << 16 {
                return Err(CborError::NonCanonical {
                    offset: start_offset,
                    message: format!("u32 arg {v} should fit in u16 form"),
                });
            }
            Ok(v)
        },
        27 => {
            ensure(bytes, *cursor, 8)?;
            let v = u64::from_be_bytes([
                bytes[*cursor],
                bytes[*cursor + 1],
                bytes[*cursor + 2],
                bytes[*cursor + 3],
                bytes[*cursor + 4],
                bytes[*cursor + 5],
                bytes[*cursor + 6],
                bytes[*cursor + 7],
            ]);
            *cursor += 8;
            if v < 1 << 32 {
                return Err(CborError::NonCanonical {
                    offset: start_offset,
                    message: format!("u64 arg {v} should fit in u32 form"),
                });
            }
            Ok(v)
        },
        other => Err(CborError::Unsupported {
            offset: start_offset,
            message: format!(
                "indefinite-length / reserved additional info {other} not supported at v0.1"
            ),
        }),
    }
}

fn ensure(bytes: &[u8], cursor: usize, needed: usize) -> Result<(), CborError> {
    if cursor + needed > bytes.len() {
        return Err(CborError::Truncated {
            offset: cursor,
            needed: needed - (bytes.len() - cursor),
        });
    }
    Ok(())
}

/// Canonical key ordering: shorter encoded key first; tie-break by
/// lexicographic byte order. Returns true iff `prev < next` per RFC 8949
/// §4.2.1.
fn key_order_canonical(prev: &[u8], next: &[u8]) -> bool {
    match prev.len().cmp(&next.len()) {
        std::cmp::Ordering::Less => true,
        std::cmp::Ordering::Greater => false,
        std::cmp::Ordering::Equal => prev < next,
    }
}

/// Encode the head byte(s) for any major type, picking the shortest
/// argument encoding that fits `value`.
fn head(major: u8, value: u64) -> Vec<u8> {
    assert!(major < 8, "CBOR major type out of range: {major}");
    let base = major << 5;
    if value < 24 {
        vec![base | (value as u8)]
    } else if value < 1 << 8 {
        vec![base | 24, value as u8]
    } else if value < 1 << 16 {
        let mut out = vec![base | 25];
        out.extend_from_slice(&(value as u16).to_be_bytes());
        out
    } else if value < 1 << 32 {
        let mut out = vec![base | 26];
        out.extend_from_slice(&(value as u32).to_be_bytes());
        out
    } else {
        let mut out = vec![base | 27];
        out.extend_from_slice(&value.to_be_bytes());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Spot-check shortest-form integer encoding against the RFC 8949
    /// examples in Appendix A.
    #[test]
    fn uint_shortest_form() {
        assert_eq!(uint(0), vec![0x00]);
        assert_eq!(uint(23), vec![0x17]);
        assert_eq!(uint(24), vec![0x18, 0x18]);
        assert_eq!(uint(255), vec![0x18, 0xff]);
        assert_eq!(uint(256), vec![0x19, 0x01, 0x00]);
        assert_eq!(uint(65535), vec![0x19, 0xff, 0xff]);
        assert_eq!(uint(65536), vec![0x1a, 0x00, 0x01, 0x00, 0x00]);
        assert_eq!(uint(u64::MAX), {
            let mut v = vec![0x1b];
            v.extend_from_slice(&u64::MAX.to_be_bytes());
            v
        });
    }

    #[test]
    fn nint_examples() {
        // CBOR encodes -1 as major type 1 with arg 0 (0x20).
        assert_eq!(nint(-1), vec![0x20]);
        // -100 -> major 1, arg 99 -> 0x38, 0x63
        assert_eq!(nint(-100), vec![0x38, 0x63]);
    }

    #[test]
    fn bstr_and_tstr() {
        assert_eq!(bstr(&[]), vec![0x40]);
        assert_eq!(bstr(&[0xaa, 0xbb]), vec![0x42, 0xaa, 0xbb]);
        assert_eq!(tstr(""), vec![0x60]);
        assert_eq!(tstr("a"), vec![0x61, b'a']);
        assert_eq!(tstr("IETF"), vec![0x64, b'I', b'E', b'T', b'F']);
    }

    #[test]
    fn bool_encoding() {
        assert_eq!(bool_(false), vec![0xf4]);
        assert_eq!(bool_(true), vec![0xf5]);
    }

    #[test]
    fn map_int_keys_sorts_canonically() {
        // Inputs intentionally out of order: 10, 1, 2.
        let items: Vec<(u64, Vec<u8>)> = vec![(10, uint(99)), (1, uint(1)), (2, bstr(&[0xaa]))];
        let encoded = map_int_keys(&items);
        // Map(3) header = 0xa3, then key 1 (0x01), then key 2 (0x02),
        // then key 10 (0x0a). All single-byte keys, so canonical order
        // == numeric ascending.
        let expected: Vec<u8> = {
            let mut v = vec![0xa3];
            v.extend_from_slice(&uint(1));
            v.extend_from_slice(&uint(1));
            v.extend_from_slice(&uint(2));
            v.extend_from_slice(&bstr(&[0xaa]));
            v.extend_from_slice(&uint(10));
            v.extend_from_slice(&uint(99));
            v
        };
        assert_eq!(encoded, expected);
    }

    #[test]
    fn decoder_rejects_non_canonical_long_encoding() {
        // u8 form for value 0 should be rejected (use inline form instead).
        let bad = vec![0x18, 0x00];
        let err = decode(&bad).unwrap_err();
        assert!(matches!(err, CborError::NonCanonical { .. }), "got {err:?}");
    }

    #[test]
    fn decoder_detects_truncation() {
        let bad = vec![0x18]; // u8 follows but missing
        let err = decode(&bad).unwrap_err();
        assert!(matches!(err, CborError::Truncated { .. }), "got {err:?}");
    }

    #[test]
    fn decoder_round_trips_record_shaped_map() {
        // Build a record-shaped map (integer keys 1..=3) and decode it back.
        let items: Vec<(u64, Vec<u8>)> =
            vec![(1, uint(42)), (2, bstr(&[0xaa, 0xbb])), (3, tstr("ts"))];
        let encoded = map_int_keys(&items);
        let decoded = decode(&encoded).unwrap();
        let Value::Map(pairs) = decoded else {
            panic!("expected map");
        };
        assert_eq!(pairs.len(), 3);
        assert!(matches!(pairs[0].0, Value::Uint(1)));
        assert!(matches!(pairs[0].1, Value::Uint(42)));
    }

    #[test]
    fn decoder_detects_map_key_disorder() {
        // Hand-craft a map with keys out of canonical order: 2 before 1.
        let mut bytes = vec![0xa2]; // map(2)
        bytes.extend_from_slice(&uint(2));
        bytes.extend_from_slice(&uint(20));
        bytes.extend_from_slice(&uint(1));
        bytes.extend_from_slice(&uint(10));
        let err = decode(&bytes).unwrap_err();
        assert!(matches!(err, CborError::MapKeyOrder { .. }), "got {err:?}");
    }

    /// OGE-833 regression: a CBOR depth bomb that previously would
    /// have run the recursive decoder all the way to stack-overflow
    /// must now reject cleanly with a structured `Unsupported` error
    /// after `MAX_CBOR_DEPTH` levels — no panic, no SIGABRT.
    #[test]
    fn decoder_rejects_deeply_nested_arrays() {
        // 32 levels of array(1) — well past MAX_CBOR_DEPTH=16 — followed
        // by a terminating uint(0). CBOR encoding of array(1) with one
        // element is 0x81, so the bytes are `0x81 * 32` then `0x00`.
        let mut bytes = vec![0x81u8; 32];
        bytes.push(0x00);
        let err = decode(&bytes).expect_err("32-deep CBOR must be rejected, not decoded");
        match err {
            CborError::Unsupported { message, .. } => {
                assert!(
                    message.contains("MAX_CBOR_DEPTH"),
                    "expected depth-exceeded error, got: {message}"
                );
            },
            other => panic!("expected Unsupported {{ depth }}, got {other:?}"),
        }
    }

    /// And the upper limit itself: a 16-deep nest hits the cap exactly,
    /// so it should still be rejected (the guard fires *at* the limit,
    /// before recursing into the 17th frame).
    #[test]
    fn decoder_rejects_at_max_depth() {
        let mut bytes = vec![0x81u8; MAX_CBOR_DEPTH];
        bytes.push(0x00);
        let err = decode(&bytes).expect_err("at-limit CBOR must be rejected");
        assert!(matches!(err, CborError::Unsupported { .. }), "got {err:?}");
    }

    /// Negative-control: a legitimately shallow nesting (4 levels deep,
    /// matching the deepest the v0.1 schema actually uses) must still
    /// decode cleanly — confirms the depth cap doesn't break real logs.
    #[test]
    fn decoder_accepts_shallow_nesting_below_cap() {
        // 4 levels of array(1) then uint(0) — well under MAX_CBOR_DEPTH.
        let mut bytes = vec![0x81u8; 4];
        bytes.push(0x00);
        let value = decode(&bytes).expect("4-deep CBOR must decode");
        // Walk the structure: Array([Array([Array([Array([Uint(0)])])])])
        fn unwrap_array(v: &Value) -> &Vec<Value> {
            match v {
                Value::Array(items) => items,
                other => panic!("expected Array, got {other:?}"),
            }
        }
        let l1 = unwrap_array(&value);
        let l2 = unwrap_array(&l1[0]);
        let l3 = unwrap_array(&l2[0]);
        let l4 = unwrap_array(&l3[0]);
        assert!(matches!(l4[0], Value::Uint(0)));
    }

    #[test]
    fn map_text_keys_sorts_by_length_then_bytes() {
        let mut items: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        items.insert("zzz".into(), uint(1));
        items.insert("aa".into(), uint(2));
        items.insert("b".into(), uint(3));
        // Canonical order: shortest first, then byte-order within length.
        // "b" (1) < "aa" (2) < "zzz" (3).
        let encoded = map_text_keys(&items);
        let mut expected = vec![0xa3];
        expected.extend_from_slice(&tstr("b"));
        expected.extend_from_slice(&uint(3));
        expected.extend_from_slice(&tstr("aa"));
        expected.extend_from_slice(&uint(2));
        expected.extend_from_slice(&tstr("zzz"));
        expected.extend_from_slice(&uint(1));
        assert_eq!(encoded, expected);
    }
}
