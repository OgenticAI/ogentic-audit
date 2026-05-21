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
