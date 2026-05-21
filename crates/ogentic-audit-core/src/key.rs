//! Signing-key abstraction for the audit log.
//!
//! The on-disk format spec (`docs/spec/v0.1.md`) defines:
//!
//! - **HMAC algorithm:** HMAC-SHA256 over each record's canonical CBOR
//!   payload bytes.
//! - **Key identifier:** `key_id = BLAKE3-256(key_material)` for v0.1
//!   symmetric HMAC keys.
//!
//! [`KeyHandle`] is the trait the writer ([R1 / OGE-429]) and verifier
//! ([R3 / OGE-437]) consume — neither depends on *where* the key lives,
//! only that it can sign bytes and produce a stable identifier.
//!
//! Two implementations ship at v0.1:
//!
//! 1. [`InMemoryKey`] in this crate — for tests, advanced users, and the
//!    OS-keychain wrapper.
//! 2. `KeychainKey` in the optional `ogentic-audit-keychain` crate — for
//!    desktop deployments that pull the key from the host OS keychain.
//!
//! [R1 / OGE-429]: https://linear.app/ogenticai/issue/OGE-429
//! [R3 / OGE-437]: https://linear.app/ogenticai/issue/OGE-437
//!
//! ## Security invariants
//!
//! - The raw key material is never exposed through any public API.
//! - [`InMemoryKey`] zeroes its key material on drop ([`zeroize`]).
//! - [`HmacBytes`] and [`KeyId`] use constant-time equality comparison
//!   ([`subtle`]) to defend against timing side channels.
//! - `Debug` and `Display` impls redact the key material; only the
//!   [`KeyId`] (a one-way hash) appears in formatted output.
//!
//! Threat-model context for what these invariants do and don't defend
//! against is in `docs/security/threat-model.md` — in particular, an
//! attacker with live read access to the running writer's memory is
//! out-of-scope at v0.1.
//!
//! ## Conformance
//!
//! The `key_id` derivation matches the v0.1 golden vectors at
//! `tests/vectors/v0.1/*/chain.json`. An end-to-end check is in the
//! `tests` module of this file (`matches_v0_1_vector`).

use core::fmt;

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::ZeroizeOnDrop;

/// Length, in bytes, of every HMAC-SHA256 output the audit log produces.
pub const HMAC_LEN: usize = 32;

/// Length, in bytes, of every [`KeyId`] (BLAKE3-256 of the key material).
pub const KEY_ID_LEN: usize = 32;

/// HMAC-SHA256 output. Compared in constant time.
#[derive(Clone)]
pub struct HmacBytes([u8; HMAC_LEN]);

impl HmacBytes {
    /// Borrow the underlying bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; HMAC_LEN] {
        &self.0
    }

    /// Consume and return the underlying bytes.
    #[must_use]
    pub fn into_bytes(self) -> [u8; HMAC_LEN] {
        self.0
    }

    /// Lowercase hex encoding for diagnostics / serialization.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex_lower(&self.0)
    }
}

impl From<[u8; HMAC_LEN]> for HmacBytes {
    fn from(value: [u8; HMAC_LEN]) -> Self {
        Self(value)
    }
}

impl PartialEq for HmacBytes {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for HmacBytes {}

impl fmt::Debug for HmacBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HmacBytes({})", self.to_hex())
    }
}

/// Fingerprint of the signing key (`BLAKE3-256` of the key material).
///
/// Stable across the lifetime of the key. Embedded in every segment header
/// and every record's `key_id` field to detect cross-key tampering.
#[derive(Clone, Copy)]
pub struct KeyId([u8; KEY_ID_LEN]);

impl KeyId {
    /// Construct from raw bytes. Reserved for the keychain crate and
    /// other code reconstructing a `KeyId` from an already-trusted source
    /// (e.g. a segment header on disk that the verifier is about to check).
    /// Most callers should not need this — derive via [`InMemoryKey`].
    #[must_use]
    pub fn from_bytes(bytes: [u8; KEY_ID_LEN]) -> Self {
        Self(bytes)
    }

    /// Borrow the underlying bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; KEY_ID_LEN] {
        &self.0
    }

    /// Lowercase hex encoding, matching `chain.json` and the spec's
    /// `key_id_hex` field.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex_lower(&self.0)
    }
}

impl PartialEq for KeyId {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for KeyId {}

impl fmt::Debug for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeyId({})", self.to_hex())
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// Abstraction over any source of HMAC-SHA256 signing capability.
///
/// Implementors must guarantee that:
///
/// - `sign(data)` returns `HMAC-SHA256(key, data)` for the same `key` used
///   to derive [`Self::key_id`].
/// - Successive calls to `key_id()` return the same value for the
///   lifetime of the handle.
/// - The raw key material is not exposed through any public API.
pub trait KeyHandle: Send + Sync {
    /// Compute HMAC-SHA256 over `data` using this key.
    fn sign(&self, data: &[u8]) -> HmacBytes;

    /// Return the BLAKE3-256 fingerprint of the underlying key material.
    fn key_id(&self) -> KeyId;
}

/// In-memory HMAC-SHA256 signing key. Zeroes its key material on drop.
///
/// Use this directly for tests and ad-hoc usage. For desktop deployments
/// where the key lives in the host OS keychain, use
/// `ogentic_audit_keychain::KeychainKey` (which wraps an `InMemoryKey`
/// loaded from the platform secret store).
///
/// # Example
///
/// ```
/// use ogentic_audit_core::{InMemoryKey, KeyHandle};
///
/// let key = [0u8; 32];
/// let handle = InMemoryKey::from_bytes(key);
///
/// let sig = handle.sign(b"hello world");
/// assert_eq!(sig.as_bytes().len(), 32);
///
/// // key_id is a stable fingerprint
/// assert_eq!(handle.key_id(), handle.key_id());
/// ```
#[derive(ZeroizeOnDrop)]
pub struct InMemoryKey {
    key: [u8; HMAC_LEN],
    // KeyId is a one-way hash of the key material — not itself sensitive,
    // so we skip zeroizing it to make `key_id()` a copy-out rather than a
    // recomputation.
    #[zeroize(skip)]
    key_id: KeyId,
}

impl InMemoryKey {
    /// Construct from a 32-byte HMAC key.
    #[must_use]
    pub fn from_bytes(key: [u8; HMAC_LEN]) -> Self {
        let key_id_bytes: [u8; KEY_ID_LEN] = blake3::hash(&key).into();
        Self {
            key,
            key_id: KeyId(key_id_bytes),
        }
    }

    /// Construct from an arbitrary-length byte slice.
    ///
    /// Returns [`KeyError::InvalidLength`] if `bytes.len() != 32`.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, KeyError> {
        let arr: [u8; HMAC_LEN] = bytes.try_into().map_err(|_| KeyError::InvalidLength {
            expected: HMAC_LEN,
            got: bytes.len(),
        })?;
        Ok(Self::from_bytes(arr))
    }
}

impl KeyHandle for InMemoryKey {
    fn sign(&self, data: &[u8]) -> HmacBytes {
        type HmacSha256 = Hmac<Sha256>;
        let mut mac =
            HmacSha256::new_from_slice(&self.key).expect("HMAC-SHA256 accepts any key length");
        mac.update(data);
        let result = mac.finalize().into_bytes();
        let mut out = [0u8; HMAC_LEN];
        out.copy_from_slice(&result);
        HmacBytes(out)
    }

    fn key_id(&self) -> KeyId {
        self.key_id
    }
}

impl fmt::Debug for InMemoryKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InMemoryKey")
            .field("key", &"<redacted>")
            .field("key_id", &self.key_id)
            .finish()
    }
}

impl fmt::Display for InMemoryKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeyHandle(<redacted>, key_id={})", self.key_id)
    }
}

/// Errors constructing or loading a key.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum KeyError {
    /// The provided key material was not the expected length.
    #[error("invalid key length: expected {expected} bytes, got {got}")]
    InvalidLength {
        /// Required length (32 bytes for HMAC-SHA256).
        expected: usize,
        /// Length actually provided.
        got: usize,
    },
}

/// Lowercase hex encoding without dependencies — matches the format used
/// in `chain.json` and on the wire.
fn hex_lower(bytes: &[u8]) -> String {
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

    /// HMAC-SHA256 self-consistency: signing the same input with the same
    /// key twice yields equal `HmacBytes`.
    #[test]
    fn sign_is_deterministic() {
        let key = [0u8; HMAC_LEN];
        let kh = InMemoryKey::from_bytes(key);
        let a = kh.sign(b"hello");
        let b = kh.sign(b"hello");
        assert_eq!(a, b);
    }

    /// Signing the same input with two different keys yields different
    /// HMACs (overwhelmingly likely; constant-time `Eq` doesn't bias this).
    #[test]
    fn sign_depends_on_key() {
        let a = InMemoryKey::from_bytes([0u8; HMAC_LEN]).sign(b"hello");
        let b = InMemoryKey::from_bytes([1u8; HMAC_LEN]).sign(b"hello");
        assert_ne!(a, b);
    }

    /// `key_id` matches BLAKE3-256 of the raw key material — the
    /// derivation defined in the v0.1 spec.
    #[test]
    fn key_id_is_blake3_of_key() {
        let key = [42u8; HMAC_LEN];
        let kh = InMemoryKey::from_bytes(key);
        let expected: [u8; KEY_ID_LEN] = blake3::hash(&key).into();
        assert_eq!(kh.key_id().as_bytes(), &expected);
    }

    /// `key_id` is stable for the lifetime of the key.
    #[test]
    fn key_id_is_stable() {
        let kh = InMemoryKey::from_bytes([7u8; HMAC_LEN]);
        assert_eq!(kh.key_id(), kh.key_id());
    }

    /// `Display` redacts the key bytes.
    #[test]
    fn display_redacts_key() {
        let kh = InMemoryKey::from_bytes([0x42u8; HMAC_LEN]);
        let formatted = format!("{kh}");
        assert!(
            formatted.contains("<redacted>"),
            "Display did not redact: {formatted}"
        );
        assert!(
            !formatted.contains("42424242"),
            "Display leaked key bytes: {formatted}"
        );
    }

    /// `Debug` redacts the key bytes but does show the `key_id`
    /// (a one-way hash — not sensitive).
    #[test]
    fn debug_redacts_key_but_shows_key_id() {
        let kh = InMemoryKey::from_bytes([0x42u8; HMAC_LEN]);
        let formatted = format!("{kh:?}");
        assert!(
            formatted.contains("<redacted>"),
            "Debug did not redact: {formatted}"
        );
        assert!(
            !formatted.contains("42424242"),
            "Debug leaked key bytes: {formatted}"
        );
        assert!(
            formatted.contains(&kh.key_id().to_hex()),
            "Debug should expose key_id for traceability: {formatted}"
        );
    }

    /// `from_slice` accepts exactly 32 bytes.
    #[test]
    fn from_slice_accepts_32_bytes() {
        let bytes = [1u8; HMAC_LEN];
        assert!(InMemoryKey::from_slice(&bytes).is_ok());
    }

    /// `from_slice` rejects any other length.
    #[test]
    fn from_slice_rejects_other_lengths() {
        for len in [0, 1, 16, 31, 33, 64] {
            let bytes = vec![0u8; len];
            let err = InMemoryKey::from_slice(&bytes).unwrap_err();
            match err {
                KeyError::InvalidLength { expected, got } => {
                    assert_eq!(expected, HMAC_LEN);
                    assert_eq!(got, len);
                },
            }
        }
    }

    /// `HmacBytes` compare in constant time and behave as expected for
    /// the `Eq` API.
    #[test]
    fn hmac_bytes_constant_time_eq() {
        let a = HmacBytes([1u8; HMAC_LEN]);
        let b = HmacBytes([1u8; HMAC_LEN]);
        let c = HmacBytes([2u8; HMAC_LEN]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    /// `KeyId` compare in constant time and behave as expected for
    /// the `Eq` API.
    #[test]
    fn key_id_constant_time_eq() {
        let a = KeyId([1u8; KEY_ID_LEN]);
        let b = KeyId([1u8; KEY_ID_LEN]);
        let c = KeyId([2u8; KEY_ID_LEN]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    /// Hex round-trip: `KeyId::to_hex` produces lowercase hex of the
    /// expected length.
    #[test]
    fn key_id_hex_formatting() {
        let id = KeyId(
            [0xab, 0xcd, 0x00, 0xff]
                .iter()
                .chain([0u8; 28].iter())
                .copied()
                .collect::<Vec<u8>>()
                .try_into()
                .unwrap(),
        );
        let hex = id.to_hex();
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')));
        assert!(hex.starts_with("abcd00ff"));
    }

    /// End-to-end cross-check against the v0.1 golden vectors:
    /// the `key_hex` in every vector's `inputs.json` must derive the
    /// `key_id_hex` recorded in that vector's `chain.json`.
    ///
    /// Tracks [`OGE-441` (Q2)] — full cross-language vector consumption
    /// will land there; this is the first foothold from Rust into the
    /// shared vector suite.
    ///
    /// [`OGE-441` (Q2)]: https://linear.app/ogenticai/issue/OGE-441
    #[test]
    fn matches_v0_1_empty_vector() {
        // From tests/vectors/v0.1/empty/inputs.json:
        let key_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        let key_bytes: [u8; HMAC_LEN] = decode_hex_32(key_hex);
        let handle = InMemoryKey::from_bytes(key_bytes);

        // From tests/vectors/v0.1/empty/chain.json:
        let expected_key_id = "e528e95798037df410543d9f31e396ecdd458d71b157d6014398bae32fb56c65";
        assert_eq!(handle.key_id().to_hex(), expected_key_id);
    }

    fn decode_hex_32(s: &str) -> [u8; HMAC_LEN] {
        assert_eq!(s.len(), HMAC_LEN * 2);
        let mut out = [0u8; HMAC_LEN];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
    }

    /// Smoke test the trait object so the type-erased `Box<dyn KeyHandle>`
    /// path used by R1 / R3 actually works.
    #[test]
    fn key_handle_object_safe() {
        let kh: Box<dyn KeyHandle> = Box::new(InMemoryKey::from_bytes([0xab; HMAC_LEN]));
        let sig = kh.sign(b"trait-object call");
        assert_eq!(sig.as_bytes().len(), HMAC_LEN);
        let _id = kh.key_id();
    }
}
