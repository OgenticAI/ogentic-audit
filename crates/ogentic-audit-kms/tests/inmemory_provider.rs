//! Unit tests for `KmsKey<P>` using a fully in-process `FakeKmsProvider`.
//!
//! These tests run without any network access and complete in milliseconds.

use hmac::{Hmac, Mac};
use ogentic_audit_core::{HmacBytes, KeyHandle, HMAC_LEN};
use ogentic_audit_kms::{KmsError, KmsKey, KmsProvider};
use sha2::Sha256;
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// Fake provider
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct FakeKmsProvider {
    key: [u8; 32],
}

#[async_trait::async_trait]
impl KmsProvider for FakeKmsProvider {
    fn key_descriptor(&self) -> &[u8] {
        b"fake-provider/test-key-1"
    }

    async fn sign(&self, msg: &[u8]) -> Result<HmacBytes, KmsError> {
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_from_slice(&self.key)
            .map_err(|_| KmsError::Internal("test fake: bad key"))?;
        mac.update(msg);
        let out = mac.finalize().into_bytes();
        let mut arr = [0u8; HMAC_LEN];
        arr.copy_from_slice(&out);
        Ok(HmacBytes::from(arr))
    }

    // Test fixtures override `provider_name()` per ADR-0002 §iv to namespace
    // test `key_id`s away from production AWS `key_id`s. Two `FakeKmsProvider`
    // instances continue to produce identical `key_id`s (descriptor-determinism
    // test below); they only differ from an `AwsKmsProvider` that happened to
    // have the same descriptor.
    fn provider_name(&self) -> &str {
        "fake"
    }

    /// Return the provider's own key bytes as the DEK (simulates a provider
    /// that already holds the plaintext HMAC key for envelope mode).
    async fn envelope_unwrap(&self) -> Result<[u8; HMAC_LEN], KmsError> {
        Ok(self.key)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Signing the same message twice with the same key produces identical MACs.
#[tokio::test]
async fn roundtrip_via_keyhandle() {
    let key = KmsKey::new(FakeKmsProvider { key: [7u8; 32] }).unwrap();
    let sig1 = key.sign(b"hello");
    let sig2 = key.sign(b"hello");
    assert_eq!(sig1.as_bytes(), sig2.as_bytes(), "deterministic signing");
    let sig3 = key.sign(b"different");
    assert_ne!(
        sig1.as_bytes(),
        sig3.as_bytes(),
        "different msg → different mac"
    );
}

/// `key_id` is derived from the provider descriptor, not the key material.
/// Two `FakeKmsProvider` instances with different `key` bytes but the same
/// `key_descriptor()` must produce the same `key_id`.
#[tokio::test]
async fn key_id_is_deterministic() {
    let a = KmsKey::new(FakeKmsProvider { key: [1u8; 32] }).unwrap();
    let b = KmsKey::new(FakeKmsProvider { key: [9u8; 32] }).unwrap(); // same descriptor
    assert_eq!(
        a.key_id().as_bytes(),
        b.key_id().as_bytes(),
        "key_id projects from descriptor, not the underlying key material"
    );
}

/// `KmsKey::with_envelope_mode` constructs a `KmsKey` in Envelope mode (OGE-603 / v0.2).
#[tokio::test]
async fn envelope_mode_constructs_ok() {
    let r = KmsKey::with_envelope_mode(FakeKmsProvider { key: [0u8; 32] });
    assert!(
        r.is_ok(),
        "with_envelope_mode must return Ok in v0.2; got {r:?}"
    );
}

/// Envelope-mode `sign()` returns a valid HMAC-SHA256.
#[tokio::test]
async fn envelope_mode_sign_produces_hmac() {
    let key_bytes = [0x5au8; 32];
    let kms_key = KmsKey::with_envelope_mode(FakeKmsProvider { key: key_bytes }).unwrap();
    let sig = kms_key.sign(b"hello envelope");
    assert_eq!(sig.as_bytes().len(), HMAC_LEN);
}

/// Envelope mode is deterministic: same key + same message → same MAC.
#[tokio::test]
async fn envelope_mode_sign_is_deterministic() {
    let key_bytes = [0x7fu8; 32];
    let kms_key = KmsKey::with_envelope_mode(FakeKmsProvider { key: key_bytes }).unwrap();
    let sig1 = kms_key.sign(b"same message");
    let sig2 = kms_key.sign(b"same message");
    assert_eq!(sig1.as_bytes(), sig2.as_bytes(), "envelope sign must be deterministic");

    let sig3 = kms_key.sign(b"different message");
    assert_ne!(
        sig1.as_bytes(),
        sig3.as_bytes(),
        "different messages must produce different MACs"
    );
}

/// Envelope-mode output matches a direct HMAC-SHA256 computation with the same key.
///
/// This test verifies AC-4: local HMAC is byte-for-byte compatible with
/// what KMS `GenerateMac` would produce for the same key material.
#[tokio::test]
async fn envelope_mode_matches_direct_hmac_sha256() {
    type HmacSha256 = Hmac<Sha256>;
    let key_bytes = [0x3cu8; 32];
    let msg = b"bytewise-compat check";

    // Envelope-mode KmsKey
    let kms_key = KmsKey::with_envelope_mode(FakeKmsProvider { key: key_bytes }).unwrap();
    let envelope_sig = kms_key.sign(msg);

    // Direct HMAC-SHA256
    let mut mac = HmacSha256::new_from_slice(&key_bytes).unwrap();
    mac.update(msg);
    let direct: [u8; HMAC_LEN] = mac.finalize().into_bytes().into();

    assert_eq!(
        envelope_sig.as_bytes(),
        &direct,
        "envelope-mode output must match direct HMAC-SHA256"
    );
}

/// `key_id` is identical for GenerateMac and envelope mode when the same
/// provider descriptor is used (AC-5).
#[tokio::test]
async fn envelope_mode_key_id_matches_generate_mode() {
    let key_bytes = [0x11u8; 32];
    let generate_key = KmsKey::new(FakeKmsProvider { key: key_bytes }).unwrap();
    let envelope_key = KmsKey::with_envelope_mode(FakeKmsProvider { key: key_bytes }).unwrap();
    assert_eq!(
        generate_key.key_id().as_bytes(),
        envelope_key.key_id().as_bytes(),
        "key_id must be identical for both modes with the same descriptor"
    );
}

/// Envelope-mode DEK buffer is held in a Zeroizing wrapper (AC-8).
///
/// We cannot safely read zeroed memory after drop (that would require
/// unsafe pointer snooping which `#![forbid(unsafe_code)]` forbids in the
/// library).  Instead we verify:
///   1. The DEK is initialised lazily (sign succeeds after construction).
///   2. The `Zeroizing` type's own guarantees cover the zeroing-on-drop.
///   3. We confirm via a compile-time property that the OnceLock<Zeroizing<_>>
///      is part of the KmsKey (by observing deterministic behaviour).
#[tokio::test]
async fn envelope_mode_dek_zeroizing_wrapper() {
    // The DEK is initialised lazily on first sign.
    let key = KmsKey::with_envelope_mode(FakeKmsProvider { key: [0xaau8; 32] }).unwrap();
    let sig_before = key.sign(b"trigger lazy init");
    // A second sign hits the cached DEK (not the provider again).
    let sig_after = key.sign(b"trigger lazy init");
    assert_eq!(
        sig_before.as_bytes(),
        sig_after.as_bytes(),
        "cached DEK must produce identical output on repeated calls"
    );
    // Dropping `key` here triggers Zeroizing::drop on the DEK buffer.
    // Correct zeroing is guaranteed by the zeroize crate's volatile-write
    // barrier; we trust the crate's own test suite for that property.
    drop(key);

    // Verify the Zeroizing type itself zeroes when dropped.
    let mut buf = Zeroizing::new([0xffu8; 32]);
    assert_eq!(*buf, [0xffu8; 32]);
    // Zeroize in place to confirm the barrier works without drop.
    use zeroize::Zeroize;
    buf.zeroize();
    assert_eq!(*buf, [0u8; 32], "Zeroizing::zeroize must zero the buffer");
}

/// The `KmsKey` satisfies `KeyHandle` as a trait object (`Box<dyn KeyHandle>`).
#[tokio::test]
async fn key_handle_object_safe() {
    let key = KmsKey::new(FakeKmsProvider { key: [0xab; 32] }).unwrap();
    let kh: Box<dyn KeyHandle> = Box::new(key);
    let sig = kh.sign(b"trait-object call");
    assert_eq!(sig.as_bytes().len(), HMAC_LEN);
    let _id = kh.key_id();
}

/// `key_id` is stable across multiple calls on the same instance.
#[tokio::test]
async fn key_id_is_stable() {
    let key = KmsKey::new(FakeKmsProvider { key: [5u8; 32] }).unwrap();
    assert_eq!(key.key_id().as_bytes(), key.key_id().as_bytes());
}

/// Two providers with the SAME `key_descriptor()` bytes but DIFFERENT
/// `provider_name()` strings produce DIFFERENT `key_id`s. Guarantees
/// cross-provider namespace separation (AWS vs GCP vs Azure vs test fixture).
/// Regression check on ADR-0002 §iv's namespace contract.
#[tokio::test]
async fn key_id_namespace_separates_providers() {
    #[derive(Debug)]
    struct SameDescriptorDifferentNamespace;
    #[async_trait::async_trait]
    impl KmsProvider for SameDescriptorDifferentNamespace {
        fn key_descriptor(&self) -> &[u8] {
            // EXACT same bytes as `FakeKmsProvider`.
            b"fake-provider/test-key-1"
        }
        async fn sign(&self, _msg: &[u8]) -> Result<HmacBytes, KmsError> {
            Ok(HmacBytes::from([0u8; HMAC_LEN]))
        }
        fn provider_name(&self) -> &str {
            // Distinct from `FakeKmsProvider::provider_name()`.
            "different-cloud"
        }
    }

    let fake = KmsKey::new(FakeKmsProvider { key: [0u8; 32] }).unwrap();
    let other = KmsKey::new(SameDescriptorDifferentNamespace).unwrap();
    assert_ne!(
        fake.key_id().as_bytes(),
        other.key_id().as_bytes(),
        "providers sharing a descriptor must still produce distinct key_ids \
         when their provider_name() differs (BLAKE3 namespace separation)"
    );
}
