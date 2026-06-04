//! Unit tests for `KmsKey<P>` using a fully in-process `FakeKmsProvider`.
//!
//! These tests run without any network access and complete in milliseconds.

use hmac::{Hmac, Mac};
use ogentic_audit_core::{HmacBytes, KeyHandle, HMAC_LEN};
use ogentic_audit_kms::{KmsError, KmsKey, KmsProvider};
use sha2::Sha256;

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

/// `KmsKey::with_envelope_mode` must return `Err(KmsError::Config(...))` in v0.1.
#[tokio::test]
async fn envelope_mode_is_deferred() {
    let r = KmsKey::with_envelope_mode(FakeKmsProvider { key: [0u8; 32] });
    assert!(
        matches!(r, Err(KmsError::Config(_))),
        "envelope mode must return Config error until OGE-603 ships; got {r:?}"
    );
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
