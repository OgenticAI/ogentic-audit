//! Signing behind a handle (spec v0.2 §7.1, §13.1).
//!
//! A [`Signer`] signs SSHSIG data in a namespace. It never exposes the
//! private key. Signing is fallible because a key that is not in process
//! memory (an OS-protected key, a hardware token, a KMS) can be
//! unavailable or need a prompt the user dismisses; the trait is the
//! extension point for such keys.

use std::fmt;

use ed25519_dalek::{Signer as _, SigningKey};
use zeroize::Zeroizing;

use super::ed25519;
use super::keys::PublicKey;
use super::sshsig;

/// A 64-byte Ed25519 signature.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Signature(pub [u8; 64]);

impl Signature {
    /// The raw bytes.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 64] {
        self.0
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signature({})", super::hex(&self.0))
    }
}

/// Why a signature could not be made.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SignError {
    /// The key is not available (locked, absent, no backend on this host).
    #[error("signing key unavailable")]
    Unavailable,
    /// A user prompt was dismissed.
    #[error("signing cancelled")]
    Cancelled,
    /// The signature failed its own strict check before being written: a
    /// fault during signing. Nothing was written.
    #[error("signature failed its own verification (possible fault); nothing written")]
    FaultDetected,
    /// A backend-specific failure.
    #[error("signing backend error: {0}")]
    Backend(String),
}

/// Signs SSHSIG data with a private key it never exposes.
pub trait Signer: Send + Sync {
    /// The signer's public key.
    fn public_key(&self) -> &PublicKey;

    /// Sign `message` in `namespace`: Ed25519 over
    /// [`sshsig::signed_data`]`(namespace, message)`.
    fn sign(&self, namespace: &str, message: &[u8]) -> Result<Signature, SignError>;
}

/// Sign and then verify strictly before returning (spec §7.1: a fault
/// during deterministic signing can leak the key, so a faulty signature
/// must never be written). Every caller in this crate signs through this.
pub fn sign_checked(
    signer: &dyn Signer,
    namespace: &str,
    message: &[u8],
) -> Result<Signature, SignError> {
    let sig = signer.sign(namespace, message)?;
    let data = sshsig::signed_data(namespace, message);
    ed25519::verify(signer.public_key().as_bytes(), &data, &sig.0)
        .map_err(|_| SignError::FaultDetected)?;
    Ok(sig)
}

/// [`sign_checked`], returning the armored detached signature.
pub fn sign_detached(
    signer: &dyn Signer,
    namespace: &str,
    message: &[u8],
) -> Result<String, SignError> {
    let sig = sign_checked(signer, namespace, message)?;
    Ok(sshsig::armor(signer.public_key(), namespace, &sig.0))
}

/// An Ed25519 key held in process memory, zeroized on drop.
///
/// The public key is derived from the seed, never accepted from the
/// caller, and re-derived for every signature (signing under a separately
/// stored public key that does not match leaks the private key).
pub struct InMemorySigner {
    seed: Zeroizing<[u8; 32]>,
    public: PublicKey,
}

impl fmt::Debug for InMemorySigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InMemorySigner")
            .field("public_key", &self.public)
            .finish_non_exhaustive()
    }
}

impl InMemorySigner {
    /// From a 32-byte RFC 8032 seed (the "secret key").
    #[must_use]
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let seed = Zeroizing::new(seed);
        let public = PublicKey::ed25519(SigningKey::from_bytes(&seed).verifying_key().to_bytes());
        Self { seed, public }
    }

    /// A fresh key from the OS CSPRNG.
    ///
    /// # Panics
    ///
    /// Panics if the OS random source fails.
    #[must_use]
    pub fn generate() -> Self {
        let mut seed = Zeroizing::new([0u8; 32]);
        getrandom::getrandom(seed.as_mut()).expect("OS random source failed");
        Self::from_seed(*seed)
    }

    /// The seed, for a caller that stores it (the keychain crate). Handle
    /// with care: this is the private key.
    #[must_use]
    pub fn seed(&self) -> &[u8; 32] {
        &self.seed
    }
}

impl Signer for InMemorySigner {
    fn public_key(&self) -> &PublicKey {
        &self.public
    }

    fn sign(&self, namespace: &str, message: &[u8]) -> Result<Signature, SignError> {
        let key = SigningKey::from_bytes(&self.seed);
        if key.verifying_key().to_bytes() != *self.public.as_bytes() {
            return Err(SignError::FaultDetected);
        }
        let data = sshsig::signed_data(namespace, message);
        Ok(Signature(key.sign(&data).to_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signs_and_checks() {
        let s = InMemorySigner::from_seed([1u8; 32]);
        let sig = sign_checked(&s, "ns", b"m").unwrap();
        let data = sshsig::signed_data("ns", b"m");
        assert!(ed25519::verify(s.public_key().as_bytes(), &data, &sig.0).is_ok());
    }

    struct Faulty(InMemorySigner);
    impl Signer for Faulty {
        fn public_key(&self) -> &PublicKey {
            self.0.public_key()
        }
        fn sign(&self, ns: &str, m: &[u8]) -> Result<Signature, SignError> {
            let mut s = self.0.sign(ns, m)?;
            s.0[5] ^= 1;
            Ok(s)
        }
    }

    #[test]
    fn fault_is_detected() {
        let f = Faulty(InMemorySigner::from_seed([1u8; 32]));
        assert_eq!(sign_checked(&f, "ns", b"m"), Err(SignError::FaultDetected));
    }
}
