//! Provider trait — provider-agnostic KMS abstraction.
//!
//! Implementations must be `Send + Sync` so they can be placed inside a
//! `Box<dyn KeyHandle>` and passed across thread boundaries by the
//! `ogentic-audit-core` writer and verifier.
//!
//! Only this file is provider-agnostic; AWS-specific types live entirely
//! in [`crate::aws`].

use crate::error::KmsError;
use ogentic_audit_core::HmacBytes;

/// A source of KMS-backed HMAC-SHA256 signing capability.
///
/// Implementors produce an HMAC of a given message by delegating to an
/// external key-management service. The default implementation (AWS KMS
/// `GenerateMac`) never extracts or caches key material in process memory —
/// the private key bytes remain inside the HSM.
///
/// ## Key descriptor
///
/// Every provider must supply a `key_descriptor` that is:
///
/// - **Stable** across processes and SDK upgrades for the same logical key.
/// - **Unique** per logical key (two different keys must differ in
///   descriptor; two references to the same key must produce identical bytes).
///
/// The descriptor is the input to the BLAKE3-based `key_id` projection in
/// [`crate::key::KmsKey`]; its bytes are never sent to the KMS service.
#[async_trait::async_trait]
pub trait KmsProvider: Send + Sync + std::fmt::Debug {
    /// Stable identifier for this provider + key, used to derive `KeyId`.
    ///
    /// Implementations MUST return the same bytes for the same logical key
    /// across processes and SDK upgrades.  The bytes are NOT the key
    /// material — they are a canonical description of which key to use.
    fn key_descriptor(&self) -> &[u8];

    /// Sign `msg` using the KMS-resident key.
    ///
    /// The default implementations MUST NOT extract or cache key material in
    /// process memory.  The MAC bytes are returned after being transmitted
    /// over TLS from the KMS service.
    async fn sign(&self, msg: &[u8]) -> Result<HmacBytes, KmsError>;
}
