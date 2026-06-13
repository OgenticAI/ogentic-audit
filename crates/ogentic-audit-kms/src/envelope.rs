//! Envelope-encrypted local-HMAC mode for KMS-backed keys.
//!
//! Deferred to OGE-603 (v0.2). The constructor [`crate::KmsKey::with_envelope_mode`]
//! returns `KmsError::Config(...)` until the v0.2 implementation ships;
//! the public API surface is reserved here so callers can write against
//! a stable shape.
//!
//! See: <https://linear.app/ogenticai/issue/OGE-603>
