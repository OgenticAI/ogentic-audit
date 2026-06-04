//! `ogentic-audit-kms` — optional KMS-backed [`KeyHandle`] for
//! `ogentic-audit`.
//!
//! This crate adds a server-side key source for deployments where the
//! HMAC signing key must never leave a hardware security module (HSM).
//! v0.1 ships with AWS KMS (`GenerateMac`); GCP Cloud KMS and Azure Key
//! Vault are reserved for v0.2 (tracked under OGE-603).
//!
//! ## Feature flags
//!
//! | Feature | Default | What it enables |
//! |---------|---------|-----------------|
//! | `aws`   | **on**  | [`AwsKmsProvider`] + `aws-sdk-kms` dependency |
//!
//! Turn off the `aws` feature with `default-features = false` if you want
//! only the [`KmsProvider`] trait and the [`KmsKey`] type surface (e.g. to
//! wire up a custom provider without pulling in the AWS SDK).
//!
//! ## Quickstart
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use ogentic_audit_kms::{AwsKmsProvider, KmsKey};
//! use ogentic_audit_core::{KeyHandle, Writer};
//!
//! let arn = "arn:aws:kms:us-east-1:123456789012:key/mrk-abcdef0123456789";
//! let provider = AwsKmsProvider::from_arn(arn).await?;
//! let key = KmsKey::new(provider)?;
//!
//! // Use like any other KeyHandle.
//! let session_id = [0u8; 16];
//! let mut writer = Writer::open("./audit-logs", Box::new(key), session_id)?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Security invariants
//!
//! - Key material never enters process memory; all HMAC operations execute
//!   inside the KMS HSM.
//! - `Display` and `Debug` impls redact the ARN and never show MAC bytes.
//!   See `crate::redact` (internal module) for the full policy.
//! - `key_id` is derived from the provider descriptor (not the key material)
//!   via BLAKE3-256.  The derivation is documented in
//!   `docs/adr/0002-server-side-kms-key-sourcing.md`.
//!
//! ## MSRV
//!
//! Rust 1.85 (edition 2021).
//!
//! ## Links
//!
//! - Integration guide: `docs/integrations/server-side-kms.md`
//! - ADR: `docs/adr/0002-server-side-kms-key-sourcing.md`
//! - Threat model: `docs/security/threat-model.md`

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms, missing_debug_implementations)]
#![warn(missing_docs)]

pub mod envelope;
pub(crate) mod redact;

mod error;
mod key;
mod provider;

#[cfg(feature = "aws")]
mod aws;

pub use crate::error::KmsError;
pub use crate::key::KmsKey;
pub use crate::provider::KmsProvider;

#[cfg(feature = "aws")]
pub use crate::aws::AwsKmsProvider;

// Re-export core types so consumers don't need to depend on
// `ogentic-audit-core` directly when composing with a `KmsKey`.
pub use ogentic_audit_core::{HmacBytes, KeyHandle, KeyId, HMAC_LEN};

/// Crate version, sourced from `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
