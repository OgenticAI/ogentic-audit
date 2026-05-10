//! `ogentic-audit-keychain` — optional OS-keychain key source.
//!
//! This crate exposes a [`KeyHandle`]-compatible adapter that pulls the HMAC
//! key material from the host operating system's secret store:
//!
//! - macOS: Keychain Services
//! - Linux: Secret Service (libsecret)
//! - Windows: Credential Manager
//!
//! It is **optional**. The default `ogentic-audit-core` build does not depend
//! on any OS-specific crypto-storage facility — consumers that prefer a vault-
//! derived passphrase, a KMS-backed signer, or any other key source skip this
//! crate entirely.
//!
//! v0.1 is in development. The public API is unstable until v0.1.0 is tagged.

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms, missing_debug_implementations)]
#![warn(missing_docs)]

/// Crate version, sourced from `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
