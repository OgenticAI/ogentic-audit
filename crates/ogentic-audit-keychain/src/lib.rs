//! `ogentic-audit-keychain` — OS-keychain-backed [`KeyHandle`] for
//! `ogentic-audit`.
//!
//! The audit log's signing key needs to live somewhere durable that the
//! application can re-acquire on every launch without prompting the user
//! to re-enter a passphrase. The platform secret store is the canonical
//! answer:
//!
//! - macOS: **Keychain Services**.
//! - Linux: **Secret Service** (e.g. `gnome-keyring`, `kwallet`) over D-Bus.
//! - Windows: **Credential Manager**.
//!
//! This crate wraps the [`keyring`](https://crates.io/crates/keyring)
//! abstraction over those three backends and exposes a [`KeychainKey`]
//! that satisfies [`KeyHandle`].
//!
//! The crate is **optional** at the workspace level: server-side
//! deployments (Zashboard, see [OGE-460]) that hold their HMAC key in a
//! cloud KMS do not link this crate at all. The default feature
//! `keychain` is on; turn it off with `default-features = false` if you
//! want only the type surface.
//!
//! [OGE-460]: https://linear.app/ogenticai/issue/OGE-460
//!
//! # Threat-model context
//!
//! The threat model at `docs/security/threat-model.md` makes the
//! OS-keychain trust assumption explicit: the host OS is trusted while
//! the user is logged in. Any attacker with the ability to read the
//! running process's memory (or impersonate it to the keychain) has the
//! key. This crate inherits that assumption — it does not, and cannot,
//! defend against process-level adversaries.
//!
//! # Rotation
//!
//! See `docs/security/key-rotation.md` for the customer-facing rotation
//! recipe. In short: a new key produces a new `key_id`, which produces a
//! new segment header, which produces a fresh chain. The library does
//! not rewrite existing logs.

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms, missing_debug_implementations)]
#![warn(missing_docs)]

/// Crate version, sourced from `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(feature = "keychain")]
mod backend;
#[cfg(feature = "keychain")]
pub use backend::{Error, KeychainKey};

// Re-export the core types consumers will interact with so they don't
// have to depend on `ogentic-audit-core` directly to compose with a
// `KeychainKey`.
pub use ogentic_audit_core::{HmacBytes, KeyHandle, KeyId, HMAC_LEN};
