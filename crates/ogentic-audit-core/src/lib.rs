//! `ogentic-audit-core` — HMAC-SHA256 chained, append-only audit log.
//!
//! See [`docs/spec/v0.1.md`](https://github.com/OgenticAI/ogentic-audit/blob/main/docs/spec/v0.1.md)
//! for the language-agnostic on-disk format and
//! [`docs/security/threat-model.md`](https://github.com/OgenticAI/ogentic-audit/blob/main/docs/security/threat-model.md)
//! for the security boundary this crate defends.
//!
//! v0.1 is in development. The public API is unstable until v0.1.0 is tagged.

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms, missing_debug_implementations)]
#![warn(missing_docs)]

/// Crate version, sourced from `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// On-disk format version implemented by this crate.
///
/// Matches the `version` field in the segment header. See
/// `docs/spec/v0.1.md` for the wire-format definition.
pub const FORMAT_VERSION: u16 = 0x0001;
