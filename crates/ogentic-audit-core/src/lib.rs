//! `ogentic-audit-core` — HMAC-SHA256 chained, append-only audit log.
//!
//! See [`docs/spec/v0.1.md`](https://github.com/OgenticAI/ogentic-audit/blob/main/docs/spec/v0.1.md)
//! for the language-agnostic on-disk format and
//! [`docs/security/threat-model.md`](https://github.com/OgenticAI/ogentic-audit/blob/main/docs/security/threat-model.md)
//! for the security boundary this crate defends.
//!
//! v0.1 is in development. The public API is unstable until v0.1.0 is tagged.
//!
//! ## What's implemented today
//!
//! - [`KeyHandle`] trait and the in-memory [`InMemoryKey`] implementation
//!   (this module, [`key`]). Optional OS-keychain backing lives in the
//!   companion `ogentic-audit-keychain` crate.
//!
//! ## What's coming
//!
//! The writer ([R1 / OGE-429]), reader ([R2 / OGE-430]), and verifier
//! ([R3 / OGE-437]) all consume [`KeyHandle`] and land in subsequent
//! tickets.
//!
//! [R1 / OGE-429]: https://linear.app/ogenticai/issue/OGE-429
//! [R2 / OGE-430]: https://linear.app/ogenticai/issue/OGE-430
//! [R3 / OGE-437]: https://linear.app/ogenticai/issue/OGE-437

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms, missing_debug_implementations)]
#![warn(missing_docs)]

pub mod cbor;
pub mod key;
pub mod segment;
pub mod sync_compat;
pub mod writer;

pub use key::{HmacBytes, InMemoryKey, KeyError, KeyHandle, KeyId, HMAC_LEN, KEY_ID_LEN};
pub use segment::{SegmentHeader, FORMAT_MAGIC, HEADER_BODY_LEN, HEADER_TOTAL_LEN, SESSION_ID_LEN};
pub use writer::{PayloadValue, RecordId, RecordInput, Writer, WriterConfig, WriterError};

/// Crate version, sourced from `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// On-disk format version implemented by this crate.
///
/// Matches the `version` field in the segment header. See
/// `docs/spec/v0.1.md` for the wire-format definition.
pub const FORMAT_VERSION: u16 = 0x0001;
