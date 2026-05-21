//! `ogentic-audit-core` — HMAC-SHA256 chained, append-only audit log.
//!
//! See [`docs/spec/v0.1.md`](https://github.com/OgenticAI/ogentic-audit/blob/main/docs/spec/v0.1.md)
//! for the language-agnostic on-disk format and
//! [`docs/security/threat-model.md`](https://github.com/OgenticAI/ogentic-audit/blob/main/docs/security/threat-model.md)
//! for the security boundary this crate defends.
//!
//! v0.1 is in development. The public API is unstable until v0.1.0 is tagged.
//!
//! # Your first audit log
//!
//! ```no_run
//! use std::collections::BTreeMap;
//! use ogentic_audit_core::{InMemoryKey, PayloadValue, RecordInput, Verifier, Writer};
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // 32 raw HMAC-SHA256 key bytes. In real use, load via the
//!     // `ogentic-audit-keychain` crate or a vault. The session_id
//!     // is a UUIDv4 generated at vault-unlock time.
//!     let key = InMemoryKey::from_bytes([0u8; 32]);
//!     let session_id = [0u8; 16];
//!
//!     // 1. Open the log directory. Creates segment 0 if empty;
//!     //    otherwise recovers a torn tail and resumes appending.
//!     let mut writer = Writer::open("./audit-logs", Box::new(key), session_id)?;
//!
//!     // 2. Append one record.
//!     let mut payload = BTreeMap::new();
//!     payload.insert("vault_id".into(), PayloadValue::Text("v-001".into()));
//!     writer.append(RecordInput {
//!         ts_wall: "2026-05-21T05:00:00.000Z".into(),
//!         ts_mono_delta: 0,
//!         actor: "user:alice".into(),
//!         event: "vault.unlocked".into(),
//!         payload,
//!         schema_version: 1,
//!     })?;
//!     writer.flush()?;
//!     drop(writer);
//!
//!     // 3. Verify the log end-to-end.
//!     let key = InMemoryKey::from_bytes([0u8; 32]);
//!     let report = Verifier::new(Box::new(key)).verify("./audit-logs")?;
//!     assert_eq!(report.compact_verdict(), "Verified");
//!     Ok(())
//! }
//! ```
//!
//! # Modules
//!
//! - [`key`] — `KeyHandle` trait + in-memory implementation; constant-time
//!   compare on HMACs and key_ids
//! - [`writer`] — append-only writer with atomic flush, segment rollover,
//!   crash-recovery scan ([`RecoveryReport`])
//! - [`reader`] — sequential iterator + indexed seek; cooperative
//!   tail-watching with a live writer
//! - [`verifier`] — HMAC + chain integrity; structured [`Violation`]
//!   evidence on any failure
//! - [`segment`] — byte-level segment-header + record framing primitives
//! - [`cbor`] — canonical CBOR encoder + decoder (RFC 8949 §4.2)
//!
//! # Tracker
//!
//! The pieces landed via these tickets:
//!
//! - Writer — [R1 / OGE-429]
//! - Reader — [R2 / OGE-430]
//! - Verifier — [R3 / OGE-437]
//! - Crash recovery — [R5 / OGE-432]
//!
//! [R1 / OGE-429]: https://linear.app/ogenticai/issue/OGE-429
//! [R2 / OGE-430]: https://linear.app/ogenticai/issue/OGE-430
//! [R3 / OGE-437]: https://linear.app/ogenticai/issue/OGE-437
//! [R5 / OGE-432]: https://linear.app/ogenticai/issue/OGE-432

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms, missing_debug_implementations)]
#![warn(missing_docs)]

pub mod cbor;
pub mod key;
pub mod reader;
pub mod segment;
pub mod sync_compat;
pub mod verifier;
pub mod writer;

pub use key::{HmacBytes, InMemoryKey, KeyError, KeyHandle, KeyId, HMAC_LEN, KEY_ID_LEN};
pub use reader::{ReadStrategy, Reader, ReaderConfig, ReaderError, Record, RecordIterator};
pub use segment::{
    HeaderParseError, SegmentHeader, FORMAT_MAGIC, HEADER_BODY_LEN, HEADER_TOTAL_LEN,
    SESSION_ID_LEN,
};
pub use verifier::{
    HeaderCorruptSubkind, LogSummary, RecordCorruptSubkind, Verdict, Verifier, VerifyError,
    VerifyOptions, VerifyReport, Violation, ViolationEvidence, ViolationKind, ViolationLocation,
};
pub use writer::{
    PayloadValue, RecordId, RecordInput, RecoveryAction, RecoveryFailure, RecoveryReport, Writer,
    WriterConfig, WriterError,
};

/// Crate version, sourced from `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// On-disk format version implemented by this crate.
///
/// Matches the `version` field in the segment header. See
/// `docs/spec/v0.1.md` for the wire-format definition.
pub const FORMAT_VERSION: u16 = 0x0001;
