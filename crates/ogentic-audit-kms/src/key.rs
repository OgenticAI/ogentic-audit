//! `KmsKey<P>` — a [`KeyHandle`] backed by any [`KmsProvider`].
//!
//! ## Blocking shim
//!
//! [`ogentic_audit_core::KeyHandle::sign`] is a synchronous, infallible
//! method — the trait cannot return an error.  `KmsKey` bridges this by
//! running the async `KmsProvider::sign` call on a tokio runtime:
//!
//! - If the caller is already inside a tokio runtime, `block_in_place` is
//!   used to avoid blocking the executor thread.
//! - Otherwise a fresh `current_thread` runtime is created for the duration
//!   of the call.
//!
//! If the provider returns an error (KMS unreachable, AccessDenied, etc.)
//! the shim panics with the `KmsError` rendered as a string.  This is
//! intentional: `KeyHandle::sign` is called deep inside
//! `ogentic_audit_core::Writer::append`, which has no error-recovery path
//! for "the signing key is unavailable".  An operator who deploys with a
//! KMS-backed key must ensure the KMS is reachable; if it is not, the
//! audit gap is surfaced loudly as a panic rather than silently as a
//! zero-byte MAC.
//!
//! ## Key-ID projection
//!
//! For KMS-backed keys, the raw key bytes are HSM-resident and never
//! visible to this process.  `key_id` is therefore derived from the
//! _provider descriptor_ (a canonical description of _which_ key to use),
//! not from the key material itself.  The derivation uses BLAKE3-256:
//!
//! ```text
//! key_id = BLAKE3-256("ogentic-audit-kms/v1\n" || provider_name || "\n" || descriptor)
//! ```
//!
//! This is transparent to the core verifier, which compares `key_id`
//! bytes without inspecting their origin.  See
//! `docs/adr/0002-server-side-kms-key-sourcing.md` for the rationale.

use std::fmt;

use ogentic_audit_core::{HmacBytes, KeyHandle, KeyId, KEY_ID_LEN};

use crate::error::KmsError;
use crate::provider::KmsProvider;

/// Operating mode of a [`KmsKey`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    /// Direct `GenerateMac` call (v0.1 default).
    Generate,
    /// Envelope-encrypted local-HMAC (reserved; deferred to OGE-603 / v0.2).
    ///
    /// The variant is never constructed in v0.1; it exists to lock the API
    /// surface so v0.2 can add the implementation without a breaking change.
    #[allow(dead_code)]
    Envelope,
}

/// A [`KeyHandle`] backed by a [`KmsProvider`].
///
/// Construct with [`KmsKey::new`]; [`KmsKey::with_envelope_mode`] reserves
/// the API surface for v0.2 but returns an error until then.
///
/// `Display` and `Debug` are redacted: neither the ARN nor the underlying
/// MAC bytes appear in formatted output.
pub struct KmsKey<P: KmsProvider> {
    provider: P,
    key_id: KeyId,
    #[allow(dead_code)] // Envelope mode is deferred to OGE-603.
    mode: Mode,
}

impl<P: KmsProvider> KmsKey<P> {
    /// Construct a `KmsKey` using direct `GenerateMac` mode (v0.1 default).
    ///
    /// `key_id` is derived from `provider.key_descriptor()` via BLAKE3-256;
    /// it does not require a network call.
    pub fn new(provider: P) -> Result<Self, KmsError> {
        let key_id = derive_key_id(provider.key_descriptor(), "aws-kms");
        Ok(Self {
            provider,
            key_id,
            mode: Mode::Generate,
        })
    }

    /// Envelope-mode constructor.  Behaviour deferred to OGE-603 (v0.2).
    ///
    /// The API surface is locked here for v0.1; calling this constructor
    /// returns `Err(KmsError::Config(...))` until the v0.2 implementation
    /// ships.
    pub fn with_envelope_mode(_provider: P) -> Result<Self, KmsError> {
        Err(KmsError::Config(
            "envelope mode not yet implemented; see OGE-603",
        ))
    }

    /// First 8 bytes of the `key_id` as lowercase hex, for use in
    /// `Display` / `Debug` impls.  Not sensitive (it's a one-way hash).
    pub(crate) fn key_id_hex_short(&self) -> String {
        let full = hex_lower(self.key_id.as_bytes());
        format!("{}…", &full[..16])
    }
}

impl<P: KmsProvider> KeyHandle for KmsKey<P> {
    /// Sign `data` using the KMS-resident key.
    ///
    /// Internally this runs `KmsProvider::sign` on a blocking tokio
    /// runtime.  If the provider returns an error, this method panics with
    /// a descriptive message.  See the module doc for the design rationale.
    ///
    /// ## Runtime compatibility
    ///
    /// - **Multi-thread runtime** — uses `tokio::task::block_in_place` so
    ///   the async KMS call can run on the current thread without starving
    ///   the executor.
    /// - **Current-thread runtime** (e.g. `#[tokio::test]`) — uses
    ///   `std::thread::scope` to spawn a scoped thread that owns a fresh
    ///   `current_thread` tokio runtime.  `std::thread::scope` ensures the
    ///   thread cannot outlive this stack frame, so no `unsafe` is required.
    /// - **No runtime** — creates a fresh `current_thread` runtime for the
    ///   duration of the call.
    fn sign(&self, data: &[u8]) -> HmacBytes {
        use tokio::runtime::{Handle, RuntimeFlavor};

        let mac = match Handle::try_current() {
            Ok(handle) => {
                match handle.runtime_flavor() {
                    RuntimeFlavor::MultiThread => {
                        tokio::task::block_in_place(|| handle.block_on(self.provider.sign(data)))
                    },
                    // CurrentThread and other flavors cannot use block_in_place.
                    // Spawn a scoped thread with its own single-thread runtime
                    // so the KMS future can run without blocking the executor.
                    _ => {
                        let provider = &self.provider;
                        std::thread::scope(|s| {
                            s.spawn(|| {
                                tokio::runtime::Builder::new_current_thread()
                                    .enable_all()
                                    .build()
                                    .expect("kms: failed to build scoped signing runtime")
                                    .block_on(provider.sign(data))
                            })
                            .join()
                            .expect("kms: scoped signing thread panicked")
                        })
                    },
                }
            },
            Err(_) => tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("kms: failed to build current-thread runtime")
                .block_on(self.provider.sign(data)),
        };
        mac.unwrap_or_else(|e| panic!("kms: sign failed — KMS unavailable or misconfigured: {e}"))
    }

    fn key_id(&self) -> KeyId {
        self.key_id
    }
}

/// Derive a `KeyId` from the provider descriptor.
///
/// ```text
/// key_id = BLAKE3-256("ogentic-audit-kms/v1\n" || provider_name || "\n" || descriptor)
/// ```
pub(crate) fn derive_key_id(descriptor: &[u8], provider_name: &str) -> KeyId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"ogentic-audit-kms/v1\n");
    hasher.update(provider_name.as_bytes());
    hasher.update(b"\n");
    hasher.update(descriptor);
    let h = hasher.finalize();
    let bytes: [u8; KEY_ID_LEN] = *h.as_bytes();
    KeyId::from_bytes(bytes)
}

/// Lowercase hex encoding (no external dep needed here).
fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

impl<P: KmsProvider> fmt::Display for KmsKey<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "KmsKey(arn=<redacted>, key_id={})",
            self.key_id_hex_short()
        )
    }
}

impl<P: KmsProvider> fmt::Debug for KmsKey<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KmsKey")
            .field("arn", &"<redacted>")
            .field("key_id", &self.key_id_hex_short())
            .finish()
    }
}
