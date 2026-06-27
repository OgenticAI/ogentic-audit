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
use std::sync::OnceLock;

use ogentic_audit_core::{HmacBytes, KeyHandle, KeyId, KEY_ID_LEN, HMAC_LEN};
use zeroize::Zeroizing;

use crate::envelope::local_hmac;
use crate::error::KmsError;
use crate::provider::KmsProvider;

/// Operating mode of a [`KmsKey`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    /// Direct `GenerateMac` call (v0.1 default).
    Generate,
    /// Envelope-encrypted local-HMAC (OGE-603 / v0.2).
    ///
    /// On the first `sign()` call the provider's `envelope_unwrap()` is
    /// invoked to obtain the raw HMAC key bytes; they are then cached in
    /// `KmsKey::envelope_key` for the lifetime of this instance.
    Envelope,
}

/// A [`KeyHandle`] backed by a [`KmsProvider`].
///
/// Construct with [`KmsKey::new`] for direct `GenerateMac` mode (HSM-resident
/// key material, one KMS call per `sign`) or with
/// [`KmsKey::with_envelope_mode`] for envelope-encrypted local-HMAC mode
/// (one KMS `GenerateDataKey`/`Decrypt` call on first `sign`, then local
/// HMAC for all subsequent calls).
///
/// `Display` and `Debug` are redacted: neither the ARN nor the underlying
/// MAC bytes appear in formatted output.
pub struct KmsKey<P: KmsProvider> {
    provider: P,
    key_id: KeyId,
    mode: Mode,
    /// Cached DEK for envelope mode.  Empty in `Generate` mode.
    /// Initialised lazily on the first `sign()` call via `OnceLock`.
    /// `Zeroizing` zeroes the buffer on drop.
    envelope_key: OnceLock<Zeroizing<[u8; HMAC_LEN]>>,
}

impl<P: KmsProvider> KmsKey<P> {
    /// Construct a `KmsKey` using direct `GenerateMac` mode (v0.1 default).
    ///
    /// `key_id` is derived from `provider.key_descriptor()` via BLAKE3-256;
    /// it does not require a network call.
    pub fn new(provider: P) -> Result<Self, KmsError> {
        let key_id = derive_key_id(provider.key_descriptor(), provider.provider_name());
        Ok(Self {
            provider,
            key_id,
            mode: Mode::Generate,
            envelope_key: OnceLock::new(),
        })
    }

    /// Construct a `KmsKey` using envelope-encrypted local-HMAC mode (v0.2).
    ///
    /// The provider's [`KmsProvider::envelope_unwrap`] is called lazily on
    /// the first [`KeyHandle::sign`] invocation to obtain the raw HMAC DEK.
    /// The DEK is then cached in a [`zeroize::Zeroizing`] buffer for the
    /// lifetime of this `KmsKey` and zeroed on drop.
    ///
    /// ## Trade-offs vs. `GenerateMac` mode
    ///
    /// | Property | GenerateMac | Envelope |
    /// |----------|-------------|---------|
    /// | Key residency | HSM (never extracted) | Local (in-process) |
    /// | Per-call latency | ~1–5 ms (TLS RTT) | ~0 ms after first call |
    /// | KMS calls per sign | 1 | 1 (init only) |
    ///
    /// `key_id` is derived identically to `GenerateMac` mode — both use
    /// `BLAKE3-256("ogentic-audit-kms/v1\n" || provider_name || "\n" || descriptor)`.
    pub fn with_envelope_mode(provider: P) -> Result<Self, KmsError> {
        let key_id = derive_key_id(provider.key_descriptor(), provider.provider_name());
        Ok(Self {
            provider,
            key_id,
            mode: Mode::Envelope,
            envelope_key: OnceLock::new(),
        })
    }

    /// First 8 bytes of the `key_id` as lowercase hex, for use in
    /// `Display` / `Debug` impls.  Not sensitive (it's a one-way hash).
    pub(crate) fn key_id_hex_short(&self) -> String {
        let full = hex_lower(self.key_id.as_bytes());
        format!("{}…", &full[..16])
    }
}

impl<P: KmsProvider> KeyHandle for KmsKey<P> {
    /// Sign `data`.
    ///
    /// - **`Generate` mode** — delegates to `KmsProvider::sign`, which calls
    ///   KMS `GenerateMac` for every invocation.
    /// - **`Envelope` mode** — lazily initialises the DEK via
    ///   `KmsProvider::envelope_unwrap` on the first call (one KMS round-trip),
    ///   then computes HMAC-SHA256 locally for all subsequent calls.
    ///
    /// If any KMS call returns an error, this method **panics**.  See the
    /// module doc and `docs/integrations/server-side-kms.md` §"v0.1 panic
    /// posture" for the design rationale.
    ///
    /// ## Runtime compatibility (both modes)
    ///
    /// - **Multi-thread runtime** — `tokio::task::block_in_place`.
    /// - **Current-thread runtime** — `std::thread::scope` with a dedicated
    ///   `current_thread` runtime (no `unsafe` needed).
    /// - **No runtime** — fresh `current_thread` runtime for the duration.
    fn sign(&self, data: &[u8]) -> HmacBytes {
        match self.mode {
            Mode::Generate => self.sign_via_kms(data),
            Mode::Envelope => {
                let key = self.envelope_key.get_or_init(|| {
                    let raw = self.unwrap_envelope_key();
                    Zeroizing::new(raw)
                });
                local_hmac(key, data)
            },
        }
    }

    fn key_id(&self) -> KeyId {
        self.key_id
    }
}

impl<P: KmsProvider> KmsKey<P> {
    /// Blocking shim for `KmsProvider::sign` (GenerateMac mode).
    fn sign_via_kms(&self, data: &[u8]) -> HmacBytes {
        let result = self.block_on_async(self.provider.sign(data));
        result
            .unwrap_or_else(|e| panic!("kms: sign failed — KMS unavailable or misconfigured: {e}"))
    }

    /// Blocking shim for `KmsProvider::envelope_unwrap` (Envelope mode).
    fn unwrap_envelope_key(&self) -> [u8; HMAC_LEN] {
        let result = self.block_on_async(self.provider.envelope_unwrap());
        result.unwrap_or_else(|e| {
            panic!("kms: envelope_unwrap failed — KMS unavailable or misconfigured: {e}")
        })
    }

    /// Run an async future to completion using a blocking shim that is
    /// compatible with all tokio runtime flavours.
    ///
    /// This is the same shim used for both `sign_via_kms` and
    /// `unwrap_envelope_key`; extracted to avoid duplication.
    fn block_on_async<F, T>(&self, fut: F) -> T
    where
        F: std::future::Future<Output = T> + Send,
        T: Send,
    {
        use tokio::runtime::{Handle, RuntimeFlavor};

        match Handle::try_current() {
            Ok(handle) => match handle.runtime_flavor() {
                RuntimeFlavor::MultiThread => tokio::task::block_in_place(|| handle.block_on(fut)),
                _ => std::thread::scope(|s| {
                    s.spawn(|| {
                        tokio::runtime::Builder::new_current_thread()
                            .enable_all()
                            .build()
                            .expect("kms: failed to build scoped runtime")
                            .block_on(fut)
                    })
                    .join()
                    .expect("kms: scoped thread panicked")
                }),
            },
            Err(_) => tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("kms: failed to build current-thread runtime")
                .block_on(fut),
        }
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
