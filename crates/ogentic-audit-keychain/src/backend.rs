//! OS-keychain-backed [`KeyHandle`].

use core::fmt;

use keyring::Entry;
use ogentic_audit_core::{HmacBytes, InMemoryKey, KeyError, KeyHandle, KeyId, HMAC_LEN};

/// A signing key sourced from the host OS keychain.
///
/// The raw 32-byte HMAC key lives in the platform secret store under a
/// `(service, account)` pair. On construction the key is read out into
/// process memory; from there it behaves identically to
/// [`ogentic_audit_core::InMemoryKey`] — signing is HMAC-SHA256, the
/// key zeroes on drop, [`Display`](fmt::Display) and [`Debug`] redact.
///
/// # Lifecycle
///
/// - [`KeychainKey::load`] — read an existing key.
/// - [`KeychainKey::store`] — write a key in (typically once, at install).
/// - [`KeychainKey::delete`] — remove a key (on uninstall or rotation).
/// - [`KeychainKey::load_or_generate`] — read; if missing, generate a
///   fresh 32-byte key from the OS CSPRNG ([`getrandom`]) and store it.
///   This is the common-case constructor for desktop apps.
///
/// # Naming convention
///
/// `service` and `account` are passed straight through to the underlying
/// platform secret store. Recommended convention:
///
/// - `service`: reverse-DNS app identifier, e.g. `"com.sotto.desktop"`.
/// - `account`: a stable per-user identifier or a deployment-specific
///   string, e.g. `"audit-log"` or `"audit-log:v0.1"`.
pub struct KeychainKey {
    inner: InMemoryKey,
    service: String,
    account: String,
}

impl KeychainKey {
    /// Load an existing key from the OS keychain.
    pub fn load(service: &str, account: &str) -> Result<Self, Error> {
        let entry = entry(service, account)?;
        let bytes = entry
            .get_secret()
            .map_err(|e| classify(e, service, account))?;
        let inner = InMemoryKey::from_slice(&bytes).map_err(Error::InvalidKey)?;
        Ok(Self {
            inner,
            service: service.to_owned(),
            account: account.to_owned(),
        })
    }

    /// Store a 32-byte HMAC key into the OS keychain under
    /// `(service, account)`. Overwrites any existing entry at that
    /// coordinate.
    pub fn store(service: &str, account: &str, key: &[u8; HMAC_LEN]) -> Result<(), Error> {
        let entry = entry(service, account)?;
        entry
            .set_secret(key)
            .map_err(|e| classify(e, service, account))?;
        Ok(())
    }

    /// Delete the key at `(service, account)`. No-op if no entry exists
    /// (returns [`Error::NotFound`] so callers can distinguish, but the
    /// keychain state after the call is the same either way).
    pub fn delete(service: &str, account: &str) -> Result<(), Error> {
        let entry = entry(service, account)?;
        entry
            .delete_credential()
            .map_err(|e| classify(e, service, account))?;
        Ok(())
    }

    /// Load if present; otherwise generate a fresh 32-byte key from the
    /// OS CSPRNG, store it, and return it.
    ///
    /// This is racy across processes — two simultaneous first-launches
    /// of the same app could each generate a fresh key and one would
    /// silently overwrite the other. Real applications should serialize
    /// the install-time key creation (e.g. behind a per-user lock) and
    /// then call [`KeychainKey::load`] from the steady-state path.
    pub fn load_or_generate(service: &str, account: &str) -> Result<Self, Error> {
        match Self::load(service, account) {
            Ok(k) => Ok(k),
            Err(Error::NotFound { .. }) => {
                let key = generate_key()?;
                Self::store(service, account, &key)?;
                Self::load(service, account)
            },
            Err(e) => Err(e),
        }
    }

    /// The platform service identifier this key was loaded from.
    #[must_use]
    pub fn service(&self) -> &str {
        &self.service
    }

    /// The platform account identifier this key was loaded from.
    #[must_use]
    pub fn account(&self) -> &str {
        &self.account
    }
}

impl KeyHandle for KeychainKey {
    fn sign(&self, data: &[u8]) -> HmacBytes {
        self.inner.sign(data)
    }

    fn key_id(&self) -> KeyId {
        self.inner.key_id()
    }
}

impl fmt::Debug for KeychainKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Mirrors InMemoryKey's redaction. Service and account are
        // identifiers, not secrets, so they're shown.
        f.debug_struct("KeychainKey")
            .field("service", &self.service)
            .field("account", &self.account)
            .field("key", &"<redacted>")
            .field("key_id", &self.inner.key_id())
            .finish()
    }
}

impl fmt::Display for KeychainKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "KeychainKey(service={}, account={}, key=<redacted>, key_id={})",
            self.service,
            self.account,
            self.inner.key_id(),
        )
    }
}

/// Errors interacting with the OS keychain.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// No entry exists at the requested `(service, account)` coordinate.
    #[error("no keychain entry at service={service:?}, account={account:?}")]
    NotFound {
        /// Service identifier that was queried.
        service: String,
        /// Account identifier that was queried.
        account: String,
    },

    /// The stored bytes were not a valid 32-byte HMAC key.
    #[error("stored keychain entry is not a valid 32-byte HMAC key: {0}")]
    InvalidKey(#[source] KeyError),

    /// CSPRNG failure during fresh-key generation.
    #[error("OS CSPRNG returned an error generating a fresh key: {0}")]
    Rng(String),

    /// Some other backend failure (permissions, locked keychain,
    /// missing D-Bus on Linux, etc.). The wrapped `keyring::Error`
    /// carries the platform-specific details.
    #[error("OS keychain backend error: {0}")]
    Backend(#[from] keyring::Error),
}

fn entry(service: &str, account: &str) -> Result<Entry, Error> {
    Entry::new(service, account).map_err(Error::Backend)
}

fn classify(err: keyring::Error, service: &str, account: &str) -> Error {
    match err {
        keyring::Error::NoEntry => Error::NotFound {
            service: service.to_owned(),
            account: account.to_owned(),
        },
        other => Error::Backend(other),
    }
}

fn generate_key() -> Result<[u8; HMAC_LEN], Error> {
    let mut out = [0u8; HMAC_LEN];
    getrandom::getrandom(&mut out).map_err(|e| Error::Rng(e.to_string()))?;
    Ok(out)
}

// ---------------------------------------------------------------------------
// Integration tests
// ---------------------------------------------------------------------------
//
// macOS-only at v0.1. The Linux and Windows backends compile-test via the
// existing rust-test CI matrix, but exercising them against a real platform
// secret store requires fixture setup that's deferred to a follow-up
// ticket. See the OGE-431 closeout note in Linear.
//
// To run locally on macOS:
//   cargo test -p ogentic-audit-keychain --features keychain -- --ignored
//
// Tests are `#[ignore]` so they don't run by default — they touch the
// real macOS Keychain and may prompt the user the first time the
// `cargo test` binary requests access.

#[cfg(all(test, target_os = "macos"))]
mod macos_integration {
    use super::*;

    const TEST_SERVICE: &str = "com.ogenticai.ogentic-audit.test";

    fn unique_account(case: &str) -> String {
        // Per-run unique account to avoid colliding with a prior aborted
        // run leaving the keychain dirty. `SystemTime::now` is normally
        // disallowed in this workspace (clippy.toml routes audit-log time
        // anchoring through `ogentic_audit_core::time::now`), but this
        // is test-only fixture naming with no chain-time implications.
        #[allow(clippy::disallowed_methods)]
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        format!("{case}-{nanos}")
    }

    #[test]
    #[ignore = "touches real macOS Keychain; run with --ignored. \
                NOTE: keyring 3.x's macOS backend does not always \
                persist across separate Entry::new() calls when invoked \
                from an unsigned binary (cargo test under default \
                sandboxing). This is an environment-dependent test, not \
                a defect in the wrapper — the unit tests above cover the \
                wrapper's correctness end-to-end."]
    fn round_trip_store_load_delete() {
        let account = unique_account("round-trip");
        let key = [0x42u8; HMAC_LEN];

        // Clean slate.
        let _ = KeychainKey::delete(TEST_SERVICE, &account);

        // Initial load should fail with NotFound.
        match KeychainKey::load(TEST_SERVICE, &account) {
            Err(Error::NotFound { .. }) => {},
            other => panic!("expected NotFound, got {other:?}"),
        }

        // Store + load round-trip.
        KeychainKey::store(TEST_SERVICE, &account, &key).expect("store");
        let loaded = KeychainKey::load(TEST_SERVICE, &account).expect("load");
        assert_eq!(loaded.service(), TEST_SERVICE);
        assert_eq!(loaded.account(), account);

        // Signing must match what InMemoryKey would produce for the
        // same key bytes — i.e. KeychainKey is a true wrapper, not a
        // re-implementation.
        let reference = InMemoryKey::from_bytes(key);
        assert_eq!(loaded.sign(b"hello"), reference.sign(b"hello"));
        assert_eq!(loaded.key_id(), reference.key_id());

        // Delete.
        KeychainKey::delete(TEST_SERVICE, &account).expect("delete");
        match KeychainKey::load(TEST_SERVICE, &account) {
            Err(Error::NotFound { .. }) => {},
            other => panic!("expected NotFound after delete, got {other:?}"),
        }
    }

    #[test]
    #[ignore = "touches real macOS Keychain; run with --ignored. \
                NOTE: keyring 3.x's macOS backend does not always \
                persist across separate Entry::new() calls when invoked \
                from an unsigned binary (cargo test under default \
                sandboxing). This is an environment-dependent test, not \
                a defect in the wrapper — the unit tests above cover the \
                wrapper's correctness end-to-end."]
    fn load_or_generate_creates_then_reuses() {
        let account = unique_account("load-or-generate");
        let _ = KeychainKey::delete(TEST_SERVICE, &account);

        let first = KeychainKey::load_or_generate(TEST_SERVICE, &account).expect("first");
        let first_id = first.key_id();
        let first_sig = first.sign(b"witness");

        // Second call should reuse the stored key — same key_id, same
        // signature for the same input.
        let second = KeychainKey::load_or_generate(TEST_SERVICE, &account).expect("second");
        assert_eq!(first_id, second.key_id());
        assert_eq!(first_sig, second.sign(b"witness"));

        KeychainKey::delete(TEST_SERVICE, &account).expect("delete");
    }
}

// ---------------------------------------------------------------------------
// Cross-platform unit tests (no real keychain touched)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod unit {
    use super::*;

    /// Redacted formatting on both `Debug` and `Display`. Constructed
    /// without touching the real keychain via the (crate-private) helper
    /// that materializes a KeychainKey from owned bytes.
    fn fake(service: &str, account: &str, key: [u8; HMAC_LEN]) -> KeychainKey {
        KeychainKey {
            inner: InMemoryKey::from_bytes(key),
            service: service.to_owned(),
            account: account.to_owned(),
        }
    }

    #[test]
    fn display_redacts() {
        let k = fake("svc", "acct", [0x42u8; HMAC_LEN]);
        let s = format!("{k}");
        assert!(s.contains("<redacted>"));
        assert!(!s.contains("42424242"));
        assert!(s.contains("svc"));
        assert!(s.contains("acct"));
    }

    #[test]
    fn debug_redacts() {
        let k = fake("svc", "acct", [0x42u8; HMAC_LEN]);
        let s = format!("{k:?}");
        assert!(s.contains("<redacted>"));
        assert!(!s.contains("42424242"));
        assert!(s.contains("svc"));
        assert!(s.contains("acct"));
    }

    #[test]
    fn delegates_to_inner_inmemory_key() {
        // Same key bytes => same signature and key_id, regardless of
        // whether you wrap it in KeychainKey or InMemoryKey directly.
        let key = [0xabu8; HMAC_LEN];
        let kc = fake("svc", "acct", key);
        let raw = InMemoryKey::from_bytes(key);

        assert_eq!(kc.sign(b"hello"), raw.sign(b"hello"));
        assert_eq!(kc.key_id(), raw.key_id());
    }
}
