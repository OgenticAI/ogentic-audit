//! OS-keychain-backed [`KeyHandle`].

use core::fmt;

use keyring::Entry;
use ogentic_audit_core::{HmacBytes, InMemoryKey, KeyError, KeyHandle, KeyId, HMAC_LEN};
use zeroize::Zeroizing;

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
        // OGE-836: `keyring::Entry::get_secret` returns a bare
        // `Vec<u8>`. Wrap it in `Zeroizing` so the intermediate copy is
        // wiped on drop — `InMemoryKey` already zeroizes its own copy,
        // but the platform-backend allocation must not be left behind
        // in the heap free-list.
        let bytes = Zeroizing::new(
            entry
                .get_secret()
                .map_err(|e| classify(e, service, account))?,
        );
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
                // OGE-836: wrap the freshly-generated key in `Zeroizing`
                // so the local copy is wiped after it's been stored to
                // the platform keychain; the subsequent `Self::load`
                // reads its own zeroizing copy back.
                let key = Zeroizing::new(generate_key()?);
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
// Integration tests — real platform secret stores (OGE-478)
// ---------------------------------------------------------------------------
//
// These exercise `store` / `load` / `load_or_generate` / `delete` against the
// actual OS secret store on macOS (Keychain), Linux (Secret Service), and
// Windows (Credential Manager) — not just compilation on those platforms.
//
// ## Why they are gated on an environment variable, not run by default
//
// A real keychain round-trip needs a provisioned, unlocked, throwaway store.
// In CI each `keychain-integration-*` job sets that up on an ephemeral runner
// and exports `OGENTIC_KEYCHAIN_CI=1`. On a developer laptop we must NOT touch
// the real login keychain (it would prompt, pollute, or — on macOS — require
// mutating the user's *default* keychain, which is session-global). So when
// `OGENTIC_KEYCHAIN_CI` is unset, every integration test skips with a message.
//
// This replaces the previous `#[ignore]`-based gating (OGE-478). `#[ignore]`
// alone could not express "run in CI, skip on laptops" — an `--ignored` run on
// a laptop would still hit the developer's Keychain.
//
// ## Why keyring 4 (OGE-478)
//
// The `keyring` 3.x macOS backend could not round-trip on this path from an
// unsigned `cargo test` binary: `set_secret` returned `Ok`, but the immediate
// `get_secret` returned `NoEntry`. The `security` CLI round-tripped fine
// against the same keychain, so the OS was healthy — the fault was in keyring
// 3.x. keyring 4's redesigned Apple backend fixes it. This is why real macOS
// keychain integration testing was impossible before this ticket.
//
// ## macOS keychain selection (why CI provisions an ephemeral default)
//
// keyring reads the user's login keychain (its `default_for_domain(User)`), not
// an arbitrary path, and there is no public API to point an `Entry` at a
// specific keychain file. So CI cannot hand the test a private keychain
// in-process; the macOS job instead creates an ephemeral keychain, makes it the
// *sole* entry in the user search list, and promotes it to the user default.
// Both steps matter: with the login keychain also in the search list, keyring 4
// lookups became ambiguous and a pre-store `load` stopped returning `NotFound`.
// The production code path (through `keyring`) is unchanged; only the ambient
// store differs, and only on the ephemeral runner.
//
// ## Concurrency
//
// The suite runs `--test-threads=1`. The tests share one real OS store, and the
// platform Security frameworks are not reliable under concurrent add/find/delete
// against the same store — parallel execution produced spurious lookup failures.
//
// ## Fail-loud semantics
//
// When `OGENTIC_KEYCHAIN_CI` IS set (CI), the tests do NOT skip on a missing or
// broken store — they run and fail. That is deliberate: a CI job whose secret
// store failed to come up must go red, not silently pass by skipping.

#[cfg(test)]
mod test_support {
    use super::*;

    /// The integration suite runs only when the environment opts in. CI
    /// sets this after provisioning + unlocking a throwaway secret store;
    /// a developer laptop leaves it unset so `cargo test` never touches
    /// the real login keychain.
    pub(super) const CI_ENV: &str = "OGENTIC_KEYCHAIN_CI";

    /// Service namespace for every integration entry. Distinct from any
    /// real application service so a stray entry is obviously test debris.
    pub(super) const TEST_SERVICE: &str = "com.ogenticai.ogentic-audit.test";

    /// `true` when the integration suite should actually touch the store.
    pub(super) fn integration_enabled() -> bool {
        std::env::var_os(CI_ENV).is_some()
    }

    /// Per-run unique account so a prior aborted run leaving debris cannot
    /// collide with this one.
    ///
    /// `SystemTime::now` is disallowed workspace-wide (clippy.toml routes
    /// audit-log time anchoring through `ogentic_audit_core::time::now`),
    /// but this is test-only fixture naming with no chain-time meaning.
    pub(super) fn unique_account(case: &str) -> String {
        #[allow(clippy::disallowed_methods)]
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        format!("{case}-{nanos}")
    }

    /// Best-effort deletion of a test entry, run from `Drop` so a panic
    /// mid-test still removes the entry from the real OS store rather than
    /// leaving it behind. A test holds one guard per entry it creates.
    ///
    /// Failures are logged, never panicked: a `Drop` that panicked during
    /// unwinding would abort the process and mask the original failure.
    pub(super) struct CleanupGuard {
        pub(super) service: &'static str,
        pub(super) account: String,
    }

    impl Drop for CleanupGuard {
        fn drop(&mut self) {
            match KeychainKey::delete(self.service, &self.account) {
                Ok(()) | Err(Error::NotFound { .. }) => {},
                Err(e) => eprintln!(
                    "[test_support] CleanupGuard failed to delete \
                     service={} account={}: {e:?}",
                    self.service, self.account
                ),
            }
        }
    }

    /// Mechanism test — no real keychain touched. Proves the property the
    /// integration suites rely on: a `Drop` guard still runs when the test
    /// body panics and is caught. If this ever regressed, a panicking
    /// integration test would leak entries into the real store.
    #[test]
    fn drop_guard_runs_on_panic() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        struct Probe(Arc<AtomicBool>);
        impl Drop for Probe {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let dropped = Arc::new(AtomicBool::new(false));
        let flag = dropped.clone();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _probe = Probe(flag);
            panic!("forced panic mid-test");
        }));

        assert!(result.is_err(), "the closure must have panicked");
        assert!(
            dropped.load(Ordering::SeqCst),
            "Drop must run during unwind — CleanupGuard depends on this"
        );
    }
}

/// Body shared by every platform's integration suite. Keeping it in one
/// place means macOS / Linux / Windows exercise byte-identical assertions;
/// each platform module is a thin `#[cfg]`-gated caller.
#[cfg(test)]
mod integration_shared {
    use super::test_support::{integration_enabled, unique_account, CleanupGuard, TEST_SERVICE};
    use super::*;

    /// `store` then `load` returns a key that signs and fingerprints
    /// identically to an `InMemoryKey` built from the same bytes — i.e.
    /// `KeychainKey` is a faithful wrapper, verified without ever exposing
    /// the raw key bytes through any (even test-only) accessor.
    pub(super) fn store_and_load_round_trips() {
        if !integration_enabled() {
            eprintln!(
                "[keychain-it] OGENTIC_KEYCHAIN_CI unset; skipping store_and_load_round_trips"
            );
            return;
        }
        let account = unique_account("store-and-load");
        let _guard = CleanupGuard {
            service: TEST_SERVICE,
            account: account.clone(),
        };

        // A fresh account must not already exist.
        match KeychainKey::load(TEST_SERVICE, &account) {
            Err(Error::NotFound { .. }) => {},
            other => panic!("expected NotFound before store, got {other:?}"),
        }

        let key = [0x42u8; HMAC_LEN];
        KeychainKey::store(TEST_SERVICE, &account, &key).expect("store");

        let loaded = KeychainKey::load(TEST_SERVICE, &account).expect("load");
        assert_eq!(loaded.service(), TEST_SERVICE);
        assert_eq!(loaded.account(), account);

        let reference = InMemoryKey::from_bytes(key);
        assert_eq!(loaded.sign(b"hello"), reference.sign(b"hello"));
        assert_eq!(loaded.key_id(), reference.key_id());
    }

    /// `delete` removes the entry; a subsequent `load` is `NotFound`.
    pub(super) fn delete_then_load_is_not_found() {
        if !integration_enabled() {
            eprintln!(
                "[keychain-it] OGENTIC_KEYCHAIN_CI unset; skipping delete_then_load_is_not_found"
            );
            return;
        }
        let account = unique_account("delete-then-load");
        let _guard = CleanupGuard {
            service: TEST_SERVICE,
            account: account.clone(),
        };

        KeychainKey::store(TEST_SERVICE, &account, &[0x11u8; HMAC_LEN]).expect("store");
        KeychainKey::delete(TEST_SERVICE, &account).expect("delete");

        match KeychainKey::load(TEST_SERVICE, &account) {
            Err(Error::NotFound { .. }) => {},
            other => panic!("expected NotFound after delete, got {other:?}"),
        }
    }

    /// `load_or_generate` creates on first call and reuses on the second —
    /// same `key_id`, same signature for the same input.
    pub(super) fn load_or_generate_creates_then_reuses() {
        if !integration_enabled() {
            eprintln!("[keychain-it] OGENTIC_KEYCHAIN_CI unset; skipping load_or_generate_creates_then_reuses");
            return;
        }
        let account = unique_account("load-or-generate");
        let _guard = CleanupGuard {
            service: TEST_SERVICE,
            account: account.clone(),
        };

        let first = KeychainKey::load_or_generate(TEST_SERVICE, &account).expect("first");
        let first_id = first.key_id();
        let first_sig = first.sign(b"witness");

        let second = KeychainKey::load_or_generate(TEST_SERVICE, &account).expect("second");
        assert_eq!(
            first_id,
            second.key_id(),
            "second call must reuse the stored key"
        );
        assert_eq!(first_sig, second.sign(b"witness"));
    }

    /// A `CleanupGuard` deletes its entry from the *real* store even when
    /// the test body panics — the property the whole suite's hygiene rests
    /// on, verified end-to-end against the provisioned store (not a mock).
    pub(super) fn cleanup_guard_removes_entry_on_panic() {
        if !integration_enabled() {
            eprintln!("[keychain-it] OGENTIC_KEYCHAIN_CI unset; skipping cleanup_guard_removes_entry_on_panic");
            return;
        }
        let account = unique_account("panic-cleanup");

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = CleanupGuard {
                service: TEST_SERVICE,
                account: account.clone(),
            };
            KeychainKey::store(TEST_SERVICE, &account, &[0u8; HMAC_LEN]).expect("store");
            panic!("forced panic after store");
        }));
        assert!(result.is_err(), "closure must have panicked");

        // The guard dropped during unwind and deleted the entry.
        match KeychainKey::load(TEST_SERVICE, &account) {
            Err(Error::NotFound { .. }) => {},
            other => {
                // Belt-and-braces: clean up before failing the assertion.
                let _ = KeychainKey::delete(TEST_SERVICE, &account);
                panic!("guard did not remove entry on panic; load returned {other:?}");
            },
        }
    }
}

// Each platform module is a thin, `#[cfg]`-gated set of callers into
// `integration_shared`, so the three platforms run identical assertions and
// `cargo test --tests <platform>_integration` selects the right one in CI.

#[cfg(all(test, target_os = "macos"))]
mod macos_integration {
    use super::integration_shared as shared;

    #[test]
    fn store_and_load_round_trips() {
        shared::store_and_load_round_trips();
    }
    #[test]
    fn delete_then_load_is_not_found() {
        shared::delete_then_load_is_not_found();
    }
    #[test]
    fn load_or_generate_creates_then_reuses() {
        shared::load_or_generate_creates_then_reuses();
    }
    #[test]
    fn cleanup_guard_removes_entry_on_panic() {
        shared::cleanup_guard_removes_entry_on_panic();
    }
}

#[cfg(all(test, target_os = "linux"))]
mod linux_integration {
    use super::integration_shared as shared;

    #[test]
    fn store_and_load_round_trips() {
        shared::store_and_load_round_trips();
    }
    #[test]
    fn delete_then_load_is_not_found() {
        shared::delete_then_load_is_not_found();
    }
    #[test]
    fn load_or_generate_creates_then_reuses() {
        shared::load_or_generate_creates_then_reuses();
    }
    #[test]
    fn cleanup_guard_removes_entry_on_panic() {
        shared::cleanup_guard_removes_entry_on_panic();
    }
}

#[cfg(all(test, target_os = "windows"))]
mod windows_integration {
    use super::integration_shared as shared;

    #[test]
    fn store_and_load_round_trips() {
        shared::store_and_load_round_trips();
    }
    #[test]
    fn delete_then_load_is_not_found() {
        shared::delete_then_load_is_not_found();
    }
    #[test]
    fn load_or_generate_creates_then_reuses() {
        shared::load_or_generate_creates_then_reuses();
    }
    #[test]
    fn cleanup_guard_removes_entry_on_panic() {
        shared::cleanup_guard_removes_entry_on_panic();
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
