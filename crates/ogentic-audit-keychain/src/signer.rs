//! OS-keychain-backed Ed25519 [`Signer`] for signed logs (spec v0.2
//! §13.2).
//!
//! The keychain item holds `ed25519-seed:v1:` ‖ seed (32) ‖ public key
//! (32). The HMAC loader ([`crate::KeychainKey`]) requires exactly 32
//! bytes, so neither kind of key can be loaded as the other. On load the
//! public key is derived from the seed and compared with the stored copy;
//! a mismatch is an error, never a silent new key.
//!
//! Creation is create-only under an exclusive lock file, so two processes
//! can never overwrite a seed whose fingerprint may already be published.
//! The public key is also written to a non-secret file
//! (`<config>/ogentic-audit/keys/<service>/<account>.pub`) so showing the
//! fingerprint never unlocks the keychain. Signing always derives the key
//! from the seed.
//!
//! The seed is never exported in OpenSSH private-key format and never
//! loaded into `ssh-agent`.
//!
//! | Platform | Store | Guarantee | Not guaranteed |
//! |---|---|---|---|
//! | macOS | login keychain (file-based) | encrypted at rest under the user's login; not synced to iCloud Keychain | moves to a new Mac with Migration Assistant or a Time Machine restore |
//! | Windows | Credential Manager, persistence **local** | stays on this machine for this user | — |
//! | Linux | Secret Service | encrypted under the login keyring | absent on headless machines (the signer is then unavailable) |

use core::fmt;
use std::fs::{File, OpenOptions};
use std::io::Write as _;
use std::path::PathBuf;

use keyring::Entry;
use ogentic_audit_core::signed::{InMemorySigner, PublicKey, SignError, Signature, Signer};
use zeroize::Zeroizing;

/// Tag at the start of every signed-mode keychain item.
pub const ITEM_TAG: &[u8; 16] = b"ed25519-seed:v1:";
/// Length of a signed-mode keychain item.
pub const ITEM_LEN: usize = 16 + 32 + 32;

/// Errors from [`KeychainSigner`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SignerError {
    /// No item at `(service, account)`.
    #[error("no signing key in the keychain at service={service:?}, account={account:?}")]
    NotFound {
        /// Service.
        service: String,
        /// Account.
        account: String,
    },
    /// `create` found an existing item. It is never overwritten.
    #[error("a key already exists at service={service:?}, account={account:?}; it is never overwritten (its fingerprint may already be published)")]
    AlreadyExists {
        /// Service.
        service: String,
        /// Account.
        account: String,
    },
    /// The item is not a signed-mode seed, or its stored public key does
    /// not match the seed.
    #[error("the keychain item is not a valid ed25519 signing key: {0}")]
    Corrupt(String),
    /// Lock file or public-key file I/O.
    #[error("{0}")]
    Io(String),
    /// Keychain backend failure.
    #[error("OS keychain backend error: {0}")]
    Backend(#[from] keyring::Error),
}

/// Encode a keychain item.
#[must_use]
pub fn encode_item(seed: &[u8; 32], public: &PublicKey) -> Zeroizing<Vec<u8>> {
    let mut v = Zeroizing::new(Vec::with_capacity(ITEM_LEN));
    v.extend_from_slice(ITEM_TAG);
    v.extend_from_slice(seed);
    v.extend_from_slice(public.as_bytes());
    v
}

/// Decode a keychain item: check the tag and length, derive the public
/// key from the seed, and compare it with the stored copy.
pub fn decode_item(bytes: &[u8]) -> Result<InMemorySigner, SignerError> {
    if bytes.len() != ITEM_LEN || &bytes[..16] != ITEM_TAG {
        return Err(SignerError::Corrupt(
            "not an ed25519-seed:v1 item (an HMAC key, or another application's item?)".into(),
        ));
    }
    let mut seed = Zeroizing::new([0u8; 32]);
    seed.copy_from_slice(&bytes[16..48]);
    let signer = InMemorySigner::from_seed(*seed);
    if signer.public_key().as_bytes()[..] != bytes[48..] {
        return Err(SignerError::Corrupt(
            "the stored public key does not match the seed".into(),
        ));
    }
    Ok(signer)
}

/// The configuration directory: `$OGENTIC_AUDIT_CONFIG_DIR`, else the
/// platform's per-user configuration directory plus `ogentic-audit`.
#[must_use]
pub fn config_dir() -> PathBuf {
    if let Some(d) = std::env::var_os("OGENTIC_AUDIT_CONFIG_DIR") {
        return PathBuf::from(d);
    }
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let base = if cfg!(target_os = "macos") {
        home.map(|h| h.join("Library/Application Support"))
    } else if cfg!(windows) {
        std::env::var_os("APPDATA").map(PathBuf::from)
    } else {
        std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| home.map(|h| h.join(".config")))
    };
    base.unwrap_or_else(std::env::temp_dir)
        .join("ogentic-audit")
}

fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Where the non-secret public key file for `(service, account)` lives.
#[must_use]
pub fn public_key_path(service: &str, account: &str) -> PathBuf {
    config_dir()
        .join("keys")
        .join(sanitize(service))
        .join(format!("{}.pub", sanitize(account)))
}

fn entry(service: &str, account: &str) -> Result<Entry, SignerError> {
    #[cfg(windows)]
    {
        // The default (`enterprise`) persistence roams with the user
        // profile; a signing seed must stay on this machine. Creating a
        // v1 entry first initialises the platform store, as keyring does.
        let _ = Entry::new(service, account)?;
        let mods = std::collections::HashMap::from([("persistence", "local")]);
        let inner = keyring_core::Entry::new_with_modifiers(service, account, &mods)?;
        Ok(Entry { inner })
    }
    #[cfg(not(windows))]
    {
        Ok(Entry::new(service, account)?)
    }
}

struct Lock {
    file: File,
}

impl Lock {
    #[allow(clippy::incompatible_msrv)] // File::lock: Rust 1.89; the workspace MSRV is 1.91.
    fn acquire(service: &str, account: &str) -> Result<Self, SignerError> {
        let dir = config_dir().join("locks");
        std::fs::create_dir_all(&dir)
            .map_err(|e| SignerError::Io(format!("{}: {e}", dir.display())))?;
        let path = dir.join(format!("{}__{}.lock", sanitize(service), sanitize(account)));
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&path)
            .map_err(|e| SignerError::Io(format!("{}: {e}", path.display())))?;
        file.lock()
            .map_err(|e| SignerError::Io(format!("locking {}: {e}", path.display())))?;
        Ok(Self { file })
    }
}

impl Drop for Lock {
    #[allow(clippy::incompatible_msrv)]
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

/// An Ed25519 signing key held in the OS keychain.
pub struct KeychainSigner {
    inner: InMemorySigner,
    service: String,
    account: String,
}

impl fmt::Debug for KeychainSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeychainSigner")
            .field("service", &self.service)
            .field("account", &self.account)
            .field("public_key", self.inner.public_key())
            .finish_non_exhaustive()
    }
}

fn not_found(e: keyring::Error, service: &str, account: &str) -> SignerError {
    match e {
        keyring::Error::NoEntry => SignerError::NotFound {
            service: service.into(),
            account: account.into(),
        },
        other => SignerError::Backend(other),
    }
}

impl KeychainSigner {
    /// Load an existing key.
    pub fn load(service: &str, account: &str) -> Result<Self, SignerError> {
        let bytes = Zeroizing::new(
            entry(service, account)?
                .get_secret()
                .map_err(|e| not_found(e, service, account))?,
        );
        let inner = decode_item(&bytes)?;
        let s = Self {
            inner,
            service: service.into(),
            account: account.into(),
        };
        // Keep the display copy of the public key current; failure to
        // write it never blocks signing.
        let _ = s.write_public_key_file();
        Ok(s)
    }

    /// Create a fresh key. Fails with [`SignerError::AlreadyExists`] if
    /// one is present: a key is never overwritten.
    pub fn create(service: &str, account: &str) -> Result<Self, SignerError> {
        let _lock = Lock::acquire(service, account)?;
        Self::create_locked(service, account)
    }

    fn create_locked(service: &str, account: &str) -> Result<Self, SignerError> {
        match Self::load(service, account) {
            Ok(_) => {
                return Err(SignerError::AlreadyExists {
                    service: service.into(),
                    account: account.into(),
                })
            },
            Err(SignerError::NotFound { .. }) => {},
            Err(e) => return Err(e),
        }
        let fresh = InMemorySigner::generate();
        let item = encode_item(fresh.seed(), fresh.public_key());
        entry(service, account)?.set_secret(&item)?;
        // Read it back: the stored key must be the key we generated.
        let loaded = Self::load(service, account)?;
        if loaded.public_key() != fresh.public_key() {
            return Err(SignerError::Corrupt(
                "the key read back differs from the key written".into(),
            ));
        }
        Ok(loaded)
    }

    /// Load the key, or create it if absent (under the same lock).
    pub fn load_or_generate(service: &str, account: &str) -> Result<Self, SignerError> {
        let _lock = Lock::acquire(service, account)?;
        match Self::load(service, account) {
            Ok(s) => Ok(s),
            Err(SignerError::NotFound { .. }) => Self::create_locked(service, account),
            Err(e) => Err(e),
        }
    }

    /// Delete the key and its public-key file.
    pub fn delete(service: &str, account: &str) -> Result<(), SignerError> {
        let _lock = Lock::acquire(service, account)?;
        entry(service, account)?
            .delete_credential()
            .map_err(|e| not_found(e, service, account))?;
        let _ = std::fs::remove_file(public_key_path(service, account));
        Ok(())
    }

    /// The public key from the non-secret `.pub` file, without unlocking
    /// the keychain. For display only.
    pub fn read_public_key(service: &str, account: &str) -> Result<PublicKey, SignerError> {
        let p = public_key_path(service, account);
        let text = std::fs::read_to_string(&p)
            .map_err(|e| SignerError::Io(format!("{}: {e}", p.display())))?;
        PublicKey::parse(&text).map_err(|e| SignerError::Corrupt(e.to_string()))
    }

    fn write_public_key_file(&self) -> Result<(), SignerError> {
        let p = public_key_path(&self.service, &self.account);
        let io = |e: std::io::Error| SignerError::Io(format!("{}: {e}", p.display()));
        if let Some(d) = p.parent() {
            std::fs::create_dir_all(d).map_err(io)?;
        }
        let line = format!(
            "{}\n",
            self.inner
                .public_key()
                .to_openssh(&format!("{}:{}", self.service, self.account))
        );
        if std::fs::read_to_string(&p).ok().as_deref() == Some(line.as_str()) {
            return Ok(());
        }
        let tmp = p.with_extension("pub.tmp");
        let mut f = File::create(&tmp).map_err(io)?;
        f.write_all(line.as_bytes()).map_err(io)?;
        std::fs::rename(&tmp, &p).map_err(io)
    }

    /// Service.
    #[must_use]
    pub fn service(&self) -> &str {
        &self.service
    }

    /// Account.
    #[must_use]
    pub fn account(&self) -> &str {
        &self.account
    }

    /// Where the public key file is.
    #[must_use]
    pub fn public_key_file(&self) -> PathBuf {
        public_key_path(&self.service, &self.account)
    }
}

impl Signer for KeychainSigner {
    fn public_key(&self) -> &PublicKey {
        self.inner.public_key()
    }

    fn sign(&self, namespace: &str, message: &[u8]) -> Result<Signature, SignError> {
        self.inner.sign(namespace, message)
    }
}

/// Load a seed for tests and tooling from a hex file (64 hex digits). Not
/// a keychain path; provided so callers share one parser.
pub fn signer_from_hex_seed(text: &str) -> Result<InMemorySigner, SignerError> {
    let seed: [u8; 32] = ogentic_audit_core::signed::unhex(text.trim())
        .ok_or_else(|| SignerError::Corrupt("expected 64 hex digits".into()))?;
    Ok(InMemorySigner::from_seed(seed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn item_round_trip_and_rejections() {
        let s = InMemorySigner::from_seed([5u8; 32]);
        let item = encode_item(s.seed(), s.public_key());
        assert_eq!(item.len(), ITEM_LEN);
        assert_eq!(decode_item(&item).unwrap().public_key(), s.public_key());
        // An HMAC key (32 bytes) is not a signing key.
        assert!(decode_item(&[1u8; 32]).is_err());
        // A stored public key that does not match the seed.
        let mut bad = item.to_vec();
        bad[60] ^= 1;
        assert!(matches!(decode_item(&bad), Err(SignerError::Corrupt(_))));
        // The HMAC loader refuses a signing item (length).
        assert!(ogentic_audit_core::InMemoryKey::from_slice(&item).is_err());
    }
}

/// Real-store round trip, gated like the HMAC suite (`OGENTIC_KEYCHAIN_CI`).
#[cfg(test)]
fn integration_round_trip() {
    if std::env::var_os("OGENTIC_KEYCHAIN_CI").is_none() {
        eprintln!("skipping: OGENTIC_KEYCHAIN_CI not set");
        return;
    }
    let dir = std::env::temp_dir().join(format!("oa-cfg-{}", std::process::id()));
    std::env::set_var("OGENTIC_AUDIT_CONFIG_DIR", &dir);
    let service = "com.ogenticai.ogentic-audit.test";
    #[allow(clippy::disallowed_methods)]
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let account = format!("signer-{nanos}:ed25519");
    let a = KeychainSigner::create(service, &account).unwrap();
    assert!(matches!(
        KeychainSigner::create(service, &account),
        Err(SignerError::AlreadyExists { .. })
    ));
    let b = KeychainSigner::load_or_generate(service, &account).unwrap();
    assert_eq!(a.public_key(), b.public_key());
    assert_eq!(
        &KeychainSigner::read_public_key(service, &account).unwrap(),
        a.public_key()
    );
    let sig = ogentic_audit_core::signed::signer::sign_checked(&b, "ns", b"m");
    assert!(sig.is_ok());
    KeychainSigner::delete(service, &account).unwrap();
    assert!(matches!(
        KeychainSigner::load(service, &account),
        Err(SignerError::NotFound { .. })
    ));
}

#[cfg(all(test, target_os = "macos"))]
mod macos_integration_signer {
    #[test]
    fn signer_round_trip() {
        super::integration_round_trip();
    }
}

#[cfg(all(test, target_os = "linux"))]
mod linux_integration_signer {
    #[test]
    fn signer_round_trip() {
        super::integration_round_trip();
    }
}

#[cfg(all(test, target_os = "windows"))]
mod windows_integration_signer {
    #[test]
    fn signer_round_trip() {
        super::integration_round_trip();
    }
}
