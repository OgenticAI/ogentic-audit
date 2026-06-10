//! Wire the `--key-source` flag to the actual key material.
//!
//! Three sources: macOS Keychain (via `ogentic-audit-keychain`),
//! filesystem (32 raw bytes or 64 hex chars), or environment variable
//! (64 hex chars).
//!
//! Two security properties are upheld here, both filed by the security
//! reviewer against the v0.1 publish:
//!
//! * **File-source permissions (OGE-835).** On Unix, `load_file` refuses
//!   to read a key file whose mode bits are wider than `0600` — matches
//!   how `ssh` rejects loose private keys. On Windows the check is a
//!   no-op (NTFS ACLs don't map to Unix mode bits); document the gap.
//!
//! * **Transient-key zeroing (OGE-836).** Every intermediate copy of key
//!   material (env-var string, file bytes, hex-decoded array) lives in a
//!   `zeroize::Zeroizing` wrapper so it's wiped from memory when this
//!   function returns. The final 32 bytes are then moved into
//!   `InMemoryKey`, which itself zeroes on drop.

use std::fs;
use std::path::Path;

use anyhow::{anyhow, Context};
use ogentic_audit_core::{InMemoryKey, KeyHandle};
use zeroize::Zeroizing;

use crate::cli::{GlobalArgs, KeySource};
use crate::exit::ExitCodeKind;

/// Resolve the key handle from the global args. Returns an `AppError`
/// shaped for CLI exit-code mapping.
pub fn load_key(global: &GlobalArgs) -> Result<Box<dyn KeyHandle>, KeyError> {
    match global.key_source {
        KeySource::Env => load_env(&global.key_env).map(box_inmemory),
        KeySource::File => {
            let path = global.key_file.as_deref().ok_or_else(|| {
                KeyError::Config("--key-source=file requires --key-file <PATH>".into())
            })?;
            load_file(path).map(box_inmemory)
        },
        KeySource::Keychain => load_keychain(&global.keychain_service, &global.keychain_account),
    }
}

fn box_inmemory(bytes: Zeroizing<[u8; 32]>) -> Box<dyn KeyHandle> {
    // `InMemoryKey::from_bytes` takes the array by value and stores it
    // inside a `ZeroizeOnDrop` field; the `Zeroizing` wrapper around our
    // intermediate copy is dropped here and wipes its own contents
    // immediately after the move.
    let bytes = *bytes;
    Box::new(InMemoryKey::from_bytes(bytes))
}

fn load_env(var: &str) -> Result<Zeroizing<[u8; 32]>, KeyError> {
    // `std::env::var` returns an owned `String`; wrap it in `Zeroizing`
    // so the 64 hex chars are wiped when the loader returns.
    let raw = Zeroizing::new(std::env::var(var).map_err(|_| {
        KeyError::Config(format!(
            "env var {var} not set; either set it or pick another --key-source"
        ))
    })?);
    parse_hex_32(raw.as_str()).map_err(|e| KeyError::Config(format!("env var {var}: {e}")))
}

fn load_file(path: &Path) -> Result<Zeroizing<[u8; 32]>, KeyError> {
    // OGE-835: refuse to read a key file with permissions wider than
    // 0600. Matches `ssh`'s behavior on loose private keys. Without this
    // check, a user running with the default `umask 022` would silently
    // get a world-readable key file accepted, exposing audit-log
    // integrity to any other local user on a shared host.
    check_key_file_permissions(path)?;

    // OGE-836: `Vec<u8>` from `fs::read` holds the raw key (or 64 hex
    // chars). Wrap in `Zeroizing` so the intermediate buffer is wiped
    // when the loader returns, regardless of which path through this
    // function we take.
    let bytes = Zeroizing::new(fs::read(path).map_err(KeyError::Io)?);
    // Accept either 32 raw bytes or 64 hex chars (with optional
    // trailing newline / whitespace).
    if bytes.len() == 32 {
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        return Ok(Zeroizing::new(out));
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| {
        KeyError::Config(format!(
            "key file {} is neither 32 raw bytes nor UTF-8 hex",
            path.display()
        ))
    })?;
    parse_hex_32(text.trim())
        .map_err(|e| KeyError::Config(format!("key file {}: {e}", path.display())))
}

/// On Unix, refuse to read `path` if its mode bits include any group/
/// other-readable bit (i.e. wider than `0600`). On non-Unix the check is
/// a no-op — NTFS ACLs do not map to Unix mode bits and modelling them
/// here would be a security theater. This is the same posture `ssh`
/// takes on Windows.
#[cfg_attr(not(unix), allow(clippy::needless_pass_by_value))]
fn check_key_file_permissions(path: &Path) -> Result<(), KeyError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let mode = fs::metadata(path).map_err(KeyError::Io)?.mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(KeyError::Config(format!(
                "key file {} has insecure permissions {:#o}; expected 0600 \
                 (run `chmod 600 {}` and retry) — refusing to read",
                path.display(),
                mode,
                path.display(),
            )));
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path; // unused on non-Unix; ACL-based check is a future task.
    }
    Ok(())
}

fn load_keychain(service: &str, account: &str) -> Result<Box<dyn KeyHandle>, KeyError> {
    // Wrap into a Box<dyn KeyHandle>. `KeychainKey::load_or_generate`
    // returns a `KeychainKey` which implements `KeyHandle`. The platform
    // keychain backend's transient `Vec<u8>` zeroing is addressed
    // separately in `ogentic-audit-keychain::backend::KeychainKey::load`.
    use ogentic_audit_keychain::KeychainKey;
    let key = KeychainKey::load_or_generate(service, account)
        .with_context(|| format!("loading keychain entry {service:?}/{account:?}"))
        .map_err(KeyError::Keychain)?;
    Ok(Box::new(key))
}

/// Hex-decode a 64-char string into a zeroizing 32-byte key buffer.
///
/// Returning `Zeroizing<[u8; 32]>` (instead of a bare `[u8; 32]`) means
/// the temporary buffer this function builds is wiped from the stack on
/// drop, including in the error path where the caller never moves it
/// into `InMemoryKey`. See OGE-836.
fn parse_hex_32(s: &str) -> Result<Zeroizing<[u8; 32]>, String> {
    let s = s.trim();
    if s.len() != 64 {
        return Err(format!("expected 64 hex chars (32 bytes); got {}", s.len()));
    }
    let mut out = Zeroizing::new([0u8; 32]);
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
            .map_err(|e| format!("bad hex at byte {i}: {e}"))?;
    }
    Ok(out)
}

/// Discriminated key-loading failure.
#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    /// I/O failure reading a key file.
    #[error("I/O error loading key: {0}")]
    Io(#[from] std::io::Error),
    /// Configuration / argument problem.
    #[error("{0}")]
    Config(String),
    /// Keychain backend failure.
    #[error("keychain: {0}")]
    Keychain(anyhow::Error),
}

impl KeyError {
    /// CLI exit code shape for this error.
    pub fn exit_code(&self) -> ExitCodeKind {
        match self {
            KeyError::Io(_) => ExitCodeKind::IoError,
            KeyError::Config(_) => ExitCodeKind::ArgumentError,
            KeyError::Keychain(_) => ExitCodeKind::IoError,
        }
    }
}

impl From<KeyError> for AppError {
    fn from(err: KeyError) -> Self {
        AppError {
            exit: err.exit_code(),
            source: anyhow!("{err}"),
        }
    }
}

/// Top-level app error used by every command. Carries the intended
/// exit code so `main` doesn't have to introspect the inner cause.
#[derive(Debug, thiserror::Error)]
#[error("{source}")]
pub struct AppError {
    /// Discriminated exit-code outcome.
    pub exit: ExitCodeKind,
    /// Underlying error.
    #[source]
    pub source: anyhow::Error,
}

impl AppError {
    /// Construct an I/O-error variant.
    pub fn io(source: impl Into<anyhow::Error>) -> Self {
        Self {
            exit: ExitCodeKind::IoError,
            source: source.into(),
        }
    }

    /// The exit code the binary should return for this error.
    pub fn exit_code(&self) -> ExitCodeKind {
        self.exit
    }
}
