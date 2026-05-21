//! Wire the `--key-source` flag to the actual key material.
//!
//! Three sources: macOS Keychain (via `ogentic-audit-keychain`),
//! filesystem (32 raw bytes or 64 hex chars), or environment variable
//! (64 hex chars).

use std::fs;
use std::path::Path;

use anyhow::{anyhow, Context};
use ogentic_audit_core::{InMemoryKey, KeyHandle};

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

fn box_inmemory(bytes: [u8; 32]) -> Box<dyn KeyHandle> {
    Box::new(InMemoryKey::from_bytes(bytes))
}

fn load_env(var: &str) -> Result<[u8; 32], KeyError> {
    let raw = std::env::var(var).map_err(|_| {
        KeyError::Config(format!(
            "env var {var} not set; either set it or pick another --key-source"
        ))
    })?;
    parse_hex_32(&raw).map_err(|e| KeyError::Config(format!("env var {var}: {e}")))
}

fn load_file(path: &Path) -> Result<[u8; 32], KeyError> {
    let bytes = fs::read(path).map_err(KeyError::Io)?;
    // Accept either 32 raw bytes or 64 hex chars (with optional
    // trailing newline / whitespace).
    if bytes.len() == 32 {
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        return Ok(out);
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

fn load_keychain(service: &str, account: &str) -> Result<Box<dyn KeyHandle>, KeyError> {
    // Wrap into a Box<dyn KeyHandle>. `KeychainKey::load_or_generate`
    // returns a `KeychainKey` which implements `KeyHandle`.
    use ogentic_audit_keychain::KeychainKey;
    let key = KeychainKey::load_or_generate(service, account)
        .with_context(|| format!("loading keychain entry {service:?}/{account:?}"))
        .map_err(KeyError::Keychain)?;
    Ok(Box::new(key))
}

fn parse_hex_32(s: &str) -> Result<[u8; 32], String> {
    let s = s.trim();
    if s.len() != 64 {
        return Err(format!("expected 64 hex chars (32 bytes); got {}", s.len()));
    }
    let mut out = [0u8; 32];
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
