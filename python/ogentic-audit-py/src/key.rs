//! `KeyHandle` Python wrapper.
//!
//! Pythonic API:
//!
//! ```python
//! key = KeyHandle.from_bytes(b"\x00" * 32)
//! key = KeyHandle.from_hex("00" * 32)
//! key = KeyHandle.from_env("OGENTIC_AUDIT_KEY_HEX")
//! key = KeyHandle.from_keychain("ogentic-audit", "default")
//! ```

use std::env;
use std::sync::Arc;

use ogentic_audit_core::{InMemoryKey, KeyHandle};
use pyo3::prelude::*;

use crate::errors::{ArgumentError, IoFailure};

/// Python-facing wrapper over a boxed `KeyHandle`.
///
/// Internally we hold an `Arc<dyn KeyHandle>` so Python can pass the
/// same key into both Writer and Verifier without cloning the
/// underlying material.
#[pyclass(name = "KeyHandle", module = "ogentic_audit._native")]
pub struct PyKeyHandle {
    pub(crate) inner: Arc<dyn KeyHandle>,
}

#[pymethods]
impl PyKeyHandle {
    /// Build a KeyHandle from 32 raw bytes.
    #[staticmethod]
    fn from_bytes(bytes: &[u8]) -> PyResult<Self> {
        if bytes.len() != 32 {
            return Err(ArgumentError::new_err(format!(
                "KeyHandle.from_bytes requires 32 bytes; got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Ok(Self {
            inner: Arc::new(InMemoryKey::from_bytes(arr)),
        })
    }

    /// Build a KeyHandle from a 64-character hex string.
    #[staticmethod]
    fn from_hex(hex_str: &str) -> PyResult<Self> {
        let bytes = parse_hex_32(hex_str)
            .map_err(|e| ArgumentError::new_err(format!("KeyHandle.from_hex: {e}")))?;
        Ok(Self {
            inner: Arc::new(InMemoryKey::from_bytes(bytes)),
        })
    }

    /// Build a KeyHandle from an environment variable containing 64
    /// hex chars (default `OGENTIC_AUDIT_KEY_HEX`).
    #[staticmethod]
    #[pyo3(signature = (var_name = "OGENTIC_AUDIT_KEY_HEX"))]
    fn from_env(var_name: &str) -> PyResult<Self> {
        let raw = env::var(var_name).map_err(|_| {
            ArgumentError::new_err(format!(
                "env var {var_name} not set; either set it or pick a different KeyHandle source"
            ))
        })?;
        let bytes = parse_hex_32(&raw)
            .map_err(|e| ArgumentError::new_err(format!("env var {var_name}: {e}")))?;
        Ok(Self {
            inner: Arc::new(InMemoryKey::from_bytes(bytes)),
        })
    }

    /// Build a KeyHandle backed by the macOS Keychain (via
    /// `ogentic-audit-keychain`). On non-macOS platforms the
    /// underlying keyring backend behaves per the `keyring` crate's
    /// cross-platform abstraction.
    #[staticmethod]
    #[pyo3(signature = (service, account = "default"))]
    fn from_keychain(service: &str, account: &str) -> PyResult<Self> {
        use ogentic_audit_keychain::KeychainKey;
        let key = KeychainKey::load_or_generate(service, account).map_err(|e| {
            IoFailure::new_err(format!(
                "loading keychain entry service={service:?} account={account:?}: {e}"
            ))
        })?;
        Ok(Self {
            inner: Arc::new(key),
        })
    }

    /// Lowercase hex of the BLAKE3-256 key fingerprint.
    fn key_id_hex(&self) -> String {
        self.inner.key_id().to_hex()
    }

    fn __repr__(&self) -> String {
        format!("KeyHandle(key_id={})", self.inner.key_id().to_hex())
    }
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

/// Used by Writer/Verifier constructors to obtain a boxed clone of the
/// underlying KeyHandle. We construct a fresh `InMemoryKey` clone via
/// the `Arc<dyn KeyHandle>` so the new boxed handle is independent of
/// the Python-side handle's lifetime.
pub fn clone_boxed(handle: &PyKeyHandle) -> Box<dyn KeyHandle> {
    // KeyHandle doesn't have a clone-into-box method in the trait. We
    // do an arc-clone of the implementation and re-wrap. This works
    // because `Box<dyn KeyHandle>` only requires that the wrapped
    // value can sign + report a key_id; an Arc<dyn KeyHandle> is also
    // `KeyHandle` by trait-object coercion.
    Box::new(ArcKey(Arc::clone(&handle.inner)))
}

/// `KeyHandle` impl over an `Arc<dyn KeyHandle>` so Python can re-use
/// one PyKeyHandle across multiple Writer / Verifier calls.
struct ArcKey(Arc<dyn KeyHandle>);

impl std::fmt::Debug for ArcKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ArcKey({})", self.0.key_id().to_hex())
    }
}

impl KeyHandle for ArcKey {
    fn sign(&self, payload: &[u8]) -> ogentic_audit_core::HmacBytes {
        self.0.sign(payload)
    }
    fn key_id(&self) -> ogentic_audit_core::KeyId {
        self.0.key_id()
    }
}
