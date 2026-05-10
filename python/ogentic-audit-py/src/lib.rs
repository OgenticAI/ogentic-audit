//! PyO3 bindings for `ogentic-audit-core`.
//!
//! Exposed as the `ogentic_audit._native` module. The Python-facing API lives
//! in `python/ogentic_audit/__init__.py`; this crate's job is to surface the
//! Rust core to that wrapper.

use pyo3::prelude::*;

/// Format version implemented by the bound core crate.
#[pyfunction]
fn format_version() -> u16 {
    ogentic_audit_core::FORMAT_VERSION
}

/// Crate version of the bound core crate.
#[pyfunction]
fn core_version() -> &'static str {
    ogentic_audit_core::VERSION
}

#[pymodule]
fn _native(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(format_version, m)?)?;
    m.add_function(wrap_pyfunction!(core_version, m)?)?;
    Ok(())
}
