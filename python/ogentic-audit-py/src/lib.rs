//! PyO3 bindings for `ogentic-audit-core`.
//!
//! Exposed as the `ogentic_audit._native` module. The Python-facing
//! surface (`from ogentic_audit import Writer, Reader, verify,
//! KeyHandle`) lives in `python/ogentic_audit/__init__.py`, which
//! re-exports the bindings here with idiomatic Python aliases.
//!
//! Design choices documented for OGE-433 reviewers:
//!
//! * **Records exposed as dict-like.** The chosen alternative was
//!   per-event dataclasses; we picked dicts because audit logs cross
//!   trust boundaries with arbitrary event shapes, and a typed
//!   surface would require generating dataclasses for every event
//!   tag — an open-ended problem the format spec doesn't solve.
//!   Type stubs in `__init__.pyi` document the dict shape.
//!
//! * **Errors map to a Python exception hierarchy** rooted at
//!   `OgenticAuditError`. Subclasses cover every `ViolationKind` so
//!   callers can `except HmacMismatchError:` precisely.
//!
//! * **`Writer` is a context manager** — `__enter__` returns self,
//!   `__exit__` flushes then drops the underlying writer.

#![allow(clippy::too_many_arguments)]

mod errors;
mod key;
mod reader;
mod verify;
mod writer;

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
fn _native(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(format_version, m)?)?;
    m.add_function(wrap_pyfunction!(core_version, m)?)?;

    // Exception hierarchy.
    errors::register(py, m)?;

    // Core types.
    m.add_class::<key::PyKeyHandle>()?;
    m.add_class::<writer::PyWriter>()?;
    m.add_class::<reader::PyReader>()?;
    m.add_class::<reader::PyRecordIter>()?;
    m.add_class::<verify::PyVerifyReport>()?;

    // Top-level `verify` function (so the Python wrapper can re-export
    // `verify` as a module-level call).
    m.add_function(wrap_pyfunction!(verify::verify, m)?)?;

    Ok(())
}
