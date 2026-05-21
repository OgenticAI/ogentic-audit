//! `verify(path, key, *, forensic=False) -> VerifyReport` Python binding.
//!
//! On a violation we BOTH raise a Python exception (so `assert
//! report.ok` paths can also `try/except`) AND return a structured
//! `VerifyReport` that includes the violation. Callers pick whichever
//! shape is more natural:
//!
//! ```python
//! # Boolean-only style
//! report = verify("./logs", key=key)
//! assert report.ok
//!
//! # Exception style
//! try:
//!     verify("./logs", key=key, raise_on_violation=True)
//! except HmacMismatchError as e:
//!     ...
//! ```

use ogentic_audit_core::{Verdict, Verifier, VerifyOptions, Violation};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use pyo3::IntoPyObjectExt;

use crate::errors::{violation_exception, IoFailure, VerificationFailed};
use crate::key::{clone_boxed, PyKeyHandle};

// PyO3 0.28 uses `Py<PyAny>` for the type historically named PyObject.
type PyObject = Py<PyAny>;

/// Verify the log directory and return a structured report.
///
/// If `raise_on_violation=True`, raise a typed exception for non-
/// `Verified` verdicts instead of returning a report whose `.ok` is
/// False.
#[pyfunction]
#[pyo3(signature = (log_dir, key, forensic = false, raise_on_violation = false))]
pub fn verify(
    py: Python<'_>,
    log_dir: &str,
    key: &PyKeyHandle,
    forensic: bool,
    raise_on_violation: bool,
) -> PyResult<PyVerifyReport> {
    let key_box = clone_boxed(key);
    let verifier = Verifier::new(key_box);
    let opts = VerifyOptions {
        forensic_mode: forensic,
    };
    let report = verifier
        .verify_with_options(log_dir, opts)
        .map_err(|e| IoFailure::new_err(format!("verifier could not open log: {e}")))?;

    let ok = matches!(report.verdict, Verdict::Verified);
    if !ok && raise_on_violation {
        if let Some(v) = &report.violation {
            let kind = format!("{:?}", v.kind);
            return Err(violation_exception(&kind, &v.message));
        }
        return Err(VerificationFailed::new_err(format!(
            "verify returned non-Verified verdict with no violation populated: {:#?}",
            report
        )));
    }
    Ok(PyVerifyReport::from_core(py, report)?)
}

/// Python-facing verify report.
#[pyclass(name = "VerifyReport", module = "ogentic_audit._native", unsendable)]
pub struct PyVerifyReport {
    /// `True` iff the verdict was `Verified`.
    #[pyo3(get)]
    pub ok: bool,
    /// Compact verdict string, either `"Verified"` or `"<Kind>@s<N>r<N>"`.
    #[pyo3(get)]
    pub compact: String,
    /// `"Verified"` or the violation `kind` discriminator
    /// (`"HmacMismatch"`, `"ChainBreak"`, …).
    #[pyo3(get)]
    pub verdict_kind: String,
    /// Log directory.
    #[pyo3(get)]
    pub log_dir: String,
    /// Hex of the signing key's key_id.
    #[pyo3(get)]
    pub key_id_hex: String,
    /// Segments inspected.
    #[pyo3(get)]
    pub segments_inspected: u32,
    /// Records inspected.
    #[pyo3(get)]
    pub records_inspected: u64,
    /// Final HMAC hex if the log verified, otherwise None.
    #[pyo3(get)]
    pub final_hmac_hex: Option<String>,
    /// First violation as a dict (None on Verified).
    #[pyo3(get)]
    pub violation: Option<PyObject>,
    /// Additional violations (only populated under `forensic=True`).
    #[pyo3(get)]
    pub additional_violations: Py<PyList>,
}

#[pymethods]
impl PyVerifyReport {
    fn __repr__(&self) -> String {
        format!(
            "VerifyReport(ok={}, compact={:?}, records_inspected={}, segments_inspected={})",
            self.ok, self.compact, self.records_inspected, self.segments_inspected
        )
    }
}

impl PyVerifyReport {
    fn from_core(py: Python<'_>, report: ogentic_audit_core::VerifyReport) -> PyResult<Self> {
        let ok = matches!(report.verdict, Verdict::Verified);
        let compact = report.compact_verdict();
        let verdict_kind = match &report.verdict {
            Verdict::Verified => "Verified".to_string(),
            Verdict::Violation => report
                .violation
                .as_ref()
                .map(|v| format!("{:?}", v.kind))
                .unwrap_or_else(|| "Unknown".to_string()),
        };
        let violation = match &report.violation {
            Some(v) => Some(violation_to_dict(py, v)?),
            None => None,
        };
        let additional = PyList::empty(py);
        for v in &report.additional_violations {
            additional.append(violation_to_dict(py, v)?)?;
        }
        Ok(Self {
            ok,
            compact,
            verdict_kind,
            log_dir: report.log.log_dir.to_string_lossy().into_owned(),
            key_id_hex: report.log.key_id_hex,
            segments_inspected: report.log.segments_inspected,
            records_inspected: report.log.records_inspected,
            final_hmac_hex: report.log.final_hmac_hex,
            violation,
            additional_violations: additional.into(),
        })
    }
}

fn violation_to_dict(py: Python<'_>, v: &Violation) -> PyResult<PyObject> {
    let dict = PyDict::new(py);
    dict.set_item("kind", format!("{:?}", v.kind))?;
    dict.set_item("segment_index", v.location.segment_index)?;
    dict.set_item("record_id", v.location.record_id)?;
    dict.set_item("byte_offset", v.location.byte_offset)?;
    dict.set_item("message", &v.message)?;
    dict.into_py_any(py)
}
