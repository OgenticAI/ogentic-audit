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

use ogentic_audit_core::{
    Checkpoint, Reader, Verdict, Verifier, VerifyError, VerifyOptions, Violation,
    CHECKPOINT_FORMAT, HMAC_LEN, KEY_ID_LEN,
};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use pyo3::IntoPyObjectExt;

use crate::errors::{
    violation_exception, ArgumentError, CheckpointKeyMismatchError, IoFailure, VerificationFailed,
};
use crate::key::{clone_boxed, PyKeyHandle};

// PyO3 0.28 uses `Py<PyAny>` for the type historically named PyObject.
type PyObject = Py<PyAny>;

/// Verify the log directory and return a structured report.
///
/// If `raise_on_violation=True`, raise a typed exception for non-
/// `Verified` verdicts instead of returning a report whose `.ok` is
/// False.
///
/// `checkpoint` (a `{format, key_id, segment, record_id, hmac,
/// observed_at}` dict, as produced by [`checkpoint`]) additionally
/// proves the log still extends a previously-observed head. Without it,
/// verification is self-referential — it proves the chain is consistent
/// with itself, which a keyholder who rewrote the chain also satisfies.
/// The Python `verify` wrapper accepts a file path here too and loads it
/// into this dict before calling the native function.
#[pyfunction]
#[pyo3(signature = (log_dir, key, forensic = false, raise_on_violation = false, checkpoint = None))]
pub fn verify(
    py: Python<'_>,
    log_dir: &str,
    key: &PyKeyHandle,
    forensic: bool,
    raise_on_violation: bool,
    checkpoint: Option<Bound<'_, PyDict>>,
) -> PyResult<PyVerifyReport> {
    let key_box = clone_boxed(key);
    let verifier = Verifier::new(key_box);
    let checkpoint = match &checkpoint {
        Some(d) => Some(parse_checkpoint_dict(d)?),
        None => None,
    };
    let opts = VerifyOptions {
        forensic_mode: forensic,
        checkpoint,
    };
    let report = verifier
        .verify_with_options(log_dir, opts)
        .map_err(map_verify_error)?;

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
    PyVerifyReport::from_core(py, report)
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

/// Emit a checkpoint pinning the current chain head.
///
/// Mirrors the `ogentic-audit checkpoint` CLI subcommand: the log is
/// verified first (a checkpoint over a broken chain would launder the
/// break into a trusted anchor), then the head `(segment, record_id,
/// hmac)` is returned as a `ogentic-audit-checkpoint/v1` dict. `observed_at`
/// is descriptive only and never participates in the later comparison; the
/// Python `checkpoint` wrapper defaults it to the current UTC time.
///
/// Hand the result to a party that does not control the log — a copy kept
/// beside the log proves nothing, since both can be rewritten together.
#[pyfunction]
#[pyo3(signature = (log_dir, key, observed_at))]
pub fn checkpoint(
    py: Python<'_>,
    log_dir: &str,
    key: &PyKeyHandle,
    observed_at: &str,
) -> PyResult<Py<PyDict>> {
    let verifier = Verifier::new(clone_boxed(key));
    let report = verifier.verify(log_dir).map_err(map_verify_error)?;

    if !matches!(report.verdict, Verdict::Verified) {
        let detail = report
            .violation
            .as_ref()
            .map(|v| v.message.clone())
            .unwrap_or_else(|| "chain verification failed".to_string());
        return Err(VerificationFailed::new_err(format!(
            "refusing to checkpoint a log that does not verify: {detail}"
        )));
    }

    let (Some(segment), Some(head_hex)) =
        (report.log.last_segment_index, report.log.final_hmac_hex)
    else {
        return Err(ArgumentError::new_err(
            "log has no records — nothing to checkpoint",
        ));
    };

    // `records_inspected` counts across all segments, but `record_id` is
    // per-segment, so read the head record's own id from the last segment.
    let reader =
        Reader::open(log_dir).map_err(|e| IoFailure::new_err(format!("opening log: {e}")))?;
    let mut iter = reader.iter();
    let mut record_id: Option<u64> = None;
    while let Some(record) = iter
        .next_record()
        .map_err(|e| IoFailure::new_err(format!("reading record: {e}")))?
    {
        if record.segment_index == segment {
            record_id = Some(record.record_id);
        }
    }
    let record_id = record_id
        .ok_or_else(|| IoFailure::new_err(format!("segment {segment} contained no records")))?;

    let dict = PyDict::new(py);
    dict.set_item("format", CHECKPOINT_FORMAT)?;
    dict.set_item("key_id", report.log.key_id_hex)?;
    dict.set_item("segment", segment)?;
    dict.set_item("record_id", record_id)?;
    dict.set_item("hmac", head_hex)?;
    dict.set_item("observed_at", observed_at)?;
    Ok(dict.into())
}

/// Parse a checkpoint dict (as emitted by [`checkpoint`]) into the core
/// type. Every failure here is an argument error, not a violation — a
/// checkpoint we cannot read tells us nothing about the log.
fn parse_checkpoint_dict(d: &Bound<'_, PyDict>) -> PyResult<Checkpoint> {
    let get_str = |k: &str| -> PyResult<String> {
        d.get_item(k)?
            .ok_or_else(|| ArgumentError::new_err(format!("checkpoint missing key {k:?}")))?
            .extract::<String>()
            .map_err(|_| ArgumentError::new_err(format!("checkpoint {k:?} must be a string")))
    };
    let get_int = |k: &str| -> PyResult<u64> {
        d.get_item(k)?
            .ok_or_else(|| ArgumentError::new_err(format!("checkpoint missing key {k:?}")))?
            .extract::<u64>()
            .map_err(|_| ArgumentError::new_err(format!("checkpoint {k:?} must be an integer")))
    };

    let format = get_str("format")?;
    if format != CHECKPOINT_FORMAT {
        return Err(ArgumentError::new_err(format!(
            "unsupported checkpoint format {format:?} (expected {CHECKPOINT_FORMAT})"
        )));
    }

    let key_id = decode_hex_fixed::<KEY_ID_LEN>(&get_str("key_id")?, "key_id")?;
    let hmac = decode_hex_fixed::<HMAC_LEN>(&get_str("hmac")?, "hmac")?;
    let segment = u16::try_from(get_int("segment")?)
        .map_err(|_| ArgumentError::new_err("checkpoint \"segment\" exceeds u16"))?;
    let record_id = get_int("record_id")?;
    // observed_at is descriptive metadata only; default to empty if absent.
    let observed_at = match d.get_item("observed_at")? {
        Some(v) => v.extract::<String>().unwrap_or_default(),
        None => String::new(),
    };

    Ok(Checkpoint {
        key_id,
        segment,
        record_id,
        hmac,
        observed_at,
    })
}

fn decode_hex_fixed<const N: usize>(value: &str, field: &str) -> PyResult<[u8; N]> {
    let bytes = hex::decode(value)
        .map_err(|e| ArgumentError::new_err(format!("checkpoint {field} is not valid hex: {e}")))?;
    let len = bytes.len();
    bytes.try_into().map_err(|_| {
        ArgumentError::new_err(format!("checkpoint {field} must be {N} bytes, got {len}"))
    })
}

/// Map a core `VerifyError` onto the Python exception hierarchy. A
/// checkpoint from a different log is an operator mistake (argument
/// error), deliberately distinct from I/O failure and never surfaced as
/// tamper evidence.
fn map_verify_error(e: VerifyError) -> PyErr {
    match e {
        VerifyError::CheckpointKeyMismatch {
            log_key_id_hex,
            checkpoint_key_id_hex,
        } => CheckpointKeyMismatchError::new_err(format!(
            "checkpoint belongs to a different log: checkpoint key_id {checkpoint_key_id_hex}, log key_id {log_key_id_hex}"
        )),
        other => IoFailure::new_err(format!("verifier could not open log: {other}")),
    }
}
