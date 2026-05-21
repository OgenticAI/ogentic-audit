//! `Writer` Python wrapper.
//!
//! Pythonic API:
//!
//! ```python
//! key = KeyHandle.from_env("OGENTIC_AUDIT_KEY_HEX")
//! with Writer.open("./audit-logs", key=key) as w:
//!     rid = w.append({"actor": "user:alice", "event": "vault.unlocked"})
//! ```
//!
//! Notes:
//!
//! * `__enter__` / `__exit__` make this a context manager. `__exit__`
//!   flushes any buffered records (already a tight invariant in the
//!   Rust core: writes go straight to the OS, `flush` is fsync), then
//!   drops the underlying writer.
//! * `append(dict)` infers the required fields from the dict:
//!     - `actor`, `event` (strings, required)
//!     - `ts_wall` (string, optional — defaults to "1970-01-01T00:00:00.000Z");
//!       Python callers SHOULD supply real timestamps from
//!       `datetime.utcnow().isoformat(timespec="milliseconds") + "Z"`
//!     - `ts_mono_delta` (int, optional — defaults to 0)
//!     - `payload` (dict, optional — must contain only int/str/bool/bytes/None)
//!     - `schema_version` (int, optional — defaults to 1)

use std::collections::BTreeMap;

use ogentic_audit_core::{PayloadValue, RecordInput, Writer, WriterConfig};
use pyo3::exceptions::PyTypeError;
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyBool, PyBytes, PyDict, PyFloat, PyInt, PyString};

// PyO3 0.28 uses `Py<PyAny>` for the type historically named PyObject.
type PyObject = Py<PyAny>;

use crate::errors::{ArgumentError, IoFailure, RecoveryError};
use crate::key::{clone_boxed, PyKeyHandle};

/// Python wrapper over a Rust `Writer`.
#[pyclass(name = "Writer", module = "ogentic_audit._native", unsendable)]
pub struct PyWriter {
    inner: Option<Writer>,
}

#[pymethods]
impl PyWriter {
    /// Open or recover an audit-log directory and return a Writer.
    ///
    /// `session_id_hex` is a 32-char hex string (UUIDv4 with dashes
    /// stripped). Defaults to all zeros — Python callers SHOULD
    /// generate a real session_id from `uuid.uuid4()`.
    #[staticmethod]
    #[pyo3(signature = (log_dir, key, session_id_hex = "00000000000000000000000000000000", segment_size_bytes = None))]
    fn open(
        log_dir: &str,
        key: &PyKeyHandle,
        session_id_hex: &str,
        segment_size_bytes: Option<u64>,
    ) -> PyResult<Self> {
        let session_id = parse_session_id(session_id_hex)?;
        let key_box = clone_boxed(key);
        let mut config = WriterConfig::default();
        if let Some(size) = segment_size_bytes {
            config.segment_size_bytes = size;
        }
        let writer = Writer::with_config(log_dir, key_box, session_id, config)
            .map_err(|e| map_writer_error(e))?;
        Ok(Self {
            inner: Some(writer),
        })
    }

    /// Append a record. Returns the assigned `record_id`.
    fn append(&mut self, py: Python<'_>, record: &Bound<'_, PyAny>) -> PyResult<u64> {
        let writer = self
            .inner
            .as_mut()
            .ok_or_else(|| ArgumentError::new_err("Writer is closed"))?;
        let dict = record
            .downcast::<PyDict>()
            .map_err(|_| PyTypeError::new_err("Writer.append expects a dict"))?;
        let input = dict_to_input(py, dict)?;
        writer.append(input).map_err(map_writer_error)
    }

    /// Force durable writes (`F_FULLFSYNC` on macOS).
    fn flush(&mut self) -> PyResult<()> {
        let writer = self
            .inner
            .as_mut()
            .ok_or_else(|| ArgumentError::new_err("Writer is closed"))?;
        writer.flush().map_err(map_writer_error)
    }

    /// Flush + drop the underlying writer.
    fn close(&mut self) -> PyResult<()> {
        if let Some(mut w) = self.inner.take() {
            w.flush().map_err(map_writer_error)?;
        }
        Ok(())
    }

    /// `with` enter — returns self.
    fn __enter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    /// `with` exit — flush + close.
    #[pyo3(signature = (_exc_type = None, _exc_value = None, _traceback = None))]
    fn __exit__(
        &mut self,
        _exc_type: Option<PyObject>,
        _exc_value: Option<PyObject>,
        _traceback: Option<PyObject>,
    ) -> PyResult<bool> {
        self.close()?;
        // Return False so any in-flight exception propagates.
        Ok(false)
    }

    /// `recovery_action`: structured description of what `open` did
    /// (`"Fresh"` / `"Resumed"` / `"Repaired"` / `"OpenedNextAfterFinalized"`).
    fn recovery_action(&self) -> PyResult<String> {
        let writer = self
            .inner
            .as_ref()
            .ok_or_else(|| ArgumentError::new_err("Writer is closed"))?;
        Ok(format!("{:?}", writer.recovery_report().action))
    }

    /// `recovery_truncated_bytes`: bytes lopped off the tail during
    /// `Repaired` recovery (0 otherwise).
    fn recovery_truncated_bytes(&self) -> PyResult<u64> {
        let writer = self
            .inner
            .as_ref()
            .ok_or_else(|| ArgumentError::new_err("Writer is closed"))?;
        Ok(writer.recovery_report().truncated_bytes)
    }

    fn __repr__(&self) -> String {
        match &self.inner {
            Some(_) => "Writer(open)".to_string(),
            None => "Writer(closed)".to_string(),
        }
    }
}

fn parse_session_id(hex_str: &str) -> PyResult<[u8; 16]> {
    let s = hex_str.trim();
    if s.len() != 32 {
        return Err(ArgumentError::new_err(format!(
            "session_id_hex must be 32 hex chars; got {}",
            s.len()
        )));
    }
    let mut out = [0u8; 16];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|e| {
            ArgumentError::new_err(format!("session_id_hex bad hex at byte {i}: {e}"))
        })?;
    }
    Ok(out)
}

fn dict_to_input(py: Python<'_>, dict: &Bound<'_, PyDict>) -> PyResult<RecordInput> {
    let actor: String = require_string(dict, "actor")?;
    let event: String = require_string(dict, "event")?;
    let ts_wall: String =
        optional_string(dict, "ts_wall")?.unwrap_or_else(|| "1970-01-01T00:00:00.000Z".to_string());
    let ts_mono_delta: u64 = optional_uint(dict, "ts_mono_delta")?.unwrap_or(0);
    let schema_version: u8 = optional_uint(dict, "schema_version")?
        .map(|n: u64| n as u8)
        .unwrap_or(1);
    let payload = match dict.get_item("payload")? {
        Some(value) => {
            let payload_dict = value
                .downcast::<PyDict>()
                .map_err(|_| PyTypeError::new_err("'payload' must be a dict if provided"))?;
            payload_dict_to_map(py, payload_dict)?
        },
        None => BTreeMap::new(),
    };
    Ok(RecordInput {
        ts_wall,
        ts_mono_delta,
        actor,
        event,
        payload,
        schema_version,
    })
}

fn require_string(dict: &Bound<'_, PyDict>, key: &str) -> PyResult<String> {
    let value = dict.get_item(key)?.ok_or_else(|| {
        ArgumentError::new_err(format!("record dict is missing required key {key:?}"))
    })?;
    value
        .downcast::<PyString>()
        .map_err(|_| PyTypeError::new_err(format!("record[{key:?}] must be a str")))?
        .extract::<String>()
}

fn optional_string(dict: &Bound<'_, PyDict>, key: &str) -> PyResult<Option<String>> {
    match dict.get_item(key)? {
        Some(value) => Ok(Some(
            value
                .downcast::<PyString>()
                .map_err(|_| PyTypeError::new_err(format!("record[{key:?}] must be a str")))?
                .extract::<String>()?,
        )),
        None => Ok(None),
    }
}

fn optional_uint(dict: &Bound<'_, PyDict>, key: &str) -> PyResult<Option<u64>> {
    match dict.get_item(key)? {
        Some(value) => Ok(Some(
            value
                .downcast::<PyInt>()
                .map_err(|_| PyTypeError::new_err(format!("record[{key:?}] must be an int")))?
                .extract::<u64>()?,
        )),
        None => Ok(None),
    }
}

fn payload_dict_to_map(
    py: Python<'_>,
    dict: &Bound<'_, PyDict>,
) -> PyResult<BTreeMap<String, PayloadValue>> {
    let mut out = BTreeMap::new();
    for (k, v) in dict.iter() {
        let key_str = k
            .downcast::<PyString>()
            .map_err(|_| PyTypeError::new_err("payload keys must be str"))?
            .extract::<String>()?;
        let value = python_to_payload(py, &v)?;
        out.insert(key_str, value);
    }
    Ok(out)
}

fn python_to_payload(py: Python<'_>, value: &Bound<'_, PyAny>) -> PyResult<PayloadValue> {
    // Order matters — `bool` is a subclass of `int` in Python, so check
    // bool first.
    if let Ok(b) = value.downcast::<PyBool>() {
        return Ok(PayloadValue::Bool(b.is_true()));
    }
    if let Ok(i) = value.downcast::<PyInt>() {
        // u64 first; fall back to i64 for negative.
        if let Ok(n) = i.extract::<u64>() {
            return Ok(PayloadValue::Uint(n));
        }
        if let Ok(n) = i.extract::<i64>() {
            return Ok(PayloadValue::Nint(n));
        }
        return Err(ArgumentError::new_err(format!(
            "payload int out of range: {}",
            i.repr()?
        )));
    }
    if value.downcast::<PyFloat>().is_ok() {
        return Err(PyTypeError::new_err(
            "payload floats are not supported in v0.1 (per spec § Canonical encoding rules)",
        ));
    }
    if let Ok(s) = value.downcast::<PyString>() {
        return Ok(PayloadValue::Text(s.extract::<String>()?));
    }
    if let Ok(b) = value.downcast::<PyBytes>() {
        return Ok(PayloadValue::Bytes(b.as_bytes().to_vec()));
    }
    if let Ok(d) = value.downcast::<PyDict>() {
        return Ok(PayloadValue::Map(payload_dict_to_map(py, d)?));
    }
    if let Ok(seq) = value.downcast::<pyo3::types::PyList>() {
        let mut items = Vec::with_capacity(seq.len());
        for item in seq.iter() {
            items.push(python_to_payload(py, &item)?);
        }
        return Ok(PayloadValue::List(items));
    }
    Err(PyTypeError::new_err(format!(
        "unsupported payload value type: {}",
        value.get_type().name()?,
    )))
}

fn map_writer_error(err: ogentic_audit_core::WriterError) -> PyErr {
    use ogentic_audit_core::WriterError;
    match err {
        WriterError::Io(e) => IoFailure::new_err(format!("{e}")),
        WriterError::InvalidInput(msg) => ArgumentError::new_err(msg),
        WriterError::Recovery { reason } => {
            RecoveryError::new_err(format!("recovery refused: {reason}"))
        },
        other => ArgumentError::new_err(format!("unrecognized writer error: {other:?}")),
    }
}
