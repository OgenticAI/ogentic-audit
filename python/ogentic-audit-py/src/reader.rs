//! `Reader` Python wrapper + record iterator.
//!
//! Pythonic API:
//!
//! ```python
//! reader = Reader.open("./audit-logs")
//! for record in reader:
//!     print(record["record_id"], record["event"])
//! ```
//!
//! Records are dict-like (`dict[str, Any]`) — choice documented in
//! OGE-433's reviewer notes and the `.pyi` stub.
//!
//! ## Iterator implementation note
//!
//! `ogentic_audit_core::RecordIterator<'a>` borrows the `Reader`,
//! which is awkward to expose to PyO3 without a self-referential
//! struct. For v0.1 we sidestep the lifetime by using `Reader::seek`
//! per `__next__` call. This is O(N²) in the worst case (each `seek`
//! linear-scans the segment from the header). For the v0.1 audit-log
//! workloads — daily logs in the thousands of records — this is fine.
//! A v0.2 fix is to expose `Reader::into_iter()` from core; tracked
//! informally as a follow-up.

use std::collections::BTreeMap;
use std::path::PathBuf;

use ogentic_audit_core::{PayloadValue, Reader, ReaderError, Record};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};
use pyo3::IntoPyObjectExt;

use crate::errors::{IoFailure, RecordCorruptError};

// PyO3 0.28 uses `Py<PyAny>` for the type historically named PyObject.
type PyObject = Py<PyAny>;

/// Python wrapper over a Rust `Reader`.
#[pyclass(name = "Reader", module = "ogentic_audit._native", unsendable)]
pub struct PyReader {
    log_dir: PathBuf,
}

#[pymethods]
impl PyReader {
    /// Open a log directory (no key needed — verification is `verify(path, key)`).
    #[staticmethod]
    fn open(log_dir: &str) -> PyResult<Self> {
        // Eagerly validate the directory; surface errors at open time
        // rather than on first iter().
        let _reader = Reader::open(log_dir).map_err(map_reader_error)?;
        Ok(Self {
            log_dir: PathBuf::from(log_dir),
        })
    }

    /// Return the list of segment indices on disk.
    fn segments(&self) -> PyResult<Vec<u16>> {
        let reader = Reader::open(&self.log_dir).map_err(map_reader_error)?;
        reader.segments().map_err(map_reader_error)
    }

    /// Return a new iterator over the records.
    fn __iter__(slf: PyRef<'_, Self>) -> PyResult<PyRecordIter> {
        let reader = Reader::open(&slf.log_dir).map_err(map_reader_error)?;
        let segments = reader.segments().map_err(map_reader_error)?;
        Ok(PyRecordIter {
            reader,
            segments,
            seg_cursor: 0,
            next_record_id: 0,
        })
    }

    fn __repr__(&self) -> String {
        format!("Reader(log_dir={:?})", self.log_dir.display())
    }
}

/// Record iterator over a `Reader`.
#[pyclass(name = "RecordIter", module = "ogentic_audit._native", unsendable)]
pub struct PyRecordIter {
    reader: Reader,
    segments: Vec<u16>,
    seg_cursor: usize,
    next_record_id: u64,
}

#[pymethods]
impl PyRecordIter {
    fn __iter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    fn __next__(&mut self, py: Python<'_>) -> PyResult<Option<PyObject>> {
        loop {
            if self.seg_cursor >= self.segments.len() {
                return Ok(None);
            }
            let seg_idx = self.segments[self.seg_cursor];
            match self.reader.seek(seg_idx, self.next_record_id) {
                Ok(record) => {
                    self.next_record_id += 1;
                    return Ok(Some(record_to_dict(py, &record)?));
                },
                Err(ReaderError::NotFound { .. }) => {
                    self.seg_cursor += 1;
                    self.next_record_id = 0;
                    continue;
                },
                Err(e) => return Err(map_reader_error(e)),
            }
        }
    }
}

/// Convert a `Record` into a Python dict matching the type stub shape.
pub fn record_to_dict(py: Python<'_>, record: &Record) -> PyResult<PyObject> {
    let dict = PyDict::new(py);
    dict.set_item("segment_index", record.segment_index)?;
    dict.set_item("record_id", record.record_id)?;
    dict.set_item("ts_wall", &record.ts_wall)?;
    dict.set_item("ts_mono_delta", record.ts_mono_delta)?;
    dict.set_item("session_id_hex", hex_bytes(&record.session_id))?;
    dict.set_item("actor", &record.actor)?;
    dict.set_item("event", &record.event)?;
    dict.set_item("payload", payload_map_to_pydict(py, &record.payload)?)?;
    dict.set_item("key_id_hex", hex_bytes(&record.key_id))?;
    dict.set_item("schema_version", record.schema_version as u32)?;
    dict.set_item("prev_hash", PyBytes::new(py, &record.prev_hash))?;
    dict.set_item("prev_hash_hex", hex_bytes(&record.prev_hash))?;
    dict.set_item("hmac", PyBytes::new(py, &record.hmac))?;
    dict.set_item("hmac_hex", hex_bytes(&record.hmac))?;
    dict.into_py_any(py)
}

fn payload_map_to_pydict(
    py: Python<'_>,
    map: &BTreeMap<String, PayloadValue>,
) -> PyResult<PyObject> {
    let dict = PyDict::new(py);
    for (k, v) in map {
        dict.set_item(k, payload_value_to_py(py, v)?)?;
    }
    dict.into_py_any(py)
}

fn payload_value_to_py(py: Python<'_>, v: &PayloadValue) -> PyResult<PyObject> {
    match v {
        PayloadValue::Uint(n) => n.into_py_any(py),
        PayloadValue::Nint(n) => n.into_py_any(py),
        PayloadValue::Text(s) => s.into_py_any(py),
        PayloadValue::Bytes(b) => PyBytes::new(py, b).into_py_any(py),
        PayloadValue::Bool(b) => b.into_py_any(py),
        PayloadValue::Map(m) => payload_map_to_pydict(py, m),
        PayloadValue::List(items) => {
            let list = PyList::empty(py);
            for item in items {
                list.append(payload_value_to_py(py, item)?)?;
            }
            list.into_py_any(py)
        },
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

pub fn map_reader_error(err: ReaderError) -> PyErr {
    match err {
        ReaderError::Io(e) => IoFailure::new_err(format!("{e}")),
        ReaderError::InvalidHeader {
            segment_index,
            message,
        } => RecordCorruptError::new_err(format!(
            "invalid header at segment {segment_index}: {message}"
        )),
        ReaderError::Decode {
            segment_index,
            offset,
            message,
        } => RecordCorruptError::new_err(format!(
            "record decode error at segment {segment_index} offset {offset}: {message}"
        )),
        ReaderError::TornTail {
            segment_index,
            offset,
        } => RecordCorruptError::new_err(format!(
            "torn tail at segment {segment_index} offset {offset}"
        )),
        ReaderError::NotFound {
            segment_index,
            record_id,
        } => RecordCorruptError::new_err(format!(
            "record not found: segment {segment_index}, record_id {record_id}"
        )),
        other => RecordCorruptError::new_err(format!("unrecognized reader error: {other:?}")),
    }
}
