//! Python exception hierarchy.
//!
//! Root is `OgenticAuditError(Exception)`. Subclasses cover every
//! violation kind plus the I/O / argument failure shape. Callers can
//! `except HmacMismatchError:` for a specific failure or
//! `except OgenticAuditError:` for any binding-emitted error.

use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;

create_exception!(_native, OgenticAuditError, PyException);
create_exception!(_native, IoFailure, OgenticAuditError);
create_exception!(_native, ArgumentError, OgenticAuditError);
create_exception!(_native, RecoveryError, OgenticAuditError);

// Verification failures — each corresponds to a v0.1 ViolationKind.
create_exception!(_native, VerificationFailed, OgenticAuditError);
create_exception!(_native, ChainBreakError, VerificationFailed);
create_exception!(_native, HmacMismatchError, VerificationFailed);
create_exception!(_native, MissingRecordError, VerificationFailed);
create_exception!(_native, RecordCorruptError, VerificationFailed);
create_exception!(_native, HeaderCorruptError, VerificationFailed);
create_exception!(_native, KeyIdMismatchError, VerificationFailed);
create_exception!(_native, SegmentDiscontinuityError, VerificationFailed);
create_exception!(_native, TimestampError, VerificationFailed);
create_exception!(_native, SchemaError, VerificationFailed);

/// Register every exception type on the module.
pub fn register(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("OgenticAuditError", py.get_type::<OgenticAuditError>())?;
    m.add("IoFailure", py.get_type::<IoFailure>())?;
    m.add("ArgumentError", py.get_type::<ArgumentError>())?;
    m.add("RecoveryError", py.get_type::<RecoveryError>())?;
    m.add("VerificationFailed", py.get_type::<VerificationFailed>())?;
    m.add("ChainBreakError", py.get_type::<ChainBreakError>())?;
    m.add("HmacMismatchError", py.get_type::<HmacMismatchError>())?;
    m.add("MissingRecordError", py.get_type::<MissingRecordError>())?;
    m.add("RecordCorruptError", py.get_type::<RecordCorruptError>())?;
    m.add("HeaderCorruptError", py.get_type::<HeaderCorruptError>())?;
    m.add("KeyIdMismatchError", py.get_type::<KeyIdMismatchError>())?;
    m.add(
        "SegmentDiscontinuityError",
        py.get_type::<SegmentDiscontinuityError>(),
    )?;
    m.add("TimestampError", py.get_type::<TimestampError>())?;
    m.add("SchemaError", py.get_type::<SchemaError>())?;
    Ok(())
}

/// Convert a `ViolationKind` discriminator string into the appropriate
/// PyException constructor.
pub fn violation_exception(kind: &str, message: &str) -> PyErr {
    match kind {
        "ChainBreak" => ChainBreakError::new_err(message.to_string()),
        "HmacMismatch" => HmacMismatchError::new_err(message.to_string()),
        "MissingRecord" => MissingRecordError::new_err(message.to_string()),
        "RecordCorrupt" => RecordCorruptError::new_err(message.to_string()),
        "HeaderCorrupt" => HeaderCorruptError::new_err(message.to_string()),
        "KeyIdMismatch" => KeyIdMismatchError::new_err(message.to_string()),
        "SegmentDiscontinuity" => SegmentDiscontinuityError::new_err(message.to_string()),
        "TimestampRegression" | "TimestampInconsistency" => {
            TimestampError::new_err(message.to_string())
        },
        "SchemaViolation" | "UnknownVersion" => SchemaError::new_err(message.to_string()),
        _ => VerificationFailed::new_err(message.to_string()),
    }
}
