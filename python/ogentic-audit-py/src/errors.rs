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

// Checkpoint anchoring (OGE-1671). CheckpointMismatch / CheckpointTruncated
// are genuine tamper findings, so they sit under VerificationFailed. A
// checkpoint from a *different* log, by contrast, is a wrong-file operator
// mistake, not tamper evidence — it subclasses ArgumentError so callers can
// `except CheckpointKeyMismatchError:` without treating it as an accusation.
create_exception!(_native, CheckpointMismatchError, VerificationFailed);
create_exception!(_native, CheckpointTruncatedError, VerificationFailed);
create_exception!(_native, CheckpointKeyMismatchError, ArgumentError);

// Signed mode (format 0x0002). `SignerNotPinnedError` is deliberately
// OUTSIDE the tamper hierarchy: a log checked without the signer's key is
// not verified, but nothing shows it was altered. `HmacLogError` is an
// argument error: an HMAC log cannot be checked with a public key.
create_exception!(_native, SignerNotPinnedError, OgenticAuditError);
create_exception!(_native, HmacLogError, ArgumentError);
create_exception!(_native, SignatureInvalidError, VerificationFailed);
create_exception!(_native, UntrustedSignerError, VerificationFailed);
create_exception!(_native, RevokedKeyError, VerificationFailed);
create_exception!(_native, RetiredKeyError, VerificationFailed);
create_exception!(_native, TransitionEquivocationError, VerificationFailed);
create_exception!(_native, AlgorithmMismatchError, VerificationFailed);
create_exception!(_native, UnsupportedAlgorithmError, VerificationFailed);
create_exception!(_native, LogIdMismatchError, VerificationFailed);
create_exception!(_native, SealedLogExtendedError, VerificationFailed);
create_exception!(_native, CheckpointForDifferentLogError, VerificationFailed);
create_exception!(_native, FormatDowngradeError, VerificationFailed);
create_exception!(_native, AttestationMissingError, VerificationFailed);
create_exception!(_native, AttestationMalformedError, VerificationFailed);
create_exception!(_native, ReleaseIdMismatchError, VerificationFailed);
create_exception!(_native, FileMissingError, VerificationFailed);
create_exception!(_native, FileAlteredError, VerificationFailed);
create_exception!(_native, UnattestedFileError, VerificationFailed);

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
    m.add(
        "CheckpointMismatchError",
        py.get_type::<CheckpointMismatchError>(),
    )?;
    m.add(
        "CheckpointTruncatedError",
        py.get_type::<CheckpointTruncatedError>(),
    )?;
    m.add(
        "CheckpointKeyMismatchError",
        py.get_type::<CheckpointKeyMismatchError>(),
    )?;
    m.add(
        "SignerNotPinnedError",
        py.get_type::<SignerNotPinnedError>(),
    )?;
    m.add("HmacLogError", py.get_type::<HmacLogError>())?;
    m.add(
        "SignatureInvalidError",
        py.get_type::<SignatureInvalidError>(),
    )?;
    m.add(
        "UntrustedSignerError",
        py.get_type::<UntrustedSignerError>(),
    )?;
    m.add("RevokedKeyError", py.get_type::<RevokedKeyError>())?;
    m.add("RetiredKeyError", py.get_type::<RetiredKeyError>())?;
    m.add(
        "TransitionEquivocationError",
        py.get_type::<TransitionEquivocationError>(),
    )?;
    m.add(
        "AlgorithmMismatchError",
        py.get_type::<AlgorithmMismatchError>(),
    )?;
    m.add(
        "UnsupportedAlgorithmError",
        py.get_type::<UnsupportedAlgorithmError>(),
    )?;
    m.add("LogIdMismatchError", py.get_type::<LogIdMismatchError>())?;
    m.add(
        "SealedLogExtendedError",
        py.get_type::<SealedLogExtendedError>(),
    )?;
    m.add(
        "CheckpointForDifferentLogError",
        py.get_type::<CheckpointForDifferentLogError>(),
    )?;
    m.add(
        "FormatDowngradeError",
        py.get_type::<FormatDowngradeError>(),
    )?;
    m.add(
        "AttestationMissingError",
        py.get_type::<AttestationMissingError>(),
    )?;
    m.add(
        "AttestationMalformedError",
        py.get_type::<AttestationMalformedError>(),
    )?;
    m.add(
        "ReleaseIdMismatchError",
        py.get_type::<ReleaseIdMismatchError>(),
    )?;
    m.add("FileMissingError", py.get_type::<FileMissingError>())?;
    m.add("FileAlteredError", py.get_type::<FileAlteredError>())?;
    m.add("UnattestedFileError", py.get_type::<UnattestedFileError>())?;
    Ok(())
}

/// The exception for a signed-mode violation kind. An unknown kind raises
/// `VerificationFailed` itself, so it fails closed.
pub fn signed_violation_exception(kind: &str, message: &str) -> PyErr {
    let m = message.to_string();
    match kind {
        "SignatureInvalid" => SignatureInvalidError::new_err(m),
        "UntrustedSigner" => UntrustedSignerError::new_err(m),
        "RevokedKey" => RevokedKeyError::new_err(m),
        "RetiredKey" => RetiredKeyError::new_err(m),
        "TransitionEquivocation" => TransitionEquivocationError::new_err(m),
        "AlgorithmMismatch" => AlgorithmMismatchError::new_err(m),
        "UnsupportedAlgorithm" => UnsupportedAlgorithmError::new_err(m),
        "LogIdMismatch" => LogIdMismatchError::new_err(m),
        "SealedLogExtended" => SealedLogExtendedError::new_err(m),
        "CheckpointForDifferentLog" => CheckpointForDifferentLogError::new_err(m),
        "FormatDowngrade" => FormatDowngradeError::new_err(m),
        "AttestationMissing" => AttestationMissingError::new_err(m),
        "AttestationMalformed" => AttestationMalformedError::new_err(m),
        "ReleaseIdMismatch" => ReleaseIdMismatchError::new_err(m),
        "FileMissing" => FileMissingError::new_err(m),
        "FileAltered" => FileAlteredError::new_err(m),
        "UnattestedFile" => UnattestedFileError::new_err(m),
        other => violation_exception(other, message),
    }
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
        "CheckpointMismatch" => CheckpointMismatchError::new_err(message.to_string()),
        "CheckpointTruncated" => CheckpointTruncatedError::new_err(message.to_string()),
        _ => VerificationFailed::new_err(message.to_string()),
    }
}
