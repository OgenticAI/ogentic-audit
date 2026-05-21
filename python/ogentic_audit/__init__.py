"""Python bindings for ogentic-audit.

This package re-exports a thin Pythonic API on top of the PyO3 extension
module ``ogentic_audit._native``. v0.1 is in development; the API is unstable
until v0.1.0 is tagged.

Target API (mirrors the OGE-433 spec):

```python
from ogentic_audit import Writer, Reader, KeyHandle, verify

key = KeyHandle.from_env("OGENTIC_AUDIT_KEY_HEX")

with Writer.open("./audit-logs", key=key) as w:
    w.append({"actor": "user:alice", "event": "vault.unlocked"})

for record in Reader.open("./audit-logs"):
    print(record["record_id"], record["event"])

report = verify("./audit-logs", key=key)
assert report.ok
```

See the on-disk format specification at
https://github.com/OgenticAI/ogentic-audit/tree/main/docs/spec.
"""

from __future__ import annotations

try:
    from ogentic_audit._native import (
        ArgumentError,
        ChainBreakError,
        HeaderCorruptError,
        HmacMismatchError,
        IoFailure,
        KeyHandle,
        KeyIdMismatchError,
        MissingRecordError,
        OgenticAuditError,
        Reader,
        RecordCorruptError,
        RecoveryError,
        SchemaError,
        SegmentDiscontinuityError,
        TimestampError,
        VerificationFailed,
        VerifyReport,
        Writer,
        core_version,
        format_version,
        verify,
    )
except ImportError as exc:  # pragma: no cover - import-time only
    raise ImportError(
        "ogentic_audit native extension not built. Install via "
        "`pip install ogentic-audit` or, for development, run "
        "`maturin develop` from the repo root."
    ) from exc

__all__ = [
    "ArgumentError",
    "ChainBreakError",
    "HeaderCorruptError",
    "HmacMismatchError",
    "IoFailure",
    "KeyHandle",
    "KeyIdMismatchError",
    "MissingRecordError",
    "OgenticAuditError",
    "Reader",
    "RecordCorruptError",
    "RecoveryError",
    "SchemaError",
    "SegmentDiscontinuityError",
    "TimestampError",
    "VerificationFailed",
    "VerifyReport",
    "Writer",
    "__version__",
    "core_version",
    "format_version",
    "verify",
]

__version__ = "0.1.0a0"
