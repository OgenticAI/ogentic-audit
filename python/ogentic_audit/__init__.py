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

import json as _json
from datetime import datetime as _datetime
from datetime import timezone as _timezone
from pathlib import Path as _Path
from typing import TYPE_CHECKING, Any, Union

try:
    from ogentic_audit._native import (
        ArgumentError,
        ChainBreakError,
        CheckpointKeyMismatchError,
        CheckpointMismatchError,
        CheckpointTruncatedError,
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
    )
    from ogentic_audit._native import checkpoint as _native_checkpoint
    from ogentic_audit._native import verify as _native_verify
except ImportError as exc:  # pragma: no cover - import-time only
    raise ImportError(
        "ogentic_audit native extension not built. Install via "
        "`pip install ogentic-audit` or, for development, run "
        "`maturin develop` from the repo root."
    ) from exc

if TYPE_CHECKING:
    from os import PathLike

    _CheckpointArg = Union[str, "PathLike[str]", dict[str, Any]]


def verify(
    log_dir: str,
    key: KeyHandle,
    forensic: bool = False,
    raise_on_violation: bool = False,
    checkpoint: _CheckpointArg | None = None,
) -> VerifyReport:
    """Verify a log directory, optionally against a checkpoint.

    ``checkpoint`` may be a mapping in the ``ogentic-audit-checkpoint/v1``
    shape, or a path to a JSON file of that shape (as written by
    :func:`checkpoint`). Without it, verification is self-referential — it
    proves the chain is consistent with itself, which a keyholder who
    rewrote the chain also satisfies. With it, a rewrite raises
    ``CheckpointMismatchError`` (or sets ``.violation``) and a truncation
    raises ``CheckpointTruncatedError``; a checkpoint from a *different*
    log raises ``CheckpointKeyMismatchError``.
    """
    cp: dict[str, Any] | None
    if checkpoint is None:
        cp = None
    elif isinstance(checkpoint, dict):
        cp = checkpoint
    elif isinstance(checkpoint, (str, _Path)) or hasattr(checkpoint, "__fspath__"):
        cp = _json.loads(_Path(checkpoint).read_text())
    else:
        raise ArgumentError(
            f"checkpoint must be a dict, a path, or None; got {type(checkpoint).__name__}"
        )
    return _native_verify(log_dir, key, forensic, raise_on_violation, cp)


def checkpoint(
    log_dir: str,
    key: KeyHandle,
    *,
    observed_at: str | None = None,
    out: str | PathLike[str] | None = None,
) -> dict[str, Any]:
    """Emit a checkpoint pinning the current chain head.

    The log is verified first (a checkpoint over a broken chain would
    launder the break into a trusted anchor). Returns the
    ``ogentic-audit-checkpoint/v1`` dict; if ``out`` is given, also writes
    it there as pretty JSON. ``observed_at`` defaults to the current UTC
    time and is descriptive only — it never participates in verification.

    Store the result somewhere the log's writer cannot reach; a copy kept
    beside the log proves nothing, since both can be rewritten together.
    """
    if observed_at is None:
        observed_at = _datetime.now(_timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    result = _native_checkpoint(log_dir, key, observed_at)
    if out is not None:
        _Path(out).write_text(_json.dumps(result, indent=2) + "\n")
    return result


__all__ = [
    "ArgumentError",
    "ChainBreakError",
    "CheckpointKeyMismatchError",
    "CheckpointMismatchError",
    "CheckpointTruncatedError",
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
    "checkpoint",
    "core_version",
    "format_version",
    "verify",
]

# Track the installed distribution version instead of a hand-maintained
# literal (which drifted: it read 0.1.0 through the 0.3.0 release). Falls
# back to the native crate version for editable/source checkouts where the
# distribution metadata may be absent.
try:
    from importlib.metadata import version as _dist_version

    __version__ = _dist_version("ogentic-audit")
except Exception:  # pragma: no cover - metadata missing in odd installs
    __version__ = core_version()
