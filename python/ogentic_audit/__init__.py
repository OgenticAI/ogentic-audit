"""Python bindings for ogentic-audit.

This package re-exports a thin Pythonic API on top of the PyO3 extension
module ``ogentic_audit._native``.

Two log formats:

* **signed (0x0002)**: every record carries an Ed25519 signature. Anyone
  holding the signer's *public* key can verify, and nobody who verifies can
  forge. Write with ``Writer.open(dir, signing_key=SigningKey...)``; verify
  with ``verify(dir, key_fingerprint="...")``.
* **HMAC (0x0001)**: verifying needs the shared secret key, and whoever holds
  it could also have written the log.

``verify`` reads the log's format before it uses any key, never takes a key
you did not pass, and reports a signed log checked without a key as
``"SelfConsistent"`` (not verified), never ``"Verified"``.

```python
from ogentic_audit import SigningKey, Writer, verify

key = SigningKey.from_keychain("com.example.app", "audit:ed25519", create=True)
with Writer.open("./audit-logs", signing_key=key) as w:
    w.append({"actor": "user:alice", "event": "vault.unlocked"})

report = verify("./audit-logs", key_fingerprint=key.fingerprint())
assert report.ok
```

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
from collections.abc import Sequence
from dataclasses import dataclass as _dataclass
from dataclasses import field as _field
from datetime import datetime as _datetime
from datetime import timezone as _timezone
from pathlib import Path as _Path
from typing import TYPE_CHECKING, Any, Union

try:
    from ogentic_audit._native import (
        FORMAT_VERSION_SIGNED,
        AlgorithmMismatchError,
        ArgumentError,
        AttestationMalformedError,
        AttestationMissingError,
        ChainBreakError,
        CheckpointForDifferentLogError,
        CheckpointKeyMismatchError,
        CheckpointMismatchError,
        CheckpointTruncatedError,
        FileAlteredError,
        FileMissingError,
        FormatDowngradeError,
        HeaderCorruptError,
        HmacLogError,
        HmacMismatchError,
        IoFailure,
        KeyHandle,
        KeyIdMismatchError,
        LogIdMismatchError,
        MissingRecordError,
        OgenticAuditError,
        Reader,
        RecordCorruptError,
        RecoveryError,
        ReleaseIdMismatchError,
        ReleaseReport,
        RetiredKeyError,
        RevokedKeyError,
        SchemaError,
        SealedLogExtendedError,
        SegmentDiscontinuityError,
        SignatureInvalidError,
        SignedVerifyReport,
        SignerNotPinnedError,
        SigningKey,
        TimestampError,
        TransitionEquivocationError,
        UnattestedFileError,
        UnsupportedAlgorithmError,
        UntrustedSignerError,
        VerificationFailed,
        VerifyReport,
        Writer,
        core_version,
        format_version,
        log_format,
    )
    from ogentic_audit._native import attest_release as _native_attest_release
    from ogentic_audit._native import checkpoint as _native_checkpoint
    from ogentic_audit._native import checkpoint_signed as _native_checkpoint_signed
    from ogentic_audit._native import verify as _native_verify
    from ogentic_audit._native import verify_release as _native_verify_release
    from ogentic_audit._native import verify_signed as _native_verify_signed
except ImportError as exc:  # pragma: no cover - import-time only
    raise ImportError(
        "ogentic_audit native extension not built. Install via "
        "`pip install ogentic-audit` or, for development, run "
        "`maturin develop` from the repo root."
    ) from exc

if TYPE_CHECKING:
    from os import PathLike

    _CheckpointArg = Union[str, "PathLike[str]", dict[str, Any]]


_PathLike = Union[str, "PathLike[str]"]


def _paths(v: _PathLike | Sequence[_PathLike] | None) -> list[str]:
    if v is None:
        return []
    if isinstance(v, (str, _Path)) or hasattr(v, "__fspath__"):
        return [str(v)]
    return [str(x) for x in v]


def _strs(v: str | Sequence[str] | None) -> list[str]:
    if v is None:
        return []
    if isinstance(v, str):
        return [v]
    return list(v)


def _detect_format(log_dir: _PathLike) -> int:
    fmt = log_format(str(log_dir))
    if fmt is None:
        raise IoFailure(f"no audit-NNNN.cbor segment files in {log_dir}")
    if fmt > FORMAT_VERSION_SIGNED:
        raise ArgumentError(f"this log uses format 0x{fmt:04x}; upgrade ogentic-audit")
    return fmt


def verify(
    log_dir: _PathLike,
    key: KeyHandle | None = None,
    forensic: bool = False,
    raise_on_violation: bool = False,
    checkpoint: _CheckpointArg | Sequence[_PathLike] | None = None,
    *,
    public_key: str | None = None,
    key_fingerprint: str | Sequence[str] | None = None,
    trust: _PathLike | None = None,
    statements: _PathLike | Sequence[_PathLike] | None = None,
    revocations: _PathLike | Sequence[_PathLike] | None = None,
    witnesses: _PathLike | Sequence[_PathLike] | None = None,
    expect_log_id: str | None = None,
    segment: int | None = None,
) -> VerifyReport | SignedVerifyReport:
    """Verify a log directory, reading its format before using any key.

    **Signed logs (format 0x0002)** are checked with the signer's public key,
    obtained from the signer, never from the log: ``public_key`` (a file or
    the key text), ``key_fingerprint`` (one or more, any grouping), or
    ``trust`` (an OpenSSH ``allowed_signers`` file with ``namespaces=``
    scopes), plus ``statements`` (directories of key transitions and
    revocations) and ``revocations``. ``checkpoint`` is one or more v2
    checkpoint files (their ``.sig`` beside them), ``witnesses`` witness
    co-signatures. Without a key the best verdict is ``"SelfConsistent"``:
    ``report.ok`` is False and ``raise_on_violation=True`` raises
    ``SignerNotPinnedError``. Passing an HMAC ``key`` for a signed log is an
    ``ArgumentError``.

    **HMAC logs (format 0x0001)** need ``key`` (a ``KeyHandle``) and accept
    one v1 ``checkpoint`` (dict or path). Passing a public key or
    fingerprint for an HMAC log raises ``HmacLogError``: whoever holds its
    key could also have written it, so it can never be verified that way.
    """
    fmt = _detect_format(log_dir)
    signed_inputs = any(
        x
        for x in (
            public_key,
            key_fingerprint,
            trust,
            statements,
            revocations,
            witnesses,
            expect_log_id,
        )
    )
    if fmt == 1:
        if signed_inputs:
            raise HmacLogError(
                "this log is protected by a shared secret key (format 0x0001). It cannot be "
                "checked with a public key, and whoever holds its key could also have written it"
            )
        if key is None:
            raise ArgumentError("this is an HMAC log; pass its key (key=KeyHandle...)")
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
        return _native_verify(str(log_dir), key, forensic, raise_on_violation, cp)
    if key is not None:
        raise ArgumentError(
            "this is a signed log; pass the signer's public key or fingerprint "
            "(public_key=, key_fingerprint=, trust=), not an HMAC key"
        )
    if isinstance(checkpoint, dict):
        raise ArgumentError("signed logs take checkpoint files (v2), not a v1 dict")
    return _native_verify_signed(
        str(log_dir),
        public_key=public_key,
        key_fingerprint=_strs(key_fingerprint),
        trust=str(trust) if trust is not None else None,
        statements=_paths(statements),
        revocations=_paths(revocations),
        checkpoints=_paths(checkpoint),  # type: ignore[arg-type]
        witnesses=_paths(witnesses),
        expect_log_id=expect_log_id,
        forensic=forensic,
        segment=segment,
        raise_on_violation=raise_on_violation,
    )


def checkpoint(
    log_dir: _PathLike,
    key: KeyHandle | None = None,
    *,
    signing_key: SigningKey | None = None,
    observed_at: str | None = None,
    out: _PathLike | None = None,
) -> dict[str, Any]:
    """Emit a checkpoint pinning the current chain head.

    The log is verified first (a checkpoint over a broken chain would
    launder the break into a trusted anchor).

    * Signed logs: a v2 checkpoint, unsigned (your own observation) or, with
      ``signing_key`` (the log's own key), signed. With ``out``, writes the
      canonical JSON there and the signature to ``<out>.sig``.
    * HMAC logs: the v1 checkpoint (needs ``key``).

    Store the result somewhere the log's writer cannot reach; a copy kept
    beside the log proves nothing, since both can be rewritten together.
    """
    fmt = _detect_format(log_dir)
    if fmt == 1:
        if key is None or signing_key is not None:
            raise ArgumentError("an HMAC log is checkpointed with its key=KeyHandle")
        if observed_at is None:
            observed_at = _datetime.now(_timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        result = _native_checkpoint(str(log_dir), key, observed_at)
        if out is not None:
            _Path(out).write_text(_json.dumps(result, indent=2) + "\n")
        return result
    if key is not None:
        raise ArgumentError("this is a signed log; an HMAC key does not apply")
    if observed_at is None:
        now = _datetime.now(_timezone.utc)
        observed_at = now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"
    data, sig = _native_checkpoint_signed(
        str(log_dir), observed_at=observed_at, signing_key=signing_key
    )
    if out is not None:
        _Path(out).write_bytes(data)
        if sig is not None:
            _Path(str(out) + ".sig").write_text(sig)
    elif sig is not None:
        raise ArgumentError("a signed checkpoint needs out= (the signature goes to <out>.sig)")
    result: dict[str, Any] = _json.loads(data)
    return result


@_dataclass(frozen=True)
class FileSpec:
    """A released file: path relative to the release folder, optional role
    (``"page"``, ``"index"``, …) and optional named byte ranges
    ``(name, offset, length)``, such as the rows of an index."""

    path: str
    role: str | None = None
    parts: Sequence[tuple[str, int, int]] = _field(default_factory=tuple)


@_dataclass(frozen=True)
class LogSpec:
    """A log to include: its live directory, the path inside the release,
    the head to attest as ``(segment, record_id)`` (default: the log must be
    sealed), and records whose bodies are withheld, as
    ``(segment, record_id)`` pairs."""

    path: str
    head: tuple[int, int] | None = None
    elide: Sequence[tuple[int, int]] = _field(default_factory=tuple)
    dest: str = "Audit log"


def attest_release(
    release_dir: _PathLike,
    *,
    files: Sequence[str | FileSpec],
    logs: Sequence[LogSpec],
    signing_key: SigningKey,
    release_id: str,
    created_at: str | None = None,
) -> str:
    """Sign a release: copy each log through its head (eliding withheld
    bodies), write the instructions and public key, hash every file, and
    sign the attestation. Returns the attestation's SHA-256 (hex)."""
    fs = []
    for f in files:
        spec = FileSpec(f) if isinstance(f, str) else f
        fs.append((spec.path, spec.role, [tuple(p) for p in spec.parts]))
    ls = [(lg.path, lg.dest, lg.head, [tuple(e) for e in lg.elide]) for lg in logs]
    return _native_attest_release(
        str(release_dir),
        files=fs,
        logs=ls,
        signing_key=signing_key,
        release_id=release_id,
        created_at=created_at,
    )


def verify_release(
    release_dir: _PathLike,
    *,
    public_key: str | None = None,
    key_fingerprint: str | Sequence[str] | None = None,
    trust: _PathLike | None = None,
    statements: _PathLike | Sequence[_PathLike] | None = None,
    revocations: _PathLike | Sequence[_PathLike] | None = None,
    witnesses: _PathLike | Sequence[_PathLike] | None = None,
    expect_release_id: str | None = None,
    allow_unattested: bool = False,
) -> ReleaseReport:
    """Verify a signed release folder: the attestation's signature, every
    file, and every audit log in it. ``report.violations`` lists every
    problem, each naming its item (``file:<path>``, ``file:<path>#<row>``,
    ``log:<path>/s0r4``, ``attestation``)."""
    return _native_verify_release(
        str(release_dir),
        public_key=public_key,
        key_fingerprint=_strs(key_fingerprint),
        trust=str(trust) if trust is not None else None,
        statements=_paths(statements),
        revocations=_paths(revocations),
        witnesses=_paths(witnesses),
        expect_release_id=expect_release_id,
        allow_unattested=allow_unattested,
    )


__all__ = [
    "FORMAT_VERSION_SIGNED",
    "AlgorithmMismatchError",
    "ArgumentError",
    "AttestationMalformedError",
    "AttestationMissingError",
    "ChainBreakError",
    "CheckpointForDifferentLogError",
    "CheckpointKeyMismatchError",
    "CheckpointMismatchError",
    "CheckpointTruncatedError",
    "FileAlteredError",
    "FileMissingError",
    "FileSpec",
    "FormatDowngradeError",
    "HeaderCorruptError",
    "HmacLogError",
    "HmacMismatchError",
    "IoFailure",
    "KeyHandle",
    "KeyIdMismatchError",
    "LogIdMismatchError",
    "LogSpec",
    "MissingRecordError",
    "OgenticAuditError",
    "Reader",
    "RecordCorruptError",
    "RecoveryError",
    "ReleaseIdMismatchError",
    "ReleaseReport",
    "RetiredKeyError",
    "RevokedKeyError",
    "SchemaError",
    "SealedLogExtendedError",
    "SegmentDiscontinuityError",
    "SignatureInvalidError",
    "SignedVerifyReport",
    "SignerNotPinnedError",
    "SigningKey",
    "TimestampError",
    "TransitionEquivocationError",
    "UnattestedFileError",
    "UnsupportedAlgorithmError",
    "UntrustedSignerError",
    "VerificationFailed",
    "VerifyReport",
    "Writer",
    "__version__",
    "attest_release",
    "checkpoint",
    "core_version",
    "format_version",
    "log_format",
    "verify",
    "verify_release",
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
