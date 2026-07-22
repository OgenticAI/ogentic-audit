"""Checkpoint anchoring through the Python binding (OGE-1673).

Mirrors the Rust core's ``tests/checkpoint_anchor.rs`` so the two shipped
implementations answer the rewrite question the same way. Chain
verification is self-referential — it proves a log is consistent with
itself, which a keyholder who rewrote the chain also satisfies. A
checkpoint held outside the log is what makes the rewrite visible.
"""

from __future__ import annotations

import json
import tempfile
import uuid
from pathlib import Path

import pytest

ogentic_audit = pytest.importorskip("ogentic_audit", reason="native extension not built yet")
from ogentic_audit import (  # noqa: E402
    ArgumentError,
    CheckpointKeyMismatchError,
    CheckpointMismatchError,
    CheckpointTruncatedError,
    KeyHandle,
    VerificationFailed,
    Writer,
    checkpoint,
    verify,
)

VECTORS_DIR = Path(__file__).resolve().parent.parent.parent / "tests" / "vectors" / "v0.1"


def _fresh_session() -> str:
    return uuid.uuid4().hex


def _write_log(tmp: str, key: KeyHandle, decisions: list[str]) -> None:
    """Write one record per decision; content is a function of the decision."""
    session = _fresh_session()
    with Writer.open(tmp, key=key, session_id_hex=session) as w:
        for i, decision in enumerate(decisions):
            w.append(
                {
                    "actor": "agent:zing",
                    "event": "tool.exec",
                    "payload": {"i": i, "decision": decision},
                }
            )


# ---------------------------------------------------------------------------
# Happy path: a clean log verifies against its own checkpoint.
# ---------------------------------------------------------------------------


def test_clean_log_verifies_against_its_own_checkpoint() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        key = KeyHandle.from_hex("11" * 32)
        _write_log(tmp, key, ["allow", "allow", "deny"])
        cp = checkpoint(tmp, key)
        assert cp["format"] == "ogentic-audit-checkpoint/v1"

        report = verify(tmp, key=key, checkpoint=cp)
        assert report.ok
        assert report.compact == "Verified"


def test_checkpoint_accepts_a_file_path() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        key = KeyHandle.from_hex("11" * 32)
        _write_log(tmp, key, ["allow", "allow"])
        cp_path = str(Path(tmp) / "cp.json")
        checkpoint(tmp, key, out=cp_path, observed_at="2026-07-22T20:00:00Z")

        # Verify accepts the path form, not just the dict.
        report = verify(tmp, key=key, checkpoint=cp_path)
        assert report.ok
        on_disk = json.loads(Path(cp_path).read_text())
        assert on_disk["observed_at"] == "2026-07-22T20:00:00Z"


def test_checkpoint_still_matches_after_honest_appends() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        key = KeyHandle.from_hex("11" * 32)
        _write_log(tmp, key, ["allow", "allow", "deny"])
        cp = checkpoint(tmp, key)

        # More history happens; the log extends the observed head.
        session = _fresh_session()
        with Writer.open(tmp, key=key, session_id_hex=session) as w:
            for i in range(3, 6):
                w.append({"actor": "agent:zing", "event": "tool.exec", "payload": {"i": i}})

        report = verify(tmp, key=key, checkpoint=cp)
        assert report.ok


# ---------------------------------------------------------------------------
# The attack: a rewritten chain passes plain verification but fails against
# a checkpoint observed before the rewrite.
# ---------------------------------------------------------------------------


def test_rewritten_chain_passes_plain_verification() -> None:
    """Documents the gap: internal-only verification cannot see a rewrite."""
    with tempfile.TemporaryDirectory() as tmp:
        key = KeyHandle.from_hex("11" * 32)
        _write_log(tmp, key, ["allow", "allow", "deny", "allow"])
        # Rewrite: same key, different history.
        for f in Path(tmp).glob("*.cbor"):
            f.unlink()
        _write_log(tmp, key, ["allow", "allow", "deny", "deny"])

        report = verify(tmp, key=key)  # no checkpoint
        assert report.ok, (
            "plain verification is self-referential and cannot see a rewrite; "
            "if this fails, the threat model changed"
        )


def test_checkpoint_catches_rewritten_history() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        key = KeyHandle.from_hex("11" * 32)
        _write_log(tmp, key, ["allow", "allow", "deny", "allow"])
        cp = checkpoint(tmp, key)  # observed while honest

        for f in Path(tmp).glob("*.cbor"):
            f.unlink()
        _write_log(tmp, key, ["allow", "allow", "deny", "deny"])

        report = verify(tmp, key=key, checkpoint=cp)
        assert not report.ok
        assert report.verdict_kind == "CheckpointMismatch"

        with pytest.raises(CheckpointMismatchError):
            verify(tmp, key=key, checkpoint=cp, raise_on_violation=True)


def test_checkpoint_catches_truncated_history() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        key = KeyHandle.from_hex("11" * 32)
        _write_log(tmp, key, ["allow", "allow", "deny", "allow", "deny"])
        cp = checkpoint(tmp, key)  # pins the last record

        # Attacker keeps a shorter, internally-consistent prefix.
        for f in Path(tmp).glob("*.cbor"):
            f.unlink()
        _write_log(tmp, key, ["allow", "allow", "deny"])

        # Plain verification is content.
        assert verify(tmp, key=key).ok

        report = verify(tmp, key=key, checkpoint=cp)
        assert not report.ok
        assert report.verdict_kind == "CheckpointTruncated"

        with pytest.raises(CheckpointTruncatedError):
            verify(tmp, key=key, checkpoint=cp, raise_on_violation=True)


# ---------------------------------------------------------------------------
# Operator errors: a checkpoint from a different log, or a broken chain.
# ---------------------------------------------------------------------------


def test_checkpoint_from_a_different_log_is_refused() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        key = KeyHandle.from_hex("11" * 32)
        _write_log(tmp, key, ["allow", "allow"])
        cp = checkpoint(tmp, key)
        cp["key_id"] = "aa" * 32  # a different log's key

        with pytest.raises(CheckpointKeyMismatchError):
            verify(tmp, key=key, checkpoint=cp)


def test_malformed_checkpoint_is_rejected_not_ignored() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        key = KeyHandle.from_hex("11" * 32)
        _write_log(tmp, key, ["allow"])
        with pytest.raises(ArgumentError):
            verify(tmp, key=key, checkpoint={"format": "nope"})


def test_checkpoint_refuses_a_tampered_log() -> None:
    key = _key_for_vector("tampered-byte")
    with pytest.raises(VerificationFailed):
        checkpoint(str(VECTORS_DIR / "tampered-byte"), key)


# ---------------------------------------------------------------------------
# Cross-language parity (AC 5): the same committed golden vector + a
# checkpoint derived from its chain.json must reach the same verdict the
# Rust core reaches (Rust side: crates/ogentic-audit-core/tests/
# checkpoint_anchor.rs::python_parity_single_record_vector).
# ---------------------------------------------------------------------------


def _key_for_vector(name: str) -> KeyHandle:
    inputs = json.loads((VECTORS_DIR / name / "inputs.json").read_text())
    return KeyHandle.from_hex(inputs["key_hex"])


def _checkpoint_from_chain(name: str, *, hmac_override: str | None = None) -> dict:
    """Build a checkpoint for a committed vector straight from its chain.json.

    Deterministic and identical to what the Rust parity test constructs, so
    both languages verify the exact same (log, checkpoint) pair.
    """
    chain = json.loads((VECTORS_DIR / name / "chain.json").read_text())
    head = chain["records"][-1]
    return {
        "format": "ogentic-audit-checkpoint/v1",
        "key_id": chain["key_id_hex"],
        "segment": head["segment"],
        "record_id": head["record_id"],
        "hmac": hmac_override if hmac_override is not None else head["hmac_hex"],
        "observed_at": "2026-07-22T00:00:00Z",
    }


def test_parity_single_record_matching_checkpoint_verifies() -> None:
    key = _key_for_vector("single-record")
    cp = _checkpoint_from_chain("single-record")
    report = verify(str(VECTORS_DIR / "single-record"), key=key, checkpoint=cp)
    assert report.ok
    assert report.compact == "Verified"


def test_parity_single_record_wrong_hmac_is_mismatch() -> None:
    # Same log, same position, a head that was never there → the record at
    # the checkpointed position differs from the observed one = rewrite.
    key = _key_for_vector("single-record")
    cp = _checkpoint_from_chain("single-record", hmac_override="00" * 32)
    report = verify(str(VECTORS_DIR / "single-record"), key=key, checkpoint=cp)
    assert not report.ok
    assert report.verdict_kind == "CheckpointMismatch"
