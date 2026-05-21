"""End-to-end Writer/Reader/verify round-trip via the Python bindings."""

from __future__ import annotations

import json
import os
import tempfile
import uuid
from pathlib import Path

import pytest

ogentic_audit = pytest.importorskip("ogentic_audit", reason="native extension not built yet")
from ogentic_audit import (  # noqa: E402
    ChainBreakError,
    HmacMismatchError,
    KeyHandle,
    Reader,
    VerificationFailed,
    Writer,
    verify,
)

VECTORS_DIR = Path(__file__).resolve().parent.parent.parent / "tests" / "vectors" / "v0.1"


def _key_for_vector(name: str) -> KeyHandle:
    inputs = json.loads((VECTORS_DIR / name / "inputs.json").read_text())
    return KeyHandle.from_hex(inputs["key_hex"])


# ---------------------------------------------------------------------------
# Golden-vector parity: every Rust-verifiable vector verifies the same way in
# Python.
# ---------------------------------------------------------------------------


def test_verify_empty_vector() -> None:
    key = _key_for_vector("empty")
    report = verify(str(VECTORS_DIR / "empty"), key=key)
    assert report.ok
    assert report.compact == "Verified"


def test_verify_single_record_vector() -> None:
    key = _key_for_vector("single-record")
    report = verify(str(VECTORS_DIR / "single-record"), key=key)
    assert report.ok
    assert report.records_inspected == 1


def test_verify_1k_records_vector() -> None:
    key = _key_for_vector("1k-records")
    report = verify(str(VECTORS_DIR / "1k-records"), key=key)
    assert report.ok


def test_verify_segment_rollover_vector() -> None:
    key = _key_for_vector("segment-rollover")
    report = verify(str(VECTORS_DIR / "segment-rollover"), key=key)
    assert report.ok


def test_verify_tampered_byte_vector_raises_hmac_mismatch() -> None:
    key = _key_for_vector("tampered-byte")
    report = verify(str(VECTORS_DIR / "tampered-byte"), key=key)
    assert not report.ok
    assert report.compact == "HmacMismatch@s0r2"
    assert report.violation is not None
    assert report.violation["kind"] == "HmacMismatch"


def test_verify_missing_record_vector_raises_chain_break() -> None:
    key = _key_for_vector("missing-record")
    report = verify(str(VECTORS_DIR / "missing-record"), key=key)
    assert not report.ok
    assert report.compact == "ChainBreak@s0r3"
    assert report.violation is not None
    assert report.violation["kind"] == "ChainBreak"


def test_verify_raise_on_violation_raises_typed_exception() -> None:
    key = _key_for_vector("tampered-byte")
    with pytest.raises(HmacMismatchError):
        verify(
            str(VECTORS_DIR / "tampered-byte"),
            key=key,
            raise_on_violation=True,
        )


def test_verify_chain_break_raises_chain_break_error() -> None:
    key = _key_for_vector("missing-record")
    with pytest.raises(ChainBreakError):
        verify(
            str(VECTORS_DIR / "missing-record"),
            key=key,
            raise_on_violation=True,
        )
    # ChainBreakError is also a VerificationFailed and an OgenticAuditError.
    key = _key_for_vector("missing-record")
    with pytest.raises(VerificationFailed):
        verify(
            str(VECTORS_DIR / "missing-record"),
            key=key,
            raise_on_violation=True,
        )


# ---------------------------------------------------------------------------
# Writer / Reader round trip from Python.
# ---------------------------------------------------------------------------


def test_writer_context_manager_round_trips() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        key = KeyHandle.from_hex("11" * 32)
        session_id_hex = uuid.uuid4().hex
        with Writer.open(tmp, key=key, session_id_hex=session_id_hex) as w:
            rid = w.append({"actor": "user:alice", "event": "vault.unlocked"})
            assert rid == 0
            rid2 = w.append(
                {
                    "actor": "user:alice",
                    "event": "vault.read",
                    "payload": {"key": "doc-1", "size": 4096, "ok": True},
                    "ts_wall": "2026-05-21T05:00:00.000Z",
                    "ts_mono_delta": 1000,
                }
            )
            assert rid2 == 1

        # Reader picks up both records.
        reader = Reader.open(tmp)
        records = list(reader)
        assert len(records) == 2
        assert records[0]["event"] == "vault.unlocked"
        assert records[1]["payload"] == {"key": "doc-1", "size": 4096, "ok": True}

        # Verifier passes.
        report = verify(tmp, key=key)
        assert report.ok
        assert report.records_inspected == 2


def test_writer_exit_propagates_exception() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        key = KeyHandle.from_hex("22" * 32)
        with pytest.raises(RuntimeError, match="boom"):
            with Writer.open(tmp, key=key) as w:
                w.append({"actor": "u", "event": "e"})
                raise RuntimeError("boom")
        # The writer flushed before propagating, so the one record is
        # durable + verifiable.
        report = verify(tmp, key=key)
        assert report.ok
        assert report.records_inspected == 1


def test_writer_rejects_non_dict_append() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        key = KeyHandle.from_hex("33" * 32)
        with Writer.open(tmp, key=key) as w:
            with pytest.raises(TypeError):
                w.append("not a dict")  # type: ignore[arg-type]


def test_writer_rejects_float_payload() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        key = KeyHandle.from_hex("44" * 32)
        with Writer.open(tmp, key=key) as w:
            with pytest.raises(TypeError, match="float"):
                w.append({"actor": "u", "event": "e", "payload": {"x": 1.5}})


def test_reader_iterator_picks_up_payload_types() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        key = KeyHandle.from_hex("55" * 32)
        with Writer.open(tmp, key=key) as w:
            w.append(
                {
                    "actor": "u",
                    "event": "e",
                    "payload": {
                        "i": 42,
                        "j": -7,
                        "s": "hello",
                        "b": True,
                        "nested": {"deep": "value"},
                        "list": [1, 2, "three"],
                        "raw": b"\x00\xffbytes",
                    },
                }
            )
        records = list(Reader.open(tmp))
        assert len(records) == 1
        p = records[0]["payload"]
        assert p["i"] == 42
        assert p["j"] == -7
        assert p["s"] == "hello"
        assert p["b"] is True
        assert p["nested"] == {"deep": "value"}
        assert p["list"] == [1, 2, "three"]
        assert p["raw"] == b"\x00\xffbytes"


# ---------------------------------------------------------------------------
# KeyHandle factories.
# ---------------------------------------------------------------------------


def test_keyhandle_from_env_works() -> None:
    os.environ["OGENTIC_AUDIT_KEY_HEX_TEST"] = "66" * 32
    try:
        key = KeyHandle.from_env("OGENTIC_AUDIT_KEY_HEX_TEST")
        assert isinstance(key, KeyHandle)
        # Same hex → same key_id.
        same = KeyHandle.from_hex("66" * 32)
        assert key.key_id_hex() == same.key_id_hex()
    finally:
        del os.environ["OGENTIC_AUDIT_KEY_HEX_TEST"]


def test_keyhandle_from_bytes_rejects_wrong_length() -> None:
    with pytest.raises(Exception):  # ArgumentError
        KeyHandle.from_bytes(b"\x00" * 16)


# ---------------------------------------------------------------------------
# Recovery surface (R5 / OGE-432) exposed to Python.
# ---------------------------------------------------------------------------


def test_writer_recovery_action_on_fresh_dir_is_fresh() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        key = KeyHandle.from_hex("77" * 32)
        w = Writer.open(tmp, key=key)
        assert w.recovery_action() == "Fresh"
        assert w.recovery_truncated_bytes() == 0
        w.close()


def test_writer_recovery_action_on_reopen_is_resumed() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        key = KeyHandle.from_hex("88" * 32)
        with Writer.open(tmp, key=key) as w:
            w.append({"actor": "u", "event": "e"})
        w2 = Writer.open(tmp, key=key)
        assert w2.recovery_action() == "Resumed"
        w2.close()
