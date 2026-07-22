"""MCP tool-call audit middleware (OGE-1721).

Exercises ogentic_audit.mcp end to end: tool-calls become chained records,
the chain verifies, payloads round-trip, errors and policy attestations are
captured, and redaction / truncation behave. Also runs the committed
examples/mcp-audit/demo.py so the shipped example is covered by a test.
"""

from __future__ import annotations

import importlib.util
import tempfile
import uuid
from pathlib import Path

import pytest

ogentic_audit = pytest.importorskip("ogentic_audit", reason="native extension not built yet")
from ogentic_audit import KeyHandle, Reader, Writer, verify  # noqa: E402
from ogentic_audit.mcp import (  # noqa: E402
    MCP_TOOL_CALL_EVENT,
    MCPAuditMiddleware,
    audit_tool_call,
)

KEY = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def _key() -> KeyHandle:
    return KeyHandle.from_hex(KEY)


def _records(audit_dir: str) -> list[dict]:
    return list(Reader.open(audit_dir))


def test_wrapper_appends_a_chained_record_that_verifies() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        key = _key()
        with Writer.open(tmp, key=key, session_id_hex=uuid.uuid4().hex) as w:
            rid = audit_tool_call(
                w,
                tool="search_docs",
                arguments={"query": "revenue"},
                result=["a.pdf", "b.xlsx"],
                actor="mcp:agent-zing",
            )
            assert rid == 0

        assert verify(tmp, key=key).ok
        rec = _records(tmp)[0]
        assert rec["event"] == MCP_TOOL_CALL_EVENT
        assert rec["actor"] == "mcp:agent-zing"
        assert rec["payload"]["tool"] == "search_docs"
        assert rec["payload"]["outcome"] == "ok"
        assert "revenue" in rec["payload"]["arguments"]
        assert "a.pdf" in rec["payload"]["result"]


def test_error_calls_are_recorded_as_outcome_error() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        key = _key()
        with Writer.open(tmp, key=key, session_id_hex=uuid.uuid4().hex) as w:
            audit_tool_call(
                w,
                tool="shell_exec",
                arguments={"cmd": "rm -rf /"},
                error={"type": "PermissionError", "message": "denied"},
            )
        rec = _records(tmp)[0]
        assert rec["payload"]["outcome"] == "error"
        assert "denied" in rec["payload"]["error"]
        assert "result" not in rec["payload"]


def test_instrument_records_result_and_reraises_on_error() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        key = _key()
        with Writer.open(tmp, key=key, session_id_hex=uuid.uuid4().hex) as w:
            audit = MCPAuditMiddleware(w)

            @audit.instrument("adder")
            def adder(a: int, b: int) -> int:
                return a + b

            @audit.instrument("boom")
            def boom() -> None:
                raise ValueError("kaboom")

            assert adder(2, 3) == 5
            with pytest.raises(ValueError, match="kaboom"):
                boom()

        assert verify(tmp, key=key).ok
        recs = _records(tmp)
        assert len(recs) == 2
        assert recs[0]["payload"]["tool"] == "adder"
        assert recs[0]["payload"]["outcome"] == "ok"
        assert "5" in recs[0]["payload"]["result"]
        assert recs[1]["payload"]["tool"] == "boom"
        assert recs[1]["payload"]["outcome"] == "error"
        assert "kaboom" in recs[1]["payload"]["error"]


def test_policy_attestation_nests_under_the_tool_call() -> None:
    policy = {
        "format": "ogentic-audit-policy/v1",
        "decision": "permit",
        "digest": "sha256:" + "00" * 32,
        "policy_id": "agent-tools-v3",
        "deciding_rules": ["rule.read"],
    }
    with tempfile.TemporaryDirectory() as tmp:
        key = _key()
        with Writer.open(tmp, key=key, session_id_hex=uuid.uuid4().hex) as w:
            audit_tool_call(w, tool="read", arguments={}, result="ok", policy=policy)
        assert verify(tmp, key=key).ok
        pol = _records(tmp)[0]["payload"]["policy"]
        assert pol["decision"] == "permit"
        assert pol["format"] == "ogentic-audit-policy/v1"


def test_redact_hook_scrubs_before_writing() -> None:
    def scrub(value):
        if isinstance(value, dict):
            return {k: ("***" if k == "token" else v) for k, v in value.items()}
        return value

    with tempfile.TemporaryDirectory() as tmp:
        key = _key()
        with Writer.open(tmp, key=key, session_id_hex=uuid.uuid4().hex) as w:
            audit = MCPAuditMiddleware(w, redact=scrub)
            audit.record_call("login", {"user": "alice", "token": "s3cr3t"}, {"ok": True})
        args = _records(tmp)[0]["payload"]["arguments"]
        assert "s3cr3t" not in args
        assert "***" in args
        assert "alice" in args


def test_long_arguments_are_truncated_with_a_marker() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        key = _key()
        with Writer.open(tmp, key=key, session_id_hex=uuid.uuid4().hex) as w:
            audit_tool_call(
                w,
                tool="big",
                arguments={"blob": "x" * 10000},
                result="ok",
                max_summary_chars=256,
            )
        args = _records(tmp)[0]["payload"]["arguments"]
        assert len(args) < 400
        assert "truncated" in args


def test_shipped_example_runs_end_to_end() -> None:
    # Import and run examples/mcp-audit/demo.py against a temp dir, so the
    # committed example is covered by CI rather than bit-rotting.
    demo_path = REPO_ROOT / "examples" / "mcp-audit" / "demo.py"
    spec = importlib.util.spec_from_file_location("mcp_audit_demo", demo_path)
    assert spec and spec.loader
    demo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(demo)

    with tempfile.TemporaryDirectory() as tmp:
        key = _key()
        demo.run(str(Path(tmp) / "mcp-audit"), key)
        assert verify(str(Path(tmp) / "mcp-audit"), key=key).ok
        recs = _records(str(Path(tmp) / "mcp-audit"))
        assert [r["payload"]["outcome"] for r in recs] == ["ok", "ok", "error"]
        # Every recorded call carries its policy decision.
        assert all("policy" in r["payload"] for r in recs)
