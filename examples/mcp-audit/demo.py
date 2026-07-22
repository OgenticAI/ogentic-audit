"""Toy MCP-style tool server audited end-to-end with ogentic-audit (OGE-1721).

Run from the repo root with the Python bindings built (``maturin develop``)
and a key in the environment::

    export OGENTIC_AUDIT_KEY_HEX=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
    python examples/mcp-audit/demo.py

See docs/integrations/mcp.md for the full guide.
"""

from __future__ import annotations

import hashlib
import tempfile
from pathlib import Path

from ogentic_audit import KeyHandle, Reader, Writer, verify
from ogentic_audit.mcp import MCPAuditMiddleware


def _policy(decision: str, policy_text: str, rule: str) -> dict:
    """Build an ogentic-audit-policy/v1 attestation over a policy document."""
    digest = hashlib.sha256(policy_text.encode("utf-8")).hexdigest()
    return {
        "format": "ogentic-audit-policy/v1",
        "decision": decision,
        "digest": f"sha256:{digest}",
        "policy_id": "agent-tools-v3",
        "deciding_rules": [rule],
    }


def run(audit_dir: str, key: KeyHandle) -> None:
    with Writer.open(audit_dir, key=key) as w:
        audit = MCPAuditMiddleware(w, actor="mcp:agent-zing")

        # A couple of tools, instrumented so every call is recorded.
        @audit.instrument("search_docs", policy=_policy("permit", "allow: read", "rule.read"))
        def search_docs(query: str) -> list[str]:
            return ["q3-report.pdf", "q4-forecast.xlsx"]

        @audit.instrument("write_file", policy=_policy("permit", "allow: write", "rule.write"))
        def write_file(path: str, data: bytes) -> dict:
            return {"path": path, "bytes": len(data)}

        @audit.instrument("shell_exec", policy=_policy("deny", "deny: shell", "rule.no-shell"))
        def shell_exec(cmd: str) -> dict:
            raise PermissionError(f"policy denied shell command: {cmd!r}")

        # Serve some calls. The last one is denied by policy and raises;
        # the middleware records the error before it propagates.
        search_docs("quarterly revenue")
        write_file("/tmp/out.txt", b"hello world")
        try:
            shell_exec("rm -rf /")
        except PermissionError:
            pass

    for record in Reader.open(audit_dir):
        p = record["payload"]
        print(f"recorded {record['event']} #{record['record_id']}  {p['tool']:<16} {p['outcome']}")

    report = verify(audit_dir, key=key)
    status = "✓ Verified" if report.ok else f"✗ {report.verdict_kind}"
    print(f"verify: {status} · {report.records_inspected} events")


def main() -> None:
    key = KeyHandle.from_env("OGENTIC_AUDIT_KEY_HEX")
    with tempfile.TemporaryDirectory() as tmp:
        run(str(Path(tmp) / "mcp-audit"), key)


if __name__ == "__main__":
    main()
