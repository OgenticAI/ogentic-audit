# MCP tool-call audit integration guide

How to give an [MCP](https://modelcontextprotocol.io) server a
tamper-evident, court-defensible record of every tool call — *what* the
agent invoked, with what arguments, what came back, and (optionally) *which
policy permitted it* — using `ogentic-audit`.

This is the reference integration behind the "drop-in HMAC hash-chain
audit trail for MCP tool-call logs" promised to compliance customers. It
adds **no new record format and no new crate**: an MCP tool-call is an
ordinary `ogentic-audit` record with a conventional `payload` shape, so it
inherits the whole chain — HMAC-chained, append-only, crash-safe,
verifiable, exportable to a court-ready PDF.

## Architecture at a glance

```
 MCP tool call ──▶ your handler ──▶ ogentic_audit.mcp ──▶ Writer.append
   (name,args)          │             (summarise + chain)      │
                        ▼                                       ▼
                    tool result ─────────────────────▶  audit-NNNN.cbor
                                                        (HMAC-chained record)
```

Each call becomes one record:

| field | value |
|---|---|
| `actor` | who/what made the call (default `"mcp:client"`) |
| `event` | `"mcp.tool_call"` |
| `payload.tool` | the tool name |
| `payload.arguments` | JSON summary of the arguments (capped, redactable) |
| `payload.outcome` | `"ok"` or `"error"` |
| `payload.result` / `payload.error` | JSON summary of the outcome |
| `payload.policy` | *optional* — the [`ogentic-audit-policy/v1`](../adr/0003-policy-attestation-payload-convention.md) decision that authorised the call |

## 1. Quick start

Install the Python bindings (see the [README](../../README.md); until PyPI
publish, `maturin develop`), then:

```python
from ogentic_audit import KeyHandle, Writer, verify
from ogentic_audit.mcp import MCPAuditMiddleware

key = KeyHandle.from_env("OGENTIC_AUDIT_KEY_HEX")   # 64 hex chars

with Writer.open("./mcp-audit", key=key) as w:
    audit = MCPAuditMiddleware(w)

    # Wrap each MCP tool so every call is recorded automatically.
    @audit.instrument("search_docs")
    def search_docs(query: str) -> list[str]:
        return ["q3-report.pdf", "q4-forecast.xlsx"]

    search_docs("quarterly revenue")     # ← one chained record appended

# Later — verify the trail end to end.
report = verify("./mcp-audit", key=key)
assert report.ok
```

`instrument` records the arguments and return value on success, the
exception on failure (then re-raises — your tool's own error handling is
unchanged), and never alters the tool's behaviour.

## 2. One-shot recording (no decorator)

When you already have the `(name, args, result)` in hand — e.g. inside a
generic MCP dispatch loop — call the wrapper function directly:

```python
from ogentic_audit.mcp import audit_tool_call

record_id = audit_tool_call(
    writer,
    tool="write_file",
    arguments={"path": "/tmp/out.txt", "bytes": 12},
    result={"ok": True},
    actor="mcp:agent-zing",
)
```

Pass `error=...` instead of `result=...` to record a failed call.

## 3. Redaction — the audit log is NOT an encryption boundary

MCP tool arguments and results routinely carry secrets, PII, or file
contents. `arguments` and `result` are JSON-summarised and length-capped,
then stored **verbatim**. Redact before auditing:

```python
def scrub(value):
    if isinstance(value, dict):
        return {k: ("***" if k in {"token", "password"} else v) for k, v in value.items()}
    return value

audit = MCPAuditMiddleware(writer, redact=scrub)
```

or summarise to non-sensitive metadata yourself before calling. This
mirrors the redaction caveat in
[`docs/spec/violation-report.md`](../spec/violation-report.md): the chain
protects integrity, not confidentiality — that is the vault's job.

## 4. Recording *why* a call was allowed (policy attestation)

To make the trail a compliance artifact rather than just a log, attach the
policy decision that authorised the call (the
[`ogentic-audit-policy/v1`](../adr/0003-policy-attestation-payload-convention.md)
convention). It nests directly under the tool-call payload:

```python
audit_tool_call(
    writer,
    tool="shell_exec",
    arguments={"cmd": "ls -la"},
    result={"exit": 0},
    policy={
        "format": "ogentic-audit-policy/v1",
        "decision": "permit",
        "digest": "sha256:" + policy_sha256_hex,   # over YOUR canonicalised policy
        "policy_id": "agent-tools-v3",
        "deciding_rules": ["rule.shell-allowlist"],
    },
)
```

A denied call is still worth recording (`"decision": "deny"`, with the
result being the refusal) — "the agent tried X and policy stopped it" is
exactly the accountability signal an unattended fleet needs.

## 5. Verifying and exporting

The recorded chain is an ordinary `ogentic-audit` log, so every existing
tool applies:

```sh
# Fast integrity check (CI-friendly exit codes).
ogentic-audit verify ./mcp-audit --summary

# Prove it was not rewritten, using a checkpoint held elsewhere.
ogentic-audit checkpoint ./mcp-audit --out head.json
ogentic-audit verify   ./mcp-audit --checkpoint head.json

# Court-ready PDF evidence package.
ogentic-audit export ./mcp-audit --pdf mcp-trail.pdf
```

Or from Python: `verify("./mcp-audit", key=key)` and, for rewrite
detection, `verify(..., checkpoint=...)` / `checkpoint(...)`.

## 6. Compliance mapping

Each record is a SHA-256-HMAC-chained, append-only entry
([`docs/spec/v0.1.md`](../spec/v0.1.md)) — the "record of the operation of
the system" contemplated by **EU AI Act Article 12** (logging /
traceability), and an audit-trail control satisfying **SOC 2 CC7** and
**ISO 42001**. The `policy` sub-map records the authorisation basis for
each action. What the log does **not** do on its own is prove *when* it was
observed by an outside party — for that, pair it with checkpoints held by a
counterparty (rewrite detection) and, in a future version, external witness
attestation. See the [court-defensibility brief](../legal/court-defensibility.md)
for what these records do and do not establish.

## Cross-reference

- Runnable example: [`examples/mcp-audit/`](../../examples/mcp-audit/)
- Reference module: [`python/ogentic_audit/mcp.py`](../../python/ogentic_audit/mcp.py)
- Policy attestation: [ADR-0003](../adr/0003-policy-attestation-payload-convention.md)
- On-disk format: [`docs/spec/v0.1.md`](../spec/v0.1.md)
