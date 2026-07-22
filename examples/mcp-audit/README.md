# mcp-audit

Minimal example: audit every tool call of a toy MCP-style server with
`ogentic-audit`, then verify the chain. Mirrors the integration documented
in [`docs/integrations/mcp.md`](../../docs/integrations/mcp.md).

This is a **standalone reference**, not a real MCP server. It shows the full
loop — instrument tools → serve calls → append chained records → verify —
end to end, and is exercised by
[`python/tests/test_mcp.py`](../../python/tests/test_mcp.py).

## Run it

```sh
# From the repo root, with the Python bindings built (maturin develop).
export OGENTIC_AUDIT_KEY_HEX=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
python examples/mcp-audit/demo.py
```

Expected output (abridged):

```
recorded mcp.tool_call #0  search_docs        ok
recorded mcp.tool_call #1  write_file         ok
recorded mcp.tool_call #2  shell_exec         error
verify: ✓ Verified · 3 events
```

## Layout

```
examples/mcp-audit/
├── README.md     # this file
└── demo.py       # toy tool server + audit middleware + verify
```

## What it demonstrates

- `MCPAuditMiddleware.instrument(...)` auditing a tool on every call,
  recording the result on success and the exception on failure.
- A denied/failed call captured as `outcome: "error"` — still auditable.
- Attaching a policy decision (`ogentic-audit-policy/v1`) to a call.
- Verifying the resulting chain with `verify(...)`.
