"""Reference MCP tool-call audit middleware (OGE-1721).

A minimal, dependency-free integration that turns MCP server tool-call
events into chained, tamper-evident `ogentic-audit` records. It wraps the
existing `Writer` — there is no new record format and no new crate: a
tool-call is an ordinary audit record with a conventional `payload` shape.

Two entry points:

- :func:`audit_tool_call` — the one-shot wrapper: given a `(tool, arguments,
  result)` (or an `error`), append one chained record. Returns the record id.
- :class:`MCPAuditMiddleware` — holds a `Writer` and adds
  :meth:`~MCPAuditMiddleware.instrument`, a decorator that audits every call
  of a tool function (result on success, error on exception, then re-raises).

Example::

    from ogentic_audit import Writer, KeyHandle
    from ogentic_audit.mcp import MCPAuditMiddleware

    key = KeyHandle.from_env("OGENTIC_AUDIT_KEY_HEX")
    with Writer.open("./mcp-audit", key=key) as w:
        audit = MCPAuditMiddleware(w)

        @audit.instrument("search_docs")
        def search_docs(query: str) -> list[str]:
            return [...]

        search_docs("quarterly revenue")   # recorded automatically

## Redaction

`arguments` and `result` are JSON-summarised and length-capped, then stored
verbatim. **The audit log is not an encryption boundary** — MCP tool
arguments and results routinely carry secrets, PII, or file contents. Redact
before auditing: pass a ``redact`` callable to scrub the value first, or
summarise to non-sensitive metadata yourself. This mirrors the redaction
caveat in `docs/spec/violation-report.md`.

## Compliance mapping

Each record is a SHA-256-HMAC-chained, append-only entry (`docs/spec/v0.1.md`),
which is the "records of the operation of the system" contemplated by EU AI
Act Article 12 (logging) and the audit-trail controls under SOC 2 CC7 /
ISO 42001. Attach the policy decision that authorised the call via ``policy``
(the ``ogentic-audit-policy/v1`` convention, OGE-1674) to record *why* the
call was permitted, not just that it happened.
"""

from __future__ import annotations

import functools
import json
from collections.abc import Mapping
from typing import Any, Callable, TypeVar

__all__ = ["MCP_TOOL_CALL_EVENT", "MCPAuditMiddleware", "audit_tool_call"]

#: The `event` tag every audited MCP tool-call carries.
MCP_TOOL_CALL_EVENT = "mcp.tool_call"

#: Default cap on a serialised `arguments`/`result`/`error` summary. Keeps
#: records bounded regardless of tool payload size; the overflow is noted so
#: an auditor knows truncation occurred.
DEFAULT_MAX_SUMMARY_CHARS = 4096

_Redactor = Callable[[Any], Any]
_F = TypeVar("_F", bound=Callable[..., Any])


def _summarise(value: Any, *, max_chars: int, redact: _Redactor | None) -> str:
    """Deterministically JSON-summarise a value, redacted and length-capped."""
    if redact is not None:
        value = redact(value)
    try:
        text = json.dumps(value, default=repr, sort_keys=True, ensure_ascii=False)
    except (TypeError, ValueError):
        text = repr(value)
    if len(text) > max_chars:
        dropped = len(text) - max_chars
        text = text[:max_chars] + f"…(+{dropped} chars truncated)"
    return text


def audit_tool_call(
    writer: Any,
    *,
    tool: str,
    arguments: Any = None,
    result: Any = None,
    error: Any = None,
    actor: str = "mcp:client",
    policy: Mapping[str, Any] | None = None,
    redact: _Redactor | None = None,
    max_summary_chars: int = DEFAULT_MAX_SUMMARY_CHARS,
) -> int:
    """Append one MCP tool-call as a chained audit record.

    Returns the new record's id (its per-segment ``record_id``).

    ``arguments`` and ``result`` are JSON-summarised and capped (see module
    docs on redaction). Pass ``error`` instead of ``result`` to record a
    failed call; ``outcome`` in the payload is ``"error"`` then, else ``"ok"``.
    ``policy`` (an ``ogentic-audit-policy/v1`` dict) records the decision that
    authorised the call.
    """
    payload: dict[str, Any] = {
        "tool": tool,
        "arguments": _summarise(arguments, max_chars=max_summary_chars, redact=redact),
        "outcome": "error" if error is not None else "ok",
    }
    if error is not None:
        payload["error"] = _summarise(error, max_chars=max_summary_chars, redact=redact)
    else:
        payload["result"] = _summarise(result, max_chars=max_summary_chars, redact=redact)
    if policy is not None:
        # The policy attestation convention (OGE-1674) is itself a payload
        # sub-map, so it nests directly under the tool-call payload.
        payload["policy"] = dict(policy)

    return writer.append({"actor": actor, "event": MCP_TOOL_CALL_EVENT, "payload": payload})


class MCPAuditMiddleware:
    """Bind a `Writer` and audit MCP tool-calls against it.

    Not thread-safe on its own — the underlying `Writer` serialises appends,
    but if you share one middleware across threads, guard it as you would the
    writer.
    """

    def __init__(
        self,
        writer: Any,
        *,
        actor: str = "mcp:client",
        redact: _Redactor | None = None,
        max_summary_chars: int = DEFAULT_MAX_SUMMARY_CHARS,
    ) -> None:
        self._writer = writer
        self._actor = actor
        self._redact = redact
        self._max = max_summary_chars

    def record_call(
        self,
        tool: str,
        arguments: Any = None,
        result: Any = None,
        *,
        error: Any = None,
        policy: Mapping[str, Any] | None = None,
        actor: str | None = None,
    ) -> int:
        """Record a single tool-call. Thin binding over :func:`audit_tool_call`."""
        return audit_tool_call(
            self._writer,
            tool=tool,
            arguments=arguments,
            result=result,
            error=error,
            actor=actor if actor is not None else self._actor,
            policy=policy,
            redact=self._redact,
            max_summary_chars=self._max,
        )

    def instrument(
        self, tool: str | None = None, *, policy: Mapping[str, Any] | None = None
    ) -> Callable[[_F], _F]:
        """Decorator: audit every call of a tool function.

        Records the positional/keyword arguments and the return value on
        success, or the exception on failure — then re-raises so the tool's
        own error handling is unchanged. ``tool`` defaults to the wrapped
        function's ``__name__``.
        """

        def decorate(func: _F) -> _F:
            name = tool if tool is not None else getattr(func, "__name__", "tool")

            @functools.wraps(func)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                call_args = {"args": list(args), "kwargs": kwargs}
                try:
                    value = func(*args, **kwargs)
                except Exception as exc:
                    self.record_call(
                        name,
                        arguments=call_args,
                        error={"type": type(exc).__name__, "message": str(exc)},
                        policy=policy,
                    )
                    raise
                self.record_call(name, arguments=call_args, result=value, policy=policy)
                return value

            return wrapper  # type: ignore[return-value]

        return decorate
