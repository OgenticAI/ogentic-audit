---
name: build-with-tests
description: The OgenticAI build standard. Every builder agent follows it. Use when any agent writes or edits source code in this repo.
---

# Build with tests — the OgenticAI build standard

This skill encodes how we write code at OgenticAI. Every builder agent (Python, TypeScript, Frontend) follows it. It is short on purpose.

## 1. Read before you write

Always start by reading the brief and the researcher's findings. If a similar feature already exists, read the file. Copy the pattern. The fastest path to consistency is to match what is already there.

## 2. Tests next to code

Tests are not optional. Tests are not "later". Tests live next to the code they test:

- `feature.ts` → `feature.test.ts` in the same folder
- `feature.py` → `test_feature.py` in the same folder

Every public function gets at least:
- One happy-path test
- One failure-path test (invalid input, unauthorised, dependency error)

Acceptance tests live in `tests/acceptance/` (web) or `services/ai/tests/acceptance/` (Python) and are written by the `test-verifier`, not by you.

## 3. The "before I finish" check

Before you stop, run the full check for your stack and confirm green:

**TypeScript:**
```
pnpm typecheck
pnpm lint --fix
pnpm test
```

**Python:**
```
uv run ruff check .
uv run mypy services/ai
uv run pytest services/ai
```

If any check is red, fix it. Do not finish red.

## 4. Match existing patterns

If the codebase uses a pattern, use it. Do not introduce a new pattern silently. If you think the existing pattern is wrong, surface that in your summary as a "patterns I would change" line — do not just go around it.

## 5. Tenant scoping is not optional

Every query that touches a tenant-scoped table filters by tenant. Derive the tenant from the authenticated principal, never from the request body. This rule is enforced by the validator.

## 6. Errors do not leak

Catch domain errors at the boundary (route handler / server action). Log with structured context. Return a sanitised message. Stack traces, DB errors, and provider responses never reach the client.

## 7. New dependencies require approval

If you need a new package, stop. Surface it as an open question. The brief should have named it. If it did not, the human gets to decide before you `pnpm add` or `uv add`.

## 8. Summary block at the end

Every builder ends its run with a structured summary (Python API summary, TS API summary, or Frontend summary — see the agent file). The downstream agents depend on it. No summary = the chain stalls.

## 9. Stay in your lane

If you are a backend builder and you find yourself opening a `.tsx` file to edit it: stop. That is the Frontend Builder's territory. Note it in your summary as a follow-up.
