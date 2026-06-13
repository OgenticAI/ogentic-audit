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

## 10. Clean Code standard (non-negotiable)

"Code is clean if it can be read and enhanced by a developer other than its original author." Apply Robert Martin's *Clean Code* — the validator enforces these (07, Point 15):

- **Small, single-purpose functions.** A function does one thing at one level of abstraction. If a block needs a comment to explain it, that block wants to be its own well-named function. Aim ≤ ~20–30 lines.
- **Intention-revealing, searchable names.** `elapsedDays`, not `d`. Verbs for functions (`postPayment`), nouns for types (`Invoice`). No `Manager`/`Data`/`tmp`/`genymdhms`; no disinformation (`accountList` that isn't a list).
- **≤ 3 arguments.** More wants a parameter object. No boolean flag-args that make one function do two things.
- **No hidden side effects.** A function named `isValid` does not also mutate state.
- **Code over comments.** Express intent in code; comments explain *why*, never restate *what*. Delete dead and commented-out code — git remembers it.
- **Errors, not sentinels.** Raise/throw or return a typed `Result`. Never return `null`/`None` to mean failure; never pass `null` where a value is expected.
- **SRP.** A module/class has one reason to change. Reuse before adding; no duplicated logic.
- **FIRST tests.** Fast, Independent, Repeatable, Self-validating, Timely (tests live next to code — §2).

**Clean-code checklist — run before you finish:**
- [ ] Each function does one thing and is small (≤ ~20–30 lines)?
- [ ] Every name reveals intent and is searchable?
- [ ] Comments justified (explain *why*); no dead/commented-out code left behind?
- [ ] ≤ 3 args, no flag-arguments?
- [ ] Errors raised/typed, never `null`-as-error?
- [ ] A failing test existed before the code that makes it pass?

## 11. Reach for the right skill

For a deeper pass, the operator/orchestrator can invoke the installed skills mapped per role in `.claude/SKILLS.md` — e.g. `/clean-code` and `/simplify` for any builder, `python-pro`/`fastapi-pro` for Python, `typescript-pro`/`nodejs-best-practices` for TS, `react-best-practices` for frontend, `rust-pro` for Rust. The standard above is the floor; those skills deepen it.
