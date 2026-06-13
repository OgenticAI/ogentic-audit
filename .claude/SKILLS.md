# SKILLS.md — factory skill audit & role → skill map

Which installed skills deepen each factory phase. **The Clean Code standard
(`skills/build-with-tests` §10) is the floor every builder must meet; the skills
below are the ceiling** — invoke them for a deeper pass.

> **Who invokes these.** Builder/reviewer *subagents* don't carry the `Skill` tool,
> so they can't call these mid-run. The **operator** (or the orchestrator between
> agents) invokes them — e.g. run `/clean-code` then `/simplify` on a builder's diff
> before the validator, or `/code-review` on the PR before Checkpoint 3. Treat this
> file as the menu, not an automatic step.

## Every builder (language-agnostic)
- **`clean-code`** — Uncle Bob principles; the source of `build-with-tests` §10.
- **`simplify`** (built-in) / **`simplify-code`** — reuse, dedup, altitude cleanups on the diff.
- **`code-review`** (built-in) — correctness + cleanup pass on the current diff before the validator.

## Python builder (04a)
- `python-pro`, `fastapi-pro`, `pydantic-models-py`, `async-python-patterns`

## TypeScript builder (04b)
- `typescript-pro`, `nodejs-best-practices`, `modern-javascript-patterns`

## Frontend builder (05)
- `react-best-practices`, `react-component-performance`, `senior-frontend`

## Rust builder (14)
- `rust-pro`, `rust-async-patterns`, `memory-safety-patterns`

## Test verifier (06)
- `test-driven-development`, `testing-patterns`

## Validator (07)
- `code-reviewer`, `code-review-excellence` — second opinion on structure/quality findings.

## Security reviewer (09)
- `backend-security-coder`, `frontend-security-coder`, `security-audit`, `security-review` (built-in)

## Library publisher (13)
- `python-packaging` (PyPI), language-native publish flows.

## Orchestrator / cross-cutting
- `architecture`, `senior-architect` — for spec-writer / cross-repo-coordinator design calls.
- `ogenticai-git` plugin (`/push`) — the org's git/PR flow.

---
_Audit basis: skills installed via the OgenticAI plugin marketplace as of 2026-06.
Names are the invocable skill slugs; some are plugin-namespaced (e.g.
`ant-development:code-reviewer`) — invoke by the short name your install exposes.
Re-audit when the marketplace changes._
