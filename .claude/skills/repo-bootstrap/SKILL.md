---
name: repo-bootstrap
description: Install the OgenticAI Software Factory in a new repo. Drops the agents, the skills, the CLAUDE.md template, and the hooks. Use when adopting the factory in a repo for the first time.
---

# Repo bootstrap

Install the factory into a fresh OgenticAI repo.

## §0 — Pre-flight (always run first)

Before anything else, invoke the `setup-check` skill. It verifies that:

- `gh` CLI is authenticated as `davidoladeji-ogenticai` (the org-admin account)
- The local git author email is an OgenticAI identity
- The SSH key for OgenticAI plugin pushes is present
- The current branch is sensible for this run

`setup-check` is fast (~1s) and halts with the exact fix if anything is off. If the operator sets `OGENTICAI_BYPASS_IDENTITY=1`, it short-circuits — only use that when the operator explicitly authorises it in chat. See `CLAUDE-FACTORY.md` §F5 for the full identity contract.

---

## When to use

The user said:
- "Install the factory in [repo]"
- "Bootstrap this repo for the factory"
- "Set up the agents here"

## What this skill does

1. **Detect the stack.** Look for `package.json` (Node/TS), `pyproject.toml` (Python), `apps/` folders, `services/ai/`, `prisma/`, `alembic/`. Build a profile.
2. **Confirm with the operator.** Print the detected stack profile and ask: "Does this look right?" If anything is wrong, stop and ask.
3. **Copy the kit.** Drop into the repo root:
   - `.claude/agents/01-researcher.md` … `12-incident-responder.md`
   - `.claude/skills/feature-factory/SKILL.md`
   - `.claude/skills/build-with-tests/SKILL.md`
   - `.claude/skills/multi-repo-coordinator/SKILL.md`
   - `.claude/hooks/pre-commit`
   - `.claude/hooks/pre-push`
   - `.claude/registry/repos.yml.template`
   - `.claude/_factory-manifest.yml` — copied from `kit/_factory-manifest.template.yml`, with `synced_kit_sha`, `synced_kit_hash`, `synced_at`, and the per-file `content_sha256` list populated from the kit at install time. This is what the `propagate-factory-kit` workflow uses to detect local edits later. See `CLAUDE-FACTORY.md` §F6.
4. **Generate a tailored `CLAUDE.md`.** Start from the template. Pre-fill stack and commands based on what was detected. Leave the architecture-rules and don't-do sections for the human to flesh out.
5. **Install the hooks.** Make them executable; configure `git config core.hooksPath` if the repo uses a non-default hooks path; otherwise drop into `.git/hooks/` symlinks.
6. **Blessed agent scaffold** — only if the target repo is a **new agent**. See §8.
7. **Smoke test.** Try committing a fake `.env` file. Confirm the pre-commit blocks it. Revert.
8. **Print the next-step checklist.**

## §8 — Blessed agent scaffold (new agents only)

`kit/agent-scaffold/` is the governed application code a *new* agent starts from, pre-wired to `@ogenticai/agent-core` so Shield + Audit are enforced from line one (closes R-1 for every new agent; this is the R-13 "blessed scaffold").

Apply it when the target repo is a **new agent** — not when an existing app is adopting the factory. After copying the factory kit:

1. Copy `kit/agent-scaffold/*` into the repo root — **including dotfiles** (`.github/`, `.npmrc`, `.env.example`, `.gitignore`).
2. Substitute placeholders:
   - `package.json` → `name` = `@ogenticai/<repo-id>`.
   - `src/agent.ts` → `id`, `name`, `owner`, and `model.provider` / `model.model` (`anthropic` | `openrouter` | `ollama`).
3. `@ogenticai/agent-core` is already a dependency (`^0.1.0`), resolved from GitHub Packages via the scaffold's `.npmrc`. Install with a `read:packages` token: `export NODE_AUTH_TOKEN=<gh PAT>` then `npm install` (CI uses the built-in `GITHUB_TOKEN`).
4. Confirm the guardrail: `npm run gate` (`verify-agent-core-coverage`) passes and `npm test` (the governance smoke test) is green.

The operator gets an agent that is compliant by construction: one governed model path (`runtime` in `src/agent.ts`), the R-1 CI gate, the ESLint rule, a filled `CLAUDE.md`, and a passing governance smoke test — before a single line of custom logic is written.

## Output: the next-step checklist

After install, print this for the operator:

```
✅ Factory installed in <repo>.

Next steps (in this order):
1. Open .claude/CLAUDE.md and fill in:
   - Architecture rules specific to this repo
   - The "Don't do this" list (start small; grow it)
   - Pointers to deeper docs
   Target: 100–300 lines.

2. Open .claude/registry/repos.yml.template, rename to repos.yml,
   and add this repo plus any others it depends on or is depended on by.

3. Run one tiny feature through the factory. Pick something safe:
   - A copy change
   - A new admin button that calls an existing endpoint
   - A new internal metric
   Watch where the chain stumbles. Add the rules you wish CLAUDE.md had.

4. After 3 features, the factory will know this repo.
```

## Don't

- Don't overwrite an existing `.claude/` folder. If one exists, ask before merging.
- Don't auto-add the registry to git (it may reference private repos by URL).
- Don't enable factory-aware GitHub Actions automatically; that is a follow-up the human chooses.
- Don't drop the agent-scaffold `src/` over an existing agent's code; only scaffold a fresh repo.
- Don't hand-write a raw `@anthropic-ai/sdk` / `@ai-sdk/*` / `openai` client in an agent — route every call through `@ogenticai/agent-core`, or the gate fails the build.
