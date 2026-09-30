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
7. **The agent's charter** — only if the target repo is a **new agent**. See §9.
8. **Smoke test.** Try committing a fake `.env` file. Confirm the pre-commit blocks it. Revert.
9. **Print the next-step checklist.**

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

## §9 — The agent's charter (new agents only)

Every agent enters through eight answers: the Agent Stack Playbook, section 7
(`internal-ops-agent/docs/standards/agent-stack-playbook.md`). Mission Control's Agent Builder
asks them for a fleet agent at `/fleet/new`. For a repo-backed agent this is where they are asked,
and the answers are written as a decision record in the agent's own repo, so the record travels
with the agent (OGE-2797).

1. **Ask the eight questions, verbatim, one at a time.** All eight need an answer. "TBD" is not one;
   if the operator cannot answer, stop and say which question is open.

   | # | Question |
   | --- | --- |
   | 01 Principal | Who does it serve? |
   | 02 Job | What job does it hold? |
   | 03 Incumbent | Who holds that job today, and why is that not enough? |
   | 04 Harnesses | Where does it run? |
   | 05 Memory | Where does its memory start and stop? |
   | 06 Tier | What sits behind approval? |
   | 07 Reporting | How do activity, failures and cost report? |
   | 08 Harm | Who could it harm, how, and what would they do about it? |

2. **Before question 03, show the agents already near this job.** Read the `scope:` of every entry
   in agentshub's `registry/teammate-agents.yml` and list each agent whose scope shares two or more
   meaningful words with this agent's job (one is enough when that scope is a single short line).
   Ignore filler such as "agent", "OgenticAI" and "team"; a shared division is not an overlap. Ask the
   operator to answer question 03 with that list in view. **Warn, never block**: an adjacent job is
   sometimes a real second agent. Mission Control computes its own list when the answers are filed
   there (step 4) and stores it with its record.

3. **If the agent already has a Mission Control row, stop here and file the answers on its Charter
   tab instead** (`/fleet/<agent-id>?tab=charter`). Mission Control delivers the record itself, by pull
   request. Writing the file here as well would give the repo two authors for one record.

   Otherwise, write `docs/decisions/0001-<agent-id>-charter.md` from the template below and commit it
   with the bootstrap. `<agent-id>` is the slug the agent will have in Mission Control (the same one its
   Slack token variable is named after), so the path matches what Mission Control writes.

4. **Once the bootstrap PR has merged AND the agent's registry row exists** (the playbook's Path B,
   step 5), file the same eight answers, word for word, on `/fleet/<agent-id>?tab=charter`:
   - The row must name this repo for records. If its `config.slack.repo` does not, set **Record repo** on
     the same tab; that changes where records go, never where the agent runs.
   - Mission Control finds the file on the default branch, records it as present and does not
     overwrite it. It checks that the file is there, not what it says, which is why the answers must be
     the same.
   - Filing before the bootstrap PR merges makes Mission Control open a competing PR for the same file.

   Until step 4, the `/fleet` sweep lists the agent as having no charter. That is intended: the sweep
   reads Mission Control, not repos.

**A filed record's answers are never edited.** When the agent's remit changes, file a new record on its
Charter tab. It becomes `0002`: Mission Control opens one PR that adds `0002-<agent-id>-charter.md` and
changes only the Status line of `0001` to Superseded.

The template, in the same shape Mission Control renders. Every answer line is quoted with `> `, and
any `&` or `<` in an answer is written as `&amp;` or `&lt;`, so an answer can never read as part of the
record's structure (raw HTML such as `</blockquote>` would end the quote on GitHub):

```markdown
# 0001. <Display name> charter

- Agent: `<agent-id>`
- Status: Accepted
- Date: <YYYY-MM-DD>
- Filed by: <operator email>

## Context

**01 Principal.** Who does it serve?

> <answer>

**03 Incumbent.** Who holds that job today, and why is that not enough?

> <answer>

Existing agents shown as overlapping when this was filed (question 03 was answered with these in view):

- `<other-agent-id>` (<division>) — <role or scope> — shared: <words>

## Decision

**02 Job.** What job does it hold?

> <answer>

**04 Harnesses.** Where does it run?

> <answer>

**05 Memory.** Where does its memory start and stop?

> <answer>

## Consequences

**06 Tier.** What sits behind approval?

> <answer>

**07 Reporting.** How do activity, failures and cost report?

> <answer>

**08 Harm.** Who could it harm, how, and what would they do about it?

> <answer>

---

Filed through repo-bootstrap (OGE-2797). This record is not edited. When the remit changes, a new record supersedes it.
```

If no agent overlapped, replace the overlap list with the line
`No existing agent was shown as overlapping when this was filed.` A multi-paragraph answer keeps a
bare `>` on its blank lines.

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

5. New agent only: once the bootstrap PR has merged and its registry
   row exists, file the same eight answers, word for word, at
   /fleet/<agent-id>?tab=charter. Mission Control finds
   docs/decisions/0001-<agent-id>-charter.md and does not overwrite it.
```

## Don't

- Don't overwrite an existing `.claude/` folder. If one exists, ask before merging.
- Don't auto-add the registry to git (it may reference private repos by URL).
- Don't enable factory-aware GitHub Actions automatically; that is a follow-up the human chooses.
- Don't drop the agent-scaffold `src/` over an existing agent's code; only scaffold a fresh repo.
- Don't edit a filed charter's answers in `docs/decisions/`. A changed remit is a new record that supersedes it, filed on the agent's Charter tab.
- Don't write `0001` here for an agent that already has a Mission Control row; its Charter tab delivers the record.
- Don't hand-write a raw `@anthropic-ai/sdk` / `@ai-sdk/*` / `openai` client in an agent — route every call through `@ogenticai/agent-core`, or the gate fails the build.
