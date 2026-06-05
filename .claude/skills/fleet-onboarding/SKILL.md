---
name: fleet-onboarding
description: One-shot onboarding for the existing OgenticAI fleet — discover every active repo + Linear project, map repos to their owning projects, ensure factory labels exist, then bulk-install the factory into each repo through PRs (no direct pushes to main). Two human approval gates total, regardless of how many repos. Use once, when first adopting the factory across the org.
---

# Fleet onboarding

You are running this skill **once**, when the factory is first being adopted across the OgenticAI fleet. It is the bulk counterpart to `repo-bootstrap` (one repo) and `project-planner` (one project). Use it the day the factory goes live and never again.

After this run, growth happens organically: new repos via `repo-create`, new projects via `project-planner`, day-to-day work via `feature-factory`.

## §0 — Pre-flight (always run first)

Before anything else, invoke the `setup-check` skill. It verifies that:

- `gh` CLI is authenticated as `davidoladeji-ogenticai` (the org-admin account)
- The local git author email is an OgenticAI identity
- The SSH key for OgenticAI plugin pushes is present
- The current branch is sensible for this run

`setup-check` is fast (~1s) and halts with the exact fix if anything is off. If the operator sets `OGENTICAI_BYPASS_IDENTITY=1`, it short-circuits — only use that when the operator explicitly authorises it in chat. See `CLAUDE-FACTORY.md` §F5 for the full identity contract.

---

## When to invoke this skill

The operator said:
- "Get all our current projects and repos on board"
- "Onboard the fleet"
- "Run the factory across everything we already have"
- "Bulk-install the factory"

If the operator only wants one repo onboarded → use `repo-bootstrap`. If they only want one project shaped → use `project-planner`.

## What this skill does in one paragraph

It runs in **three phases** — Discover, Confirm, Apply — with one approval gate at the end of Confirm. It pulls the current state from GitHub (`OgenticAI/*` repos) and Linear (OGE team — projects, labels, active issues). It maps each repo to its primary Linear project **and surfaces orphan projects (Linear projects with no corresponding repo)** so the operator can decide which deserve a fresh codebase. It ensures the factory labels exist on the OGE team. It opens one PR per repo to install the factory (never pushes to `main` directly). For every orphan project approved as **needs-repo**, it chains into `repo-create` and then `repo-bootstrap`. It writes a single registry update PR on the `agent-factory` repo with `primary_project` filled in for every onboarded repo (existing and newly-created). It then prints a fleet dashboard.

## Phase 1 — Discover (read-only, no side effects)

Print a header to chat: `Discovering the fleet — read-only…`

### 1.1 Repos
- Call `gh repo list OgenticAI --limit 200 --json name,description,visibility,defaultBranchRef,isArchived,updatedAt,primaryLanguage`.
- Filter out: `isArchived=true` repos, repos whose `updatedAt` is older than 12 months and have `<5` commits in the last year (treat as dormant — report separately, do not onboard).
- For each active repo:
  - Check for existing `CLAUDE.md` at root (`gh api repos/OgenticAI/<name>/contents/CLAUDE.md` — 404 means no).
  - Check for existing `.claude/` directory (look for `.claude/CLAUDE-FACTORY.md` — 404 means no).
  - Classify: `clean` (no CLAUDE.md, no .claude/), `existing-claude-md` (has CLAUDE.md, no .claude/), `partial-factory` (has either .claude/CLAUDE-FACTORY.md or .claude/agents/), `fully-onboarded` (has both `CLAUDE-FACTORY.md` AND `agents/`).
- Cross-check against `kit/.claude/registry/repos.yml`: list any repo in the org but NOT in the registry, and any repo in the registry but NOT in the org.

### 1.2 Linear projects
- Call `linear.list_projects(team="OGE", state in ["Planned","Started","Paused"])`. Skip projects in `Completed`, `Cancelled`, `Archived`.
- For each project, count active issues (state in `[Backlog, Triage, Todo, "In Progress", "In Review"]`).
- Flag projects with **zero active issues** and **no updates in 60 days** — likely dormant, surface separately.

### 1.3 Labels
- Call `linear.list_issue_labels(team="OGE")`.
- Check for each required factory label:
  - `factory-in-progress`
  - `needs-story-approval`
  - `needs-brief-approval`
  - `building`
  - `validator-blocked`
  - `security-blocked`
  - `compliance-blocked`
  - `cross-repo`
  - `from-validator`
  - `from-security`
  - `from-compliance`
  - `from-project-planner`
  - `from-factory`
- Build a list of `missing_labels` to create in Phase 3.

### 1.4a Orphan projects (Linear without a repo)

After §1.1 + §1.2, compute the **inverse map**: which Linear projects in §1.2 don't appear as a `primary_project` candidate for any active repo in §1.1?

For each orphan project:
- Read its description + last 20 issues' titles.
- Classify it as one of:
  - `code-shaped` — issues mention features, endpoints, services, UI, builds. Suggests there should be a repo.
  - `ops-or-research` — issues are research notes, vendor evaluations, hiring threads, ops checklists. Code-less by design; do NOT create a repo.
  - `existing-but-unmapped` — issues clearly reference one of the existing repos by name. Suggest mapping instead of creating.

Hold this set for Phase 2.

### 1.4 Output — the discovery dashboard

Post this to chat (use mono spacing, one row per repo):

```
FLEET DISCOVERY
============================================================
GitHub:  <N> active repos in OgenticAI/  ·  <M> archived/dormant (skipped)
Linear:  <P> active projects in OGE team ·  <Q> dormant (separate list)
Labels:  <K> of 13 factory labels missing (will create in Apply)

REPOS — current state vs. factory
----------------------------------------------------------------
NAME                       STATE                  STACK         OWNER
ogentic-audit              clean                  rust-lib      David
agent-reviewer             existing-claude-md     nextjs-ts     David
sotto-desktop              partial-factory        tauri-rust    David
agent-knowledge            existing-claude-md     fastapi-py    David
…
zashboard-ultimate         clean                  nextjs-ts     David
----------------------------------------------------------------
<TOTALS>:  clean: N1  ·  existing-claude-md: N2  ·  partial-factory: N3  ·  fully-onboarded: N4

LINEAR PROJECTS (active)
----------------------------------------------------------------
NAME                              STATE      ISSUES   LAST UPDATE
Agent DealSizer v3                Started      42       2 days ago
Covenant Monitor pilot            Started      18       1 day ago
Ogentic-Audit OSS Wave 1          Planned       7       5 days ago
…
----------------------------------------------------------------

REGISTRY DRIFT
----------------------------------------------------------------
In GitHub but NOT in kit/.claude/registry/repos.yml:
  - <repo>      (will add)
In registry but NOT in GitHub:
  - <repo>      (will remove; archived? deleted?)
----------------------------------------------------------------

DORMANT (skipped — surface only)
----------------------------------------------------------------
Repos:    <list>      Linear projects:  <list>

ORPHAN PROJECTS (active in Linear, no repo mapping)
----------------------------------------------------------------
NAME                              CLASSIFICATION         ACTIVE ISSUES
Therapy onboarding rebuild        code-shaped                  6
Quarterly partner research        ops-or-research              4
DealSizer mobile prototype        code-shaped                  3
Audit OSS extraction              code-shaped                  2
Hiring — Q3 senior backend        ops-or-research              5
DealSizer pricing refresh         existing-but-unmapped (agent-dealsizer)   3
----------------------------------------------------------------
```

Halt here. Do not advance.

## Phase 2 — Confirm (operator approves the mapping)

For each **active** repo, propose its `primary_project` based on:
1. Name similarity (e.g., `agent-knowledge` → "Knowledge Agent" project, `agent-reviewer` → "Reviewer Agent" project).
2. Active-issue keyword overlap (call `linear.list_issues(project=<p>, limit=50)` and check repo name occurrences in titles).
3. Falls back to operator decision if ambiguous.

Post a single mapping table:

```
PROPOSED REPO → PRIMARY PROJECT MAPPING
============================================================
REPO                          →  LINEAR PROJECT                          CONFIDENCE
ogentic-audit                 →  Ogentic-Audit OSS Wave 1                high
agent-reviewer                →  Agent Reviewer                          high
agent-knowledge               →  Agent Knowledge                         medium  ← ambiguous, two candidates
sotto-desktop                 →  Sotto Desktop pilot                     high
zashboard-ultimate            →  Internal Ops                            low    ← guessed, please confirm
…
============================================================

PROPOSED FACTORY-LABEL CREATIONS (on OGE team)
- factory-in-progress  (#7C3AED)
- needs-story-approval (#F59E0B)
- needs-brief-approval (#F59E0B)
- building             (#3B82F6)
- validator-blocked    (#DC2626)
- security-blocked     (#DC2626)
- compliance-blocked   (#DC2626)
- cross-repo           (#475569)
- from-validator       (#94A3B8)
- from-security        (#94A3B8)
- from-compliance      (#94A3B8)
- from-project-planner (#94A3B8)
- from-factory         (#94A3B8)
(labels already present are omitted)

PROPOSED ORPHAN-PROJECT ACTIONS
----------------------------------------------------------------
ORPHAN                              SUGGESTED ACTION                              CONFIDENCE
Therapy onboarding rebuild          A. repo-create → new repo `therapy-onboarding`     high
DealSizer mobile prototype          A. repo-create → new repo `dealsizer-mobile`       high
Audit OSS extraction                A. repo-create → new repo `audit-rs` (oss-library) medium
DealSizer pricing refresh           B. map to existing repo `agent-dealsizer`          high
Quarterly partner research          C. leave as ops-only project (no repo)             —
Hiring — Q3 senior backend          C. leave as ops-only project (no repo)             —
----------------------------------------------------------------

For each orphan, the operator may edit the action:
  - A:<repo-name> [stack] [kind]    create a new repo via repo-create
  - B:<repo-name>                   map to an existing repo (registry only)
  - C                               leave as ops-only project
  - skip                            defer to a later run

PROPOSED PER-REPO ACTION
----------------------------------------------------------------
clean repos          →  open install PR: full kit (CLAUDE.md + .claude/)
existing-claude-md   →  open install PR: drop .claude/ only (append @import line to CLAUDE.md)
partial-factory      →  open install PR: fill in what's missing (do NOT overwrite existing files)
fully-onboarded      →  skip; verify only
new repos (from A)   →  spin up via repo-create, then drop the full kit in the initial commit
----------------------------------------------------------------

REGISTRY UPDATE PR ON agent-factory:
- Add missing repos: <list>
- Remove stale entries: <list>
- Fill primary_project for every repo per the mapping above.

NOTHING HAS BEEN CHANGED YET.

Approve to apply:
  /approved              — run Phase 3 as drafted
  /approved with edits:  — list changes, then apply
  /cancel                — discard
```

Halt. Wait for explicit approval. Do not silently re-attempt.

## Phase 3 — Apply (after approval, side effects begin)

Run in this order, halting on any failure:

### 3.0 Handle orphan projects FIRST

Process the orphan-project actions approved in Phase 2, in this order:

**Action A — repo-create.** For each orphan flagged `A:<name>`:
  1. Invoke the `repo-create` skill with: name, description (pulled from the Linear project), canonical stack + kind (operator-confirmed), visibility (`private` unless `oss-library`), owning Linear project = this orphan, initial team push grants (mirror the closest existing repo's grants).
  2. `repo-create` runs its own approval gate by default — in fleet mode, the operator's Phase-2 `/approved` covers them all. Pass a `--bulk-approved` flag to `repo-create` so it skips its internal checkpoint. (If `repo-create` doesn't expose that flag yet, run it interactively and accept one extra approval per orphan — note this in the dashboard.)
  3. Capture the new repo URL and add the orphan project's pairing to the in-memory mapping for §3.3.
  4. The new repo will be picked up by §3.2 as a `clean` repo on the same pass (the kit lands in the repo's initial commit via `repo-bootstrap`, which `repo-create` chains into automatically — so no extra install PR is needed for these).

**Action B — map to existing.** Add the orphan project as `primary_project` for the named existing repo in the registry PR (§3.3). No code changes, no install PR.

**Action C — leave.** Note the orphan in the final dashboard as `intentionally ops-only`. No registry write.

### 3.1 Create missing Linear labels (idempotent)
For each missing label, call `linear.create_issue_label(team="OGE", name=<n>, color=<hex>, description="Factory: …")`.

### 3.2 For each active repo — one install PR per repo

Loop in this order: alphabetical by repo name (so the dashboard is predictable).

For each repo:

1. **Clone** the repo into a scratch dir: `git clone git@github.com:OgenticAI/<name>.git /tmp/factory-onboarding/<name>`.
2. **Create branch**: `git checkout -b factory/onboard`.
3. **Detect the canonical stack** (re-use `repo-bootstrap` §1 detection logic) and tailor a CLAUDE.md template if and only if the repo is in `clean` state.
4. **Apply the per-state action:**
   - `clean` → drop the full kit: `cp -r <agent-factory-clone>/kit/CLAUDE.md ./CLAUDE.md` (after templating) + `cp -r <agent-factory-clone>/kit/.claude ./.claude`.
   - `existing-claude-md` → `cp -r <agent-factory-clone>/kit/.claude ./.claude` + append the import line:
     ```markdown
     
     ## Factory contract
     @./.claude/CLAUDE-FACTORY.md
     ```
   - `partial-factory` → diff what's there vs. the kit; only copy missing files. Never overwrite an existing file in `.claude/`. If `CLAUDE-FACTORY.md` is missing, copy it. If individual agent files are missing, copy them. If `CLAUDE.md` lacks the `@import` line, append it.
   - `fully-onboarded` → skip the file changes; only verify the hooks are wired and skip to step 7.
5. **Commit**: `git add -A && git commit -m "feat(factory): onboard via fleet-onboarding\n\nInstalled .claude/ kit and (where applicable) appended factory-contract import to CLAUDE.md. Generated automatically by fleet-onboarding. Review the diff carefully — particularly the tailored CLAUDE.md if this repo was 'clean'."`
6. **Push branch**: `git push -u origin factory/onboard`.
7. **Open PR**: `gh pr create --base main --head factory/onboard --title "Onboard <repo> to the OgenticAI Software Factory" --body "<see body template below>"`.
8. Record the PR URL and the resulting state.

PR body template:

```
This PR onboards `<repo>` to the OgenticAI Software Factory.

What's inside:
- `.claude/CLAUDE-FACTORY.md` (factory contract — additive partial)
- `.claude/LINEAR-INTEGRATION.md` (state-machine contract for OGE tickets)
- `.claude/agents/` (15 agent definitions)
- `.claude/skills/` (orchestrator skills)
- `.claude/hooks/` (pre-commit secrets blocker, pre-push checks)
- `.claude/registry/repos.yml` (multi-repo registry)
<if clean: + `CLAUDE.md` (tailored to detected stack)>
<if existing-claude-md: + one-line import added to existing CLAUDE.md>

What's NOT changed:
- Source code
- Existing tooling
- CI/CD config (the hooks are local, not Actions)

After merge:
- Open Claude Desktop on this repo and type `> Build OGE-<ticket> through the factory`.
- The factory will respect this repo's `CLAUDE.md` rules and the LINEAR-INTEGRATION contract.

Reviewers: please skim the diff and merge if it looks right. No code is altered.
```

### 3.3 Registry update — one PR on agent-factory

Back in the `agent-factory` working copy:

1. Branch: `factory/fleet-onboarding-registry-<YYYYMMDD>`.
2. Edit `kit/.claude/registry/repos.yml`:
   - Add any missing repos (from §1.1 drift report).
   - Remove any stale entries (only if confirmed by operator in Phase 2; otherwise skip).
   - Fill `primary_project: <project-id-or-slug>` for each entry per the approved mapping.
3. Commit + push branch + open PR titled `chore(registry): fleet-onboarding mapping <YYYYMMDD>` with a body listing every change.

### 3.4 Dashboard — one final post

```
✅ Fleet onboarding complete.

Labels created on OGE team:           N1
New repos created (from orphans):     Na →  <links>
Orphan projects mapped to existing:   Nb
Orphan projects intentionally left:   Nc
Install PRs opened across repos:      N2 →  <links>
Repos already fully onboarded:        N3  (verified, no PR)
Repos skipped (dormant):              N4
Registry update PR on agent-factory:  <link>

Next steps (suggested order):
1. Review and merge the per-repo install PRs — small, mechanical, safe to bulk-approve.
2. Merge the registry PR on agent-factory once the per-repo PRs are in.
3. Run `> Build OGE-<smallest-real-ticket> through the factory` in the most-active repo. Observe.
4. After 3 real runs, evolve the tailored CLAUDE.md in that repo with any "don't do this" rules the factory surfaces.
```

## Halt conditions

- Active `gh` account lacks `admin:org` or `repo` write across OgenticAI/* → halt; ask the operator to `gh auth switch`.
- Linear connectivity lost mid-Phase-3.1 → halt; created labels persist; resume from the next label on retry.
- A per-repo `git push` fails (branch protection, no write access to one specific repo) → halt that repo only, continue the rest; report the failure in the final dashboard.
- A repo has uncommitted changes pending in its default branch (rare in practice) → skip with a warning; the operator should clean it manually.
- An orphan project's classification is `code-shaped` but the operator declined to act (no A/B/C chosen) → halt for that orphan; note it as `unresolved orphan` in the final dashboard and continue the rest.
- Phase 2 not approved within the session → discard the discovery output; require re-run if resumed.

## What this skill is NOT

- Not for ongoing repo creation — that's `repo-create`.
- Not for ongoing project shaping — that's `project-planner`.
- Not idempotent in a useful way: rerunning Phase 3 after PRs are merged will mostly no-op (every repo will register as `fully-onboarded`), but the discovery dashboard alone is the value if you want a fleet-wide audit later.
- Not a substitute for human review — every install PR still needs a human merge.

## Cross-references

- Uses the same detection logic as `repo-bootstrap` §1.
- Uses the same install patterns as `repo-bootstrap` §3 + the additive partial pattern from `CLAUDE-FACTORY.md`.
- The registry it writes is the same one `multi-repo-coordinator` reads.
- The labels it creates are the same ones `feature-factory` §2 expects.
