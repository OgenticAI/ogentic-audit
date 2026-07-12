---
name: feature-factory
description: Master orchestrator for the OgenticAI Software Factory. Runs the full chain from a Linear ticket (or a free-form ask) to a PR-ready code change, with three human checkpoints and full Linear state sync. Use when David wants to ship a feature end-to-end with the agent team.
---

# Feature Factory

You are orchestrating the OgenticAI Software Factory. Twenty specialised agents (plus a scheduled backlog-groomer). Three human checkpoints (plus a design gate for UI work). One coordinated pipeline. **Linear is the source of truth** — every run is grounded in a Linear ticket, and every artefact flows back to that ticket.

## §0 — Pre-flight (always run first)

Before anything else, invoke the `setup-check` skill. It verifies that:

- `gh` CLI is authenticated as `davidoladeji-ogenticai` (the org-admin account)
- The local git author email is an OgenticAI identity
- The SSH key for OgenticAI plugin pushes is present
- The current branch is sensible for this run

`setup-check` is fast (~1s) and halts with the exact fix if anything is off. If the operator sets `OGENTICAI_BYPASS_IDENTITY=1`, it short-circuits — only use that when the operator explicitly authorises it in chat. See `CLAUDE-FACTORY.md` §F5 for the full identity contract.

---

## §0.5 — Headless mode (auto-loop driver)

When the env var `FACTORY_HEADLESS=true` is set (the multi-repo auto-loop driver sets this in `auto-loop/scripts/per_repo_run.sh`), the three human checkpoints in §2 are replaced by **programmatic gates**. The chain runs to completion without operator approval; failures escalate to a `needs-human-review` label instead of blocking on a wait.

**Headless mode trigger.** The orchestrator MUST check `os.environ.get("FACTORY_HEADLESS")` (or the equivalent shell `$FACTORY_HEADLESS`) at the start of every run. If `true`, skip every "wait for /approved" block in §2 and use the gate replacements below.

### Programmatic gate replacements

| Old human gate (§2) | Headless replacement |
| --- | --- |
| **Checkpoint 1 — story approval** | Linear ticket must have label `auto-eligible` AND `description.length >= 200` AND contain ≥1 acceptance criterion (a line matching `Acceptance criteria` / `AC:` / a numbered `1.` list under that header). |
| **Checkpoint 2 — brief approval** | spec-writer's brief must (a) pass the project's `gate_lint` + `gate_typecheck` from `factories.yml`, and (b) include both a `Files` section and an `Acceptance criteria` section. Heuristic-graded. |
| **Checkpoint 2.5 — design approval** (UI tickets only) | No human eyeballing of mockups. `design-architect` still writes the dossier under `design/<OGE-xxx>/` and proceeds; the fidelity loop is enforced *after* the build by **design-fidelity-checker** (§2 step 17), which renders the implementation and diffs it against that dossier + the Claude Design export. A Critical fidelity mismatch escalates like any reviewer (`design-fidelity-blocked` → `needs-human-review` + `FACTORY_BLOCKED`). Non-UI tickets skip this row entirely. |
| **Checkpoint 3 — PR approval** | **CI green + branch protection.** PR opens with `gh pr merge --auto --squash`; auto-merge fires on green. If CI red after 3 retries, escalate. |

### Escalation pattern (used by all three gates)

Whenever a programmatic gate FAILS in headless mode, the chain MUST:

1. Add Linear label `needs-human-review` to the ticket.
2. Post a `[factory:auto-loop]` comment explaining which gate failed and why.
3. Emit the final sentinel `FACTORY_BLOCKED <ticket-id> <reason>` so `per_repo_run.sh` records exit 2 (blocked, not crashed).

The ticket then sits in the operator's queue. The loop won't pick it up again until David either removes `needs-human-review` or the gate-failure cause is fixed.

### Per-agent headless behaviour

- **story-writer** — in headless mode, skip the "wait for approval" block; emit `[factory:story-writer] DONE — AC count: N` and continue.
- **spec-writer** — same; emit `[factory:spec-writer] DONE — brief posted, Files: N, AC: N` and continue. If the brief fails the heuristic compile-clean check, follow the escalation pattern above.
- **release-manager** — open the PR with `gh pr merge --auto --squash` instead of waiting for operator merge. On CI red after 3 retries, escalate.

When `FACTORY_HEADLESS=false` (default), the existing operator-driven behaviour described in §2 is unchanged.

---

## When to invoke this skill

The user said something like:
- "Run OGE-123 through the factory"
- "Build OGE-123"
- "Ship the feature in OGE-456"
- "Build feature X" (with no ticket — see §3 below)
- "Add support for Y" / "Implement Z" with a Linear context

If they ask for a quick fix or a one-off question with no production impact, do not engage the factory — answer directly.

## 1. Kickoff — three forms accepted

### Form A: Ticket ID (preferred)
```
> Build OGE-123 through the factory.
```
- Parse the ticket ID. Confirm format `OGE-\d+` (or your team's prefix).
- Call `linear.get_issue(OGE-123)` and `linear.list_comments(OGE-123)`. If not found, halt and ask.
- Check the ticket's current state. If `Done` or `Canceled`, halt and ask whether to reopen.
- If any of these labels are already present — `factory-in-progress`, `needs-story-approval`, `needs-brief-approval`, `building` — there is a prior run in flight. Halt and ask whether to resume from the last completed step or to restart.

### Form B: Free-form ask, no ticket
```
> Add invoice reminders for unpaid > 7d.
```
- Draft a ticket title (short, imperative — "Invoice reminders for unpaid > 7 days").
- **Project decision — see §9 first.** If the ask doesn't fit an existing project, halt and ask whether to create a new one (do not silently invent a project).
- If §9 says "fits an existing project", pick that project (default: the repo's primary project per `.claude/registry/repos.yml`; ask if more than one candidate).
- Call `linear.save_issue` to create the ticket in `Backlog`, assigned to David, with the ask as the body.
- Post back to chat: "Created OGE-xxx in project <name>. Proceeding."
- Continue as Form A.

### Form C: Resume in flight
```
> Continue OGE-123.
```
- Read the ticket's labels + comment history to determine the last completed step.
- Resume from the next agent. Confirm with David before re-running an agent whose comment is already present.

## 2. The chain

Linear-grounded, with state transitions and labels noted next to each step.

```
[STATE: Backlog]
1. researcher
     - reads OGE-123 (description, comments, linked tickets)
     - searches linear.list_issues for similar features (last 60d)
     - posts findings comment
     - moves state → "In Progress", adds label "factory-in-progress"
        ↓
2. story-writer
     - reads ticket + researcher findings
     - REWRITES ticket description with the formal user story + ACCEPTANCE CRITERIA AS CHECKBOXES
     - posts comment with link to original description (preserved)
     - adds label "needs-story-approval"
        ↓
⏸ CHECKPOINT 1
     - operator approves by replying to the Linear ticket: "/approved", or by removing the "needs-story-approval" label
     - orchestrator polls / waits
     - on approval: remove label, proceed
        ↓
3. spec-writer
     - reads approved story (description) + researcher findings + CLAUDE.md
     - posts brief as a comment (or Linear document if >2000 words, linked from the ticket)
     - flags multi-repo work — if found, adds label "cross-repo" and hands off to cross-repo-coordinator instead of normal chain
     - adds label "needs-brief-approval"
        ↓
⏸ CHECKPOINT 2
     - operator approves
        ↓
16. design-architect            (if brief lists user-facing UI)
     - reads approved brief + tokens (packages/config-tailwind) + packages/ui + ADR-0003 + PRD
     - generates Claude Design mockups + component map; writes them under design/<OGE-xxx>/
     - renders them (Claude Preview / screenshots) so review is possible
     - posts design dossier comment; adds label "needs-design-approval"
        ↓
⏸ CHECKPOINT 2.5 — operator approves design (skipped for non-UI tickets)
     - operator approves; remove "needs-design-approval"; pass dossier + mockup paths to frontend-builder
     - HEADLESS: no wait; the dossier is the fidelity contract that design-fidelity-checker
       (step 17) enforces against the built UI after frontend-builder — see §0.5
        ↓
4a/4b/14. backend builders — FAN-OUT via Workflow.parallel() when ≥2 stacks touched

     The spec's "Stacks touched" line (or an equivalent signal) determines
     which backend builders to invoke. The orchestrator MUST inspect this
     before dispatching.

     Single-stack spec (one of python / ts / rust):
       Invoke just the one relevant builder. No parallel() ceremony.

     Multi-stack spec (any combination of python + ts + rust):
       Dispatch the relevant builders concurrently:
         ```
         results = Workflow.parallel([
           *([lambda: invoke("backend-builder-python",     context=python_slice)]
             if "python" in stacks_touched else []),
           *([lambda: invoke("backend-builder-typescript", context=ts_slice)]
             if "ts" in stacks_touched else []),
           *([lambda: invoke("rust-builder",              context=rust_slice)]
             if "rust" in stacks_touched else []),
         ])
         ```
       Each builder receives its own slice of the spec (the section of the
       brief that pertains to its stack). Each posts its own API summary
       comment. The first builder to be dispatched adds label "building" and
       removes "needs-brief-approval" (idempotent — if both fire near-
       simultaneously, last-write-wins on the label, which is harmless).

     Overlap / file-scope guard (Tauri repos):
       rust-builder and backend-builder-python may both write into crates/
       in a Tauri repo (e.g. Sotto Desktop). Before dispatching the parallel
       fan-out, the orchestrator MUST check whether two builders would target
       the same path. If they would, fall back to serial with python first:
         1. backend-builder-python (writes its crates/ output)
         2. backend-builder-typescript (parallel is safe if no overlap)
         3. rust-builder (reads python's output before writing its own crates/)
       Call out the fall-back in the ticket comment:
         "[factory:orchestrator] Falling back to serial builder order — rust
          and python both write crates/; parallel fan-out skipped to prevent
          path conflicts."

5.  frontend-builder            (if brief lists frontend work)
     - ALWAYS runs AFTER all backend builders complete (UI depends on the
       API surface published by the backend API summary comments)
     - posts its own API summary as a comment
     - does NOT run in the backend parallel() fan-out
        ↓
17. design-fidelity-checker     (if the ticket has user-facing UI)
     - renders the IMPLEMENTED UI (Claude Preview MCP) and diffs it against the
       design-architect dossier (design/<OGE-xxx>/) + the Claude Design export:
       verbatim copy, real (non-invented) data, tokens/components, all four states
     - on Critical fidelity mismatch: label "design-fidelity-blocked", sub-issues
       "from-design-fidelity"; loops back to frontend-builder with the deltas
     - this is the enforcement half of Checkpoint 2.5; skipped for non-UI tickets
        ↓
6. test-verifier
     - writes acceptance tests against the story's checkboxes
     - posts pass/fail per criterion; updates the description's checkboxes accordingly
     - REJECTS false-green tests (existence-only / assertion-free /
       config-not-behaviour / boundary-mock) — those criteria stay unchecked
     - on fail: routes to the right builder via a comment; loops
        ↓
8. ai-eval-engineer  (only if feature touches LLMs)
     - posts scorecard
        ↓
7/9/18/19/15. reviewer panel — FAN-OUT via Workflow.parallel()
     Reviewers dispatched concurrently; each gets the same context
     (story + spec + diff). Results awaited, then synthesized into one
     severity-grouped report before the human checkpoint.

     Reviewers in the panel:
       7.  validator          — always invoked
       9.  security-reviewer  — always invoked
       18. deploy-fitness-reviewer — always invoked; SELF-SKIPS (reports N/A) if
                                 the repo is not a serverless/edge deploy target.
                                 Safe to dispatch unconditionally.
       19. monorepo-consistency-reviewer — always invoked; SELF-SKIPS (reports
                                 N/A) if the repo is not an apps/* + packages/*
                                 monorepo. Safe to dispatch unconditionally.
       15. compliance-reviewer — only if repo imports ogentic-shield or
                                 ogentic-audit (preserve existing conditional;
                                 do NOT make compliance unconditional)

     Fan-out instruction (orchestrator MUST follow):
       ```
       findings = Workflow.parallel([
         lambda: invoke("validator",                    context=review_context),
         lambda: invoke("security-reviewer",            context=review_context),
         lambda: invoke("deploy-fitness-reviewer",      context=review_context),
         lambda: invoke("monorepo-consistency-reviewer", context=review_context),
         # compliance is conditional:
         *([lambda: invoke("compliance-reviewer", context=review_context)]
           if imports_shield_or_audit else []),
       ])
       ```
       deploy-fitness and monorepo-consistency are dispatched every run — they
       decide their own relevance and return N/A cheaply when they don't apply,
       so the orchestrator needs no conditional for them (unlike compliance).
       Then synthesize: collect all findings, group by severity (Critical →
       High → Medium → Low → Informational), and post one combined
       "[factory:reviewer-panel] Review complete" comment on the ticket
       before proceeding to the human checkpoint.

     Loop-back rule: if any reviewer returns Critical findings, route to the
     specific builder named in the finding's file:line, re-run the full panel
     after the fix (another parallel() fan-out), up to two consecutive
     all-Critical rounds before escalating.

     Labels:
       - Critical from validator   → "validator-blocked"   + sub-issue "from-validator"
       - Critical from security    → "security-blocked"    + sub-issue "from-security"
       - Critical from deploy-fit   → "deploy-blocked"      + sub-issue "from-deploy-fitness"
       - Critical from consistency  → "consistency-blocked" + sub-issue "from-consistency"
       - Critical from compliance   → "compliance-blocked"  + sub-issue "from-compliance"
       - All Clean                 → remove those labels if present
        ↓
       PR opens (built off the Linear branch name)
       Linear auto-moves state → "In Review"
        ↓
⏸ CHECKPOINT 3 — operator approves PR
        ↓
       PR merges → Linear auto-moves to "Done"
        ↓
10. release-manager
     - posts release plan + deploy timestamps + customer-facing note
     - state stays "Done" (release happens in a Done ticket)
     - on regression: hands off to incident-responder
        ↓
13. library-publisher  (only if repo kind=oss-library in registry)
     - semver bump, changelog, sign, publish, smoke-import test
     - posts publish status comment
```

## 3. Cross-repo handoff

If the Spec Writer's brief lists changes across more than one repo (per `.claude/registry/repos.yml`):

- Spec Writer adds label `cross-repo` to the parent ticket.
- Orchestrator hands off to **cross-repo-coordinator** instead of the normal builder chain.
- Coordinator creates one Linear sub-issue per affected repo, linked to the parent. Same branch name in every repo (from the Linear branch convention).
- Each sub-issue runs its own feature-factory pass with the sliced sub-brief.
- Parent ticket stays in `In Progress` with label `factory-in-progress` until all sub-issues are validator-clean.
- One combined Security + Compliance review on the union diff before Checkpoint 3.
- Release Manager sequences deploys per repo dependency order from the registry.

## 4. Orchestration rules

- **One agent active at a time** on any given path, except for the two sanctioned parallel() fan-outs: the reviewer panel (§2 step 7/9/18/19/15) and the multi-stack builder fan-out (§2 steps 4a/4b/14). Both are explicit Workflow.parallel() calls — no other ad-hoc parallelism. (design-fidelity-checker, step 17, runs serially before test-verifier — it needs the rendered UI and gates the acceptance tests, so it is not part of the panel.)
- **Every agent gets the ticket ID** as its first input, alongside any artefacts it needs. Never paste the whole conversation.
- **Every agent ends with a `[factory:<agent>]` comment on the ticket** in the standard format (see `LINEAR-INTEGRATION.md` §2/§4). The agent **returns the comment body**; **the orchestrator posts it as the factory bot** via `.claude/scripts/factory-linear-comment.sh --issue <OGE-ID> --body <markdown>` (`LINEAR_FACTORY_TOKEN`) — **never `linear.save_comment`** (authors as the human operator). Same for the §5 final telemetry comment.
- **Every agent owns its state transitions and labels.** No agent flips a state it does not own. See LINEAR-INTEGRATION §3.
- **At each checkpoint**, present the artefact in chat AND on the ticket. Don't auto-advance. The operator's approval can be in chat ("/approved") or on the ticket (removing the `needs-X-approval` label).
- **Any reviewer can loop builders.** Validator, security-reviewer, compliance-reviewer, design-fidelity-checker, deploy-fitness-reviewer, and monorepo-consistency-reviewer all route Critical findings to the specific agent named in the finding's `file:line` (fidelity findings → frontend-builder). Re-run the reviewer after the fix. The conditional reviewers self-skip when they don't apply (deploy-fitness on non-serverless repos, monorepo-consistency on single-app repos, design-fidelity on non-UI tickets) — they report `N/A` and never block.
- **Halt conditions**:
  - Operator disapproval at any checkpoint
  - An agent unable to proceed without an answer (post the question as a ticket comment; halt)
  - Two consecutive validator runs with the same Critical (the fix is structural — escalate)
  - Linear connectivity lost → degraded mode (see LINEAR-INTEGRATION §9); halt if also losing source-control tools
- **No factory run without a Linear ticket.** If Linear is fully unavailable, halt; do not run blind.

## 5. The "what just happened" telemetry

After every successful run, post one final comment on the ticket:

```
[factory:orchestrator] Run complete.

Timeline:
- 2026-05-29 09:01Z — kicked off
- 2026-05-29 09:08Z — Checkpoint 1 approved
- 2026-05-29 09:42Z — Checkpoint 2 approved
- 2026-05-29 11:24Z — first validator pass clean
- 2026-05-29 11:30Z — security review clean
- 2026-05-29 11:34Z — PR #482 opened
- 2026-05-29 12:50Z — PR merged
- 2026-05-29 13:01Z — released to prod

Agents engaged: researcher, story-writer, spec-writer, backend-builder-ts, frontend-builder,
                test-verifier, validator, security-reviewer, release-manager
Sub-issues opened: OGE-451 (from-validator, deferred)

CLAUDE.md updates suggested:
- Add rule: "manual trigger endpoints must derive tenant from session, never request body"
```

Use this comment to evolve CLAUDE.md in your next session.

## 6. Opening prompt template

When the user kicks off a run, reply:

> Engaging the OgenticAI Software Factory for **OGE-123 — <title>**.
>
> Three human checkpoints ahead — I'll pause at each, on the ticket and in chat.
>
> Starting the researcher (read-only). State moves to "In Progress" now.

Then invoke `researcher`.

## 7. Closing prompt template

When the chain completes:

> Run complete on **OGE-123**.
> - PR: #482 (merged)
> - Release: live as of 2026-05-29 13:01Z
> - Sub-issues opened: OGE-451
> - Full run history on the Linear ticket.

## 8. What this skill is NOT

- Not for one-off bugfixes that don't need a story → use `incident-responder` directly (it still creates a Linear ticket).
- Not for refactors with no user-visible behaviour → lighter chain: researcher → spec-writer → builders → validator. Story is implied; criteria are the test list.
- Not for docs-only PRs → write them, attach to a `docs-` labelled ticket.
- Not without a Linear ticket. Ever.

## 9. When to create a new Linear project (vs. drop the issue into an existing one)

The factory's home is **an existing Linear project**. New projects are a human decision in spirit — but the factory should *pause and ask* when the ask doesn't obviously fit, instead of silently dropping a stray issue into the wrong project.

### 9.1 Default behaviour

For any free-form ask (Form B kickoff), pick the **most specific existing project** that fits, using this preference order:

1. The project named in `.claude/registry/repos.yml` under the current repo's `primary_project` field, if present.
2. The active project whose recent issues most closely match the ask's domain (search `linear.list_issues` last 60d for keyword overlap).
3. The repo's catch-all maintenance project (e.g. `<product>-platform`, `<product>-ops`).

If exactly one candidate scores clearly, use it. If two or more are close, ask the operator before choosing.

### 9.2 When to halt and propose a NEW project

Stop and ask the operator before creating any issue if the ask trips **two or more** of these:

| Signal | What it looks like |
| --- | --- |
| **New product surface** | The ask names a customer/persona/surface that isn't represented by any current project (e.g. a brand-new vertical, a new app, a new external integration). |
| **Multi-cycle scope** | The ask reads like an initiative, not a ticket — it implies five or more child issues spread across cycles, with its own success metric. |
| **OSS / library carve-out** | The ask is to extract code into a new published library or to open-source something internal. Libraries live in their own projects (and usually their own repos — see `repo-create`). |
| **New customer segment** | The ask is scoped to a paying customer or pilot that doesn't yet have a dedicated project. |
| **Distinct success metric** | The ask comes with its own KPI (north-star, retention, MRR slice) that no current project owns. |
| **Cross-team ownership** | The work spans more than one engineer's domain in a way that benefits from a shared roadmap, not a single ticket. |

If two or more fire, post in chat:

> The ask **<short title>** doesn't fit any current project cleanly. I see signals: <list-the-signals-that-fired>.
>
> Options:
> - **A.** Create a new Linear project: `<proposed-name>` (description, owner, milestones to follow). Use the `project-planner` skill.
> - **B.** Park it inside `<closest-existing-project>` for now and revisit if scope grows.
> - **C.** It's actually a one-off issue — drop it into `<existing-project>`.
>
> Which do you want?

Do not proceed until the operator picks. If they pick A, hand off to the `project-planner` skill. If B or C, continue Form B.

### 9.3 When NOT to create a new project

- The ask is a single ticket that happens to be larger than usual — issues can scale; projects are about *containers of related work*.
- The ask is a bugfix or refactor inside an existing surface — it belongs to whichever project already owns that surface.
- The ask is "we should also do X" raised mid-run — that's a sub-issue (use the validator/security pattern: `from-<source>` label, link to parent), not a new project.

### 9.4 Telemetry

When you halt for a project decision and the operator chooses A (new project), record it in the ticket-less chat trail like this so the decision is auditable:

```
[factory:orchestrator] Project decision — created new project "<name>" via project-planner. Trigger signals: <list>.
```

If the operator picks B or C, post a one-line note in chat (no ticket exists yet) and then continue Form B with that project.
