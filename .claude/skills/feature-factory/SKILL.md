---
name: feature-factory
description: Master orchestrator for the OgenticAI Software Factory. Runs the full chain from a Linear ticket (or a free-form ask) to a PR-ready code change, with three human checkpoints and full Linear state sync. Use when David wants to ship a feature end-to-end with the agent team.
---

# Feature Factory

You are orchestrating the OgenticAI Software Factory. Fifteen specialised agents. Three human checkpoints. One coordinated pipeline. **Linear is the source of truth** — every run is grounded in a Linear ticket, and every artefact flows back to that ticket.

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
4a. backend-builder-python      (if brief lists Python work)
4b. backend-builder-typescript  (if brief lists TS backend work)
14. rust-builder                (if brief lists Rust work — Tauri shells, OSS lib cores)
5.  frontend-builder            (if brief lists frontend work)
     - each builder posts its API summary as a comment
     - first builder adds label "building", removes "needs-brief-approval"
        ↓
6. test-verifier
     - writes acceptance tests against the story's checkboxes
     - posts pass/fail per criterion; updates the description's checkboxes accordingly
     - on fail: routes to the right builder via a comment; loops
        ↓
8. ai-eval-engineer  (only if feature touches LLMs)
     - posts scorecard
        ↓
7. validator
     - posts findings comment
     - on Critical: opens sub-issues (label "from-validator"), adds label "validator-blocked"
     - on Clean: removes label
        ↺ loop back to relevant builder if Critical
        ↓
9. security-reviewer
     - same pattern; labels "security-blocked" / "from-security"
        ↺ loop back if Critical
        ↓
15. compliance-reviewer  (if repo imports Shield/Audit, or is Therapy/Private-Credit/Contractor)
     - same pattern; labels "compliance-blocked" / "from-compliance"
        ↺ loop back if Critical
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

- **One agent active at a time** on any given path. Parallel only inside cross-repo fan-out.
- **Every agent gets the ticket ID** as its first input, alongside any artefacts it needs. Never paste the whole conversation.
- **Every agent ends with a `[factory:<agent>]` comment on the ticket** in the standard format (see `.claude/LINEAR-INTEGRATION.md`).
- **Every agent owns its state transitions and labels.** No agent flips a state it does not own. See LINEAR-INTEGRATION §3.
- **At each checkpoint**, present the artefact in chat AND on the ticket. Don't auto-advance. The operator's approval can be in chat ("/approved") or on the ticket (removing the `needs-X-approval` label).
- **Validator / Security / Compliance Reviewer can loop builders.** Critical findings route to the specific agent named in the finding's `file:line`. Re-run the reviewer after the fix.
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
