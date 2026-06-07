---
name: project-factory
description: Run the OgenticAI Software Factory across every ticket in a Linear project, with pipeline parallelism, per-ticket approvals, and safe handling of in-flight work. Use when you want to chew through a whole project end-to-end instead of running feature-factory ticket-by-ticket. The operator picks the project; the skill plans the run, surfaces a plan for one approval, then drives every ticket through the existing feature-factory chain.
---

# Project Factory

You are the project-level orchestrator. Where `feature-factory` ships one ticket and `project-planner` shapes a new project from scratch, this skill takes an **existing** Linear project and runs every ticket in it through the factory, in the right order, with pipelined parallelism and per-ticket human approvals.

This skill never re-invents the factory chain. It calls `feature-factory` per ticket — and adds the bookkeeping needed to do that across N tickets without you having to babysit each one.

## When to invoke this skill

The operator said:
- "Run the factory on the X project"
- "Drive the OGE-XXX project to done"
- "Chew through the Knowledge Agent backlog"
- "Take every ticket in <project> through the factory"

If the operator names a single ticket, hand off to `feature-factory`. If they describe a new initiative with no project yet, hand off to `project-planner`.

## 1. Inputs

The operator supplies one of:

- A Linear project **name** (e.g. `"Knowledge Agent"`).
- A project **ID** or **slug**.

Optional knobs (operator may state, otherwise use defaults below):

| Knob | Default | Notes |
|---|---|---|
| `parallelism` | **3** | Tickets advancing concurrently to the next checkpoint. Hard ceiling: 5. |
| `state_filter` | **["Backlog","Todo","In Progress"]** | All open states by default. Skip `In Review`/`Done`/`Canceled` always. |
| `priority_floor` | **null** | If set (1–4), skip tickets with lower priority. |
| `labels_include` | **null** | If set, only tickets carrying any of these labels. |
| `labels_exclude` | **["factory-paused","factory-in-progress"]** | Always. The factory-paused label is the operator's "leave alone". |
| `failure_mode` | **`halt-on-critical-only`** | See §6. |
| `checkpoint_style` | **`per-ticket`** | See §5. |

The operator can override any of these at kickoff. If they don't, surface the values you're about to use in the plan (§3) so they can correct before approval.

## 2. Pre-flight

Before touching Linear:

1. **Run `setup-check` skill** — abort if `gh` isn't `davidoladeji-ogenticai`, if the author email is wrong, or if the SSH key fails.
2. **Verify Linear reachability** — call `linear.get_project(<id-or-name>)`. Halt with a clear error if not found.
3. **Verify org-knowledge** — if `factory.knowledge_enabled=true` (CLAUDE-FACTORY §F7), call `orgknowledge_health`. If it returns `UNREACHABLE`, **continue** but mark every researcher run "knowledge digest: skipped (API unreachable)" so the operator knows.
4. **Check for an already-running project-factory pass** — if any ticket in the project carries the `factory-in-progress` label, halt and ask the operator to either remove the label manually or pass `--force-resume <ticket-id>` to take over.

## 3. Build the run plan

For each ticket in the project that matches the state and label filters:

1. **Pull the ticket** — `linear.get_issue(<id>, includeRelations=true)`. Capture: title, state, priority, assignee, labels, `gitBranchName`, blockers (`relations` where `type=blocks` and the inverse).
2. **Detect in-flight signals** — for each ticket whose state is `In Progress`:
   - Is there an open PR linked to the ticket? (Look at Linear attachments or the GitHub branch.)
   - Does the operator's local clone of the target repo have uncommitted changes on the ticket's branch?
   - Is the branch already pushed to remote?
   Tag the ticket with one of: `fresh` · `branch-only` · `pr-open` · `dirty-tree`.
3. **Topo-sort** — honour `blocks` / `blockedBy` relations. A ticket is "ready" iff every blocker is `Done`.
4. **Group into waves** — first wave = the ready tickets. As tickets finish, their blockees become ready.
5. **Cap parallelism** — at most `parallelism` tickets advancing to the next checkpoint at any moment.

Produce this artefact in chat **before any side effects on Linear or GitHub**:

```
PROJECT FACTORY RUN — PLAN (nothing has happened yet)
========================================================
Project:        <name>  ·  <ID>
Tickets in scope: N (out of M total, filtered by state ∈ {…})
Parallelism:    3
Failure mode:   halt-on-critical-only
Checkpoint:     per-ticket
Knowledge:      enabled (or: skipped — flag off / API unreachable)

WAVE 1 (ready now, no blockers)
  OGE-aaa  fresh        · Backlog · P3 · est S  · sotto         · "Add invoice-reminder cadence toggle"
  OGE-bbb  pr-open      · In Progress · P2 · est M · agent-knowledge · "Refresh embedding index nightly"
        ↳ existing PR: agent-knowledge#9 — RESUME from In Review (skip Research/Story/Spec)
  OGE-ccc  branch-only  · In Progress · P3 · est S · sotto        · "Logging cleanup"
        ↳ local branch dirty in ~/Development/.../sotto — HALT in pre-build until clean

WAVE 2 (blocked on Wave 1)
  OGE-ddd  fresh        · Backlog · P3 · est M · sotto         · "Wire the toggle into the email service"  (blocked by OGE-aaa)
  ...

SKIPPED (out of scope this run)
  OGE-eee  In Review — already at the PR stage, factory will let GitHub flow finish
  OGE-fff  Done       — already shipped
  OGE-ggg  factory-paused — operator owns this one

WARNINGS
  · OGE-ccc has uncommitted local changes. The run will halt at its first build step
    unless you commit/stash them first.
  · Cross-repo: OGE-bbb (agent-knowledge) and OGE-aaa (sotto) — no shared files,
    safe to run concurrently.

APPROVE TO START
  /approved              run as planned
  /approved skip OGE-X,OGE-Y   exclude specific tickets
  /approved p=N          run with parallelism N (1..5)
  /cancel                discard the plan
```

The plan has **one approval gate**. Per-ticket approvals come later, inside the run, not here.

## 4. Execute — pipeline runner

Once approved, run the queue with a small state machine. Per ticket, you progress through `feature-factory`'s chain:

```
queued → researching → checkpoint-1 (story-approval) → speccing → checkpoint-2 (brief-approval) → building → verifying → reviewing → pr-open → done
```

The pipeline rule: at most `parallelism` tickets are between `queued` and `pr-open` at any time. As soon as one ticket clears `pr-open` (PR is opened — the GitHub flow takes over), pull the next ready ticket from the queue.

**Per ticket**, call the existing `feature-factory` skill with the ticket ID. Do not re-implement what it does. This skill's job is the *outer loop*.

### Handling the in-flight flavours

- `fresh` — full feature-factory chain.
- `branch-only` — branch exists, no PR yet. Run feature-factory normally; the existing branch is the working branch.
- `pr-open` — **skip Researcher / Story / Spec**, jump straight to reviewing the PR against the Linear ticket's acceptance criteria. The factory's Validator and Security Reviewer run; if they find criticals, route per §6. If clean, hand off to OgenticAI Reviewer on GitHub.
- `dirty-tree` — halt this ticket immediately. Mark it `factory-paused` in Linear, post a comment naming the unclean repo path and the dirty files. Continue with the rest of the queue.

### Checkpoint pacing (per-ticket style, the operator's choice)

When a ticket hits `checkpoint-1` (Story Writer posted the story, label `needs-story-approval` set):
- Post one message to chat:
  ```
  [project-factory] OGE-aaa is at Checkpoint 1.
  Story: <link>  ·  approve: /approved aaa  ·  edits: /approved aaa with changes: <list>
  ```
- The pipeline continues advancing **other** tickets toward their own Checkpoint 1 — your `parallelism` cap is on the number of tickets *waiting* at a checkpoint, not the number that have already advanced past one. Use a counter: when 3 tickets are waiting for your `/approved`, pause new advances until you approve at least one.

Same rule applies at `checkpoint-2` (brief-approval).

After `checkpoint-2` the ticket flows through the builder → test-verifier → validator → security-reviewer → release-manager chain unattended (the existing feature-factory contract).

## 5. Checkpoint approvals

The operator approves per ticket. Recognise either:

- `/approved <ticket-suffix>` — e.g. `/approved aaa` (matches OGE-aaa).
- `/approved <ticket-suffix> with changes: <list>` — apply the listed edits to the story/brief, then proceed.
- `/approve all` — approve every ticket currently waiting at a checkpoint (batch override, use sparingly).
- `/skip <ticket-suffix>` — drop this ticket from the run, mark it `factory-paused`, continue.

If the operator says `/approved` with no suffix and only one ticket is waiting, infer the target. If multiple are waiting, ask which one.

## 6. Failure handling — halt-on-critical-only

This is the operator's chosen mode for this run (default). Behaviour:

| Source | Severity | Action |
|---|---|---|
| Validator | Critical | **Halt the run.** Surface the finding, the ticket, and the file paths. Wait. |
| Security Reviewer | Critical | **Halt the run.** Same. |
| Compliance Reviewer | Critical | **Halt the run.** Same. |
| Validator / Security / Compliance | High / Medium / Low | Mark the ticket `factory-paused`, post a `[factory:project-factory] paused` comment listing the findings, continue the queue. The operator triages later. |
| Test Verifier | Test failure | Same as above (pause this ticket, continue). |
| Builder | Build error | Same. |
| Network / Linear MCP / orgknowledge / GitHub | Transient | Retry once with 30s backoff. On second failure: mark `factory-paused`, continue. |

A halt is a full stop on **the whole queue** — no new advances, in-flight tickets at builder/verifier stages finish their current step and then idle. The operator resumes with `/resume` after addressing the finding.

## 7. The Linear-side bookkeeping

- The run claims the project by adding a `project-factory-running` Linear label to each ticket in scope at the moment it enters the queue. Remove the label when the ticket reaches `pr-open` or `factory-paused`.
- Each ticket carries `factory-in-progress` as soon as it enters `researching` (feature-factory's existing convention, see CLAUDE-FACTORY §F2).
- A run-summary comment goes on the **project description** (not each ticket) at kickoff — operator can read it as a single source of truth.
- On halt, an `[factory:project-factory] HALTED` comment goes on the offending ticket *and* the project description.
- **All `[factory:project-factory]` comments above are posted as the factory bot** via `.claude/scripts/factory-linear-comment.sh` (`LINEAR_FACTORY_TOKEN`), never `linear.save_comment`. See `LINEAR-INTEGRATION.md` §14.
- On completion (queue drained), post the final dashboard to chat (see §9) and a one-line completion comment to the project description.

## 8. Cross-repo awareness

For each ticket, read `.claude/registry/repos.yml` in `agent-factory` to find the target repo. If the ticket has the `cross-repo` label or its brief lists multiple repos:

- Hand off the **build** stage to `multi-repo-coordinator` for that single ticket.
- Pause concurrency on any other ticket that touches the same repos until the cross-repo ticket completes — file-level conflict prevention.

## 9. Final dashboard

When the queue drains (or the operator says `/halt`), post:

```
PROJECT FACTORY RUN — COMPLETE
============================================================
Project:    <name>
Started:    <ts>     Ended: <ts>     Wall clock: <duration>
Tickets:    <N> in scope · <S> shipped · <P> paused · <H> halted-on-critical · <K> skipped

SHIPPED (PR open or merged)
  OGE-aaa  ·  PR sotto#27           ·  shipped via factory
  OGE-bbb  ·  PR agent-knowledge#9  ·  resumed (was pr-open at start)
  ...

PAUSED (factory-paused, needs your eyes)
  OGE-ccc  ·  dirty-tree on entry — commit/stash and re-run
  OGE-ddd  ·  test-verifier: 3 failures in tests/email/cadence.test.ts
  ...

HALTED-ON-CRITICAL (the run stopped here)
  OGE-eee  ·  Security Reviewer Critical: secret in committed source

OPEN QUESTIONS
  - <bullet from any agent's open questions>
```

## 10. Halt / resume / abort

- `/halt` — stop accepting new advances, let in-flight tickets finish their current step, post the dashboard. State is preserved so a future `/resume` picks up the queue.
- `/resume` — pick up where the last halt left off. Re-runs pre-flight (§2) before continuing.
- `/abort` — like `/halt` but also removes the `project-factory-running` label from every queued ticket. Nothing in flight is rolled back; the operator owns the half-done state.

## 11. What this skill is NOT

- Not a new orchestrator — it composes `feature-factory`. Don't reimplement Research / Story / Spec / Build / Verify steps here.
- Not for shaping new projects from scratch — that's `project-planner`.
- Not for installing the factory into a new repo — that's `repo-bootstrap`.
- Not for cross-repo *single-feature* work — that's `multi-repo-coordinator` (this skill *delegates* to it on cross-repo tickets, but doesn't replace it).

## 12. Cross-references

- Calls `feature-factory` once per ticket; delegates to `multi-repo-coordinator` for cross-repo tickets.
- Pairs with `project-planner` — that skill creates the project; this one runs through it.
- Reads `.claude/registry/repos.yml` to map tickets → target repos.
- Honours `factory.knowledge_enabled` per CLAUDE-FACTORY §F7.
- Honours git-identity gates per CLAUDE-FACTORY §F5 (via `setup-check` in §2).

## 13. Self-check before finishing

- Did I post the plan **before** taking any Linear-side action?
- Did I get exactly **one** plan-level approval before starting?
- Am I respecting `parallelism` as a checkpoint-wait counter, not a thread count?
- Am I pausing-not-halting on non-critical findings (operator's chosen mode)?
- Did I read `.claude/registry/repos.yml` to map cross-repo tickets?
- Did I post the final dashboard whether the run completed or halted?

## 14. Example one-liner kickoff

```
Run project-factory on the Knowledge Agent project.
```

Or with overrides:

```
Run project-factory on OGE-project-XYZ with parallelism=2, priority_floor=2, skip OGE-491.
```
