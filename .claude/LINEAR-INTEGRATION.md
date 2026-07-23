# Linear Integration — the factory's source-of-truth contract

This file defines how every factory agent reads from and writes to Linear. **Every agent file links here.** When the contract changes, change it here, then propagate.

Linear is not a side artefact — it is the canonical record of what the factory built. The ticket is the brief. The comments are the audit trail. The state transitions are the workflow.

---

## 1. The ticket is the input

The factory's canonical kickoff is a Linear ticket ID — e.g. `OGE-123` — not a free-form feature description.

When David runs the factory, he passes the ticket. The orchestrator pulls it once, validates it, and feeds each agent the slice it needs. Every agent's first action is to read the latest state of the ticket (in case David edited something between checkpoints).

A free-form description is still allowed, but the orchestrator will refuse to proceed until a Linear ticket has been created for it. Posting to chat without a ticket is a code smell — it means there is no record. The factory creates the ticket on the operator's behalf if needed (via `save_issue`), assigns it to David, and asks for confirmation before proceeding.

---

## 1a. No implementation without a ticket (standing rule)

**Every implementation change is grounded in a Linear ticket before code is written.** This is not only a factory-orchestration convenience — it is a standing rule for all work in every OgenticAI repo, whether the change comes from the factory, a Cowork session, or a human. If you are about to write feature or fix code and there is no ticket, **create one first** (with a project AND assignee per §2a), put its `OGE-NNN` in the branch name, and only then implement.

**Why — the reviewer makes ticketless work invisible, not reviewed.** The OgenticAI Reviewer verifies a PR against its linked ticket's `## UAT checklist`. A PR with no `OGE-NNN` and no checklist has nothing to review against, so the reviewer correctly **skips** it — publishing a grey `skipped` Check that sits next to the green ones and looks reviewed. It was not. On 2026-07-22 a real feature PR (`zashboard-ultimate#233`, an integrations-directory UI) merged this way: no ticket, no checklist, no verdict, and no record in any project view. The fix is upstream, at authoring time: **no ticket, no implementation.** A ticket is also what makes the work show up in a project, carry an owner, and leave an audit trail — the same reasons §2a exists.

**The one exception — automated / chore PRs.** Factory-kit syncs (`chore(factory): …`), dependency bumps, and other machine-generated maintenance legitimately carry no ticket, and must not be blocked for lacking one. The reviewer is built this way on purpose: a **missing ticket never fails the check** (only a missing checklist can, and only where a repo opts into `require_checklist`). This rule binds human and agent **implementation** work — the things a person would open a ticket for — not routine machine chores.

---

## 2. The Linear MCP tools every agent uses

The kit refers to Linear tools by logical name. The actual MCP namespace depends on which Linear connector is installed locally; current OgenticAI installs use `mcp__plugin_engineering_linear__*` or a UUID-prefixed server. Map the logical names to whatever your install exposes.

> **Identity (critical).** `[factory:*]` **comments** MUST be authored by the factory bot, not the human connector — see §14. Because Claude caps Linear connectors at two (both human), the bot has no connector: comments are posted via the Linear API with `LINEAR_FACTORY_TOKEN` (the bot's personal API key), out-of-band from `linear.save_comment`. Reads and ticket state may use the human connector. Until `LINEAR_FACTORY_TOKEN` is set, the factory does not post `[factory:*]` comments as a human — it buffers them (§9).

| Logical name | What it does | Tools that need it |
|---|---|---|
| `linear.get_issue` | Read a ticket + its acceptance criteria + description | **All agents** |
| `linear.list_comments` | Read prior agent outputs and human responses | All agents |
| `factory.comment` | Post a `[factory:*]` comment **as the factory bot** — the subagent returns the body; the **orchestrator** posts it via `.claude/scripts/factory-linear-comment.sh` (`LINEAR_FACTORY_TOKEN`). NEVER use MCP `linear.save_comment` for `[factory:*]` comments (authors as the human). | Orchestrator, for every agent |
| `linear.save_issue` | Update title, description, state, assignee, labels, parent | Story Writer, Spec Writer, Validator, Security Reviewer, Compliance Reviewer, Release Manager, Cross-Repo Coordinator, Incident Responder |
| `linear.list_issues` | Search related tickets in the same project / similar features | Researcher, Story Writer |
| `linear.list_projects` | Cross-reference project metadata | Researcher, Spec Writer, Cross-Repo Coordinator |
| `linear.list_issue_labels` | Look up label IDs for state-blocking labels | Security Reviewer, Compliance Reviewer |
| `linear.list_users` | Resolve owners for sub-issues | Cross-Repo Coordinator |
| `linear.list_initiatives` | Validate cross-project work belongs to the right initiative | Cross-Repo Coordinator |

If a tool is missing from your local install, the orchestrator should report which agents will degrade and ask whether to proceed in **degraded mode** (no Linear writes, just reads) or **halt**.

> **Headless mode has NO MCP connector.** The Linear MCP tools above are interactively authenticated, so they are typically **absent in the auto-loop / cron driver**. Headless agents MUST NOT fall back to hand-rolling an HTTP call with the token pasted in — that leaks the secret (see §15). Use the kit's token-less helpers instead, which read `LINEAR_FACTORY_TOKEN` from the environment and send it only in the Authorization header:
> - **reads / arbitrary GraphQL** → `.claude/scripts/factory-linear-query.sh --query - --vars '{...}'` (query on stdin or `--query '<gql>'`)
> - **`[factory:*]` comments** → `.claude/scripts/factory-linear-comment.sh --issue OGE-NNN --body -`
> These map to `linear.get_issue` / `linear.list_*` (query helper) and `factory.comment` (comment helper).

---

## 2a. Assignee AND project are MANDATORY on every issue an agent creates

**Any issue an agent creates via `linear.save_issue` MUST have an assignee — never `null`.** Unowned agent tickets pile up invisibly: an org-wide audit (OGE-1290, 2026-07-02) found 374 unassigned issues in OGE, 173 of them agent-created (121 from the project-planner seed backlog alone). Resolve the assignee in this order:

1. **Self** — if the agent authenticates as its own Linear user (the factory bot is `factory-bot@ogenticai.com`, id `d3e2dfa8-7f3d-4db7-ad33-a3ad0b2d4ffd`), assign the created issue to that user.
2. **The operator** — otherwise assign the operator (**David** by default; `david@ogenticai.com`). An operator may direct issues to **Dennis** or **Craig**; never assign any other human, and never leave it unassigned (see §12).

This is a hard rule for **every** created issue, not just the intake ticket: the project-planner seed backlog, finding sub-issues (Validator / Security / Compliance), decomposition sub-issues (backlog-groomer), and decision-derived issues (new-from-knowledge) all fall under it. `assignee` is a required field on any `save_issue` **create** — if you can't resolve a specific person, default to the operator.

### Project is mandatory too

**`project` is equally required.** A project-less ticket does not appear in any project view — it is reachable only by scrolling an 800-item backlog or by knowing its id. Filing one is worse than not filing at all, because the work looks captured when it is not.

- Set `project` **in the create call**, not as a follow-up edit.
- Resolve it by asking which existing project owns the surface the work touches. `list_projects` on the team, filtered by name, is usually enough.
- **If no existing project fits, ask the operator.** Do not file project-less, and do not invent a project — `project-planner` exists for work that genuinely needs a new one.

### Verify before reporting success

A returned `url` is not success. Confirm the `save_issue` response contains non-null **`project`** and **`assignee`** before telling the operator the ticket is filed. After a batch, sanity-check with `list_issues` using `assignee: null` — nothing you just created should appear.

> **Why this is spelled out twice.** §2a already required an assignee when, on 2026-07-19, one session filed 9 tickets with neither field and a concurrent session filed 6 more with no assignee. The operator caught all 15 in the backlog view. The rule existed; it was not applied. Treat both fields as part of the create call's required arguments, not as metadata to tidy up later.

---

## 3. The state machine

Every Linear ticket touched by the factory moves through this canonical state sequence. The state names below are the OgenticAI team's (OGE) state names. If a state doesn't exist, the closest equivalent is used and the orchestrator logs which state mapping was applied.

```
Backlog
   │
   │  Researcher reads, posts findings comment
   ▼
In Progress
   │
   │  Story Writer posts story; description updated with acceptance criteria as checkboxes
   ▼
In Progress + label "needs-story-approval"
   │
   │  ⏸ CHECKPOINT 1 — David approves via comment "/approved" or a Linear "Approve" button
   │
   │  Spec Writer posts brief comment; description gets a "Brief" link
   ▼
In Progress + label "needs-brief-approval"
   │
   │  ⏸ CHECKPOINT 2 — David approves
   │
   │  Builders work; each posts API summary comment; branch attached via Linear branch name
   ▼
In Progress + label "building"
   │
   │  Test Verifier checks the acceptance-criteria boxes that pass; comments full report
   │  AI Eval Engineer (if applicable) posts scorecard comment
   │  Validator posts findings; if Critical, opens sub-issues + label "validator-blocked"
   │  Security Reviewer posts findings; if Critical, sub-issues + label "security-blocked"
   │  Compliance Reviewer (if applicable) — same pattern
   ▼
In Review  (set by Linear's GitHub integration when the PR opens)
   │
   │  ⏸ CHECKPOINT 3 — David approves PR
   │
   │  PR merged → Linear's GitHub integration auto-moves the ticket to Done
   │  (it keys off the OGE-NNN in the PR title).
   ▼
Done
   │
   │  ✅ MANDATORY post-merge check — Done = merged, and no merged ticket is ever
   │  left un-Done. Immediately after merge, CONFIRM the ticket is in `Done`. If the
   │  integration did not move it — the PR title lacked `OGE-NNN`, the ticket shipped
   │  outside the full factory chain (lighter/direct ship), or the integration was
   │  degraded — set it explicitly: `linear.save_issue(<TICKET-ID>, state='Done')`.
   │  Whoever merges owns this check: the Release Manager in the full chain; otherwise
   │  the operator/agent that performed the merge.
   │
   │  Release Manager posts release plan + deploy timestamps; (state may already be Done)
   ▼
[ticket closed; sub-issues for any deferred follow-ups remain in Backlog]
```

**State transitions are owned.** An agent only flips the state it owns. No agent flips backward except in failure (a Validator-critical fix loops the builder; the builder does NOT change state back, the validator does, with an explanatory comment).

---

## 4. Comment templates

Every agent writes a comment in a standard shape so a human can scan a ticket and see the run history. Open the ticket, scroll the comments — the full chain.

> **How these are posted (MANDATORY).** Subagents do **not** call a Linear tool — they return their `[factory:*]` body in their sign-off. The **orchestrator** posts each one **as the factory bot** via `.claude/scripts/factory-linear-comment.sh --issue <OGE-ID> --body <markdown>` (`LINEAR_FACTORY_TOKEN`). The MCP `linear.save_comment` is **never** used for `[factory:*]` comments — it authors as the human operator. See §2, §14, and `setup-check` #6.

All comments start with a single-line header:

```
[factory:<agent-name>] <one-line outcome>
```

…then a body, then a footer with the timestamp and the run ID. Examples below.

### Researcher comment
```
[factory:researcher] Codebase mapped — 7 files identified, 2 risks flagged.

## Relevant files
- ...

## Existing patterns to follow
- ...

## Risks
- Tenant isolation: ...

## Open questions
- ...

—
run: 2026-05-29T14:02Z · factory-run/oge-123/v1
```

### Story Writer
The story writer is special — it **edits the ticket description** to embed the formal user story and acceptance criteria as Linear checkboxes (so test-verifier can later mark them). Old description is preserved as a comment.

```
[factory:story-writer] User story drafted — 5 acceptance criteria, 1 open question. Awaiting Checkpoint 1.

(Description rewritten — see the ticket body. Original description preserved below.)

---
<original description>
---

—
run: ...
```

### Spec Writer
Brief is too long for description. Lives as a comment. If >2000 words, it goes into a Linear **document** linked from the ticket.

```
[factory:spec-writer] Technical brief ready. Awaiting Checkpoint 2.

## Data model changes
...
## API — Python AI service
...
## Files that will change
...

—
run: ...
```

### Backend builders
```
[factory:backend-builder-typescript] TS backend complete — 4 files, 12 tests green. Branch: oge-123-invoice-reminders.

PYTHON API CONSUMED:
- aiClient.detectPhi() — see researcher's notes

TYPESCRIPT API SUMMARY:
- POST /api/reminders ...

Tests:
- ...

—
run: ...
```

### Test Verifier
**Checks the acceptance-criteria checkboxes** on the ticket description that pass. Posts a comment with the report.

```
[factory:test-verifier] 7 of 8 acceptance criteria pass; 1 fails — tenant check on manual trigger.

Criterion #5 ❌: "Only admins of the tenant can fire the manual reminder."
File: apps/web/app/api/reminders/trigger/route.test.ts
Expected: 403 for cross-tenant admin. Actual: 200.

Routing back to: backend-builder-typescript

—
run: ...
```

### Validator / Security Reviewer / Compliance Reviewer
```
[factory:validator] 1 CRITICAL, 0 IMPORTANT, 2 MINOR.

🔴 CRITICAL
- apps/web/app/api/reminders/trigger/route.ts:42 — missing tenant check on manual trigger endpoint. Sub-issue opened: OGE-451.

🟠 IMPORTANT
- (none)

⚪ MINOR
- ...

Label added: "validator-blocked"
State unchanged (still In Progress).

—
run: ...
```

If the report is `CLEAN`, the agent removes its own blocking label (if it added one earlier) and the comment says so.

### Release Manager
```
[factory:release-manager] Deploy complete.

Steps:
1. alembic migration 20260601_invoice_reminders ✅ 12:01Z
2. ai-service image v2.4.1 ✅ 12:04Z
3. web prisma migration ✅ 12:06Z
4. web image v3.7.0 ✅ 12:08Z
5. workers v3.7.0 ✅ 12:08Z

Healthcheck window (10m): green.
Customer-facing release note: "Invoice reminders are now sent automatically after 7 days unpaid."

State → Done.

—
run: ...
```

---

## 5. Branch / PR convention

**The OgenticAI convention is: the issue ID lives in the commit message and the PR title, not in the branch name.** Confirmed against 253 PRs across all OgenticAI repos (May 2026): 79% carry an `OGE-NNN` prefix in PR titles; 0% use Linear's native `linkedIssues` PR linker.

- **Branch:** descriptive feature-style — e.g. `feat/shield-analyze-document`, `fix/reviewer-checks-api`. NOT Linear's auto-generated `oge-123-…` branch name.
- **Commit titles and PR titles:** conventional-commit prefix carrying the ticket ID — e.g. `feat(OGE-398): Shield.analyze_document API + plain-text Phase 1`, `fix(OGE-394): isCiGreen reads both Checks and Statuses APIs`, `docs(OGE-391): chaos runbook from hardening sweep`.

`agent-reviewer` (the OgenticAI Reviewer) reads the `OGE-NNN` from the PR title to locate the linked Linear ticket and its UAT checklist. The factory uses the same parse for the same purpose.

If a feature spans multiple repos, the Cross-Repo Coordinator opens one PR per repo, all carrying the **same parent ticket's OGE-NNN** in their titles (e.g. `feat(OGE-501): shield-side` and `feat(OGE-501): consumer-side`). One ticket; multiple PRs; reviewer correlates by ticket ID.

---

## 6. Sub-issues — when and how

The factory creates sub-issues for:

- **Validator-critical / Security-critical / Compliance-critical findings** that the operator agrees to defer beyond this PR. The sub-issue is filed in the same project, labelled with the source agent (`from-validator`, `from-security`, `from-compliance`).
- **Open questions** from Researcher / Story Writer / Spec Writer that the operator answers as "out of scope for now". Filed in the same project, labelled `deferred-question`.
- **Cross-repo slices** when the Cross-Repo Coordinator fans out — one sub-issue per affected repo, all linked to the parent ticket.

The factory **never** creates a sub-issue silently. Every sub-issue is announced in a comment on the parent ticket with the sub-issue ID and a one-line rationale.

---

## 7. Labels used by the factory

Add these labels to the OGE team (one-time setup). The factory expects them.

| Label | Applied by | Removed by |
|---|---|---|
| `factory-in-progress` | Researcher (first step) | Release Manager (last step) |
| `needs-story-approval` | Story Writer | Spec Writer (after Checkpoint 1 passes) |
| `needs-brief-approval` | Spec Writer | First Builder (after Checkpoint 2 passes) |
| `building` | First Builder | Test Verifier |
| `validator-blocked` | Validator (if Critical) | Validator (when next run is clean) |
| `security-blocked` | Security Reviewer (if Critical) | Security Reviewer (when next run is clean) |
| `compliance-blocked` | Compliance Reviewer (if Critical) | Compliance Reviewer (when next run is clean) |
| `from-validator` | When opening a sub-issue from validator findings | manual |
| `from-security` | sub-issue from security review | manual |
| `from-compliance` | sub-issue from compliance review | manual |
| `deferred-question` | sub-issue from open questions | manual |
| `factory-degraded` | Orchestrator (if Linear MCP partially unavailable) | Orchestrator (when restored) |
| `factory-paused` | Orchestrator (if a checkpoint stalls > 24h) | manual |

The orchestrator creates any missing labels on first run (via `linear.create_issue_label`).

---

## 8. Acceptance criteria as Linear checkboxes

When the Story Writer formalises a story, the acceptance criteria go into the ticket description as Linear checkboxes:

```markdown
## Acceptance criteria
- [ ] Invoices unpaid > 7 days are surfaced in the reminder queue
- [ ] Admin can fire a manual reminder per invoice
- [ ] Only admins of the tenant can fire the manual reminder
- [ ] The reminder email contains the invoice number and amount due
- [ ] A reminder is logged in the audit trail (Ogentic-Audit emit)
```

The Test Verifier later flips each box to ✅ on pass and explicitly leaves it unchecked on fail. The Validator reads the box state to confirm Test Verifier did its job.

For verticals or repos that import Ogentic-Shield / Ogentic-Audit, the Story Writer **always** adds these criteria automatically:

```
- [ ] PHI / privilege / MNPI handling routes through Shield before any LLM call
- [ ] An audit event is emitted via Ogentic-Audit for every state change
- [ ] Tenant isolation verified by an explicit test
```

---

## 9. The "degraded" mode

If the Linear MCP is offline mid-run, the orchestrator:

1. Posts a single best-effort comment "Linear connection lost at <step>. Run continuing in degraded mode. Re-sync queued." then continues.
2. Buffers every comment / state-transition that would have been written.
3. On next run with Linear restored, replays the buffer with a single batch comment "[factory] Re-sync after degraded mode" containing the buffered events.

The orchestrator never silently drops state changes. Better to over-report than to leave the ticket out of date.

---

## 10. The "create-on-the-fly" pattern

If David starts the factory with a free-form description (no ticket ID), the orchestrator:

1. Drafts a ticket title from the description (one short imperative sentence).
2. Picks the project (asks David if ambiguous; defaults to the repo's primary project from `repos.yml`).
3. Creates the ticket in `Backlog`, assigns David, attaches the description as the initial body.
4. Posts the ID back to chat: "Created OGE-xxx. Proceeding with factory."
5. Now the run is identical to a ticket-id run.

This keeps the rule simple: **every factory run has a Linear ticket.** No exceptions.

---

## 11. Failure modes the factory handles

- **Ticket not found** — orchestrator halts; asks David for the right ID.
- **Ticket already in `Done`** — orchestrator asks: "This ticket is closed. Reopen and run, or create a follow-up ticket?"
- **Ticket has an open child blocking it** — orchestrator surfaces the blocker, asks whether to run anyway.
- **Acceptance criteria changed mid-run** — Test Verifier compares the ticket's current criteria to the snapshot taken at Checkpoint 1 approval. If they differ, halts and asks for re-approval.
- **A label the factory expects doesn't exist** — orchestrator creates it (with `linear.create_issue_label`) and continues.
- **Sub-issue creation fails** — agent surfaces the failing call in its comment with the intended sub-issue body, so David can create it manually.

---

## 12. What the factory will NOT do in Linear

- It will not move a ticket to `Done` ahead of merge. Done = merged.
- It will not delete comments. Even mistakes stay as audit trail.
- It will not edit human comments. It only edits / replaces ticket descriptions (Story Writer specifically) and only between Checkpoints, never after Checkpoint 1 is approved.
- It will not assign tickets to anyone other than the operator unless the operator says so.
- It will not change a ticket's project or team.
- It will not write to a Linear ticket if it cannot find a matching repo in `repos.yml`. The factory expects its work to belong to a known repo.

---

## 13. Auditability — what David can see at a glance

Open any ticket the factory has touched. You see:

- The original ask (preserved as a comment by Story Writer)
- The formalised user story + checkbox acceptance criteria (in the description)
- The researcher findings, spec brief, every builder summary, test results, validator + security + compliance reports — each as its own labeled comment
- The PR(s) linked
- Sub-issues for deferred findings
- State at every milestone, owned by the agent that flipped it

No off-ticket Slack threads. No mysterious "ask Claude in chat" history. The ticket is the run.

---

## 14. Linear identity — the factory bot

Linear attributes every comment, state change, and label to whoever the active connector authenticates as. The audit trail in §5 and §13 is only trustworthy if that actor is the **factory bot**, not a human — the same principle as OGE-333 ("record the actor who triggered it") and the §F5 git-identity gate on the GitHub side.

**Required identity:** `factory-bot@ogenticai.com` — display name "OgenticAI Factory Bot".

**How it's wired:** Claude caps Linear connectors at **two** per install, and at OgenticAI both are needed for human workspaces — so the bot gets **no connector**. It posts comments via the **Linear API** using `LINEAR_FACTORY_TOKEN` — a Linear **personal API key** belonging to `factory-bot@ogenticai.com` — out-of-band from the MCP connector (the same pattern as OgenticAI Reviewer's `LINEAR_API_TOKEN`). Reads, ticket state, and labels still flow through the operator's human connector; only `[factory:*]` **comments** route through the bot token.

- **Provisioning** (one-time, admin): `docs/LINEAR-BOT-SETUP.md` — create the bot member, mint its personal API key, expose it as `LINEAR_FACTORY_TOKEN` (1Password → env/secret, off-disk; org/repo Actions secret for CI).
- **Posting:** the **orchestrator** posts each `[factory:*]` comment by running `.claude/scripts/factory-linear-comment.sh --issue OGE-NNN --body <md>` (or `--project <id>`) — `commentCreate` via the token. Subagents return their comment body and never call `linear.save_comment` (human-authed).
- **Enforcement:** `setup-check` check #6 confirms `LINEAR_FACTORY_TOKEN` is set and its Linear `viewer` resolves to the bot — **hard-fails** otherwise (skip with `OGENTICAI_BYPASS_IDENTITY`).
- **Acceptable interim:** ticket creation + state moves may run through the human connector; only comments are gated.

Until `LINEAR_FACTORY_TOKEN` is set, the factory MUST NOT post `[factory:*]` comments as a human — it buffers them to chat (degraded-mode, §9) and replays them once the token is live.

---

## 15. Secret handling — never put a token on argv

`LINEAR_FACTORY_TOKEN` (and `ANTHROPIC_API_KEY`, `GH_TOKEN`, any `*_TOKEN`/key) is present in the headless agent's **environment** so the sanctioned helpers can use it. Process **arguments are world-readable** on the host (`ps -ef`, `ps eww`), so a secret that lands on a command line — directly, in a heredoc literal, or interpolated into an inline script — is exposed to every local process for the lifetime of that process. This is exactly how a factory run leaked the bot token once (an agent wrote inline python with `key = "lin_api_…"` pasted in).

**Rules (MANDATORY for every agent + the orchestrator):**

1. **Never** write a token as a literal in code, a heredoc, a config/temp file, or any argv element; **never** echo or log it.
2. For all Linear access use the kit helpers — `factory-linear-query.sh` (reads / arbitrary GraphQL) and `factory-linear-comment.sh` (comments). Both read the token from the environment and pass it **only in the HTTP `Authorization` header** (via `urllib`), so it never touches argv.
3. If you genuinely must call an API without a helper: read the token from the environment **at runtime** (`os.environ["LINEAR_FACTORY_TOKEN"]`) inside the program and put it in a request header. Do **not** pass it to `curl -H "Authorization: …"` (that header value is visible in `ps`); use a language HTTP client (urllib/requests/fetch) whose headers never appear on argv, or `curl -H @<(…)` / `--config <fd>` so the value stays off the command line.
4. The same rule covers `gh` (use `GH_TOKEN` from the env; never `--with-token` on a visible command line with the literal) and any model/provider key.

`setup-check` should treat a token literal found in a script or in recent process output as a hard finding.

— end —
