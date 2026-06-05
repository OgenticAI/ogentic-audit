---
name: new-from-knowledge
description: Scans org-knowledge for "decisions without tickets" — Slack threads, Notion specs, Drive docs where the team made a decision but no Linear issue exists yet — and proposes Linear issues to create. Use when running the periodic factory hygiene pass, when the operator asks "what have we decided but not ticketed?", or as a scheduled task at the start of each week.
---

# new-from-knowledge — turn team decisions into Linear tickets

This skill closes the gap between "the team decided something in a thread" and "there's a Linear ticket tracking it". It scans org-knowledge for decision-shaped content, cross-references against the active Linear backlog, and proposes new issues for the gap.

**Status:** ships behind feature flag `factory.knowledge_enabled = true` (see CLAUDE-FACTORY §F7). Until the org-knowledge API is live the skill is a no-op stub — it returns "knowledge unreachable" cleanly.

## When to invoke

- Periodic factory hygiene (suggested: Monday mornings).
- Operator asks "what have we decided but not ticketed?" / "what's drifting?" / "create tickets for last week's decisions".
- Scheduled task — register via `mcp__scheduled-tasks__create_scheduled_task` with cron `0 9 * * 1` (Mondays 09:00).

## Pre-flight

1. Check `factory.knowledge_enabled` in `.claude/CLAUDE-FACTORY.md` §F7 / repo `CLAUDE.md` §6. If false, halt with: "new-from-knowledge skipped — factory.knowledge_enabled=false".
2. Call `orgknowledge_health()`. If unreachable, halt with: "orgknowledge unreachable — Phase C1 still in flight; nothing to scan yet".

## How it works (the loop)

For each "decision marker" query — currently a small fixed set, expand over time:

```python
DECISION_QUERIES = [
    "decided to",
    "let's go with",
    "approved",
    "we'll ship",
    "RFC accepted",
    "spec frozen",
    "ADR adopted",
]
```

For each query:

1. `orgknowledge_search(q, since=(today - P14D).isoformat() + "Z", limit=15, threshold=0.6)`.
2. For each hit, extract: title, snippet, channel, captured_at, source_url, participants.
3. Cross-check against Linear: `linear.list_issues(team=OGE, query=<first 4 keywords of title>, updatedAt=-P30D)`. If any open issue matches → skip (already tracked).
4. Otherwise → candidate ticket.

## Output — draft, don't create

Present the candidates to the operator as a draft list **before** touching Linear:

```
NEW-FROM-KNOWLEDGE — scan of last 14 days
============================================================
Searched: orgknowledge (Slack, Notion, Drive, Gmail, Calendar, GitHub, OneDrive, Documents)
Queries:  decision-marker set (7 patterns)
Hits:     <N> total, <M> candidates after Linear de-dup

CANDIDATE TICKETS

1. [Slack #revere · captured 2026-05-30] "Decided to switch invoice reminders to 5-day cadence"
   participants: Alice, Bob
   suggested: OGE / Sizer · title: "Invoice reminder cadence: 5 days (was 7)"
   source: <url>

2. [Notion · captured 2026-05-28] "Spec frozen — Therapy onboarding rebuild v2"
   suggested: OGE / Therapy · title: "Onboarding v2 — implement spec"
   source: <url>

3. ...

APPROVE TO CREATE
  /approved              create all <M> as Backlog issues with label `from-knowledge-scan`
  /approved 1,3,5        create only those rows
  /approved with edits:  reply with a numbered list of edits, then re-approve
  /cancel                discard
```

Default labels on every created ticket:
- `from-knowledge-scan`
- `needs-triage` (so the operator can re-prioritise in the Linear UI)

Default state: `Backlog`. Default assignee: unassigned. Estimate: unset.

## What this skill is NOT

- Not a code generator. It only proposes Linear tickets.
- Not a perfect dedup — if Linear's search is sparse, the operator may see suggestions that overlap an existing issue. They reject those at the checkpoint.
- Not a replacement for `feature-factory`. It feeds the backlog; `feature-factory` consumes from it.

## Failure modes

| Outcome | Behaviour |
|---|---|
| `orgknowledge_health` → `UNREACHABLE` | Halt cleanly with the noted message. No retries. |
| `orgknowledge_search` returns 0 hits across all queries | Report "no decision-shaped content found in the last 14 days". |
| Linear MCP unavailable | Halt — cannot de-dup safely. Don't create anything. |
| Operator says `/cancel` | Drop the draft, no side effects. |

## Cross-references

- Uses `mcp-orgknowledge` plugin's `orgknowledge_search` + `orgknowledge_health`.
- Pairs with `feature-factory` (the consumer of the backlog this skill grows) and `project-planner` (which it complements — that skill plans new projects, this skill catches loose tickets).
- Behind feature flag `factory.knowledge_enabled` — see CLAUDE-FACTORY §F7.
