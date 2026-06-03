# CLAUDE-FACTORY.md — the OgenticAI Software Factory contract

This file is the **factory partial**. It contains only what the agents need to know about how the factory operates — not what this repo is, not your stack, not your architecture rules. Those stay in your existing `CLAUDE.md`.

**How to use it.** Two options:

1. **Import it from your existing `CLAUDE.md`** by adding one line near the bottom:

   ```markdown
   ## Factory contract
   @./.claude/CLAUDE-FACTORY.md
   ```

2. **Paste it inline** if your Claude Code version doesn't support `@file` imports. Copy this entire file's contents into a new section of your existing `CLAUDE.md`. It's self-contained.

Either way, **do not let this file silently overwrite anything you wrote.** It is additive.

---

## §F1 — Where the factory lives in this repo

- Agent definitions: `.claude/agents/` (12 core + 3 extensions: library-publisher, rust-builder, compliance-reviewer)
- Orchestrator skills: `.claude/skills/feature-factory/`, `build-with-tests/`, `repo-bootstrap/`, `multi-repo-coordinator/`, `project-planner/`, `repo-create/`, `fleet-onboarding/`
- Hooks: `.claude/hooks/pre-commit`, `.claude/hooks/pre-push`
- Multi-repo registry: `.claude/registry/repos.yml`
- Linear integration contract: `.claude/LINEAR-INTEGRATION.md` — every agent links here.

If you reorganise this layout, update §F1.

---

## §F2 — Linear conventions (OgenticAI, team OGE)

The factory grounds every run in a Linear ticket. No exceptions. These are the OgenticAI-specific values the agents expect.

**Linear workspace:** Ogenticai
**Linear team key:** `OGE`
**Primary project for this repo:** TODO — fill in. Match the `linear_project` field for this repo in `.claude/registry/repos.yml`.

**State machine.** The factory walks tickets through:
```
Backlog → In Progress → In Review → Done
```
- `In Progress` — set by Researcher (first step).
- `In Review` — set by Linear's GitHub integration when the PR opens.
- `Done` — set on PR merge.

If your team uses different state names, list the mapping here. The orchestrator falls back to the closest equivalent and logs the substitution.

**Branch naming.** Always use Linear's auto-generated branch name (copy it from the ticket's "Copy branch name" affordance). Example: `oge-123-invoice-reminders-7d`. This is what links the PR to the ticket and what OgenticAI Reviewer uses to find the linked UAT checklist.

**Labels** the factory uses (auto-created on first run if missing):

| Label | Set by | Removed by |
|---|---|---|
| `factory-in-progress` | Researcher (first step) | Release Manager (last step) |
| `needs-story-approval` | Story Writer | Spec Writer (after Checkpoint 1) |
| `needs-brief-approval` | Spec Writer | First Builder (after Checkpoint 2) |
| `building` | First Builder | Test Verifier |
| `validator-blocked` | Validator on Critical | Validator when next pass is Clean |
| `security-blocked` | Security Reviewer on Critical | Security Reviewer when Clean |
| `compliance-blocked` | Compliance Reviewer on Critical | Compliance Reviewer when Clean |
| `from-validator` / `from-security` / `from-compliance` | applied to sub-issues from findings | manual |
| `deferred-question` | applied to sub-issues from open questions | manual |
| `cross-repo` | Spec Writer when brief spans repos | manual |
| `factory-degraded` | Orchestrator when Linear MCP partial | Orchestrator on reconnect |
| `factory-paused` | Orchestrator on stall > 24h | manual |
| `incident` + priority 1 | Incident Responder | manual / on resolution |

**Acceptance criteria** live as Linear **checkboxes** in the ticket description. Test Verifier ticks them on pass; Validator reads them to confirm coverage. See `.claude/LINEAR-INTEGRATION.md` §8.

**Auto-added criteria.** If this repo imports `@ogenticai/shield` or `@ogenticai/audit`, or is in the Therapy / Private Credit verticals, the Story Writer **always** appends these three criteria:
- `- [ ] PHI / privilege / MNPI handling routes through Shield before any LLM call`
- `- [ ] An audit event is emitted via Ogentic-Audit for every state change`
- `- [ ] Tenant isolation verified by an explicit test`

**Checkpoint approval.** David can approve either:
- In chat: reply `/approved` or `approved`
- In Linear: remove the relevant `needs-X-approval` label, or post a comment `/approved`

**OgenticAI Reviewer** already exists and lives in GitHub. On PR open it audits the diff against the linked Linear ticket's UAT checklist and blocks merge on fail. The factory's Validator and Security Reviewer **complement** it (catching things before the PR opens); they do not duplicate its checks.

---

## §F3 — Agent sign-off block

Every factory agent ends its final message with a structured summary so the next agent (and the human at checkpoints) can read the state quickly. This is the canonical shape:

```
SUMMARY
- Ticket: <OGE-xxx>
- Files added: ...
- Files edited: ...
- Patterns reused: ...
- New rules CLAUDE.md should learn from this work: ...
- Open questions for the next agent / human: ...
```

The "New rules" line is how your `CLAUDE.md` grows over time. Whenever an agent had to guess, surface the assumption. Every guess that wasn't perfectly right earns a new rule in your `CLAUDE.md` next session.

---

## §F4 — What the factory will NOT touch in your existing CLAUDE.md

Hard rule: the factory **never** edits `CLAUDE.md`. It surfaces rule-additions in its sign-off summaries. You decide whether to add them.

Sections 1–8 (or whatever your existing sections are) are yours. The factory reads them; it does not write them.

If you want the factory's section to live elsewhere — different filename, different folder, included from a higher-level memory file — change the `@./.claude/CLAUDE-FACTORY.md` import in your `CLAUDE.md` and update §F1 here to match. The agents discover everything via that file path.

---

— end of factory partial —
