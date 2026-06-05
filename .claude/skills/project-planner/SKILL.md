---
name: project-planner
description: Shape a new initiative into a Linear project — name, description, milestones, success metric, and a seed backlog of 3–7 issues — with one human approval gate before anything is created. Use when the work is too big to live in a single ticket or doesn't fit any existing project. Partner skill to feature-factory.
---

# Project Planner

You are the partner skill to `feature-factory`. Where `feature-factory` ships features, this skill **shapes the home those features live in**. It takes an initiative-sized ask and produces a Linear project with a seeded backlog, ready for `feature-factory` to start chewing through.

**Linear is the source of truth.** Everything this skill produces lands in Linear, and nothing is created until the operator approves.

## When to invoke this skill

The operator (or `feature-factory` §9) said:
- "Plan a new project for X"
- "Set up the X initiative"
- "Start a project for X"
- The `feature-factory` halted on the project-decision heuristic and the operator picked **Option A — create a new project**.

If the ask is a single feature or a bugfix, do **not** engage. Hand back to `feature-factory` instead.

## 0. Pre-flight — check org-knowledge first

Before you ask the operator anything, look for prior discussion of this initiative.

If `factory.knowledge_enabled` is true for the surface(s) involved (see `.claude/CLAUDE-FACTORY.md` §F7), call:

```
orgknowledge_search(
  q   = <one-sentence paraphrase of the ask the operator just made>,
  since = (today - P60D).isoformat() + "Z",   # last 60 days only
  limit = 10,
  threshold = 0.5
)
```

Three outcomes:

| Hit pattern | What you do |
|---|---|
| Any hit ≥ 0.80 that points to an **existing Linear project** | Halt before drafting. Tell the operator: "On reflection this fits `<existing project>` (cited: `<source_url>`). Want me to fold this in as a new milestone there, or are you sure it's a new project?" If yes-still-new, continue; otherwise hand back to `feature-factory`. |
| Hits 0.65–0.79 referencing decisions, prior specs, customer asks | Pull them into the intake. Reference them in the draft's OUTCOME / SUCCESS METRIC / NON-GOALS so the project is grounded in what the team has already said. |
| All hits < 0.65, or `code: NO_CONTENT`, or `code: UNREACHABLE` | Note "no prior org-knowledge above 0.65" in the draft's preamble and proceed normally. |

Do not gate the human checkpoint on this step — it just enriches the intake. The only hard halt is the **"already-fits-an-existing-project"** case above.

If `factory.knowledge_enabled=false`, skip silently and move to §1.

---

## 1. Intake — collect the brief

Ask the operator the following, one at a time (or in a single message if context supplies them already):

1. **Working name.** A short noun phrase. e.g. "Agent DealSizer v3", "Audit Library OSS Wave 2", "Therapy onboarding rebuild".
2. **One-sentence outcome.** What does success look like, in plain language? e.g. "DealSizer can quote a CRE loan in under 45 seconds end-to-end."
3. **Customer / persona.** Who benefits? Internal, named pilot, paying customer, broad public.
4. **Surface(s) affected.** Which repo(s) and which user surfaces? Pull from `.claude/registry/repos.yml`.
5. **Success metric.** What number moves? e.g. "median quote latency < 45s on the 50 most-recent quotes", "100% of audit chain breaks caught in CI".
6. **Time horizon.** Days, one cycle, multi-cycle, open-ended.
7. **Owner.** Who's accountable (likely David, but ask).
8. **Constraints / non-goals.** What this project explicitly *does not* do.

If the operator is brisk and gives a one-paragraph blob, parse what you can and confirm the rest in one round, not seven.

## 2. Shape — produce the plan as a draft

Produce this artefact in chat **before touching Linear**:

```
PROJECT PLAN — DRAFT (not yet created in Linear)
============================================================
Name:           <working name>
Owner:          <name>
Time horizon:   <e.g. 2 cycles>
Customer:       <persona / segment>
Surface(s):     <repo:area, repo:area>

OUTCOME
<one-sentence outcome>

SUCCESS METRIC
<the number that moves, and how it's measured>

NON-GOALS
- <thing this project explicitly does not do>
- <…>

MILESTONES
M1 — <short name>          target: <cycle / date>
   Definition of done: <one sentence>
M2 — <short name>          target: <cycle / date>
   Definition of done: <one sentence>
M3 — <short name>          target: <cycle / date>
   Definition of done: <one sentence>

SEED BACKLOG (3–7 issues)
- <Issue title>     · M1 · est: <S/M/L>
   <one-line description>
- <Issue title>     · M1 · est: <S/M/L>
   <one-line description>
- <Issue title>     · M2 · est: <S/M/L>
   <one-line description>
- <Issue title>     · M2 · est: <S/M/L>
   <one-line description>
- <Issue title>     · M3 · est: <S/M/L>
   <one-line description>

PROPOSED LINEAR SETTINGS
- Team:         OGE
- State:        Planned
- Lead:         <owner>
- Color:        <pick from existing palette or default>
- Icon:         <pick or default>
```

Three milestones is the default. Use two if the horizon is short, four if the work is genuinely staged. Never more than four.

Seed backlog rules:
- Each issue is **small enough that `feature-factory` could run it end-to-end without a re-scope.**
- Each issue points to a milestone.
- Each issue has a one-line description — not a full story (Story Writer will produce that when the issue runs).
- Cover every milestone with at least one seed issue.
- Do not seed more than 7. The backlog will grow during the run; you're seeding, not exhausting.

## 3. Checkpoint — the only human approval

Post the draft and stop:

> Draft project plan above. **Nothing has been created in Linear yet.**
>
> Approve to create:
> - **/approved** — create the project, the milestones, and the seed backlog as listed.
> - **/approved with changes: <list>** — apply edits, then create.
> - **/cancel** — discard.

Do not proceed without explicit approval. If the operator asks to iterate, edit the draft in place and re-post.

## 4. Execute — create in Linear (after approval)

In this order:

1. **Create the project.** `linear.save_project` with name, description (the OUTCOME + SUCCESS METRIC + NON-GOALS, formatted), team=OGE, state=Planned, lead, color, icon.
2. **Create the milestones.** `linear.save_milestone` per M, linked to the project, with target date if given.
3. **Create the seed issues.** `linear.save_issue` per row, with title, one-line description as body, project=<new>, milestone=<assigned M>, state=Backlog, assignee=<owner or null>, estimate=<S=1, M=3, L=5>, labels=[`from-project-planner`].
4. **Post the summary back to chat:**

```
✅ Project created: <name>
   Linear: <URL>
   Milestones: M1 (<id>), M2 (<id>), M3 (<id>)
   Seeded: <N> issues — OGE-aaa, OGE-bbb, OGE-ccc, …

Next step: pick the first seed issue and run it through the factory:
   > Build OGE-aaa through the factory.
```

## 5. Halt conditions

- Operator hasn't given enough to fill the brief and won't answer follow-ups → halt; do not invent.
- The ask actually fits an existing project once you've read the brief carefully → halt and tell the operator: "On reflection this fits <existing project>. Run it through `feature-factory` directly instead?"
- Linear is unavailable → halt; do not create blind.
- Operator's name/scope conflicts with an existing Linear project name → ask before proceeding.

## 6. What this skill is NOT

- Not for adding milestones to an existing project. That's a direct `linear.save_milestone` call by the operator.
- Not for opening a *GitHub repo* — that's `repo-create`. If the initiative needs a new repo (OSS library carve-out, new app), call `repo-create` first, then come back here.
- Not for sprint planning. Sprint planning happens inside an existing project, in the Linear UI or via `feature-factory` runs.

## 7. Cross-references

- Calls `orgknowledge_search` in §0 before any drafting — see `mcp-orgknowledge` plugin and CLAUDE-FACTORY §F7.
- Triggered by `feature-factory` §9 when the project-decision heuristic fires "Option A — create a new project".
- Pairs with `repo-create` when the initiative needs its own repo *and* its own project — call `repo-create` first to get the repo + registry entry, then call `project-planner` with the new repo as the surface.
- The seed issues land in `Backlog` with the `from-project-planner` label so they're easy to audit later. `feature-factory` runs them as normal.
