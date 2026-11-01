---
name: factory-learn
description: Turn what factory runs learned into rules the next run follows. Reads the per-ticket learnings feature-factory captures in .claude/learnings/, groups the ones that say the same thing, and promotes any rule two or more tickets taught into .claude/LEARNED.md through a PR the operator approves. Rules true of every repo go upstream to the agent-factory kit instead. Use when the operator asks "what has the factory learned?", when a run reports a recurring learning, or as a periodic hygiene pass.
---

# Factory Learn — remember, then improve

Every agent already says what it learned: the sign-off block has a `New rules CLAUDE.md should learn` line (CLAUDE-FACTORY §F3), and feature-factory §5a writes those lines to `.claude/learnings/<TICKET-ID>.md`. Before this skill they stopped there, in comments nobody added up. This skill closes the loop: plan → test → implement → review → verify → **remember → improve**.

## The model

| Stage | Where it lives | Changes how runs behave? |
|---|---|---|
| Candidate | `.claude/learnings/<TICKET-ID>.md`, one file per ticket, written by every run | No. Nothing loads it. |
| Rule | `.claude/LEARNED.md`, loaded by `CLAUDE-FACTORY.md` §F4 | Yes, every session in this repo. |
| Canon | the agent-factory kit: `build-with-tests`, an agent's checklist, or the core canon at its source | Yes, every repo after propagation. |

A candidate becomes a rule when **two or more distinct tickets** taught it. One ticket is an anecdote; two is a pattern.

## Steps

1. **Read** every `.claude/learnings/*.md`, `CLAUDE.md` and `.claude/LEARNED.md`.
2. **Group** candidates that state the same rule in different words. Two lines are the same rule when an agent following either would do the same thing.
3. **Drop** any group that `CLAUDE.md` or `LEARNED.md` already states. If it is in `LEARNED.md`, add the new tickets to that rule's evidence instead.
4. **Classify** each group taught by two or more tickets:
   - **Repo rule** — it depends on this repo's code, stack or domain. Promote it into `.claude/LEARNED.md`.
   - **Fleet rule** — it holds for any OgenticAI repo (a testing, SQL or security discipline). Send it upstream (step 7) and keep it out of `LEARNED.md`.
5. **Write the rules** into `.claude/LEARNED.md` under domain headings, one line each, ending with the tickets that taught it:
   ```markdown
   ## tenancy
   - Manual trigger endpoints derive the tenant from the session, never from the request body. (OGE-123, OGE-161)
   ```
   If the file does not exist, start it with the header at the end of this skill.
6. **Tidy the candidates.** Delete a candidate file once every line in it is promoted or dropped as already known. Delete candidates older than 90 days that never recurred: a lesson nobody learned again in a quarter was not a pattern.
7. **Send fleet rules upstream.** Open an issue on `OgenticAI/agent-factory` (or a PR against the kit file the rule belongs in) quoting the rule, its tickets and its repo. Never edit this repo's vendored kit files instead: the next sync undoes it, and no other repo ever sees it.
8. **Open one PR**, `chore(factory): promote N learnings`, holding `LEARNED.md` and the tidied candidates. The body lists each promoted rule with its tickets and each fleet rule with its upstream link. The operator's approval of this PR is the checkpoint for changing how the factory behaves.

## Hard rules

- **Never edit `CLAUDE.md`** (CLAUDE-FACTORY §F4). `LEARNED.md` exists so the factory can learn without touching the operator's file.
- **Never promote a candidate only one ticket taught**, however good it sounds.
- **Never merge the promotion PR yourself**, headless mode included. A rule changes every later run, so a person reads it first.
- **Never promote a rule that contradicts `CLAUDE.md`.** Put the conflict to the operator.
- A rule is an instruction about this codebase that an agent can follow and a reviewer can check: "X must Y, because Z". "Be careful with X" is not a rule.

## LEARNED.md header

```markdown
# LEARNED.md — rules this repo's factory runs taught it

Promoted by the `factory-learn` skill from `.claude/learnings/`. Each rule was taught by two or more tickets, and a person approved it in a PR. Loaded through `CLAUDE-FACTORY.md` §F4. Edit freely: delete a rule that stopped being true, and the factory adds it back only if two new tickets teach it again.
```

## Output

```
FACTORY LEARN REPORT
Candidates read: N files, M lines
Promoted to LEARNED.md: K      (each: rule — tickets)
Sent upstream as fleet rules: J (each: rule — link)
Existing rules reinforced: R
Still candidates (one ticket so far): C
Pruned (older than 90 days, never recurred): P
PR: <url>
```
