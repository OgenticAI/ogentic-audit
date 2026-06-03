---
name: multi-repo-coordinator
description: Helper skill used by the cross-repo-coordinator agent. Knows how to read .claude/registry/repos.yml, fan out per-repo factory runs, and re-converge. Use when a feature's brief lists changes across more than one OgenticAI repo.
---

# Multi-repo coordinator (helper)

This skill backs the `cross-repo-coordinator` agent. It exists so the orchestration logic for cross-repo features is in one place, not duplicated inside agent prompts.

## When to engage

A technical brief produced by `spec-writer` has a "Cross-repo notes" section listing two or more repos. The feature-factory skill detects this and hands off to `cross-repo-coordinator`, which uses this skill.

## The fan-out pattern

```
                       approved technical brief
                                 │
                                 ▼
                   ┌─── cross-repo-coordinator ───┐
                   │                              │
   ┌───────────────┼──────────────┬───────────────┤
   │               │              │               │
   ▼               ▼              ▼               ▼
sub-brief A   sub-brief B    sub-brief C    sub-brief D
   │               │              │               │
   ▼               ▼              ▼               ▼
factory run    factory run    factory run    factory run
in repo A      in repo B      in repo C      in repo D
   │               │              │               │
   └───────────────┴──────────────┴───────────────┘
                                 │
                                 ▼
                       integration check
                                 │
                                 ▼
                          release-manager
```

## Steps

1. **Load the registry.** Read `.claude/registry/repos.yml`. Confirm every repo referenced in the brief is in the registry. If not, halt and ask the human to update the registry.

2. **Compute build order.** Topologically sort the affected repos by their declared dependencies (registry entry `depends_on`). Upstream (the repo whose API others consume) first. If a cycle exists, halt and report.

3. **Slice the brief.** For each repo, produce a sub-brief containing:
   - The slice of work owned by that repo
   - The API contracts this repo exposes (if it is upstream)
   - The API contracts this repo consumes from upstream repos (if it is downstream)
   - A reference list of all the other sub-briefs so each repo's builders know who is on the other end
   - The same approved user story (shared across all repos)

4. **Spawn sub-runs.** For each repo, in build order, spawn a feature-factory invocation. Pass it:
   - The sub-brief
   - The shared user story
   - The upstream repos' API summaries (only those produced before this sub-run started)

   Sub-runs can run in parallel only when they share no `depends_on` edges. The cross-repo-coordinator decides this from the topology.

5. **Track status.** Hold a status table:
   ```
   | Repo | Stage | Status |
   ```
   Update on each sub-run handoff.

6. **Propagate contracts.** When a sub-run's Python or TS Backend Builder emits its API summary, capture it and inject it into the downstream sub-runs that have not yet started.

7. **Re-converge.** When every sub-run is at "validator: clean" or "validator: open findings", produce an integration check:
   - Pull all open PRs into a local cross-repo checkout
   - Run any `cross-repo-tests/` suite the registry declares
   - Verify the API contracts line up (the Python API summary in repo A matches the ai-client expectations in repo B)

8. **Hand off to security-reviewer.** Once integration is green, run the security-reviewer against the union of all diffs. Then proceed to checkpoint 3 (PR approval) and release-manager.

## Halts

- Registry missing or out of date → halt, ask human
- Circular dependency between repos → halt, ask human
- A sub-run's validator finds the same Critical twice → halt, the design is wrong, escalate
- Integration check fails on API contract mismatch → halt, return to the upstream builder with the mismatch

## Output schema

The cross-repo-coordinator agent uses this skill's outputs. See that agent file for the exact `MULTI-REPO PLAN` and `INTEGRATION CHECK` block formats.
