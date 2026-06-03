---
name: repo-bootstrap
description: Install the OgenticAI Software Factory in a new repo. Drops the agents, the skills, the CLAUDE.md template, and the hooks. Use when adopting the factory in a repo for the first time.
---

# Repo bootstrap

Install the factory into a fresh OgenticAI repo.

## When to use

The user said:
- "Install the factory in [repo]"
- "Bootstrap this repo for the factory"
- "Set up the agents here"

## What this skill does

1. **Detect the stack.** Look for `package.json` (Node/TS), `pyproject.toml` (Python), `apps/` folders, `services/ai/`, `prisma/`, `alembic/`. Build a profile.
2. **Confirm with the operator.** Print the detected stack profile and ask: "Does this look right?" If anything is wrong, stop and ask.
3. **Copy the kit.** Drop into the repo root:
   - `.claude/agents/01-researcher.md` … `12-incident-responder.md`
   - `.claude/skills/feature-factory/SKILL.md`
   - `.claude/skills/build-with-tests/SKILL.md`
   - `.claude/skills/multi-repo-coordinator/SKILL.md`
   - `.claude/hooks/pre-commit`
   - `.claude/hooks/pre-push`
   - `.claude/registry/repos.yml.template`
4. **Generate a tailored `CLAUDE.md`.** Start from the template. Pre-fill stack and commands based on what was detected. Leave the architecture-rules and don't-do sections for the human to flesh out.
5. **Install the hooks.** Make them executable; configure `git config core.hooksPath` if the repo uses a non-default hooks path; otherwise drop into `.git/hooks/` symlinks.
6. **Smoke test.** Try committing a fake `.env` file. Confirm the pre-commit blocks it. Revert.
7. **Print the next-step checklist.**

## Output: the next-step checklist

After install, print this for the operator:

```
✅ Factory installed in <repo>.

Next steps (in this order):
1. Open .claude/CLAUDE.md and fill in:
   - Architecture rules specific to this repo
   - The "Don't do this" list (start small; grow it)
   - Pointers to deeper docs
   Target: 100–300 lines.

2. Open .claude/registry/repos.yml.template, rename to repos.yml,
   and add this repo plus any others it depends on or is depended on by.

3. Run one tiny feature through the factory. Pick something safe:
   - A copy change
   - A new admin button that calls an existing endpoint
   - A new internal metric
   Watch where the chain stumbles. Add the rules you wish CLAUDE.md had.

4. After 3 features, the factory will know this repo.
```

## Don't

- Don't overwrite an existing `.claude/` folder. If one exists, ask before merging.
- Don't auto-add the registry to git (it may reference private repos by URL).
- Don't enable factory-aware GitHub Actions automatically; that is a follow-up the human chooses.
