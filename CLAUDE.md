# ogentic-audit — Architecture & Conventions

This file defines how this codebase is structured, how code is written, and how decisions are made. The OgenticAI Software Factory (a coordinated set of Claude agents in `.claude/`) reads this file and generates code coherent with these rules on the first pass.

---

## 0. Factory wiring (do not delete)

@./.claude/CLAUDE-FACTORY.md

The factory partial above tells every agent who they are, how Linear is wired, and what the three checkpoints are. Repo-specific rules continue below.

---

## 1. What this repo is

> _Replace this paragraph with one or two sentences describing what `ogentic-audit` does and who it serves. Keep it concrete — the agents read this first._

- **Primary Linear project:** (set in .claude/registry/repos.yml)
- **Stack:** undetected
- **Kind:** oss-library

---

## 2. Project structure

> _Sketch the directory layout. List the folders Claude is allowed to touch and the ones that are off-limits. 5–20 lines is usually enough._

```
ogentic-audit/
├── README.md
├── ...
```

---

## 3. Architecture rules

> _The non-negotiables. Things like:_
>
> - All tenancy comes from the session, never the request body.
> - One service per file under `services/`. Routes are thin.
> - No raw SQL outside the data layer.
>
> _Start with 3–5 rules. Grow the list every time the factory ships something you wish it had known._

1. _Rule one._
2. _Rule two._
3. _Rule three._

---

## 4. Don't do this

> _The smallest, sharpest list of anti-patterns the agents must avoid in this repo. Read `.claude/CLAUDE-FACTORY.md` for cross-repo "don't"s; this list is local-only._

- _Don't commit `.env` files._
- _Don't add a new top-level dependency without an ADR._

---

## 5. Build, test, run

> _Drop the exact commands the agents should use._

```
# install
# test
# lint
# typecheck
# run
```

---

## 6. Open questions for the operator

> _If anything above is wrong, leave a note here so the next factory run flags it before agents read this file._

- _none yet_
