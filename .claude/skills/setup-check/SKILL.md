---
name: setup-check
description: Verify the local environment before a factory run — gh CLI account, git author email, SSH key, gh version, current branch, Linear actor identity. Use at the top of feature-factory, project-factory, repo-bootstrap, repo-create, fleet-onboarding (they call this automatically), or any time an agent in the chain hits an unexplained auth/attribution failure. Fails fast with the exact command to fix.
---

# Setup check

Verify the local environment is correct before any factory work starts. Cheap to run (~1s), expensive to skip (mis-attributed pushes break Vercel previews and OgenticAI Reviewer).

## When to invoke

- At the very top of `feature-factory`, `repo-bootstrap`, `repo-create`, `fleet-onboarding`.
- Any time an agent encounters an unexplained auth or attribution failure (it's almost always one of the things below).
- After the operator switches gh accounts or rotates SSH keys.

## What to check

### 1. gh CLI is authenticated as `davidoladeji-ogenticai`

```
gh api user --jq .login
```

Expect: `davidoladeji-ogenticai`. If anything else (including `davidoladeji`), halt and tell the operator:

> Your gh CLI is logged in as `<other>`. Switch with:
> ```
> gh auth switch -u davidoladeji-ogenticai
> ```

### 2. Global git author email is an OgenticAI identity

```
git config --global user.email
```

Expect: `david@ogenticai.com` (or any `@ogenticai.com` address, or the `davidoladeji-ogenticai@users.noreply.github.com` no-reply). If it's `davidoladeji@users.noreply.github.com` or any personal address, halt:

> Your global git author email is `<email>`. Fix:
> ```
> git config --global user.email david@ogenticai.com
> ```

### 3. SSH key for OgenticAI plugin pushes is present

```
test -f ~/.ssh/ogenticai_plugins
```

If missing, link the operator to the `ogenticai-git` plugin's setup-check tool — that plugin owns this concern.

### 4. gh CLI is recent enough

```
gh --version | head -1
```

Require ≥ `2.40.0`. Older versions parse `gh auth status` differently and the pre-push hook will misfire.

### 5. Current branch is sensible

- For `feature-factory`: must not be `main`. If on `main`, halt and ask which Linear branch to checkout (use Linear's auto-generated branch name).
- For `repo-bootstrap` / `repo-create` / `fleet-onboarding`: any branch is fine.

### 6. Box→Mission Control Linear path

The box holds **no Linear token** (OGE-2796). Every Linear call routes through Mission
Control, which acts as the "OgenticAI Factory Bot" OAuth app — so `[factory:*]` comments are
authored by the app, never a human, and the box carries only the box→MC bearer. See
`LINEAR-INTEGRATION.md` §14.

Confirm the box→MC secret is present and the round-trip resolves to the app user (MC's read-only
relay runs `viewer` as the app):

```
SECRET="${FACTORY_DASHBOARD_SECRET:-$TWIN_DASHBOARD_SECRET}"
test -n "$SECRET" && curl -fsS -X POST "${MC_BASE_URL:-https://missioncontrol.ogenticai.com}/api/linear/factory-gql" \
  -H "Authorization: Bearer $SECRET" -H "Content-Type: application/json" \
  -d '{"query":"{ viewer { email displayName } }"}'
```

Expect `data.viewer.email` ending `@oauthapp.linear.app` with `displayName` = `ogenticaifactorybot`.

If neither `FACTORY_DASHBOARD_SECRET` nor `TWIN_DASHBOARD_SECRET` is set, or the viewer is a human
(email NOT ending `@oauthapp.linear.app`), **halt** (unless `OGENTICAI_BYPASS_IDENTITY=1`). Post and stop:

> ❌ box→MC secret missing, or MC is not authenticated as the app. Set FACTORY_DASHBOARD_SECRET (or TWIN_DASHBOARD_SECRET) per `docs/LINEAR-BOT-SETUP.md`, or run once with `OGENTICAI_BYPASS_IDENTITY=1` (comments are buffered per LINEAR-INTEGRATION §9 — never posted as a human).

This is the Linear analogue of the git-identity gate — see `CLAUDE-FACTORY.md` §F2 and `LINEAR-INTEGRATION.md` §14.

## Output

On success, post a single block:

```
✅ setup-check
   gh user:    davidoladeji-ogenticai
   git email:  david@ogenticai.com
   ssh key:    ~/.ssh/ogenticai_plugins (present)
   gh version: 2.42.1
   branch:     oge-123-invoice-reminders-7d
   linear:     box→MC → OgenticAI Factory Bot (app)   (halts if secret missing/human — see check 6)
```

On any failure, post the failing item and the exact one-liner that fixes it, then halt the orchestration. Don't try to fix the operator's machine config yourself — they own that.

## Bypass

If the operator confirms they understand the risk (e.g., hot-fix from a borrowed machine), set:

```
OGENTICAI_BYPASS_IDENTITY=1
```

This skips checks 1, 2, and 6 here AND mirrors into the pre-push hook so the push isn't blocked downstream. Set it for the single command only — do not export it persistently.

## Why this exists

Vercel and OgenticAI Reviewer both attribute work by author email. The personal-account no-reply (`davidoladeji@users.noreply.github.com`) attributes commits to the wrong GitHub user, which:

- Breaks Vercel preview-deployment owner detection.
- Breaks OgenticAI Reviewer's UAT-checklist gating (it can't tie the PR back to the right Linear assignee).
- Confuses contributor-stat dashboards across the org.

This skill makes the failure mode visible **before** the push, not after. See `CLAUDE-FACTORY.md` §F5 for the full identity contract.
