---
name: repo-create
description: Create a new GitHub repository in the OgenticAI org, register it in `.claude/registry/repos.yml`, and chain into `repo-bootstrap` to install the factory inside it. One human approval gate before any side effect. Use when an initiative needs its own codebase — a new app, an OSS-library carve-out, a service split-out.
---

# Repo Create

The upstream partner of `repo-bootstrap`. Where `repo-bootstrap` installs the factory **into an existing repo**, this skill **creates the repo first** — in the OgenticAI GitHub organisation — and only then hands off to `repo-bootstrap`.

This is the heaviest of the orchestrator skills because it has real, external side effects: a new GitHub repo is a permanent artefact, visible to anyone with org access, that we'll have to live with. So: one approval gate, no surprises.

## §0 — Pre-flight (always run first)

Before anything else, invoke the `setup-check` skill. It verifies that:

- `gh` CLI is authenticated as `davidoladeji-ogenticai` (the org-admin account)
- The local git author email is an OgenticAI identity
- The SSH key for OgenticAI plugin pushes is present
- The current branch is sensible for this run

`setup-check` is fast (~1s) and halts with the exact fix if anything is off. If the operator sets `OGENTICAI_BYPASS_IDENTITY=1`, it short-circuits — only use that when the operator explicitly authorises it in chat. See `CLAUDE-FACTORY.md` §F5 for the full identity contract.

---

## When to invoke this skill

The operator (or `project-planner`) said:
- "Create a new repo for X"
- "Open a repo called <name>"
- "Carve out <library> as its own OSS repo"
- "Spin up the <new-app> codebase"

If the work fits an existing repo, do **not** engage. Hand back to `feature-factory` or `repo-bootstrap` instead.

## 1. Intake — collect the brief

Ask the operator (or parse from context):

1. **Repo name.** Lowercase, kebab-case, no `ogenticai-` prefix (the org is `OgenticAI/` — names don't need to repeat it). Examples: `agent-billing`, `audit-rs`, `dealsizer-mobile`.
2. **One-sentence description.** Goes into the GitHub repo description and the registry entry.
3. **Canonical stack.** One of: `nextjs-ts`, `fastapi-python`, `tauri-rust`, `rust-lib`, `python-lib`, `ts-lib`, `mixed`, `other-<explain>`. Pull defaults from existing repos in the registry.
4. **Repo kind.** One of: `app` (deployable), `service` (deployable backend), `oss-library` (published), `internal-library` (consumed by other Ogentic repos), `tooling` (CLI/scripts), `playground` (experimental).
5. **Visibility.** `private` (default for OgenticAI) or `public` (only for `oss-library` or explicit-decision public).
6. **Initial team(s) granted push.** Default: the team(s) listed for the closest existing repo. Ask if unsure.
7. **License.** `proprietary` (default for `private`), `MIT` / `Apache-2.0` (for `oss-library`). If `public`, license is required.
8. **Linear project.** Which project owns it? If no fitting project exists, halt and route via `project-planner` first.

## 2. Validate before drafting

- **Name doesn't already exist** in the org. Call `gh repo view OgenticAI/<name>` — if it returns a repo, halt and ask whether to rename or use the existing one.
- **Org policy.** OgenticAI disallows private repo forking by default; if the operator asked for `allow_forking=true`, warn that it'll be rejected for private and ask whether to make the repo public instead.
- **Registry slot.** Check `.claude/registry/repos.yml`. If the name is already in the registry but the GitHub repo doesn't exist, the registry is out of date — flag this; ask whether to remove the stale entry first.

## 3. Draft — produce the plan

Post the plan to chat **before any `gh` call**:

```
REPO CREATE — DRAFT (nothing created yet)
============================================================
Repo:          OgenticAI/<name>
Visibility:    <private | public>
Description:   <one-sentence>
Kind:          <app | service | oss-library | …>
Canonical stack: <nextjs-ts | fastapi-python | …>
License:       <proprietary | MIT | Apache-2.0>
Allow forking: false (org policy for private)
Default branch: main
Wiki:          off
Projects:      off
Issues:        on
Topics:        <kind>, <stack>, <one-or-two-domain-tags>

ACCESS
- Push:        <team-slugs>
- Admin:       org-admins (inherited)

REGISTRY ENTRY (.claude/registry/repos.yml)
- name: <name>
  url: https://github.com/OgenticAI/<name>
  kind: <kind>
  canonical_stack: <stack>
  primary_project: <linear-project-id-or-name>
  description: <one-sentence>
  visibility: <private | public>
  depends_on: []         # operator can fill in later
  depended_on_by: []     # operator can fill in later
  linkage: commit-prefix # feat(OGE-NNN): … per OgenticAI convention

POST-CREATE CHAIN
1. Initialise repo with README + LICENSE + .gitignore (auto for stack).
2. Hand off to repo-bootstrap to install the factory.
```

## 4. Checkpoint — the only human approval

> Draft above. **Nothing has been created in GitHub yet.** Approve to proceed:
>
> - **/approved** — create the repo as drafted, update the registry, run `repo-bootstrap`.
> - **/approved with changes: <list>** — apply edits, then create.
> - **/cancel** — discard.

Do not proceed without explicit approval. Side effects from here onward are external and not trivially reversible.

### 4.1 Bulk-approved mode (for fleet-onboarding only)

When invoked by `fleet-onboarding` Phase 3.0 with the parameter `--bulk-approved`, the operator's earlier Phase-2 approval in `fleet-onboarding` substitutes for this checkpoint. In that mode:

- Skip the chat-side `Approve to proceed` prompt.
- Still print the draft from §3 to chat — it remains the auditable record of what's about to happen.
- Halt anyway if any §2 validation fails (name collision, org policy conflict, stale registry entry). Those are not pre-approvable.

`--bulk-approved` must come from an orchestrator skill in the kit, not from a free-form operator request. If you can't verify the caller, ignore the flag and run the normal §4 gate.

## 5. Execute — create in order, halting on any failure

1. **Create the repo.**
   ```
   gh repo create OgenticAI/<name> \
     --<visibility> \
     --description "<desc>" \
     --license "<license>"             # only if non-proprietary
   ```
   Use the `gh` auth scoped to the OgenticAI org (token with `admin:org`). Verify with `gh auth status` first; if the active account can't write to the org, halt and ask the operator to switch.

2. **Set repo settings.**
   ```
   gh api -X PATCH repos/OgenticAI/<name> \
     -F has_wiki=false \
     -F has_projects=false \
     -F delete_branch_on_merge=true
   ```
   Forking is already false by org policy; do not include it in the PATCH or the call will 422.

3. **Set topics.**
   ```
   gh api -X PUT repos/OgenticAI/<name>/topics \
     -f names[]="<kind>" -f names[]="<stack>" …
   ```

4. **Grant team push access** for each requested team:
   ```
   gh api -X PUT orgs/OgenticAI/teams/<slug>/repos/OgenticAI/<name> \
     -F permission=push
   ```

5. **Initial commit.** Clone the empty repo locally, drop in a starter `README.md` (just the name + description + "Generated by `repo-create` on <date>"), the stack-appropriate `.gitignore`, and a `LICENSE` (Git filling for non-proprietary; a short proprietary notice for proprietary). Commit. Push.

6. **Update the registry.** Open `.claude/registry/repos.yml` *in the current repo* (the one this skill is running from). Append the new entry from §3. Save. Stage. Commit to a branch `factory/register-<name>` and open a PR — don't push directly to main.

7. **Hand off to `repo-bootstrap`.** Clone the new repo, run `repo-bootstrap` against it. That skill detects the stack (which will be the just-bootstrapped one), drops the kit, installs hooks, smoke-tests, prints its checklist.

8. **Summary to chat:**

```
✅ Repo created: OgenticAI/<name>
   URL: https://github.com/OgenticAI/<name>
   Initial commit: <sha>
   Registry PR: <url-of-PR-on-current-repo>
   repo-bootstrap: ran on the new repo, install checklist below ↓

<checklist from repo-bootstrap>
```

## 6. Halt conditions

- Active `gh` account doesn't have `admin:org` on OgenticAI → halt; ask the operator to `gh auth switch`.
- Name collision with existing repo → halt; ask rename or reuse.
- Operator asked for a setting that conflicts with org policy (e.g. forking on a private) → halt; surface the policy; ask the operator to choose.
- Registry entry collides with a stale line → halt; ask whether to clean the registry first.
- Any `gh` call in §5 fails with a non-trivial error → halt; surface the error; do not attempt cleanup automatically (the operator may want the partial state preserved for diagnosis).
- Linear connectivity lost mid-run → §5 steps 1–7 can complete; defer the registry-PR-Linear-link until Linear is back. The registry PR itself goes through.

## 7. What this skill is NOT

- Not for renaming or transferring existing repos — those are explicit `gh repo rename` / `gh api transfers` calls.
- Not for forks — OgenticAI's policy disallows them for private repos, and public forks should be made via the GitHub UI by the human, not by the factory.
- Not for archival — archiving is `gh repo archive`, run by the operator.
- Not for creating Linear projects — that's `project-planner`. If the new repo also needs a new project (which it usually does for an OSS-library carve-out), call `project-planner` *after* this skill completes, with the new repo's name as the surface.

## 8. Cross-references

- Pairs with `project-planner` when the new repo needs a fresh Linear project. Order: `repo-create` first, then `project-planner` with `surface: <new-repo>`.
- Hands off to `repo-bootstrap` to install the factory inside the new repo.
- Updates `.claude/registry/repos.yml`, which `multi-repo-coordinator` reads when work spans repos.
