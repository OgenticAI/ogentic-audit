#!/usr/bin/env python3
"""Apply the factory's repository settings to one repo, or backfill an org.

OGE-2818. The same finding was raised and fixed one repo at a time four times
(OGE-1021, OGE-1654, OGE-2363, OGE-2769) while the org never changed. The cause
was that `repo-create` set `delete_branch_on_merge` and nothing else, and no
tool existed to bring an existing repo up to the standard. This is that tool,
and `repo-create` calls it, so a new repo and a backfilled one get the same
settings from the same code.

What it sets, per repo:

- `allow_auto_merge=true`, so agent PRs merge themselves once CI is green.
- `delete_branch_on_merge=true`.
- Branch protection on the default branch with **at least one required status
  check**, discovered from the checks that actually ran on recent PRs.

Two rules it will not break, because each describes a failure already seen:

1. **It never creates protection that requires nothing.** Protection with zero
   required checks reads as configured and gates nothing. A repo with no CI is
   reported as needing CI first, and left alone.
2. **It only requires a check that ran on every recent PR.** A check with a
   `paths:` filter, or one that is skipped on some PRs, would block every PR it
   does not run on, forever. A name has to appear, not skipped, on each of the
   last few merged PR heads before it is treated as safe to require.

What it deliberately does not do:

- It does not lower a required-approvals count. Agents author as
  `den-ogenticai` and GitHub will not let an account approve its own PR, so a
  count above zero blocks agent PRs. That is reported. Relaxing a review rule
  weakens protection and stays a human decision.
- It does not touch secret scanning, push protection or Dependabot security
  updates. Those are organisation-level defaults, and on private repositories
  they are a paid add-on. Current state is reported so the org change can be
  verified afterwards.
- It does not change `enforce_admins`. It reports it.

Dry-run is the default. Nothing is written without `--apply`.

    harden-repo.py --repo OgenticAI/<name>            # plan one repo
    harden-repo.py --repo OgenticAI/<name> --apply    # apply to one repo
    harden-repo.py --org OgenticAI                    # plan the whole org
    harden-repo.py --org OgenticAI --apply --json out.json

Uses the `gh` CLI, so it runs as whichever account `gh` (or `GH_TOKEN`) holds.
That account needs admin on the repositories it changes.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from dataclasses import dataclass, field

# How many recent merged PRs a check must appear on to count as always-run.
PR_SAMPLE = 5
# Fewer merged PRs than this and there is not enough evidence to require anything.
MIN_PRS_FOR_EVIDENCE = 2
# A check-run in any of these conclusions did not really run on that PR.
DID_NOT_RUN = {"skipped", "neutral", "stale", "cancelled", None}


# --------------------------------------------------------------------------
# State and plan. Pure data, so the decisions can be tested without GitHub.
# --------------------------------------------------------------------------

@dataclass
class RepoState:
    full_name: str
    archived: bool = False
    default_branch: str = "main"
    branch_exists: bool = True
    allow_auto_merge: bool | None = None
    delete_branch_on_merge: bool | None = None
    protected: bool = False
    # None: protection exists but has no required_status_checks object at all.
    # []:   the object exists and requires nothing.
    required_checks: list[str] | None = None
    # The raw protection document, so a rewrite can preserve what it does not own.
    protection: dict = field(default_factory=dict)
    # Check names seen on each of the recent merged PR heads, newest first.
    pr_check_names: list[set[str]] = field(default_factory=list)
    security: dict = field(default_factory=dict)


@dataclass
class Plan:
    repo: str
    changes: list[dict] = field(default_factory=list)   # things --apply would do
    needs_human: list[str] = field(default_factory=list)  # things it will not do
    notes: list[str] = field(default_factory=list)
    discovered_checks: list[str] = field(default_factory=list)


def discover_required_checks(pr_check_names: list[set[str]]) -> list[str]:
    """Names that ran on every one of the recent PR heads.

    The intersection is the whole safety argument: a name missing from any
    sampled PR is exactly the kind of check that would strand a future PR.
    """
    sample = pr_check_names[:PR_SAMPLE]
    if len(sample) < MIN_PRS_FOR_EVIDENCE:
        return []
    common = set.intersection(*sample) if sample else set()
    return sorted(common)


def plan_repo(s: RepoState) -> Plan:
    p = Plan(repo=s.full_name)

    if s.archived:
        p.notes.append("archived, skipped")
        return p
    if not s.branch_exists:
        p.notes.append(f"default branch '{s.default_branch}' does not exist (empty repo), skipped")
        return p

    if s.allow_auto_merge is not True:
        p.changes.append({"kind": "repo_setting", "field": "allow_auto_merge", "value": True})
    if s.delete_branch_on_merge is not True:
        p.changes.append({"kind": "repo_setting", "field": "delete_branch_on_merge", "value": True})

    checks = discover_required_checks(s.pr_check_names)
    p.discovered_checks = checks
    already = s.required_checks or []

    if s.protected and already:
        p.notes.append(f"already requires: {', '.join(sorted(already))}")
    elif not checks:
        # Rule 1: never create or leave protection that pretends to gate.
        why = (
            f"fewer than {MIN_PRS_FOR_EVIDENCE} merged PRs to learn from"
            if len(s.pr_check_names) < MIN_PRS_FOR_EVIDENCE
            else "no check ran on every recent PR"
        )
        if s.protected:
            p.needs_human.append(
                f"protected but requires no status check, and none can be required safely ({why}); needs CI that runs on every PR"
            )
        else:
            p.needs_human.append(f"unprotected, and no check can be required safely ({why}); needs CI before protection")
    elif not s.protected:
        p.changes.append({"kind": "create_protection", "branch": s.default_branch, "checks": checks})
    elif s.required_checks is None:
        p.changes.append({"kind": "add_status_checks_object", "branch": s.default_branch, "checks": checks})
    else:
        p.changes.append({"kind": "add_status_check_contexts", "branch": s.default_branch, "checks": checks})

    reviews = (s.protection or {}).get("required_pull_request_reviews") or {}
    count = reviews.get("required_approving_review_count") or 0
    if count > 0:
        p.needs_human.append(
            f"requires {count} approving review(s); agents author as den-ogenticai and cannot approve their own PRs, so agent PRs cannot merge"
        )

    if s.protected:
        admins = ((s.protection or {}).get("enforce_admins") or {}).get("enabled")
        p.notes.append(f"enforce_admins={admins} (left unchanged)")

    for key in ("secret_scanning", "secret_scanning_push_protection", "dependabot_security_updates"):
        status = (s.security.get(key) or {}).get("status")
        if status != "enabled":
            p.notes.append(f"{key}={status or 'unavailable'} (org-level setting, not changed here)")

    return p


def protection_put_body(existing: dict, checks: list[str]) -> dict:
    """A full protection PUT that adds status checks and keeps everything else.

    PUT replaces the whole rule, so every field not being changed has to be
    carried across, or an unrelated rule is silently dropped.
    """
    def enabled(key: str) -> bool:
        return bool((existing.get(key) or {}).get("enabled"))

    reviews = existing.get("required_pull_request_reviews")
    reviews_body = None
    if reviews:
        reviews_body = {
            "dismiss_stale_reviews": reviews.get("dismiss_stale_reviews", False),
            "require_code_owner_reviews": reviews.get("require_code_owner_reviews", False),
            "required_approving_review_count": reviews.get("required_approving_review_count", 0),
            "require_last_push_approval": reviews.get("require_last_push_approval", False),
        }

    restrictions = existing.get("restrictions")
    restrictions_body = None
    if restrictions:
        restrictions_body = {
            "users": [u["login"] for u in restrictions.get("users", [])],
            "teams": [t["slug"] for t in restrictions.get("teams", [])],
            "apps": [a["slug"] for a in restrictions.get("apps", [])],
        }

    return {
        "required_status_checks": {"strict": False, "contexts": checks},
        "enforce_admins": enabled("enforce_admins"),
        "required_pull_request_reviews": reviews_body,
        "restrictions": restrictions_body,
        "required_linear_history": enabled("required_linear_history"),
        "allow_force_pushes": enabled("allow_force_pushes"),
        "allow_deletions": enabled("allow_deletions"),
        "required_conversation_resolution": enabled("required_conversation_resolution"),
        "lock_branch": enabled("lock_branch"),
    }


# --------------------------------------------------------------------------
# GitHub I/O.
# --------------------------------------------------------------------------

def gh(path: str, method: str = "GET", body: dict | None = None) -> tuple[int, object]:
    cmd = ["gh", "api", "-X", method, path]
    if body is not None:
        cmd += ["--input", "-"]
    r = subprocess.run(cmd, input=json.dumps(body) if body is not None else None,
                       capture_output=True, text=True)
    try:
        data = json.loads(r.stdout) if r.stdout.strip() else None
    except json.JSONDecodeError:
        data = r.stdout
    return r.returncode, data


def gh_paginated(path: str) -> list:
    r = subprocess.run(["gh", "api", "--paginate", path], capture_output=True, text=True)
    if r.returncode != 0 or not r.stdout.strip():
        return []
    return json.loads(r.stdout.replace("][", ","))


def read_state(full_name: str) -> RepoState:
    _, repo = gh(f"repos/{full_name}")
    repo = repo if isinstance(repo, dict) else {}
    branch = repo.get("default_branch", "main")
    s = RepoState(
        full_name=full_name,
        archived=bool(repo.get("archived")),
        default_branch=branch,
        allow_auto_merge=repo.get("allow_auto_merge"),
        delete_branch_on_merge=repo.get("delete_branch_on_merge"),
        security=repo.get("security_and_analysis") or {},
    )
    if s.archived:
        return s

    code, _ = gh(f"repos/{full_name}/branches/{branch}")
    if code != 0:
        s.branch_exists = False
        return s

    code, prot = gh(f"repos/{full_name}/branches/{branch}/protection")
    if code == 0 and isinstance(prot, dict):
        s.protected = True
        s.protection = prot
        rsc = prot.get("required_status_checks")
        if rsc is None:
            s.required_checks = None
        else:
            names = [c.get("context") for c in rsc.get("checks") or []] or list(rsc.get("contexts") or [])
            s.required_checks = [n for n in names if n]

    _, pulls = gh(f"repos/{full_name}/pulls?state=closed&base={branch}&sort=updated&direction=desc&per_page=30")
    merged = [pr for pr in (pulls or []) if isinstance(pr, dict) and pr.get("merged_at")][:PR_SAMPLE]
    for pr in merged:
        sha = pr["head"]["sha"]
        _, runs = gh(f"repos/{full_name}/commits/{sha}/check-runs?per_page=100")
        names = {
            cr["name"]
            for cr in ((runs or {}).get("check_runs") or [])
            if cr.get("conclusion") not in DID_NOT_RUN
        }
        s.pr_check_names.append(names)
    return s


def apply_plan(s: RepoState, p: Plan) -> list[str]:
    results = []
    repo_fields = {c["field"]: c["value"] for c in p.changes if c["kind"] == "repo_setting"}
    if repo_fields:
        code, data = gh(f"repos/{s.full_name}", "PATCH", repo_fields)
        results.append(f"repo settings {repo_fields}: {'ok' if code == 0 else f'FAILED {data}'}")

    for c in p.changes:
        branch = c.get("branch")
        if c["kind"] in ("create_protection", "add_status_checks_object"):
            body = protection_put_body(s.protection if c["kind"] != "create_protection" else {}, c["checks"])
            code, data = gh(f"repos/{s.full_name}/branches/{branch}/protection", "PUT", body)
            results.append(f"{c['kind']} {c['checks']}: {'ok' if code == 0 else f'FAILED {data}'}")
        elif c["kind"] == "add_status_check_contexts":
            code, data = gh(
                f"repos/{s.full_name}/branches/{branch}/protection/required_status_checks/contexts",
                "POST", {"contexts": c["checks"]},
            )
            results.append(f"{c['kind']} {c['checks']}: {'ok' if code == 0 else f'FAILED {data}'}")
    return results


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    target = ap.add_mutually_exclusive_group(required=True)
    target.add_argument("--repo", help="owner/name")
    target.add_argument("--org", help="apply to every non-archived repo in this org")
    ap.add_argument("--apply", action="store_true", help="write changes (default is a dry run)")
    ap.add_argument("--json", help="write the per-repo report to this file")
    args = ap.parse_args(argv)

    if args.repo:
        names = [args.repo]
    else:
        names = sorted(r["full_name"] for r in gh_paginated(f"orgs/{args.org}/repos?type=all&per_page=100")
                       if not r.get("archived"))

    report = []
    mode = "APPLY" if args.apply else "DRY RUN"
    print(f"{mode}: {len(names)} repo(s)\n")
    for name in names:
        s = read_state(name)
        p = plan_repo(s)
        applied = apply_plan(s, p) if args.apply and p.changes else []
        report.append({"repo": name, "changes": p.changes, "applied": applied,
                       "needs_human": p.needs_human, "notes": p.notes,
                       "discovered_checks": p.discovered_checks})
        print(f"== {name}")
        for c in p.changes:
            label = "applied" if args.apply else "would"
            print(f"   {label}: {c['kind']} {c.get('field') or c.get('checks')}")
        for r in applied:
            print(f"   result: {r}")
        for h in p.needs_human:
            print(f"   NEEDS HUMAN: {h}")
        for n in p.notes:
            print(f"   note: {n}")

    changed = sum(1 for r in report if r["changes"])
    human = sum(1 for r in report if r["needs_human"])
    failed = sum(1 for r in report for a in r["applied"] if "FAILED" in a)
    print(f"\n{mode} summary: {len(report)} repos, {changed} with changes, {human} need a human, {failed} failures")
    if args.json:
        with open(args.json, "w") as fh:
            json.dump(report, fh, indent=1)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
