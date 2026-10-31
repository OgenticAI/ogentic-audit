#!/usr/bin/env bash
# Test harness for kit/.claude/hooks/pre-push.
#
# Pushes commits through the hook in a throwaway repo, with stubs first on
# PATH: `gh` answers with the approved account, and `uv` and `pnpm` record
# that they ran, then fail, so any language check that runs blocks the push.
# Run from any directory:
#
#   ./kit/.claude/hooks/tests/test-pre-push.sh
#
# Reporting site: the OgenticAI/sottonotes-hype bootstrap (2026-10-30). The
# push that installed the kit carried its .claude/scripts/*.py, so a Rust repo
# with no Python project ran `uv run ruff check .` and the push was blocked.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOOK="$SCRIPT_DIR/../pre-push"

if [[ ! -x "$HOOK" ]]; then
  echo "FAIL: hook not found or not executable at $HOOK" >&2
  exit 2
fi

tmpdir="$(mktemp -d -t pre-push-test.XXXXXX)"
trap 'rm -rf "$tmpdir"' EXIT

mkdir "$tmpdir/bin" "$tmpdir/repo"
printf '#!/bin/sh\necho davidoladeji-ogenticai\n' > "$tmpdir/bin/gh"
for tool in uv pnpm; do
  printf '#!/bin/sh\necho "%s $*" >> "%s/ran"\nexit 1\n' "$tool" "$tmpdir" > "$tmpdir/bin/$tool"
done
chmod +x "$tmpdir"/bin/*
PATH="$tmpdir/bin:$PATH"

cd "$tmpdir/repo"
git init -q -b main .
git config user.email "test@ogenticai.com"
git config user.name  "test"
git config commit.gpgsign false
git commit -q --allow-empty -m base
base="$(git rev-parse HEAD)"

passes=0
fails=0

# Commits the given files on top of the base commit and runs the hook for that
# push. expected: "skip" (the push passes and no check ran) or "check" (a
# check ran, and its failing stub blocked the push).
push_case() {
  local name="$1" expected="$2" rc=0 got
  shift 2
  git reset -q --hard "$base"
  git clean -qfdx
  rm -f "$tmpdir/ran"
  for f in "$@"; do
    mkdir -p "$(dirname "$f")"
    echo "x = 1" > "$f"
  done
  git add -A
  git commit -q -m "$name"
  echo "refs/heads/main $(git rev-parse HEAD) refs/heads/main $base" \
    | "$HOOK" origin "$tmpdir/remote.git" >/dev/null 2>&1 || rc=$?
  if [[ -s "$tmpdir/ran" ]]; then got="check"; else got="skip"; fi
  if [[ "$expected" == "skip" && "$got" == "skip" && $rc -eq 0 ]] ||
     [[ "$expected" == "check" && "$got" == "check" && $rc -ne 0 ]]; then
    echo "PASS  $name ($got, rc=$rc)"
    passes=$((passes+1))
  else
    echo "FAIL  $name — expected $expected, got $got with rc=$rc"
    fails=$((fails+1))
  fi
}

# The kit's files under .claude/ are not the repo's project, so they never
# trigger its checks, even in a repo that has one.
push_case "kit .py file, no pyproject.toml"      skip  .claude/scripts/tool.py
push_case "kit .py file, with pyproject.toml"    skip  pyproject.toml .claude/scripts/tool.py
# A check needs the manifest it runs against.
push_case "project .py file, no pyproject.toml"  skip  src/app.py
push_case "project .ts file, no package.json"    skip  src/app.ts
# With the manifest present, the checks still run.
push_case "project .py file, with pyproject.toml" check pyproject.toml src/app.py
push_case "project .ts file, with package.json"   check package.json src/app.ts

echo ""
echo "Results: $passes passed, $fails failed"
if (( fails > 0 )); then
  exit 1
fi
exit 0
