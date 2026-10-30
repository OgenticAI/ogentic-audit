#!/usr/bin/env bash
# Test harness for kit/.claude/hooks/pre-commit.
#
# Runs the hook against a series of staged fixtures in a throwaway git repo
# and asserts each one is either allowed (exit 0) or blocked (exit 1).
#
# Designed to work on macOS (BSD grep) and Linux (GNU grep). Run from any
# directory:
#
#   ./kit/.claude/hooks/tests/test-pre-commit.sh
#
# Reporting site for the bug this regresses against:
#   OgenticAI/finops-ogentic initial bootstrap (2026-06-03), which committed
#   a .env.example template and tripped the over-broad `\.env\.` rule.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOOK="$SCRIPT_DIR/../pre-commit"

if [[ ! -x "$HOOK" ]]; then
  echo "FAIL: hook not found or not executable at $HOOK" >&2
  exit 2
fi

tmpdir="$(mktemp -d -t pre-commit-test.XXXXXX)"
trap 'rm -rf "$tmpdir"' EXIT

cd "$tmpdir"
git init -q -b main .
git config user.email "test@example.com"
git config user.name  "test"
git config commit.gpgsign false

passes=0
fails=0

# Run the hook against the currently-staged tree. expected: "allow" | "block".
# Resets the index between cases so fixtures don't bleed.
run_case() {
  local name="$1"
  local expected="$2"
  local rc=0
  "$HOOK" >/dev/null 2>&1 || rc=$?
  if [[ "$expected" == "allow" && $rc -eq 0 ]]; then
    echo "PASS  $name (allowed)"
    passes=$((passes+1))
  elif [[ "$expected" == "block" && $rc -ne 0 ]]; then
    echo "PASS  $name (blocked, rc=$rc)"
    passes=$((passes+1))
  else
    echo "FAIL  $name — expected $expected, got rc=$rc"
    fails=$((fails+1))
  fi
  git rm -rf --cached -q . >/dev/null 2>&1 || true
  find . -mindepth 1 -path ./.git -prune -o -print0 | xargs -0 rm -rf
}

# --- Case 1: .env.example with a placeholder DATABASE_URL is allowed -------
# This is the reporting-site regression. finops-ogentic committed exactly
# this kind of file and the over-broad `\.env\.` forbidden-path rule blocked
# it. With the allowlist in place it must pass.
cat > .env.example <<'EOF'
# Copy to .env and fill in real values.
DATABASE_URL=postgres://user:password@localhost:5432/finops_ogentic
OPENAI_API_KEY=sk-REPLACE_ME
EOF
git add .env.example
run_case ".env.example with DATABASE_URL placeholder" "allow"

# --- Case 2: .env.local.example is also allowed ---------------------------
cat > .env.local.example <<'EOF'
NEXTAUTH_SECRET=replace-me
EOF
git add .env.local.example
run_case ".env.local.example" "allow"

# --- Case 3: .env.sample is allowed ---------------------------------------
cat > .env.sample <<'EOF'
FOO=bar
EOF
git add .env.sample
run_case ".env.sample" "allow"

# --- Case 4: an actual .env file is still blocked -------------------------
cat > .env <<'EOF'
DATABASE_URL=postgres://user:password@localhost:5432/whatever
EOF
git add .env
run_case ".env (real dotenv) is blocked" "block"

# --- Case 5: .env.local is still blocked ----------------------------------
cat > .env.local <<'EOF'
SECRET=hunter2
EOF
git add .env.local
run_case ".env.local is blocked" "block"

# --- Case 6: a PEM-shaped private key in content is detected on BSD grep --
# Before the `--` fix, BSD grep parsed the leading `-` of the regex as a
# flag and silently failed. This case proves the content scan actually fires.
mkdir -p config
# Before the `--` fix, BSD grep parsed the leading dash of the pattern as a
# flag and printed `usage:` for every staged file, so this content scan
# silently passed even on a real key. With the fix it must block.
# Every key header in this file is assembled by printf at run time: a literal
# one would make the hook block the commit that installs the kit (Case 9).
printf -- 'Pasted from old server, do not commit:\n-----BEGIN %s-----\nMIIEpAIBAAKCAQEAtVERYFAKEKEYMATERIALFORTESTONLY\n-----END %s-----\n' \
  "PRIVATE KEY" "PRIVATE KEY" > config/notes.txt
git add config/notes.txt
run_case "PEM private key in file content is blocked" "block"

# --- Case 7: every common private-key header is blocked -------------------
# The original regex only matched PKCS8 `BEGIN PRIVATE KEY`; RSA, EC, DSA,
# OpenSSH, encrypted and PGP keys slipped through.
for header in "RSA PRIVATE KEY" "EC PRIVATE KEY" "DSA PRIVATE KEY" \
              "OPENSSH PRIVATE KEY" "ENCRYPTED PRIVATE KEY" "PGP PRIVATE KEY BLOCK"; do
  printf -- '-----BEGIN %s-----\nMIIFAKEKEYMATERIALFORTESTONLY\n' "$header" > key.txt
  git add key.txt
  run_case "BEGIN $header in content is blocked" "block"
done

# --- Case 8: a public key is not a secret ---------------------------------
printf -- '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n' > pub.txt
git add pub.txt
run_case "BEGIN PUBLIC KEY is allowed" "allow"

# --- Case 9: the kit's own files commit clean ------------------------------
# Installing the kit commits every file under .claude/, this test included.
# A secret-shaped literal anywhere in the kit blocks that commit, as the PEM
# header Case 6 once held did on the OgenticAI/sottonotes-hype bootstrap
# (2026-10-30).
cp -R "$SCRIPT_DIR/../.." .claude
git add .claude
run_case "the kit's own files commit clean" "allow"

# --- Case 10: a key at the top of a large file is blocked ------------------
# The scan piped `git diff` into `grep -q`. grep exits on the first match,
# git then dies of SIGPIPE on its next write, and under pipefail that 141
# read as "no match": any diff bigger than the pipe buffer let a key through.
{ printf -- '-----BEGIN %s-----\n' "PRIVATE KEY"; head -c 300000 /dev/zero | tr '\0' 'a' | fold -w 80; } > big.txt
git add big.txt
run_case "key on the first line of a 300KB file is blocked" "block"

# --- Case 11: deleting a committed key is allowed --------------------------
# Only the lines a commit adds are scanned. Scanning the whole diff also
# matched the line being removed, which blocked deleting a leaked key.
printf -- 'keep\n-----BEGIN %s-----\n' "PRIVATE KEY" > old-key.txt
git add old-key.txt
git commit -q -m "a key that leaked"
echo keep > old-key.txt
git add old-key.txt
run_case "deleting a committed key is allowed" "allow"

echo ""
echo "Results: $passes passed, $fails failed"
if (( fails > 0 )); then
  exit 1
fi
exit 0
