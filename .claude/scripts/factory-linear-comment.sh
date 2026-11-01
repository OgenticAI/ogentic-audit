#!/usr/bin/env bash
# factory-linear-comment.sh — post a [factory:*] comment authored by the factory's
# Linear agent (the OgenticAI Factory Bot OAuth app), via Mission Control. The box
# holds NO Linear token (OGE-2796): it POSTs to MC's factory-comment endpoint with
# the box→MC bearer, and MC posts the comment as the app. MC resolves an OGE-123
# identifier to a UUID server-side, so --issue takes either.
#
# Requires: FACTORY_DASHBOARD_SECRET (or TWIN_DASHBOARD_SECRET) and optionally
# MC_BASE_URL (defaults to https://missioncontrol.ogenticai.com), python3.
#
# Usage:
#   factory-linear-comment.sh --issue OGE-123 --body "markdown…"
#   printf '%s' "$long_md" | factory-linear-comment.sh --issue OGE-123 --body -
#
# The secret is read from the env INSIDE python and sent only in the Authorization
# header — never on argv.
set -euo pipefail

issue=""; body=""
while [ $# -gt 0 ]; do
  case "$1" in
    --issue) issue="$2"; shift 2;;
    --body)  body="$2";  shift 2;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done

[ "$body" = "-" ] && body="$(cat)"
[ -n "$body" ] || { echo "--body required" >&2; exit 2; }
[ -n "$issue" ] || { echo "--issue required (a Linear issue UUID or OGE-123 identifier)" >&2; exit 2; }

python3 - "$issue" "$body" <<'PY'
import json, os, ssl, sys, urllib.error, urllib.request
secret = os.environ.get("FACTORY_DASHBOARD_SECRET", "").strip() or os.environ.get("TWIN_DASHBOARD_SECRET", "").strip()
if not secret:
    sys.exit("box→MC secret not set (FACTORY_DASHBOARD_SECRET or TWIN_DASHBOARD_SECRET) — see docs/LINEAR-BOT-SETUP.md")
base = os.environ.get("MC_BASE_URL", "https://missioncontrol.ogenticai.com").rstrip("/")
payload = json.dumps({"issue": sys.argv[1], "body": sys.argv[2]}).encode()
req = urllib.request.Request(
    base + "/api/linear/factory-comment",
    data=payload,
    headers={"Authorization": "Bearer " + secret, "Content-Type": "application/json"},
)
try:
    with urllib.request.urlopen(req, timeout=30, context=ssl.create_default_context()) as r:
        out = json.loads(r.read())
except urllib.error.HTTPError as e:
    sys.exit("factory-comment HTTP %s: %s" % (e.code, e.read().decode()[:300]))
if not out.get("ok"):
    sys.exit("comment failed: " + json.dumps(out))
print("posted as %s — %s" % (out.get("author", "?"), out.get("url", "")))
PY
