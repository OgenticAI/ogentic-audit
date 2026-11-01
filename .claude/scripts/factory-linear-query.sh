#!/usr/bin/env bash
# factory-linear-query.sh — run a Linear GraphQL READ through Mission Control's
# read-only relay, which executes it as the factory's Linear agent (OAuth app).
# The box holds NO Linear token (OGE-2796); it authenticates to MC with the box→MC
# bearer and MC talks to Linear as the app.
#
# READ-ONLY: the relay rejects mutations (HTTP 403). For writes use the typed
# helpers (factory-linear-comment.sh for [factory:*] comments; `linear.py state|
# label|subissue` for the rest).
#
# Requires: FACTORY_DASHBOARD_SECRET (or TWIN_DASHBOARD_SECRET) and optionally
# MC_BASE_URL (defaults to https://missioncontrol.ogenticai.com), python3.
#
# Usage:
#   factory-linear-query.sh --query 'query($id:String!){issue(id:$id){title state{name}}}' --vars '{"id":"OGE-123"}'
#   printf '%s' "$big_query" | factory-linear-query.sh --query - --vars '{"id":"OGE-123"}'
#
# The secret is read from the env INSIDE python and sent only in the Authorization
# header — never on argv, so it can't leak through `ps`.
set -euo pipefail

query=""; vars="{}"
while [ $# -gt 0 ]; do
  case "$1" in
    --query) query="$2"; shift 2;;
    --vars)  vars="$2";  shift 2;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done

[ "$query" = "-" ] && query="$(cat)"
[ -n "$query" ] || { echo "--query required (a GraphQL string, or - to read from stdin)" >&2; exit 2; }

python3 - "$query" "$vars" <<'PY'
import json, os, ssl, sys, urllib.error, urllib.request
secret = os.environ.get("FACTORY_DASHBOARD_SECRET", "").strip() or os.environ.get("TWIN_DASHBOARD_SECRET", "").strip()
if not secret:
    sys.exit("box→MC secret not set (FACTORY_DASHBOARD_SECRET or TWIN_DASHBOARD_SECRET) — see docs/LINEAR-BOT-SETUP.md")
base = os.environ.get("MC_BASE_URL", "https://missioncontrol.ogenticai.com").rstrip("/")
try:
    variables = json.loads(sys.argv[2] or "{}")
except json.JSONDecodeError as e:
    sys.exit("--vars is not valid JSON: %s" % e)
payload = json.dumps({"query": sys.argv[1], "variables": variables}).encode()
req = urllib.request.Request(
    base + "/api/linear/factory-gql",
    data=payload,
    headers={"Authorization": "Bearer " + secret, "Content-Type": "application/json"},
)
try:
    with urllib.request.urlopen(req, timeout=30, context=ssl.create_default_context()) as r:
        body = r.read().decode()
except urllib.error.HTTPError as e:
    # The relay returns { "error": ... } on 4xx/5xx (e.g. 403 for a mutation).
    detail = e.read().decode()[:300]
    sys.exit("MC relay HTTP %s: %s" % (e.code, detail))
out = json.loads(body)
if out.get("errors"):
    sys.exit("Linear API error: " + json.dumps(out["errors"]))
sys.stdout.write(body)
PY
