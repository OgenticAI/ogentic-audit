#!/usr/bin/env bash
# factory-linear-query.sh — run an arbitrary Linear GraphQL request (read OR write)
# as the OgenticAI Factory Bot WITHOUT ever exposing the token on a command line.
#
# Headless factory runs usually have NO Linear MCP connector (it's interactively
# authenticated). Without a sanctioned path, agents tend to hand-roll an inline
# script with the token pasted in as a literal (e.g. `key = "lin_api_…"`) — which
# leaks the secret into the process table (`ps`). This helper closes that gap: it
# reads LINEAR_FACTORY_TOKEN from the environment and sends it ONLY in the HTTP
# Authorization header via urllib, so the token never appears on argv. Companion
# to factory-linear-comment.sh. See .claude/LINEAR-INTEGRATION.md §2 + §15.
#
# Requires: LINEAR_FACTORY_TOKEN (the bot's Linear personal API key), python3.
#
# Usage:
#   factory-linear-query.sh --query 'query($id:String!){issue(id:$id){title state{name}}}' --vars '{"id":"OGE-123"}'
#   printf '%s' "$big_query" | factory-linear-query.sh --query - --vars '{"id":"OGE-123"}'
#
# Prints the raw GraphQL JSON response to stdout. Exits non-zero on transport or
# GraphQL errors. NEVER pass the token as an argument — it is read from the env.
set -euo pipefail

query=""; vars="{}"
while [ $# -gt 0 ]; do
  case "$1" in
    --query) query="$2"; shift 2;;
    --vars)  vars="$2";  shift 2;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done

: "${LINEAR_FACTORY_TOKEN:?LINEAR_FACTORY_TOKEN not set — see docs/LINEAR-BOT-SETUP.md}"
[ "$query" = "-" ] && query="$(cat)"
[ -n "$query" ] || { echo "--query required (a GraphQL string, or - to read from stdin)" >&2; exit 2; }

# query + vars are passed as argv (they carry NO secret); the token is read from
# the environment INSIDE python and sent only in the Authorization header.
python3 - "$query" "$vars" <<'PY'
import json, os, ssl, sys, urllib.error, urllib.request
tok = os.environ.get("LINEAR_FACTORY_TOKEN", "")
if not tok:
    sys.exit("LINEAR_FACTORY_TOKEN not set")
try:
    variables = json.loads(sys.argv[2] or "{}")
except json.JSONDecodeError as e:
    sys.exit("--vars is not valid JSON: %s" % e)
payload = json.dumps({"query": sys.argv[1], "variables": variables}).encode()
req = urllib.request.Request(
    "https://api.linear.app/graphql",
    data=payload,
    headers={"Authorization": tok, "Content-Type": "application/json"},
)
try:
    with urllib.request.urlopen(req, timeout=30,
                                context=ssl.create_default_context()) as r:
        body = r.read().decode()
except urllib.error.HTTPError as e:
    sys.exit("Linear API HTTP %s: %s" % (e.code, e.read().decode()[:300]))
out = json.loads(body)
if out.get("errors"):
    sys.exit("Linear API error: " + json.dumps(out["errors"]))
sys.stdout.write(body)
PY
