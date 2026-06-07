#!/usr/bin/env bash
# factory-linear-comment.sh — post a [factory:*] comment authored by the OgenticAI
# Factory Bot, via the Linear API (NOT an MCP connector). This is how the factory
# keeps its Linear audit trail attributed to the bot when there's no connector slot
# for it (Claude caps Linear connectors at two; both are human). See
# docs/LINEAR-BOT-SETUP.md and .claude/LINEAR-INTEGRATION.md §14.
#
# Requires: LINEAR_FACTORY_TOKEN (the bot's Linear personal API key), python3, curl.
#
# Usage:
#   factory-linear-comment.sh --issue   OGE-123       --body "markdown…"
#   factory-linear-comment.sh --project <project-uuid> --body "markdown…"
#   printf '%s' "$long_md" | factory-linear-comment.sh --issue OGE-123 --body -
set -euo pipefail

issue=""; project=""; body=""
while [ $# -gt 0 ]; do
  case "$1" in
    --issue)   issue="$2";   shift 2;;
    --project) project="$2"; shift 2;;
    --body)    body="$2";    shift 2;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done

: "${LINEAR_FACTORY_TOKEN:?LINEAR_FACTORY_TOKEN not set — see docs/LINEAR-BOT-SETUP.md}"
[ "$body" = "-" ] && body="$(cat)"
[ -n "$body" ] || { echo "--body required" >&2; exit 2; }
[ -n "$issue$project" ] || { echo "--issue or --project required" >&2; exit 2; }

api() {  # $1 = JSON payload string
  curl -fsS -X POST https://api.linear.app/graphql \
    -H "Authorization: $LINEAR_FACTORY_TOKEN" \
    -H "Content-Type: application/json" \
    --data "$1"
}

# Default to a project comment; resolve an issue identifier (OGE-123) to its UUID.
field="projectId"; pid="$project"
if [ -n "$issue" ]; then
  field="issueId"
  q='{"query":"query($id:String!){issue(id:$id){id}}","variables":{"id":"__ID__"}}'
  resolve=$(python3 -c 'import json,sys; print(json.dumps({"query":"query($id:String!){issue(id:$id){id}}","variables":{"id":sys.argv[1]}}))' "$issue")
  pid=$(api "$resolve" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(((d.get("data") or {}).get("issue") or {}).get("id") or "")')
  [ -n "$pid" ] || { echo "could not resolve issue $issue (check the identifier and token scope)" >&2; exit 1; }
fi

payload=$(python3 -c '
import json, sys
field, pid, body = sys.argv[1], sys.argv[2], sys.argv[3]
q = "mutation($input: CommentCreateInput!){ commentCreate(input:$input){ success comment { id url user { email displayName } } } }"
print(json.dumps({"query": q, "variables": {"input": {field: pid, "body": body}}}))
' "$field" "$pid" "$body")

api "$payload" | python3 -c '
import json, sys
d = json.load(sys.stdin)
c = (d.get("data") or {}).get("commentCreate") or {}
if not c.get("success"):
    sys.exit("comment failed: " + json.dumps(d))
cm = c["comment"]
print("posted as %s — %s" % (cm["user"]["email"], cm["url"]))
'
