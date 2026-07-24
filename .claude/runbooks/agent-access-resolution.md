# Runbook — Agent access resolution (never stall on "I can't find my key/tool")

**Owner:** Otto. **Applies to:** every agent in the fleet. **Status:** v1 (2026-07-14, from Dennis's feedback: work stalls when an agent thinks it lacks access).
**The rule in one line:** an agent never reports "no access" and never silently stalls — it walks this checklist top to bottom, and if every path fails it escalates with what it tried.

## Why this exists

Agents have been failing to find their Slack bot keys, defaulting to the wrong identity (the claude.ai
Slack connector, which posts as Dennis), or getting confused about what "the bridge" is. Every one of
those stalls is a false blocker: the access exists; the awareness does not. This runbook is the
standard awareness.

## Terminology (get these straight)

- **The bridge** = a fresh `claude -p "<prompt>" --output-format text` subprocess run from Bash. It
  carries the claude.ai connectors (Gmail, Drive, Calendar) even when the current session's tool
  registry does not. It is NOT the browser and NOT Zing.
- **Zing** = the knowledge/intelligence layer (agent-knowledge). Today it answers questions with
  citations. It is not yet an integration or access layer.
- **The browser** = Claude driving Chrome (claude-in-chrome). Used for things no connector can do,
  for example editing a Google Doc body in place.
- **Your bot token** = your own Slack identity. It exists. See step 2.

## The resolution order (walk it top to bottom)

**Priority 1 — Zing (target state, not yet).** The direction (OGE-1154, OGE-1409, OGE-1165) is that
agents and people go through Zing as the governed interface: one place for integrations, role-based
access, and audit. When Zing exposes that surface, it becomes step 1 of this list. Until then, do
not wait for it — use the paths below.

**Today, in priority order (most capable and consistent first):**

1. **In-session MCP connectors.** Check what this session actually has before claiming a gap:
   `claude mcp list` in Bash is the source of truth for connector status (CLAUDE.md §9a-bis). Slack,
   Linear, Notion, Drive, Gmail, Calendar, HubSpot are usually already connected.
2. **Your own Slack bot token.** Every one of the 13 fleet agents has a live bot identity. The tokens
   live in `slack-fleet-listener/.env` (`SLACK_XOXB_<AGENT>`), and the mapping is in
   `.claude/registry/teammate-agents.yml` under `bot_tokens`. Post via `chat.postMessage` with your
   own token. NEVER post through the claude.ai Slack connector (it renders as "Dennis Howell · Sent
   using Claude"). If the API says `not_in_channel`, join the channel first — that is not a missing key.
3. **The `claude -p` bridge** for Gmail / Drive / Calendar reads and drafts when the in-session
   registry lacks those tools. Foreground from a TTY when possible; in scheduled runs prefer
   in-session tools (the bridge can hang on permission prompts in non-TTY runs).
4. **The browser (Chrome)** for the few writes no connector supports (for example replacing a Google
   Doc's body in place). Requires Dennis's Chrome to be connected; if it is not, say exactly that.
5. **Escalate — loudly, with evidence.** If every path above fails, post what you tried (the actual
   commands/errors) to your home channel or Otto, and hand the work off rather than parking it.
   A stalled task with no message is the failure mode this runbook kills.

## Verification habits (before reporting any access gap)

- Run the check, not the assumption: `claude mcp list`, `grep XOXB slack-fleet-listener/.env`,
  ToolSearch for the tool name.
- A response you failed to parse is not a failed send: verify live state (channel history, sent
  folder, the ticket) before retrying anything that posts. Duplicates are a rule violation.
- If a capability genuinely does not exist (for example: no connector can edit a Google Doc body,
  no Google Admin provisioning via connector), say so plainly and use the documented alternative —
  do not re-derive it every session. CLAUDE.md §9a records these facts.

## Keeping this current

When a new access path lands (Zing's governed interface, the org memory layer, a new MCP server),
this runbook updates in the same change. Gaps found in sweeps get a line here, not a new doc.
