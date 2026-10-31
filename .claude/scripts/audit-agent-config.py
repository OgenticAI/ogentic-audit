#!/usr/bin/env python3
"""Audit the agent configuration a repo hands to its agents.

The kit is a distribution channel. Sync PRs that only add or update kit files
merge themselves once CI is green (CLAUDE-FACTORY §F6), and on the box the
factory runs headless, so whatever lands in an agent or skill file is what
every repo's agents read next. OGE-1691 already watched that channel carry a
client's name into seven public repositories. The code the agents write passes
a panel of reviewers; the agents' own files passed nothing.

Five checks, each for a failure that a person reading the diff would miss:

1. Frontmatter. Every agent file opens with a frontmatter block that names
   `name`, `description` and `tools`, and no two agents share a name. Claude
   Code skips a file it cannot parse without saying so, and the chain stalls at
   that stage. An agent with no `tools:` line inherits every tool.
2. Read-only means read-only. An agent whose description says "read-only" may
   not carry Write, Edit, MultiEdit or NotebookEdit. The reviewer panel runs in
   parallel on one working tree only because its members do not write.
3. Every invoked agent exists. Each `invoke("<name>")` in a skill must match an
   agent's `name:`, or a rename surfaces mid-run, headless.
4. No hidden characters. Zero-width, bidirectional and Unicode tag characters
   in agent, skill or memory files hide text from the reviewer while the model
   still reads it.
5. Every memory import resolves. An `@./path` import in CLAUDE.md or a
   `.claude/*.md` partial resolves relative to the file that contains it, and
   one that names no file is dropped without a warning. The core canon's
   `@./.claude/core-canon.md` inside `.claude/CLAUDE-FACTORY.md` named
   `.claude/.claude/core-canon.md`, so the canon never loaded in any repo.

Secret-shaped strings are the pre-commit hook's job and are not repeated here.

    audit-agent-config.py                    # .claude/agents, .claude/skills, CLAUDE.md, .claude/**/*.md
    audit-agent-config.py --root kit
    audit-agent-config.py --agents agents/engineering --agents agents/ops --skills skills

Exits 1 when it finds anything, 0 when clean.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

WRITE_TOOLS = {"Write", "Edit", "MultiEdit", "NotebookEdit"}
REQUIRED_KEYS = ("name", "description", "tools")
INVOKE = re.compile(r"""invoke\(\s*["']([A-Za-z0-9_-]+)["']""")
IMPORT = re.compile(r"(?<![\w`])@(\.{1,2}/\S+)")
FENCE = re.compile(r"^[\s>]*(```|~~~)")
# Imported before the file exists: factory-learn creates it on first promotion.
OPTIONAL_IMPORTS = {"LEARNED.md"}
# Zero-width and directional marks, bidi embeddings/overrides/isolates, the BOM,
# and the Unicode tag block, which renders as nothing anywhere.
HIDDEN = re.compile(
    "[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff\U000e0000-\U000e007f]"
)


def frontmatter(text: str) -> dict[str, str] | None:
    """The `key: value` pairs of the leading `---` block, or None without one."""
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return None
    meta: dict[str, str] = {}
    key = None
    for line in lines[1:]:
        if line.strip() == "---":
            return meta
        if key and line[:1] in (" ", "\t"):  # a YAML list item under `tools:`
            item = line.strip().removeprefix("-").strip()
            meta[key] = f"{meta[key]}, {item}" if meta[key] else item
            continue
        k, sep, v = line.partition(":")
        if sep:
            key = k.strip()
            meta[key] = v.strip()
    return None  # never closed


def tool_names(tools: str) -> set[str]:
    """`Read, Bash(git:*)` or `[Read, Edit]` → {"Read", "Bash"}."""
    names = (t.split("(")[0].strip(" []'\"") for t in tools.split(","))
    return {n for n in names if n}


def audit_agent(path: Path, meta: dict[str, str] | None) -> list[str]:
    if meta is None:
        return [f"{path}: no closed `---` frontmatter block; Claude Code will skip this agent"]
    found = [f"{path}: frontmatter has no `{k}:`" for k in REQUIRED_KEYS if not meta.get(k)]
    if "tools" not in meta:
        found.append(f"{path}: no `tools:` line, so the agent inherits every tool")
    if re.search(r"read-only", meta.get("description", ""), re.I):
        writes = sorted(tool_names(meta.get("tools", "")) & WRITE_TOOLS)
        if writes or "tools" not in meta:
            found.append(f"{path}: described as read-only but can write ({', '.join(writes) or 'inherits every tool'})")
    return found


def imports(text: str) -> list[tuple[int, str]]:
    """Relative `@./` and `@../` imports outside code blocks and code spans."""
    found, in_fence = [], False
    for lineno, line in enumerate(text.splitlines(), 1):
        if FENCE.match(line):
            in_fence = not in_fence
        elif not in_fence:
            found += [(lineno, t) for t in IMPORT.findall(re.sub(r"`[^`]*`", "", line))]
    return found


def md_files(dirs: list[Path]) -> list[Path]:
    return sorted(f for d in dirs if d.is_dir() for f in d.rglob("*.md"))


def audit(root: Path, agent_dirs: list[Path], skill_dirs: list[Path]) -> list[str]:
    findings: list[str] = []
    names: dict[str, Path] = {}
    for path in md_files(agent_dirs):
        meta = frontmatter(path.read_text(encoding="utf-8"))
        findings += audit_agent(path, meta)
        name = (meta or {}).get("name")
        if name and name in names:
            findings.append(f"{path}: agent name `{name}` is also used by {names[name]}")
        elif name:
            names[name] = path

    skills = md_files(skill_dirs)
    for path in skills:
        for wanted in sorted(set(INVOKE.findall(path.read_text(encoding="utf-8")))):
            if wanted not in names:
                findings.append(f"{path}: invokes `{wanted}`, which no agent file names")

    for path in sorted(p for p in [root / "CLAUDE.md", *(root / ".claude").glob("*.md")] if p.is_file()):
        for lineno, target in imports(path.read_text(encoding="utf-8")):
            if Path(target).name not in OPTIONAL_IMPORTS and not (path.parent / target).is_file():
                findings.append(f"{path}:{lineno}: imports {target}, which resolves to no file (relative to {path.parent})")

    memory = [root / "CLAUDE.md", *(root / ".claude").rglob("*.md")]
    scanned = {p for p in memory if p.is_file() and "worktrees" not in p.parts}
    for path in sorted(scanned | set(md_files(agent_dirs)) | set(skills)):
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            for ch in sorted(set(HIDDEN.findall(line))):
                findings.append(f"{path}:{lineno}: hidden character U+{ord(ch):04X}")
    return findings


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--root", default=".", type=Path, help="repo (or kit) root; default .")
    ap.add_argument("--agents", action="append", type=Path, help="agent dir, repeatable; default <root>/.claude/agents")
    ap.add_argument("--skills", action="append", type=Path, help="skill dir, repeatable; default <root>/.claude/skills")
    args = ap.parse_args(argv)
    root = args.root
    agents = [root / d for d in args.agents] if args.agents else [root / ".claude" / "agents"]
    skills = [root / d for d in args.skills] if args.skills else [root / ".claude" / "skills"]

    findings = audit(root, agents, skills)
    for f in findings:
        print(f)
    print(f"audit-agent-config: {len(findings)} finding(s)" if findings else "audit-agent-config: clean")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
