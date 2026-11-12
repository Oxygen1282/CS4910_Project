# Architecture

Memtegrity protects the files AI coding agents load as **instructions**, **memory** and **config**. The project's scope is Claude Code, but the long-term goal is every agent platform. So the code is split into an **agent-neutral core** and **thin per-agent pieces**. Nothing in the core knows Claude Code exists.

```
                   ┌───────────────────── agent-neutral core ─────────────────────┐
 Claude Code hook ─┤                                                              │
 (hooks.py)        │  engine.assess_change(surface, before, after, evidence)      │
                   │     ├─ integrity   hashes, diffs, added lines, edit sim       │
 memtegrity scan  ─┤     ├─ rules       text rules (normalize → match → decode)   │
 (scan.py, CI,     │     ├─ provenance  where did the new text come from?        │
  pre-commit)      │     └─ scoring     clusters + noisy-OR → allow / ask / deny  │
                   │  paths.classify(path) → Surface (agent, kind)                │
 future: Cursor / ─┤                                                              │
 Copilot / Gemini  └──────────────────────────────────────────────────────────────┘
 adapters                               ▲ data only
                   ┌──────────────── per-agent knowledge (agents/) ───────────────┐
                   │ claude_code.py  files, transcript → Evidence, settings rules │
                   │ others.py       Copilot, Cursor, Windsurf, Gemini, Cline,    │
                   │                 AGENTS.md (files only, for now)              │
                   └──────────────────────────────────────────────────────────────┘
```

## Core (agent-neutral)

| Module | Job | Agent-specific? |
|---|---|---|
| `surfaces.py` | `Surface(agent, kind, name, pattern)` + the path matcher | No: shapes only |
| `paths.py` | Canonicalize a path (symlinks, `..`, case, hard links), then look it up in the registry | No |
| `integrity.py` | SHA-256, diffs, added lines, Edit simulation | No |
| `rules.py` | Text rules with anti-evasion (normalize, decode hidden text, re-scan) | No |
| `provenance.py` | Compare new text to what the user typed vs. what the agent read | No: takes `Evidence` |
| `scoring.py` | Cluster nearby signals, combine with noisy-OR, apply provenance and user intent | No |
| `engine.py` | One entry point used by every adapter and the scanner | Looks up a config analyzer by agent name |
| `scan.py` | Scan a repository's agent files at rest | No |

## Per-agent pieces

| Piece | Claude Code (built) | Another agent (later) |
|---|---|---|
| **Which files** (`agents/<agent>.py`, an `AgentProfile`) | `claude_code.py` | Already listed in `others.py` for 6 agents/standards |
| **Session record → `Evidence`** (for provenance) | `evidence_from_transcript` (JSONL transcript) | Write a parser for that agent's log format |
| **Config analyzer** (structure of settings files) | `assess_config` (hooks, MCP, permissions, env) | Optional: until then, config changes are judged by text rules and default to "ask" |
| **Real-time adapter** (hook protocol in → engine → protocol out) | `hooks.py` + `hooks/hooks.json` | One module per agent that has hooks |

**To add an agent:** add its profile (files) to `agents/`, then optionally an evidence parser, a config analyzer and a hook adapter. The core, the scanner, the data models and the audit trail don't change. `ChangeEvent` already records `agent` and `surface_kind`.

## Decisions that keep the door open

1. **Files are data, not code.** The registry tags every protected file with an agent and a role. `memtegrity scan` already covers all registered agents.
2. **Roles, not product names.** `SurfaceKind` = instructions / memory / config. Every platform has all three under different names.
3. **The engine takes plain values.** Hook JSON and transcript formats are translated at the edge (`hooks.py`, `agents/claude_code.py`).
4. **Provenance takes neutral `Evidence`** (user text vs. external text with a trust level), so any agent with a session log can feed it.
5. **The CLI hook command is Claude Code's adapter.** `memtegrity hook <event>` defaults to Claude Code; other agents get their own adapter (e.g. `memtegrity hook --agent cursor …`) without breaking this one.
6. **Claude-specific facts are labelled.** Claude Code strips HTML comments before loading; other agents may not, so the rule stays, with a low weight.

## Security decisions (why it's built this way)

| Decision | Principle | Where |
|---|---|---|
| Enforcement in hooks, not in instructions | Enforcement outside the protected system (Anthropic's docs: memory is "context, not enforced configuration") | `hooks.py` |
| Never answer "allow" | Least privilege: "allow" would skip the user's own permission prompt | `hooks.py` |
| Errors → "ask" | Fail securely | `hooks.run_hook` |
| Resolve paths before deciding | Canonicalize before authorizing (path traversal, symlinks, case, hard links; on Windows also `CLAUDE.md.`, `CLAUDE.md::$DATA`, `.claude::$INDEX_ALLOCATION`) | `paths.py` |
| Decode hook input as UTF-8 ourselves | Windows' default code page (cp1252) would garble hidden-Unicode payloads into text the rules can't see | `hooks.read_stdin` |
| Bounded regex gaps, bounded negation look-back | No ReDoS: the PreToolUse hook must not be stallable by a crafted long line | `rules.py` |
| Normalize + decode before matching | Defense against obfuscation (Unicode tags, zero-width, variation selectors, Sneaky Bits, base64) | `rules.py` |
| Unpredictable edit ≠ safe | No fail-open on parser mismatch | `engine.py` |
| Provenance amplifies only directives | Precision: don't punish `/init` for copying README text | `scoring.py` |
| User intent softens soft signals only | Respect the user; hidden text is never "what the user wanted" | `scoring.py` |
| Evidence sanitized before echoing | Don't re-inject attacker text into the agent | `rules.snippet` |
| No hidden Unicode in our own source (CI check) | Trojan Source (CVE-2021-42574) | `scripts/escape_invisible.py` |

## Performance

The PreToolUse hook runs on **every** Write/Edit, so:
- The hook path imports only `paths`, `surfaces`, `enums` and `agents` (no Pydantic or SQLAlchemy). Non-protected files take ≈0.1 s, most of it `uv` start-up.
- The analysis stack loads only for protected files (≈0.5 s).
- Pydantic models build lazily (`defer_build`), database tables load lazily (`tables.py`), and `entry.py` skips the CLI framework for hooks.

## Provisional numbers

Rule severities, the 2-line cluster window, provenance weights, the user-intent factor (0.6) and the ask/deny thresholds (40/75) are **hand-set from the threat research**. The evaluation block calibrates them on the labeled dataset, trading detection rate against false positives. They live in `rules.py`, `scoring.py`, `provenance.py` and `config.py`.
