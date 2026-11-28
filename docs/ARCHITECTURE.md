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
| `baseline.py` | Between-session check: compare files with approved snapshots, trust on first use, approvals | No |
| `store.py` | SQLite: snapshots, baselines, hash-chained audit log, `verify_chain` | No |
| `recovery.py` | Judge a protected file that changed on disk; restore policy (who made it?); restore + quarantine | No |
| `markers.py`, `watch.py` | Tiny files that let hook processes coordinate without the database: content awaiting approval, Memtegrity's own writes, tool calls in flight, queued warnings, per-session watch list | No |
| `mcp.py` | What an MCP tool call will write, from its arguments (paths, content, edits, moves) | No: MCP is cross-agent |
| `packages.py`, `_popular.py` | Look-alike (typosquatted) package names, offline | No |
| `judge.py` | AI judge interface (`Judge` → `JudgeResult`), shared cache, per-session cost cap, on/off switch | No: any model can implement it |
| `llm_risk.py` | The Claude implementation of `Judge`: key loading, prompt, structured-output call | Claude API (not Claude Code) |
| `redact.py` | Remove secrets from text before it is sent anywhere | No |

## Per-agent pieces

| Piece | Claude Code (built) | Another agent (later) |
|---|---|---|
| **Which files** (`agents/<agent>.py`, an `AgentProfile`) | `claude_code.py` | Already listed in `others.py` for 6 agents/standards |
| **Files outside the project that load into its sessions** (`session_paths`) and **imports** (`imported`, `import_closure`, `new_import_targets`) | `~/.claude`, parent-folder CLAUDE.md, auto memory; `@path` imports | Optional (e.g. Gemini CLI also has `@` imports) |
| **Files that may be created later** (`expected_paths`) | CLAUDE.md files, AGENTS.md, `.claude/rules` etc., auto memory | Optional |
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
| Audit failures never change a decision | A broken database must not open the gate | `hooks.handle_pre_tool_use` |
| Trust on first use, except what the rules call "deny" | Usability without blindly trusting a pre-poisoned repo | `baseline.check` |
| A flagged change stays flagged until the user approves it | The approved version stays the reference; no silent drift | `baseline.check` |
| Only content the user approved *in the permission prompt* becomes the baseline | The same text written another way (Bash) isn't approved | `hooks.handle_post_tool_use` |
| Auto-restore only what the agent wrote (default) | Contain the attacker's channel (the agent) without overwriting the user's own work | `recovery.handle_change` |
| Restore only to an approved version, keep the replaced one, never delete | Recovery must be reversible and evidence-preserving | `recovery.restore` |
| "From the repository" means the content matches `git show HEAD:` | Attribute by content, not by command line: `git pull && echo poison >> CLAUDE.md` gets no pass | `recovery.matches_repository` |
| Our own restore write is marked and ignored | No restore → file-watch → restore loop | `markers.note_own_write` |
| `memtegrity approve` / `baseline` / database access from the agent → ask | Separation of duties: the party being checked can't vouch for itself | `hooks._pre_bash` |
| Settings changes blocked, not just reported | Prevent, then detect: a malicious hook must never run | `hooks.handle_config_change` |
| An edit adding an `@import` is judged with the imported file | Two harmless-looking steps can't add up to poison | `engine._import_target_hits` |
| Text addressed to AI reviewers is a signal | Defense in depth for the AI judge: trying to talk the reviewer out of it is evidence | `rules.py` (`evasion.addresses_reviewer`) |
| The AI judge can raise freely, lower one level at most, never past a hard rule | Don't let the component an attacker can talk to have the last word (bounded trust in a probabilistic check) | `scoring.blend_llm` |
| Judge failure, timeout or refusal → rules only | Fail securely: an extra signal, never a dependency, never "allow" | `llm_risk.judge_with_claude`, `engine.assess_change` |
| Only the diff, secrets redacted, home folder removed from paths | Data minimization: send a third party the least that does the job | `redact.py`, `llm_risk.build_user_content` |
| The change sits in a tag named after its own hash | Keep data and instructions apart (the change can't close the tag) | `llm_risk.build_user_content` |
| Judge's API address pinned; key read only from our own `.env`, never exported | A poisoned setting (`ANTHROPIC_BASE_URL`) or repository can't redirect or choose our key | `llm_risk.make_client`, `llm_risk.load_api_key` |
| Judge answers cached, paid calls capped per session | Availability and cost: an attacker can't run up the user's bill by forcing many judgments | `judge.cache_*`, `judge.take_call` |
| Restores can be fenced to a folder (`$MEMTEGRITY_RESTORE_ROOTS`) | Safe live testing on a real machine | `recovery.restore_allowed` |
| Hash-chained audit log, serialized writers | Tamper evidence; integrity of the record | `store.record_change`, `store.verify_chain` |
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
- The analysis stack loads only for protected files (≈0.5 s). The `anthropic` SDK loads only when the judge actually makes a call (a cached answer doesn't load it).
- The judge adds one API call (20 s timeout, effort `low`, no retries) to judged changes to protected files, never to other writes, and never at SessionStart.
- Pydantic models build lazily (`defer_build`), database tables load lazily (`tables.py`), and `entry.py` skips the CLI framework for hooks.
- PreToolUse touches the database only after an ask/deny; PostToolUse only if a small marker file says the content was asked about. Ordinary writes never load SQLModel.
- Every Bash command now runs two quick hooks (PreToolUse notes it's running; PostToolUse `stat`s the watched files and folders). Measured: about 0.12 s each when nothing protected changed, with no database access. The database loads only when a protected file actually changed.
- FileChanged and UserPromptSubmit check marker files first. Repeated events for one save are recorded once.
- SessionStart finds files with a cheap name check first and compiled glob regexes, reads every approved hash in one query, and stops walking after 0.8 s (the user is told if the check was partial). Measured on a slow Windows laptop: ~0.6 s of work for 45 files, plus ~2 s of one-time imports per process (Python, SQLModel). The very first run is slower (it analyzes every file).

## Provisional numbers

Rule severities, the 2-line cluster window, provenance weights, the user-intent factor (0.6) and the ask/deny thresholds (40/75) are **hand-set from the threat research**. The evaluation block calibrates them on the labeled dataset, trading detection rate against false positives. They live in `rules.py`, `scoring.py`, `provenance.py` and `config.py`.
