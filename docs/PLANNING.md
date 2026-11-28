# Planning meeting: Thursday, Nov 5, 2026

Goal: leave with owners, issues, and a schedule, so both of us can start building on Friday.
Background: [README](../README.md) for the overview, [CONTEXT.md](CONTEXT.md) for the full reasoning.

## Before the meeting (each of us)
- [ ] Install uv, clone, check out `feat/memtegrity-skeleton`, run `uv sync && uv run pytest`
- [ ] Skim `src/memtegrity/models.py`, the shared contract we both build against

## Open decisions at the Nov 5 meeting (historical; resolved below)
- [ ] **1. Who is Partner A and who is Partner B?** (A = plugin & integrity, B = AI analysis & evidence)
- [ ] **2. API key:** who creates the Anthropic Console account, adds ~$20 prepaid credit, and sets the spend limit? How do we share the key (one shared key, or one key each under the same org)? Remember: the API is billed separately from Claude Pro/Max.
- [ ] **3. Protect `main`** and require one PR review before merging. The repo owner (Oxygen1282) sets this up in GitHub settings.
- [ ] **4. Confirm the target memory files:**
  - `./CLAUDE.md`, `./.claude/CLAUDE.md`, `./CLAUDE.local.md`, `~/.claude/CLAUDE.md`
  - `AGENTS.md`
  - `.claude/rules/*.md`, `~/.claude/rules/`
  - auto memory: `~/.claude/projects/<project>/memory/` (`MEMORY.md` + topic files), plus `autoMemoryDirectory` if set
- [ ] **5. Confirm the risk thresholds.** Current defaults in `config.py`: score < 40 → allow, 40–74 → ask, ≥ 75 → deny. Also decide whether one high-severity rule hit forces deny on its own (`scoring.combine`).
- [ ] **6. Turn the TODOs into GitHub Issues** and assign owners (`grep -rn "TODO(" src skills datasets` lists them). Also file an issue for the **eval harness** (B), which has no stub yet.
- [ ] **7. Check-in schedule:** e.g. two 15-minute check-ins per week (which days?).
- [ ] **8. Demo machine:** whose Mac records the demo?

Smaller things to agree on:
- [ ] Dataset file format (proposal in `datasets/README.md`)
- [ ] Marketplace name: currently `cs4910`, so the install is `memtegrity@cs4910`
- [ ] Run `uv run pre-commit autoupdate` once to pin the newest hook versions

## Decisions made (Nov 7)
- **Scope:** real-time protection is Claude Code only for this project, but everything is built so other agents can be added without a rewrite (agent-neutral core, per-agent registry). See `docs/ARCHITECTURE.md`. Other agents' instruction files are already protected when Claude writes them, and covered by `memtegrity scan`.
- **Scoring:** the current weights and thresholds are provisional (hand-set from the threat research). A later block calibrates them on the labeled dataset.
- **Provenance** (did new memory text come from the user or from content Claude read?) is part of Block 1.
- **Workflow:** we work in blocks, one person at a time. Each block ends with a PR and a `docs/BLOCK<n+1>.md` guide for the next person. Current: [BLOCK4.md](BLOCK4.md).

## Decisions made (Nov 14, Block 2)
- Model changes are fine if listed in the PR.
- First baseline is silent apart from one line: "Memtegrity is now protecting N files."
- SessionStart may take about 1 second of work.
- First-run timeout fixed: PreToolUse timeout raised to 300 s; SessionStart (600 s) runs first and builds the environment.
- `@import` targets are protected, with `/` and `\` paths.

## Decisions made (Nov 17–23, Block 3)
- Blocks 3 and 4 were combined into Block 3, minus the AI judge. Block 3 built catch-and-undo plus every detection that needs no AI. The AI judge is Block 4.
- **Restore policy** (`auto_restore`, default `agent`): only high-risk changes the agent made (shell, MCP) are restored automatically. Changes from outside the agent (editors, `git pull`) are flagged, and the agent is told to distrust them. `always` and `off` are available.
- **"Ask"-level changes** detected during a session: warn only.
- **Shared database:** the CLI finds the plugin's data folder; the skills pass it explicitly.
- **ConfigChange blocking** moved from Block 6 into Block 3.
- **Judge model:** `claude-sonnet-5-5` (already `scoring_model` in `config.py`).
- **The judge may raise a score freely,** but lower it by at most one verdict level (deny → ask, ask → allow), and never when a *hard* rule fired (hidden text, encoded payloads, tampering, import of a risky file).
- **Privacy for the judge:** send the diff and a little context, never whole files, with secrets redacted first.
- **Live testing** on a real machine: `--plugin-dir` in a throwaway folder, with `MEMTEGRITY_RESTORE_ROOTS` set to that folder.

## Decisions made (Nov 27, Block 4)
- **Judge refusals → rules only.** No server-side fallback to another model (that's a beta API); `llm_refused` is recorded.
- **Live check later:** Block 4 is built and tested with a mocked API; the real calls (latency, cost) run once a key is in `.env`.
- **Judge settings:** effort `low`, one try, 20 s timeout, at most 40 paid calls per session, answers cached (`config.py`: `judge_*`).
- **Judge not used at SessionStart** (its ~1 s budget) or when the rules already deny with a hard hit.
- Windows test fix included: the launcher test kills the whole process tree on timeout instead of hanging.

## Risks
1. **PreToolUse latency.** Claude waits while we score. Keep the LLM call short with a timeout (`llm_timeout_seconds`), fall back to rules only, and measure it.
2. **Claude may not take the bait on camera.** It often resists obvious poison. Use subtle poison and keep a scripted fallback for the video (`demo/README.md`).
3. **Everyone needs uv installed**, including anyone who installs the plugin, since the hooks run `uv run`.
4. **Restore → FileChanged loop.** Our own restore write triggers FileChanged. `recovery.is_own_write` must ignore it.
5. **Multiple file events per save.** One save can fire several change/add/unlink events. De-duplicate by content hash.

## For the deliverables
**Video outline (3–5 min):** problem → architecture → live demo (poisoned page → blocked memory write with risk score → restore → replay evidence → HTML report) → metrics + limitations.

**Class concepts to call out:**
- hashing / integrity checking
- audit trail
- least privilege / sandboxing
- defense in depth (rules + LLM + replay; PreToolUse + FileChanged + SessionStart)
- incident response: detect → contain → recover
- enforcement outside the protected system

**Starting citations:**
- OWASP Top 10 for LLM Applications (LLM01: Prompt Injection)
- OWASP Agentic AI: Threats & Mitigations (memory poisoning)
- K. Greshake et al., "Not what you've signed up for: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection," 2023
- Z. Chen et al., "AgentPoison: Red-teaming LLM Agents via Poisoning Memory or Knowledge Bases," 2024
- J. Rehberger, "SpAIware" (persistent ChatGPT memory injection), 2024
- Anthropic, Claude Code documentation: memory and hooks (code.claude.com/docs)

**Deliverable checklist (due Dec 14, one of us uploads to Canvas):**
- [ ] Report: 3 pages, IEEE conference format, `.docx` (appendices may exceed 3 pages)
- [ ] Slides: 10–12, `.pptx` (intro, methodology, implementation, results)
- [ ] Video: 3–5 min, MP4 or YouTube
- [ ] File names: `CS4910_Memtegrity_McGuire_<PartnerLastName>`
