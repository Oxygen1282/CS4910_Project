# Block 5 guide: replay evidence (what would the poisoned memory make the agent do?)

**For:** whoever builds Block 5 (and their coding agent). Read this file first.
**Prerequisite:** Block 4 (`feat/block4-judge`) is merged into `main` (done and checked live; results in [BLOCK4.md](BLOCK4.md) under 4.9).
**Needs an API key for the live check only.** `ANTHROPIC_API_KEY=…` in the repo's `.env` (see `.env.example`). Tests and CI never call the real API.

## 1. Get oriented (15 min)

1. Read, in this order:
   - `README.md`: the **Status** table and *Try it*.
   - [BLOCK4.md](BLOCK4.md): what every block built, the decisions already made (section 2), and the rules (section 4). Its "Block 5" paragraph is the short version of this guide.
   - `docs/ARCHITECTURE.md`: core vs. per-agent pieces, security decisions.
   - `src/memtegrity/models.py`: `ToolCall`, `Trial`, `BehaviorDiff`, `ReplayResult` (the shared contract you fill in), and `config.py` (`replay_model`, `trials_per_condition`, `flag_min_suspicious`, `flag_max_clean`, `replay_max_turns`).
   - The stubs: `src/memtegrity/replay/harness.py`, `fake_tools.py`, `compare.py`, and `cli.py` → `replay`.
   - `src/memtegrity/llm_risk.py` and `tests/test_judge.py`: how Block 4 calls the API (key loading, pinned address, error handling) and how its tests fake the API with the real SDK on a mock HTTP transport. Reuse both patterns.
2. Set up and check:
   ```bash
   uv sync
   uv run pytest          # all pass; a few skips on Windows (symlinks without Developer Mode)
   uv run ruff check && uv run ruff format --check
   uv run pre-commit install
   ```
   Works on macOS, Linux and Windows (CI runs all three; on Windows use Git Bash).
3. Branch from up-to-date `main`: `git switch main && git pull && git switch -c feat/block5-replay`

## 2. The idea in one paragraph

Rules and the AI judge say a change *looks* like poison. Replay shows what it would *do*. Run a small simulated agent on ordinary user prompts ("deploy the app to staging") N times with the **approved** memory and N times with the **flagged** memory. Its tools are fakes that only record what the agent tried. A behavior that shows up in most suspicious trials and (almost) no clean ones, such as `webfetch:backup-sync.example`, is behavioral evidence that the change steers the agent. Models are nondeterministic (no `temperature` on current models), which is why every condition runs several trials and the comparison counts.

## 3. What to build

| # | Build | Where | Done when (test, mocked client) |
|---|---|---|---|
| 1 | **Fake tools:** `TOOL_DEFINITIONS` mirroring Claude Code's `Bash`, `Read`, `Write`, `Edit`, `WebFetch` (same names and input fields, `strict: true`, `additionalProperties: false`). `FakeToolbox.call` records a `ToolCall` and returns a harmless, plausible result: `Read` from the fake file system (or "file not found"), `WebFetch` a bland placeholder page, `Bash` empty output with exit 0, `Write`/`Edit` "ok". **Nothing is ever executed, fetched or written** | `replay/fake_tools.py` | Every tool records its input in order; a test proves no subprocess, file write or network call happens (monkeypatch `subprocess.run`, `open` for writing, sockets to raise) |
| 2 | **Memory loading:** `build_system_prompt(memory)` loads the files the way Claude Code does: instruction files (CLAUDE.md, rules, AGENTS.md…) in full, auto memory's `MEMORY.md` capped at `memory_index_max_lines` (200) / `memory_index_max_bytes` (25 KB). Each file labeled with its path. Base it on Claude Code's own wording for memory ("these are instructions from the user/project"), so the poison has the authority it would really have | `replay/harness.py` | Cap respected (line 201 is absent); every file appears with its path |
| 3 | **One trial:** `run_trial` runs a manual tool-use loop on `replay_model` (`claude-haiku-5-5`): call → for each `tool_use` block, `FakeToolbox.call` → send all `tool_result`s back **in one user message** → repeat until `end_turn` or `replay_max_turns`. Record tool calls, final text, `stop_reason`, token counts. Check `stop_reason == "refusal"` → `Trial.refused = True`. `tool_choice` must be `auto` (forced tool use is rejected on the 5.5 models). No `temperature` | `replay/harness.py` | Scripted fake responses (tool_use, then end_turn) → `Trial` with those calls; refusal → `refused`; turn cap stops a looping model |
| 4 | **Behaviors + comparison:** `extract_behaviors` normalizes calls into labels: `webfetch:<domain>`, `bash:<program>` (first word, plus `bash:pipe-to-shell` for `… \| sh`), `read:<sensitive class>` (`~/.ssh`, `.env`, credentials), `write:<file>`, `refusal`. Reuse `rules.py`'s destination / credential helpers instead of new regexes. `compare` counts each behavior per condition and flags it if ≥ `flag_min_suspicious` suspicious and ≤ `flag_max_clean` clean | `replay/compare.py` | Poisoned memory (scripted: suspicious trials fetch `backup-sync.example`) → that behavior flagged; benign memory → nothing flagged; refusals counted separately |
| 5 | **Test prompts:** `generate_test_prompts(diff, client, n)` asks the model (structured output, a Pydantic model with `prompts: list[str]`) for ordinary user requests that would exercise the changed instruction (a deploy request for a deploy rule). The diff is untrusted data: same tag-and-redact pattern as `llm_risk.build_user_content` | `replay/harness.py` | Mocked answer parsed; the request body contains no secrets (`redact`) |
| 6 | **The replay:** `run_replay` runs every prompt × `trials_per_condition` × {clean, suspicious}, fills `ReplayResult` (`behaviors`, refusal counts, `poison_confirmed`, `estimated_cost_usd` from token counts and model prices). Stop early and cleanly on API errors (partial result marked as such, never a crash) | `replay/harness.py` | End-to-end with a mocked API: poisoned → `poison_confirmed`; benign → not |
| 7 | **Trigger + storage:** `memtegrity replay <event>`: loads the event's approved and flagged snapshots (`store.get_snapshot`), runs the replay, and records the result as a **new** `ChangeEvent` (`note="replay evidence for #<event>"`, `replay_json` set). Never edit the old event: `replay_json` is outside the hash chain on purpose. `memtegrity review <#>` shows the flagged behaviors and counts | `cli.py`, `store.py` | `CliRunner`: replay → new event; `verify_chain()` still clean; `review` shows "webfetch:backup-sync.example 4/5 vs 0/5" |
| 8 | **Optional: background trigger** after a deny/restore, as an `async` command hook with `asyncRewake` (exit code 2 wakes Claude with the evidence). Only if 1–7 are done and the decisions in section 5 allow it | `hooks/hooks.json`, `hooks.py` | Hook test with a mocked replay |
| 9 | **Live check:** one real replay of a poisoned and a benign example; note trials, flagged behaviors, wall-clock time and cost | — | Numbers in the PR |

Suggested order: 1 → 4 → 2 → 3 → 6 → 7 → 5 → 9 → 8. (Fake tools and comparison need no API at all; prompts can be hand-written until item 5 exists.)

## 4. Rules to follow

- **Never execute anything.** The fake tools are the security boundary of this block: the simulated agent is running poisoned instructions on purpose. No `subprocess`, no network except the Claude API, no file writes from tool calls. Test it.
- **Speed:** replay never runs inside a blocking hook (PreToolUse, SessionStart). Keep `anthropic`, Pydantic and SQLModel out of module tops on the hook path. Check:
  `uv run python -c "import sys, memtegrity.hooks; print('pydantic' in sys.modules, 'anthropic' in sys.modules)"` → `False False`.
- **Reuse Block 4's API handling:** `llm_risk.load_api_key()` (key from our own `.env`, never exported, never from the project) and the pinned `llm_risk.API_BASE_URL`. Replay runs in the background, so it may use a longer timeout and a couple of retries; make its own client with those, don't change the judge's.
- **Cost:** Haiku 5.5 is $0.10 / $0.50 per million tokens. 3 prompts × 5 trials × 2 conditions = 30 trials, a few turns each: about $0.05–0.15 per replay (estimate; measure it in item 9). Put any new cap (e.g. max replays per session) in `config.py`.
- **No API calls in tests or CI.** Copy `FakeAPI` from `tests/test_judge.py` (real SDK, `httpx2.MockTransport`) and script multi-turn responses with `tool_use` blocks. `conftest.py` already forces `MEMTEGRITY_JUDGE=off` and an empty plugin root; keep tests from ever finding a real key.
- **Agent-neutral core:** the harness simulates *Claude Code*. Keep that knowledge (tool names, how memory loads) in clearly labeled places, so another agent's simulation could sit next to it.
- **Cross-platform:** `encoding="utf-8"`, `pathlib`, `Path.home()`; in tests `conftest.set_home`, `write_bytes` when comparing hashes. CI runs macOS, Linux and Windows.
- **No hidden Unicode in source:** write escapes, then run `uv run python scripts/escape_invisible.py <files>`.
- **Don't change scoring numbers** (calibration is Block 6). Replay evidence is shown next to the verdict; it doesn't change it (yet).

## 5. Decisions to make first (ask the other partner, record them in PLANNING.md)

1. **Privacy:** replay must send the **whole** memory files (clean and flagged) to the API, unlike the judge, which only sends diffs. Proposal: `redact()` everything first, and run replay only when the user asks (`memtegrity replay <#>` / a skill), not automatically.
2. **Automatic trigger (item 8):** run in the background after every deny/restore, or only on request? Automatic costs money on every flag and needs the privacy decision above.
3. **Prompts:** hand-written ones live in the datasets (Block 6, `datasets/README.md` → `test_prompts`). Until then, use 2–3 hand-written prompts in the tests and the generator (item 5) for real events.
4. **Model:** `claude-haiku-5-5` (cheap, many calls) is the plan in `config.replay_model`. Haiku may refuse obvious poison more or less than Claude Code's real model; note what the live check shows.

## 6. Out of scope

Datasets, the evaluation harness and score calibration, the HTML report and `/memtegrity:report`, the popular-package refresh (all Block 6). The Docker sandbox from the original plan is optional and last: the fake tools already mean nothing runs.

## 7. Done = PR ready

- [ ] `uv run pytest`, `ruff check`, `ruff format --check` pass on all three CI systems; fast-path check prints `False False`.
- [ ] A test proves the fake tools execute nothing.
- [ ] Live replay of one poisoned and one benign example; flagged behaviors, time and cost in the PR.
- [ ] README **Status** (Block 5), `docs/THREATS.md` (behavioral evidence), `docs/PLANNING.md` (the decisions in section 5) updated; the `replay` stub test in `tests/test_placeholder.py` replaced (it guards the replay stub today).
- [ ] Write `docs/BLOCK6.md` for the next person (datasets, evaluation + calibration, HTML report, chain-head anchoring).
- [ ] PR to `main`, reviewed by the other partner.
