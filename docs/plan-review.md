# CS4910_Project
A repo for our CS4910 semester project

Claude Review of Project Plan:

This is a well-scoped, genuinely interesting plan — the “AI provides analysis; software provides evidence, isolation, history, and recovery” framing is a strong organizing principle, and the scope section cutting cloud/accounts/K8s is the right instinct. Below is what you’ll need to actually build it, then the issues I’d resolve before you commit.

What you’ll need to complete it

Accounts / external resources

An LLM API key and a cost budget (risk scoring + test generation + every replay run burns tokens — see issue #5).
Docker Desktop on each dev machine (WSL2 backend on Windows, native on macOS).
Python 3.11+ and Node 18+ toolchains on every machine.

Components to build (maps to your 7 dev phases)

Memory watcher on watchdog with a config file listing which files/paths to monitor.
Snapshot store: SQLite + SQLAlchemy schema for versions, SHA-256 hashes, diffs, alerts, replay results.
Diff engine (textual/structured diff appropriate to your memory format).
Rule-based risk layer (deterministic indicators) + LLM risk layer (semantic scoring with structured output).
Restore/quarantine logic.
The agent runner — the thing that actually loads a memory state and emits tool calls (this is undefined in the plan; see issue #1).
Mock tool harness: read_file(), run_command(), http_request() that record intent instead of executing.
Docker sandbox image + orchestration to run clean vs. suspicious in a consistent environment.
Comparison engine that turns two recorded action traces into a “behavioral difference.”
React/TS/Vite/Tailwind dashboard.
A labeled benign/poisoned memory test set plus a metrics harness (detection rate, replay success, latency, API cost).
pytest + Vitest suites.

Process / group logistics (not in the plan)

Git repo + branching convention, and a division of the 7 phases across teammates.
A timeline/milestones with a minimum-viable-demo fallback.
Issues to resolve

I’d rank these by how much they threaten the project.

1. Which agent are you replaying? (biggest gap) The entire “behavioral replay” pillar assumes an agent that loads persistent memory and decides on actions, but the plan never says what that agent is. Are you writing a minimal LLM + tool-calling loop yourselves, or wrapping a real one? This is the crux of the whole tool and it’s currently unspecified. Decide early, because almost everything downstream depends on it.

2. LLM nondeterminism breaks the clean-vs-suspicious comparison. Two runs with the same memory can already differ, so a single clean-vs-suspicious diff may be noise rather than the poison’s effect. You’ll need temperature 0, multiple trials per condition, and a comparison that’s statistical (“suspicious caused action X in 9/10 runs vs 0/10 clean”) rather than a single pairwise diff. Plan for this in the comparison engine and the metrics.

3. “Persistent-memory files” is undefined. Claude’s memory, Cursor rules, a ChatGPT-style memory, a plain JSON file — these differ in format, location, and how poison would be injected. Pick a concrete target (or a small defined set). It determines your diff format, your poison examples, and your watcher config.

4. Threat model is fuzzy. The pitch says “independent evidence outside the agent,” but the tool runs on the same machine as the memory it’s protecting. If your adversary is local malware, it could also tamper with your SQLite DB and hashes. If your adversary is prompt-injection/poisoning that arrives through normal use (far more defensible for a course project), say so explicitly — it makes the integrity story coherent and bounds the work.

5. Cost and latency compound fast. One suspicious change = test generation + risk scoring + (clean + suspicious) × N trials of multi-step agent runs. That’s a lot of API calls per event. Estimate per-replay cost/time up front so the demo doesn’t stall and the budget doesn’t surprise you.

6. Sandbox network boundary is contradictory. Mock tools stop dangerous local actions, but the agent inside Docker still needs network egress to reach the LLM API. So the container isn’t fully isolated. Define the boundary: outbound to the LLM allowed, everything else mocked/blocked.

7. Generated-test quality is a silent failure mode. If the LLM-generated tests don’t actually exercise the poisoned behavior, you’ll report “no difference” and miss real poison. You need a way to validate that your tests are meaningful (e.g., hand-authored tests for your known poisoned cases to check the generator).

8. Quarantine semantics vs. a live agent. What does quarantine physically do — revert the file, stash it? And if the real agent re-reads that file at runtime, how do you stop it loading the poison while “quarantined”? Define the interaction with the live memory file.

9. Dual-OS support doubles your test surface (watchdog quirks, Docker-on-Windows via WSL2, path handling). Confirm both Windows and macOS are required for grading; dropping to one, or making the second “best effort,” buys you a lot of time.

10. Scope vs. semester. The replay + Docker + agent-runner piece is arguably a project on its own. Sequence the 7 phases so you have a working demo of phases 1–5 (watch → snapshot → detect → restore) even if the replay sandbox slips — that protects your demo.
