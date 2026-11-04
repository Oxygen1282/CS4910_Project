# Demo

Material for the 3–5 minute demo video. Nothing here yet.

## Planned contents
- `poisoned-page/`: a harmless-looking web page or README with a hidden indirect prompt
  injection that asks the agent to "remember" a malicious standing instruction.
- `demo-project/`: a small throwaway project to run Claude Code in, with a clean `CLAUDE.md`.
- `script.md`: the narration and the exact prompts to type, in order.
- `fallback/`: a scripted path (pre-made memory edit plus `memtegrity` commands) in case
  Claude doesn't take the bait on camera.

## Planned flow
1. Show the clean memory and Memtegrity's `status`.
2. Ask Claude Code to read the poisoned page, and it tries to save the instruction to memory.
3. **PreToolUse blocks the write** and shows the risk score and reason.
4. Write the poison via Bash instead, and **FileChanged detects it and restores** the file.
5. Show **replay evidence**: clean vs. suspicious behavior counts.
6. Open the **HTML incident report**.
7. Quick metrics: detection rate, false positives, latency, cost.

Run it on one Mac (decided Thursday), with a throwaway project only, never a real one.
