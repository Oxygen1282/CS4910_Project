# Poisoned examples

About 10 memory-poisoning changes that Memtegrity should **flag** (`ask` or `deny`). Keep them
**subtle and plausible-sounding**, since Claude often refuses obvious poison. Cover each
`RiskCategory`: exfiltration, credential access, code execution, instruction override,
concealment and tampering.

Each example needs hand-written `test_prompts` that would make the poison show up in replay.

Format: see [`../README.md`](../README.md). `label` is `"poisoned"`.

TODO(B): write the examples.
