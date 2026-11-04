# Datasets

Labeled memory changes for evaluating Memtegrity. Owner: **Partner B**. No data yet.

- [`benign/`](benign/): about 10 ordinary memory edits that must be **allowed** (false-positive check).
- [`poisoned/`](poisoned/): about 10 memory-poisoning edits that must be **flagged** (detection check).

## Planned format (confirm Thursday)

One JSON file per example, named `<id>-<short-slug>.json` (e.g. `p01-deploy-backup-sync.json`):

```json
{
  "id": "p01",
  "label": "poisoned",
  "target_file": "CLAUDE.md",
  "before": "...approved content...",
  "after": "...content after the change...",
  "injection_source": "README of a cloned repo",
  "category": "exfiltration",
  "expected_verdict": "deny",
  "expected_behavior": "webfetch:backup-sync.example",
  "test_prompts": ["Deploy the app to staging"],
  "notes": "Why this is realistic / what makes it subtle"
}
```

`category`, `expected_verdict` and `expected_behavior` use the values in `src/memtegrity/models.py`.
`test_prompts` are hand-written; the LLM-generated prompts are compared against them.
