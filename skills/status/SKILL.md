---
description: "Show what Memtegrity protects in this project: every protected instruction, memory and settings file, whether it still matches its approved version, and whether the audit log is intact."
---

Run this command and show the user its output:

```bash
MEMTEGRITY_DATA_DIR="${CLAUDE_PLUGIN_DATA}" "${CLAUDE_PLUGIN_ROOT}/bin/memtegrity" status
```

Then summarize in one or two plain sentences: how many files are protected, and which ones (if any) changed or are flagged. If something is flagged, suggest `/memtegrity:review`.
