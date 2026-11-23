---
description: "Put a protected file (CLAUDE.md, a rule, a memory file, settings) back to its last approved version. The version it replaces is kept as evidence."
argument-hint: "<file>"
disable-model-invocation: true
---

Run this command with the file the user named, and tell the user the result:

```bash
MEMTEGRITY_DATA_DIR="${CLAUDE_PLUGIN_DATA}" "${CLAUDE_PLUGIN_ROOT}/bin/memtegrity" restore $ARGUMENTS
```

If it says there is no approved version, tell the user and suggest `/memtegrity:review`. Don't edit the file yourself.
