---
description: "Approve a flagged change as the user's own: it becomes the trusted version Memtegrity compares against. Takes a file, or an event number from /memtegrity:review."
argument-hint: "<file or event number>"
disable-model-invocation: true
---

Run this command with what the user named. Claude Code will ask the user to confirm, because only the user may approve content:

```bash
MEMTEGRITY_DATA_DIR="${CLAUDE_PLUGIN_DATA}" "${CLAUDE_PLUGIN_ROOT}/bin/memtegrity" approve $ARGUMENTS
```

Tell the user the result in one sentence.
