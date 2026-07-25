---
"cipher-brain": minor
---

The MCP server now exposes a resource and a prompt, not just tools.

`cipher-brain://schedule/status` serves the installed schedule's state as JSON — the
same object the `schedule_status` tool returns, so a client can attach it rather
than relying on the model to think to fetch it. The `restore-runbook` prompt
returns the restore procedure verbatim from `MANAGEMENT.md`, so an agent no longer
reconstructs it from prose.

**Breaking, for MCP clients only:** `schedule_status` now returns the structured
report (`configured`, `runner`, `config_file`, `ping`, `trigger`, `last_run`,
`next_run`) instead of `{ report: [printed lines] }`. It is the same shape
`cipher-brain schedule status --json` has always printed, and all three surfaces
now come from one function rather than three descriptions of one contract. The CLI
is unaffected.
