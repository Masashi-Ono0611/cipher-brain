---
'cipher-brain': minor
---

`push` and `pull` now report transfer progress on the backends that can be slow.

`turbo` uploads subscribe to the SDK's own progress events, `rclone` transfers ask the
binary for periodic stats and translate them, and an `arweave` gateway read counts bytes
as they stream to disk. `file` and the L1 `arweave` upload path say nothing — the first is
a local copy and the second is capped at ~10 MiB, so neither has anything to report.

Lines go to stderr in the existing `component: message` style, and the cadence depends on
who is watching: about every 2 seconds when stderr is a terminal, about every 30 seconds
otherwise. That second number matters because the generated nightly runner appends all
output to a log that is never rotated, and because an MCP tool that surfaces its captured
output puts these lines in the tool result — a per-second line would grow both without
telling anyone anything new.
