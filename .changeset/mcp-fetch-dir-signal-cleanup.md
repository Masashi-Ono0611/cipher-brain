---
'cypher-brain': patch
---

Stopping the MCP server no longer leaves its temp directories behind. `verify_restore` and
`restore_now` stage a pulled or copied artifact in a `cipher-brain-mcp-*` directory under
your temp dir and erase it when the call ends — but a SIGTERM or SIGINT (launchd stopping
the server, a machine shutdown, Ctrl-C on a foreground server) ended the process without
that cleanup running, accumulating one leftover directory of ciphertext per interrupted
call. The signal handler that already erases the snapshot staging directory now erases
these too, including several from calls in flight at the same time.
