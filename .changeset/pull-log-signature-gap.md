---
'cipher-brain': minor
---

The MCP `verify_restore` and `restore_now` tools return `pulled.log` — everything their
fetch said, which they used to collect and discard: retries, the `sha256 OK` confirmation,
transfer progress, and the reason a signature could not be fetched. URL userinfo is redacted
from it.

They also return a `signature` object when the sidecar fetch failed. Without it, a signature
that could not be retrieved was reported as `unsigned (legacy) artifact` — which is what
deleting a `.minisig` produces, and is not the same thing.
