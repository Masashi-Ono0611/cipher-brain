---
'cipher-brain': patch
---

The MCP server refuses a declared argument the chosen branch will never read, instead of
dropping it in silence. `verify_restore {file, backend}` returned `PASS` from a code path
that fetches nothing; `snapshot_now` without a `backend` accepted `locator_file` and
`confirm_paid` and never wrote the locator file. Completes #308, whose enum half landed in
#310.
