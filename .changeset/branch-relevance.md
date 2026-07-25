---
'cipher-brain': patch
---

The MCP server refuses a declared argument whose branch will never read it.

`verify_restore {file, backend}` took the local-file branch, fetched nothing, and returned
`PASS` — a verdict from a code path that never touched the backend it was handed.
`snapshot_now` with no `backend` was worse in consequence: `locator_file` and `confirm_paid`
only reach the push step, so a caller asking for the durable recovery pointer got a clean
exit, no push, and no file (measured on `main` before the change).

This completes #308, whose enum half landed in #310. It is not a new discipline — the server
already refused three cases of exactly this, each written by hand where someone noticed
(`locator_file` with `backend`, `ping_url_fail` without `ping_url`, `max_spend` on a free
backend). What was missing was anything that made the question get asked. Each tool now
declares which of its fields are branch-dependent, an empty declaration counts as an answer,
and the dispatcher refuses to serve a tool that has no declaration at all — so a tool added
later forces the decision rather than defaulting to silence, and `scripts/mcp-smoke.mjs`
turns a forgotten declaration into a failing build.

Cases already enforced in `src/lib/` are deliberately left there: `schedule install`'s three
are shared with the CLI, which needs them just as much.

Review found a fourth instance the first declarations missed — `confirm_paid` is inert on
the free `file` backend too, not only when no backend is named — and one way the new check
could make things worse: a call naming two sources has no valid branch at all, so reporting
"backend is irrelevant on this branch" would have named the smaller problem and hidden the
real one. Irrelevance is now claimed only when the branch is unambiguous.
