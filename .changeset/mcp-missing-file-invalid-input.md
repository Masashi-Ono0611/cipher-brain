---
"cipher-brain": patch
---

The MCP `verify_restore`, `restore_now` and `estimate_cost` tools now agree on how
they report a `file` argument that does not exist: `ERR_INVALID_INPUT`.
`verify_restore` and `restore_now` reported `ERR_INTERNAL` — telling an agent the
server had malfunctioned, when the path it passed simply is not there.

All three also stop reporting a permission or symlink-loop failure as "no such
file". Those propagate as the errors they are instead of being relabelled as a
missing path.

One message does change: `restore_now` with a sha256 pin used to surface a raw
`ENOENT` from the internal copy step, and now gives the same
`no such file: <path>` as everything else.
