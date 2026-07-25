---
"cipher-brain": patch
---

The MCP `verify_restore` and `restore_now` tools now report a nonexistent `file`
argument as `ERR_INVALID_INPUT`, matching `estimate_cost`. They reported
`ERR_INTERNAL` — telling an agent the server had malfunctioned, when the path it
passed simply does not exist. The message is unchanged (`no such file: <path>`);
only the code an agent branches on is corrected.
