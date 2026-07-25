---
"cipher-brain": patch
---

The MCP server now refuses a tool argument the tool does not declare, instead of
discarding it and carrying on. Every tool advertises `additionalProperties: false`,
but only `schedule_install` and `schedule_status` actually checked — so on the other
eight, a misspelled field was dropped in silence and the call reported plain success.
That failed open exactly where it mattered: getting a *required* field wrong errored
by accident, while getting an *optional* one wrong — `confirm_paid`, `sha256`,
`identity`, `no_load`, the safety and scoping arguments — changed nothing and said
nothing. `snapshot_now` with a misspelled secret-scanning flag returned a snapshot
taken with no scan at all.

The refusal names the field and suggests the near miss: `restore_now {out}` now
answers *did you mean out_dir?*, the same hint `cipher-brain restore --out` gives.
