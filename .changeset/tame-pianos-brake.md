---
'cipher-brain': patch
---

MCP: a value outside a tool argument's declared `enum` is now refused instead of
silently ignored. `backend` advertises `["file","arweave","turbo"]`, but a bad value
was only caught where the handler happened to read it — `estimate_cost` errored while
`verify_restore {file, backend: "nonsense"}` returned a clean `PASS` from a code path
that never touched the backend it was told to use. The check now runs in the
dispatcher against each tool's own published schema, so it covers every tool, every
branch, and any enum a tool declares later, and it names the near miss (`"fille"` →
*did you mean file?*). A value the enum permits but the chosen branch does not need is
still accepted and ignored.
