---
"cypher-brain": patch
---

`restore` now tells you when it ignored a `--out` you passed. `--out` names the
destination on `snapshot`, `pull` and `wallet create`, but `restore` uses
`--out-dir`, and the old message — a bare `--out-dir <dir> required` — read as
if no destination had been given at all. Passing neither still produces the same
plain message.
