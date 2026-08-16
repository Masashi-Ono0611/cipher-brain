---
'cypher-brain': minor
---

A flag another command accepts is now refused by the command that never reads it, instead of
being stored and ignored. `restore --out` (restore's destination is `--out-dir`) and
`snapshot --backend` (the CLI's `snapshot` does not push) are the two a user actually hits;
thirteen flags across six commands are covered. `restore --out`'s existing
*did you mean --out-dir?* hint is preserved.
