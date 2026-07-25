---
'cipher-brain': patch
---

`restore --help` no longer advertises `--keep-old-files` as if it were a flag you can pass.

It is not one — typing it gets `unknown flag` — and it was the sole borrowed flag in the
help that did not name its owning tool, unlike the neighbouring `pg_dump --filter` and
`pg_restore --clean` mentions. It also named the wrong one: `tarNoClobberFlag()` picks
`--skip-old-files` on GNU tar, because GNU's `--keep-old-files` exits 2 on a collision,
which is the same signal a corrupt artifact gives. The guarantee is now stated as
restore's own behavior, with both tar flags attributed and the flavor split explained.
