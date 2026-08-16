---
'cypher-brain': minor
---

`doctor` now reports the provenance of the code that is actually running: which commit
the build came from, whether the tree was dirty, and how many days old that commit is —
WARNing past 90 days. Motivation, measured: a hand-copied `dist/cli.mjs` ran the real
snapshot host for 5+ weeks silently missing documented features, and nothing surfaced
its age (the version string says 0.0.1 on every build to date, so it cannot). The stamp
is the commit hash + commit date baked into dist at build time — not wall-clock, so
rebuilding the same commit still yields identical bytes; a dev run derives the same
facts live from git, and a stampless git-less run reports "unknown", never "fresh".
Comparing against a latest release is deferred until releases exist to compare against.
