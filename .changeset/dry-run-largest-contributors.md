---
'cipher-brain': minor
---

`snapshot --dry-run` now reports the largest contributors to each `--dir`/`--profile`
source — up to the top 10 by bytes, aggregated one directory level deep (so a big nested
tree reads as one line, not thousands of files), with each one's share of that source's
total. With more than 10, the rest are folded into one `other (N more)` remainder line
carrying their combined bytes/share, so the printed shares always add up to the whole
source instead of silently truncating.

Shown in both branches: **with no `.cipherbrainignore` present** (previously a single
aggregate line and nothing else — the state nobody has audited yet) and with one present,
alongside the existing include/exclude report. Reporting only — no new flags, and what
gets archived is unchanged either way.

`estimate` is left as-is: it only ever sees an already-built, encrypted snapshot file, not
a source tree, so it has no cheap way to produce the same breakdown without a hidden
re-scan of a live source right before a paid push — not something to add silently.
