---
"cypher-brain": patch
---

`push --skip-unchanged` now takes the signing state into account. It compared
only the ciphertext, so turning signing on for the first time, or rotating to a
new signing key, left the previously-pushed unsigned (or old-key) artifact in
place and reported the push as skipped — the new signature never reached the
backend. Signing changes now force the upload; an unparseable local signature
is treated as unknown rather than as unsigned.
