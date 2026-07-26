---
"cipher-brain": patch
---

Internal: `npm run verify` now runs the suite under an isolated `TMPDIR` and fails if
anything is left in it, so a script that forgets to clean up its temp directory is caught
rather than accumulating age private keys in a shared `TMPDIR` (#328). The suite itself is
unchanged and now lives at `npm run verify:suite`. No behaviour change to the package.
