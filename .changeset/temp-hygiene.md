---
"cipher-brain": patch
---

Internal: two selftests left their temp directory behind on every run, so `npm run verify`
accumulated them — `selftest-arweave-nodeps` runs `keygen` into its one, so those were
working age private keys (157 of them here after a day). Both now remove it. No behaviour
change.
