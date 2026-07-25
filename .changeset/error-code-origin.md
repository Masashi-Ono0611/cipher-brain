---
"cipher-brain": patch
---

Internal: `CB-E###` error-code entries now record whether the text they match is
written here or by a dependency, and a new selftest fails when a pattern of ours
no longer matches anything in the source. No user-visible change — the codes,
messages and exit codes are identical.
