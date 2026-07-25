---
"cipher-brain": minor
---

`--json` output is now a complete, stable object. `estimate --json` always emits
all seven keys, using `null` where a backend has no value, instead of omitting
them — a consumer no longer has to distinguish "absent" from "not applicable".
And when a command fails, `--json` now prints `{error, code, exit_code}` on
stdout rather than nothing, so a `--json` caller never has to fall back to
scraping stderr.
