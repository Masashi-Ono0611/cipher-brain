---
"cypher-brain": minor
---

`--json` output is now a complete, stable object. `estimate --json` always emits
all seven keys, using `null` where a backend has no value, instead of omitting
them — a consumer no longer has to distinguish "absent" from "not applicable".
And when a recognized command fails, `--json` now prints `{error, code,
exit_code}` on stdout rather than nothing, so the failure arrives on the same
channel as the success. An unrecognized command still reports on stderr only
(exit code 2) — that is argument parsing, before any command runs.
