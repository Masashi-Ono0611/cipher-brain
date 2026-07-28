---
'cipher-brain': minor
---

`verify` gains `--level quick|remote|drill` (issue #209), restic/kopia-style staged
verification for "is this backup actually still durable" instead of only "does this local
file still parse":

- `quick` (default, unchanged): everything `verify` already did — age header, wrong-key
  rejection, and (with a private identity) a positive-control decrypt, all against the
  local `--in` file. No network access, same as before this change.
- `remote`: pulls the artifact by `--locator`/`--backend` (or `--from-locator-file`) into
  a scratch temp file, then runs the same checks against what actually came back from
  storage — proving the object is still retrievable and unchanged, not merely that a
  local copy still parses. A fetch failure reports `VERDICT: FAIL` (exit 1) instead of a
  raw error, since retrievability is the thing being tested.
- `drill`: does everything `remote` does, and — once those checks reach PASS — also
  decrypts and extracts the pulled artifact into a scratch directory (the same code path
  `restore` runs), the full pull -> decrypt -> extract rehearsal MANAGEMENT.md's restore
  runbook describes. Refuses `--pg` (a verification drill must never run `pg_restore`
  against a live database) and always removes its scratch directory afterward.

`--json` gains matching fields (`level`, `pulled: {backend, locator, sha256_pin,
fetched}` for `remote`/`drill`; `full_restore: true|false|"skip"` for `drill`) alongside
the existing `checks`/`verdict`/`exit_code` — the `quick` JSON shape is unchanged.
