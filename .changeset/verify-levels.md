---
'cypher-brain': minor
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
  raw error, since retrievability is the thing being tested. A recorded-but-unfetchable
  authenticity sidecar is now also reported structurally in `--json` (`pulled.signature`,
  the same downgrade the MCP `verify_restore`/`restore_now` tools already surfaced),
  not just as a stderr warning.
- `drill`: does everything `remote` does, and — once those checks reach PASS — also
  decrypts and extracts the pulled artifact into a scratch directory (the same code path
  `restore` runs), the full pull -> decrypt -> extract rehearsal MANAGEMENT.md's restore
  runbook describes. Refuses `--pg` (a verification drill must never run `pg_restore`
  against a live database). A SIGINT/SIGTERM/SIGHUP during a drill now reliably erases its
  scratch directory (pulled ciphertext, and any decrypted plaintext) instead of only on a
  clean exit, and a FAIL/PARTIAL verdict reached before the restore step (a corrupt fetch,
  or no private identity on this box) now prints its `VERDICT: …` line like every other
  outcome, rather than only setting the exit code.

Two related hardenings to the backends `remote`/`drill` (and `pull`) read from:
- The `file` backend's locator is its own object's sha256 — `get()` now verifies the
  fetched bytes against that hash before ever returning them, so a substituted/rolled-back
  object under the same locator is refused outright, not only when the caller happens to
  pass `--sha256`.
- `rclone`'s locator (an operator-chosen remote path, not a content hash) now gets the same
  "no integrity pin was applied" warning arweave/turbo already had; it had been missing
  from that check.

`--json` gains matching fields (`level`, `pulled: {backend, locator, sha256_pin, fetched,
signature?}` for `remote`/`drill`, present with the same shape whether the fetch itself
succeeded or failed; `full_restore: true|false|"skip"` for `drill`) alongside the existing
`checks`/`verdict`/`exit_code` — the `quick` JSON shape is unchanged.
