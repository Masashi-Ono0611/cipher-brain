---
'cipher-brain': minor
---

gbrain support no longer assumes Postgres (#367). PGLite — Postgres compiled to WASM,
whose entire database is a directory on disk — is gbrain's default engine, and everything
cipher-brain said and did about gbrain was written for the other one.

`init` now reads which engine your `~/.gbrain/config.json` names (gbrain's own order: an
explicit `engine`, else `database_path` implies PGLite, else Postgres). On a PGLite brain
it drops the Postgres prose and stops offering a `--pg` dump of a server that does not
exist. It then tells you whether the directories you chose actually cover the store,
checked against the `database_path` the config records — so a brain kept somewhere other
than `~/.gbrain` is no longer reported as backed up by a snapshot that does not contain
it. It only gives a verdict when it can actually know the answer: a `database_path` that
is missing, or recorded as a relative path (which gbrain resolves against whatever
directory *it* runs from), gets an explicit "cannot tell — check this yourself" instead of
a guess. Beyond the engine and that one path, nothing is read out of `config.json`, which
holds API keys. On a Postgres brain the wizard behaves exactly as before.

`snapshot` now warns when a `--dir`/`--profile` source **is**, or has **directly inside
it**, a PostgreSQL data directory (`PG_VERSION` plus `pg_wal/` — a PGLite store is one).
A running cluster cannot be copied safely at the file level outside PostgreSQL's own
backup API, so the archive may be internally inconsistent; crash recovery usually but not
always rescues such a copy, and `verify` cannot tell you either way, because the
ciphertext is well-formed regardless. It is a warning and never a refusal, so an
unattended nightly backup is never blocked by it, and it reaches both the CLI run summary
and the MCP `warnings` array. A store that a `.cipherbrainignore` rule has cut into pieces
gets a stronger warning of its own — stated as a certainty when the excluded paths hit
something a cluster cannot start without (`PG_VERSION`, `pg_wal/`, `base/`, `global/`),
and hedged when they do not.

Two limits are stated rather than glossed. Without a `.cipherbrainignore` the search
reads the source root and one level below it (with one, the walk has already happened and
the search is exact at any depth). And the markers identify a Postgres-format data
directory, not gbrain specifically — an ordinary server's datadir looks the same, so the
warning names the format and offers `gbrain pglite-repair` as something to try if it is a
gbrain store, not as a prescription.

README.md and MANAGEMENT.md are corrected accordingly, including what to do when a
restored PGLite store will not open.
