---
'cipher-brain': minor
---

gbrain support no longer assumes Postgres (#367). PGLite — Postgres compiled to WASM,
whose entire database is a directory under `~/.gbrain` — is gbrain's default engine, and
everything cipher-brain said and did about gbrain was written for the other one.

`init` now reads which engine your `~/.gbrain/config.json` names (gbrain's own order:
an explicit `engine`, else `database_path` implies PGLite, else Postgres — and nothing
else is read out of that file, which holds API keys). On a PGLite brain it drops the
Postgres prose, stops offering a `--pg` dump of a server that does not exist, and
instead confirms that the directory you chose actually covers the store. On a Postgres
brain it behaves exactly as before.

`snapshot` now warns when a `--dir`/`--profile` source is, or contains, a PGLite data
directory: it is archived as a plain tar while a single-writer engine may be mid-write,
with none of the point-in-time consistency `pg_dump -Fc` gives the `--pg` path, and
`verify` cannot see the difference — the ciphertext is internally consistent either way
and a torn store only fails at restore time. The warning reaches the CLI run summary and
the MCP `warnings` array. It is a warning and never a refusal, so an unattended nightly
backup is never blocked by it.

README.md and MANAGEMENT.md are corrected accordingly, including where to go when a
restored PGLite store will not open: gbrain's own `gbrain pglite-repair`.
