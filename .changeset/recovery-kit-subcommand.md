---
"cypher-brain": minor
---

New `cipher-brain recovery-kit` subcommand (#364): regenerate the printable
recovery kit `init` prints once, pointed at the CURRENT latest push — every
push changes the locator/sha the kit exists to carry, so a printed kit went
stale each cycle with no way to refresh it. The kit builder moved out of the
init wizard into a shared module, so `init` and `recovery-kit` render one
canonical kit that cannot drift. Reads a `push --save-locator` file (locator +
backend validated, not trusted) plus the standard key layout under
`CIPHER_BRAIN_HOME`; prints to stdout, or `--out` writes 0600 via an
exclusive-create temp and an atomic no-clobber promote (`--force` replaces).
`--inline-identity` embeds the primary identity only when the file really is a
passphrase wrap — classified from its bytes (age ciphertext with an scrypt
first stanza), with a binary wrap re-armored to the printable `age -p -a`
encoding; a bare private key in a paste-anywhere document is refused outright.
`--backup-identity` inlines a backup key wizard-style (an unwrapped one warns
loudly through the run-summary chokepoint; a wrapped one is re-armored if
binary and requires `--backup-recipient`). PQ hybrid identities classify and
derive like X25519 ones. A regenerated kit reports the profile and Postgres
columns as unknown rather than guessing. Deliberately CLI-only — no MCP tool
exposes it, since the kit can embed private key blocks that must never land in
an agent's tool-result context.
