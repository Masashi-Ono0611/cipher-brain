---
"cypher-brain": minor
---

New `cipher-brain doctor` command: a read-only health check of the current
setup. It re-checks, on the machine you run it on, the permission/config
problems several past issues were filed for — `$CIPHER_BRAIN_HOME` and the age
identity's permissions (0700/0600), the Arweave JWK wallet's permissions (FAIL,
not skipped, when `CIPHER_BRAIN_AR_WALLET` is explicitly set but nothing is
there), an identity/recipient pairing mismatch (including an unexpected EXTRA
recipient in `recipient.txt` that the identity does not derive — the same
"rewrite recipient.txt to re-key future snapshots" attack the README's Threat
model describes), an empty `CIPHER_BRAIN_PIN_RECIPIENTS` fail-closing every
snapshot, any recipient.txt entry missing from that same allowlist (not just
the primary one — `snapshot()` itself requires every effective recipient to be
allowlisted), an offline backup keypair sharing a disk with the primary
identity at its default location, and the last scheduled run's outcome — and
reports PASS/WARN/FAIL/SKIP per check, each FAIL/WARN paired with the exact
command that fixes it. A permission-denied path, a symlink loop, or an
unexpected file type (e.g. a FIFO) on a checked path is reported as its own
FAIL rather than folded into the same result an absent path gets.

Between runs it keeps a small bookkeeping file
(`$CIPHER_BRAIN_HOME/doctor-state.json` — check ids and timestamps only, never
key material, written via an exclusive-create-then-rename so a pre-existing
symlink at that path is replaced rather than followed) so an already-seen,
still-unfixed problem is marked "known" instead of re-surprising you every
time, while a genuinely new one is marked distinctly and costs more against
the printed `health_score` — a discount, not a full exclusion, so a lingering
FAIL never reads a healthy-looking 100/100. `--json` prints the same
computation as one machine-readable object. `doctor` never creates
`$CIPHER_BRAIN_HOME` itself, so it stays read-only on a machine with nothing
set up yet, and a corrupt/unparseable identity file is reported as a FAIL
without ever echoing the underlying error (which can otherwise embed key
material).
