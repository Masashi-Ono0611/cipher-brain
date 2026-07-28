---
"cipher-brain": minor
---

New `cipher-brain doctor` command: a read-only health check of the current
setup. It re-checks, on the machine you run it on, the permission/config
problems several past issues were filed for — `$CIPHER_BRAIN_HOME` and the age
identity's permissions (0700/0600), the Arweave JWK wallet's permissions, an
identity/recipient pairing mismatch, an empty `CIPHER_BRAIN_PIN_RECIPIENTS`
fail-closing every snapshot, the primary recipient missing from that same
allowlist, an offline backup keypair sharing a disk with the primary identity
at its default location, and the last scheduled run's outcome — and reports
PASS/WARN/FAIL/SKIP per check, each FAIL/WARN paired with the exact command
that fixes it.

Between runs it keeps a small bookkeeping file
(`$CIPHER_BRAIN_HOME/doctor-state.json` — check ids and timestamps only, never
key material) so an already-seen, still-unfixed problem is marked "known"
instead of re-surprising you every time, while a genuinely new one is marked
distinctly and costs more against the printed `health_score` — a discount, not
a full exclusion, so a lingering FAIL never reads a healthy-looking 100/100.
`--json` prints the same computation as one machine-readable object. `doctor`
never creates `$CIPHER_BRAIN_HOME` itself, so it stays read-only on a machine
with nothing set up yet.
