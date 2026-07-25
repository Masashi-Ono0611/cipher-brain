---
'cipher-brain': minor
---

cipher-brain now states that it does not delete, and the secret scan runs by default.

**The position (#301).** There is no `forget`, `prune` or `delete`, and there will not be
one: `arweave`/`turbo` are write-once, and destroying your identity is not an escape hatch
either, because the backup recipient this project tells you to keep still decrypts
everything. Recoverability was chosen over erasability on purpose, and `--help`, README and
MANAGEMENT.md now say so before you push rather than after you leak. What is parked is
ciphertext — a secret that reaches a snapshot is sealed to your key, not published — and
that nuance is stated too, because overstating the exposure would be its own dishonesty.

**The consequence.** With no way to unsay a push, the one preventive measure cannot stay
switched off by default. `--scan-secrets` now defaults to `warn` whenever there is a
`--dir`/`--profile` source and gitleaks is resolvable. On a machine without gitleaks
nothing scans, nothing errors and no new dependency appears. `--scan-secrets off` is the
new third mode: it turns the default off out loud, rather than by uninstalling a binary.

Two asymmetries are deliberate and are what keep this a default rather than a requirement:

- Only the IMPLICIT default may skip quietly, because nobody asked for a gate and nothing
  claims one ran. An EXPLICIT `--scan-secrets` that cannot scan still refuses (#307).
- A scanner that ERRORS degrades the default to a loud "snapshotting it UNSCANNED" warning
  instead of failing the snapshot. Found by an existing test: `gitleaks dir` exits 1 on a
  dangling top-level symlink, a source snapshot archives on purpose, so a fail-closed
  default would have turned a supported input into a hard error. An explicit request on the
  same source still refuses.

`schedule install` resolves the effective mode at install time and bakes it into the
runner, including `off` — a nightly must not start scanning, or stop, because of what lands
on the scheduler's `PATH` months later.
