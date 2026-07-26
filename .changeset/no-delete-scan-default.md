---
'cipher-brain': minor
---

**`--scan-secrets` now defaults to `warn`** when there is a `--dir`/`--profile` source and
gitleaks is resolvable. Without gitleaks nothing scans and nothing errors. `off` is a new
third mode — the way to turn the default off without uninstalling a binary. An explicit
`--scan-secrets` that cannot scan still refuses; only the implicit default skips quietly,
and a scanner that errors degrades it to a warning rather than failing the snapshot.

`schedule install` bakes the effective mode into the runner even when none is given, so a
nightly cannot start or stop scanning because of what is on `PATH` months later.

`--help`, README and MANAGEMENT.md now state plainly that **nothing can be deleted** once
pushed to `arweave`/`turbo`, at any granularity — destroying your identity does not help
either, since the backup recipient still decrypts everything.
