---
'cipher-brain': patch
---

`push --sign`'s authenticity sidecar can now actually be pulled back from `arweave`/`turbo`.

The gateway read promotes a response body only if it passes `isAgeCiphertext()` — a guard
that exists for a good reason, since a gateway can answer HTTP 200 with a soft-404 page or a
"tx pending" placeholder that must never be written to `--out`. But a minisign signature is
plaintext, so a `.minisig` sitting **intact** in storage failed that check, fell through
every gateway and the L1 chunk read, and surfaced as the retryable error that `pull`'s
best-effort sidecar step turns into `warning: could not fetch the authenticity signature`.

The pull succeeded, the ciphertext was correct, and `verify` then reported
`[SKIP] … unsigned (legacy) artifact, authenticity not checked` — for a signed artifact. On
the permanent, un-deletable backends, where someone else's infrastructure serves the bytes
and authenticity matters most.

The comment above that guard said "every stored object is age ciphertext (push enforces the
same header)". That stopped being true when #214 began pushing a second, non-ciphertext
object to the same backend, and nothing noticed because `selftest-minisign.sh` exercises the
sidecar round-trip only on the `file` backend — every `push` in it passes `--backend file`.

`StorageBackend.get()` now takes an optional `expect: 'age' | 'minisig'`, so the check is
per shape rather than removed: a soft-404 is still refused for a sidecar exactly as it is
for a ciphertext. `file` and `rclone` accept it and ignore it, having no such gate. The
signed round trip is now part of `scripts/arweave-roundtrip.mjs`, against arlocal.
