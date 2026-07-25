---
'cipher-brain': minor
---

The MCP `verify_restore` and `restore_now` tools accept `require_signature`.

The CLI has had `--require-signature` on both `verify` and `restore` since #214: an artifact
whose `.minisig` is **absent**, rather than invalid, is refused instead of warned about. It
exists for the attacker who deletes a sidecar rather than forging one. The surface an agent
drives — the one that cannot look at a terminal and decide — did not offer it, and so got
the permissive posture with no way to ask for the strict one.

#312 made that situation visible on this surface, but for `restore_now` visibility arrived
at the wrong moment: the `signature` field is computed after the pull, and execution then
continues into `restore()`, so with `pg` the database could already have been dropped and
replaced before the caller saw it. Detection after the consequential action is not a gate.

The flag is passed through rather than reimplemented, which is what fixes the ordering for
free: `restore()` checks authenticity first — before the identity is loaded, before
`out_dir` is touched, before `pg_restore --clean --if-exists` runs — so the refusal now
happens ahead of the write. Measured: `restore_now` with `require_signature` on an unsigned
artifact refuses and `out_dir` is never created at all.

This waited on #321, without which it would have refused every signed `arweave`/`turbo`
restore — the sidecar could not be fetched from those backends at all.

Review of this change surfaced a security bug in an adjacent path, fixed here as #322:
`restore_now` with a `sha256` pin copies the ciphertext into a private tmpdir and restores
that copy, but copied **only the ciphertext** — so the artifact looked unsigned to
`restore()`, and an absent signature warns while an invalid one refuses. Passing an
integrity pin therefore disabled the authenticity check: a tampered `.minisig` that the CLI
refuses was decrypted and extracted. The sidecar now travels with the copy. Two smaller
review findings are fixed too: a non-boolean `require_signature` is refused rather than
coerced to false, and a refusal under the flag now carries #312's signature diagnosis
instead of falling back to restore()'s generic wording.
