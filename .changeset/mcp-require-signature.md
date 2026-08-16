---
'cypher-brain': minor
---

The MCP `verify_restore` and `restore_now` tools accept `require_signature`, the CLI's
`--require-signature`: an artifact whose `.minisig` is absent is refused rather than warned
about. On `restore_now` it is checked before anything is decrypted or written, so it gates
`pg_restore` rather than reporting after it.

Also fixes a security bug on an adjacent path: `restore_now` with a `sha256` pin restored a
copy without the sidecar, so a **tampered** signature that the CLI refuses was decrypted and
extracted. Passing an integrity pin disabled the authenticity check. The sidecar now travels
with the copy.
