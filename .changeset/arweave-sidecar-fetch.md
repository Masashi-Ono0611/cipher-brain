---
'cypher-brain': patch
---

`push --sign`'s `.minisig` sidecar can now be pulled back from `arweave`/`turbo`. The
gateway read accepted only age ciphertext, so a signature sitting intact in storage could
never be fetched — `pull` warned, and `verify` then reported a signed artifact as
`unsigned (legacy) artifact, authenticity not checked`. `StorageBackend.get()` takes an
optional `expect: 'age' | 'minisig'`; `file` and `rclone` ignore it.
