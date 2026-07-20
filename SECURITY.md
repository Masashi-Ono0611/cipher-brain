# Security Policy

`cipher-brain` is a cryptographic tool: it encrypts second-brain snapshots
client-side with [age](https://age-encryption.org) (X25519 + ChaCha20-Poly1305,
via the bundled [typage](https://github.com/FiloSottile/typage) implementation)
and parks the ciphertext on pluggable storage backends (Arweave/Turbo, local
file). Treat findings that could weaken the encryption, key handling, or the
ciphertext-only guarantee with the same seriousness as a vulnerability in a
key-management tool.

## Supported versions

This is a young, fast-moving, single-maintainer project without long-term
support branches. Only the **latest published version** (see the `version`
field in [`package.json`](package.json), or `npx cipher-brain --version`)
receives security fixes.

| Version | Security fixes |
|---|---|
| latest | ✅ |
| anything older | ❌ Upgrade first |

## Reporting a vulnerability

**Do not file a public GitHub issue for security problems.**

Use GitHub's private vulnerability reporting: open the
[Security tab](https://github.com/Masashi-Ono0611/cipher-brain/security) on
this repo and click **"Report a vulnerability"** to start a private security
advisory. Include:

1. A description of the issue and its impact.
2. Reproduction steps (or a PoC). Never include real identity files, recipient
   files, or unencrypted snapshot contents in a report — use synthetic data.
3. The affected version (`cipher-brain --version`).
4. Your suggested fix, if any.

## Threat model — what's in scope

See the README's [Threat model](README.md#threat-model--the-key-is-only-mine)
section for the full design rationale. In short: the always-on machine that
runs snapshots holds only the **recipient** (public key) and should only ever
produce or see **ciphertext**; the **identity** (private key) never touches it.

In scope:

- Anything that could let the always-on/public-key-only side of the design
  read plaintext it shouldn't (a break of the ciphertext-only guarantee).
- Anything that could let an attacker who does *not* control the identity
  file decrypt a snapshot.
- Silent re-keying of future snapshots to an attacker-controlled recipient
  (bypassing `CIPHER_BRAIN_PIN_RECIPIENTS`) or other ways `verify` could
  report `PASS` when a snapshot is not actually restorable.
- Vulnerabilities in the age/typage integration, key file handling
  (permissions, atomic writes, symlink handling), or the storage-backend
  clients (Arweave/Turbo, `file`) that touch key material or plaintext.
- Supply-chain issues in this repo's own release pipeline (e.g. the OIDC
  trusted-publishing workflow, `dist/` bundling).

Out of scope (already acknowledged as caveats in the README's threat model):

- Compromise of the always-on box itself (its live Postgres / `~/.gbrain`
  plaintext, or local root/shell access) — `cipher-brain` protects the
  snapshots shipped off-box, not the source machine. Keep that machine
  full-disk-encrypted; that's outside this tool's control.
- The fact that age's X25519 recipient scheme is not post-quantum secure, and
  that ciphertext already parked on a permanent public network (e.g. Arweave)
  cannot be recalled — these are documented, accepted tradeoffs of the design,
  not bugs. (A post-quantum hybrid recipient is on the roadmap.)
- Bugs in upstream dependencies (`age-encryption`/typage, `@ardrive/turbo-sdk`,
  `arweave`, `@modelcontextprotocol/sdk`) themselves — report those upstream,
  though a report here that identifies how this repo's usage of them is unsafe
  is welcome.
