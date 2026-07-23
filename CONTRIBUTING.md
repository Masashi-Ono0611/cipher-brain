# Contributing to cipher-brain

Thanks for taking the time to contribute. `cipher-brain` is a cryptographic
tool — it encrypts second-brain snapshots client-side and parks the
ciphertext on pluggable storage backends — so contributions here get a
higher review bar than a typical CLI project, especially anything touching
key handling or the storage backends. This document sets expectations
up front so review is predictable for everyone.

## Language policy

All GitHub issues and pull requests (title, body, and comments), commit
messages, and code comments must be written in **English**. This applies to
everything created from now on. A number of issues and PRs from earlier work
in this repo were written in Japanese — those are left as historical
exceptions and are not being retroactively translated; do not use them as a
template for language when writing new ones.

(This is the same policy [`AGENTS.md`](AGENTS.md) states for AI coding
agents working in this repo — this section is the human-contributor
counterpart of that.)

## Before you start

- **Small fixes** (typos, docs, obviously-correct one-liners): open a PR
  directly.
- **Anything larger** (new flags, new backends, behaviour changes): open an
  issue first describing what you want to do and why. This avoids spending
  time on a PR that doesn't fit the project's direction — see "What
  cipher-brain isn't" in [`README.md`](README.md) for scope boundaries the
  project intentionally does not expand.
- Check open issues and PRs first so you're not duplicating in-flight work.

## Do not roll your own crypto

This is the single most important rule for this repo.

- Do **not** write new cryptographic primitives, re-implement encryption,
  key derivation, or key-wrapping schemes, or "improve" the existing age/
  typage integration's cryptographic logic. Use the existing
  [age](https://age-encryption.org) (X25519 + ChaCha20-Poly1305) format via
  [typage](https://github.com/FiloSottile/typage), which is what this
  project is built on and byte-compatible with the reference `age` CLI.
- If a change appears to require new crypto (a new algorithm, a new key
  format, a new wrapping scheme), open an issue describing the *problem*
  first — do not submit the implementation directly. Cryptographic design
  changes need discussion and, ideally, review from someone with a crypto
  background before any code is written.
- Vendor/upstream crypto bugs (in `age-encryption`/typage, `@ardrive/
  turbo-sdk`, `arweave`) belong upstream; a report here explaining how this
  repo's *usage* of them is unsafe is welcome.
- See [`SECURITY.md`](SECURITY.md) for how to report an actual
  vulnerability — not as a public issue or PR.

## What gets extra scrutiny

Because of what this tool does, PRs touching any of the following get a
slower, more careful review than a typical docs or CLI-ergonomics change:

- Identity/recipient generation, storage, or file permissions
  (`~/.cipher-brain/*`).
- The age/typage encryption or decryption call paths.
- Any storage backend (`file`, `arweave`/`turbo`, `rclone`) — anything that
  could let ciphertext-only guarantees slip, or that touches wallet/JWK
  handling.
- The MCP server contract (`src/mcp.ts`) — its tool surface is a public API
  surface for agents.
- Signal handling (SIGINT/SIGTERM/SIGHUP) and atomic write paths, where a
  bug can corrupt a snapshot or leave partial plaintext on disk.

Security- or crypto-adjacent PRs should go through a multi-model review
before merge (see the PR template's "Multi-model review" section) — this is
not optional for that category of change, even from the maintainer.

## Quality bar

Before opening a PR:

- `npm run lint` (biome, `--error-on-warnings`) passes.
- `npm run verify` (build + typecheck + the full selftest suite + CLI/MCP
  smoke) passes.
- No new `VERDICT: FAIL`, and no unexpected `VERDICT: PARTIAL`, in
  `verify`/`restore` output — see the README's
  [Threat model](README.md#threat-model--the-key-is-only-mine) for what
  those verdicts mean.
- Fill out the [PR template](.github/pull_request_template.md) checklist
  honestly, including the "Architecture impact" and "Regression / behaviour"
  sections — they tell the reviewer where to look first.

## Response time

This is a single-maintainer project maintained outside of working hours, so
please set expectations accordingly:

- **Security reports** (via GitHub's private vulnerability reporting, see
  [`SECURITY.md`](SECURITY.md)): best-effort acknowledgement, prioritized
  over everything else.
- **Bug reports and PRs**: no guaranteed SLA. Expect an initial response
  within roughly a week for most issues; complex crypto/storage-touching PRs
  may take longer given the review bar above.
- **Feature requests**: read and considered, but may sit unanswered for a
  while if they're not an immediate priority — a PR moves things faster than
  a request.

If something looks stalled, a polite bump on the issue/PR is fine.

## Code style

- TypeScript, formatted and linted with [biome](https://biomejs.dev)
  (`npm run format` / `npm run lint`) — match existing style rather than
  introducing a new one.
- Match the tone of existing code comments and docs: direct and technical,
  no marketing language.
- Keep changes scoped to what the issue/PR describes — avoid drive-by
  refactors of unrelated code in the same PR.

## License

By contributing, you agree that your contributions will be licensed under
this project's [MIT License](LICENSE).
