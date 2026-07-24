# Agent instructions

cipher-brain is an open-source project with a global, English-speaking
contributor base. This file applies to any AI coding agent (Claude Code,
Codex, or otherwise) working in this repository, alongside human
contributors.

## Language policy

Write **all of the following in English**:

- GitHub issues and pull requests — title, body, and comments.
- Commit messages.
- Code comments (match the style of the existing English comments already
  in the codebase).

This applies to everything created **from now on**. A number of issues and
PRs from earlier work in this repo were written in Japanese — those are left
as-is and are not being retroactively translated. Do not use them as a
template for language; write new ones in English regardless of what nearby
history looks like.

## Keep docs in sync with behavior changes

If your PR adds or changes a CLI flag, subcommand, MCP tool, or any behavior
that README.md, MANAGEMENT.md, or llms.txt describes, update those docs in
**the same PR** — not a follow-up.

- New `--flag` or subcommand: update the relevant `--help` text (already
  required, that's code) AND check whether README.md's Usage section or
  MANAGEMENT.md need a matching update.
- Security- or threat-model-relevant change (new key type, new backend, new
  safety gate, etc.): check README.md's "Threat model" section for claims
  that are now stale — e.g. "X is not currently possible" when your change
  just made X possible.
- New or changed MCP tool: check llms.txt for whether it lists MCP tools and
  needs updating.
- Before opening the PR, self-check: does anything in README.md,
  MANAGEMENT.md, or llms.txt now describe old behavior as current, or fail
  to mention what you just added? If yes, fix it in the same PR.

Issue #227's automated CI check (`scripts/check-help-docs.mjs`, run in CI —
see `.github/workflows/ci.yml`) now enforces this for README.md's "CLI
reference" section, which must be byte-identical to `cipher-brain --help`'s
current output (`node scripts/check-help-docs.mjs --write` regenerates it).
That only covers the literal `--help` text, though — MANAGEMENT.md, llms.txt,
and everything else the bullets above mention (Threat model claims, prose
Usage sections, MCP tool listings) is still manual discipline; keep applying
this section's checklist to those.

## Everything else

For CLI usage, architecture, and the quality bar PRs must meet, see
[`README.md`](README.md), [`MANAGEMENT.md`](MANAGEMENT.md), and
[`llms.txt`](llms.txt) (a quick orientation aimed at AI agents). The PR
checklist in [`.github/pull_request_template.md`](.github/pull_request_template.md)
still applies unchanged.
