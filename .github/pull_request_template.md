<!--
Thanks for sending a PR! Quick checklist below.
-->

## Summary

<!-- 1–3 bullets: what changed and why. Link relevant issues (#NN). -->

## Quality bar (must be ✅ before requesting review)

- [ ] `npm run verify` green (build + typecheck + full selftest suite +
      CLI smoke + MCP smoke — see `package.json` `scripts.verify`)
- [ ] No new `VERDICT: FAIL` / unexpected `VERDICT: PARTIAL` introduced in
      `verify`/`restore` output (see README's [Threat model](README.md#threat-model--the-key-is-only-mine)
      for what `PASS`/`FAIL`/`PARTIAL` mean)

## Evidence — paste what the change actually printed

<!--
Not a gate, and not a screenshot requirement: just the terminal output of the
thing you changed, doing the thing you changed it to do, trimmed to the lines
that make the point. A reviewer can check that in seconds, and it costs you
nothing you were not already running to convince yourself.

REDACT FIRST. This tool's output routinely carries things that must not land in
a public PR: recipient/identity values and key file paths, wallet addresses,
Arweave locators and transaction IDs, `--pg` connection strings, real paths off
your own machine. Replace them with placeholders, or reproduce the run against
a scratch fixture instead of your own backup. Never paste a private key, a
passphrase, a recovery kit, or anything out of a `config.json`.

A comment-only or docs-only change still qualifies when there is something to
run — call the function the comment describes and paste the value it returned,
or show the rendered result. When there is genuinely nothing executable, or the
behaviour needs a paid backend or another machine, say so in a line and paste
the closest thing you could run instead.
-->

## Architecture impact

<!-- Tick whichever applies; leave others unchecked. -->

- [ ] Touches key handling (identity/recipient generation, storage, permissions)
- [ ] Touches a storage backend (`file`, `arweave`/`turbo`)
- [ ] Touches `src/mcp.ts` (MCP server contract / tool surface)
- [ ] Changes the CLI's public flags/subcommands
- [ ] Changes signal handling (SIGINT/SIGTERM/SIGHUP) or atomic write paths
- [ ] Pure docs / templates / CI

## Multi-model review

Security- or crypto-adjacent changes should run through a multi-model
review before merge — paste the severity-tagged findings + a short note on
each fix in this section, or link to the review session.

- [ ] No multi-model review needed (docs / CI / trivial)
- [ ] Findings addressed: <!-- summarise -->
- [ ] Review pending — DRAFT status until done

## Regression / behaviour

- [ ] No user-facing CLI behaviour changes (regression-zero)
- [ ] User-facing CLI behaviour intentionally changed — described below

<!-- if behaviour changed, list what was old → new for each affected flag / command -->

## Closes

<!-- Closes #NN, #MM -->
