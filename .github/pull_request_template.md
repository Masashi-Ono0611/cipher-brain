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
thing you changed, doing the thing you changed it to do. A reviewer can check
that in seconds, and it costs you nothing you were not already running to
convince yourself.

A comment-only or docs-only fix still qualifies — call the function the comment
describes and paste the value it returned. If the behaviour genuinely cannot be
executed here (a paid backend, another machine), say so and paste the closest
thing you could run instead.
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
