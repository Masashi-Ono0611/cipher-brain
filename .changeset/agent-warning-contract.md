---
'cipher-brain': minor
---

Warnings now survive being run by an agent (#347). A real monthly push driven
end-to-end by an AI agent lost every crafted line to a background log — including
"snapshot encrypted to a SINGLE recipient key — … UNRECOVERABLE", a warning that exists
precisely to reach a human. Two structural holes made that silent: warnings written
straight to `process.stderr.write` bypassed the MCP server's per-call capture entirely,
and nothing marked which stderr lines were load-bearing versus decoration. Every
⚠-class runtime warning now goes through one chokepoint (`warn()`): it prints
immediately as before, and is recorded — so the CLI ends any run that produced warnings
with a `run summary` block explicitly addressed to relaying agents ("show these
verbatim"), and MCP tool results carry a dedicated `warnings` array beside `log`.
llms.txt and AGENTS.md document the contract: stderr is load-bearing; parse stdout,
relay the summary.
