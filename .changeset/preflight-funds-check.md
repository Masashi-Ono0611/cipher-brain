---
'cipher-brain': minor
---

A `turbo` push now runs a funds check BEFORE signing: when the estimated cost exceeds
even the reachable credit (the signer's own balance plus the live approvals
`CIPHER_BRAIN_AR_PAID_BY` selects), the spend is headed for a payment-service refusal
that previously arrived only after minutes spent signing a multi-hundred-MB snapshot,
with no explanation. What happens depends on who is there to act, because a balance read
has no freshness guarantee and a false positive must land on someone who can absorb it:
on a TTY the push aborts with the funding steps spelled out in place — the exact
shortfall, both funding paths (fund the signer directly, or buy on another wallet +
Share Credits + `CIPHER_BRAIN_AR_PAID_BY`), and the `wallet address` / `wallet balance`
commands that verify each step — after confirming the shortfall on a second balance read,
so a top-up landing that same moment is not blocked. Without a TTY (a nightly runner, an
MCP host) the same facts are written as a warning and the upload proceeds: a balance
read must never be what blocks an unattended backup, and the payment service stays the
authority. Skipped entirely when the balance cannot be read at all;
`CIPHER_BRAIN_SKIP_FUNDS_CHECK=1` (strictly '1' — any other value leaves the check on)
bypasses it for one run.
