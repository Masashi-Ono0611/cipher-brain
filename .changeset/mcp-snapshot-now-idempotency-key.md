---
'cipher-brain': minor
---

The MCP `snapshot_now` tool (the only tool that can spend money) accepts an optional
`idempotency_key` (#220, the Stripe idempotency-key pattern): a repeat call with the SAME
key and the same `dirs`/`pg`/`recipients`/`out`/`backend`/`scan_secrets` returns the FIRST
call's result — `idempotent_replay: true`, no new snapshot, no new spend — instead of
re-executing, so an AI agent's own retry logic (a network blip after an arweave/turbo
upload already succeeded, say) cannot spend twice for what it believes is one call. The
same key reused for a call that differs in any of those fields is refused
(`ERR_IDEMPOTENCY_KEY_REUSED`) rather than silently answered with an unrelated result.

Results are cached in `<CIPHER_BRAIN_HOME>/idempotency-log.jsonl` (the same
CIPHER_BRAIN_HOME-scoped bookkeeping style `push --skip-unchanged`'s save-locator file
already uses) and expire after `CIPHER_BRAIN_IDEMPOTENCY_TTL_SECONDS` (default 24h).
