---
'cipher-brain': minor
---

The MCP `verify_restore` and `restore_now` tools stop discarding everything their pull said.

Both fetched their artifact with `await captureCall(() => pull(pullOpts))` and never bound
the result, so the retry lines behind `wait`, the `sha256 OK: <hash>` confirmation, the
transfer progress added in #283, and the warning explaining why an authenticity signature
could not be fetched were all collected into a buffer and dropped. `snapshot_now` has always
surfaced its push output; these two were the odd ones out. The fetch output is now returned
as `pulled.log`.

That last dropped line was a correctness bug, not a missing convenience. `pull()`'s sidecar
fetch is best-effort by design (#214: a signature it cannot retrieve must warn and continue,
never fail the pull), and `verify()` only ever sees the local directory — so a `.minisig`
that was recorded but could not be fetched came back as
`[SKIP] … unsigned (legacy) artifact, authenticity not checked` and a `PASS` verdict. That
sentence is true of a pre-#214 backup and false here, and deleting a sidecar rather than
forging one produces exactly it.

Both tools now return a `signature` object when pull reported that it could not fetch the
sidecar — carrying pull's own reason, saying plainly that authenticity was not checked, and
stating that the "unsigned (legacy)" line in `checks` describes a different situation.

It is keyed on that warning rather than on "a locator was recorded and the file is missing",
which review showed infers too much in both directions: a recorded locator proves a sidecar
object was pushed, not that it holds a valid signature; and on arweave/turbo a perfectly
intact sidecar can never be fetched (#318), so the missing-file inference would have cried
downgrade on every signed arweave pull.

`pulled.log` puts stderr before stdout — pull's narrative before the locator it prints last —
and redacts URL userinfo, since `CIPHER_BRAIN_AR_GATEWAYS` may legitimately carry a
credential that pull prints when a gateway fails. That was acceptable on the operator's own
stderr and is not once it is returned to an MCP client.
