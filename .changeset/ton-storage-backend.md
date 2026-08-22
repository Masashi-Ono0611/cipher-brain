---
'cypher-brain': minor
---

Add a `ton` storage backend: TON Storage seeded from your own always-on box.

`push --backend ton` transfers the ciphertext to an operator-run seeder
(`CYPHER_BRAIN_TON_SSH_HOST`, a machine running tonutils-storage) over ssh/scp and
creates the bag there — on the machine that must retain and seed it. The locator is
`ton:v1:<64-hex-bag-id>` (the bag's merkle root); re-pushing unchanged ciphertext is
idempotent via a seeder-side sha256 inventory. `pull`'s primary path is a
credential-less P2P download by bag id through an ephemeral local tonutils-storage
(`--daemon` mode, throwaway db, killed after the fetch), preserving the
"identity + locator is all a fresh machine needs" recovery promise; a direct copy
off the seeder is a loud, explicit fallback, and `CYPHER_BRAIN_TON_NO_FALLBACK=1`
turns a pull into a strict P2P availability proof. Free per upload — and honestly
documented as NOT permanent storage (docs/durability.md): a bag is retrievable only
while at least one reachable seeder retains it, so `ton` is a sovereign redundancy
lane next to the Arweave/turbo permanence mainline, not a replacement.

CI coverage: `selftest:ton` exercises the real backend code against a mock
tonutils-storage daemon and PATH-shimmed ssh/scp — round-trip, idempotent re-push,
and fired positive controls (malformed-locator rejection, wrong sha256 pin, the
loud fallback, the no-fallback refusal). New settings:
`CYPHER_BRAIN_TON_{SSH_HOST,SSH_KEY,REMOTE_DIR,REMOTE_API,BIN,HTTP_TIMEOUT,NO_FALLBACK,NETWORK_CONFIG}`.
Ported daemon-management/API-client knowledge is credited to the sibling
ton-mesh-harness project. `ton` stays CLI-only (not an MCP tool backend), same
posture as rclone.
