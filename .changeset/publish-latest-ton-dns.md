---
'cypher-brain': minor
---

Add `publish-latest`, an opt-in command that points a `.ton` domain's DNS `storage`
record at the ton backend's latest bag id — so a fresh machine can discover the newest
encrypted-backup bag from a human-memorable name instead of needing
`--from-locator-file`'s bytes. It is never run automatically (not wired into
`schedule install`): reading `--from-locator-file`, it requires the recorded backend to
be `ton` and the locator to match `ton:v1:<64-hex-bag-id>`, then spins an ephemeral local
TON Storage daemon to PROBE that the bag is actually discoverable and served on the P2P
network right now (metadata found via DHT and at least one byte served) — a stale or
never-seeded bag is refused with "DNS must never point at an unavailable bag" before
anything is printed. It then resolves the domain's NFT item address via tonapi
(`CYPHER_BRAIN_TON_TONAPI_URL`, default `https://tonapi.io`), builds the on-chain
`change_dns_record` message body (a `dns_storage_address` record over the bag id, ported
from `ton-mesh-harness`'s `src/dns.ts`/`src/deeplink.ts`), and prints the domain, the
resolved NFT address, the bag id, and — gated behind `--yes`/`CYPHER_BRAIN_YES`, since
acting on it spends ~0.02 TON gas — a Tonkeeper transfer deeplink. cypher-brain itself
never signs anything; the operator opens the link and approves the transaction in their
own wallet. `--wait <seconds>` polls tonapi's DNS resolution afterward and reports
CONFIRMED or NOT-YET. `@ton/ton` (Cell/DNS-record building) is a lazily-imported
optionalDependency, same pattern as `@ardrive/turbo-sdk`.
