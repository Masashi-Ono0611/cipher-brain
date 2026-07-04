# Durability — will the ciphertext still be there in a year? (prep for #7)

`push`/`pull` prove a snapshot round-trips *today*. **Durability** is a different
question: will the bytes survive months of neglect, a dead disk, or a provider that
stops caring? On testnet the honest answer is **no guarantee** — a bag lives only as
long as some node keeps seeding it, and nothing is paying anyone to. This doc lays out
the paths to a real guarantee so the choice (which costs money) is an informed one. No
funds are spent here.

> Three things people conflate. **Reachability** (#6) = can a peer connect to the
> seeder. **Availability** = is *someone* serving the bag right now. **Durability** (this
> doc, #7) = is it *guaranteed* to still be served later. A public IP fixes reachability
> but not durability — a reachable seeder you forget to keep running still loses the bag.

## TON: durability is rented, with proofs

A TON bag is durable only while a node seeds it. Two ways to make that last:

1. **Self-host an always-on seeder** (the same public-IP host as #6). Cheapest, fully
   under your control — but it is *operational* durability, not a cryptoeconomic
   guarantee: one host, your uptime, your disk. Good as the hot copy, not as the only copy.
2. **A storage-provider contract** (mainnet). A provider commits to store the bag and
   submit periodic Merkle **proofs of storage**, paid in TON; if it stops proving, it
   stops getting paid. The testnet trial proved this side works end-to-end (accept
   contract → download → submit proof → earn). Mechanics to reuse:
   - `storage-daemon-cli new-contract-message <bag> <file> --provider <addr>` (or
     `--rate <r> --max-span <s>`) builds the offer; the kit's `src/provider.ts` (op
     `new_storage_contract`/`0x107c49ef`) is the same flow.
   - Proof cadence ≈ **max_span / 2**; the cost is `rate` × size × time plus proof gas.
   - **Caveat (measured):** the mainnet provider *market* is thin — even foundation.ton
     self-hosts, and a 2026-06 re-probe found no provider taking contracts. So in
     practice this means **running your own mainnet provider** and contracting to it,
     not buying from a market. That is durability-by-your-own-redundancy, with proofs.

Net: TON gives you a fast, `.ton`-addressable hot copy you control, but the durability
guarantee is something you must actively pay for or operate.

## Arweave: durability is bought once, by design

**Arweave the network** has the opposite economic model to rented TON storage:
**pay once, stored ~forever.** An upload funds an endowment that pays for perpetual
replication across the network — no ongoing proofs to run, no single seeder to babysit,
no GC. For a "impossible to delete" brain backup this is a categorically stronger
durability story: it is the archive that survives neglect.

cipher-brain reaches that network two ways — pick by **size**:

- **`--backend turbo`** — the path for real, brain-sized snapshots. It *streams* the
  ciphertext and uploads an ANS-104 *bundled* data item via a bundler (ArDrive Turbo),
  payable with **ETH/USDC** (`<100 KB` free). This is the "push every snapshot for
  permanence" path. Use it.
- **`--backend arweave`** — the raw single-tx backend. It posts the whole artifact
  inline in **one L1 transaction**, which gateways cap at ~12 MiB, so it suits small
  artifacts only. To avoid a brain-sized upload buffering the lot and then failing with
  a bare `HTTP 400`, `put()` now refuses anything over ~10 MiB up front and tells you to
  switch to `turbo` (override with `CIPHER_BRAIN_AR_L1_MAX` for a deliberate large L1 post).

Both produce an Arweave tx / data-item id. The trade vs TON: you pay up front (per-byte,
one time), and retrieval is via a gateway (slower, not `.ton`-native). Reads need no
wallet AND no npm dependency — the gateway pull path is pure `fetch`, so a fresh machine
restores with just the id (the `arweave` package is needed only for the raw `arweave`
push, or for the rare L1 chunk fallback — see #9). You must still *retain* that id
off-box, though: it is not self-discoverable, so back up the latest locator
(`push --save-locator`, MANAGEMENT.md "Key recovery #3") next to your identity. A
self-resolving stable name (`.ton` DNS / ArNS) is future work.

## Recommended model: Arweave is the mainline

The default — and the only path this project recommends — is **Arweave via
`--backend turbo`**: push every snapshot once, and permanence is the network's job
rather than a service you keep alive. Recovery matches: the pull is a plain gateway
fetch, so a fresh machine needs only the locator and the identity. Storage sees only
ciphertext.

| | Arweave (`turbo`) | TON Storage (self-hosted seeder) |
|---|---|---|
| Durability | **pay-once, perpetual** | rented / operational (you keep it alive) |
| Address | tx id (opaque) | `.ton` DNS → BagID (human-routable) |
| Speed / native | gateway fetch | fast, TON-native |
| Role | **the mainline** | optional hot copy (advanced) |

A TON hot copy is an **advanced recipe, not part of the default**: it only makes
sense if you *already* operate an always-on seeder (and, for a real guarantee, your
own mainnet provider — the market is empty, as measured above). For such an operator
the cipher layer being backend-agnostic (#9) makes the hot copy one extra
`push --backend ton`, and a cross-backend copy removes any single point of durability
failure. If you don't already run that infrastructure, don't start for this — the
operational cost buys you speed and a `.ton` address, not durability.

## What actually closing #7 needs (a funding decision)

Proving durability — not just documenting it — needs real money on one of these paths,
which is the user's call:

- **Arweave**: fund a wallet with AR (or pay via a fiat/crypto on-ramp like a bundler),
  upload a real snapshot, confirm it resolves after the tx is mined to the permanent
  network. (The round-trip is already CI-proven against arlocal; this swaps in mainnet.)
- **TON**: run a mainnet provider, create a contract for a real bag, and confirm proofs
  land over time (cadence ≈ max_span/2) — i.e. observe the bag survive past one proof
  interval with the provider getting paid.

Until one of those runs, durability is **designed and documented, not yet demonstrated** —
exactly the honest status #7 was filed to track. The mainline keeps the funding
decision simple: the permanence anchor is Arweave, and the TON path is only worth
funding if you are running the provider anyway.
