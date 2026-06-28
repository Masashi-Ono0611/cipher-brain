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

The `arweave` backend (already shipped, #9) has the opposite economic model:
**pay once, stored ~forever.** An upload funds an endowment that pays for perpetual
replication across the network — no ongoing proofs to run, no single seeder to babysit,
no GC. For a "impossible to delete" brain backup this is a categorically stronger
durability story than rented TON storage: it is the cold archive that survives neglect.

The trade: you pay AR up front (per-byte, one time), and retrieval is via a gateway
(slower, not `.ton`-native). Reads need no wallet AND no npm dependency — the gateway
pull path is pure `fetch`, so a fresh machine restores with just the tx id (the
`arweave` package is needed only to push, or for the rare L1 chunk fallback — see #9).
You must still *retain* that tx id off-box, though: it is not self-discoverable, so
back up the latest locator (`push --save-locator`, MANAGEMENT.md "Key recovery #3")
next to your identity. A self-resolving stable name (`.ton` DNS / ArNS) is future work.

## Recommended model: redundancy across backends

These two backends are complements, not competitors:

| | TON Storage (self-hosted seeder) | Arweave |
|---|---|---|
| Durability | rented / operational (you keep it alive) | **pay-once, perpetual** |
| Address | `.ton` DNS → BagID (human-routable) | tx id (opaque) |
| Speed / native | fast, TON-native | gateway fetch |
| Best role | **hot copy** | **durable cold archive** |

For a personal brain that must not vanish: **push every snapshot to Arweave for
permanence, and keep a TON copy for `.ton`-addressable hot access.** The cipher layer is
backend-agnostic (#9), so this is just two `push` calls. Storage sees only ciphertext
either way. Cross-backend = no single point of durability failure.

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
exactly the honest status #7 was filed to track. The recommendation (Arweave for
permanence + TON for hot access) does not depend on which TON-vs-Arweave "winner" you
pick for the hot copy; the permanence anchor is Arweave either way.
