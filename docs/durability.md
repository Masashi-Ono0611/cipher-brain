# Durability — will the ciphertext still be there in a year? (prep for #7)

`push`/`pull` prove a snapshot round-trips *today*. **Durability** is a different
question: will the bytes survive months of neglect, a dead disk, or a provider that
stops caring? This doc lays out the path to a real guarantee so the choice (which
costs money) is an informed one. No funds are spent here.

## Arweave: durability is bought once, by design

**Arweave the network** has a simple economic model: **pay once, stored ~forever.**
An upload funds an endowment that pays for perpetual
replication across the network — no ongoing proofs to run, no single seeder to babysit,
no GC. For a "impossible to delete" brain backup this is a categorically stronger
durability story: it is the archive that survives neglect.

cypher-brain reaches that network two ways — pick by **size**:

- **`--backend turbo`** — the path for real, brain-sized snapshots. It *streams* the
  ciphertext and uploads an ANS-104 *bundled* data item via a bundler (ArDrive Turbo),
  payable with **ETH/USDC** (`<100 KB` free). This is the "push every snapshot for
  permanence" path. Use it.
- **`--backend arweave`** — the raw single-tx backend. It posts the whole artifact
  inline in **one L1 transaction**, which gateways cap at ~12 MiB, so it suits small
  artifacts only. To avoid a brain-sized upload buffering the lot and then failing with
  a bare `HTTP 400`, `put()` now refuses anything over ~10 MiB up front and tells you to
  switch to `turbo` (override with `CYPHER_BRAIN_AR_L1_MAX` for a deliberate large L1 post).

Both produce an Arweave tx / data-item id. You pay up front (per-byte, one time), and
retrieval is via a gateway. Reads need no wallet AND no npm dependency — the gateway
pull path is pure `fetch`, so a fresh machine restores with just the id (the `arweave`
package is needed only for the raw `arweave` push, or for the rare L1 chunk fallback —
see #9). You must still *retain* that id off-box, though: it is not self-discoverable,
so back up the latest locator (`push --save-locator`, MANAGEMENT.md "Key recovery #3")
next to your identity. A self-resolving stable name (ArNS) is future work.

## TON Storage (`--backend ton`): availability while seeded, not permanence

TON Storage is the categorically different second on-chain lane: a bag (torrent) is
**content-addressed** — the bag id in the `ton:v1:<bag-id>` locator is the merkle
root the P2P download path verifies every piece against — but it is retrievable
**only while at least one reachable seeder retains it**. There is no endowment and
no network-level replication promise. Stop your seeder and, once caches drain, the
bag is gone. In the 3-2-1 framing: `turbo` is the archive that survives neglect;
`ton` is a **sovereign, self-hosted replica** with cryptographic addressing —
useful redundancy, never a substitute for the Arweave lane.

Honest operational notes, so nothing here silently over-promises:

- **One seeder box is one failure domain.** The default deployment (one always-on
  machine you run) is closer to "your own server with content addressing" than to
  decentralized durability. A second, independent seeder is what upgrades that
  story — until then, treat `ton` as replica #2, with `turbo` as the permanence.
- **Retrieval proof matters.** A pull that fell back to the seeder copy proved only
  that your box still had the file — the backend says so loudly when that happens,
  and `CYPHER_BRAIN_TON_NO_FALLBACK=1` turns a pull into a strict P2P availability
  check (success then *proves* a reachable seeder served the bag over the real
  network).
- **Measured, not just designed** (2026-08-22, `npm run dogfood:ton` against a real
  DigitalOcean seeder, ~20 KB ciphertext): push (scp + seeder-side bag creation)
  34.0 s; idempotent re-push 7.0 s; **strict P2P pull 6.9 s** — with
  `CYPHER_BRAIN_TON_NO_FALLBACK=1`, so the bytes provably came over the real TON
  Storage P2P network, sha256-matched, then verified and restored; a normal
  (non-strict) pull was also served via P2P. Latency will differ for brain-sized
  bags (piece-hashing dominates the push); what this run pins down is that the
  whole path — DHT discovery included — actually works today. Paying third-party storage
  providers for retention exists as a protocol (per-day storage contracts with
  on-chain proofs) but was measured dormant in practice (providers listed, none
  accepting contracts) as of mid-2026 — which is exactly why this backend seeds
  from your OWN box instead of depending on that market.

## Recommended model: Arweave is the mainline

The default — and the only path this project recommends — is **Arweave via
`--backend turbo`**: push every snapshot once, and permanence is the network's job
rather than a service you keep alive. Recovery matches: the pull is a plain gateway
fetch, so a fresh machine needs only the locator and the identity. Storage sees only
ciphertext.

## What actually closing #7 needs (a funding decision)

Proving durability — not just documenting it — needs real money: fund a wallet with AR
(or pay via a fiat/crypto on-ramp like a bundler), upload a real snapshot, confirm it
resolves after the tx is mined to the permanent network. (The round-trip is already
CI-proven against arlocal; this swaps in mainnet.)

Until that runs, durability is **designed and documented, not yet demonstrated** —
exactly the honest status #7 was filed to track.
