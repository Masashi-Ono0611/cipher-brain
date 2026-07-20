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

Both produce an Arweave tx / data-item id. You pay up front (per-byte, one time), and
retrieval is via a gateway. Reads need no wallet AND no npm dependency — the gateway
pull path is pure `fetch`, so a fresh machine restores with just the id (the `arweave`
package is needed only for the raw `arweave` push, or for the rare L1 chunk fallback —
see #9). You must still *retain* that id off-box, though: it is not self-discoverable,
so back up the latest locator (`push --save-locator`, MANAGEMENT.md "Key recovery #3")
next to your identity. A self-resolving stable name (ArNS) is future work.

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
