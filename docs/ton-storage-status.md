# TON Storage — measured status log

What we have actually MEASURED about TON Storage, organized by network and by
who runs the storage. Every claim here has a date; nothing is folklore. Update
this file when a new measurement changes a verdict — do not append a diary,
rewrite the verdict it invalidates (repo style: later decisions get merged in,
not stapled on).

The product stance this log justifies is unchanged (docs/durability.md):
Arweave/`turbo` is the permanence mainline; `ton` is a sovereign self-hosted
replica; third-party TON providers are an experiment lane, not a dependency.

## The four lanes

| lane | what it is | verdict (date) |
|---|---|---|
| **Mainnet, our own seeder** | The `ton` backend's normal path: an operator box (currently one DigitalOcean droplet) seeds our bags | **WORKS, in production** (2026-08-22) |
| **Mainnet, third-party providers** | Paying listed storage providers per-day for retention | **GRAVEYARD, one faint candidate** (2026-08-23 census) |
| **Testnet, third-party providers** | Same, on testnet | **DEAD DAEMONS, live contracts** (2026-08-22 experiment) |
| **Testnet, our own provider** | Our tonutils-storage-provider on the droplet, to prove the full offer→accept→proof loop against a provider we KNOW is alive | **STANDING, blocked on a chicken-egg** (2026-08-23) |

## Mainnet — our own seeder (production)

- 2026-08-22: the real 481 MB encrypted brain snapshot round-trips: `push
  --backend ton` (upload + seeder-side piece hashing inside the create budget),
  strict P2P pull back in **95 s (~5 MB/s)** with the sha256 pin matching
  (`CYPHER_BRAIN_TON_NO_FALLBACK=1`, so the P2P network provably served it).
  That bag is the live replica; the domain's TON DNS `storage` record points at
  it (published + resolver-confirmed the same day).
- Small-bag latency (20 KB dogfood, same day): push ~34 s, strict P2P pull
  7–14 s across runs, DHT discovery included.
- Known limit, unchanged: one seeder box is one failure domain. A second
  independent seeder is the real durability upgrade (open follow-up).

## Mainnet — third-party providers

- 2026-05-10 (ton-mesh-harness era): 7-round soak. Offers deployed contracts,
  **zero `accept_storage_contract` ever arrived**; funds reclaimed via
  `op::close_contract` (0.022 TON lost to fees per round). Verdict then:
  provider economy dormant.
- 2026-08-23 census (all 115 listed providers, last on-chain activity via
  tonapi, read-only): **0 active within 7 days, 1 within 30 days, 94 dead for
  over a year.** The listing is overwhelmingly a graveyard of configurations
  whose operators left years ago.
- The one faint candidate: `0:f0a21e2e5630caee3034879b789dd5fd8fd060e6bf4b9f5ef94fc0b49238c633`
  — last activity 8.8 d before the census, and its recent history shows an
  incoming ~1.5 TON offer followed by several externally-signed messages,
  which is the signature of a daemon actually reacting. Rate is in the
  expensive tier (1,000,000 nanoTON/MB/day ≈ 365 TON/GB/yr). A single
  bounded mainnet offer at it is the only measurement left that could flip
  this lane's verdict; everything cheaper on the list has shown no on-chain
  activity for months to years (which is strong — but activity-based, not
  proof the daemons are gone).

## Testnet — third-party providers

- 2026-08-22 live experiment (bag `a2b26f1c…`, 8 KB, seeded from the droplet's
  testnet C++ storage-daemon):
  - 173 providers listed; 2 passed the offer filters (size/span/accepting).
  - `new-contract-message` over ADNL (tried against 3 providers picked from
    the raw list before filtering): **2 of the 3 answered the rate query** —
    some daemons DO respond at the P2P layer.
  - Signed offer (0.3 testnet TON) → the provider's main contract
    **mechanically deployed** the per-bag storage contract (its first activity
    since January 2023) — contract code working ≠ operator alive.
  - **No accept within 30+ min.** Meanwhile an independent fresh client
    (NAT-ed laptop, new identity) fetched the same bag via DHT in **6 s** —
    so generic unreachability of the bag is excluded (a provider-SPECIFIC
    network/configuration failure cannot be fully ruled out from outside);
    the behavior is most consistent with a dead or ignoring storage daemon.
    Funds recovered via `close` — measured round-trip on 2026-08-23: sent
    0.35 testnet TON (offer 0.3 + close gas 0.05), refunded 0.328, net fee
    loss 0.022 TON, matching the 2026-05 mainnet figure.
- Net: same shape as mainnet 2026-05 — the chain-side machinery is alive, the
  operator-side daemons are not.

## Testnet — our own provider (full-loop proof, in progress)

- Purpose: separate PROTOCOL from MARKET. If our own provider accepts and
  proves storage, the protocol works end-to-end and the third-party failures
  are purely a dead-market problem.
- Standing (2026-08-23): tonutils-storage-provider v0.4.3 + its own testnet
  tonutils-storage run as transient units on the droplet (isolated under
  `/opt/tsp/testnet-*`, mainnet services untouched); provider wallet funded
  with 2 testnet TON.
- Two findings from source (xssnick/tonutils-storage-provider):
  1. The Go provider **never self-deploys a contract** — deployment is always
     client-initiated (offer to the provider address); the daemon answers ADNL
     rate queries and reacts to offers.
  2. Chicken-egg blocking the offer: the C++ `storage-daemon-cli --provider`
     path calls a get-method only C++-style provider CONTRACTS have (a plain
     wallet fails with exit code -13, incompatibility confirmed by source and
     by measurement), and our own experiment script's `--provider` flag
     currently requires the address to appear in tonapi's provider index,
     which a never-deployed provider is not in. Fix in flight: allow an
     explicit `--provider` together with explicit `--provider-rate`/
     `--provider-span` to bypass the index (values are known from our own
     provider config).

## Cost reality check (so nobody misreads "cheap")

Comparing self-hosted TON seeding to Arweave is category confusion — it is
"own hard drive" vs "paid permanence". The like-for-like comparison is
Arweave (~$28/GB one-time, measured via turbo) vs provider contracts
(listed floor ~0.73 TON/GB/yr): as of 2026-08-23 and assuming ~$3/TON,
breakeven at the floor rate is over a decade, mid-tier listed rates 2–9 years — and the market behind those listed rates is, per
above, mostly not real. Self-hosted TON is cheap because you are the storage;
it buys availability, not permanence.

## Operational inventory (what exists where, as of 2026-08-23)

- Droplet (mainnet, production): `tonutils-storage.service` +
  `tonutils-storage-provider.service` (long-standing), the cypher-brain bag
  layout under `~/cypher-brain-ton/`, healthcheck pinned to the live brain bag.
- Droplet (testnet, experiment, transient systemd units — disposable):
  `tsp-testnet-storage` (C++ seeder, udp 17777), `tsp-testnet-provider-storage`
  (Go storage, udp 17556), `tsp-testnet-provider` (provider daemon, udp 18556),
  all under `/opt/tsp/testnet-*`. Stop with `systemctl stop <unit>`; nothing
  survives a reboot by design.
- Experiment wallet (testnet, throwaway): provider key lives in
  `/opt/tsp/testnet-provider/config.json` on the droplet only.
