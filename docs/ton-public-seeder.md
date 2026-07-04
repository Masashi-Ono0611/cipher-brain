# Making the TON seeder publicly reachable (closes the #2 PARTIAL → #6)

> **Status: iceboxed (#6).** The project is Arweave-first (#60): `--backend turbo` is
> the recommended mainline and the `ton` backend is experimental — a 2026-06 re-probe
> found the TON mainnet storage-provider market empty
> ([`durability.md`](durability.md)), so this path only makes sense for operators
> running their own seeder. The doc below remains the runbook if it is reactivated.

The `ton` backend round-trip is **PARTIAL** today for one reason: the seeder runs on a
home NAT. It can hold a bag (`active_upload: true`) but it shows **`Peers: 0`** — it
can't advertise an address that other nodes can reach, so the testnet DHT never lets a
downloader rendezvous with it. A second daemon on the *same LAN* still couldn't peer.

The fix is not code — it's a **host with a reachable public IP**. This runbook stands one
up (non-gcloud, per the project's gcloud-avoidance), then re-runs the cross-node proof so
it reports **PASS** instead of PARTIAL. Procuring the host is a human decision; everything
here is ready to run once it exists.

## Why a public IP is the whole fix

A TON storage node announces its ADNL address to the DHT so peers can find it. Behind NAT
the only address it can announce is a private/unroutable one (or none), so `get-peers`
stays empty on both sides. Give the seeder a **static public IPv4 + an open UDP port** and
start it with `-I <PUBLIC_IP>:<UDP_PORT>`; now its DHT announcement points at a reachable
address and downloaders connect. Nothing about the cipher-brain CLI changes — `push`/`pull`
already work; they just need a seeder peers can reach.

## Host requirements

| Requirement | Why |
|---|---|
| **Static public IPv4** | the seeder must announce a routable ADNL address |
| **One open inbound UDP port** (e.g. 13333) | ADNL/DHT traffic is UDP; this is the reachability |
| **Linux x86_64** | the official `storage-daemon` prebuilt binary targets it (no build needed) |
| **Non-gcloud** | per the Cipher Brain decision (don't depend on a host that can quietly delete you) |
| **Crypto-payable, low-KYC** *(preferred)* | matches the censorship-resistance goal |
| ~1 vCPU / 1–2 GB RAM / small disk | a seeder is light; disk scales with what you host |

> The **control port** (`-p`, default 15555) must stay bound to **localhost only** — never
> expose it. Drive the CLI over an SSH tunnel. Only the **UDP ADNL port** is public.

## Setup (on the public host)

```sh
# 1. fetch the official storage-daemon (same binaries the trial used) + a global config
#    (testnet-global.config.json for testnet, or the mainnet config for real use)
mkdir -p ~/ton-seeder/{bin,work} && cd ~/ton-seeder

# 2. open the UDP port in the host firewall (provider panel and/or ufw)
sudo ufw allow 13333/udp

# 3. start the seeder announcing the PUBLIC ip; control stays on localhost
PUBLIC_IP=<your.public.ip>
nohup ./bin/storage-daemon -v 3 -C work/global.config.json \
  -I "$PUBLIC_IP:13333" -p 15555 -D work/db -P \
  -l work/daemon.log >/dev/null 2>&1 &

# 4. confirm it bound the public UDP addr and the control port (localhost)
grep -i "udp server" work/daemon.log
```

Provision the CLI keys (`work/db/cli-keys/` are auto-created on first start, as in the
trial), then **push a ciphertext** to this seeder (snapshot+encrypt elsewhere, copy the
`*.age` here or push from a tunneled CLI):

```sh
CB=path/to/cipher-brain.mjs
export CIPHER_BRAIN_TON_CLI=~/ton-seeder/bin/storage-daemon-cli
export CIPHER_BRAIN_TON_API=127.0.0.1:15555
export CIPHER_BRAIN_TON_CLIENT=~/ton-seeder/work/db/cli-keys/client
export CIPHER_BRAIN_TON_SERVER=~/ton-seeder/work/db/cli-keys/server.pub
BAG=$(node "$CB" push --in brain.age --backend ton)   # note the BagID + this host's PUBLIC_IP
```

## Validate the cross-node transfer (from a *different* network)

On any other machine (e.g. the Mac mini), run the leech-side proof — it starts a throwaway
downloader daemon, fetches the bag **by BagID over the public internet**, and asserts
`get-peers` shows the seeder (a transfer a local read can't fake), then decrypts:

```sh
CB_CONFIG=~/path/global.config.json \
CB_BAG=<BagID from above> \
CB_SEEDER_IP=<PUBLIC_IP of the seeder> \
CB_LAN_IP=<this downloader host's own ip> \
CB_ORIG_SHA=$(shasum -a 256 brain.age | cut -d' ' -f1) \
CIPHER_BRAIN_HOME=~/.cipher-brain \
  bash scripts/ton-public-roundtrip.sh
```

PASS = the downloader peered with the public seeder, the bytes match, and they decrypt.
That is the result #6 is blocked on; capture it in #6 and flip the README's `ton` row from
PARTIAL to ✅. If `get-peers` is still empty, the UDP port isn't actually open end-to-end
(provider firewall vs host firewall) — fix that first.

## Picking a non-gcloud host

Selection criteria, in priority order: **public IPv4 included**, **inbound UDP allowed**
(some budget hosts block non-TCP or non-web), **crypto payment / low KYC**, jurisdiction,
price. Confirm the UDP + public-IP points with the provider *before* paying — they're the
two that actually decide whether #6 passes.

| Provider | Jurisdiction | Pays with | Notes (verify current specs before buying) |
|---|---|---|---|
| **Njalla** | Sweden | BTC, XMR, ZEC, LTC, card | Privacy-first (Peter Sunde); VPS + domains; single location |
| **1984 Hosting** | Iceland | BTC, XMR, card | Strong jurisdictional protections; long-running |
| **FlokiNET** | Iceland / NL / Finland / Romania | BTC, LTC, card | Multiple EU locations; anonymous-hosting focus |
| **Incognet / MyNymBox / OrangeWebsite** | EU (privacy-conscious) | BTC, often XMR | Low/no-KYC; confirm UDP + dedicated IPv4 per plan |

> Specs and prices move — treat this as a shortlist, not quotes. The two must-confirm
> items are **a dedicated public IPv4** and **inbound UDP allowed** for the ADNL port;
> everything else (a tiny seeder) is undemanding. A crypto-payable host keeps the whole
> path aligned with "impossible to quietly take down."

Sources: [KYCnot.me — Njalla](https://kycnot.me/service/njalla) ·
[1VPS — crypto/no-KYC providers](https://1vps.com/crypto-payments-no-kyc/) ·
[0xnull — anonymous VPS 2026](https://0xnull.io/blog/anonymous-vps-hosting-crypto-guide)
