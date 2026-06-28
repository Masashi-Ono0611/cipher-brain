# cipher-brain

Encrypt a gbrain snapshot so that **only you** can read it, then park the
resulting ciphertext anywhere — including censorship-resistant storage that you
don't control. (*gbrain* is a personal "second brain": a local Postgres + `~/.gbrain`
knowledge store that re-synthesizes nightly.)

This repo is the **Cipher layer** of Cipher Brain: the part that turns your
growing second brain into a single encrypted artifact. *Where* those bytes live
(TON Storage / Arweave / anything) is a separate, pluggable concern — storage
only ever sees ciphertext.

> Status: proof-of-concept for [issue #1](https://github.com/Masashi-Ono0611/cipher-brain/issues/1).
> The round-trip is validated end-to-end against real gbrain data (see below).

## Threat model — "the key is only mine"

`cipher-brain` uses [age](https://age-encryption.org) (X25519 + ChaCha20-Poly1305)
with an **asymmetric** keypair:

- **identity** (private key) — lives off your always-on machine; the *only* thing
  that can decrypt. Lose it and the snapshots are unrecoverable.
- **recipient** (public key) — all the snapshotting machine needs.

So the always-on box that runs gbrain (e.g. a Mac mini) holds **only the public
key**. It can produce snapshots forever but can never read them back: the
**snapshots it writes, and anything the storage backend ever sees, are ciphertext
only** — that is the property this design guarantees.

Two honest caveats, since this is a security tool. (1) That box also *runs* gbrain,
so the live plaintext (its Postgres + `~/.gbrain`) is on it regardless — cipher-brain
protects the snapshots you ship off-box, not the source machine; keep it
full-disk-encrypted. (2) A box that can rewrite `recipient.txt` (or inject an extra
`--recipient`) could silently re-key *future* snapshots to an attacker while your own
restore still works. Pin the allowed recipients with `CIPHER_BRAIN_PIN_RECIPIENTS`
(snapshot refuses any recipient not on the list), and prove restorability where the
identity lives — `verify` on a public-key-only box reports **PARTIAL**, never PASS.

## Install

```sh
# requires: node >= 18, and the `age` binary (brew install age)
git clone https://github.com/Masashi-Ono0611/cipher-brain
cd cipher-brain && npm link        # exposes `cipher-brain`
```

**Prerequisites for `--pg`:** the `pg_dump`/`pg_restore` client tools (e.g.
`brew install libpq` or your distro's `postgresql-client`) — without them the
headline `--pg` flow fails with a cryptic `spawn pg_dump ENOENT`. If they are not
on `PATH`, point `CIPHER_BRAIN_PG_BIN` at their directory. `tar` is assumed
present. The `turbo` backend additionally needs `@ardrive/turbo-sdk`
(`npm install @ardrive/turbo-sdk`); the `arweave` package is already installed by
`npm link`.

## Usage

```sh
cipher-brain keygen                 # one-time: creates ~/.cipher-brain/{identity.age,recipient.txt}

# encrypt a gbrain snapshot (pg_dump + the ~/.gbrain dir) to your PUBLIC key:
cipher-brain snapshot \
  --pg "postgres://user@localhost:5432/gbrain" \
  --dir ~/.gbrain \
  --out brain-2026-06-27.age

cipher-brain verify --in brain-2026-06-27.age      # real ciphertext? wrong key rejected?

# park the ciphertext on a storage backend (storage only ever sees ciphertext):
BAG=$(cipher-brain push --in brain-2026-06-27.age --backend ton)   # prints the locator (BagID)
cipher-brain pull --locator "$BAG" --backend ton --out got.age     # fetch it back, anywhere

# later, on the machine that holds your PRIVATE identity:
cipher-brain restore \
  --in got.age \
  --out-dir ./restored \
  --pg "postgres://user@localhost:5432/gbrain_restore"
```

`push`/`pull` are storage primitives over a pluggable backend (`--backend` is
required — there is no default). The **`file`** backend is a local
content-addressed store (no daemon, used by CI); the **`ton`** backend shells out
to a TON Storage `storage-daemon` (`locator` = hex BagID, a content fingerprint).
The **`arweave`** and **`turbo`** backends are also shipped: they push to the
Arweave network (turbo accepts ETH/USDC for the bundler fee) and pull from any
Arweave gateway via plain HTTP — the `locator` is the tx id assigned after upload
(not a content hash). The backend abstraction is what makes the same
`snapshot → push … pull → restore` pipeline work across all four.

Each component (the `pg_dump`, each `--dir` archive) is staged into a private
(0700) temp dir, then the bundle is streamed `tar -> age`, so the final ciphertext
never loads into memory. The staged plaintext is erased even on failure, so it
doesn't linger — but staging needs scratch space about the size of the snapshot,
so point `TMPDIR` at a disk with room for large brains. The Postgres connection
string is passed as a process argument; for password auth use `~/.pgpass` or
`PGPASSWORD` so secrets stay out of the process list. Binary paths are overridable
for non-PATH installs: `CIPHER_BRAIN_AGE`, `CIPHER_BRAIN_PG_BIN` (dir holding
`pg_dump`/`pg_restore`), `CIPHER_BRAIN_HOME`. Storage backends read
`CIPHER_BRAIN_FILE_DIR` (file backend object store) and
`CIPHER_BRAIN_TON_{CLI,API,CLIENT,SERVER,TIMEOUT}` (the `storage-daemon-cli` path,
control address, key paths, and download timeout for the ton backend).

## Validation

1. **Local crypto round-trip** (`npm run selftest`) — no Postgres, no network.
   keygen → snapshot a synthetic tree → verify → restore → assert the tree is
   byte-identical, the ciphertext leaks no plaintext, and a *different* identity
   cannot restore.
2. **Real gbrain round-trip** (`scripts/real-gbrain-roundtrip.sh`, operator-run on
   the machine that holds gbrain) — dumps a live table, encrypts, verifies,
   decrypts, restores into a throwaway scratch DB, and asserts the row count and a
   content checksum match the source exactly. The scratch DB is dropped afterward.

   Result (2026-06-27, table `dream_verdicts`, 796 rows): ciphertext 90 KB,
   restored count = 796, source checksum == restored checksum. ✅
3. **Storage round-trip — `file` backend** (`npm run selftest:storage`, gated in
   CI, no daemon/network) — snapshot → push → *delete the original* → pull → verify
   → restore, asserting the locator is content-addressed (not the source path), the
   pulled bytes decrypt to the source, and an absent locator errors. ✅
4. **Storage round-trip — `ton` backend** (`scripts/ton-roundtrip.sh`,
   operator-run) — pushes the ciphertext to a real `storage-daemon`, starts an
   independent second daemon with its own db, and attempts a cross-node fetch by
   BagID, gated on `get-peers` showing the seeder (so a local read can't pass as a
   transfer).

   Result (2026-06-27, testnet, home-NAT'd seeder): **PARTIAL**. The daemon stored
   the *exact* ciphertext (sha256 match), it decrypts back to the original, storage
   held no plaintext, and a flipped BagID returns nothing — but the two daemons
   never peered (the seeder shows 0 peers), so the cross-node ADNL transfer was
   **not** exercised. That gap is seeder reachability (NAT / sparse testnet DHT),
   filed as a follow-up issue (#6). It is honestly *not* a full PASS — the path to
   PASS (a public-IP seeder + the cross-node proof) is laid out in
   [`docs/ton-public-seeder.md`](docs/ton-public-seeder.md).
5. **Key recovery + versioning** (`npm run selftest:recovery`, gated in CI, no
   daemon) — encrypts a snapshot to a primary *and* an offline backup key, then
   shows the **backup key restores with the primary identity absent**, an unrelated
   identity cannot, and two snapshots restore independently. ✅
6. **Large-file / multi-chunk** (`scripts/large-file-test.sh`, operator-run) —
   runs the whole pipeline at scale through both backends.

   Result (2026-06-27, 256 MB): snapshot streamed in 9 s at **~101 MB node RSS**
   (≪ the 256 MB input → not buffered); the `file` backend round-tripped
   byte-identical; the `ton` backend produced a **2050-piece** bag the daemon
   stored exactly and that decrypted byte-identical. ✅
7. **Arweave backend parity** (`npm run selftest:arweave`, gated in CI against a
   local [arlocal](https://github.com/textury/arlocal) gateway — no real AR) —
   proves the `StorageBackend` abstraction holds for a backend whose locator is an
   **Arweave tx id assigned *after* upload** (not a content hash like `file`/`ton`):
   push → tx id, fetch by that id, byte-identical, decrypts; unknown id fails. ✅
   `pull` reads both plain **L1** txs and **ANS-104 bundled** data items — the form a
   bundler (Turbo/Irys) produces when you pay with **ETH/USDC/fiat** — via a gateway-HTTP
   read with an L1 chunk-read fallback, proven against *real* arweave.net by
   `node scripts/arweave-real-read.mjs` (operator-run; external, not in CI). ✅

## Managing snapshots over time

[`MANAGEMENT.md`](MANAGEMENT.md) covers cadence (a nightly snapshot+push recipe),
versioning (each push → an immutable locator + an append-only
index — content-addressed for `file`/`ton`, a tx id for `arweave`/`turbo`), the
restore runbook, and **key recovery** — the primary-plus-offline-backup
model above, so losing one identity never loses the brain.

**Durability** (will the bytes survive a year of neglect?) is a separate question from
the round-trip: [`docs/durability.md`](docs/durability.md) lays out the paths to a real
guarantee — Arweave's pay-once permanence vs TON's proof-based rental — and recommends
Arweave as the durable cold archive + a TON copy for `.ton`-addressable hot access (#7).

## Roadmap

- **#1 Cipher** — encrypt a snapshot client-side, key only yours. ✅
- **#2 Storage** — pluggable backend, storage sees ciphertext only. `file` backend
  round-trip ✅ (CI-gated); `ton` push/store/decrypt ✅, cross-node fetch blocked on
  seeder reachability (PARTIAL — tracked as a follow-up).
- **#3 Management** — key recovery (backup key, CI-proven ✅) + versioning ✅;
  cadence / restore runbook documented in [`MANAGEMENT.md`](MANAGEMENT.md).
- **Backends** — `file` (CI ✅) · `ton` (store/decrypt ✅, cross-node PARTIAL, #6) ·
  `arweave` (parity CI-proven against arlocal ✅, #9) · `turbo` (upload via a bundler,
  payable with **ETH/USDC** — `<100KB` free; operator-proven real round-trip, #20). The
  abstraction is validated across content-addressed *and* post-assigned-id backends.

The cipher layer is backend-agnostic by design — proven, not just asserted, now that
both a content-addressed (`ton`) and a post-assigned-id (`arweave`) backend round-trip.
The remaining **Arweave-vs-TON-for-real** decision is about durability/cost/UX on
*real* networks (#6 reachability, #7 persistence), not the abstraction.
