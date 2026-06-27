# cipher-brain

Encrypt a [gbrain](https://github.com/) snapshot so that **only you** can read it,
then park the resulting ciphertext anywhere — including censorship-resistant
storage that you don't control.

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
key**. It can produce snapshots forever but can never read them back. Compromising
that machine — or the storage backend — leaks no brain content.

## Install

```sh
# requires: node >= 18, and the `age` binary (brew install age)
git clone https://github.com/Masashi-Ono0611/cipher-brain
cd cipher-brain && npm link        # exposes `cipher-brain`
```

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
The same `snapshot → push … pull → restore` pipeline will hold for an Arweave
backend later — that is the point of the abstraction.

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
   filed as a follow-up issue. It is honestly *not* a full PASS.
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

## Managing snapshots over time

[`MANAGEMENT.md`](MANAGEMENT.md) covers cadence (a nightly snapshot+push recipe),
versioning (each push → an immutable content-addressed locator + an append-only
index), the restore runbook, and **key recovery** — the primary-plus-offline-backup
model above, so losing one identity never loses the brain.

## Roadmap

- **#1 Cipher** — encrypt a snapshot client-side, key only yours. ✅
- **#2 Storage** — pluggable backend, storage sees ciphertext only. `file` backend
  round-trip ✅ (CI-gated); `ton` push/store/decrypt ✅, cross-node fetch blocked on
  seeder reachability (PARTIAL — tracked as a follow-up).
- **#3 Management** — key recovery (backup key, CI-proven ✅) + versioning ✅;
  cadence / restore runbook documented in [`MANAGEMENT.md`](MANAGEMENT.md).

With #1–#3 in, the Arweave-vs-TON storage decision is the next step — deliberately
*downstream*, because the cipher layer is backend-agnostic by design (#9).
