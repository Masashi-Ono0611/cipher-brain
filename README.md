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

# later, on the machine that holds your PRIVATE identity:
cipher-brain restore \
  --in brain-2026-06-27.age \
  --out-dir ./restored \
  --pg "postgres://user@localhost:5432/gbrain_restore"
```

Each component (the `pg_dump`, each `--dir` archive) is staged into a private
(0700) temp dir, then the bundle is streamed `tar -> age`, so the final ciphertext
never loads into memory. The staged plaintext is erased even on failure, so it
doesn't linger — but staging needs scratch space about the size of the snapshot,
so point `TMPDIR` at a disk with room for large brains. The Postgres connection
string is passed as a process argument; for password auth use `~/.pgpass` or
`PGPASSWORD` so secrets stay out of the process list. Binary paths are overridable
for non-PATH installs: `CIPHER_BRAIN_AGE`, `CIPHER_BRAIN_PG_BIN` (dir holding
`pg_dump`/`pg_restore`), `CIPHER_BRAIN_HOME`.

## Validation

Two layers, both green:

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

## Roadmap

- **#1 Cipher (this PoC)** — encrypt a snapshot client-side, key only yours. ✅
- **#2 Storage** — put the ciphertext on a real backend (TON Storage / Arweave),
  fetch it back from elsewhere, decrypt. Storage sees only ciphertext.
- **#3 Management** — snapshot cadence, versioning, and key recovery.

The Arweave-vs-TON storage decision is deliberately *downstream* of #1–#3: the
cipher layer is backend-agnostic by design.
