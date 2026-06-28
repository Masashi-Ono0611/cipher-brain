# Managing cipher-brain snapshots

How to run encrypted gbrain backups over time: **cadence**, **versioning**,
**restore**, and **key recovery**. The recovery and versioning claims here are
exercised by `npm run selftest:recovery` (gated in CI).

## Key recovery — "losing the identity must not lose the brain"

The #1 footgun is simple: the private `identity.age` is the *only* thing that can
decrypt. Lose it and every snapshot is permanently unreadable. cipher-brain gives
you two independent defenses; **use both**.

### 1. Encrypt to a backup key (recommended, built in)

`snapshot --recipient` is repeatable. Give it a **primary** and an **offline
backup** public key, and *either* identity can restore:

```sh
# one-time: make a backup keypair on a machine you control, keep its identity OFFLINE
CIPHER_BRAIN_HOME=~/.cipher-brain-backup cipher-brain keygen     # -> backup recipient + identity

# every snapshot: encrypt to BOTH the primary and the backup public key
cipher-brain snapshot --dir ~/.gbrain --pg "$PG" \
  --recipient ~/.cipher-brain/recipient.txt \
  --recipient ~/.cipher-brain-backup/recipient.txt \
  --out brain-$(date +%F).age
```

Store the backup `identity.age` somewhere the primary machine isn't: an encrypted
USB in a drawer, a second location, a trusted person. If the primary box dies, the
backup identity restores everything. (Proven in `selftest-recovery.sh`: the backup
key restores with the primary identity absent; an unrelated key cannot.)

### 2. Back up the identity file itself

The identity is a short text file — copy it somewhere durable and private:
a password manager (secure note), a printed copy in a safe, or a hardware-backed
store. Treat it like a seed phrase.

> **M-of-N (Shamir) split** — splitting the identity into *N* shares where any *K*
> reconstruct it (no single point of loss *or* compromise) is tracked as a future
> option rather than hand-rolled here. See the repo issues.

## Cadence

gbrain re-synthesizes nightly, so a **nightly** snapshot is the natural cadence.
On macOS, a `launchd` agent (or `cron`) that runs the snapshot+push once a day:

```sh
# nightly.sh — runs on the machine that holds gbrain (it has the public key only)
set -euo pipefail
OUT="$HOME/brain-snapshots/brain-$(date +%F).age"
cipher-brain snapshot --pg "postgres://you@localhost:5432/gbrain" --dir "$HOME/.gbrain" \
  --recipient ~/.cipher-brain/recipient.txt --recipient ~/.cipher-brain-backup/recipient.txt \
  --out "$OUT"
# arweave/turbo are paid, permanent stores — CIPHER_BRAIN_YES=1 suppresses the
# interactive --yes guard when running unattended. Remove if using file/ton only.
# Optionally set CIPHER_BRAIN_MAX_SPEND=<n> (native units: winston for arweave L1,
# winc for turbo) to abort when the cost estimate exceeds your budget.
export CIPHER_BRAIN_YES=1        # omit for file/ton backends (no charge)
LOC=$(cipher-brain push --in "$OUT" --backend "$BACKEND")   # file | ton | arweave | turbo
printf '%s\t%s\t%s\n' "$(date -u +%FT%TZ)" "$LOC" "$(shasum -a 256 "$OUT" | cut -d" " -f1)" \
  >> "$HOME/brain-snapshots/index.tsv"
```

Snapshotting needs only the **public** key, so the snapshots the always-on box
writes (and anything storage sees) are ciphertext only. Two caveats: that box also
runs gbrain, so the live plaintext is on it regardless (keep it full-disk-encrypted);
and a box that can rewrite `recipient.txt` could re-key *future* snapshots — set
`CIPHER_BRAIN_PIN_RECIPIENTS` (an allowlist of `age1…` keys) so snapshot refuses any
recipient you did not pin. A full snapshot is ~850 MB today (pg_dump ~630 MB +
`~/.gbrain` ~220 MB); incremental snapshots are a future optimization.

Prove restorability where the identity lives, on a cadence: a `verify` on the
public-key-only snapshotting box reports **PARTIAL** (exit 2) because it cannot run
the decrypt proof, so periodically pull a recent snapshot to a machine that holds the
identity and run `verify` there (a full **PASS** = restorable by you). `scripts/selftest-recovery.sh` is the off-box drill in miniature.

## Versioning

Each snapshot is immutable: `push` returns a **locator** whose form depends on the
backend — a store path (`file`), a hex BagID that is a content fingerprint (`ton`),
or a tx id assigned *after* upload (`arweave`/`turbo`; not a content hash). Keep an
append-only
`index.tsv` of `timestamp · locator · sha256` (the cadence script above does this).
That index *is* your version history — every line is an independently restorable
point in time. A "latest" pointer (the newest line, or a `.ton` DNS record updated
to the newest BagID) is how a fresh machine finds the most recent backup.

## Restore runbook

On a machine that holds a recipient **identity** (primary or backup):

```sh
# 1. pick a version from index.tsv (or the latest line); take its <locator>
# 2. fetch the ciphertext back from storage
cipher-brain pull --locator "<locator>" --backend "$BACKEND" --out restored.age

# 3. confirm it is intact and yours BEFORE trusting it
cipher-brain verify --in restored.age          # header + your key decrypts it

# 4. decrypt + rebuild into a SCRATCH database (never straight over a live gbrain)
cipher-brain restore --in restored.age --out-dir ./restored \
  --pg "postgres://you@localhost:5432/gbrain_restore"

# 5. sanity-check row counts / content, then cut over deliberately
```

If you only need the files (not a live DB), drop `--pg` and untar the components
under `./restored` yourself.

## What's proven vs recommended

| Area | Status |
|---|---|
| Backup-key recovery (any one identity restores), versioning round-trip | **proven** — `selftest:recovery` (CI) |
| `file` backend store/fetch | **proven** — `selftest:storage` (CI) |
| `arweave` backend round-trip | **proven** — `selftest:arweave` (CI, against arlocal); real-network gateway pull confirmed operator-run |
| `turbo` backend (ETH/USDC bundler upload) | **proven** — operator-run real round-trip (#20) |
| `ton` cross-node fetch | **PARTIAL** — blocked on seeder reachability (see issues) |
| Cadence script, identity off-box backup, Shamir M-of-N | **recommended practice / future** — not enforced by code |
