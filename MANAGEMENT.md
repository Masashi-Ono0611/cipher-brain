# Managing cipher-brain snapshots

How to run encrypted gbrain backups over time: **cadence**, **versioning**,
**restore**, and **key recovery**. The recovery and versioning claims here are
exercised by `npm run selftest:recovery` (gated in CI).

> **New setup?** `cipher-brain init` is the recommended entry point — an interactive
> wizard that walks keygen, the backup key and passphrase-wrap choices below,
> `CIPHER_BRAIN_PIN_RECIPIENTS`, a `--profile`, and the first snapshot + push, ending
> in a printable recovery kit (issue #68; exercised end-to-end by
> `npm run selftest:init`, including a kit-only restore drill). Everything below still
> applies — the wizard is a thin, interactive front end over these same commands, not
> a different mechanism.

## Key recovery — "losing the identity *or the locator* must not lose the brain"

Recovery needs **two** things, and both can be lost. The private `identity.age` is the
only thing that can *decrypt* — lose it and every snapshot is permanently unreadable.
But the **locator** (which tx id / store path holds the latest ciphertext) is
the only thing that tells a fresh machine *where to fetch from* — and today the full
record of locators is a local `index.tsv` on the always-on box. If that box dies, an
operator who backed up only the identity still cannot find the bytes. So back up both:
the identity (below) **and** the latest locator (`#3`).

cipher-brain gives you two independent defenses for the identity; **use both**.

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

Either `keygen` call above can add `--pq` for a post-quantum HYBRID keypair
(ML-KEM-768 + X25519) instead of plain X25519 — the primary and backup don't need
to match (a hybrid primary + an X25519 backup, or vice versa, both restore). See
README Threat model for why this matters against harvest-now-decrypt-later.

### 2. Back up the identity file itself

The identity is a short text file — copy it somewhere durable and private:
a password manager (secure note), a printed copy in a safe, or a hardware-backed
store. Treat it like a seed phrase.

**Protect it at rest.** A bare `keygen` identity (the standard age secret-key file) is an unwrapped secret guarded
only by file perms (0600) — theft of the file = every snapshot decryptable. Two
defenses, ideally both:
- **Passphrase-wrap it:** `cipher-brain keygen --passphrase` (for a *fresh* keypair) or
  `cipher-brain keygen --wrap-in-place` (for an identity you already have — e.g. one
  created by a bare `keygen`, or by `init` with this step skipped) encrypts the identity
  with a scrypt passphrase (you enter it on `restore`/`verify`). An exfiltrated identity
  file is then useless without the passphrase. **Do not** use `keygen --passphrase
  --force` to add a passphrase to an existing identity — `--force` always generates a
  brand-new keypair (it does not wrap the old one), so every snapshot already encrypted
  to the old identity becomes unrecoverable; `--wrap-in-place` keeps the same keypair.
- **Full-disk-encrypt the identity host.** The machine that holds the identity is
  secret-bearing (it can read every snapshot); FileVault / LUKS protects it (and any
  off-box copies) if the disk or USB is lost or stolen.

> **M-of-N (Shamir) split** — splitting the identity into *N* shares where any *K*
> reconstruct it (no single point of loss *or* compromise) is tracked as a future
> option rather than hand-rolled here. See the repo issues.

### 3. Retain the latest locator off-box (built in)

The identity decrypts, but you still need to know *where the latest ciphertext lives*.
`push --save-locator <path>` writes
`<locator>\t<backend>\t<sha256>[\t<content_digest>[\t<recipients_fingerprint>]]`
to a small file, rewritten atomically on every push so it always holds the **most
recent** snapshot's locator plus an integrity pin. The optional 4th field is the
plaintext content digest (from the `<out>.digest` sidecar `snapshot` writes); the
optional 5th is the recipients fingerprint (from the `<out>.recipients-fingerprint`
sidecar) — `push --skip-unchanged` compares BOTH against the current snapshot and only
skips when neither changed, so re-snapshotting unchanged content under a **different**
`--recipient` set (added/removed a key) never returns a stale locator. Older 3- and
4-field files keep working everywhere:

```sh
cipher-brain push --in brain-$(date +%F).age --backend turbo --yes \
  --save-locator ~/.cipher-brain/latest-locator.tsv
```

> **Use a network backend here.** For `--backend file` the locator is a *local* store
> path, useless on a fresh machine — only `turbo`/`arweave` locators are portable.

Back this file up **off-box, next to the backup identity** (same encrypted USB / secure
note). Recovery on a fresh machine then needs only those two things — no `index.tsv`. The
saved sha256 is applied automatically, so a substituted ciphertext is rejected:

```sh
cipher-brain pull --from-locator-file ~/restore/latest-locator.tsv --out latest.age
cipher-brain restore --in latest.age --out-dir ./restored --pg "$PG_RESTORE" --yes
```

For full version history (not just the latest), keep backing up the whole `index.tsv`
(below) — but the single latest-locator file is the minimum that makes disk-death
recoverable. *(A stable name that always resolves to the newest snapshot — an ArNS
mutable pointer — is a future option; until then this file is the durable pointer.)*

## Cadence

gbrain re-synthesizes nightly, so a **nightly** snapshot is the natural cadence.
`cipher-brain schedule install` is the primary path: it composes the snapshot+push
pipeline from the same flags those commands take, writes it as a runner script
(`$CIPHER_BRAIN_HOME/schedule/nightly.sh`), and registers the platform trigger —
a `launchd` agent on macOS, a `crontab` entry on Linux:

```sh
# runs on the machine that holds gbrain (it has the public key only)
cipher-brain schedule install --backend turbo \
  --pg "postgres://you@localhost:5432/gbrain" --dir "$HOME/.gbrain" \
  --recipient ~/.cipher-brain/recipient.txt \
  --recipient ~/.cipher-brain-backup/recipient.txt \
  --max-spend 500000000            # REQUIRED for arweave/turbo (native units) — see below

cipher-brain schedule status       # configured time · trigger state · last run + rc · next run
cipher-brain schedule uninstall    # unregister the trigger, remove the generated artifacts
```

The default run time is **03:30** (change with `--at HH:MM`): well after gbrain's
overnight re-synthesis settles, so the DB and files are captured from the same settled
state ("Avoid the write window", below). Each run appends to
`$CIPHER_BRAIN_HOME/schedule/logs/nightly-YYYY-MM-DD.log` and always ends with a
machine-readable `OK rc=0` / `FAILED rc=N` line, so `schedule status` (or any monitor)
can tail the newest log for the outcome.

That, though, is a *pull*: it tells you the outcome only when you go check. Add
`--ping-url <url>` for the *push* half — a `healthchecks.io`-style dead man's switch —
and every run also `curl`s that URL on success, or `<url>/fail` on failure (a plain
string append, not URL-aware — pass `--ping-url-fail` explicitly if your ping URL has
a query string or a trailing slash), so a schedule that silently stops running at all
gets noticed even if nobody runs `schedule status`. Both are best-effort (10s timeout,
never affects the run's own outcome).

**Paid backends must be capped.** For `turbo`/`arweave` the generated runner sets
`CIPHER_BRAIN_YES=1` — the unattended equivalent of `--yes` — which is exactly why
`schedule install` *refuses* those backends without `--max-spend <n>`: an unattended
nightly upload must never run uncapped. Review the `CIPHER_BRAIN_MAX_SPEND` line it
writes (native units: winc for turbo, winston for arweave L1); if
`CIPHER_BRAIN_AR_WALLET` is set when you run install it is baked into the runner,
otherwise edit the commented wallet line the runner carries. Wallet funding and
credit-share setup: [`docs/arweave-upload-runbook.md`](docs/arweave-upload-runbook.md).

What the generated runner does is the hand-rolled recipe it replaces — kept here as
the explanation of the moving parts:

```sh
# nightly.sh (shape of the generated runner)
set -euo pipefail
# Keyed on date+time (not just the day) and disambiguated on collision, so a manual
# test/retry on install day — or any same-day re-run — never refuses to overwrite
# the prior run's snapshot.
STAMP="$(date +%Y%m%dT%H%M%S)"
OUT="$HOME/.cipher-brain/schedule/snapshots/brain-$STAMP.age"
n=1
while [ -e "$OUT" ]; do n=$((n + 1)); OUT="$HOME/.cipher-brain/schedule/snapshots/brain-$STAMP-$n.age"; done
cipher-brain snapshot --pg "postgres://you@localhost:5432/gbrain" --dir "$HOME/.gbrain" \
  --recipient ~/.cipher-brain/recipient.txt --recipient ~/.cipher-brain-backup/recipient.txt \
  --out "$OUT"
# turbo (the recommended backend) is a paid, permanent store — CIPHER_BRAIN_YES=1
# suppresses the interactive --yes guard when running unattended, and
# CIPHER_BRAIN_MAX_SPEND=<n> (native units: winc for turbo, winston for arweave L1)
# aborts when the cost estimate exceeds your budget. Omit both (and the wallet) for
# the free file backend.
export CIPHER_BRAIN_YES=1
export CIPHER_BRAIN_MAX_SPEND=500000000
export CIPHER_BRAIN_AR_WALLET="$HOME/.cipher-brain/wallet.json"   # JWK signer for turbo
# --save-locator keeps a one-line file with the LATEST locator; back it up off-box
# next to the backup identity so disk-death is recoverable (see Key recovery #3).
# --skip-unchanged reads the plaintext content digest snapshot wrote to "$OUT.digest"
# AND the recipients fingerprint it wrote to "$OUT.recipients-fingerprint"; only when
# BOTH match what's recorded in the save-locator file does it exit 0 with the previous
# locator instead of paying to re-upload (a changed --recipient set always re-uploads;
# --force overrides either way).
LOC=$(cipher-brain push --in "$OUT" --backend turbo --skip-unchanged \
  --save-locator "$HOME/.cipher-brain/latest-locator.tsv")   # or: file | arweave
# Read the SHA256 back from the save-locator file's 3rd field rather than re-hashing
# "$OUT": on a --skip-unchanged SKIP, $LOC is the PREVIOUS run's locator while $OUT is
# THIS run's freshly re-encrypted (age's ephemeral file key differs every run) and
# never-uploaded ciphertext — shasum-ing $OUT would pair $LOC with a hash it will never
# actually produce, breaking any later `pull --locator ... --sha256 ...` check against
# this index row. The save-locator file's 3rd field already holds the correct hash for
# whatever $LOC points to (cipher-brain push writes it there on every real push, and
# leaves it untouched — still correct — on a skip).
SHA=$(cut -f3 "$HOME/.cipher-brain/latest-locator.tsv")
printf '%s\t%s\t%s\n' "$(date -u +%FT%TZ)" "$LOC" "$SHA" \
  >> "$HOME/.cipher-brain/schedule/index.tsv"
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

**Avoid the write window.** A run `pg_dump`s the DB and then tars `~/.gbrain` at
*different instants*, so a snapshot that straddles gbrain's nightly re-synthesis can
pair a newer DB with older files (or vice versa). Schedule the snapshot *outside* that
window (gbrain re-synthesizes overnight — snapshot well after it settles). The manifest
now records a top-level `created_at` and a per-component `captured_at` (echoed by
`restore`/`verify`), so any DB↔files skew is detectable after the fact. (`pg_dump -Fc`
is itself point-in-time consistent via one REPEATABLE READ txn — only the DB↔file
boundary needs aligning.)

## Versioning

Each snapshot is immutable: `push` returns a **locator** whose form depends on the
backend — a store path (`file`, content-addressed) or a tx id assigned *after*
upload (`arweave`/`turbo`; not a content hash). Keep an append-only
`index.tsv` of `timestamp · locator · sha256` (the scheduled nightly runner does this).
That index *is* your version history — every line is an independently restorable
point in time. To find the *most recent* backup, a fresh machine reads the latest
line of `index.tsv`, or the one-line `--save-locator` file (Key recovery #3) if it
has only that. *(A self-resolving stable name — an ArNS pointer updated to the
newest locator — would let a fresh machine find the latest with no local file at
all; that is a future option, not yet implemented.)*

## Restore runbook

On a machine that holds a recipient **identity** (primary or backup):

```sh
# 1. pick a version from index.tsv (or the latest line); take its <locator>
# 2. fetch the ciphertext back from storage
cipher-brain pull --locator "<locator>" --backend "$BACKEND" --out restored.age

# 3. confirm it is intact and yours BEFORE trusting it
cipher-brain verify --in restored.age          # header + your key decrypts it

# 4. decrypt + rebuild into a SCRATCH database (never straight over a live gbrain)
# --pg runs pg_restore --clean --if-exists, which DROPS/replaces objects in the
# target database — an irreversible operation, so it requires --yes to confirm.
cipher-brain restore --in restored.age --out-dir ./restored \
  --pg "postgres://you@localhost:5432/gbrain_restore" --yes

# 5. sanity-check row counts / content, then cut over deliberately
```

If you only need the files (not a live DB), drop `--pg` — every `--dir`/`--profile`
component is auto-expanded into `./restored/expanded/<NNN>-<encoded source path>/`,
keyed to the component's ORIGINAL absolute source path (from `manifest.json`), not its
on-disk name. This is what makes many same-basename sources (e.g. dozens of claude-code
project `memory/` dirs under `--profile claude-code`) land in separate, clearly-labeled
directories instead of an undifferentiated pile of `memory.tar.gz` / `memory-1.tar.gz` /
etc that only `manifest.json` could disambiguate (#181). `./restored/expanded/README.txt`
(and restore's own stdout) records which expanded directory came from which source path.
Nothing is ever written back to that original absolute path — expansion only ever creates
NEW directories under `--out-dir`, and re-running restore into the same `--out-dir` does
not clobber a prior expansion (same no-clobber posture as the outer extract). Pass
`--no-expand-components` to skip this and get only the raw `*.tar.gz` files (the pre-#181
behavior, still there either way as the fallback).

## Error codes

Failures print with a stable `[CB-E0xx]` code and this section's anchor, the same shape
ngrok uses for its own errors (https://ngrok.com/docs/errors): `error: <existing message>
[CB-E0xx] see MANAGEMENT.md#error-codes`. The code identifies the FAILURE PATTERN, not
the exact wording — it's meant to stay stable across a future rewording of the surrounding
message (`src/lib/errors.ts`'s registry matches text, so keeping that promise in practice
means the registry entry is updated in the SAME change that reworks its message — see that
file's `source` field on each entry). An error with no code just means it hasn't been
assigned one yet (issue #212 covers the most common ~15 patterns, not every possible
failure); the plain message is still the full story either way. Over MCP,
`verify_restore`/`snapshot_now`/etc.'s error result also carries the code as its own
`cb_code` field, so an agent can branch on it without parsing the message text.

| Code | Cause | Next action |
|---|---|---|
| CB-E001 | `pull --sha256` (or a locator-file's saved pin) didn't match the fetched bytes — the storage/gateway served something else. | Retry against a different gateway/backend, or re-check the trusted source (e.g. `index.tsv`) the expected hash came from. Never trust a substituted artifact that still merely opens. |
| CB-E002 | age decryption itself failed — most often the identity you gave isn't a recipient this ciphertext was encrypted to (wrong `--identity`/wrong keypair), or the artifact is corrupt/truncated. | Confirm you're pointing at the identity that matches one of the snapshot's `--recipient`s. If it should be the right key, re-fetch the artifact and check its size/sha256 for truncation. |
| CB-E003 | The identity file is passphrase-wrapped (`keygen --passphrase`) and the passphrase given was wrong (or the file is damaged). | Re-enter the correct passphrase (prompted on the TTY, or set `CIPHER_BRAIN_PASSPHRASE` for automation). |
| CB-E004 | `pull` reached the backend, but the object isn't retrievable yet — a fresh Arweave/Turbo upload typically takes ~5-8 min to propagate to a gateway. | Re-run with `--wait <seconds>` (retries until ready), or simply wait a few minutes and pull again. |
| CB-E005 | `CIPHER_BRAIN_PIN_RECIPIENTS` is set, and a recipient this snapshot would encrypt to is not on that allowlist (a tampered `recipient.txt`, or an unexpected extra `--recipient`). | Confirm the recipient is one you actually intend to grant access; if so, add it to `CIPHER_BRAIN_PIN_RECIPIENTS`. If not, this is exactly the attack the pin exists to catch — investigate before proceeding. |
| CB-E006 | The upload's cost estimate exceeds `CIPHER_BRAIN_MAX_SPEND`, or the signing wallet's balance/credits are insufficient. | Raise (or intentionally lower) `CIPHER_BRAIN_MAX_SPEND`, or fund the wallet (Turbo Credits top up at app.ardrive.io; Arweave L1 needs AR in the JWK's own address). |
| CB-E007 | `push`/`schedule install` targets a paid, permanent backend (arweave/turbo) without consent. | Pass `--yes`, or set `CIPHER_BRAIN_YES=1` (the unattended-cadence escape hatch) to confirm the spend. |
| CB-E008 | `push --in` points at a file that isn't age ciphertext (its header doesn't match) — storage must only ever see ciphertext. | Pass the `.age` file `cipher-brain snapshot` produced, not a plaintext/other file. |
| CB-E009 | The command's output path already exists and no-clobber refused to overwrite it (protects a prior snapshot/pull result from silent loss). | Pick a different `--out`/`--save-locator` path, move the existing file aside, or pass `--force` to overwrite it deliberately. |
| CB-E010 | A `file`-backend locator resolves outside `CIPHER_BRAIN_FILE_DIR`, or doesn't match the `<sha256>.age` shape `push` itself produces — refused as a possible path-traversal/arbitrary-file-read attempt via a tampered locator. | Only pass locators exactly as `push` printed them (or as saved in a `--save-locator`/index file from a trusted, off-box copy); don't hand-construct one. |
| CB-E011 | The `arweave`/`turbo` backend needs `CIPHER_BRAIN_AR_WALLET` (a JWK signer) and it's unset, or the path isn't readable. | Run `cipher-brain wallet create` to generate one, then set `CIPHER_BRAIN_AR_WALLET` to its path (`wallet address` shows what to fund). |
| CB-E012 | The optional peer dependency the backend needs (`arweave` or `@ardrive/turbo-sdk`) isn't installed. | Run the `npm install …` command the error itself prints. |
| CB-E013 | `--backend` was given a value other than `file`, `arweave`, or `turbo`. | Correct the typo — only those three are valid. |
| CB-E014 | `schedule status`/`uninstall` ran before `schedule install`, or writing the crontab entry failed. | Run `cipher-brain schedule install` first; a crontab-write failure usually means missing cron permissions/availability in this environment. |
| CB-E015 | `restore`/`verify` can't find the private identity file it needs to decrypt (default or `--identity` path). | Run `cipher-brain keygen` if you haven't yet, or point `--identity` at the correct file. |

## What's proven vs recommended

| Area | Status |
|---|---|
| Backup-key recovery (any one identity restores), versioning round-trip | **proven** — `selftest:recovery` (CI) |
| `file` backend store/fetch | **proven** — `selftest:storage` (CI) |
| `arweave` backend round-trip | **proven** — `selftest:arweave` (CI, against arlocal); real-network gateway pull confirmed operator-run |
| `turbo` backend (ETH/USDC bundler upload) | **proven** — operator-run real round-trip (#20) |
| Identity at rest (passphrase-wrap via `keygen --passphrase`; FDE on the identity host) | **available / recommended** — `--passphrase` ships; FDE is operator config, not enforced by code |
| Post-quantum hybrid keypair (`keygen --pq`, ML-KEM-768 + X25519 — mitigates harvest-now-decrypt-later, see README Threat model) | **available** — `selftest:pq` (CI); combines with a plain-X25519 backup key and `CIPHER_BRAIN_PIN_RECIPIENTS`, but the recipient/ciphertext are much bigger than plain X25519 |
| Nightly cadence (`schedule install / status / uninstall`: generated runner + launchd/cron trigger, paid backends refused without a spend cap, end-to-end run of the generated runner) | **proven** — `selftest:schedule` (CI) |
| Identity off-box backup, Shamir M-of-N | **recommended practice / future** — not enforced by code |
