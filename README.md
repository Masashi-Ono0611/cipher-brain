# cipher-brain

Encrypt your growing second brain — the AI memory, conversation history, and
knowledge store you build up over years — so that **only you** can read it,
then park the ciphertext **permanently on Arweave**: pay once at upload, and
the network's endowment keeps the bytes replicated with no server of yours to
keep alive. Recovery is deliberately minimal: a fresh machine restores with
just the locator and your identity file — the pull is a plain HTTP gateway
fetch, no wallet, no npm package. (*gbrain* is the second brain this was built
for: a local Postgres + `~/.gbrain` knowledge store that re-synthesizes
nightly.)

This repo is the **Cipher layer** of Cipher Brain: the part that turns your
growing second brain into a single encrypted artifact. Storage is a pluggable
backend behind one `push`/`pull` interface, and it only ever sees ciphertext.
Arweave via the **`turbo`** backend is the recommended mainline; a local
`file` backend covers dev and CI (see [Backends](#backends)).

> Status: proof-of-concept for [issue #1](https://github.com/Masashi-Ono0611/cipher-brain/issues/1).
> The round-trip is validated end-to-end against real gbrain data (see below).

## Threat model — "the key is only mine"

`cipher-brain` uses [age](https://age-encryption.org) (X25519 + ChaCha20-Poly1305)
with an **asymmetric** keypair. The crypto runs in-process via
[typage](https://github.com/FiloSottile/typage) (`age-encryption`, by age's
author), bundled into the CLI — no external `age` binary is required, and every
format stays byte-compatible with it (CI asserts both directions, including
scrypt passphrase wrapping):

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

Permanence adds a third caveat: **harvest now, decrypt later.** Ciphertext parked
on a permanent public network can never be recalled — anyone can copy it today and
wait for the cryptography to fail. age's X25519 recipient scheme is **not
post-quantum secure**, and rotating keys cannot protect snapshots already pushed:
the old ciphertext stays public forever. Weigh what you park against that horizon.
A post-quantum hybrid recipient (via an age plugin) is on the roadmap.

## Install

Install from the registry (requires node >= 22.6.0 — the age crypto layer is
bundled, nothing else to install):

```sh
npx cipher-brain --help            # zero-install, one-off
npm install -g cipher-brain        # or on PATH permanently: `cipher-brain`, `cipher-brain-mcp`
```

The packaged bins are the bundled `dist/` artifacts — self-contained single
files that run on plain Node.

Or run from source (the committed `bin/` shims run straight off `src/`, no
build step — this dev path needs Node >=22.6.0, the release that added the
`--experimental-strip-types` flag the shims re-exec under):

```sh
git clone https://github.com/Masashi-Ono0611/cipher-brain
cd cipher-brain && npm install
node bin/cipher-brain.mjs --help   # bin/cipher-brain-mcp.mjs is the MCP server
```

To expose the `cipher-brain` / `cipher-brain-mcp` commands from a checkout,
build first — the package `bin` entries point at the gitignored `dist/`
bundles, so a bare `npm link` silently creates no commands ([Bun](https://bun.sh)
required for the build):

```sh
npm run build && npm link
```

**Prerequisites for `--pg`:** the `pg_dump`/`pg_restore` client tools (e.g.
`brew install libpq` or your distro's `postgresql-client`) — without them the
headline `--pg` flow fails with a cryptic `spawn pg_dump ENOENT`. If they are not
on `PATH`, point `CIPHER_BRAIN_PG_BIN` at their directory. `tar` is assumed
present. The paid **upload** backends need their optional peer package next to
your project: `npm install arweave` for `--backend arweave`,
`npm install @ardrive/turbo-sdk` for `--backend turbo` (a from-source checkout
already has `arweave` from its `npm install`). Recovery pulls from an Arweave
gateway need no extra dependency.

## Usage

New here? `cipher-brain init` is the recommended starting point: an interactive
wizard that walks keygen, an offline backup key, passphrase-wrap,
`CIPHER_BRAIN_PIN_RECIPIENTS`, a `--profile`, a `--pg` dump when it detects a local
gbrain config, and the first snapshot + push in one sitting, ending in a printable
recovery kit (see MANAGEMENT.md's "Key recovery" section for what each step means).
The manual flow below is exactly what it wraps — useful once you know what you want,
or for scripting/automation `init` itself refuses (it is interactive only).

```sh
cipher-brain keygen                 # one-time: creates ~/.cipher-brain/{identity.age,recipient.txt}

# encrypt a gbrain snapshot (pg_dump + the ~/.gbrain dir) to your PUBLIC key.
# Add a second --recipient (an OFFLINE backup public key) so losing one identity
# never loses the brain — single-key snapshots warn on stderr. See MANAGEMENT.md.
cipher-brain snapshot \
  --pg "postgres://user@localhost:5432/gbrain" \
  --dir ~/.gbrain \
  --recipient ~/.cipher-brain/recipient.txt \
  --recipient ~/.cipher-brain-backup/recipient.txt \
  --out brain-2026-06-27.age

cipher-brain verify --in brain-2026-06-27.age      # real ciphertext? wrong key rejected?

# park the ciphertext permanently on Arweave (storage only ever sees ciphertext).
# push pays a one-time bundler fee (<100 KB free) and needs a JWK wallet;
# pull is a plain gateway fetch — no wallet, no npm package.
TX=$(CIPHER_BRAIN_AR_WALLET=~/.cipher-brain/wallet.json \
  cipher-brain push --in brain-2026-06-27.age --backend turbo --yes)  # prints the locator (tx id)
cipher-brain pull --locator "$TX" --backend turbo --out got.age \
  --wait 1200    # fetch it back, anywhere (a fresh upload takes minutes to hit gateways)

# later, on the machine that holds your PRIVATE identity:
cipher-brain restore \
  --in got.age \
  --out-dir ./restored \
  --pg "postgres://user@localhost:5432/gbrain_restore"

# make it nightly + unattended: generates the runner and the launchd/cron trigger
# (paid backends require --max-spend so an unattended run can never spend uncapped)
cipher-brain schedule install --backend turbo --pg "postgres://user@localhost:5432/gbrain" \
  --dir ~/.gbrain --max-spend 500000000
cipher-brain schedule status   # last run + rc, next scheduled run
```

Not running gbrain? `--profile` is a one-flag entry point for the common
sources — it resolves to the same `--dir` assembly (extra `--dir` flags are
appended after the profile's paths) and records the profile name in the
manifest:

```sh
# Claude Code: every ~/.claude/projects/*/memory/ + ~/.claude/CLAUDE.md
# (whichever exist; errors if none do)
cipher-brain snapshot --profile claude-code --out claude-memory.age

# Obsidian: the whole vault (must contain .obsidian/; --force-vault to override)
cipher-brain snapshot --profile obsidian --vault ~/Vaults/main --out vault.age

# ChatGPT: the official data-export zip, archived as-is (never extracted)
cipher-brain snapshot --profile chatgpt-export --zip ~/Downloads/chatgpt-export.zip --out chatgpt.age
```

Each component (the `pg_dump`, each `--dir` archive) is staged into a private
(0700) temp dir, then the bundle is streamed `tar -> age`, so the final ciphertext
never loads into memory. The staged plaintext is erased even on failure, so it
doesn't linger — but staging needs scratch space about the size of the snapshot,
so point `TMPDIR` at a disk with room for large brains. The Postgres connection
string is passed as a process argument; for password auth use `~/.pgpass` or
`PGPASSWORD` so secrets stay out of the process list. Binary paths are overridable
for non-PATH installs: `CIPHER_BRAIN_PG_BIN` (dir holding
`pg_dump`/`pg_restore`), `CIPHER_BRAIN_HOME`. Storage backends read
`CIPHER_BRAIN_FILE_DIR` (file backend object store).

## Backends

`push`/`pull` are storage primitives over a pluggable backend (`--backend` is
required — there is no default). Paid pushes print a winc/AR estimate plus an
approximate USD line, and `push --skip-unchanged` skips a paid re-upload when the
snapshot's plaintext content digest (the `<out>.digest` sidecar `snapshot` writes)
matches the previous push. Three backends ship, but they are not peers:

- **`turbo` — the recommended mainline.** Uploads the ciphertext to the Arweave
  network as an ANS-104 bundled data item via a bundler (ArDrive Turbo), payable
  with **ETH/USDC** (`<100 KB` free); pushing needs `@ardrive/turbo-sdk` and a
  JWK wallet. The `locator` is the data-item id assigned after upload. Pulling
  needs neither — it is a plain HTTP read from any Arweave gateway. Funding/credit-share
  details: [`docs/arweave-upload-runbook.md`](docs/arweave-upload-runbook.md).
- **`arweave`** — the raw single-L1-transaction path to the same network, for
  small artifacts only (a ~10 MiB guard redirects anything larger to `turbo`).
- **`file`** — a local content-addressed store (no daemon, no network); used by
  CI and for local drills.

The backend abstraction is what makes the same `snapshot → push … pull → restore`
pipeline work across all three — a content-addressed (`file`) and
post-assigned-id (`arweave`/`turbo`) locators alike.

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
4. **Key recovery + versioning** (`npm run selftest:recovery`, gated in CI, no
   daemon) — encrypts a snapshot to a primary *and* an offline backup key, then
   shows the **backup key restores with the primary identity absent**, an unrelated
   identity cannot, and two snapshots restore independently. ✅
5. **Large-file / multi-chunk** (`scripts/large-file-test.sh`, operator-run) —
   runs the whole pipeline at scale through the file backend.

   Result (2026-06-27, 256 MB): snapshot streamed in 9 s at **~101 MB node RSS**
   (≪ the 256 MB input → not buffered); the `file` backend round-tripped
   byte-identical. ✅
6. **Arweave backend parity** (`npm run selftest:arweave`, gated in CI against a
   local [arlocal](https://github.com/textury/arlocal) gateway — no real AR) —
   proves the `StorageBackend` abstraction holds for a backend whose locator is an
   **Arweave tx id assigned *after* upload** (not a content hash like `file`):
   push → tx id, fetch by that id, byte-identical, decrypts; unknown id fails. ✅
   `pull` reads both plain **L1** txs and **ANS-104 bundled** data items — the form a
   bundler (Turbo/Irys) produces when you pay with **ETH/USDC/fiat** — via a gateway-HTTP
   read with an L1 chunk-read fallback, proven against *real* arweave.net by
   `node scripts/arweave-real-read.mjs` (operator-run; external, not in CI). ✅

## Managing snapshots over time

[`MANAGEMENT.md`](MANAGEMENT.md) covers cadence (`cipher-brain schedule install`
generates the nightly snapshot+push runner and its launchd/cron trigger),
versioning (each push → an immutable locator + an append-only
index — content-addressed for `file`, a tx id for `arweave`/`turbo`), the
restore runbook, and **key recovery** — the primary-plus-offline-backup
model above, so losing one identity never loses the brain.

**Durability** (will the bytes survive a year of neglect?) is a separate question from
the round-trip: [`docs/durability.md`](docs/durability.md) lays out why Arweave's
pay-once permanence (via `--backend turbo`) is the one recommended path.

## Roadmap

- **#1 Cipher** — encrypt a snapshot client-side, key only yours. ✅
- **#2 Storage** — pluggable backend, storage sees ciphertext only. `file` backend
  round-trip ✅ (CI-gated).
- **#3 Management** — key recovery (backup key, CI-proven ✅) + versioning ✅;
  cadence / restore runbook documented in [`MANAGEMENT.md`](MANAGEMENT.md).
- **Backends** — `turbo` (**recommended** — upload via a bundler, payable with
  **ETH/USDC**, `<100KB` free; operator-proven real round-trip, #20) · `arweave`
  (raw L1; parity CI-proven against arlocal ✅, #9) · `file` (local/CI ✅). The
  abstraction is validated across content-addressed *and* post-assigned-id backends.

The cipher layer is backend-agnostic by design — proven, not just asserted, now that
both a content-addressed (`file`) and a post-assigned-id (`arweave`) backend round-trip.
Arweave is the mainline because its durability is purchasable (pay once) — see
[`docs/durability.md`](docs/durability.md) for the reasoning behind that call (#60).

## MCP server

`cipher-brain-mcp` (stdio) lets an AI agent snapshot and verify its own brain by
calling the same `src/lib` functions the CLI uses:

```sh
node dist/mcp.mjs        # bundled build (npm run build), or: bin/cipher-brain-mcp.mjs
```

| Tool | Money | What it does |
|---|---|---|
| `snapshot_now` | **can spend** (paid backend) | snapshot + optional push. `arweave`/`turbo` require `confirm_paid: true` (the `--yes` guard; the `CIPHER_BRAIN_YES` env escape hatch is not honored over MCP) |
| `last_snapshot_status` | read-only | latest locator/backend/sha256/timestamp/age from a save-locator file and/or `index.tsv` |
| `verify_restore` | read-only | pull by locator (or a local file) + verify; honest `PASS`/`FAIL`/`PARTIAL` verdict mirroring the CLI exit codes |
| `estimate_cost` | read-only | upload cost for a size: turbo (winc, via the optional `@ardrive/turbo-sdk`), arweave (winston, gateway `/price`), file (free); turbo/arweave add an approximate `usd_estimate` when a USD/AR rate is fetchable |

Claude Code config (`.mcp.json`):

```json
{
  "mcpServers": {
    "cipher-brain": {
      "command": "node",
      "args": ["/path/to/cipher-brain/dist/mcp.mjs"]
    }
  }
}
```

`scripts/mcp-smoke.mjs` (part of `npm run verify`) proves initialize/tools-list,
a real `snapshot_now` round-trip on the `file` backend, and that the paid-backend
spend gate refuses without `confirm_paid`.
