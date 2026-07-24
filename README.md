# cipher-brain

```text
     ,--^--,
  /           \    hi — I encrypt your second brain so only YOUR key opens it.
 | [10]  [01] |    ( sunglasses stay on for verify PASS, slip for FAIL,
 |     -      |      one lens shifts for PARTIAL — see `verify` below )
  \___________/
```

[![CI](https://img.shields.io/github/actions/workflow/status/Masashi-Ono0611/cipher-brain/ci.yml?branch=main&label=CI&logo=github)](https://github.com/Masashi-Ono0611/cipher-brain/actions/workflows/ci.yml)

> **OpenSSF Best Practices:** the technical prerequisites (SECURITY.md,
> private vulnerability reporting, branch protection, dependency updates —
> see [#149](https://github.com/Masashi-Ono0611/cipher-brain/issues/149),
> [#184](https://github.com/Masashi-Ono0611/cipher-brain/issues/184),
> [#185](https://github.com/Masashi-Ono0611/cipher-brain/issues/185),
> [#186](https://github.com/Masashi-Ono0611/cipher-brain/issues/186)) are in
> place. Registration on [bestpractices.dev](https://www.bestpractices.dev/)
> itself (creating an account, filling out the self-assessment) is a manual
> step still pending for the maintainer — this line will become the actual
> badge once that's done.

> **For AI agents:** see [`llms.txt`](llms.txt) for a quick, machine-friendly orientation.

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

**What cipher-brain isn't:**

- Not a general-purpose backup tool — it targets one shape: encrypt a snapshot
  (gbrain, Claude Code memory, an Obsidian vault, a ChatGPT export) client-side and
  park it durably. See [`--profile`](#usage) for the sources it knows about.
- Not a key management service — there is no server holding your keys. The
  identity file is yours to keep offline; lose it and the snapshots are
  unrecoverable (see Threat model below).
- Not gbrain itself — gbrain is the second-brain product (Postgres + `~/.gbrain`)
  that produces the plaintext. cipher-brain only ever touches it long enough to
  encrypt.
- Not a crypto wallet or exchange integration — an Arweave upload goes through a
  bundler ([Turbo](https://ardrive.io)) paid with **ETH/USDC**; no native AR
  purchase and no exchange account are needed (see [Backends](#backends)).

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
wait for the cryptography to fail. age's plain X25519 recipient scheme is **not
post-quantum secure**, and rotating keys cannot protect snapshots already pushed:
the old ciphertext stays public forever. Weigh what you park against that horizon.

`keygen --pq` mitigates this: it generates a **post-quantum HYBRID keypair**
(ML-KEM-768 + X25519, via [typage](https://github.com/FiloSottile/typage)'s
`generateHybridIdentity()` — no external age plugin needed) instead of plain
X25519. A hybrid identity/recipient/ciphertext is much bigger than its X25519
counterpart (recipient ~1.9KB vs ~62 bytes; ciphertext carries a fixed ~1.4KB
per-recipient overhead), but that's negligible next to a real snapshot. It
combines normally with the existing multi-recipient mechanism (a hybrid primary +
an X25519 backup, or vice versa — either identity restores) and with
`CIPHER_BRAIN_PIN_RECIPIENTS`.

A different risk lives in the plaintext sources themselves, not the crypto:
`snapshot --scan-secrets warn|deny` runs [gitleaks](https://github.com/gitleaks/gitleaks)
over each `--dir`/`--profile` source's staged plaintext *before* it is
archived+encrypted, and `deny` refuses the whole snapshot if a component has
findings. Because Arweave/Turbo are write-once, un-deletable backends, an
accidentally-committed API key/token/password can never be scrubbed out after
the fact — the ciphertext sealing it stays parked there permanently, exposed
to whatever might compromise the identity down the line.

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

Before opening a PR: `npm run lint` (biome, `--error-on-warnings` — also gated
in CI) and `npm run verify` (build + typecheck + the full selftest suite +
CLI/MCP smoke) should both pass. `npm run format` applies biome's formatting.

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

### Quickstart

New here? `cipher-brain init` is the recommended starting point: an interactive
wizard that walks keygen, an offline backup key, passphrase-wrap,
`CIPHER_BRAIN_PIN_RECIPIENTS`, a `--profile`, a `--pg` dump when it detects a local
gbrain config, and the first snapshot + push in one sitting, ending in a printable
recovery kit (see MANAGEMENT.md's "Key recovery" section for what each step means).

```sh
cipher-brain init
```

That's it. The manual flow below is exactly what it wraps — useful once you know
what you want, or for scripting/automation `init` itself refuses (it is
interactive only).

`init` finishing, and each successful paid `push` to arweave/turbo (never a
`--skip-unchanged` no-op, and never the free `file` backend), print a short
STDERR-only note (a note from the person who built this, or a cited quote from an
encryption/privacy precursor) alongside the mascot — decoration only, never mixed
into `--save-locator`/stdout or the MCP server's output.

### Manual flow

```sh
cipher-brain keygen                 # one-time: creates ~/.cipher-brain/{identity.age,recipient.txt}
# cipher-brain keygen --pq          # or: a post-quantum HYBRID keypair (ML-KEM-768 + X25519) —
#                                     mitigates harvest-now-decrypt-later, see Threat model above

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

cipher-brain estimate --in brain-2026-06-27.age --backend turbo   # preview the cost — uploads nothing

# park the ciphertext permanently on Arweave (storage only ever sees ciphertext).
# push pays a one-time bundler fee (<100 KB free) and needs a JWK wallet;
# pull is a plain gateway fetch — no wallet, no npm package.
cipher-brain wallet create                 # one-time: writes ~/.cipher-brain/wallet.json (0600)
cipher-brain wallet address                # prints the address — fund THIS one (crypto or a card;
                                            # see docs/arweave-upload-runbook.md), then push:
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
# --ping-url adds a healthchecks.io-style dead man's switch: the runner pings it on
# success, <url>/fail on failure, so a silently-stopped schedule gets noticed.
cipher-brain schedule install --backend turbo --pg "postgres://user@localhost:5432/gbrain" \
  --dir ~/.gbrain --max-spend 500000000 --ping-url https://hc-ping.com/<uuid>
cipher-brain schedule status   # last run + rc, next scheduled run, ping-url config
```

`verify`, `estimate`, and `schedule status` each also take `--json` for a
single machine-readable object instead of the printed report — the same
fields the equivalent MCP tool (`verify_restore`/`estimate_cost`/
`schedule_status`, see below) returns, so scripts and the MCP server never
disagree.

### Profiles

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

Restoring one of these is the same `cipher-brain restore --in <file.age> --out-dir <dir>`
as any other snapshot — no `--pg` needed. `restore` auto-expands every component into
`<out-dir>/expanded/<NNN>-<encoded source path>/`, keyed to its original absolute source
path, so many same-basename sources (e.g. dozens of claude-code project `memory/` dirs)
land in separate, clearly-labeled directories instead of an undifferentiated pile of
`memory.tar.gz` / `memory-1.tar.gz` / etc — see MANAGEMENT.md's Restore runbook.

### Staging & env vars

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

### CLI reference

The full `cipher-brain --help` output, kept byte-for-byte in sync with the
`HELP` text in `src/cli.ts` by `scripts/check-help-docs.mjs` (CI-enforced —
issue #227; this section drifting out of date from real CLI behavior is what
issue #40 hit before this check existed). The `${IDENTITY}` line below shows a
fixed, synthetic `CIPHER_BRAIN_HOME` path (`/home/user/.cipher-brain`), not
your actual home directory — that keeps this block identical on every
machine, including CI.

After changing `HELP`, regenerate this block and commit the diff:

```sh
node scripts/check-help-docs.mjs --write
```

<!-- HELP-START: auto-generated by scripts/check-help-docs.mjs — do not edit by hand -->

```text
cipher-brain — encrypt a gbrain snapshot so only you can read it

  cipher-brain init
      Recommended for a FRESH setup: an interactive wizard that walks keygen -> an
      offline backup keypair (optional) -> passphrase-wrap (optional) -> a
      CIPHER_BRAIN_PIN_RECIPIENTS suggestion -> --profile selection -> the first
      snapshot + push, ending in a printable plain-text recovery kit (the backup
      identity + latest locator + exact recovery commands). Refuses if an identity
      already exists (init is for a fresh setup, not overwriting one — use keygen
      --force, or drive the commands below by hand, to redo it) and requires a TTY
      on stdin (it is interactive, not automatable).

  cipher-brain keygen [--passphrase] [--force] [--pq] | keygen --wrap-in-place
      Create your age keypair: identity (PRIVATE) + recipient (PUBLIC).
      --passphrase wraps the identity at rest with a scrypt passphrase (prompted on the
      TTY); restore/verify then prompt for it. Identity = /home/user/.cipher-brain/identity.age
      --pq generates a POST-QUANTUM HYBRID keypair (ML-KEM-768 + X25519, via typage's
      generateHybridIdentity()) instead of plain X25519 — mitigates "harvest now,
      decrypt later" against a future quantum computer (see README Threat model), at
      the cost of a MUCH bigger recipient/identity and per-recipient ciphertext
      overhead (recipient ~1.9KB vs ~62 bytes for X25519; negligible next to a real
      snapshot). Combines normally with --recipient (a hybrid primary + an X25519
      backup, or vice versa, both work — pick whichever identity "restore" is called with).
      --wrap-in-place passphrase-protects the EXISTING identity WITHOUT generating a new
      keypair (unlike --force, which always creates a brand-new one and makes every prior
      snapshot unrecoverable) — use this if you skipped the passphrase step during "init"
      or a bare keygen and want to add one later. Refuses if the identity is already
      wrapped, or if none exists yet.

  cipher-brain wallet create [--out <path>] [--force]
      Generate a fresh Arweave JWK for the arweave/turbo storage backends (needs the
      'arweave' package — a peerDependency, same as those backends). Defaults to
      $CIPHER_BRAIN_HOME/wallet.json; --out picks a different path. Prints the wallet
      path (PRIVATE) and its derived address (PUBLIC — fund THIS one). Refuses to
      overwrite an existing wallet file (same no-clobber posture as keygen); --force to
      replace it. Written 0600, same fail-closed handling as the age identity.

  cipher-brain wallet address [--wallet <path>]
      Derive and print the Arweave address a JWK spends from, without uploading
      anything. --wallet defaults to CIPHER_BRAIN_AR_WALLET, then to
      $CIPHER_BRAIN_HOME/wallet.json (the same default 'wallet create' writes to). Use
      this to confirm you are funding the SAME wallet cipher-brain will sign uploads
      with.

  cipher-brain snapshot --out <file.age> [--profile <name>] [--pg <conn>] [--pg-table <t>]... [--dir <path>]... [--recipient <pubkey|file>]... [--scan-secrets warn|deny]
      Bundle a pg_dump and/or directories, encrypt to the PUBLIC recipient(s).
      Also records a deterministic PLAINTEXT content digest (mtime-independent) in the
      manifest and in a "<out>.digest" sidecar, PLUS a recipients fingerprint (the
      effective age1… recipient set actually encrypted to) in a
      "<out>.recipients-fingerprint" sidecar — push --skip-unchanged reads BOTH
      sidecars and only skips when neither the content nor the recipient set changed,
      so it never re-pushes unchanged content to a paid store, and never skips past a
      changed --recipient set.
      Pass --recipient more than once (a primary + an offline backup key) for key
      recovery: any one of those identities can restore. The snapshotting machine
      never needs a private key.
      --profile is a one-flag source preset (recorded in the manifest); extra --dir
      flags are appended after the profile's paths:
        claude-code                  ~/.claude/projects/*/memory/ + ~/.claude/CLAUDE.md
                                     (whichever exist; errors if none do)
        obsidian --vault <path>      the vault directory (must contain .obsidian/;
                                     --force-vault to snapshot a vault-less dir anyway)
        chatgpt-export --zip <path>  the official ChatGPT export zip, archived as-is
                                     (never extracted)
      --scan-secrets warn|deny (#215) runs gitleaks (must be on PATH — install via
      https://github.com/gitleaks/gitleaks) over each --dir/--profile source's staged
      plaintext BEFORE it is archived+encrypted — Arweave/Turbo are write-once,
      un-deletable backends, so an accidentally-committed API key/token/password can
      never be scrubbed after the fact. Default (flag omitted): no scan, unchanged
      behavior. warn: log any findings (rule ID + count only — never the matched
      secret, file path, or line) and proceed. deny: refuse the whole snapshot if
      any component has findings. Drop a .gitleaks.toml into a scanned source to
      customize/allowlist rules, same as you would for a git repo.

  cipher-brain restore --in <file.age> --out-dir <dir> [--identity <file>] [--pg <conn>] [--yes] [--no-expand-components]
      Decrypt with the PRIVATE identity. Extraction never clobbers a file already
      present in --out-dir (--keep-old-files: an existing file is left untouched,
      the rest of the archive still extracts around it).
      Every --dir/--profile component's staged tarball is then auto-expanded into
      "<out-dir>/expanded/<NNN>-<encoded source path>/", keyed to the component's
      ORIGINAL absolute source path (from manifest.json) rather than its on-disk name —
      so components with a colliding basename (e.g. many claude-code project memory/
      dirs) land in separate, clearly-labeled directories instead of an undifferentiated
      pile of memory.tar.gz / memory-1.tar.gz / etc. A "expanded/README.txt" (and the
      same mapping on stdout) records which expanded directory came from which source
      path. Nothing is ever written back to that original absolute path — this only ever
      creates NEW directories under --out-dir. Re-running restore into the same
      --out-dir does not clobber a prior expansion (same no-clobber posture as the outer
      extract). --no-expand-components skips this step, leaving only the raw *.tar.gz
      files (the pre-#181 behavior).
      --pg additionally pg_restore's the db.dump into that connection, independently of
      the expand step above (pg_dump's component has no "source" field, so the two never
      touch the same thing). pg_restore --clean --if-exists DROPS and replaces objects
      in the target database — an irreversible operation — so it requires --yes or
      CIPHER_BRAIN_YES=1 to confirm, same as push's paid-backend guard below. Bounded by
      the same pipe timeout as the decrypt/extract step (CIPHER_BRAIN_PIPE_TIMEOUT).

  cipher-brain verify --in <file.age> [--identity <file>] [--sha256 <hex>] [--json]
      Assert it is real age ciphertext, a wrong key cannot open it, AND (when the
      private identity is on this box) that YOUR key decrypts it into a well-formed
      bundle. --sha256 also pins the artifact to an expected hash. VERDICT: PASS (exit 0)
      / FAIL (exit 1) / PARTIAL (exit 2 — decryptability not proven, e.g. public-key-only box).
      --json prints one JSON object to stdout instead of the human-readable report
      (file, size_bytes, checks: {age_header, sha256_match, wrong_key_rejected,
      positive_control}, verdict, exit_code) — the SAME checks computed above, so it
      never disagrees with the human-readable report or the MCP verify_restore tool.
      The exit code is unchanged either way.

  cipher-brain push --in <file.age> --backend <file|arweave|turbo|rclone> [--remote <name>:<path>] [--yes] [--save-locator <path>] [--skip-unchanged] [--digest <hex>] [--force]
      Upload ciphertext to storage. Prints ONLY the locator to stdout
      (file: store path; arweave: tx id; turbo: ANS-104 data item id; rclone: the
      --remote value itself).
      Storage sees ciphertext only.
      arweave/turbo are paid permanent stores — require --yes or CIPHER_BRAIN_YES=1;
      both print a native-unit cost estimate (winston/winc) plus an approximate USD
      line before uploading. Preview the same estimate beforehand without pushing
      anything via "cipher-brain estimate".
      --backend rclone --remote <rclone-remote-name>:<path> shells out to the
      rclone binary (rclone copyto <in> <remote>), delegating auth/protocol for
      any of rclone's 70+ supported providers to your own rclone config — cipher-
      brain implements none of them itself. Free (like file); needs rclone on
      PATH and a remote already set up via 'rclone config' (or a config-less
      on-the-fly remote, e.g. --remote ":local:/path"). --remote is required.
      --save-locator writes "<locator>\t<backend>\t<sha256>[\t<content_digest>[\t
      <recipients_fingerprint>]]" to a file (rewritten atomically each push, so it
      always holds the LATEST + an integrity pin; legacy 3/4-field files are still
      accepted everywhere). Back this file up off-box next to your identity: it is the
      durable pointer a fresh machine needs to find the most recent snapshot. (For the
      file backend the locator is a LOCAL store path — arweave/turbo locators are
      always portable to another machine; an rclone locator is portable too, PROVIDED
      the same remote name is configured there — a config-less ":local:/path" remote
      is as machine-local as the file backend.)
      --skip-unchanged (requires --save-locator): skips ONLY when BOTH (a) the
      snapshot's PLAINTEXT content digest — read from the "<in>.digest" sidecar
      snapshot writes, or given as --digest <hex> — equals the content_digest recorded
      in the save-locator file for the same backend, AND (b) the recipients
      fingerprint — read from the "<in>.recipients-fingerprint" sidecar — equals the
      recipients_fingerprint recorded there too. Requiring both means a re-snapshot of
      unchanged plaintext under a CHANGED --recipient set (a newly added recovery key,
      a removed/revoked key) is never skipped. When both match: print SKIPPED + the
      previous locator and exit 0 WITHOUT contacting storage or spending. Any missing
      piece on EITHER side (no sidecar, a legacy 3/4-field file, a different backend)
      just pushes normally: skip is an optimization, never a gate. --force uploads even
      when unchanged. (The digest is plaintext-side by necessity: age's ephemeral file
      key makes identical content encrypt to different ciphertext bytes every run.)

  cipher-brain estimate --in <file.age> --backend <file|arweave|turbo|rclone> [--json]
      Read-only preview: print what pushing --in to --backend would cost WITHOUT
      uploading anything. turbo/arweave show the native unit (winc/winston) plus
      an approximate USD line when a USD/AR rate is fetchable; file and rclone are
      always reported as free (rclone's actual transfer/storage cost, if any, is
      whatever the operator's own cloud contract for that remote charges — cipher-
      brain cannot query it). Sizes --in the same way push does (a real byte count
      off disk). The SAME computation backs the MCP estimate_cost tool, so the two
      never disagree.
      --json prints the same CostEstimate object as one JSON line on stdout
      (backend, size_bytes, cost, unit, approx_ar, usd_estimate, note) instead of
      the human-readable report — field-for-field identical to what estimate_cost
      returns.

  cipher-brain pull (--locator <id> --backend <…> | --remote <name>:<path> --backend rclone | --from-locator-file <path>) --out <file.age> [--wait <seconds>] [--sha256 <hex>] [--force]
      Fetch ciphertext by locator into --out. --from-locator-file reads the locator, its
      backend AND the saved sha256 from a file written by push --save-locator (the recovery
      path: identity + this file are all a fresh machine needs; the saved sha256 is applied
      as the integrity pin automatically). --wait retries while the item is not yet
      retrievable (a fresh Turbo/Arweave upload takes ~5-8 min to propagate); default 0.
      --sha256 fail-closes the fetch: the bytes must match the expected hash (sourced
      out-of-band from a trusted index) or pull errors, having written nothing to --out.
      No-clobber by default: refuses to overwrite an existing --out (the recovery steps
      above reuse a fixed filename, so a second pull could otherwise destroy the first
      one's result) — pass --force to overwrite it anyway.
      --backend rclone accepts --remote <name>:<path> in place of --locator (the
      rclone backend's locator IS that string — see push's rclone section above);
      an explicit --locator still wins if both are given.

  cipher-brain schedule install --backend <file|arweave|turbo> [--at HH:MM] [--max-spend <n>] [--no-load]
                                [--profile <name>] [--pg <conn>] [--pg-table <t>]... [--dir <path>]... [--recipient <pubkey|file>]...
                                [--vault <path>] [--zip <path>] [--save-locator <path>] [--index-file <path>]
                                [--ping-url <url>] [--ping-url-fail <url>]
      Make the nightly snapshot+push unattended. Writes a runner script
      ($CIPHER_BRAIN_HOME/schedule/nightly.sh) composing the snapshot/push pipeline from
      the SAME flags those commands take — dated outputs, --save-locator, an index.tsv
      append — plus the platform trigger (macOS: a launchd plist in ~/Library/LaunchAgents;
      Linux: a crontab entry), and registers it. Default --at 03:30: run well after the
      source re-synthesizes overnight so the DB and files are captured from the same
      settled state (MANAGEMENT.md, "Avoid the write window"). Paid backends
      (arweave/turbo) REQUIRE --max-spend <n>: the runner gets CIPHER_BRAIN_YES=1 for the
      unattended consent, so it must also get a CIPHER_BRAIN_MAX_SPEND cap — an uncapped
      unattended spender is refused. --no-load writes the artifacts without registering.
      Each run logs to $CIPHER_BRAIN_HOME/schedule/logs/nightly-YYYY-MM-DD.log, ending
      "OK rc=0" or "FAILED rc=N".
      --ping-url <url> adds a healthchecks.io-style dead man's switch: the runner curl's
      <url> (best-effort, 10s timeout, never affects the run's own outcome) on every
      successful run, and <url>/fail on every failed run — so a schedule that silently
      stops running (a wedged launchd/cron, a box left off) gets noticed even without
      anyone running 'schedule status'. --ping-url-fail overrides the failure URL
      (default: <url>/fail — a plain string append, not URL-aware: pass --ping-url-fail
      explicitly if your ping URL has a query string or a trailing slash); it requires
      --ping-url to also be set.

  cipher-brain schedule status [--json]
      Report the configured time + backend, whether a dead man's switch ping-url is
      configured, the trigger load state, the last run log and its final rc line, and the
      next scheduled run.
      --json prints one JSON object to stdout instead of the human-readable report
      (configured, runner, ping, trigger: {type, loaded, legacy, ...}, last_run,
      next_run) — the SAME state read above, so it never disagrees with the
      human-readable report or the MCP schedule_status tool.

  cipher-brain schedule uninstall
      Unregister the trigger and remove the generated runner/plist/cron entry (idempotent;
      logs, snapshots and index.tsv are kept — they are your data).

Env: CIPHER_BRAIN_HOME (default ~/.cipher-brain), CIPHER_BRAIN_PG_BIN (dir of pg_dump/pg_restore).
     CIPHER_BRAIN_SCHEDULE_DIR (schedule artifacts/logs dir; default $CIPHER_BRAIN_HOME/schedule).
     CIPHER_BRAIN_LAUNCHD_DIR (macOS only: where 'schedule install' writes the launchd plist;
     default ~/Library/LaunchAgents — a REAL system dir, NOT scoped to CIPHER_BRAIN_HOME, written
     even under --no-load; override to sandbox a --no-load preview run).
     CIPHER_BRAIN_PASSPHRASE (non-interactive passphrase for a wrapped identity — automation/CI; otherwise prompted on the TTY).
     CIPHER_BRAIN_PIN_RECIPIENTS (snapshot: allowlist of age1… pubkeys, inline or a file — refuse to encrypt to any other recipient).
     CIPHER_BRAIN_INIT_ALLOW_NONINTERACTIVE=1 (init: bypass its TTY requirement — automation/CI only, e.g. this repo's own selftest; a human just runs init directly in a terminal).
Storage: CIPHER_BRAIN_FILE_DIR (file);
         CIPHER_BRAIN_AR_{HOST,PORT,PROTOCOL,WALLET,GATEWAY,GATEWAYS,HTTP_TIMEOUT} (arweave; CIPHER_BRAIN_AR_WALLET is a path to a JWK key file — 'cipher-brain wallet create' generates one, 'wallet address' shows what to fund; the 'arweave' npm package is needed only to PUSH or for the rare L1 chunk fallback — a gateway pull needs none);
         turbo: CIPHER_BRAIN_AR_WALLET (JWK signer) + optional CIPHER_BRAIN_AR_PAID_BY (an address sharing Turbo Credits to that signer); needs '@ardrive/turbo-sdk' to PUSH (a pull reuses the arweave gateway read, no SDK). Funding/credit-share details: docs/arweave-upload-runbook.md.
         rclone: CIPHER_BRAIN_RCLONE_BIN (path to the rclone binary; default 'rclone' on PATH) — the remote itself is whatever --remote <name>:<path> names in your own 'rclone config'.
Spend: arweave/turbo PUSH needs --yes or CIPHER_BRAIN_YES=1 (paid, permanent); CIPHER_BRAIN_MAX_SPEND caps the arweave/turbo cost estimate (winston/winc).
Consent: restore --pg (pg_restore --clean --if-exists, irreversible) needs --yes or CIPHER_BRAIN_YES=1.
```

<!-- HELP-END -->

## Backends

`push`/`pull` are storage primitives over a pluggable backend (`--backend` is
required — there is no default). Paid pushes print a cost estimate before
uploading — both turbo (winc) and arweave (winston) show an approximate USD line
alongside the native unit. Preview that same estimate WITHOUT pushing anything via
`cipher-brain estimate --in <file.age> --backend <backend>` (also exposed as the
`estimate_cost` MCP tool — see below); `push --skip-unchanged` skips a paid
re-upload when the snapshot's plaintext content digest (the `<out>.digest`
sidecar `snapshot` writes) matches the previous push. Four backends ship, but
they are not peers:

- **`turbo` — the recommended mainline.** Uploads the ciphertext to the Arweave
  network as an ANS-104 bundled data item via a bundler (ArDrive Turbo), payable
  with **ETH/USDC** (`<100 KB` free); pushing needs `@ardrive/turbo-sdk` and a
  JWK wallet — `cipher-brain wallet create` generates one, `cipher-brain wallet
  address` prints what to fund. The `locator` is the data-item id assigned after
  upload. Pulling needs neither — it is a plain HTTP read from any Arweave gateway.
  Funding/credit-share details: [`docs/arweave-upload-runbook.md`](docs/arweave-upload-runbook.md).
- **`arweave`** — the raw single-L1-transaction path to the same network, for
  small artifacts only (a ~10 MiB guard redirects anything larger to `turbo`).
- **`file`** — a local content-addressed store (no daemon, no network); used by
  CI and for local drills.
- **`rclone`** — a thin subprocess wrapper around the `rclone` binary
  (`push --backend rclone --remote <rclone-remote-name>:<path>`), the same
  "delegate to rclone" pattern restic/kopia use to reach 70+ cloud providers
  (S3, GCS, B2, Azure Blob, Dropbox, SFTP, …) without cipher-brain implementing
  any of their APIs itself — auth/protocol/retries are entirely rclone's own
  configured remote (`rclone config`). Free like `file` (`estimate` always
  reports cost `0` — any real transfer/storage cost is whatever your own cloud
  contract for that remote charges); the locator IS the `<remote>:<path>`
  string. A cheap way to add an offsite copy (the "1" in 3-2-1 backup) next to
  `turbo`'s permanent store, reusing an rclone config you may already have from
  restic/kopia. Needs the `rclone` binary on PATH.

The backend abstraction is what makes the same `snapshot → push … pull → restore`
pipeline work across all four — locators known before upload (`file`'s content
hash, `rclone`'s caller-chosen `--remote`) and post-assigned-id ones
(`arweave`/`turbo`) alike.

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

**When something fails**, the most common failure patterns print with a stable
`[CB-E0xx]` code and a pointer to [`MANAGEMENT.md`'s error code table](MANAGEMENT.md#error-codes)
(cause + next action for each) — the same shape ngrok uses for its own errors.

## Roadmap

- **#1 Cipher** — encrypt a snapshot client-side, key only yours. ✅
- **#2 Storage** — pluggable backend, storage sees ciphertext only. `file` backend
  round-trip ✅ (CI-gated).
- **#3 Management** — key recovery (backup key, CI-proven ✅) + versioning ✅;
  cadence / restore runbook documented in [`MANAGEMENT.md`](MANAGEMENT.md).
- **Backends** — `turbo` (**recommended** — upload via a bundler, payable with
  **ETH/USDC**, `<100KB` free; operator-proven real round-trip, #20) · `arweave`
  (raw L1; parity CI-proven against arlocal ✅, #9) · `file` (local/CI ✅) ·
  `rclone` (delegates to the `rclone` binary's own configured remote, #204/#233,
  CI-proven ✅). The abstraction is validated across content-addressed *and*
  post-assigned-id backends.

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
| `estimate_cost` | read-only | upload cost for a size: turbo (winc, via the optional `@ardrive/turbo-sdk`), arweave (winston, gateway `/price`), file (free); turbo/arweave add an approximate `usd_estimate` when a USD/AR rate is fetchable — a direct HTTP call to Turbo's public rate endpoint (#170), so it works with or without `@ardrive/turbo-sdk` installed. Same computation as `cipher-brain estimate` (`src/lib/estimate.ts`) |
| `schedule_status` | read-only | the same report as `cipher-brain schedule status`: configured time/backend, trigger registration state, last run log + its final rc line, next scheduled run |
| `keygen` | **writes a keypair** (no spend) | generate a fresh age identity/recipient keypair at `<CIPHER_BRAIN_HOME>/{identity.age,recipient.txt}` — first-run setup for a shell-less agent. `pq: true` generates a post-quantum HYBRID keypair (ML-KEM-768 + X25519) instead of plain X25519. Refuses if one already exists unless `force: true` (destructive — discards the old identity) |
| `wallet_create` | **writes a wallet** (no spend) | generate a fresh Arweave JWK wallet (default `<CIPHER_BRAIN_HOME>/wallet.json`, `out` overrides). Refuses if one already exists at the target path unless `force: true` (destructive — discards spend authority over any funds already sent to it) |
| `wallet_address` | read-only | derive and show the Arweave address for a JWK wallet file (the address to fund before pushing to `arweave`/`turbo`) |

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
a real `snapshot_now` round-trip on the `file` backend, `schedule_status` against a
`--no-load` schedule installed via the CLI, that the paid-backend spend gate
refuses without `confirm_paid`, and a real `keygen` → `wallet_create` → `wallet_address`
round-trip (plus the no-clobber-unless-`force` refusal) against an isolated
`CIPHER_BRAIN_HOME`.

## Project continuity

`cipher-brain` is currently maintained by a single person
([@Masashi-Ono0611](https://github.com/Masashi-Ono0611)). There is no formal
succession plan or pre-granted collaborator/npm-publish access at this time.

If you need to reach the maintainer about something urgent — a security
issue, or the project appearing unmaintained for an extended period — use
GitHub's private vulnerability reporting (see [`SECURITY.md`](SECURITY.md))
for security matters, or open a public issue otherwise. There is no other
published contact channel.
