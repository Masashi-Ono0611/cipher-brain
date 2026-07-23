// cipher-brain — encrypt a gbrain snapshot so only the key holder can read it.
//
// Threat model: the always-on machine (e.g. the Mac mini that runs gbrain) holds
// ONLY the recipient PUBLIC key, so it can produce snapshots but can never read
// them. The private identity — the "key only mine" — lives off the always-on box
// and is the sole thing that can restore. Compromising the snapshotting machine
// therefore leaks no brain content.
//
// Crypto: age (X25519 + ChaCha20-Poly1305) via typage (npm `age-encryption`,
// FiloSottile's official TypeScript implementation), bundled into the CLI — no
// external `age` binary is needed, and the format stays byte-compatible with it.
// Each component (the pg_dump, each directory archive) is staged into a private
// (0700) temp dir, then the bundle is streamed `tar -> age` so the final ciphertext
// never loads into memory. The staged plaintext is erased on a normal failure (the
// snapshot finally-block) AND on Ctrl-C / SIGTERM / SIGHUP (a signal handler that
// rmSync's the active stage dir, since a signal tears the process down without
// unwinding the finally), so it doesn't linger. Staging needs scratch space ~the
// size of the snapshot, so point TMPDIR at a disk with room for large brains.
//
// Backend-agnostic: this produces ONE encrypted artifact (`*.age`). Where those
// bytes get parked (Arweave / anything) is a separate, pluggable concern —
// storage only ever sees ciphertext.
//
// This entry point holds arg parsing + command dispatch; the implementation lives
// in src/lib/ (config, proc, util, signal-guard, identity, snapshot, restore,
// pushpull, backends/).

import { IDENTITY } from './lib/config.js';
import { keygen } from './lib/keys.js';
import { snapshot } from './lib/snapshot.js';
import { restore, verify } from './lib/restore.js';
import { push, pull } from './lib/pushpull.js';
import { schedule } from './lib/schedule.js';
import { wallet } from './lib/wallet.js';
import { estimate } from './lib/estimate.js';
import { init } from './lib/wizard.js';
import { errMsg } from './lib/util.js';
import { printMascot } from './lib/ui.js';
import { printFounderNote, printWisdomQuote } from './lib/wisdom.js';
import type { CliOptions } from './lib/types.js';

const BOOL_FLAGS = new Set(['force', 'passphrase', 'wrap_in_place', 'yes', 'force_vault', 'skip_unchanged', 'no_load']); // flags that take no value

function parseArgs(argv: string[]): CliOptions {
  const o: CliOptions = { dirs: [], tables: [], recipients: [] };
  const rec = o as unknown as Record<string, string | boolean | undefined>;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--dir') o.dirs.push(argv[++i]);
    else if (a === '--pg-table') o.tables.push(argv[++i]);
    else if (a === '--recipient')
      o.recipients.push(argv[++i]); // repeatable: key recovery
    else if (a.startsWith('--')) {
      const key = a.slice(2).replace(/-/g, '_');
      rec[key] = BOOL_FLAGS.has(key) ? true : argv[++i];
    } else o._ = a;
  }
  return o;
}

const HELP = `cipher-brain — encrypt a gbrain snapshot so only you can read it

  cipher-brain init
      Recommended for a FRESH setup: an interactive wizard that walks keygen -> an
      offline backup keypair (optional) -> passphrase-wrap (optional) -> a
      CIPHER_BRAIN_PIN_RECIPIENTS suggestion -> --profile selection -> the first
      snapshot + push, ending in a printable plain-text recovery kit (the backup
      identity + latest locator + exact recovery commands). Refuses if an identity
      already exists (init is for a fresh setup, not overwriting one — use keygen
      --force, or drive the commands below by hand, to redo it) and requires a TTY
      on stdin (it is interactive, not automatable).

  cipher-brain keygen [--passphrase] [--force] | keygen --wrap-in-place
      Create your age keypair: identity (PRIVATE) + recipient (PUBLIC).
      --passphrase wraps the identity at rest with a scrypt passphrase (prompted on the
      TTY); restore/verify then prompt for it. Identity = ${IDENTITY}
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

  cipher-brain snapshot --out <file.age> [--profile <name>] [--pg <conn>] [--pg-table <t>]... [--dir <path>]... [--recipient <pubkey|file>]...
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

  cipher-brain restore --in <file.age> --out-dir <dir> [--identity <file>] [--pg <conn>] [--yes]
      Decrypt with the PRIVATE identity. Extraction never clobbers a file already
      present in --out-dir (--keep-old-files: an existing file is left untouched,
      the rest of the archive still extracts around it).
      --pg additionally pg_restore's the db.dump into that connection. pg_restore
      --clean --if-exists DROPS and replaces objects in the target database — an
      irreversible operation — so it requires --yes or CIPHER_BRAIN_YES=1 to confirm,
      same as push's paid-backend guard below. Bounded by the same pipe timeout as
      the decrypt/extract step (CIPHER_BRAIN_PIPE_TIMEOUT).

  cipher-brain verify --in <file.age> [--identity <file>] [--sha256 <hex>]
      Assert it is real age ciphertext, a wrong key cannot open it, AND (when the
      private identity is on this box) that YOUR key decrypts it into a well-formed
      bundle. --sha256 also pins the artifact to an expected hash. VERDICT: PASS (exit 0)
      / FAIL (exit 1) / PARTIAL (exit 2 — decryptability not proven, e.g. public-key-only box).

  cipher-brain push --in <file.age> --backend <file|arweave|turbo> [--yes] [--save-locator <path>] [--skip-unchanged] [--digest <hex>] [--force]
      Upload ciphertext to storage. Prints ONLY the locator to stdout
      (file: store path; arweave: tx id; turbo: ANS-104 data item id).
      Storage sees ciphertext only.
      arweave/turbo are paid permanent stores — require --yes or CIPHER_BRAIN_YES=1;
      both print a native-unit cost estimate (winston/winc) plus an approximate USD
      line before uploading. Preview the same estimate beforehand without pushing
      anything via "cipher-brain estimate".
      --save-locator writes "<locator>\\t<backend>\\t<sha256>[\\t<content_digest>[\\t
      <recipients_fingerprint>]]" to a file (rewritten atomically each push, so it
      always holds the LATEST + an integrity pin; legacy 3/4-field files are still
      accepted everywhere). Back this file up off-box next to your identity: it is the
      durable pointer a fresh machine needs to find the most recent snapshot. (For the
      file backend the locator is a LOCAL store path — only arweave/turbo locators
      are portable to another machine.)
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

  cipher-brain estimate --in <file.age> --backend <file|arweave|turbo>
      Read-only preview: print what pushing --in to --backend would cost WITHOUT
      uploading anything. turbo/arweave show the native unit (winc/winston) plus
      an approximate USD line when a USD/AR rate is fetchable; file is always free.
      Sizes --in the same way push does (a real byte count off disk). The SAME
      computation backs the MCP estimate_cost tool, so the two never disagree.

  cipher-brain pull (--locator <id> --backend <…> | --from-locator-file <path>) --out <file.age> [--wait <seconds>] [--sha256 <hex>] [--force]
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

  cipher-brain schedule status
      Report the configured time + backend, whether a dead man's switch ping-url is
      configured, the trigger load state, the last run log and its final rc line, and the
      next scheduled run.

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
Spend: arweave/turbo PUSH needs --yes or CIPHER_BRAIN_YES=1 (paid, permanent); CIPHER_BRAIN_MAX_SPEND caps the arweave/turbo cost estimate (winston/winc).
Consent: restore --pg (pg_restore --clean --if-exists, irreversible) needs --yes or CIPHER_BRAIN_YES=1.`;

async function main(): Promise<void> {
  const [cmd, ...rest] = process.argv.slice(2);
  // `<subcommand> --help` / `-h` must show help instead of running the
  // subcommand (issue #171) — checked on the raw args, BEFORE parseArgs(),
  // so it applies uniformly to every subcommand (not just the bare
  // `cipher-brain --help` handled by the switch below) and keeps working
  // even if parseArgs() is ever changed to validate/throw on bad input
  // (multi-model review finding).
  if (rest.includes('--help') || rest.includes('-h')) {
    printMascot('neutral');
    console.log(HELP);
    return;
  }
  const o = parseArgs(rest);
  switch (cmd) {
    case 'init':
      // A note from the person who built this, right after the wizard's own
      // completion summary above (issue #195) — CLI-only: init has no MCP
      // tool, so this never touches an agent's machine-readable output.
      await init(o);
      printMascot('happy');
      printFounderNote();
      return;
    case 'keygen':
      return keygen(o);
    case 'snapshot':
      return snapshot(o);
    case 'restore':
      return restore(o);
    case 'verify':
      return verify(o);
    case 'push': {
      // push() is shared with the MCP server (src/mcp.ts) and the init wizard
      // (wizard.ts), both of which capture its console.error output as
      // machine-readable data — so the mood mascot (issue #194) is printed HERE,
      // at the CLI-only dispatch site, rather than inside push() itself, where it
      // would otherwise leak the ASCII art into an MCP tool result's `log` field.
      // Decoration only, on stderr (see printMascot in ui.ts).
      let uploaded: boolean;
      try {
        uploaded = await push(o);
      } catch (e) {
        printMascot('sad');
        throw e;
      }
      printMascot('happy');
      // A cited precursor quote after a successful upload to a PAID,
      // permanent backend only (issue #195) — never the free `file` backend,
      // and never a --skip-unchanged run that hit its early SKIPPED return
      // (uploaded === false there — push()'s own doc comment in pushpull.ts).
      // CLI-only: mcp.ts calls push() directly (not through this dispatch),
      // so an MCP push never gets this decoration mixed into its result.
      if (uploaded && (o.backend === 'arweave' || o.backend === 'turbo')) {
        printWisdomQuote();
      }
      return;
    }
    case 'pull':
      return pull(o);
    case 'estimate':
      return estimate(o);
    case 'schedule':
      return schedule(o);
    case 'wallet':
      return wallet(o);
    // mascot on stderr (decoration only, EPIPE-safe — see printMascot in
    // ui.ts), HELP text stays on stdout so `cipher-brain --help | grep …`
    // still sees only the HELP text on its stdin.
    case 'help':
    case '--help':
    case '-h':
    case undefined:
      printMascot('neutral');
      console.log(HELP);
      return;
    default:
      console.error(`unknown command: ${cmd}\n`);
      console.log(HELP);
      process.exitCode = 2;
  }
}

main().catch((e: unknown) => {
  console.error(`error: ${errMsg(e)}`);
  process.exitCode = 1;
});
