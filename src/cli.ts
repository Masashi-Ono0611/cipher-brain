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

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { IDENTITY, CONFIG_FILE_ERROR } from './lib/config.js';
import { keygen } from './lib/keys.js';
import { snapshot } from './lib/snapshot.js';
import { restore, verify } from './lib/restore.js';
import { push, pull } from './lib/pushpull.js';
import { schedule } from './lib/schedule.js';
import { wallet } from './lib/wallet.js';
import { estimate } from './lib/estimate.js';
import { init } from './lib/wizard.js';
import { errMsg } from './lib/util.js';
import { annotateErrorMessage, matchErrorCode } from './lib/errors.js';
import { didYouMean } from './lib/suggest.js';
import { hasWrittenJson, printMascot } from './lib/ui.js';
import { printFounderNote, printWisdomQuote } from './lib/wisdom.js';
import type { CliOptions } from './lib/types.js';

const BOOL_FLAGS = new Set([
  'force',
  'passphrase',
  'wrap_in_place',
  'yes',
  'force_vault',
  'skip_unchanged',
  'no_load',
  'no_expand_components',
  'pq',
  'dry_run',
  'json',
  'sign',
  'no_sign',
  'require_signature',
]); // flags that take no value

// Value flags (always a string when passed) — kept in sync with CliOptions
// (src/lib/types.ts), which is the authoritative list of every field a command
// actually reads. `dir`/`pg-table`/`pg-exclude-table-data`/`recipient` are NOT
// listed here: they're repeatable array flags handled by their own branches
// below, before this set is ever consulted.
const VALUE_FLAGS = new Set([
  'out',
  'out_dir',
  'profile',
  'vault',
  'zip',
  'export',
  'pg',
  'pg_filter',
  'in',
  'identity',
  'sha256',
  'backend',
  'remote',
  'digest',
  'save_locator',
  'locator',
  'scan_secrets',
  'from_locator_file',
  'sign_identity',
  'sign_recipient',
  'sig_locator',
  'wait',
  'at',
  'max_spend',
  'index_file',
  'wallet',
  'ping_url',
  'ping_url_fail',
]);

function parseArgs(argv: string[]): CliOptions {
  const o: CliOptions = { dirs: [], tables: [], recipients: [] };
  const rec = o as unknown as Record<string, string | boolean | undefined>;
  // A value-taking flag whose value is MISSING used to read its value off the end of the
  // array (or off the next flag), i.e. `undefined` — which then looks exactly like "the
  // flag was never passed" to every reader downstream. For a REQUIRED flag that surfaces
  // as a confusing but safe "--x required"; for an OPTIONAL one it is silent, which is the
  // same "asked for a gate, got none" failure #307 is about. Two shapes, both found by
  // multi-model review, both refused here by naming the flag:
  //
  //   snapshot --dir src --out --scan-secrets deny   -> --out swallowed "--scan-secrets",
  //                                                     scan_secrets stayed undefined, and
  //                                                     the snapshot ran UNSCANNED into a
  //                                                     file literally named --scan-secrets
  //   schedule install … --scan-secrets              -> exit 0, runner with no scan at all
  //
  // "Looks like a flag" is ANY token starting with "--", not just a recognized one. An
  // earlier revision only rejected recognized names, and review found the hole that
  // leaves: `--out --scan-secret deny` (note the typo) is not a name this CLI knows, so
  // it was swallowed as --out's value — writing an unscanned snapshot to a file called
  // "--scan-secret" and never reaching the unknown-flag refusal (#253) that exists to
  // catch exactly that typo. A value that genuinely begins with "--" is pathological
  // enough to be worth an explicit "./--name", which the message suggests.
  const valueAt = (i: number, flag: string): string => {
    if (i >= argv.length) throw new Error(`${flag} requires a value (run 'cipher-brain --help' for the expected form)`);
    if (argv[i].startsWith('--'))
      throw new Error(
        `${flag} requires a value, but the next argument looks like another flag (${argv[i]}) — ` +
          `it was NOT consumed as ${flag}'s value. Give ${flag} its value, or write "./${argv[i]}" if you really ` +
          `meant a path by that name.`,
      );
    return argv[i];
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--dir') o.dirs.push(valueAt(++i, a));
    else if (a === '--pg-table') o.tables.push(valueAt(++i, a));
    else if (a === '--pg-exclude-table-data') {
      if (!o.pg_exclude_table_data) o.pg_exclude_table_data = [];
      o.pg_exclude_table_data.push(valueAt(++i, a));
    } else if (a === '--recipient')
      o.recipients.push(valueAt(++i, a)); // repeatable: key recovery
    else if (a.startsWith('--')) {
      const key = a.slice(2).replace(/-/g, '_');
      // issue #253: an unrecognized/mistyped --flag used to be silently stored
      // on `o` and then just never read by any command — no error, just quiet
      // wrong behavior (the same bug class as #96/#101/#114). Refuse instead.
      if (!BOOL_FLAGS.has(key) && !VALUE_FLAGS.has(key)) {
        throw new Error(
          `unknown flag: --${a.slice(2)} (run 'cipher-brain --help' or '<command> --help' to see valid flags)`,
        );
      }
      rec[key] = BOOL_FLAGS.has(key) ? true : valueAt(++i, a);
    } else o._ = a;
  }
  return o;
}

const HELP = `cipher-brain — encrypt a gbrain snapshot so only you can read it

  cipher-brain --version
      Print the version this build was packaged with (the "version" field of the
      installed package.json) on stdout and exit 0 — nothing else, so it can be
      captured straight into a variable. "-V" is the same thing.

  cipher-brain <command> --help
      Print just that command's section of this reference (plus the Env/Storage/
      Spend/Consent block below, which applies to every command). Plain
      "cipher-brain --help" prints the whole thing, as it does here.

  cipher-brain init
      Recommended for a FRESH setup: an interactive wizard that walks keygen -> an
      offline backup keypair (optional) -> passphrase-wrap (optional) -> a
      CIPHER_BRAIN_PIN_RECIPIENTS suggestion -> --profile selection -> the first
      snapshot + push, ending in a printable plain-text recovery kit (the backup
      identity + latest locator + exact recovery commands). Refuses if an identity
      already exists (init is for a fresh setup, not overwriting one — use keygen
      --force, or drive the commands below by hand, to redo it) and requires a TTY
      on stdin (it is interactive, not automatable).

  cipher-brain keygen [--passphrase] [--force] [--pq] | keygen --wrap-in-place | keygen --sign
      Create your age keypair: identity (PRIVATE) + recipient (PUBLIC).
      --passphrase wraps the identity at rest with a scrypt passphrase (prompted on the
      TTY); restore/verify then prompt for it. Identity = ${IDENTITY}
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
      --sign (#214) generates a SEPARATE minisign-compatible Ed25519 SIGNING keypair
      instead of an age keypair — an independent mode (like --wrap-in-place; the two are
      mutually exclusive), so it can add authenticity to an existing setup without
      touching the age identity at all. age gives confidentiality + tamper detection but
      NOT authenticity (a recipient's public key is not secret — anyone holding it can
      forge ciphertext that decrypts cleanly); signing the *.age ciphertext and verifying
      BEFORE decrypt (see restore/verify below) closes that gap. Writes
      $CIPHER_BRAIN_HOME/sign-identity.key (PRIVATE) and sign-recipient.pub (PUBLIC, in
      the reference minisign CLI's own wire format — verifiable with a real
      "minisign -V -p sign-recipient.pub"). --passphrase/--force apply to it the same way
      they do to the age identity above; --wrap-in-place does not (age-only).

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

  cipher-brain snapshot --out <file.age> [--profile <name>] [--pg <conn>] [--pg-table <t>]...
                         [--pg-filter <file>] [--pg-exclude-table-data <t>]... [--dir <path>]...
                         [--recipient <pubkey|file>]... [--dry-run] [--scan-secrets warn|deny|off]
                         [--no-sign] [--sign-identity <file>]
      Bundle a pg_dump and/or directories, encrypt to the PUBLIC recipient(s).
      A ".cipherbrainignore" file (gitignore-compatible syntax; the "ignore" npm package
      does the matching, not a hand-rolled glob) at the ROOT of a --dir (or a --profile-
      resolved directory) filters what gets archived from that directory — node_modules,
      caches, credential files etc. never need to be tar'd, encrypted or paid for. No file
      -> unchanged behavior (every path is archived, exactly as before #216). A single-file
      --dir source (a --profile file/zip) is archived as-is; it has no tree to filter.
      --dry-run previews --dir/--profile filtering WITHOUT writing, staging or encrypting
      anything (--out is not required): prints, per --dir, whether a .cipherbrainignore was
      found and the include/exclude file list with an approximate byte total for each side
      — the "capacity difference" a --recipient/--pg pipeline never touches until you drop
      --dry-run and actually run the snapshot.
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
        o2b --export <path>          an Open Second Brain bank-export bundle
                                     ("o2b brain bank-export --out <path>.json"), archived
                                     as-is (never extracted; must end in .json)
      --pg-filter <file> and --pg-exclude-table-data <table> are a thin, literal pass-through
      to pg_dump's OWN standard flags (--filter / --exclude-table-data) — cipher-brain does
      no SQL parsing or filtering of its own; pg_dump does exactly what it would if you ran
      it by hand with the same flags. Use them to build a "minimal recovery profile" snapshot
      alongside your normal full one: exclude large/low-value tables (raw conversation logs,
      embedding caches, tool-run logs) while keeping table structure and everything else.
      --pg-filter <file>            pg_dump --filter <file>: a file of one
                                     "{include|exclude} {table|schema} PATTERN" line per
                                     entry (repeatable in --pg-table); requires pg_dump >= 17.
                                     Docs: https://www.postgresql.org/docs/current/app-pgdump.html#PG-DUMP-FILTERING
                                     Example file:
                                       include table conversation_summaries
                                       exclude table conversation_logs
                                       exclude table embedding_cache
      --pg-exclude-table-data <t>   pg_dump --exclude-table-data <t> (repeatable): keep the
                                     table's SCHEMA in the dump but drop its ROWS — e.g. a
                                     large cache table you want restorable-empty rather than
                                     absent entirely.
      Both are additive to --pg-table and to each other; omit them and --pg behaves exactly
      as before (a full pg_dump, no filtering).
      --scan-secrets warn|deny|off (#215) runs gitleaks (install via
      https://github.com/gitleaks/gitleaks) over each --dir/--profile source's staged
      plaintext BEFORE it is archived+encrypted — Arweave/Turbo are write-once,
      un-deletable backends, so an accidentally-committed API key/token/password can
      never be scrubbed after the fact. DEFAULT (#301): warn, whenever there is a
      --dir/--profile source AND gitleaks is resolvable; otherwise nothing scans,
      nothing errors, and no new dependency appears. This is the only path that may
      skip quietly — you did not ask for a gate, so nothing claims one ran. An
      EXPLICIT --scan-secrets that cannot scan always refuses instead.
      warn: log any findings (rule ID + count only — never the matched
      secret, file path, or line) and proceed. deny: refuse the whole snapshot if
      any component has findings. off: do not scan, said out loud — the way to turn
      the default off without uninstalling gitleaks.
      Drop a .gitleaks.toml into a scanned source to
      customize/allowlist rules, same as you would for a git repo. It covers
      --dir/--profile sources only — a --pg dump is not scanned — so a snapshot with
      neither is REFUSED rather than reporting a scan that inspected no component.
      For the same reason it cannot be combined with --dry-run, which stages no
      plaintext for gitleaks to look at.
      KNOWN LIMIT, so you can judge what the gate is worth for your sources: gitleaks
      reads files as they are and does NOT look inside archives, so a zip/tar source
      (notably --profile chatgpt-export or --profile o2b, which archive their export
      zip/bundle as-is) is scanned only as opaque bytes — a secret inside it will NOT
      be found, even though the run reports the mode. Extract such an export and snapshot the
      directory if you want the gate to actually cover its contents.
      Authenticity (#214): whenever a signing identity exists (default
      $CIPHER_BRAIN_HOME/sign-identity.key, from "keygen --sign"; --sign-identity picks
      a different one), snapshot ALSO writes a detached "<out>.minisig" signature over
      the ciphertext — automatic, no separate flag needed. restore/verify then check it
      BEFORE decrypting. --no-sign skips this even when a signing identity is present.
      No signing identity at all -> unchanged pre-#214 behavior (no *.minisig written).

  cipher-brain restore --in <file.age> --out-dir <dir> [--identity <file>] [--pg <conn>] [--yes] [--no-expand-components]
                        [--sign-recipient <file>] [--require-signature]
      Decrypt with the PRIVATE identity. Extraction never clobbers a file already
      present in --out-dir: an existing file is left untouched, the rest of the
      archive still extracts around it, and the collision itself is not an error.
      That is restore's own behavior, not a flag you pass — it uses tar's own
      --skip-old-files on GNU tar and --keep-old-files on bsdtar, which are those
      two tars' spellings of the same thing.
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
      Authenticity (#214): checked FIRST, before any decryption. If "<in>.minisig"
      exists AND a signing public key is configured (default
      $CIPHER_BRAIN_HOME/sign-recipient.pub; --sign-recipient picks a different one),
      an INVALID signature refuses to restore outright (nothing is decrypted or written).
      An absent signature (unsigned/legacy artifact) or an absent signing public key on
      this box only warn and proceed — this never breaks a pre-#214 backup. --require-
      signature turns that warn into a refusal too: an attacker who simply DELETES the
      .minisig sidecar (rather than forging one) no longer silently succeeds either.

  cipher-brain verify --in <file.age> [--identity <file>] [--sha256 <hex>] [--sign-recipient <file>] [--require-signature] [--json]
      Assert it is real age ciphertext, a wrong key cannot open it, AND (when the
      private identity is on this box) that YOUR key decrypts it into a well-formed
      bundle. --sha256 also pins the artifact to an expected hash. Authenticity (#214):
      if "<in>.minisig" exists and a signing public key is configured (default
      $CIPHER_BRAIN_HOME/sign-recipient.pub; --sign-recipient overrides), verifies it
      too — an INVALID signature is a hard FAIL and skips the positive-control decrypt
      below (an artifact already known to be tampered/forged proves nothing by
      decrypting); no signature or no configured public key just [SKIP]s this check
      by default. --require-signature upgrades that [SKIP] to a hard FAIL too — use it
      once you have run "keygen --sign" and expect every artifact you verify to carry
      a valid signature; without it, an unsigned/legacy artifact still reaches PASS.
      VERDICT: PASS (exit 0) / FAIL (exit 1) / PARTIAL (exit 2 — decryptability not
      proven, e.g. public-key-only box).
      --json prints one JSON object to stdout instead of the human-readable report
      (file, size_bytes, checks: {age_header, sha256_match, signature, wrong_key_rejected,
      positive_control}, verdict, exit_code) — the SAME checks computed above, so it
      never disagrees with the human-readable report or the MCP verify_restore tool.
      The exit code is unchanged either way. If the command ERRORS instead (#270 —
      a missing file, an unreadable identity), stdout carries an error object
      ({error, code, exit_code}) rather than nothing, so a --json caller never has to
      fall back to scraping stderr; "code" is the CB-E0xx identifier when the failure
      matches a known one (MANAGEMENT.md#error-codes), null otherwise.

  cipher-brain push --in <file.age> --backend <file|arweave|turbo|rclone> [--remote <name>:<path>] [--yes] [--save-locator <path>] [--skip-unchanged] [--digest <hex>] [--force]
      Upload ciphertext to storage. Prints ONLY the locator to stdout
      (file: store path; arweave: tx id; turbo: ANS-104 data item id; rclone: the
      --remote value itself).
      Storage sees ciphertext only.
      Transfer progress (#283) is printed to stderr on the backends that can actually be
      slow: turbo uploads (from the SDK's own progress events), rclone transfers (rclone's
      periodic stats, translated), and an arweave gateway READ during pull. file is a local
      copy and the L1 arweave upload is capped at ~10 MiB, so neither reports anything. How
      OFTEN depends on whether stderr is a terminal — roughly every 2s when a human is
      watching, roughly every 30s when it is a nightly log or an MCP tool result, both of
      which keep everything they are given.
      arweave/turbo are paid permanent stores — require --yes or CIPHER_BRAIN_YES=1;
      both print a native-unit cost estimate (winston/winc) before uploading, plus an
      approximate USD line when a USD/AR rate is fetchable — a rate failure drops that
      line only, never the native estimate. Preview the same estimate beforehand
      without pushing anything via "cipher-brain estimate".
      --backend rclone --remote <rclone-remote-name>:<path> shells out to the
      rclone binary (rclone copyto <in> <remote>), delegating auth/protocol for
      any of rclone's 70+ supported providers to your own rclone config — cipher-
      brain implements none of them itself. Free (like file); needs rclone on
      PATH and a remote already set up via 'rclone config' (or a config-less
      on-the-fly remote, e.g. --remote ":local:/path"). --remote is required.
      --save-locator writes "<locator>\\t<backend>\\t<sha256>[\\t<content_digest>[\\t
      <recipients_fingerprint>[\\t<sig_locator>[\\t<sign_key_id>]]]]" to a file (rewritten
      atomically each push, so it always holds the LATEST + an integrity pin; legacy
      3/4/5/6-field files are still accepted everywhere). Back this file up off-box next
      to your identity: it is the durable pointer a fresh machine needs to find the most
      recent snapshot. (For the file backend the locator is a LOCAL store path —
      arweave/turbo locators are
      always portable to another machine; an rclone locator is portable too, PROVIDED
      the same remote name is configured there — a config-less ":local:/path" remote
      is as machine-local as the file backend.)
      Authenticity (#214): if "<in>.minisig" exists (snapshot writes one automatically
      when a signing identity is present — see "snapshot" above), it is ALSO uploaded to
      the SAME backend right after the ciphertext, under the SAME already-granted
      consent — its own locator becomes the 6th --save-locator field above, so pull can
      fetch it back automatically, and the signing key id inside it becomes the 7th
      (#250, see --skip-unchanged below). Unchanged behavior when no sidecar exists.
      --skip-unchanged (requires --save-locator): skips ONLY when ALL THREE of (a) the
      snapshot's PLAINTEXT content digest — read from the "<in>.digest" sidecar
      snapshot writes, or given as --digest <hex> — equals the content_digest recorded
      in the save-locator file for the same backend, (b) the recipients
      fingerprint — read from the "<in>.recipients-fingerprint" sidecar — equals the
      recipients_fingerprint recorded there too, AND (c) the SIGNING state matches:
      an unsigned artifact where the last push was unsigned too, or a "<in>.minisig"
      whose signing key id equals the sign_key_id recorded there. Requiring (b) means a
      re-snapshot of unchanged plaintext under a CHANGED --recipient set (a newly added
      recovery key, a removed/revoked key) is never skipped; requiring (c) means turning
      signing ON ("keygen --sign") or ROTATING the signing key is never skipped either —
      otherwise the store would keep an unsigned, or stale-key-signed, copy of content
      you now expect to be signed with the current key. When all three match: print
      SKIPPED + the previous locator and exit 0 WITHOUT contacting storage or spending.
      Any missing piece on EITHER side (no sidecar, a legacy 3/4-field file, a signed
      push recorded before #250 added the 7th field, a different backend)
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
      returns. All seven keys are ALWAYS present (#268): a backend with no native
      unit, or a query that could not run, reports null rather than dropping the key,
      so the object shape does not depend on which backend was asked about. On an
      ERROR, stdout carries {error, code, exit_code} instead (#270 — see verify).

  cipher-brain pull (--locator <id> --backend <…> | --remote <name>:<path> --backend rclone | --from-locator-file <path>) --out <file.age> [--wait <seconds>] [--sha256 <hex>] [--sig-locator <id>] [--force]
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
      Authenticity (#214): --sig-locator <id> (or the 6th --from-locator-file field,
      read automatically) ALSO fetches the "<in>.minisig" sidecar push uploaded, into
      "<out>.minisig" — best-effort, never fails the pull itself (restore/verify treat a
      missing sidecar as a warning, not a failure). Omit it and pull behaves exactly as
      before #214 (ciphertext only).

  cipher-brain schedule install --backend <file|arweave|turbo> [--at HH:MM] [--max-spend <n>] [--no-load]
                                [--profile <name>] [--pg <conn>] [--pg-table <t>]...
                                [--pg-filter <file>] [--pg-exclude-table-data <t>]... [--dir <path>]...
                                [--recipient <pubkey|file>]... [--vault <path>] [--zip <path>] [--export <path>]
                                [--save-locator <path>] [--index-file <path>]
                                [--ping-url <url>] [--ping-url-fail <url>]
                                [--scan-secrets warn|deny|off]
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
      --scan-secrets warn|deny|off bakes snapshot's gitleaks gate (see 'snapshot' above)
      into the generated runner, so the unattended nightly — the run nobody is watching —
      is gated too. The EFFECTIVE mode is always baked, including when you pass nothing:
      install resolves the same default snapshot would (warn if there is a --dir/--profile
      source and gitleaks is resolvable, otherwise off) and writes it in explicitly, so the
      nightly cannot start scanning — or stop — because of what lands on PATH months later.
      Install RESOLVES gitleaks now and PINS the absolute path into the runner
      as CIPHER_BRAIN_GITLEAKS_BIN (launchd/cron do not inherit your PATH, same reason
      --pg bakes CIPHER_BRAIN_PG_BIN; pinning rather than extending PATH so a different
      gitleaks on the scheduler's PATH cannot take its place), and REFUSES to install if
      it cannot be resolved — a schedule that cannot scan is never installed as if it
      could. An explicit CIPHER_BRAIN_GITLEAKS_BIN is resolved and validated the same way,
      not taken on trust: a bare name or a stale path there would be just as unusable to
      the scheduler. Same --dir/--profile requirement as 'snapshot': a
      --pg-only schedule is refused rather than reporting a scan of no component.
      Fail-closed at run time too: if gitleaks later disappears, the nightly FAILS rather
      than silently skipping the scan.

  cipher-brain schedule status [--json]
      Report the configured time + backend, whether a dead man's switch ping-url is
      configured, the trigger load state, the last run log and its final rc line, and the
      next scheduled run.
      --json prints one JSON object to stdout instead of the human-readable report
      (configured, runner, ping, trigger: {type, loaded, legacy, ...}, last_run,
      next_run) — the SAME state read above, so it never disagrees with the
      human-readable report or the MCP schedule_status tool. "not installed" is an
      ordinary state to poll for, not an exception, so it too answers in JSON on
      stdout ({error, code: "CB-E014", exit_code}) instead of prose on stderr (#270).

  cipher-brain schedule uninstall
      Unregister the trigger and remove the generated runner/plist/cron entry (idempotent;
      logs, snapshots and index.tsv are kept — they are your data).

Config file: every setting below can also live in $CIPHER_BRAIN_HOME/config.env (KEY=value
     per line, "#" comments) instead of the environment — the same names, one place, read by
     the CLI and the MCP server alike. An explicit environment variable always WINS over the
     file. CIPHER_BRAIN_HOME is the one exception: this file is found INSIDE it, so it cannot
     set it (a file that tries is warned about, not silently obeyed). An unknown CIPHER_BRAIN_*
     key is an ERROR rather than a no-op — a "CIPHER_BRAIN_MAXSPEND" typo would otherwise
     silently drop your spend cap. ONLY CIPHER_BRAIN_* settings are applied: any other key in
     the file (TMPDIR, a proxy variable, ...) is read but never put into the environment, so
     the file cannot reach through into the processes cipher-brain spawns.
     Secrets are allowed (it warns if the file is group/other-readable — chmod 600 it).
     'schedule install' BAKES the values in effect at install time into the runner AND makes
     that runner skip this file, so editing it never retunes — or breaks — an already-
     installed nightly run; re-run install to pick changes up. 'schedule status' names the
     file it loaded.
Env: CIPHER_BRAIN_HOME (default ~/.cipher-brain), CIPHER_BRAIN_PG_BIN (dir of pg_dump/pg_restore).
     CIPHER_BRAIN_SCHEDULE_DIR (schedule artifacts/logs dir; default $CIPHER_BRAIN_HOME/schedule).
     CIPHER_BRAIN_LAUNCHD_DIR (macOS only: where 'schedule install' writes the launchd plist;
     default ~/Library/LaunchAgents — a REAL system dir, NOT scoped to CIPHER_BRAIN_HOME, written
     even under --no-load; override to sandbox a --no-load preview run).
     CIPHER_BRAIN_PASSPHRASE (non-interactive passphrase for a wrapped identity — automation/CI; otherwise prompted on the TTY).
     CIPHER_BRAIN_PIN_RECIPIENTS (snapshot: allowlist of age1… pubkeys, inline or a file — refuse to encrypt to any other recipient).
     CIPHER_BRAIN_INIT_ALLOW_NONINTERACTIVE=1 (init: bypass its TTY requirement — automation/CI only, e.g. this repo's own selftest; a human just runs init directly in a terminal).
Storage: CIPHER_BRAIN_FILE_DIR (file);
         CIPHER_BRAIN_AR_{HOST,PORT,PROTOCOL,WALLET,GATEWAY,GATEWAYS,HTTP_TIMEOUT,USD_RATE_URL} (arweave; CIPHER_BRAIN_AR_WALLET is a path to a JWK key file — 'cipher-brain wallet create' generates one, 'wallet address' shows what to fund; the 'arweave' npm package is needed only to PUSH or for the rare L1 chunk fallback — a gateway pull needs none; CIPHER_BRAIN_AR_USD_RATE_URL overrides the AR/USD rate endpoint used for the approximate-USD line printed next to the native-unit cost — a dead or unreachable endpoint just omits that line, it never blocks a push);
         turbo: CIPHER_BRAIN_AR_WALLET (JWK signer) + optional CIPHER_BRAIN_AR_PAID_BY (an address sharing Turbo Credits to that signer); needs '@ardrive/turbo-sdk' to PUSH (a pull reuses the arweave gateway read, no SDK). Funding/credit-share details: docs/arweave-upload-runbook.md.
         rclone: CIPHER_BRAIN_RCLONE_BIN (path to the rclone binary; default 'rclone' on PATH) — the remote itself is whatever --remote <name>:<path> names in your own 'rclone config'.
Spend: arweave/turbo PUSH needs --yes or CIPHER_BRAIN_YES=1 (paid, permanent); CIPHER_BRAIN_MAX_SPEND caps the arweave/turbo cost estimate (winston/winc).
Consent: restore --pg (pg_restore --clean --if-exists, irreversible) needs --yes or CIPHER_BRAIN_YES=1.
Permanence: there is NO delete, at any granularity (#301). cipher-brain has no forget/prune/delete
     command and will not grow one: arweave/turbo are write-once, and destroying your identity does
     not help either — the backup recipient you were told to keep (and the printable recovery kit, if
     it carries one) still decrypts everything. Recoverability was chosen over erasability on purpose.
     What IS parked is ciphertext, so a secret that reaches a snapshot is not published — it is sealed
     to your key, and stays exposed only to whatever might compromise that key later. That is the
     whole reason --scan-secrets now defaults to warn: the only workable answer is to not seal the
     secret in the first place. Before a paid push, assume you are deciding forever.`;

// The version reported by `--version` (issue #261). Read from package.json at
// runtime rather than copied into a constant here, which would be a second place
// to bump and so a place to drift. `../package.json` resolves to the same file
// from BOTH src/cli.ts (repo root, the dev/type-stripping path scripts use) and
// the bundled dist/cli.mjs (the installed package root) — the two are at the
// same depth, so the CLI reports one version no matter which one is running.
// npm always ships package.json in the tarball regardless of the "files" field.
function cliVersion(): string {
  const pkgUrl = new URL('../package.json', import.meta.url);
  const pkg = JSON.parse(readFileSync(pkgUrl, 'utf8')) as { version?: string };
  if (!pkg.version) throw new Error(`no "version" field in ${fileURLToPath(pkgUrl)}`);
  return pkg.version;
}

// `<command> --help` prints only that command's section of HELP (issue #262).
// #171 made `<command> --help` show help at all; it showed the WHOLE ~300-line
// reference, which is what the unknown-flag error (#253) points people at, so a
// typo'd flag on `push` answers with several screens to scroll back through.
//
// This SLICES the existing HELP string rather than introducing per-command help
// text: `cipher-brain --help`'s output stays byte-identical, which is what
// scripts/check-help-docs.mjs pins README.md's CLI reference against in CI
// (#227). One source of truth for the text, two ways to print it.
//
// Returns null when `cmd` names no section, so the caller can fall back to the
// full HELP (an unknown command with --help is better answered by everything
// than by nothing).
// Every command word HELP documents, in the order it documents them (issue #269).
// Derived from the same section headers helpForCommand() slices on, so the list an
// unknown command is answered with cannot drift from the reference itself.
// The capture is positively shaped like a command word ([a-z][a-z0-9-]*) rather than
// "anything that isn't a flag" — `--version` and `<command> --help` have their own
// sections up top but are a flag and a placeholder, and a future header of some other
// shape (`cipher-brain [options] …`) must not be advertised as a command either
//. `wallet create`, `schedule status` etc. collapse to
// their first word, which is what a user types and what helpForCommand() matches on.
function commandNames(): string[] {
  const names = HELP.split('\n')
    .map((line) => line.match(/^ {2}cipher-brain ([a-z][a-z0-9-]*)/)?.[1])
    .filter((name): name is string => name !== undefined);
  return [...new Set(names)];
}

function helpForCommand(cmd: string): string | null {
  const lines = HELP.split('\n');
  const isSectionStart = (line: string) => /^ {2}cipher-brain \S/.test(line);
  // The trailing Env:/Storage:/Spend:/Consent: block starts at column 0 and is
  // command-agnostic, so every scoped help ends with it.
  const trailerStart = lines.findIndex((line) => line.startsWith('Env:'));
  const sectionsEnd = trailerStart === -1 ? lines.length : trailerStart;

  const matched: string[] = [];
  let inMatch = false;
  for (let i = 1; i < sectionsEnd; i++) {
    const line = lines[i];
    if (isSectionStart(line)) {
      // `wallet create` / `schedule status` etc. are separate sections sharing
      // one command word — matching on the word keeps all of them together.
      inMatch = line.match(/^ {2}cipher-brain (\S+)/)?.[1] === cmd;
    }
    if (inMatch) matched.push(line);
  }
  if (matched.length === 0) return null;

  // Drop the blank line(s) each section ends with, then re-add exactly one.
  while (matched.length > 0 && matched[matched.length - 1].trim() === '') matched.pop();
  const trailer = trailerStart === -1 ? [] : ['', ...lines.slice(trailerStart)];
  return [
    lines[0],
    '',
    ...matched,
    ...trailer,
    '',
    `(one section of "cipher-brain --help", which prints the full reference)`,
  ].join('\n');
}

/**
 * #277 — a flag ANOTHER command accepts, passed to one that never reads it. #253 made an
 * unrecognized `--flag` an error; that check is global, so `restore --out ./x` is still a
 * real flag with a real value, stored and never read, because restore's destination is
 * `--out-dir`.
 *
 * Same shape as #308 took for MCP: each command declares which flags it will NOT read,
 * EMPTY IS A REAL ANSWER, and a command with no declaration fails the build —
 * scripts/cli-smoke.sh compares the dispatch switch's case labels against this table.
 *
 * A deny-list, not an allow-list. An allow-list cannot be derived from HELP (the usage
 * lines are abbreviated), and a hand-written one fails in the direction that matters: a
 * flag missing from it starts REFUSING a valid invocation. A missing deny-list entry only
 * preserves today's behaviour, so the table can grow instead of having to be right at once.
 *
 * Entries record what the command DOES with the flag, not what the flag is called.
 * "Does not read" is the user-facing phrasing; "never honors" is the precise one — restore()
 * touches o.out only to build the #279 hint, a branch now unreachable from the CLI and left
 * for a direct library caller.
 */
interface FlagIrrelevance {
  flag: string;
  because: string;
  /** The flag the user probably meant, when there is an obvious one. */
  instead?: string;
}

const FLAG_IRRELEVANT: Record<string, FlagIrrelevance[]> = {
  // restore's destination is --out-dir; src/lib/restore.ts's restore() never reads o.out.
  // The single highest-traffic instance, since --out means the output on snapshot, pull and
  // wallet create — restore is the one command that spells it differently.
  restore: [{ flag: 'out', because: 'restore extracts into a directory', instead: '--out-dir' }],
  // verify() reads neither: it inspects --in in place and writes nothing.
  verify: [
    { flag: 'out', because: 'verify writes nothing — it inspects --in in place' },
    { flag: 'out_dir', because: 'verify writes nothing — it inspects --in in place' },
  ],
  // src/lib/keys.ts reads neither o.out nor o.backend: keygen writes to the paths under
  // CIPHER_BRAIN_HOME and never touches storage.
  keygen: [
    { flag: 'out', because: 'keygen writes to the identity/recipient paths under CIPHER_BRAIN_HOME' },
    { flag: 'backend', because: 'keygen never touches a storage backend' },
  ],
  // estimate.ts reads o.backend but never o.yes: pricing spends nothing, so there is no
  // consent to give.
  estimate: [
    { flag: 'yes', because: 'estimate only prices an upload — it never spends, so there is nothing to confirm' },
  ],
  // The CLI's snapshot does NOT push (unlike the MCP snapshot_now tool, which takes a
  // backend and pushes): snapshot() reads neither o.backend nor o.locator, so both are
  // accepted and dropped today. Pipe it into `push` to upload.
  snapshot: [
    {
      flag: 'backend',
      because: 'the CLI snapshot does not push — run `push --in <file.age> --backend <name>` after it',
    },
    { flag: 'locator', because: 'a locator names an artifact already in storage; snapshot produces a local file' },
  ],
  // init's implementation is `init(_o)` — it ignores the options bag entirely and asks
  // interactively instead, so every flag is unread. The four here are the ones a user is
  // most likely to reach for; the rest are left undeclared on purpose (see the deny-list
  // reasoning above: a missing entry preserves today's behaviour, a wrong one breaks a
  // valid call).
  init: [
    { flag: 'out', because: 'init is an interactive wizard — it asks for paths rather than taking them as flags' },
    { flag: 'backend', because: 'init is an interactive wizard — it asks which backend to configure' },
    { flag: 'yes', because: 'init is interactive by definition; there is no unattended path to consent to' },
    { flag: 'force', because: 'init never overwrites — it detects what already exists and asks' },
  ],
  // Empty is an answer, not an omission. These were checked and have no flag that another
  // command accepts and they silently ignore.
  push: [],
  pull: [],
  schedule: [],
  wallet: [],
  // Reached through the same switch, so the source-level guard in cli-smoke expects an
  // answer from them too. They take no flags and produce no side effects, which is the
  // answer — recorded rather than special-cased, so a future route that DOES take flags
  // cannot slip through by looking like these.
  help: [],
  '--help': [],
  '-h': [],
  '--version': [],
  '-V': [],
};

// A command with no entry has not been considered, and "not considered" must not read as
// "nothing to declare" — that is exactly how #277's cases survived #253. Guarded against
// the SAME derived list the unknown-command reply prints, so adding a command to HELP
// without answering this question fails cli-smoke rather than shipping.
function assertFlagsDeclared(cmd: string | undefined): void {
  if (cmd === undefined) return;
  // Keyed on commandNames() so a TYPO still gets the friendly "unknown command" reply from
  // the switch's default rather than an internal error. That leaves one gap on its own — a
  // switch case never added to HELP is in neither list — which is why cli-smoke reads the
  // case labels out of the source and probes each one.
  if (!commandNames().includes(cmd) && !Object.hasOwn(FLAG_IRRELEVANT, cmd)) return;
  if (!Object.hasOwn(FLAG_IRRELEVANT, cmd)) {
    throw new Error(
      `internal: ${cmd} has no flag-relevance declaration (#277) — add an entry to FLAG_IRRELEVANT in src/cli.ts, using [] if no flag another command accepts is ignored by this one`,
    );
  }
}

function assertFlagsRelevant(cmd: string | undefined, o: CliOptions): void {
  if (cmd === undefined || !Object.hasOwn(FLAG_IRRELEVANT, cmd)) return;
  const rec = o as unknown as Record<string, unknown>;
  const ignored = FLAG_IRRELEVANT[cmd].filter((r) => rec[r.flag] !== undefined);
  if (ignored.length === 0) return;
  // The near-miss suggestion comes from the same helper #305's MCP refusal and restore's own
  // #279 hint use, so a user who typed --out on restore reads the same sentence they did
  // before this check existed — the refusal moved earlier, the help did not get worse.
  const named = ignored
    .map((r) => `--${r.flag.replace(/_/g, '-')} (${r.because}${r.instead ? ` — ${didYouMean(r.instead)}` : ''})`)
    .join('; ');
  throw new Error(
    `${cmd} does not read ${ignored.map((r) => `--${r.flag.replace(/_/g, '-')}`).join(', ')}: ${named}. ` +
      `Refused rather than ignored: a flag that is silently dropped looks exactly like one that was honored.`,
  );
}

async function main(): Promise<void> {
  // #286: the config file refused to load. config.ts records rather than throws (a
  // module-body throw escapes main().catch and prints a raw stack trace), so this is
  // where it re-enters the normal error path — `error: …`, the --json error object, and
  // the CB-E code match. Nothing from the file has been applied, so continuing would run
  // the command with the operator's settings silently absent.
  if (CONFIG_FILE_ERROR) throw CONFIG_FILE_ERROR;
  const [cmd, ...rest] = process.argv.slice(2);
  // `<subcommand> --help` / `-h` must show help instead of running the
  // subcommand (issue #171) — checked on the raw args, BEFORE parseArgs(),
  // so it applies uniformly to every subcommand (not just the bare
  // `cipher-brain --help` handled by the switch below) and keeps working
  // even if parseArgs() is ever changed to validate/throw on bad input
  //.
  if (rest.includes('--help') || rest.includes('-h')) {
    printMascot('neutral');
    console.log((cmd !== undefined && helpForCommand(cmd)) || HELP);
    return;
  }
  const o = parseArgs(rest);
  assertFlagsDeclared(cmd);
  assertFlagsRelevant(cmd, o);
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
    // issue #261: `--version` used to fall through to the `default:` arm below —
    // "unknown command: --version" on stderr, the entire HELP on stdout, exit 2.
    // Bare version string on stdout, nothing else, so it can be captured
    // directly; no mascot, for the same reason.
    case '--version':
    case '-V':
      console.log(cliVersion());
      return;
    // issue #269: this is an ERROR path, so all of it goes to stderr and stdout stays
    // empty — the HELP-on-stdout rule two cases up exists so `cipher-brain --help |
    // grep …` works, which is a REQUEST for the help, not a failure to parse a
    // command. Dumping ~26 KB of help on stdout here meant `LOC=$(cipher-brain psh …)`
    // captured the whole reference into the variable instead of nothing.
    // And it is now a short answer rather than the whole reference: since #262,
    // `<command> --help` prints one section, so the useful reply to a typo is the
    // list of real commands plus where to read more — not 300 lines to scroll back
    // through with no indication of which one was meant.
    default: {
      console.error(`error: unknown command: ${cmd}`);
      // Guard the derived list: if a future HELP edit ever changed the section-header
      // shape enough that nothing matches, "valid commands: " with nothing after it
      // would be worse than not printing the line at all.
      // cli-smoke also asserts the list matches the real command set on every run.
      const names = commandNames();
      if (names.length > 0) console.error(`valid commands: ${names.join(', ')}`);
      console.error(
        `run 'cipher-brain --help' for the full reference, or 'cipher-brain <command> --help' for one command`,
      );
      process.exitCode = 2;
      return;
    }
  }
}

main().catch((e: unknown) => {
  // issue #212: a stable "[CB-E0xx] see MANAGEMENT.md#error-codes" suffix is appended
  // HERE (the one place every command's error funnels through) when the message matches
  // a known failure pattern — never at the individual throw site, so no existing message
  // body changes; an unmatched error prints exactly as before.
  const message = errMsg(e);
  console.error(`error: ${annotateErrorMessage(message)}`);
  // issue #270: --json (#211) only ever produced JSON on the SUCCESS path, so a caller
  // that asked for machine-readable output had to parse stdout on success and scrape
  // English off stderr on failure. The stable error identity #212 computes is already
  // right here — surface it as a field instead of leaving it embedded in a sentence.
  //
  // Read off argv rather than the parsed options because parseArgs() itself can throw
  // (an unknown flag, #253) before any options exist — that failure must answer in the
  // format the caller asked for too.
  //
  // `error` carries the RAW message; the "[CB-E0xx] see …" suffix is stderr's rendering
  // of the same two facts, and duplicating it inside a field that sits next to `code`
  // would just make the JSON harder to consume. Additive: stdout on this path used to
  // be empty, stderr is byte-for-byte what it was, and the exit code stays the sole
  // authority on success/failure.
  //
  // hasWrittenJson(): never append a SECOND JSON value to a stdout that already holds
  // a command's own document — two values on one stream is not parseable as one. No
  // --json command can currently throw after printing (each prints last and returns),
  // so this is a structural guarantee for future ones rather than a live fix
  //.
  if (process.argv.slice(2).includes('--json') && !hasWrittenJson()) {
    console.log(JSON.stringify({ error: message, code: matchErrorCode(message)?.code ?? null, exit_code: 1 }));
  }
  process.exitCode = 1;
});
