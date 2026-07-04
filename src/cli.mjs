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
// bytes get parked (TON Storage / Arweave / anything) is a separate, pluggable
// concern — storage only ever sees ciphertext.
//
// This entry point holds arg parsing + command dispatch; the implementation lives
// in src/lib/ (config, proc, util, signal-guard, identity, snapshot, restore,
// pushpull, backends/).

import { IDENTITY } from './lib/config.mjs';
import { keygen } from './lib/keys.mjs';
import { snapshot } from './lib/snapshot.mjs';
import { restore, verify } from './lib/restore.mjs';
import { push, pull } from './lib/pushpull.mjs';

const BOOL_FLAGS = new Set(['force', 'passphrase', 'yes', 'force_vault']); // flags that take no value

function parseArgs(argv) {
  const o = { dirs: [], tables: [], recipients: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--dir') o.dirs.push(argv[++i]);
    else if (a === '--pg-table') o.tables.push(argv[++i]);
    else if (a === '--recipient') o.recipients.push(argv[++i]); // repeatable: key recovery
    else if (a.startsWith('--')) {
      const key = a.slice(2).replace(/-/g, '_');
      o[key] = BOOL_FLAGS.has(key) ? true : argv[++i];
    } else o._ = a;
  }
  return o;
}

const HELP = `cipher-brain — encrypt a gbrain snapshot so only you can read it

  cipher-brain keygen [--passphrase] [--force]
      Create your age keypair: identity (PRIVATE) + recipient (PUBLIC).
      --passphrase wraps the identity at rest with a scrypt passphrase (prompted on the
      TTY); restore/verify then prompt for it. Identity = ${IDENTITY}

  cipher-brain snapshot --out <file.age> [--profile <name>] [--pg <conn>] [--pg-table <t>]... [--dir <path>]... [--recipient <pubkey|file>]...
      Bundle a pg_dump and/or directories, encrypt to the PUBLIC recipient(s).
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

  cipher-brain restore --in <file.age> --out-dir <dir> [--identity <file>] [--pg <conn>]
      Decrypt with the PRIVATE identity; optionally pg_restore the db.dump.

  cipher-brain verify --in <file.age> [--identity <file>] [--sha256 <hex>]
      Assert it is real age ciphertext, a wrong key cannot open it, AND (when the
      private identity is on this box) that YOUR key decrypts it into a well-formed
      bundle. --sha256 also pins the artifact to an expected hash. VERDICT: PASS (exit 0)
      / FAIL (exit 1) / PARTIAL (exit 2 — decryptability not proven, e.g. public-key-only box).

  cipher-brain push --in <file.age> --backend <file|ton|arweave|turbo> [--yes] [--save-locator <path>]
      Upload ciphertext to storage. Prints ONLY the locator to stdout
      (file: store path; ton: hex BagID; arweave: tx id; turbo: ANS-104 data item id).
      Storage sees ciphertext only.
      arweave/turbo are paid permanent stores — require --yes or CIPHER_BRAIN_YES=1.
      --save-locator writes "<locator>\\t<backend>\\t<sha256>" to a file (rewritten
      atomically each push, so it always holds the LATEST + an integrity pin). Back this
      file up off-box next to your identity: it is the durable pointer a fresh machine
      needs to find the most recent snapshot. (For the file backend the locator is a
      LOCAL store path — only ton/arweave/turbo locators are portable to another machine.)

  cipher-brain pull (--locator <id> --backend <…> | --from-locator-file <path>) --out <file.age> [--wait <seconds>] [--sha256 <hex>]
      Fetch ciphertext by locator into --out. --from-locator-file reads the locator, its
      backend AND the saved sha256 from a file written by push --save-locator (the recovery
      path: identity + this file are all a fresh machine needs; the saved sha256 is applied
      as the integrity pin automatically). --wait retries while the item is not yet
      retrievable (a fresh Turbo/Arweave upload takes ~5-8 min to propagate); default 0.
      --sha256 fail-closes the fetch: the bytes must match the expected hash (sourced
      out-of-band from a trusted index) or --out is deleted and pull errors.

Env: CIPHER_BRAIN_HOME (default ~/.cipher-brain), CIPHER_BRAIN_PG_BIN (dir of pg_dump/pg_restore).
     CIPHER_BRAIN_PASSPHRASE (non-interactive passphrase for a wrapped identity — automation/CI; otherwise prompted on the TTY).
     CIPHER_BRAIN_PIN_RECIPIENTS (snapshot: allowlist of age1… pubkeys, inline or a file — refuse to encrypt to any other recipient).
Storage: CIPHER_BRAIN_FILE_DIR (file); CIPHER_BRAIN_TON_{CLI,API,CLIENT,SERVER,TIMEOUT} (ton);
         CIPHER_BRAIN_AR_{HOST,PORT,PROTOCOL,WALLET,GATEWAY,GATEWAYS,HTTP_TIMEOUT} (arweave; the 'arweave' npm package is needed only to PUSH or for the rare L1 chunk fallback — a gateway pull needs none);
         turbo: CIPHER_BRAIN_AR_WALLET (JWK signer) + optional CIPHER_BRAIN_AR_PAID_BY (an address sharing Turbo Credits to that signer); needs '@ardrive/turbo-sdk' to PUSH (a pull reuses the arweave gateway read, no SDK). Funding/credit-share details: docs/arweave-upload-runbook.md.
Spend: arweave/turbo PUSH needs --yes or CIPHER_BRAIN_YES=1 (paid, permanent); CIPHER_BRAIN_MAX_SPEND caps the turbo estimate (winc).`;

async function main() {
  const [cmd, ...rest] = process.argv.slice(2);
  const o = parseArgs(rest);
  switch (cmd) {
    case 'keygen': return keygen(o);
    case 'snapshot': return snapshot(o);
    case 'restore': return restore(o);
    case 'verify': return verify(o);
    case 'push': return push(o);
    case 'pull': return pull(o);
    case 'help': case '--help': case '-h': case undefined: console.log(HELP); return;
    default: console.error(`unknown command: ${cmd}\n`); console.log(HELP); process.exitCode = 2;
  }
}

main().catch((e) => { console.error(`error: ${e.message}`); process.exitCode = 1; });
