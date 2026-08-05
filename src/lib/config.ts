// config — env-driven paths, binaries and tunables shared by every module, plus the
// optional config file (#286) that can supply any of them.
import { homedir } from 'node:os';
import { join } from 'node:path';
import { existsSync, readFileSync } from 'node:fs';
import { parseEnv } from 'node:util';
import { warnIfLooseKeyPermsSync } from './util.js';

// Every CIPHER_BRAIN_* name this codebase reads, declared exactly once.
//
// This list is not documentation — `readEnv()` below only accepts a name from it, so
// reading a variable that is not declared here is a TYPE ERROR. That is what lets the
// config file reject an unknown key (a `CIPHER_BRAIN_MAXSPEND` typo would otherwise be
// silently ignored, and for a spend cap that is a real loss) WITHOUT introducing a
// second list to keep in sync — the failure mode that produced #276 in the first place.
//
// Names read lazily elsewhere (crypt.ts, pushpull.ts, wizard.ts, backends/arweave.ts)
// are declared here too and reach their call sites through readEnv(), so the set stays
// complete without forcing those reads to happen at import time — several are read
// per-invocation on purpose.
const ENV_NAMES = [
  'CIPHER_BRAIN_HOME',
  'CIPHER_BRAIN_AGE', // deprecated no-op (#64), still declared so the file can name it and get the warning
  'CIPHER_BRAIN_AGE_KEYGEN', // deprecated no-op (#64)
  'CIPHER_BRAIN_PG_BIN',
  'CIPHER_BRAIN_PIN_RECIPIENTS',
  'CIPHER_BRAIN_PASSPHRASE',
  'CIPHER_BRAIN_INIT_ALLOW_NONINTERACTIVE',
  'CIPHER_BRAIN_SCHEDULE_DIR',
  'CIPHER_BRAIN_LAUNCHD_DIR',
  'CIPHER_BRAIN_FILE_DIR',
  'CIPHER_BRAIN_RCLONE_BIN',
  'CIPHER_BRAIN_GITLEAKS_BIN',
  'CIPHER_BRAIN_AR_HOST',
  'CIPHER_BRAIN_AR_PORT',
  'CIPHER_BRAIN_AR_PROTOCOL',
  'CIPHER_BRAIN_AR_WALLET',
  'CIPHER_BRAIN_AR_PAID_BY',
  'CIPHER_BRAIN_AR_GATEWAY',
  'CIPHER_BRAIN_AR_GATEWAYS',
  'CIPHER_BRAIN_AR_HTTP_TIMEOUT',
  'CIPHER_BRAIN_AR_USD_RATE_URL',
  'CIPHER_BRAIN_AR_BALANCE_URL',
  'CIPHER_BRAIN_AR_L1_MAX',
  'CIPHER_BRAIN_YES',
  'CIPHER_BRAIN_MAX_SPEND',
  'CIPHER_BRAIN_PIPE_TIMEOUT',
  'CIPHER_BRAIN_PULL_RETRY_MS',
  'CIPHER_BRAIN_NO_CONFIG_FILE', // set by the generated nightly runner so a scheduled run uses only baked values (#286)
  'CIPHER_BRAIN_IDEMPOTENCY_TTL_SECONDS', // #220: snapshot_now MCP idempotency-key cache lifetime
] as const;

export type EnvName = (typeof ENV_NAMES)[number];

/**
 * Read one declared variable. The union type is the point: a name not in ENV_NAMES
 * does not compile, so the list above cannot fall behind what the code reads.
 * Deliberately NOT cached — several callers read per-invocation (tests set these
 * between calls), and freezing them here would change that behaviour.
 */
export const readEnv = (name: EnvName): string | undefined => process.env[name];

export interface LoadedConfigFile {
  readonly path: string;
  /** The CIPHER_BRAIN_* keys the file defined, for `schedule status` to report. */
  readonly variables: readonly string[];
}

// WHERE the config file lives, derived in exactly one place. Anything that needs to
// name the resolved path (loadConfigFile below, the `init` wizard's recipient-pin step)
// goes through this or through CONFIG_FILE_PATH under HOME — a second `join(home,
// 'config.env')` elsewhere would drift silently the day the filename changes: the
// loader would look at the new name while the wizard kept telling users to write the
// old one, and a file nothing reads produces no error at all. Same drift shape #276
// removed from the env-name list.
const configFileIn = (home: string): string => join(home, 'config.env');

// A refusal here is RECORDED, not thrown. This runs in a module body, before cli.ts's
// main().catch and before mcp.ts is serving, so throwing produces a raw stack trace
// instead of the `error: …` line (plus the --json error object, #270, and the CB-E code
// match) that every other failure in this tool gets. Both entry points re-throw
// CONFIG_FILE_ERROR as their first act, which puts it back on the normal path.
//
// The file lives at $CIPHER_BRAIN_HOME/config.env, which means CIPHER_BRAIN_HOME is the
// one variable it cannot set — the file would have to be read to know where it is. A
// file that names it is warned about rather than silently ignored.
//
// Precedence is Node's, not ours: `process.loadEnvFile()` leaves an already-set
// variable alone, so explicit env > file > built-in default with no logic here to get
// wrong. The file is parsed a second time (parseEnv, which only parses — it does not
// touch process.env) purely to learn which keys it declared, for validation and for
// `schedule status`.
function loadConfigFile(home: string): { file: LoadedConfigFile | null; error: Error | null } {
  const path = configFileIn(home);
  // The generated nightly runner sets this (#286): its values were baked in at install
  // time, and re-reading the file at run time would mean an edit could retune — or
  // break — an already-installed schedule, which is exactly the guarantee `schedule
  // install` exists to provide.
  if (process.env.CIPHER_BRAIN_NO_CONFIG_FILE === '1') return { file: null, error: null };
  if (!existsSync(path)) return { file: null, error: null }; // by far the common case — never an error

  // ONE read. An earlier version parsed the file for validation and then called
  // process.loadEnvFile() to apply it, which had two problems: the file could change
  // between the two reads (so unvalidated content could be applied), and loadEnvFile
  // applies the WHOLE file — a stray TMPDIR or HTTP_PROXY in it would silently reach
  // every child process we spawn, and an in-file CIPHER_BRAIN_HOME would land in the
  // environment despite the warning saying it is ignored (multi-model review findings).
  let parsed: Record<string, string>;
  try {
    parsed = parseEnv(readFileSync(path, 'utf8')) as Record<string, string>;
  } catch (e) {
    return { file: null, error: new Error(`config file ${path} could not be parsed: ${(e as Error)?.message ?? e}`) };
  }

  const ours = Object.keys(parsed).filter((k) => k.startsWith('CIPHER_BRAIN_'));
  const unknown = ours.filter((k) => !(ENV_NAMES as readonly string[]).includes(k));
  if (unknown.length) {
    return {
      file: null,
      error: new Error(
        `config file ${path}: unknown setting(s) ${unknown.join(', ')} — ` +
          `cipher-brain reads no such variable, so this would have no effect (a typo in e.g. ` +
          `CIPHER_BRAIN_MAX_SPEND would silently remove your spend cap). Run 'cipher-brain --help' ` +
          `for the settings it does read. Keys outside the CIPHER_BRAIN_ namespace are ignored entirely.`,
      ),
    };
  }
  if (ours.includes('CIPHER_BRAIN_HOME')) {
    process.stderr.write(
      `⚠  ${path} sets CIPHER_BRAIN_HOME, which is ignored — this file is found *inside* ` +
        `CIPHER_BRAIN_HOME, so it cannot choose it. Set it in the environment instead.\n`,
    );
  }
  warnIfLooseKeyPermsSync(path, 'config file');

  // Apply ONLY our own validated settings, and only where the environment has not
  // already spoken — explicit env > file, the same precedence Node's own loader uses,
  // written out here because we are no longer handing it the whole file.
  // CIPHER_BRAIN_HOME is excluded outright: it was resolved before this ran, so letting
  // it into the environment would mean child processes disagreeing with this one.
  const applied: string[] = [];
  for (const k of ours) {
    if (k === 'CIPHER_BRAIN_HOME') continue;
    if (process.env[k] !== undefined) continue;
    process.env[k] = parsed[k];
    applied.push(k);
  }
  return { file: { path, variables: applied }, error: null };
}

// Resolved from the environment ALONE, before the file is loaded — see loadConfigFile.
export const HOME = process.env.CIPHER_BRAIN_HOME || join(homedir(), '.cipher-brain');

/**
 * The config file's resolved path under this run's HOME, whether or not it exists —
 * for anything that needs to NAME it (e.g. `init` telling the user where to put a
 * setting). Distinct from CONFIG_FILE below, which is null unless a file was actually
 * loaded. Must stay after HOME: it is derived from it.
 */
export const CONFIG_FILE_PATH = configFileIn(HOME);

const CONFIG_LOAD = loadConfigFile(HOME);
/** The config file that was loaded, if any. `schedule status` reports it (#286). */
export const CONFIG_FILE: LoadedConfigFile | null = CONFIG_LOAD.file;
/**
 * Why the config file was refused, if it was. NOTHING from the file has been applied
 * when this is set. Both entry points (cli.ts main(), mcp.ts startup) must re-throw it
 * before doing any work — otherwise a command would run with the file silently ignored,
 * which is the outcome this refusal exists to prevent.
 */
export const CONFIG_FILE_ERROR: Error | null = CONFIG_LOAD.error;

// #64: age runs in-process (typage, bundled) — the external-binary overrides are obsolete.
for (const v of ['CIPHER_BRAIN_AGE', 'CIPHER_BRAIN_AGE_KEYGEN'] as const) {
  if (readEnv(v))
    console.error(
      `cipher-brain: ${v} is deprecated and ignored — age is bundled in-process (typage); no external age binary is used`,
    );
}
export const PG_BIN = readEnv('CIPHER_BRAIN_PG_BIN') || ''; // dir holding pg_dump/pg_restore; '' => PATH
export const pgTool = (name: string): string => (PG_BIN ? join(PG_BIN, name) : name);

export const IDENTITY = join(HOME, 'identity.age'); // private key — required to restore
export const RECIPIENT = join(HOME, 'recipient.txt'); // public key — all snapshot needs

// #220: cipher-brain-mcp's idempotency-key log for snapshot_now (the paid MCP tool) — an
// AI agent's own retry after a network blip must not spend twice for what it believes is
// one call. JSONL, one line per still-fresh (tool, idempotency_key) pair; see
// src/lib/idempotency.ts for the read/write contract. MCP-only bookkeeping (the CLI never
// reads or writes it), so it needs no CLI flag, only this path and the TTL below.
export const IDEMPOTENCY_LOG = join(HOME, 'idempotency-log.jsonl');
// How long a recorded result stays replayable before a repeat of the same key is treated
// as a brand-new call. Default 24h: long enough to cover an agent's own retry-after-
// failure window, short enough that a deliberate re-run days later (a different snapshot
// an agent mistakenly keys the same) is never silently skipped forever.
//
// Multi-model review (P2): a NaN/zero/negative override would silently DISABLE replay
// entirely — idempotency.ts's isFresh() compares `now - t < ttlSeconds * 1000`, and a `<
// NaN`/`< 0` comparison is always false, so every lookup reads as already-expired and
// every retry spends again, exactly the double-spend #220 exists to prevent. An Infinity
// override does the opposite: it never expires anything, so the SAME key reused days
// later — the "a different snapshot an agent mistakenly keys the same" case the comment
// above says the default must catch — is silently answered with a stale, unrelated
// result forever instead. Validated, not just Number()'d like the other numeric env
// overrides in this file; a bad value is RECORDED as a value here (not thrown), the same
// pattern CONFIG_FILE_ERROR above uses and for the same reason: this runs in a module
// body, before either entry point's own error formatting is available, and the CLI never
// reads or writes the idempotency log at all, so only mcp.ts's own startup (the sole
// actual consumer of this value) decides whether and when to surface it.
function parseIdempotencyTtlSeconds(raw: string | undefined): { seconds: number; error: Error | null } {
  const DEFAULT_SECONDS = 24 * 60 * 60;
  if (raw === undefined) return { seconds: DEFAULT_SECONDS, error: null };
  const n = Number(raw);
  if (!Number.isFinite(n) || !Number.isInteger(n) || n <= 0) {
    return {
      seconds: DEFAULT_SECONDS,
      error: new Error(
        `CIPHER_BRAIN_IDEMPOTENCY_TTL_SECONDS must be a positive finite integer (seconds) — got ${JSON.stringify(raw)}. ` +
          'A NaN/zero/negative value would disable idempotency-key replay entirely (every lookup reads as already ' +
          'expired); an Infinity value would never expire a key, keeping a stale result replayable forever.',
      ),
    };
  }
  return { seconds: n, error: null };
}
const IDEMPOTENCY_TTL_LOAD = parseIdempotencyTtlSeconds(readEnv('CIPHER_BRAIN_IDEMPOTENCY_TTL_SECONDS'));
export const IDEMPOTENCY_TTL_SECONDS = IDEMPOTENCY_TTL_LOAD.seconds;
/** Why CIPHER_BRAIN_IDEMPOTENCY_TTL_SECONDS was refused, if it was — mcp.ts's main() must check this before serving (mirrors CONFIG_FILE_ERROR above). */
export const IDEMPOTENCY_TTL_ERROR: Error | null = IDEMPOTENCY_TTL_LOAD.error;

// schedule (#69) state and trigger locations. Declared here rather than in schedule.ts
// so every CIPHER_BRAIN_* name lives in ENV_NAMES above (#286); the values and their
// defaults are unchanged. LAUNCHD_DIR deliberately defaults OUTSIDE CIPHER_BRAIN_HOME —
// ~/Library/LaunchAgents is a real system directory, which is why `schedule install
// --no-load` warns about writing there and why the override exists (#182).
export const SCHEDULE_DIR = readEnv('CIPHER_BRAIN_SCHEDULE_DIR') || join(HOME, 'schedule');
export const LAUNCHD_DIR = readEnv('CIPHER_BRAIN_LAUNCHD_DIR') || join(homedir(), 'Library', 'LaunchAgents');

// Minisign-compatible Ed25519 signing keypair (#214) — an ADDITIONAL, optional layer:
// age (above) gives confidentiality + tamper detection but no AUTHENTICITY (anyone
// holding `recipient` — public by design — can forge ciphertext that decrypts cleanly
// with your identity, claiming to be a real snapshot). Signing the *.age ciphertext
// with this keypair and verifying BEFORE decrypt (src/lib/restore.ts) closes that gap.
// Wire-compatible with the reference `minisign` CLI (src/lib/minisign.ts) — a real
// `minisign -V -p sign-recipient.pub` can verify a *.minisig cipher-brain writes.
export const SIGN_IDENTITY = join(HOME, 'sign-identity.key'); // PRIVATE signing key — keep offline, same posture as IDENTITY
export const SIGN_RECIPIENT = join(HOME, 'sign-recipient.pub'); // PUBLIC verification key — safe to copy, same posture as RECIPIENT

export const AGE_MAGIC = 'age-encryption.org/v1';
// The first bytes of a *.minisig, beside AGE_MAGIC because they answer the same question
// for the other object type this project stores: "are these bytes the thing I asked for, or
// something a gateway handed me instead?" (#318). Kept identical to minisign.ts's
// COMMENT_PREFIX, which is what this project's own writer emits and what the format
// specifies for line 1.
export const MINISIG_MAGIC = 'untrusted comment: ';
export const AGE_ARMOR_HEADER = '-----BEGIN AGE ENCRYPTED FILE-----';

// Optional recipient allowlist. When set (including to a non-empty inline list or a
// path to a file of them), snapshot refuses to encrypt unless EVERY effective
// recipient is on this list — so a tampered recipient.txt / an injected extra
// --recipient (which would silently re-key future snapshots to an attacker) is
// caught at the input, before any ciphertext is produced. Inline (space/comma/
// newline-separated age1… keys) OR a path to a file of them.
//
// `undefined` (unset) means "no pin configured" — the check is skipped entirely.
// `''` (explicitly set to an empty string, e.g. a broken cron/systemd template that
// renders CIPHER_BRAIN_PIN_RECIPIENTS="") is NOT treated the same as unset: `||` would
// collapse both to the same falsy '' and silently disable the allowlist (fail-open).
// Kept as `string | undefined` so the two cases stay distinguishable at the call site,
// which must fail closed on the explicit-empty-string case.
export const PIN_RECIPIENTS: string | undefined = readEnv('CIPHER_BRAIN_PIN_RECIPIENTS');
// An age recipient: X25519 (age1 + bech32, bounded 50-63 so two unseparated keys
// can't fuse) OR a post-quantum HYBRID recipient (#205: `keygen --pq`, ML-KEM-768 +
// X25519 via typage's generateHybridIdentity()) — `age1pq1` + a MUCH longer bech32
// body (~1950 chars observed; bounded 1900-2000, still far short of 2x a hybrid
// recipient so two unseparated hybrid keys can't fuse either). The hybrid
// alternative is listed FIRST so it wins the leftmost-first alternation match
// instead of the plain age1 branch truncating it at its own tight bound — without
// this, resolvePinnedRecipients() (below) would silently mismatch every hybrid
// recipient against CIPHER_BRAIN_PIN_RECIPIENTS.
export const AGE_PUBKEY_RE = /age1pq1[0-9a-z]{1900,2000}|age1[0-9a-z]{50,63}/g;

// ---------- storage backend config (pluggable: storage only ever sees ciphertext) ----------
// Backends whose locator is NOT a content hash the fetched bytes are checked against —
// a post-assigned id (a tx id / data item id) for arweave/turbo, or the operator's own
// path/remote string for rclone (src/lib/backends/rclone.ts's own doc comment: "the
// locator IS the '<remote>:<path>' string itself"), so nothing stops the SAME locator
// from later serving different bytes. `file` is deliberately NOT in this set: its
// locator IS the sha256 of what was pushed, and its get() (src/lib/backends/file.ts)
// verifies the fetched bytes against that hash itself before ever returning them
// (#209 review) — a substitution there is caught unconditionally, not only when the
// caller happens to pass --sha256. Used by verify --level remote/drill (src/lib/
// restore.ts, #209) and the MCP verify_restore tool (src/mcp.ts) to warn when a pull ran
// with no sha256 pin: without one, for arweave/turbo/rclone, a gateway/remote that
// rolled back or substituted the object served at that same locator would not be caught.
export const NON_CONTENT_ADDRESSED_BACKENDS = new Set(['arweave', 'turbo', 'rclone']);
export const FILE_DIR = readEnv('CIPHER_BRAIN_FILE_DIR') || join(HOME, 'store'); // file backend object store
// rclone backend (#204): the `rclone` binary name/path, same PATH-or-override
// pattern as PG_BIN above — most machines just need `rclone` on PATH; override
// for a non-standard install location.
export const RCLONE_BIN = readEnv('CIPHER_BRAIN_RCLONE_BIN') || 'rclone';
// --scan-secrets' gitleaks binary (#215), same PATH-or-override pattern as RCLONE_BIN.
// `schedule install --scan-secrets` sets this to the ABSOLUTE path it resolved, so the
// unattended run executes the scanner the operator was shown at install time rather than
// whatever a bare launchd/cron PATH resolves that name to (#307, multi-model review).
export const GITLEAKS_BIN = readEnv('CIPHER_BRAIN_GITLEAKS_BIN') || 'gitleaks';
export const AR_HOST = readEnv('CIPHER_BRAIN_AR_HOST') || 'arweave.net';
export const AR_PORT = Number(readEnv('CIPHER_BRAIN_AR_PORT') || 443);
export const AR_PROTOCOL = readEnv('CIPHER_BRAIN_AR_PROTOCOL') || 'https';
export const AR_WALLET = readEnv('CIPHER_BRAIN_AR_WALLET') || ''; // path to a JWK key file
export const AR_PAID_BY = readEnv('CIPHER_BRAIN_AR_PAID_BY') || ''; // optional (turbo): an address that shared (delegated) Turbo Credits to the signer — passed as `paidBy` so the upload draws from that approval before the signer's own balance (the path for credits bought on a wallet we can't sign with, e.g. MetaMask, then shared to this JWK)
export const AR_DEFAULT_EXTRA_GATEWAYS = ['https://permagate.io']; // public mirror(s) tried after the primary (override the whole list with CIPHER_BRAIN_AR_GATEWAYS)
export const AR_HTTP_TIMEOUT_MS = Number(readEnv('CIPHER_BRAIN_AR_HTTP_TIMEOUT') || 60000); // bound the gateway read so a stall falls through to the L1 chunk fallback
// Public, unauthenticated USD/AR rate endpoint (ArDrive Turbo's payment service) — a
// plain JSON GET, no SDK or auth required (#170). arUsdRate() (src/lib/estimate.ts)
// fetches this directly instead of going through @ardrive/turbo-sdk, so the USD line
// works even when that optional peerDependency isn't installed.
export const AR_USD_RATE_URL = readEnv('CIPHER_BRAIN_AR_USD_RATE_URL') || 'https://payment.ardrive.io/v1/rates/usd';
// Public, unauthenticated account-balance endpoint on the same payment service, queried
// as `<url>?address=<addr>` (#345). Same #170 reasoning as the rate URL above: the SDK
// exposes this as turbo.getBalance(), but it is a plain GET keyed on a PUBLIC address —
// no signature, no key material — so reading it must not require an optional
// peerDependency that a machine may not have (or, per #344, may not be installable on).
export const AR_BALANCE_URL = readEnv('CIPHER_BRAIN_AR_BALANCE_URL') || 'https://payment.ardrive.io/v1/balance';
// Spend guard: arweave/turbo uploads are irreversible and cost real funds. Require an
// explicit opt-in so an unattended nightly loop doesn't silently accumulate charges.
//   CIPHER_BRAIN_YES=1  — set in the nightly runner (`schedule install` writes it for paid backends) to suppress the --yes prompt
//   CIPHER_BRAIN_MAX_SPEND — abort if the upload cost estimate (in the backend's native
//     unit: winston for arweave L1, winc for turbo) exceeds this value; 0/unset = no cap
//     (the --yes guard still fires). Prevents runaway spend without changing behaviour
//     when the upload is well under budget.
export const CIPHER_YES = !!readEnv('CIPHER_BRAIN_YES');
const MAX_SPEND_RAW = readEnv('CIPHER_BRAIN_MAX_SPEND');
export const AR_MAX_SPEND = MAX_SPEND_RAW ? BigInt(MAX_SPEND_RAW) : 0n;
// The raw `arweave` backend posts one inline L1 tx; gateways reject single-tx bodies
// past ~12 MiB. Guard at a conservative 10 MiB and redirect large uploads to `turbo`
// (which streams + ANS-104-bundles). Override for a deliberate large L1 post.
export const AR_L1_MAX_BYTES = Number(readEnv('CIPHER_BRAIN_AR_L1_MAX') || 10 * 1024 * 1024);
// Overall wall-clock cap for the tar|age / age|tar streaming pipelines, the pre-stage
// tar, pg_restore, AND the rclone backend's copyto subprocess, so a wedged binary (or
// a FIFO/special file under --dir, or a stalled remote transfer) can't hang the CLI
// forever. Generous default (1h) — a real ~850 MB brain streams in seconds, so this
// only ever trips on a genuine hang. Override with CIPHER_BRAIN_PIPE_TIMEOUT (ms) for
// very large brains / restores / slow remotes.
export const PIPE_TIMEOUT_MS = Number(readEnv('CIPHER_BRAIN_PIPE_TIMEOUT') || 60 * 60 * 1000);
