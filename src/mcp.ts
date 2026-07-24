// cipher-brain-mcp — MCP server so an AI agent can snapshot/verify/restore its own brain.
//
// Second entry point next to src/cli.ts (a CLI + MCP two-face design). Every
// tool is a thin wrapper over the SAME src/lib functions the CLI dispatches
// to — no re-implemented logic, no shelling out.
//
// Transport: stdio only. Stdout is MCP JSON-RPC framing; the lib functions
// print progress via console.log/console.error, so tool handlers run inside
// captureCall() which redirects both into per-call buffers (stdout lines are
// data — e.g. push() prints the locator there — stderr lines are progress) and
// snapshots process.exitCode (verify() reports its verdict through it).
//
// Uses the LOW-LEVEL `Server` + `setRequestHandler` API (not the high-level
// McpServer helper) so validation lives in our handlers and errors come back
// as one structured {code, message} payload instead of SDK plain-text errors.
//
// Spend safety: snapshot_now is the ONLY tool that can spend money (push to
// arweave/turbo — paid, permanent). It requires an explicit confirm_paid=true
// for those backends, checked BEFORE any work happens; the CIPHER_BRAIN_YES
// env escape hatch the CLI honors is deliberately NOT honored here, so an
// agent can never spend without saying so in the call itself.

import { stat, readFile, mkdtemp, rm, copyFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve, sep } from 'node:path';

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  type Tool,
  type CallToolResult,
} from '@modelcontextprotocol/sdk/types.js';

import { HOME, IDENTITY, RECIPIENT } from './lib/config.js';
import { snapshot } from './lib/snapshot.js';
import { restore, verify } from './lib/restore.js';
import { push, pull } from './lib/pushpull.js';
import { schedule } from './lib/schedule.js';
import { estimateCost } from './lib/estimate.js';
import { keygenAt } from './lib/keys.js';
import { wallet } from './lib/wallet.js';
import { exists, sha256, errMsg } from './lib/util.js';
import { annotateErrorMessage, matchErrorCode } from './lib/errors.js';
import type { CliOptions } from './lib/types.js';

const SERVER_NAME = 'cipher-brain-mcp';
const SERVER_VERSION = '0.0.1'; // keep in sync with package.json "version"

const BACKENDS = ['file', 'arweave', 'turbo'];
const PAID_BACKENDS = new Set(['arweave', 'turbo']);
// arweave/turbo locators are post-assigned tx/upload ids, NOT content hashes —
// pulling by bare locator cannot detect a rolled-back/substituted (yet still
// age-decryptable) ciphertext unless a sha256 pin binds the fetched bytes.
const NON_CONTENT_ADDRESSED_BACKENDS = new Set(['arweave', 'turbo']);
const SHA256_HEX = /^[0-9a-fA-F]{64}$/;

// Untyped JSON-RPC tool-call arguments (an MCP client can send anything) — every
// handler below validates its own shape at runtime (isStr/isStrArray etc), so
// `unknown` per-field is the honest type until a check narrows it.
type ToolArgs = Record<string, unknown>;

// ─────────────────────────────────────────────────────────────────────────────
// stdout hygiene + per-call output capture
// ─────────────────────────────────────────────────────────────────────────────

// Safety net: nothing outside a captured call may write to stdout (it would
// corrupt the JSON-RPC framing). Rebind console.log at module load; the capture
// below swaps in per-call buffers on top of this.
const rawStderrLine = (s: string) => process.stderr.write(s + '\n');
console.log = (...a: unknown[]) => rawStderrLine(a.map(String).join(' '));
console.error = (...a: unknown[]) => rawStderrLine(a.map(String).join(' '));

interface CaptureResult<T> {
  value: T;
  out: string[];
  err: string[];
  exitCode: number;
}

// Run one lib call with console.log/console.error captured and process.exitCode
// snapshotted. Calls are serialized through a promise-chain mutex because the
// capture mutates process-global state (console + exitCode).
let callChain: Promise<void> = Promise.resolve();
function captureCall<T>(fn: () => Promise<T>): Promise<CaptureResult<T>> {
  const run = callChain.then(async (): Promise<CaptureResult<T>> => {
    const out: string[] = [];
    const err: string[] = [];
    const prevLog = console.log;
    const prevErr = console.error;
    const prevExit = process.exitCode;
    process.exitCode = undefined;
    console.log = (...a: unknown[]) => {
      out.push(a.map(String).join(' '));
    };
    console.error = (...a: unknown[]) => {
      const s = a.map(String).join(' ');
      err.push(s);
      rawStderrLine(s); // progress stays visible on the server's stderr too
    };
    try {
      const value = await fn();
      return { value, out, err, exitCode: process.exitCode ?? 0 };
    } finally {
      console.log = prevLog;
      console.error = prevErr;
      process.exitCode = prevExit;
    }
  });
  callChain = run.then(
    () => {},
    () => {},
  );
  return run;
}

// ─────────────────────────────────────────────────────────────────────────────
// Result + validation helpers (structured {code, message} error contract)
// ─────────────────────────────────────────────────────────────────────────────

class ToolError extends Error {
  code: string;
  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
}

function structuredOk(payload: Record<string, unknown>): CallToolResult {
  return {
    content: [{ type: 'text', text: JSON.stringify(payload, null, 2) }],
    structuredContent: payload,
  };
}

function structuredErr(errObj: unknown): CallToolResult {
  const rawMessage = errObj instanceof Error ? errObj.message : String(errObj);
  // issue #212: same stable "[CB-E0xx] see MANAGEMENT.md#error-codes" suffix the CLI
  // appends (cli.ts's main().catch) — applied HERE, the one place every tool call's
  // error funnels through, never at an individual throw site (no existing message body
  // changes). `cb_code` additionally surfaces the bare code as its own field — an AI
  // agent driving these tools can branch on it directly instead of regexing `message`.
  const cbCode = matchErrorCode(rawMessage)?.code;
  const payload = {
    code: errObj instanceof ToolError ? errObj.code : 'ERR_INTERNAL',
    message: annotateErrorMessage(rawMessage),
    ...(cbCode ? { cb_code: cbCode } : {}),
  };
  return {
    content: [{ type: 'text', text: JSON.stringify(payload, null, 2) }],
    structuredContent: payload,
    isError: true,
  };
}

function isStr(v: unknown): v is string {
  return typeof v === 'string' && v.length > 0;
}
function isStrArray(v: unknown): v is string[] {
  return Array.isArray(v) && v.every((x) => typeof x === 'string');
}
function isBool(v: unknown): v is boolean {
  return typeof v === 'boolean';
}

// wallet_create's `out` lets an MCP caller pick where the new JWK is written, and
// `force: true` overwrites whatever is already there — same as the CLI's own
// `wallet create --out --force`, but MCP's threat model is different: a shell-less
// caller (an AI agent acting on tool descriptions, possibly steered by adversarial
// input) has no OTHER path to an arbitrary-file-overwrite primitive the way a human
// with a shell already does. Scope `out` to CIPHER_BRAIN_HOME so this tool can only
// ever clobber cipher-brain's own key material, never an arbitrary server-writable
// file (multi-model review finding, PR #180 / issue #174).
function assertWithinHome(p: string): void {
  const resolved = resolve(p);
  const homeResolved = resolve(HOME);
  if (resolved !== homeResolved && !resolved.startsWith(homeResolved + sep)) {
    throw new ToolError('ERR_INVALID_INPUT', `out must be inside CIPHER_BRAIN_HOME (${HOME}), got: ${p}`);
  }
}

function requireBackend(value: unknown, what: string): asserts value is string {
  if (typeof value !== 'string' || !BACKENDS.includes(value)) {
    throw new ToolError(
      'ERR_INVALID_INPUT',
      `${what} must be one of ${BACKENDS.join('|')} — got ${JSON.stringify(value)}`,
    );
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tool descriptors (JSON Schemas advertised via tools/list)
// ─────────────────────────────────────────────────────────────────────────────

const SNAPSHOT_NOW_TOOL: Tool = {
  name: 'snapshot_now',
  description:
    '⚠ CAN SPEND MONEY (only tool in this server that can). Take an encrypted age snapshot of ' +
    'directories and/or a Postgres database, and optionally push the ciphertext to a storage ' +
    'backend. Backend "file" is free; "arweave" and "turbo" are PAID, PERMANENT ' +
    'stores — pushing to them REQUIRES confirm_paid=true (the MCP equivalent of the CLI --yes ' +
    'guard; the CIPHER_BRAIN_YES env escape hatch is NOT honored here, so nothing can be spent ' +
    'without an explicit confirm_paid in the call). Snapshotting itself needs only the PUBLIC ' +
    'recipient key(s); storage only ever sees ciphertext.',
  inputSchema: {
    type: 'object',
    properties: {
      dirs: {
        type: 'array',
        items: { type: 'string' },
        description: 'Directories to include (tar.gz each). At least one of dirs/pg is required.',
      },
      pg: { type: 'string', description: 'Postgres connection string to pg_dump into the snapshot.' },
      recipients: {
        type: 'array',
        items: { type: 'string' },
        minItems: 1,
        description:
          'age recipients (age1… pubkey or a recipients file path). Pass 2+ (primary + offline backup) for key recovery.',
      },
      out: {
        type: 'string',
        description: 'Output path for the .age ciphertext (must not already exist — no-clobber).',
      },
      backend: {
        type: 'string',
        enum: BACKENDS,
        description: 'When given, push the snapshot: file (free) or arweave|turbo (PAID — needs confirm_paid).',
      },
      locator_file: {
        type: 'string',
        description:
          'Path for push --save-locator: writes "<locator>\\t<backend>\\t<sha256>[\\t<content_digest>[\\t<recipients_fingerprint>]]" (the durable recovery pointer; back it up off-box).',
      },
      confirm_paid: {
        type: 'boolean',
        description: 'REQUIRED true to push to arweave/turbo. Confirms you accept an irreversible, real-money upload.',
      },
    },
    required: ['recipients', 'out'],
    additionalProperties: false,
  },
  annotations: {
    // Creates a new snapshot file (and, with backend, pushes it) — never
    // overwrites (out is no-clobber), so it adds state rather than destroying
    // existing state. Each call produces a distinct snapshot/spend, so it is
    // not idempotent. Talks to Postgres and/or the storage backends.
    readOnlyHint: false,
    destructiveHint: false,
    idempotentHint: false,
    openWorldHint: true,
  },
};

const LAST_SNAPSHOT_STATUS_TOOL: Tool = {
  name: 'last_snapshot_status',
  description:
    'Read-only, spends nothing. Report the most recent snapshot push: locator, backend, sha256, ' +
    'timestamp and age, read from the save-locator file (written by snapshot_now/push ' +
    'locator_file — "<locator>\\t<backend>\\t<sha256>[\\t<content_digest>[\\t<recipients_fingerprint>]]", ' +
    'legacy 3/4-field lines accepted, timestamped by file mtime) and/or an ' +
    'append-only index.tsv ("<timestamp>\\t<locator>\\t<sha256>" per line, newest last). With no ' +
    'arguments it tries the default save-locator path $CIPHER_BRAIN_HOME/latest-locator.tsv.',
  inputSchema: {
    type: 'object',
    properties: {
      locator_file: {
        type: 'string',
        description: 'Path to a push --save-locator file. Default: <CIPHER_BRAIN_HOME>/latest-locator.tsv',
      },
      index_file: {
        type: 'string',
        description: 'Path to an append-only index.tsv (timestamp<TAB>locator<TAB>sha256 lines).',
      },
    },
    additionalProperties: false,
  },
  annotations: {
    // Reads a local locator/index file only — no writes, no network calls.
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
  },
};

const VERIFY_RESTORE_TOOL: Tool = {
  name: 'verify_restore',
  description:
    'Read-only for your wallet (downloads only, never uploads or spends). Prove a snapshot is ' +
    'restorable: pull the ciphertext by locator, or verify a local file, or pass locator_file ' +
    '(a push --save-locator file) which supplies the locator, its backend AND the sha256 ' +
    'integrity pin in one — the same fail-closed recovery path as the CLI --from-locator-file. ' +
    'Then run the verify checks (age header, wrong-key rejection, and — when a private ' +
    'identity is available — a full decrypt proof). IMPORTANT: arweave/turbo locators are NOT ' +
    'content hashes, so verifying a bare locator without a sha256 pin cannot detect a gateway ' +
    'rollback/substitution that still decrypts with your key — pass sha256 (or use ' +
    'locator_file) to pin the fetched bytes; an unpinned arweave/turbo pull returns a warning ' +
    'field. Returns the HONEST verdict mirroring the CLI exit codes: PASS (exit 0, restorable ' +
    'by you), FAIL (exit 1), or PARTIAL (exit 2 — decryptability NOT proven, e.g. no private ' +
    'identity on this box; PARTIAL is never inflated to PASS).',
  inputSchema: {
    type: 'object',
    properties: {
      locator: {
        type: 'string',
        description: 'Storage locator to pull first (requires backend). Exactly one of locator/file/locator_file.',
      },
      file: {
        type: 'string',
        description: 'Local .age file to verify directly. Exactly one of locator/file/locator_file.',
      },
      locator_file: {
        type: 'string',
        description:
          'Path to a push --save-locator file ("<locator>\\t<backend>\\t<sha256>[\\t<content_digest>[\\t<recipients_fingerprint>]]"; legacy 3/4-field lines accepted): pull using its recorded locator + backend, with its saved sha256 applied as the integrity pin (the CLI --from-locator-file recovery path). Exactly one of locator/file/locator_file; do not also pass backend.',
      },
      backend: {
        type: 'string',
        enum: BACKENDS,
        description:
          'Backend to pull the locator from (required with locator; not allowed with locator_file — the file records it).',
      },
      sha256: {
        type: 'string',
        description:
          'Optional integrity pin: 64-hex sha256 of the expected ciphertext, sourced from a TRUSTED off-box record (index.tsv / a backed-up save-locator file). A pulled artifact that does not match is deleted and the call fails closed (no verdict); with file the mismatch is a hard FAIL verdict. Overrides the pin recorded in locator_file.',
      },
      identity: {
        type: 'string',
        description: 'Private identity file for the decrypt proof. Default: <CIPHER_BRAIN_HOME>/identity.age',
      },
    },
    additionalProperties: false,
  },
  annotations: {
    // Never uploads or spends (per description); a pulled artifact only lands
    // in a temp dir that this handler removes before returning. Pulling from
    // arweave/turbo/a gateway is a network call to an external store.
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: true,
  },
};

const RESTORE_NOW_TOOL: Tool = {
  name: 'restore_now',
  description:
    '⚠ WRITES decrypted files to disk, and can irreversibly clobber a database. The actual disaster-' +
    'recovery step verify_restore stops short of (issue #183): verify_restore only PROVES a snapshot is ' +
    'restorable, this tool actually restores it. Pull the ciphertext by locator, or restore a local file, ' +
    'or pass locator_file (a push --save-locator file) which supplies the locator, its backend AND the ' +
    'sha256 integrity pin in one — the SAME dual-mode input as verify_restore (exactly one of ' +
    'locator/file/locator_file). Decrypts with the PRIVATE identity and extracts into out_dir; extraction ' +
    'never clobbers a file already present there (tar --keep-old-files/--skip-old-files, same as the CLI). ' +
    'REQUIRES confirm_write=true before ANY work happens (pull/decrypt/extract): confirms writing decrypted ' +
    'files into out_dir, and — when pg is given — that pg_restore --clean --if-exists will ALSO DROP and ' +
    'replace objects in that database, an irreversible operation (the MCP equivalent of the CLI --yes/' +
    'CIPHER_BRAIN_YES guard on restore --pg; the CIPHER_BRAIN_YES env escape hatch is NOT honored here, so ' +
    'nothing can be restored/clobbered without an explicit confirm_write in the call).',
  inputSchema: {
    type: 'object',
    properties: {
      locator: {
        type: 'string',
        description: 'Storage locator to pull first (requires backend). Exactly one of locator/file/locator_file.',
      },
      file: {
        type: 'string',
        description: 'Local .age file to restore directly. Exactly one of locator/file/locator_file.',
      },
      locator_file: {
        type: 'string',
        description:
          'Path to a push --save-locator file ("<locator>\\t<backend>\\t<sha256>[\\t<content_digest>[\\t<recipients_fingerprint>]]"; legacy 3/4-field lines accepted): pull using its recorded locator + backend, with its saved sha256 applied as the integrity pin (the CLI --from-locator-file recovery path). Exactly one of locator/file/locator_file; do not also pass backend.',
      },
      backend: {
        type: 'string',
        enum: BACKENDS,
        description:
          'Backend to pull the locator from (required with locator; not allowed with locator_file — the file records it).',
      },
      sha256: {
        type: 'string',
        description:
          'Optional integrity pin: 64-hex sha256 of the expected ciphertext, sourced from a TRUSTED off-box record (index.tsv / a backed-up save-locator file). A pulled artifact that does not match is deleted and the call fails closed (no restore happens); with file the mismatch refuses before any decrypt/extract work. Overrides the pin recorded in locator_file.',
      },
      out_dir: {
        type: 'string',
        description:
          'Directory to extract the decrypted snapshot into (created if missing). Existing files already there are never clobbered.',
      },
      identity: {
        type: 'string',
        description: 'Private identity file to decrypt with. Default: <CIPHER_BRAIN_HOME>/identity.age',
      },
      pg: {
        type: 'string',
        description:
          "Postgres connection string to pg_restore the snapshot's db.dump into. pg_restore --clean --if-exists " +
          'DROPS and replaces objects in that database — irreversible — so this ALSO requires confirm_write=true ' +
          '(the MCP equivalent of the CLI --yes/CIPHER_BRAIN_YES guard on restore --pg).',
      },
      confirm_write: {
        type: 'boolean',
        description:
          'REQUIRED true to execute the restore. Confirms you accept decrypted files being written into out_dir, ' +
          'and — when pg is given — objects in that database being DROPPED and replaced via pg_restore --clean --if-exists.',
      },
    },
    required: ['out_dir'],
    additionalProperties: false,
  },
  annotations: {
    // The file extraction itself is no-clobber (like snapshot_now's --out), but
    // when pg is given, pg_restore --clean --if-exists DROPS and replaces
    // existing objects in that database — genuinely destructive, unlike
    // snapshot_now which never destroys existing state. Pulls from a storage
    // backend over the network.
    readOnlyHint: false,
    destructiveHint: true,
    idempotentHint: false,
    openWorldHint: true,
  },
};

const ESTIMATE_COST_TOOL: Tool = {
  name: 'estimate_cost',
  description:
    'Read-only, spends nothing (price queries only). Estimate what pushing a payload of the ' +
    'given size to a backend would cost: turbo → Turbo upload cost in winc via @ardrive/turbo-sdk ' +
    '(<100KB is free; a clear note is returned when that optional dependency is not installed); ' +
    'arweave → network price in winston from the gateway /price endpoint; file → free ' +
    '(local disk), returned with a zero-cost note. For turbo/arweave an ' +
    'approximate usd_estimate field is included when a USD/AR rate is fetchable — a direct HTTP ' +
    'call to the public Turbo rate endpoint, so it works with or without @ardrive/turbo-sdk ' +
    'installed (omitted on any rate failure — the native estimate never fails because of it).',
  inputSchema: {
    type: 'object',
    properties: {
      file: { type: 'string', description: 'Path of the payload to size (exactly one of file/size_bytes).' },
      size_bytes: {
        type: 'number',
        minimum: 0,
        description: 'Payload size in bytes (exactly one of file/size_bytes).',
      },
      backend: { type: 'string', enum: BACKENDS, description: 'Backend to estimate for.' },
    },
    required: ['backend'],
    additionalProperties: false,
  },
  annotations: {
    // Price queries only (per description) — reads a local file's size at
    // most, then calls the gateway/turbo rate endpoints for pricing.
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: true,
  },
};

const SCHEDULE_INSTALL_TOOL: Tool = {
  name: 'schedule_install',
  description:
    '⚠ WRITES a REAL, PERSISTENT system file (a launchd plist under ~/Library/LaunchAgents on ' +
    'macOS, or a crontab entry on Linux) and, unless no_load is set, REGISTERS it so the nightly ' +
    'snapshot+push runs unattended from now on (issue #174 follow-up — the MCP equivalent of the ' +
    "CLI's `schedule install`). A PAID backend (arweave/turbo) gets CIPHER_BRAIN_YES=1 baked into " +
    'the generated runner for unattended consent, so it ALSO REQUIRES max_spend (a positive integer ' +
    'cap in native units — winston for arweave, winc for turbo): an uncapped unattended spender is ' +
    'refused, same as the CLI. Requires confirm_install=true before ANY work happens — the MCP ' +
    'equivalent of consenting to both the real-system-file write and (for a paid backend) the ' +
    'ongoing capped spend risk every future unattended run carries; there is no environment escape ' +
    'hatch honored here. Only ONE schedule can be installed at a time; re-calling replaces the prior ' +
    'configuration (same as re-running the CLI command). Uses `cipher-brain schedule status` to ' +
    'read this back, and `schedule uninstall` — not exposed as a tool — to remove it by hand.',
  inputSchema: {
    type: 'object',
    properties: {
      backend: {
        type: 'string',
        enum: BACKENDS,
        description: 'Where the nightly push goes: file (free) or arweave|turbo (PAID — requires max_spend).',
      },
      dirs: {
        type: 'array',
        items: { type: 'string' },
        description: 'Directories to include in every nightly snapshot. At least one of dirs/pg is required.',
      },
      pg: { type: 'string', description: 'Postgres connection string to pg_dump into every nightly snapshot.' },
      recipients: {
        type: 'array',
        items: { type: 'string' },
        description:
          'age recipients (age1… pubkey or a recipients file path) to encrypt every nightly snapshot to. ' +
          'Defaults to the keypair\'s own recipient when omitted (same as the CLI\'s snapshot/schedule install).',
      },
      at: {
        type: 'string',
        description: 'Local time "HH:MM" to run nightly. Default 03:30 (after the source re-settles overnight).',
      },
      max_spend: {
        type: 'string',
        description:
          'REQUIRED for backend arweave|turbo: a positive integer cap (native units — winston/winc) on ' +
          'EVERY unattended run\'s spend. Not allowed for backend file (nothing to cap).',
      },
      no_load: {
        type: 'boolean',
        description:
          'Write the runner + plist/cron entry WITHOUT registering the trigger (launchctl/crontab left ' +
          'untouched) — a preview. The written file(s) still persist on disk; see the tool description.',
      },
      ping_url: {
        type: 'string',
        description:
          'Optional healthchecks.io-style dead man\'s switch: the runner curl\'s this URL (best-effort, ' +
          "never affects the run's own outcome) on every successful run.",
      },
      ping_url_fail: {
        type: 'string',
        description: 'Failure-ping URL override (default: ping_url + "/fail"). Requires ping_url to also be set.',
      },
      confirm_install: {
        type: 'boolean',
        description:
          'REQUIRED true to install. Confirms accepting a real, persistent system-file write and — for a ' +
          'paid backend — the ongoing capped spend risk every future unattended run carries.',
      },
    },
    required: ['backend'],
    additionalProperties: false,
  },
  annotations: {
    // Writes a real system file (plist/crontab) OUTSIDE CIPHER_BRAIN_HOME and,
    // unless no_load, registers it with launchd/cron — genuinely destructive in
    // the sense that re-installing replaces the prior configuration, and for a
    // paid backend it commits to an ongoing (capped) unattended spend. Not
    // idempotent: re-calling with different args produces a different runner/
    // trigger. Talks to launchctl/crontab (and, at run time, storage backends),
    // not just the local filesystem.
    readOnlyHint: false,
    destructiveHint: true,
    idempotentHint: false,
    openWorldHint: true,
  },
};

const SCHEDULE_STATUS_TOOL: Tool = {
  name: 'schedule_status',
  description:
    'Read-only, spends nothing, mutates nothing. Report the state of the nightly schedule set up ' +
    'by `cipher-brain schedule install`: the configured time + backend, whether the launchd/cron ' +
    'trigger is actually registered, the last run\'s log filename and its final "OK rc=0"/"FAILED ' +
    'rc=N" line, and the next scheduled run — the SAME report `cipher-brain schedule status` prints ' +
    'on the CLI, verbatim (one string per line). No arguments. Fails with ERR_INTERNAL if no ' +
    'schedule is installed yet — call schedule_install first.',
  inputSchema: {
    type: 'object',
    properties: {},
    additionalProperties: false,
  },
  annotations: {
    // Reads the launchd/cron registration + the last run's log file — spends
    // and mutates nothing (per description).
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
  },
};

const KEYGEN_TOOL: Tool = {
  name: 'keygen',
  description:
    '⚠ WRITES a new identity/recipient keypair — the FIRST-RUN setup step a shell-less agent otherwise ' +
    'cannot do (issue #174): snapshot_now/verify_restore need this keypair to already exist, and there ' +
    'was no MCP tool that could create one. Spends no money, but is destructive the same way a ' +
    'money-gated call is: it refuses if an identity/recipient already exists at ' +
    '<CIPHER_BRAIN_HOME>/{identity.age,recipient.txt} UNLESS force=true, and force=true DISCARDS the old ' +
    'keypair — every snapshot already encrypted to it becomes permanently unrecoverable. ' +
    'passphrase=true additionally wraps the new identity at rest; since MCP has no interactive TTY this ' +
    'REQUIRES CIPHER_BRAIN_PASSPHRASE to be set in the server environment (fails closed with a clear ' +
    'error otherwise — never prompts blindly).',
  inputSchema: {
    type: 'object',
    properties: {
      force: {
        type: 'boolean',
        description:
          'Delete and overwrite an existing identity/recipient. DESTRUCTIVE — the old identity is ' +
          'discarded, so every snapshot already encrypted to it becomes unrecoverable.',
      },
      passphrase: {
        type: 'boolean',
        description:
          'Wrap the new identity with a passphrase (scrypt). Requires CIPHER_BRAIN_PASSPHRASE set in ' +
          'the server environment (no TTY is available over MCP to prompt for one).',
      },
      pq: {
        type: 'boolean',
        description:
          'Generate a POST-QUANTUM HYBRID keypair (ML-KEM-768 + X25519, #205) instead of plain X25519 ' +
          '— mitigates "harvest now, decrypt later" (see README Threat model), at the cost of a much ' +
          'bigger recipient/identity and per-recipient ciphertext overhead.',
      },
    },
    additionalProperties: false,
  },
  annotations: {
    // force=true discards the existing identity/recipient — every snapshot
    // already encrypted to it becomes permanently unrecoverable — so this is
    // destructive the same way keygen's description frames it. Each call
    // generates a fresh random keypair, so repeat calls are not idempotent.
    // Purely local key generation, no network calls.
    readOnlyHint: false,
    destructiveHint: true,
    idempotentHint: false,
    openWorldHint: false,
  },
};

const WALLET_CREATE_TOOL: Tool = {
  name: 'wallet_create',
  description:
    '⚠ WRITES a new Arweave JWK wallet — the funding half of first-run setup (issue #174): ' +
    'arweave/turbo pushes need CIPHER_BRAIN_AR_WALLET to point at a JWK file, and there was no MCP tool ' +
    'that could create one. Spends no money by itself, but is destructive the same way keygen is: it ' +
    'refuses if a wallet already exists at the target path UNLESS force=true, and force=true DISCARDS ' +
    'the old JWK — the only credential able to spend any AR/Turbo Credits already sent to its address. ' +
    'Writes to <CIPHER_BRAIN_HOME>/wallet.json by default (out overrides the path).',
  inputSchema: {
    type: 'object',
    properties: {
      out: {
        type: 'string',
        description:
          'Output path for the wallet JWK file — must be inside CIPHER_BRAIN_HOME. Default: ' +
          '<CIPHER_BRAIN_HOME>/wallet.json',
      },
      force: {
        type: 'boolean',
        description:
          'Delete and overwrite an existing wallet file at the target path. DESTRUCTIVE — discards spend ' +
          'authority over any AR/Turbo Credits already sent to its address.',
      },
    },
    additionalProperties: false,
  },
  annotations: {
    // force=true discards the existing wallet — the only credential able to
    // spend any AR/Turbo Credits already sent to its address — so this is
    // destructive the same way keygen's force is. Each call generates a fresh
    // random JWK, so repeat calls are not idempotent. Purely local
    // key/file generation, no network calls.
    readOnlyHint: false,
    destructiveHint: true,
    idempotentHint: false,
    openWorldHint: false,
  },
};

const WALLET_ADDRESS_TOOL: Tool = {
  name: 'wallet_address',
  description:
    'Read-only, spends nothing — derives and shows the Arweave address for a JWK wallet file (the ' +
    'address to FUND, e.g. via app.ardrive.io / turbo.ar.io, before pushing to arweave/turbo). Defaults ' +
    'to $CIPHER_BRAIN_AR_WALLET, then <CIPHER_BRAIN_HOME>/wallet.json (the same default wallet_create ' +
    'writes to) when wallet is omitted.',
  inputSchema: {
    type: 'object',
    properties: {
      wallet: {
        type: 'string',
        description:
          'Path to the JWK wallet file. Default: $CIPHER_BRAIN_AR_WALLET, then <CIPHER_BRAIN_HOME>/wallet.json',
      },
    },
    additionalProperties: false,
  },
  annotations: {
    // Read-only, spends nothing (per description) — derives the address from
    // a local JWK file with no side effects; the same wallet always yields
    // the same address, and there is no network call.
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
  },
};

const ALL_TOOLS: Tool[] = [
  SNAPSHOT_NOW_TOOL,
  LAST_SNAPSHOT_STATUS_TOOL,
  VERIFY_RESTORE_TOOL,
  RESTORE_NOW_TOOL,
  ESTIMATE_COST_TOOL,
  SCHEDULE_INSTALL_TOOL,
  SCHEDULE_STATUS_TOOL,
  KEYGEN_TOOL,
  WALLET_CREATE_TOOL,
  WALLET_ADDRESS_TOOL,
];

// ─────────────────────────────────────────────────────────────────────────────
// Handlers
// ─────────────────────────────────────────────────────────────────────────────

async function handleSnapshotNow(args: ToolArgs): Promise<CallToolResult> {
  const { dirs = [], pg, recipients, out, backend, locator_file: locatorFile, confirm_paid: confirmPaid } = args;
  if (!isStrArray(recipients) || recipients.length === 0)
    throw new ToolError(
      'ERR_INVALID_INPUT',
      'recipients must be a non-empty array of strings (age1… pubkeys or recipient file paths)',
    );
  if (!isStr(out)) throw new ToolError('ERR_INVALID_INPUT', 'out (string path for the .age ciphertext) is required');
  if (!isStrArray(dirs)) throw new ToolError('ERR_INVALID_INPUT', 'dirs must be an array of strings');
  if (backend !== undefined) requireBackend(backend, 'backend');
  if (pg !== undefined && !isStr(pg)) throw new ToolError('ERR_INVALID_INPUT', 'pg must be a string connection URI');
  if (locatorFile !== undefined && !isStr(locatorFile))
    throw new ToolError('ERR_INVALID_INPUT', 'locator_file must be a string path');
  // Spend gate FIRST — before any snapshot work — so a refused paid push does no
  // work and leaves no artifact behind. Never silently spend: the CLI accepts
  // CIPHER_BRAIN_YES=1 for unattended cadence loops, but via MCP the consent
  // must be in the call itself.
  if (backend && PAID_BACKENDS.has(backend) && confirmPaid !== true) {
    throw new ToolError(
      'ERR_CONFIRM_REQUIRED',
      `backend "${backend}" is a PAID, PERMANENT Arweave store — pushing spends real funds ` +
        `irreversibly. Re-call snapshot_now with confirm_paid=true to consent (the MCP equivalent ` +
        `of the CLI --yes guard). The CIPHER_BRAIN_YES environment escape hatch is not honored ` +
        `over MCP, so no call can spend without this flag.`,
    );
  }

  const snapOpts: CliOptions = { out, pg, dirs, tables: [], recipients };
  const snap = await captureCall(() => snapshot(snapOpts));
  const size = (await stat(out)).size;
  const digest = await sha256(out);

  const result: Record<string, unknown> = {
    out,
    size_bytes: size,
    sha256: digest,
    pushed: false,
    log: [...snap.out, ...snap.err],
  };

  if (backend) {
    const pushOpts: CliOptions = {
      in: out,
      backend,
      yes: confirmPaid === true,
      save_locator: locatorFile,
      dirs: [],
      tables: [],
      recipients: [],
    };
    const pushRes = await captureCall(() => push(pushOpts));
    const locator = pushRes.out.join('\n').trim(); // push() prints ONLY the locator to stdout
    result.pushed = true;
    result.backend = backend;
    result.locator = locator;
    if (locatorFile) result.locator_file = locatorFile;
    (result.log as string[]).push(...pushRes.err);
  }
  return structuredOk(result);
}

interface LocatorSource {
  source: 'locator_file' | 'index_file';
  path: string;
  locator: string;
  backend: string | null;
  sha256: string | null;
  content_digest?: string | null;
  timestamp: string;
  entries?: number;
  age_seconds?: number | null;
}

// Parse one save-locator file ("<locator>\t<backend>\t<sha256>[\t<content_digest>[\t
// <recipients_fingerprint>]]", latest only; timestamp = file mtime since push does not
// record one in it). Legacy 3-field lines (pre-#70, no content_digest) and 4-field
// lines (no recipients_fingerprint) parse identically — never break the recovery of
// an existing file.
async function readLocatorFile(path: string): Promise<LocatorSource> {
  const text = await readFile(path, 'utf8');
  const line = text
    .split('\n')
    .map((l) => l.trim())
    .find((l) => l && !l.startsWith('#'));
  if (!line) throw new ToolError('ERR_INVALID_INPUT', `locator file ${path} has no locator line`);
  const [locator, backend, digest, contentDigest] = line.split('\t');
  if (!locator || !backend)
    throw new ToolError(
      'ERR_INVALID_INPUT',
      `locator file ${path} must contain "<locator>\\t<backend>[\\t<sha256>[\\t<content_digest>[\\t<recipients_fingerprint>]]]" — got: ${JSON.stringify(line)}`,
    );
  const { mtime } = await stat(path);
  return {
    source: 'locator_file',
    path,
    locator,
    backend,
    sha256: digest || null,
    content_digest: contentDigest || null,
    timestamp: mtime.toISOString(),
  };
}

// Parse an append-only index.tsv ("<timestamp>\t<locator>\t<sha256>", newest LAST).
async function readIndexFile(path: string): Promise<LocatorSource> {
  const text = await readFile(path, 'utf8');
  const lines = text
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith('#'));
  if (lines.length === 0) throw new ToolError('ERR_INVALID_INPUT', `index file ${path} has no entries`);
  const last = lines[lines.length - 1];
  const [timestamp, locator, digest] = last.split('\t');
  if (!timestamp || !locator)
    throw new ToolError(
      'ERR_INVALID_INPUT',
      `index file ${path} lines must be "<timestamp>\\t<locator>[\\t<sha256>]" — got: ${JSON.stringify(last)}`,
    );
  // The index records timestamp+locator+sha256 but not the backend — that lives
  // in the save-locator file / the push command itself.
  return {
    source: 'index_file',
    path,
    locator,
    backend: null,
    sha256: digest || null,
    timestamp,
    entries: lines.length,
  };
}

const ageSeconds = (iso: string): number | null => {
  const t = Date.parse(iso);
  return Number.isNaN(t) ? null : Math.max(0, Math.round((Date.now() - t) / 1000));
};

async function handleLastSnapshotStatus(args: ToolArgs): Promise<CallToolResult> {
  if (args.locator_file !== undefined && !isStr(args.locator_file))
    throw new ToolError('ERR_INVALID_INPUT', 'locator_file must be a string path');
  if (args.index_file !== undefined && !isStr(args.index_file))
    throw new ToolError('ERR_INVALID_INPUT', 'index_file must be a string path');
  let locatorFile: string | undefined = isStr(args.locator_file) ? args.locator_file : undefined;
  const indexFile: string | undefined = isStr(args.index_file) ? args.index_file : undefined;
  let defaulted = false;
  if (!locatorFile && !indexFile) {
    locatorFile = join(HOME, 'latest-locator.tsv'); // the MANAGEMENT.md cadence default
    defaulted = true;
    if (!(await exists(locatorFile))) {
      throw new ToolError(
        'ERR_INVALID_INPUT',
        `no locator_file/index_file given and the default save-locator file does not exist: ${locatorFile}. Pass locator_file (a push --save-locator file) or index_file (an append-only index.tsv).`,
      );
    }
  }
  const sources: LocatorSource[] = [];
  if (locatorFile) {
    if (!(await exists(locatorFile))) throw new ToolError('ERR_INVALID_INPUT', `no such locator file: ${locatorFile}`);
    sources.push(await readLocatorFile(locatorFile));
  }
  if (indexFile) {
    if (!(await exists(indexFile))) throw new ToolError('ERR_INVALID_INPUT', `no such index file: ${indexFile}`);
    sources.push(await readIndexFile(indexFile));
  }
  for (const s of sources) s.age_seconds = ageSeconds(s.timestamp);
  // latest = the newest-timestamped entry across whichever sources were readable
  const latest = sources.slice().sort((a, b) => Date.parse(b.timestamp) - Date.parse(a.timestamp))[0];
  return structuredOk({ latest, sources, defaulted_to: defaulted ? locatorFile : undefined });
}

async function handleVerifyRestore(args: ToolArgs): Promise<CallToolResult> {
  const { locator, file, backend, identity, sha256: pin, locator_file: locatorFile } = args;
  const given = [locator, file, locatorFile].filter((v) => v !== undefined).length;
  if (given !== 1) {
    throw new ToolError(
      'ERR_INVALID_INPUT',
      'pass exactly one of locator (pull first), file (verify a local .age), or locator_file (a push --save-locator file: locator + backend + sha256 pin in one)',
    );
  }
  if (locatorFile !== undefined) {
    if (!isStr(locatorFile)) throw new ToolError('ERR_INVALID_INPUT', 'locator_file must be a string path');
    if (backend !== undefined)
      throw new ToolError(
        'ERR_INVALID_INPUT',
        'backend cannot be combined with locator_file — the file records the backend itself',
      );
  }
  if (pin !== undefined && !(isStr(pin) && SHA256_HEX.test(pin))) {
    throw new ToolError(
      'ERR_INVALID_INPUT',
      'sha256 must be a 64-char hex string (the expected ciphertext digest, from a trusted off-box record)',
    );
  }
  if (identity !== undefined && !isStr(identity))
    throw new ToolError('ERR_INVALID_INPUT', 'identity must be a string path');
  let target: string | undefined = isStr(file) ? file : undefined;
  let effectivePin: string | undefined = isStr(pin) ? pin : undefined;
  let tdir: string | null = null;
  let pulled: Record<string, unknown> | undefined;
  let warning: string | undefined;
  try {
    if (file === undefined) {
      if (locator !== undefined) {
        if (!isStr(locator)) throw new ToolError('ERR_INVALID_INPUT', 'locator must be a string');
        requireBackend(backend, 'backend (required with locator)');
      }
      tdir = await mkdtemp(join(tmpdir(), 'cipher-brain-mcp-'));
      target = join(tdir, 'pulled.age');
      // pull() natively understands from_locator_file — the SAME parsing + pin
      // application as the CLI recovery path (src/lib/pushpull.ts) — and fills
      // the resolved locator/backend/sha256 back into this options object. A
      // sha256 mismatch deletes the artifact and throws: fail closed, no verdict.
      const pullOpts: CliOptions = {
        locator: isStr(locator) ? locator : undefined,
        backend: isStr(backend) ? backend : undefined,
        out: target,
        sha256: effectivePin,
        from_locator_file: isStr(locatorFile) ? locatorFile : undefined,
        dirs: [],
        tables: [],
        recipients: [],
      };
      await captureCall(() => pull(pullOpts));
      effectivePin = pullOpts.sha256;
      pulled = {
        backend: pullOpts.backend,
        locator: pullOpts.locator,
        sha256_pin: effectivePin ?? null,
        ...(locatorFile !== undefined ? { locator_file: locatorFile } : {}),
      };
      if (!effectivePin && pullOpts.backend && NON_CONTENT_ADDRESSED_BACKENDS.has(pullOpts.backend)) {
        warning =
          `integrity pin NOT applied: ${pullOpts.backend} locators are post-assigned ids, not content hashes, ` +
          'so a gateway rollback/substitution that still decrypts with your key would go undetected by this ' +
          'verdict. Pass sha256 (the expected ciphertext digest from a trusted off-box record, e.g. index.tsv) ' +
          'or use locator_file (a push --save-locator file, which carries the pin) to fail closed like the CLI recovery path.';
      }
    } else if (!isStr(file)) {
      throw new ToolError('ERR_INVALID_INPUT', 'file must be a string path');
    }
    if (!target) throw new ToolError('ERR_INTERNAL', 'no target file resolved for verify');
    // The pin (explicit or read from locator_file) is ALSO handed to verify() so
    // the checks record "[PASS] sha256 matches the expected hash" like the CLI;
    // for a local file this is where the pin is enforced (mismatch = FAIL).
    const verifyOpts: CliOptions = {
      in: target,
      identity: isStr(identity) ? identity : undefined,
      sha256: effectivePin,
      dirs: [],
      tables: [],
      recipients: [],
    };
    const res = await captureCall(() => verify(verifyOpts));
    // verify() reports through process.exitCode: 0 PASS, 1 FAIL, 2 PARTIAL.
    const verdict = res.exitCode === 0 ? 'PASS' : res.exitCode === 2 ? 'PARTIAL' : 'FAIL';
    return structuredOk({
      verdict,
      exit_code: res.exitCode,
      restorable_proven: verdict === 'PASS', // PARTIAL ≠ PASS: decryptability was not proven
      checks: res.out,
      ...(pulled ? { pulled } : {}),
      ...(warning ? { warning } : {}),
      ...(verdict === 'PARTIAL'
        ? {
            note: 'header + wrong-key checks passed but no private identity could prove decryptability on this box — run verify_restore where the identity lives for a full PASS.',
          }
        : {}),
    });
  } finally {
    if (tdir) await rm(tdir, { recursive: true, force: true });
  }
}

// restore_now shares its dual-mode locator/file/locator_file input resolution with
// verify_restore above (pull into a scratch tmpdir, or use a local file directly),
// then hands the resolved .age path to restore() (src/lib/restore.ts) — the SAME
// function the CLI's `restore` subcommand dispatches to — instead of re-implementing
// the decrypt+extract(+pg_restore) logic here.
async function handleRestoreNow(args: ToolArgs): Promise<CallToolResult> {
  const {
    locator,
    file,
    locator_file: locatorFile,
    backend,
    sha256: pin,
    out_dir: outDir,
    identity,
    pg,
    confirm_write: confirmWrite,
  } = args;

  const given = [locator, file, locatorFile].filter((v) => v !== undefined).length;
  if (given !== 1) {
    throw new ToolError(
      'ERR_INVALID_INPUT',
      'pass exactly one of locator (pull first), file (restore a local .age), or locator_file (a push --save-locator file: locator + backend + sha256 pin in one)',
    );
  }
  if (locatorFile !== undefined) {
    if (!isStr(locatorFile)) throw new ToolError('ERR_INVALID_INPUT', 'locator_file must be a string path');
    if (backend !== undefined)
      throw new ToolError(
        'ERR_INVALID_INPUT',
        'backend cannot be combined with locator_file — the file records the backend itself',
      );
  }
  if (pin !== undefined && !(isStr(pin) && SHA256_HEX.test(pin))) {
    throw new ToolError(
      'ERR_INVALID_INPUT',
      'sha256 must be a 64-char hex string (the expected ciphertext digest, from a trusted off-box record)',
    );
  }
  if (!isStr(outDir)) throw new ToolError('ERR_INVALID_INPUT', 'out_dir (string path) is required');
  if (identity !== undefined && !isStr(identity))
    throw new ToolError('ERR_INVALID_INPUT', 'identity must be a string path');
  if (pg !== undefined && !isStr(pg)) throw new ToolError('ERR_INVALID_INPUT', 'pg must be a string connection URI');
  if (confirmWrite !== undefined && !isBool(confirmWrite))
    throw new ToolError('ERR_INVALID_INPUT', 'confirm_write must be a boolean');

  // Consequential-action gate FIRST — before any pull/decrypt/extract work happens,
  // same "check before work" discipline as snapshot_now's confirm_paid gate above.
  // Restoring writes decrypted files into out_dir, and when pg is given ALSO runs
  // pg_restore --clean --if-exists (DROPS and replaces objects in that database).
  // The CLI accepts CIPHER_BRAIN_YES=1 for unattended runs, but via MCP the consent
  // must be in the call itself — the env escape hatch is deliberately NOT honored here.
  if (confirmWrite !== true) {
    throw new ToolError(
      'ERR_CONFIRM_REQUIRED',
      'restore_now writes decrypted files into out_dir' +
        (pg
          ? ', and pg is given so pg_restore --clean --if-exists will DROP and replace objects in that database'
          : '') +
        ' — re-call restore_now with confirm_write=true to consent (the MCP equivalent of the CLI --yes guard). ' +
        'The CIPHER_BRAIN_YES environment escape hatch is not honored over MCP, so no call can restore/clobber ' +
        'without this flag.',
    );
  }

  let target: string | undefined = isStr(file) ? file : undefined;
  let effectivePin: string | undefined = isStr(pin) ? pin : undefined;
  let tdir: string | null = null;
  let pulled: Record<string, unknown> | undefined;
  try {
    if (file === undefined) {
      if (locator !== undefined) {
        if (!isStr(locator)) throw new ToolError('ERR_INVALID_INPUT', 'locator must be a string');
        requireBackend(backend, 'backend (required with locator)');
      }
      tdir = await mkdtemp(join(tmpdir(), 'cipher-brain-mcp-'));
      target = join(tdir, 'pulled.age');
      // pull() natively understands from_locator_file and applies the sha256 pin
      // (explicit or read from the locator file) BEFORE the fetched bytes are
      // promoted to `target` — a mismatch deletes the temp fetch and throws, so
      // nothing here is ever decrypted/extracted from an unpinned/substituted artifact.
      const pullOpts: CliOptions = {
        locator: isStr(locator) ? locator : undefined,
        backend: isStr(backend) ? backend : undefined,
        out: target,
        sha256: effectivePin,
        from_locator_file: isStr(locatorFile) ? locatorFile : undefined,
        dirs: [],
        tables: [],
        recipients: [],
      };
      await captureCall(() => pull(pullOpts));
      effectivePin = pullOpts.sha256;
      pulled = {
        backend: pullOpts.backend,
        locator: pullOpts.locator,
        sha256_pin: effectivePin ?? null,
        ...(locatorFile !== undefined ? { locator_file: locatorFile } : {}),
      };
    } else if (!isStr(file)) {
      throw new ToolError('ERR_INVALID_INPUT', 'file must be a string path');
    } else if (effectivePin) {
      // Unlike a pulled artifact (pinned above by pull() itself), a directly-given
      // `file` never passes through that check — apply the SAME pin here so file
      // and locator/locator_file inputs get identical integrity guarantees before
      // any decrypt/extract work runs (restore(), unlike verify(), does not check
      // sha256 itself). Copy `file` into our own private tmpdir FIRST, then hash
      // and restore that copy — never re-open the caller-given path a second time
      // (a hash-then-reopen would leave a window where the file at that path
      // could change between the two operations; copying once removes it).
      tdir = await mkdtemp(join(tmpdir(), 'cipher-brain-mcp-'));
      const pinnedCopy = join(tdir, 'given.age');
      await copyFile(file, pinnedCopy);
      target = pinnedCopy;
      const got = await sha256(target);
      if (got.toLowerCase() !== effectivePin.toLowerCase()) {
        throw new ToolError(
          'ERR_INVALID_INPUT',
          `sha256 mismatch: ${file} has ${got}, expected ${effectivePin} — refusing to restore an unverified artifact`,
        );
      }
    }

    const restoreOpts: CliOptions = {
      in: target,
      out_dir: outDir,
      identity: isStr(identity) ? identity : undefined,
      pg: isStr(pg) ? pg : undefined,
      yes: true, // already gated above by confirm_write; restore()'s own --pg guard needs this to proceed
      dirs: [],
      tables: [],
      recipients: [],
    };
    const res = await captureCall(() => restore(restoreOpts));
    return structuredOk({
      out_dir: outDir,
      ...(pulled ? { pulled } : {}),
      pg_restored: Boolean(pg),
      log: [...res.out, ...res.err],
    });
  } finally {
    if (tdir) await rm(tdir, { recursive: true, force: true });
  }
}

async function handleEstimateCost(args: ToolArgs): Promise<CallToolResult> {
  const { file, size_bytes: sizeBytes, backend } = args;
  requireBackend(backend, 'backend');
  if ((file === undefined) === (sizeBytes === undefined)) {
    throw new ToolError('ERR_INVALID_INPUT', 'pass exactly one of file (a path to size) or size_bytes');
  }
  let size: number;
  if (file !== undefined) {
    if (!isStr(file)) throw new ToolError('ERR_INVALID_INPUT', 'file must be a string path');
    if (!(await exists(file))) throw new ToolError('ERR_INVALID_INPUT', `no such file: ${file}`);
    size = (await stat(file)).size;
  } else {
    if (typeof sizeBytes !== 'number' || !Number.isFinite(sizeBytes) || sizeBytes < 0)
      throw new ToolError('ERR_INVALID_INPUT', 'size_bytes must be a non-negative number');
    size = Math.ceil(sizeBytes);
  }
  // The actual price computation (file/turbo/arweave, incl. the optional usd_estimate)
  // lives in src/lib/estimate.ts — the SAME function the CLI `estimate` command calls,
  // so this math is never re-implemented per surface (#159).
  return structuredOk({ ...(await estimateCost(backend, size)) });
}

// schedule({_: 'install', ...}) is the SAME function + dispatch branch the CLI's
// `schedule install` subcommand uses — install() itself returns void (progress
// only via console.error, no console.log data lines), so this returns the
// captured log verbatim plus an echo of the args that were actually consented
// to, rather than re-parsing/re-deriving the written config (same "no
// re-implemented logic" approach as handleScheduleStatus below).
async function handleScheduleInstall(args: ToolArgs): Promise<CallToolResult> {
  const {
    backend,
    dirs = [],
    pg,
    recipients = [],
    at,
    max_spend: maxSpend,
    no_load: noLoad,
    ping_url: pingUrl,
    ping_url_fail: pingUrlFail,
    confirm_install: confirmInstall,
  } = args;
  requireBackend(backend, 'backend');
  if (!isStrArray(dirs)) throw new ToolError('ERR_INVALID_INPUT', 'dirs must be an array of strings');
  if (pg !== undefined && !isStr(pg)) throw new ToolError('ERR_INVALID_INPUT', 'pg must be a string connection URI');
  if (!isStrArray(recipients)) throw new ToolError('ERR_INVALID_INPUT', 'recipients must be an array of strings');
  if (at !== undefined && !isStr(at)) throw new ToolError('ERR_INVALID_INPUT', 'at must be a string "HH:MM"');
  if (maxSpend !== undefined && !isStr(maxSpend))
    throw new ToolError('ERR_INVALID_INPUT', 'max_spend must be a string (a positive integer in native units)');
  if (noLoad !== undefined && !isBool(noLoad)) throw new ToolError('ERR_INVALID_INPUT', 'no_load must be a boolean');
  if (pingUrl !== undefined && !isStr(pingUrl))
    throw new ToolError('ERR_INVALID_INPUT', 'ping_url must be a string');
  if (pingUrlFail !== undefined && !isStr(pingUrlFail))
    throw new ToolError('ERR_INVALID_INPUT', 'ping_url_fail must be a string');

  // Consequential-action gate FIRST — before any file write happens, same
  // discipline as every other mutating tool in this server. Covers BOTH the
  // real-system-file write and, for a paid backend, the ongoing capped spend
  // every future unattended run carries — there is no env escape hatch here.
  if (confirmInstall !== true) {
    throw new ToolError(
      'ERR_CONFIRM_REQUIRED',
      'schedule_install writes a real, persistent system file (a launchd plist or crontab entry)' +
        (PAID_BACKENDS.has(backend)
          ? ` and, since backend "${backend}" is paid, commits to an ongoing spend capped at max_spend on every future unattended run`
          : '') +
        ' — re-call schedule_install with confirm_install=true to consent. There is no environment escape hatch honored over MCP.',
    );
  }

  const installOpts: CliOptions = {
    _: 'install',
    backend,
    dirs,
    pg,
    recipients,
    at,
    max_spend: maxSpend,
    no_load: noLoad,
    ping_url: pingUrl,
    ping_url_fail: pingUrlFail,
    tables: [],
  };
  const res = await captureCall(() => schedule(installOpts));
  return structuredOk({
    backend,
    at: at || '03:30',
    no_load: Boolean(noLoad),
    ...(maxSpend ? { max_spend: maxSpend } : {}),
    log: [...res.out, ...res.err],
  });
}

// schedule() (src/lib/schedule.ts, the SAME function the CLI's `schedule status`
// subcommand dispatches to via `case 'schedule': return schedule(o)`) has no
// return value — its report is entirely console.log lines. Re-parsing that text
// into structured fields here would be exactly the re-implemented logic the
// module comment at the top of this file rules out, so it is captured and
// returned verbatim instead (one array entry per line, in print order).
async function handleScheduleStatus(args: ToolArgs): Promise<CallToolResult> {
  // The low-level Server does not enforce the advertised inputSchema
  // (additionalProperties: false) at runtime, so a stray/misunderstood field
  // (e.g. a client expecting a schedule_dir override) would otherwise be
  // silently discarded and this would report the server's own configured
  // schedule instead of failing loud.
  const unexpected = Object.keys(args);
  if (unexpected.length > 0)
    throw new ToolError('ERR_INVALID_INPUT', `schedule_status takes no arguments — got: ${unexpected.join(', ')}`);
  const res = await captureCall(() => schedule({ _: 'status', dirs: [], tables: [], recipients: [] }));
  return structuredOk({ report: res.out });
}

// keygenAt() (src/lib/keys.ts) is the SAME generation logic `cipher-brain keygen`
// calls (keygen() is a thin wrapper over it for the module's global HOME/IDENTITY/
// RECIPIENT paths) — used directly here (rather than keygen()) because it RETURNS
// { recipient, wrapped } instead of only printing them, so this handler returns
// structured fields instead of re-parsing console.log lines.
async function handleKeygen(args: ToolArgs): Promise<CallToolResult> {
  const { force, passphrase, pq } = args;
  if (force !== undefined && !isBool(force)) throw new ToolError('ERR_INVALID_INPUT', 'force must be a boolean');
  if (passphrase !== undefined && !isBool(passphrase))
    throw new ToolError('ERR_INVALID_INPUT', 'passphrase must be a boolean');
  if (pq !== undefined && !isBool(pq)) throw new ToolError('ERR_INVALID_INPUT', 'pq must be a boolean');
  const res = await captureCall(() =>
    keygenAt({ home: HOME, identityPath: IDENTITY, recipientPath: RECIPIENT, passphrase, force, pq }),
  );
  return structuredOk({
    identity_path: IDENTITY,
    recipient_path: RECIPIENT,
    recipient: res.value.recipient,
    passphrase_wrapped: res.value.wrapped,
    post_quantum: !!pq,
    log: [...res.out, ...res.err],
  });
}

// wallet({_: 'create'|'address'}) (src/lib/wallet.ts) is the SAME dispatch the CLI's
// `wallet create`/`wallet address` subcommands use — it has no structured return (void,
// console.log only), so unlike keygen above these two just capture + return its output
// lines, mirroring handleScheduleStatus's "no re-implemented logic" approach. Each
// printed line has exactly one trailing token that IS the field of interest (a path or
// an address, neither of which can contain whitespace), so pulling the last
// whitespace-separated token is a stable read of a fixed, first-party console.log
// format — not a parse of arbitrary text.
const lastToken = (line: string | undefined): string | undefined => line?.trim().split(/\s+/).pop();

async function handleWalletCreate(args: ToolArgs): Promise<CallToolResult> {
  const { out, force } = args;
  if (out !== undefined && !isStr(out)) throw new ToolError('ERR_INVALID_INPUT', 'out must be a string path');
  if (force !== undefined && !isBool(force)) throw new ToolError('ERR_INVALID_INPUT', 'force must be a boolean');
  if (isStr(out)) assertWithinHome(out);
  const walletOpts: CliOptions = {
    _: 'create',
    dirs: [],
    tables: [],
    recipients: [],
    out: isStr(out) ? out : undefined,
    force,
  };
  const res = await captureCall(() => wallet(walletOpts));
  return structuredOk({
    wallet_path: lastToken(res.out[0]),
    address: lastToken(res.out[1]),
    log: [...res.out, ...res.err],
  });
}

async function handleWalletAddress(args: ToolArgs): Promise<CallToolResult> {
  const { wallet: walletPath } = args;
  if (walletPath !== undefined && !isStr(walletPath))
    throw new ToolError('ERR_INVALID_INPUT', 'wallet must be a string path');
  const walletOpts: CliOptions = {
    _: 'address',
    dirs: [],
    tables: [],
    recipients: [],
    wallet: isStr(walletPath) ? walletPath : undefined,
  };
  const res = await captureCall(() => wallet(walletOpts));
  return structuredOk({ address: lastToken(res.out[0]), log: [...res.out, ...res.err] });
}

// ─────────────────────────────────────────────────────────────────────────────
// Server bootstrap
// ─────────────────────────────────────────────────────────────────────────────

const server = new Server({ name: SERVER_NAME, version: SERVER_VERSION }, { capabilities: { tools: {} } });

server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: ALL_TOOLS }));

server.setRequestHandler(CallToolRequestSchema, async (request): Promise<CallToolResult> => {
  const name = request.params.name;
  const args: ToolArgs = request.params.arguments ?? {};
  try {
    switch (name) {
      case 'snapshot_now':
        return await handleSnapshotNow(args);
      case 'last_snapshot_status':
        return await handleLastSnapshotStatus(args);
      case 'verify_restore':
        return await handleVerifyRestore(args);
      case 'restore_now':
        return await handleRestoreNow(args);
      case 'estimate_cost':
        return await handleEstimateCost(args);
      case 'schedule_install':
        return await handleScheduleInstall(args);
      case 'schedule_status':
        return await handleScheduleStatus(args);
      case 'keygen':
        return await handleKeygen(args);
      case 'wallet_create':
        return await handleWalletCreate(args);
      case 'wallet_address':
        return await handleWalletAddress(args);
      default:
        return structuredErr(new ToolError('ERR_INVALID_INPUT', `Unknown tool: ${name}`));
    }
  } catch (err) {
    return structuredErr(err);
  }
});

async function main(): Promise<void> {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((err: unknown) => {
  process.stderr.write(`cipher-brain-mcp: fatal startup error: ${errMsg(err)}\n`);
  process.exit(1);
});
