// cipher-brain-mcp — MCP server so an AI agent can snapshot/verify its own brain.
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

import { stat, readFile, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  type Tool,
  type CallToolResult,
} from '@modelcontextprotocol/sdk/types.js';

import { HOME } from './lib/config.js';
import { snapshot } from './lib/snapshot.js';
import { verify } from './lib/restore.js';
import { push, pull } from './lib/pushpull.js';
import { schedule } from './lib/schedule.js';
import { estimateCost } from './lib/estimate.js';
import { exists, sha256, errMsg } from './lib/util.js';
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
  const payload = {
    code: errObj instanceof ToolError ? errObj.code : 'ERR_INTERNAL',
    message: errObj instanceof Error ? errObj.message : String(errObj),
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
};

const ESTIMATE_COST_TOOL: Tool = {
  name: 'estimate_cost',
  description:
    'Read-only, spends nothing (price queries only). Estimate what pushing a payload of the ' +
    'given size to a backend would cost: turbo → Turbo upload cost in winc via @ardrive/turbo-sdk ' +
    '(<100KB is free; a clear note is returned when that optional dependency is not installed); ' +
    'arweave → network price in winston from the gateway /price endpoint; file → free ' +
    '(local disk), returned with a zero-cost note. For turbo/arweave an ' +
    'approximate usd_estimate field is included when a USD/AR rate is fetchable (omitted on any ' +
    'rate failure — the native estimate never fails because of it).',
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
};

const SCHEDULE_STATUS_TOOL: Tool = {
  name: 'schedule_status',
  description:
    'Read-only, spends nothing, mutates nothing. Report the state of the nightly schedule set up ' +
    'by `cipher-brain schedule install`: the configured time + backend, whether the launchd/cron ' +
    'trigger is actually registered, the last run\'s log filename and its final "OK rc=0"/"FAILED ' +
    'rc=N" line, and the next scheduled run — the SAME report `cipher-brain schedule status` prints ' +
    'on the CLI, verbatim (one string per line). No arguments. Fails with ERR_INTERNAL if no ' +
    'schedule is installed yet (run `cipher-brain schedule install` first — not exposed here, a ' +
    'human-driven operation by design).',
  inputSchema: {
    type: 'object',
    properties: {},
    additionalProperties: false,
  },
};

const ALL_TOOLS: Tool[] = [
  SNAPSHOT_NOW_TOOL,
  LAST_SNAPSHOT_STATUS_TOOL,
  VERIFY_RESTORE_TOOL,
  ESTIMATE_COST_TOOL,
  SCHEDULE_STATUS_TOOL,
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
      case 'estimate_cost':
        return await handleEstimateCost(args);
      case 'schedule_status':
        return await handleScheduleStatus(args);
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
