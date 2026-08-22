#!/usr/bin/env node
// Operator-run, REAL-NETWORK proof for the `ton` storage backend (src/lib/backends/ton.ts).
//
// scripts/selftest-ton.sh (gated in CI) proves the backend's ORCHESTRATION — the real
// backend code, its real remote command lines, its real HTTP client — against a mock
// seeder (PATH-shimmed ssh/scp + scripts/mock-tonutils.mjs). It deliberately cannot
// prove one thing: that a bag actually travels over the real TON Storage P2P network.
// This script is that missing piece — it talks to a REAL operator-run seeder box
// (CYPHER_BRAIN_TON_SSH_HOST) and does a REAL P2P download by bag id, with
// CYPHER_BRAIN_TON_NO_FALLBACK=1 on the pull so a success actually PROVES P2P
// availability rather than silently sliding through the SSH fallback.
//
//   npm run dogfood:ton               (or: node scripts/ton-dogfood.mjs)
//   node scripts/ton-dogfood.mjs --probe-fallback   (also records which path a normal,
//                                                     non-strict pull takes)
//   node scripts/ton-dogfood.mjs --keep             (skip removing the test bag after)
//
// Everything it creates is disposable: a fresh temp CYPHER_BRAIN_HOME, a fresh keypair,
// a throwaway few-KB source file. It never touches the operator's real ~/.cypher-brain,
// costs nothing (ton push/pull are free — no --yes, no wallet), and by default removes
// the test bag from the seeder afterward so repeated dogfood runs do not accumulate junk.
//
// No host/key is hardcoded here — every CYPHER_BRAIN_TON_* setting comes from the
// environment and is passed straight through to the CLI child process, same as any
// other cypher-brain invocation.
import { spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, readdirSync, statSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { DEV_ARGS } from './dev-node-flags.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, '..');
const BIN = join(ROOT, 'bin', 'cypher-brain.mjs');

// Generous safety net, not a tuned budget: push can legitimately take up to
// CREATE_READY_TIMEOUT_MS (10 min, ton.ts) waiting for the seeder to finish
// hashing/seeding a large bag, and the overall pipe cap (CYPHER_BRAIN_PIPE_TIMEOUT)
// defaults to 1h. This only exists so a truly wedged run fails loud instead of
// hanging forever unattended.
const CB_TIMEOUT_MS = 90 * 60 * 1000;

const ALL_TON_ENVS = [
  'CYPHER_BRAIN_TON_SSH_HOST',
  'CYPHER_BRAIN_TON_SSH_KEY',
  'CYPHER_BRAIN_TON_REMOTE_DIR',
  'CYPHER_BRAIN_TON_REMOTE_API',
  'CYPHER_BRAIN_TON_BIN',
  'CYPHER_BRAIN_TON_HTTP_TIMEOUT',
  'CYPHER_BRAIN_TON_NO_FALLBACK',
  'CYPHER_BRAIN_TON_NETWORK_CONFIG',
];
const REQUIRED_ENVS = ['CYPHER_BRAIN_TON_SSH_HOST', 'CYPHER_BRAIN_TON_BIN'];

const HELP = `ton-dogfood — operator-run real-network proof for the ton storage backend

Usage: node scripts/ton-dogfood.mjs [--probe-fallback] [--keep] [--help]

  --probe-fallback  also run a normal (non-strict) pull afterward and record whether
                     it was served over P2P or the seeder fallback (best-effort; never
                     fails the run).
  --keep            skip removing the test bag from the seeder when done.
  --help            print this and exit 0.

Required env: CYPHER_BRAIN_TON_SSH_HOST, CYPHER_BRAIN_TON_BIN.
All CYPHER_BRAIN_TON_* env vars are passed straight through to the CLI — see the
README "TON Storage" section / src/lib/backends/ton.ts for what each one does.
`;

function requireEnv() {
  const missing = REQUIRED_ENVS.filter((k) => !process.env[k]);
  if (missing.length === 0) return;
  console.error(`ton-dogfood: missing required env var(s): ${missing.join(', ')}`);
  console.error('');
  console.error('This script drives the REAL ton backend against a REAL operator-run seeder box');
  console.error('(no mocks) — see README.md "TON Storage" and src/lib/backends/ton.ts for the');
  console.error('seeder setup (a machine running tonutils-storage, reached over SSH).');
  console.error('');
  console.error('Env vars this script uses (passed straight through to the CLI child process):');
  for (const k of ALL_TON_ENVS) {
    const req = REQUIRED_ENVS.includes(k);
    console.error(`  ${k}${req ? ' (required)' : ''} = ${process.env[k] ?? '<unset>'}`);
  }
  process.exit(2);
}

// ---------- tiny CLI-driving + hashing helpers ----------

function cb(args, extraEnv) {
  const r = spawnSync(process.execPath, [...DEV_ARGS, BIN, ...args], {
    cwd: ROOT,
    env: extraEnv ? { ...process.env, ...extraEnv } : process.env,
    encoding: 'utf8',
    timeout: CB_TIMEOUT_MS,
    maxBuffer: 64 * 1024 * 1024,
  });
  if (r.error) throw new Error(`spawn failed for 'cypher-brain ${args.join(' ')}': ${r.error.message}`);
  return r;
}

function cbOk(args, extraEnv) {
  const r = cb(args, extraEnv);
  if (r.status !== 0) {
    throw new Error(
      `'cypher-brain ${args.join(' ')}' exited ${r.status}${r.signal ? ` (signal ${r.signal})` : ''}: ` +
        (r.stderr || '').trim().slice(-4000),
    );
  }
  return r;
}

const sha256File = (path) => createHash('sha256').update(readFileSync(path)).digest('hex');

function findMarker(dir, marker) {
  for (const e of readdirSync(dir, { recursive: true, withFileTypes: true })) {
    if (!e.isFile()) continue;
    const p = join(e.parentPath, e.name);
    try {
      if (readFileSync(p, 'utf8').includes(marker)) return p;
    } catch {
      /* binary or unreadable — not the marker file */
    }
  }
  return null;
}

// ---------- remote-command safety (mirrors the allowlist idea in src/lib/backends/ton.ts:
// every value interpolated into a REMOTE shell command line must pass a narrow character
// allowlist first, since the remote side is a real shell) ----------

const HOST_RE = /^[A-Za-z0-9._-]+(?:@[A-Za-z0-9._-]+)?$/;
const REMOTE_PATH_RE = /^[A-Za-z0-9._/-]+$/;
const HEX64_RE = /^[0-9a-f]{64}$/;
const API_RE = /^[A-Za-z0-9.:-]+$/;

function assertSafe(value, what, re) {
  if (typeof value !== 'string' || !re.test(value) || value.startsWith('-')) {
    throw new Error(
      `${what} contains characters this script refuses to place in a remote command: ${JSON.stringify(value)}`,
    );
  }
  return value;
}

function sshBaseArgs() {
  const args = ['-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10'];
  if (process.env.CYPHER_BRAIN_TON_SSH_KEY) args.push('-i', process.env.CYPHER_BRAIN_TON_SSH_KEY);
  return args;
}

function sshRun(cmd, timeoutMs = 60_000) {
  const host = assertSafe(process.env.CYPHER_BRAIN_TON_SSH_HOST, 'CYPHER_BRAIN_TON_SSH_HOST', HOST_RE);
  const r = spawnSync('ssh', [...sshBaseArgs(), '--', host, cmd], { encoding: 'utf8', timeout: timeoutMs });
  if (r.error) throw new Error(`ssh failed: ${r.error.message}`);
  if (r.status !== 0)
    throw new Error(
      `ssh exited ${r.status}${r.signal ? ` (signal ${r.signal})` : ''}: ${(r.stderr || '').trim().slice(-2000)}`,
    );
  return r.stdout;
}

// Removes the ONE test bag this run created: the seeder daemon record (via its own
// /api/v1/remove, with_files:true) plus cypher-brain's own inventory bookkeeping (which
// the daemon does not know about). Best-effort — cleanup failures are WARN, never FAIL,
// per this script's own contract (see main()).
function cleanupRemoteBag(sha, bagId) {
  const base = assertSafe(
    process.env.CYPHER_BRAIN_TON_REMOTE_DIR || 'cypher-brain-ton',
    'CYPHER_BRAIN_TON_REMOTE_DIR',
    REMOTE_PATH_RE,
  );
  const api = assertSafe(
    process.env.CYPHER_BRAIN_TON_REMOTE_API || '127.0.0.1:9955',
    'CYPHER_BRAIN_TON_REMOTE_API',
    API_RE,
  );
  const safeSha = assertSafe(sha, 'ciphertext sha256', HEX64_RE);
  const safeBag = assertSafe(bagId, 'bag id', HEX64_RE);

  const body = JSON.stringify({ bag_id: safeBag, with_files: true });
  sshRun(
    `curl -sS -m 30 -X POST -H 'Content-Type: application/json' --data '${body}' 'http://${api}/api/v1/remove' >/dev/null`,
    60_000,
  );
  sshRun(`rm -rf -- '${base}/bags/${safeSha}' '${base}/inventory/${safeSha}.locator'`);
}

// ---------- main ----------

function main() {
  const args = process.argv.slice(2);
  if (args.includes('--help') || args.includes('-h')) {
    process.stdout.write(HELP);
    process.exit(0);
  }
  const known = new Set(['--probe-fallback', '--keep']);
  const unknown = args.filter((a) => !known.has(a));
  if (unknown.length > 0) {
    console.error(`ton-dogfood: unknown argument(s): ${unknown.join(', ')}\n`);
    process.stdout.write(HELP);
    process.exit(2);
  }
  const probeFallback = args.includes('--probe-fallback');
  const keep = args.includes('--keep');

  requireEnv();

  const tmpRoot = mkdtempSync(join(tmpdir(), 'cypher-brain-ton-dogfood-'));
  process.env.CYPHER_BRAIN_HOME = join(tmpRoot, 'home'); // never the operator's real ~/.cypher-brain
  const srcDir = join(tmpRoot, 'src');
  mkdirSync(srcDir, { recursive: true });
  const snapPath = join(tmpRoot, 'snap.age');
  const gotPath = join(tmpRoot, 'got.age');
  const restoreDir = join(tmpRoot, 'restored');
  const locFile = join(tmpRoot, 'locator.tsv');

  const marker = `ton-dogfood-${randomBytes(8).toString('hex')}`;

  const phases = {};
  const timings = {};
  let origSha = null;
  let sizeBytes = null;
  let locator = null;
  let bagId = null;
  let requiredOk = true;

  const REQUIRED_PHASES = ['setup', 'push', 'idempotent', 'p2p_pull', 'verify', 'restore'];

  function runPhase(name, fn) {
    if (!requiredOk) {
      phases[name] = 'BLOCKED';
      timings[name] = 0;
      console.log(`[BLOCKED] ${name}: skipped — an earlier required phase failed`);
      return;
    }
    const t0 = Date.now();
    try {
      fn();
      phases[name] = 'PASS';
      console.log(`[PASS] ${name}`);
    } catch (e) {
      phases[name] = 'FAIL';
      requiredOk = false;
      console.log(`[FAIL] ${name}: ${e.message}`);
    } finally {
      timings[name] = Date.now() - t0;
    }
  }

  try {
    runPhase('setup', () => {
      cbOk(['keygen']);
      // A few-KB text file (well under a "large file" scenario — this dogfood proves
      // P2P retrievability, not throughput) with a random marker, so restore's output
      // can be asserted to actually be THIS run's content, not a stale leftover.
      const filler = randomBytes(2048).toString('hex'); // ~4KB
      writeFileSync(join(srcDir, 'note.txt'), `marker: ${marker}\n${filler}\n`);
      cbOk(['snapshot', '--dir', srcDir, '--out', snapPath]);
      origSha = sha256File(snapPath);
      sizeBytes = statSync(snapPath).size;
    });

    runPhase('push', () => {
      const r = cbOk(['push', '--in', snapPath, '--backend', 'ton', '--save-locator', locFile]);
      locator = r.stdout.trim();
      const m = /^ton:v1:([0-9a-f]{64})$/.exec(locator);
      if (!m) throw new Error(`locator does not match ^ton:v1:[0-9a-f]{64}$: ${JSON.stringify(locator)}`);
      bagId = m[1];
    });

    runPhase('idempotent', () => {
      const r = cbOk(['push', '--in', snapPath, '--backend', 'ton']);
      const loc2 = r.stdout.trim();
      if (loc2 !== locator)
        throw new Error(`re-push returned a different locator: ${JSON.stringify(loc2)} != ${JSON.stringify(locator)}`);
    });

    // The core proof: strict mode means a success can ONLY have come from the real P2P
    // network (CYPHER_BRAIN_TON_NO_FALLBACK=1 forbids the SSH fallback outright) — no
    // silent retry through the seeder if P2P fails.
    runPhase('p2p_pull', () => {
      const r = cb(['pull', '--backend', 'ton', '--locator', locator, '--out', gotPath], {
        CYPHER_BRAIN_TON_NO_FALLBACK: '1',
      });
      if (r.status !== 0) {
        throw new Error(
          `strict P2P pull (CYPHER_BRAIN_TON_NO_FALLBACK=1) failed: ${(r.stderr || '').trim().slice(-4000)}`,
        );
      }
      if (!(r.stderr || '').includes('over the TON Storage P2P network')) {
        throw new Error(
          'pull exited 0 but did not report the P2P path in stderr — cannot confirm what actually served it',
        );
      }
      const gotSha = sha256File(gotPath);
      if (gotSha !== origSha) throw new Error(`pulled bytes differ from pushed bytes: ${gotSha} != ${origSha}`);
    });

    runPhase('verify', () => {
      cbOk(['verify', '--in', gotPath]);
    });

    runPhase('restore', () => {
      cbOk(['restore', '--in', gotPath, '--out-dir', restoreDir]);
      const found = findMarker(restoreDir, marker);
      if (!found) throw new Error(`restored tree under ${restoreDir} does not contain this run's marker (${marker})`);
    });

    // Optional, informational: does a normal pull actually go P2P, or quietly fall
    // back? Never fails the run — see the flag's own --help description.
    if (probeFallback) {
      const t0 = Date.now();
      try {
        if (!locator) throw new Error('no locator to probe (push phase never succeeded)');
        const probeOut = join(tmpRoot, 'got-probe.age');
        const env = { ...process.env };
        delete env.CYPHER_BRAIN_TON_NO_FALLBACK;
        const r = spawnSync(
          process.execPath,
          [...DEV_ARGS, BIN, 'pull', '--backend', 'ton', '--locator', locator, '--out', probeOut, '--force'],
          {
            cwd: ROOT,
            env,
            encoding: 'utf8',
            timeout: CB_TIMEOUT_MS,
            maxBuffer: 64 * 1024 * 1024,
          },
        );
        const stderrText = r.stderr || '';
        const path = stderrText.includes('over the TON Storage P2P network')
          ? 'p2p'
          : stderrText.includes('falling back to a direct copy from the seeder')
            ? 'seeder-fallback'
            : 'unknown';
        if (r.status !== 0) throw new Error(`probe pull failed: ${stderrText.trim().slice(-2000)}`);
        phases.fallback_probe = 'PASS';
        console.log(`[PASS] fallback_probe: served via ${path}`);
      } catch (e) {
        phases.fallback_probe = 'BLOCKED';
        console.log(`[BLOCKED] fallback_probe: ${e.message}`);
      } finally {
        timings.fallback_probe = Date.now() - t0;
      }
    } else {
      phases.fallback_probe = 'SKIP';
    }

    if (!keep && bagId && origSha) {
      try {
        cleanupRemoteBag(origSha, bagId);
        console.log('[INFO] cleanup: removed the test bag from the seeder');
      } catch (e) {
        console.log(
          `[WARN] cleanup failed — remove manually on the seeder (bag ${bagId}, sha ${origSha}): ${e.message}`,
        );
      }
    } else if (keep) {
      console.log(`[INFO] --keep: leaving bag ${bagId ?? '(none created)'} on the seeder`);
    }
  } finally {
    rmSync(tmpRoot, { recursive: true, force: true });
  }

  console.log('== ton dogfood summary ==');
  console.log(JSON.stringify({ phases, timings_ms: timings, locator, size_bytes: sizeBytes }));

  const ok = REQUIRED_PHASES.every((p) => phases[p] === 'PASS');
  process.exit(ok ? 0 : 1);
}

main();
