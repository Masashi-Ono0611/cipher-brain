#!/usr/bin/env node
// End-to-end tarball install + run smoke. Packs the package (no registry write),
// installs the tarball into a fresh sandbox package, and runs BOTH installed
// bins through the published surface:
//
//   1. `npm pack --json` — asserts the packed file list ships dist/ (+ README,
//      LICENSE-equivalents) and does NOT ship src/, scripts/, bin/, any *.age
//      ciphertext or identity/wallet key material.
//   2. `npm install <tarball>` into a throwaway sandbox package.
//   3. node_modules/.bin/cipher-brain --help (exit 0, non-empty) + a real
//      keygen inside a temp CIPHER_BRAIN_HOME (identity + recipient created).
//   4. node_modules/.bin/cipher-brain-mcp driven over stdio: initialize +
//      tools/list, asserting the four tool names.
//
// This catches the class of bugs the dev-tree smokes can't see: missing
// `files` entries, bins that run from a checkout but not from a
// node_modules install, and key material accidentally packed.
//
// Exits 0 on success, 1 on first failure with stderr context.

import { execFileSync, spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PKG = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, 'package.json'), 'utf8'));

const log = (msg) => process.stdout.write(`  ${msg}\n`);
const fail = (msg) => {
  process.stderr.write(`tarball smoke FAILED: ${msg}\n`);
  process.exit(1);
};

let sandbox = '';
let tarballPath = '';

function cleanup() {
  if (sandbox && fs.existsSync(sandbox)) {
    fs.rmSync(sandbox, { recursive: true, force: true });
  }
  if (tarballPath && fs.existsSync(tarballPath)) {
    fs.unlinkSync(tarballPath);
  }
}
process.on('exit', cleanup);
process.on('SIGINT', () => process.exit(130));
process.on('SIGTERM', () => process.exit(143));

// ─── 1. npm pack + packed-file-list assertions ────────────────────────────
log(`packing ${PKG.name}@${PKG.version}…`);
let packedFiles = [];
try {
  // --json is machine-parseable and includes the full packed file list, so
  // the content assertions need no tarball extraction.
  const json = execFileSync('npm', ['pack', '--json'], {
    cwd: REPO_ROOT,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const parsed = JSON.parse(json);
  const tarballName = parsed[0]?.filename;
  if (!tarballName) fail('npm pack --json returned no filename');
  tarballPath = path.join(REPO_ROOT, tarballName);
  if (!fs.existsSync(tarballPath)) fail(`tarball not at ${tarballPath}`);
  packedFiles = (parsed[0]?.files ?? []).map((f) => f.path);
  if (packedFiles.length === 0) fail('npm pack --json returned an empty file list');
} catch (err) {
  fail(`npm pack failed: ${err.message}`);
}

for (const rel of ['package.json', 'README.md', 'dist/cli.mjs', 'dist/mcp.mjs']) {
  if (!packedFiles.includes(rel)) fail(`expected file not in tarball: ${rel}`);
}
const forbidden = packedFiles.filter(
  (p) =>
    p.startsWith('src/') ||
    p.startsWith('scripts/') ||
    p.startsWith('bin/') ||
    p.endsWith('.age') ||
    /identity/i.test(p) ||
    /wallet/i.test(p) ||
    p.endsWith('.jwk'),
);
if (forbidden.length > 0) fail(`tarball ships files it must not: ${forbidden.join(', ')}`);
log(`${packedFiles.length} packed files; dist/ present, no src/scripts/bin/key material`);

// ─── 2. Install into a fresh sandbox ─────────────────────────────────────
sandbox = fs.mkdtempSync(path.join(os.tmpdir(), 'cb-tarball-smoke-'));
log(`installing into ${sandbox}…`);
fs.writeFileSync(
  path.join(sandbox, 'package.json'),
  JSON.stringify({ name: 'cb-smoke', version: '0.0.0', private: true }, null, 2),
);
const install = spawnSync('npm', ['install', tarballPath], {
  cwd: sandbox,
  encoding: 'utf8',
  stdio: 'pipe',
});
if (install.status !== 0) {
  fail(
    `npm install failed (status=${install.status})\n` +
      `stdout: ${install.stdout?.slice(0, 500)}\n` +
      `stderr: ${install.stderr?.slice(0, 500)}`,
  );
}
const installedRoot = path.join(sandbox, 'node_modules', PKG.name);
for (const rel of ['dist/cli.mjs', 'dist/mcp.mjs']) {
  if (!fs.existsSync(path.join(installedRoot, rel))) fail(`installed package missing ${rel}`);
}
for (const rel of ['src', 'scripts', 'bin']) {
  if (fs.existsSync(path.join(installedRoot, rel))) fail(`installed package must not contain ${rel}/`);
}

// ─── 3. CLI bin: --help + a real keygen in a temp CIPHER_BRAIN_HOME ──────
log('running installed CLI bin (--help + keygen)…');
const cliBin = path.join(sandbox, 'node_modules', '.bin', 'cipher-brain');
if (!fs.existsSync(cliBin)) fail(`cli bin not at ${cliBin}`);
const help = spawnSync(process.execPath, [cliBin, '--help'], { encoding: 'utf8' });
if (help.status !== 0) fail(`cipher-brain --help failed (status=${help.status}): ${help.stderr}`);
if (help.stdout.trim().length === 0) fail('cipher-brain --help printed nothing');
for (const word of ['keygen', 'snapshot', 'restore', 'verify', 'push', 'pull']) {
  if (!help.stdout.includes(word)) fail(`cipher-brain --help missing command: ${word}`);
}

const cbHome = path.join(sandbox, 'cb-home');
const keygen = spawnSync(process.execPath, [cliBin, 'keygen'], {
  encoding: 'utf8',
  env: { ...process.env, CIPHER_BRAIN_HOME: cbHome },
});
if (keygen.status !== 0) {
  fail(`cipher-brain keygen failed (status=${keygen.status}): ${keygen.stderr}`);
}
const recipientPath = path.join(cbHome, 'recipient.txt');
if (!fs.existsSync(recipientPath)) fail(`keygen did not create ${recipientPath}`);
const recipient = fs.readFileSync(recipientPath, 'utf8').trim();
if (!recipient.startsWith('age1')) fail(`recipient does not look like an age key: ${recipient.slice(0, 20)}`);
log(`keygen OK (recipient ${recipient.slice(0, 12)}…)`);

// ─── 4. MCP bin over stdio: initialize + tools/list ──────────────────────
log('driving installed MCP bin over stdio (initialize + tools/list)…');
const mcpBin = path.join(sandbox, 'node_modules', '.bin', 'cipher-brain-mcp');
if (!fs.existsSync(mcpBin)) fail(`mcp bin not at ${mcpBin}`);

const EXPECTED_TOOLS = ['estimate_cost', 'last_snapshot_status', 'snapshot_now', 'verify_restore'];
const TIMEOUT_MS = 30_000;

const parseFrames = (buf) => {
  const out = [];
  for (const line of buf.split('\n')) {
    const s = line.trim();
    if (!s) continue;
    try {
      out.push(JSON.parse(s));
    } catch {
      /* incomplete JSON line — ignore */
    }
  }
  return out;
};

const mcp = spawn(process.execPath, [mcpBin], {
  stdio: ['pipe', 'pipe', 'pipe'],
  env: { ...process.env, CIPHER_BRAIN_HOME: cbHome },
});
let stdoutBuf = '';
let stderrBuf = '';
mcp.stdout.on('data', (d) => {
  stdoutBuf += d.toString('utf8');
});
mcp.stderr.on('data', (d) => {
  stderrBuf += d.toString('utf8');
});

const send = (msg) => mcp.stdin.write(`${JSON.stringify(msg)}\n`);
const wait = (ms) => new Promise((r) => setTimeout(r, ms));
async function waitFor(id) {
  const deadline = Date.now() + TIMEOUT_MS;
  while (Date.now() < deadline) {
    const frame = parseFrames(stdoutBuf).find((f) => f.id === id);
    if (frame) return frame;
    await wait(100);
  }
  fail(`no MCP response for id=${id} within ${TIMEOUT_MS}ms; stderr=${stderrBuf.slice(-500)}`);
}

try {
  send({
    jsonrpc: '2.0',
    id: 1,
    method: 'initialize',
    params: {
      protocolVersion: '2025-06-18',
      capabilities: {},
      clientInfo: { name: 'tarball-smoke', version: '0.0.0' },
    },
  });
  const init = await waitFor(1);
  if (init.result?.serverInfo?.name !== 'cipher-brain-mcp') {
    fail(`initialize.serverInfo unexpected: ${JSON.stringify(init.result?.serverInfo)}`);
  }
  send({ jsonrpc: '2.0', method: 'notifications/initialized' });
  await wait(100);

  send({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} });
  const list = await waitFor(2);
  const names = (list.result?.tools ?? []).map((t) => t.name).sort();
  if (JSON.stringify(names) !== JSON.stringify(EXPECTED_TOOLS)) {
    fail(`tools/list mismatch: expected [${EXPECTED_TOOLS.join(', ')}], got [${names.join(', ')}]`);
  }
} finally {
  try {
    mcp.stdin.end();
  } catch {
    /* ignore */
  }
  try {
    mcp.kill();
  } catch {
    /* ignore */
  }
}

process.stdout.write(
  `tarball smoke OK — ${PKG.name}@${PKG.version}; ${packedFiles.length} packed files, ` +
    `cli --help + keygen + mcp tools=[${EXPECTED_TOOLS.join(', ')}] verified\n`,
);
