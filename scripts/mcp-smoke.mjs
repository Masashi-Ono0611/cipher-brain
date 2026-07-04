#!/usr/bin/env node
// MCP smoke test for the bundled build (adapted from ton-mesh-harness's
// scripts/mcp-smoke.cjs, ESM here). Spawns `node dist/mcp.mjs` over stdio and:
//   1. initialize + notifications/initialized + tools/list — asserts the four
//      tool names (snapshot_now, last_snapshot_status, verify_restore,
//      estimate_cost).
//   2. a REAL snapshot_now round-trip against the free `file` backend inside a
//      temp CIPHER_BRAIN_HOME/CIPHER_BRAIN_FILE_DIR (keygen via the existing
//      lib first), then last_snapshot_status + verify_restore (by bare locator;
//      by locator_file, asserting its sha256 integrity pin was applied; and a
//      wrong-sha256 negative control that must fail closed with no verdict)
//      + estimate_cost on the result.
//   3. the spend gate: snapshot_now with backend=turbo and no confirm_paid
//      must be refused with ERR_CONFIRM_REQUIRED — even with CIPHER_BRAIN_YES
//      set in the environment (never silently spend).
//
// Exits 0 on success, 1 on any failure with a descriptive message on stderr.

import { spawn } from 'node:child_process';
import { mkdtemp, mkdir, writeFile, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const SERVER_PATH = join(ROOT, 'dist', 'mcp.mjs');
const TIMEOUT_MS = 30_000;

const wait = (ms) => new Promise((r) => setTimeout(r, ms));

function parseFrames(buf) {
  const out = [];
  for (const line of buf.split('\n')) {
    const s = line.trim();
    if (!s) continue;
    try { out.push(JSON.parse(s)); } catch { /* incomplete JSON line — ignore */ }
  }
  return out;
}

async function main() {
  const tmp = await mkdtemp(join(tmpdir(), 'cb-mcp-smoke-'));
  try {
    await run(tmp);
  } finally {
    await rm(tmp, { recursive: true, force: true });
  }
}

async function run(tmp) {
  const home = join(tmp, 'home');
  const store = join(tmp, 'store');
  const data = join(tmp, 'data');
  const outAge = join(tmp, 'snap.age');
  const locatorFile = join(tmp, 'latest-locator.tsv');

  // keygen via the existing lib (config.mjs reads env at import time, so set
  // it BEFORE the dynamic import).
  process.env.CIPHER_BRAIN_HOME = home;
  process.env.CIPHER_BRAIN_FILE_DIR = store;
  const { keygen } = await import(join(ROOT, 'src', 'lib', 'keys.mjs'));
  await keygen({});
  const recipientPath = join(home, 'recipient.txt');

  await mkdir(data, { recursive: true });
  await writeFile(join(data, 'hello.txt'), 'cipher-brain mcp smoke payload\n');

  const child = spawn(process.execPath, [SERVER_PATH], {
    stdio: ['pipe', 'pipe', 'pipe'],
    env: {
      ...process.env,
      CIPHER_BRAIN_HOME: home,
      CIPHER_BRAIN_FILE_DIR: store,
      // The MCP spend gate must hold EVEN when the CLI env escape hatch is set.
      CIPHER_BRAIN_YES: '1',
    },
  });

  let stdoutBuf = '';
  let stderrBuf = '';
  child.stdout.on('data', (d) => { stdoutBuf += d.toString('utf8'); });
  child.stderr.on('data', (d) => { stderrBuf += d.toString('utf8'); });
  child.on('error', (err) => { throw err; });

  const send = (msg) => child.stdin.write(JSON.stringify(msg) + '\n');
  async function waitFor(id) {
    const deadline = Date.now() + TIMEOUT_MS;
    while (Date.now() < deadline) {
      const frame = parseFrames(stdoutBuf).find((f) => f.id === id);
      if (frame) return frame;
      await wait(100);
    }
    throw new Error(`no response for id=${id} within ${TIMEOUT_MS}ms; stdout=${stdoutBuf.slice(0, 500)} stderr=${stderrBuf.slice(-500)}`);
  }

  try {
    // 1. handshake + tools/list
    send({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'ci-smoke', version: '0.0.0' } } });
    const init = await waitFor(1);
    if (init.result?.serverInfo?.name !== 'cipher-brain-mcp') {
      throw new Error(`initialize.serverInfo unexpected: ${JSON.stringify(init.result?.serverInfo)}`);
    }
    send({ jsonrpc: '2.0', method: 'notifications/initialized' });
    await wait(100);

    send({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} });
    const list = await waitFor(2);
    const names = (list.result?.tools ?? []).map((t) => t.name).sort();
    const expected = ['estimate_cost', 'last_snapshot_status', 'snapshot_now', 'verify_restore'];
    if (JSON.stringify(names) !== JSON.stringify(expected)) {
      throw new Error(`tools/list mismatch: expected ${expected.join(', ')} got ${names.join(', ')}`);
    }

    // 2a. spend gate: paid backend without confirm_paid must be refused —
    // BEFORE any snapshot work (outAge must not exist afterwards) — even
    // though CIPHER_BRAIN_YES=1 is set in the server's environment.
    send({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'snapshot_now', arguments: { dirs: [data], recipients: [recipientPath], out: outAge, backend: 'turbo' } } });
    const guard = await waitFor(3);
    const guardSc = guard.result?.structuredContent;
    if (!guard.result?.isError || guardSc?.code !== 'ERR_CONFIRM_REQUIRED') {
      throw new Error(`paid-backend spend gate is OFF: expected isError + ERR_CONFIRM_REQUIRED, got ${JSON.stringify(guard.result).slice(0, 300)}`);
    }
    const guardLeftArtifact = await stat(outAge).then(() => true, () => false);
    if (guardLeftArtifact) throw new Error('spend gate fired but a snapshot artifact was still produced (gate must run before any work)');

    // 2b. real snapshot_now round-trip on the free file backend
    send({ jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'snapshot_now', arguments: { dirs: [data], recipients: [recipientPath], out: outAge, backend: 'file', locator_file: locatorFile } } });
    const snap = await waitFor(4);
    const snapSc = snap.result?.structuredContent;
    if (snap.result?.isError) throw new Error(`snapshot_now failed: ${JSON.stringify(snapSc).slice(0, 500)}`);
    if (snapSc?.pushed !== true || snapSc?.backend !== 'file') throw new Error(`snapshot_now result unexpected: ${JSON.stringify(snapSc).slice(0, 300)}`);
    if (typeof snapSc.locator !== 'string' || !snapSc.locator.endsWith('.age')) throw new Error(`snapshot_now locator unexpected: ${JSON.stringify(snapSc.locator)}`);
    if (!/^[0-9a-f]{64}$/.test(snapSc.sha256 ?? '')) throw new Error(`snapshot_now sha256 unexpected: ${JSON.stringify(snapSc.sha256)}`);
    if (!(Number.isInteger(snapSc.size_bytes) && snapSc.size_bytes > 0)) throw new Error(`snapshot_now size_bytes unexpected: ${JSON.stringify(snapSc.size_bytes)}`);

    // 2c. last_snapshot_status reads the save-locator file back
    send({ jsonrpc: '2.0', id: 5, method: 'tools/call', params: { name: 'last_snapshot_status', arguments: { locator_file: locatorFile } } });
    const status = await waitFor(5);
    const statusSc = status.result?.structuredContent;
    if (status.result?.isError) throw new Error(`last_snapshot_status failed: ${JSON.stringify(statusSc).slice(0, 500)}`);
    const latest = statusSc?.latest;
    if (latest?.locator !== snapSc.locator) throw new Error(`last_snapshot_status locator mismatch: ${JSON.stringify(latest?.locator)} != ${JSON.stringify(snapSc.locator)}`);
    if (latest?.backend !== 'file') throw new Error(`last_snapshot_status backend unexpected: ${JSON.stringify(latest?.backend)}`);
    if (latest?.sha256 !== snapSc.sha256) throw new Error(`last_snapshot_status sha256 mismatch`);
    if (!(typeof latest?.age_seconds === 'number' && latest.age_seconds >= 0 && latest.age_seconds < 600)) {
      throw new Error(`last_snapshot_status age_seconds not sane: ${JSON.stringify(latest?.age_seconds)}`);
    }

    // 2d. verify_restore pulls by locator and must reach a full PASS (the
    // private identity lives in this temp CIPHER_BRAIN_HOME).
    send({ jsonrpc: '2.0', id: 6, method: 'tools/call', params: { name: 'verify_restore', arguments: { locator: snapSc.locator, backend: 'file' } } });
    const ver = await waitFor(6);
    const verSc = ver.result?.structuredContent;
    if (ver.result?.isError) throw new Error(`verify_restore failed: ${JSON.stringify(verSc).slice(0, 500)}`);
    if (verSc?.verdict !== 'PASS' || verSc?.exit_code !== 0 || verSc?.restorable_proven !== true) {
      throw new Error(`verify_restore expected a full PASS, got: ${JSON.stringify(verSc).slice(0, 500)}`);
    }
    if (!Array.isArray(verSc.checks) || verSc.checks.length === 0) throw new Error('verify_restore checks output missing');

    // 2e. verify_restore via locator_file — the save-locator file supplies the
    // locator, its backend AND the sha256 integrity pin in one (the CLI
    // --from-locator-file recovery path); the response must show the pin was
    // applied (pulled.sha256_pin + the sha256 check line) and carry no warning.
    send({ jsonrpc: '2.0', id: 7, method: 'tools/call', params: { name: 'verify_restore', arguments: { locator_file: locatorFile } } });
    const verPinned = await waitFor(7);
    const verPinnedSc = verPinned.result?.structuredContent;
    if (verPinned.result?.isError) throw new Error(`verify_restore(locator_file) failed: ${JSON.stringify(verPinnedSc).slice(0, 500)}`);
    if (verPinnedSc?.verdict !== 'PASS' || verPinnedSc?.restorable_proven !== true) {
      throw new Error(`verify_restore(locator_file) expected a full PASS, got: ${JSON.stringify(verPinnedSc).slice(0, 500)}`);
    }
    if (verPinnedSc?.pulled?.locator !== snapSc.locator || verPinnedSc?.pulled?.backend !== 'file') {
      throw new Error(`verify_restore(locator_file) pulled the wrong artifact: ${JSON.stringify(verPinnedSc?.pulled)}`);
    }
    if (verPinnedSc?.pulled?.sha256_pin !== snapSc.sha256) {
      throw new Error(`verify_restore(locator_file) did not apply the sha256 integrity pin: ${JSON.stringify(verPinnedSc?.pulled)}`);
    }
    if (!(verPinnedSc.checks ?? []).some((l) => /\[PASS\] sha256 matches/.test(l))) {
      throw new Error(`verify_restore(locator_file) checks are missing the sha256 pin line: ${JSON.stringify(verPinnedSc.checks)}`);
    }
    if (verPinnedSc?.warning !== undefined) throw new Error(`verify_restore(locator_file) unexpected warning: ${JSON.stringify(verPinnedSc.warning)}`);

    // 2f. negative control: an explicitly WRONG sha256 pin must fail CLOSED —
    // an error result with NO verdict field, never a PASS.
    const wrongSha = (snapSc.sha256[0] === '0' ? '1' : '0') + snapSc.sha256.slice(1);
    send({ jsonrpc: '2.0', id: 8, method: 'tools/call', params: { name: 'verify_restore', arguments: { locator: snapSc.locator, backend: 'file', sha256: wrongSha } } });
    const verWrong = await waitFor(8);
    const verWrongSc = verWrong.result?.structuredContent;
    if (verWrong.result?.isError !== true) {
      throw new Error(`wrong-sha256 pin did NOT fail closed: ${JSON.stringify(verWrong.result).slice(0, 500)}`);
    }
    if (!/sha256 mismatch/.test(verWrongSc?.message ?? '')) {
      throw new Error(`wrong-sha256 pin failed for the wrong reason: ${JSON.stringify(verWrongSc).slice(0, 300)}`);
    }
    if (verWrongSc?.verdict !== undefined) {
      throw new Error(`wrong-sha256 pin still produced a verdict: ${JSON.stringify(verWrongSc).slice(0, 300)}`);
    }

    // 2g. estimate_cost on the free file backend (offline + deterministic —
    // exercises the fourth tool's dispatch without a network dependency).
    send({ jsonrpc: '2.0', id: 9, method: 'tools/call', params: { name: 'estimate_cost', arguments: { file: outAge, backend: 'file' } } });
    const est = await waitFor(9);
    const estSc = est.result?.structuredContent;
    if (est.result?.isError) throw new Error(`estimate_cost failed: ${JSON.stringify(estSc).slice(0, 500)}`);
    if (estSc?.cost !== '0' || estSc?.size_bytes !== snapSc.size_bytes || !estSc?.note) {
      throw new Error(`estimate_cost(file) result unexpected: ${JSON.stringify(estSc).slice(0, 300)}`);
    }

    process.stdout.write(
      `MCP SMOKE: PASS — tools=[${names.join(', ')}], spend gate=ERR_CONFIRM_REQUIRED, ` +
      `file round-trip locator=${snapSc.locator.split('/').pop()}, status.age=${latest.age_seconds}s, verify=${verSc.verdict}, ` +
      `verify(locator_file pin)=${verPinnedSc.verdict}, wrong-pin=fail-closed, estimate(file)=0\n`,
    );
  } finally {
    try { child.stdin.end(); } catch { /* ignore */ }
    try { child.kill(); } catch { /* ignore */ }
  }
}

main().catch((err) => {
  process.stderr.write(`MCP SMOKE: FAIL — ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
});
