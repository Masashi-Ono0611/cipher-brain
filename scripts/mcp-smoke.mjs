#!/usr/bin/env node
// MCP smoke test for the bundled build. Spawns `node dist/mcp.mjs` over stdio and:
//   1. initialize + notifications/initialized + tools/list — asserts all ten
//      tool names (snapshot_now, last_snapshot_status, verify_restore,
//      restore_now, estimate_cost, schedule_install, schedule_status, keygen,
//      wallet_create, wallet_address) AND their MCP standard tool annotations
//      (readOnlyHint/destructiveHint/idempotentHint/openWorldHint, issue #219)
//      match the expected hints per tool (e.g. last_snapshot_status/
//      estimate_cost/schedule_status/wallet_address are readOnlyHint:true;
//      keygen/wallet_create are destructiveHint:true since force=true discards
//      existing key material; restore_now/schedule_install are
//      destructiveHint:true — restore_now can clobber pre-existing state via
//      pg_restore --clean --if-exists, schedule_install writes a real system
//      file and replaces any prior configuration).
//   2. a REAL snapshot_now round-trip against the free `file` backend inside a
//      temp CIPHER_BRAIN_HOME/CIPHER_BRAIN_FILE_DIR (keygen via the existing
//      lib first), then last_snapshot_status + verify_restore (by bare locator;
//      by locator_file, asserting its sha256 integrity pin was applied; and a
//      wrong-sha256 negative control that must fail closed with no verdict)
//      + restore_now (refuses without confirm_write, leaving out_dir untouched;
//      then a REAL round-trip — pull by locator, decrypt, extract — with the
//      restored file's content asserted on disk against what was snapshotted)
//      + estimate_cost on the result + schedule_install (refuses without
//      confirm_install; a REAL --no-load install against an isolated
//      CIPHER_BRAIN_LAUNCHD_DIR/CIPHER_BRAIN_SCHEDULE_DIR, never touching the
//      real launchctl/crontab) + schedule_status reading that same state back
//      (same schedule.ts state `cipher-brain schedule status` reads); the
//      spend gate: snapshot_now with
//      backend=turbo and no confirm_paid must be refused with
//      ERR_CONFIRM_REQUIRED — even with CIPHER_BRAIN_YES set in the
//      environment (never silently spend); and a keygen call against this
//      server's ALREADY-KEYED home, which must refuse rather than re-key.
//   3. runKeygenWalletTests(): a SEPARATE server + a fresh, isolated
//      CIPHER_BRAIN_HOME proves the issue #174 first-run path end to end —
//      keygen then wallet_create then wallet_address, each's no-clobber
//      refusal without --force, and keygen --force actually rotating the
//      keypair — with real files asserted on disk, not just tool output.
//
// Exits 0 on success, 1 on any failure with a descriptive message on stderr.

import { spawn, spawnSync } from 'node:child_process';
import { mkdtemp, mkdir, writeFile, readFile, rm, stat } from 'node:fs/promises';
import { existsSync } from 'node:fs';
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
    try {
      out.push(JSON.parse(s));
    } catch {
      /* incomplete JSON line — ignore */
    }
  }
  return out;
}

async function main() {
  const tmp = await mkdtemp(join(tmpdir(), 'cb-mcp-smoke-'));
  try {
    await run(tmp);
    await runKeygenWalletTests(tmp);
  } finally {
    await rm(tmp, { recursive: true, force: true });
  }
}

// Wires one spawned MCP server's stdout/stderr into the same send()/waitFor(id)
// JSON-RPC-over-stdio pattern the main flow below uses — pulled out so the isolated
// keygen/wallet_create/wallet_address round-trip (its own server, its own temp
// CIPHER_BRAIN_HOME) doesn't hand-roll a second copy of this plumbing.
function makeRpcClient(child) {
  let stdoutBuf = '';
  let stderrBuf = '';
  child.stdout.on('data', (d) => {
    stdoutBuf += d.toString('utf8');
  });
  child.stderr.on('data', (d) => {
    stderrBuf += d.toString('utf8');
  });
  child.on('error', (err) => {
    throw err;
  });
  const send = (msg) => child.stdin.write(`${JSON.stringify(msg)}\n`);
  async function waitFor(id) {
    const deadline = Date.now() + TIMEOUT_MS;
    while (Date.now() < deadline) {
      const frame = parseFrames(stdoutBuf).find((f) => f.id === id);
      if (frame) return frame;
      await wait(100);
    }
    throw new Error(
      `no response for id=${id} within ${TIMEOUT_MS}ms; stdout=${stdoutBuf.slice(0, 500)} stderr=${stderrBuf.slice(-500)}`,
    );
  }
  return { send, waitFor };
}

// 3. keygen / wallet_create / wallet_address round-trip (issue #174): a SEPARATE
// server + a FRESH, isolated CIPHER_BRAIN_HOME (rather than reusing `home` above,
// which already has an identity from the CLI-driven keygen at the top of run())
// so the very first keygen/wallet_create call here exercises the real "nothing
// exists yet" first-run path, not the already-exists refusal.
async function runKeygenWalletTests(tmp) {
  const home2 = join(tmp, 'home2');
  const child2 = spawn(process.execPath, [SERVER_PATH], {
    stdio: ['pipe', 'pipe', 'pipe'],
    env: { ...process.env, CIPHER_BRAIN_HOME: home2 },
  });
  const { send, waitFor } = makeRpcClient(child2);
  try {
    send({
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'ci-smoke', version: '0.0.0' } },
    });
    await waitFor(1);
    send({ jsonrpc: '2.0', method: 'notifications/initialized' });
    await wait(100);

    // 3a. keygen on a brand-new home: must succeed and actually write both files.
    send({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'keygen', arguments: {} } });
    const keygen1 = await waitFor(2);
    const keygen1Sc = keygen1.result?.structuredContent;
    if (keygen1.result?.isError) throw new Error(`keygen (fresh) failed: ${JSON.stringify(keygen1Sc).slice(0, 500)}`);
    if (typeof keygen1Sc?.recipient !== 'string' || !keygen1Sc.recipient.startsWith('age1'))
      throw new Error(`keygen (fresh) recipient unexpected: ${JSON.stringify(keygen1Sc?.recipient)}`);
    if (keygen1Sc?.passphrase_wrapped !== false)
      throw new Error(`keygen (fresh) passphrase_wrapped unexpected: ${JSON.stringify(keygen1Sc?.passphrase_wrapped)}`);
    const identityPath = keygen1Sc.identity_path;
    const recipientPath2 = keygen1Sc.recipient_path;
    if (!existsSync(identityPath)) throw new Error(`keygen (fresh) did not write identity_path: ${identityPath}`);
    if (!existsSync(recipientPath2)) throw new Error(`keygen (fresh) did not write recipient_path: ${recipientPath2}`);

    // 3b. keygen again, no force: must refuse (no-clobber) rather than silently re-key.
    send({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'keygen', arguments: {} } });
    const keygen2 = await waitFor(3);
    if (keygen2.result?.isError !== true)
      throw new Error(
        `keygen (no force, already exists) did not refuse: ${JSON.stringify(keygen2.result).slice(0, 300)}`,
      );
    if (!/already exists/.test(keygen2.result?.structuredContent?.message ?? ''))
      throw new Error(
        `keygen (no force) refused for the wrong reason: ${JSON.stringify(keygen2.result?.structuredContent)}`,
      );

    // 3c. keygen with force=true: must succeed and actually rotate the recipient.
    send({ jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'keygen', arguments: { force: true } } });
    const keygen3 = await waitFor(4);
    const keygen3Sc = keygen3.result?.structuredContent;
    if (keygen3.result?.isError) throw new Error(`keygen (force) failed: ${JSON.stringify(keygen3Sc).slice(0, 500)}`);
    if (keygen3Sc?.recipient === keygen1Sc.recipient)
      throw new Error('keygen (force) did not generate a new keypair (recipient unchanged)');

    // 3d. wallet_create on a brand-new home: must succeed and actually write the JWK.
    send({ jsonrpc: '2.0', id: 5, method: 'tools/call', params: { name: 'wallet_create', arguments: {} } });
    const wc1 = await waitFor(5);
    const wc1Sc = wc1.result?.structuredContent;
    if (wc1.result?.isError) throw new Error(`wallet_create (fresh) failed: ${JSON.stringify(wc1Sc).slice(0, 500)}`);
    if (typeof wc1Sc?.wallet_path !== 'string' || !existsSync(wc1Sc.wallet_path))
      throw new Error(`wallet_create (fresh) did not write wallet_path: ${JSON.stringify(wc1Sc?.wallet_path)}`);
    if (typeof wc1Sc?.address !== 'string' || wc1Sc.address.length < 10)
      throw new Error(`wallet_create (fresh) address unexpected: ${JSON.stringify(wc1Sc?.address)}`);

    // 3e. wallet_create again, no force: must refuse (no-clobber).
    send({ jsonrpc: '2.0', id: 6, method: 'tools/call', params: { name: 'wallet_create', arguments: {} } });
    const wc2 = await waitFor(6);
    if (wc2.result?.isError !== true)
      throw new Error(
        `wallet_create (no force, already exists) did not refuse: ${JSON.stringify(wc2.result).slice(0, 300)}`,
      );

    // 3f. wallet_address with no arguments falls back to the SAME default path
    // wallet_create just wrote to, and must report the SAME address.
    send({ jsonrpc: '2.0', id: 7, method: 'tools/call', params: { name: 'wallet_address', arguments: {} } });
    const addr = await waitFor(7);
    const addrSc = addr.result?.structuredContent;
    if (addr.result?.isError)
      throw new Error(`wallet_address (default path) failed: ${JSON.stringify(addrSc).slice(0, 500)}`);
    if (addrSc?.address !== wc1Sc.address)
      throw new Error(
        `wallet_address mismatch: ${JSON.stringify(addrSc?.address)} != ${JSON.stringify(wc1Sc.address)}`,
      );

    process.stdout.write(
      `MCP SMOKE (keygen/wallet): PASS — keygen fresh+no-clobber+force ok, ` +
        `wallet_create fresh+no-clobber ok, wallet_address matches wallet_create\n`,
    );
  } finally {
    try {
      child2.stdin.end();
    } catch {
      /* ignore */
    }
    try {
      child2.kill();
    } catch {
      /* ignore */
    }
  }
}

async function run(tmp) {
  const home = join(tmp, 'home');
  const store = join(tmp, 'store');
  const data = join(tmp, 'data');
  const outAge = join(tmp, 'snap.age');
  const locatorFile = join(tmp, 'latest-locator.tsv');
  const launchdDir = join(tmp, 'launchagents'); // install() writes a plist here even with --no-load — must never touch the real ~/Library/LaunchAgents

  // keygen via the bundled CLI (dist/cli.mjs — already built by the time this smoke
  // test runs in `npm run verify`). Previously this dynamic-imported src/lib/keys.mjs
  // in-process; since #63 renamed it to keys.ts (internal imports use the OUTPUT
  // extension, e.g. `./config.js`), a plain in-process `import()` can no longer resolve
  // it without the same dev-only TS resolve hook the bash selftests use (see
  // scripts/dev-ts-resolve-hook.mjs) — spawning the already-built CLI is simpler and
  // exercises the exact artifact this smoke test is otherwise testing against.
  process.env.CIPHER_BRAIN_HOME = home;
  process.env.CIPHER_BRAIN_FILE_DIR = store;
  const keygenRes = spawnSync(process.execPath, [SERVER_PATH.replace(/mcp\.mjs$/, 'cli.mjs'), 'keygen'], {
    env: { ...process.env },
    encoding: 'utf8',
  });
  if (keygenRes.status !== 0) {
    throw new Error(`keygen failed (${keygenRes.status}): ${keygenRes.stderr || keygenRes.stdout}`);
  }
  const recipientPath = join(home, 'recipient.txt');

  await mkdir(data, { recursive: true });
  await writeFile(join(data, 'hello.txt'), 'cipher-brain mcp smoke payload\n');

  const child = spawn(process.execPath, [SERVER_PATH], {
    stdio: ['pipe', 'pipe', 'pipe'],
    env: {
      ...process.env,
      CIPHER_BRAIN_HOME: home,
      CIPHER_BRAIN_FILE_DIR: store,
      CIPHER_BRAIN_LAUNCHD_DIR: launchdDir, // install() writes a plist here even with --no-load
      // The MCP spend gate must hold EVEN when the CLI env escape hatch is set.
      CIPHER_BRAIN_YES: '1',
    },
  });

  const { send, waitFor } = makeRpcClient(child);

  try {
    // 1. handshake + tools/list
    send({
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'ci-smoke', version: '0.0.0' } },
    });
    const init = await waitFor(1);
    if (init.result?.serverInfo?.name !== 'cipher-brain-mcp') {
      throw new Error(`initialize.serverInfo unexpected: ${JSON.stringify(init.result?.serverInfo)}`);
    }
    send({ jsonrpc: '2.0', method: 'notifications/initialized' });
    await wait(100);

    send({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} });
    const list = await waitFor(2);
    const names = (list.result?.tools ?? []).map((t) => t.name).sort();
    const expected = [
      'estimate_cost',
      'keygen',
      'last_snapshot_status',
      'restore_now',
      'schedule_install',
      'schedule_status',
      'snapshot_now',
      'verify_restore',
      'wallet_address',
      'wallet_create',
    ];
    if (JSON.stringify(names) !== JSON.stringify(expected)) {
      throw new Error(`tools/list mismatch: expected ${expected.join(', ')} got ${names.join(', ')}`);
    }

    // 1b. MCP standard tool annotations (issue #219) — every tool must carry
    // readOnlyHint/destructiveHint/idempotentHint/openWorldHint hints
    // matching its actual behavior, alongside the existing confirm_paid logic.
    const expectedAnnotations = {
      snapshot_now: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
      last_snapshot_status: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
      verify_restore: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
      restore_now: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
      estimate_cost: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
      schedule_install: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
      schedule_status: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
      keygen: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
      wallet_create: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
      wallet_address: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    };
    for (const tool of list.result?.tools ?? []) {
      const expectedAnn = expectedAnnotations[tool.name];
      if (!expectedAnn) continue; // unreachable given the names check above
      const actualAnn = tool.annotations ?? {};
      const mismatched = Object.entries(expectedAnn).filter(([key, value]) => actualAnn[key] !== value);
      if (mismatched.length > 0) {
        throw new Error(
          `${tool.name}.annotations mismatch: expected ${JSON.stringify(expectedAnn)} got ${JSON.stringify(actualAnn)} (field(s) ${mismatched.map(([key]) => key).join(', ')})`,
        );
      }
    }

    // 2a. spend gate: paid backend without confirm_paid must be refused —
    // BEFORE any snapshot work (outAge must not exist afterwards) — even
    // though CIPHER_BRAIN_YES=1 is set in the server's environment.
    send({
      jsonrpc: '2.0',
      id: 3,
      method: 'tools/call',
      params: {
        name: 'snapshot_now',
        arguments: { dirs: [data], recipients: [recipientPath], out: outAge, backend: 'turbo' },
      },
    });
    const guard = await waitFor(3);
    const guardSc = guard.result?.structuredContent;
    if (!guard.result?.isError || guardSc?.code !== 'ERR_CONFIRM_REQUIRED') {
      throw new Error(
        `paid-backend spend gate is OFF: expected isError + ERR_CONFIRM_REQUIRED, got ${JSON.stringify(guard.result).slice(0, 300)}`,
      );
    }
    // issue #212: the same "spends real funds" consent-gate wording the CLI's own
    // push --yes guard uses (pushpull.ts) is recognized here too, so this MCP-level
    // refusal also carries the stable CB-E007 code.
    if (guardSc?.cb_code !== 'CB-E007') {
      throw new Error(`paid-backend spend gate result lacks cb_code=CB-E007: ${JSON.stringify(guardSc).slice(0, 300)}`);
    }
    const guardLeftArtifact = await stat(outAge).then(
      () => true,
      () => false,
    );
    if (guardLeftArtifact)
      throw new Error('spend gate fired but a snapshot artifact was still produced (gate must run before any work)');

    // 2b. real snapshot_now round-trip on the free file backend
    send({
      jsonrpc: '2.0',
      id: 4,
      method: 'tools/call',
      params: {
        name: 'snapshot_now',
        arguments: {
          dirs: [data],
          recipients: [recipientPath],
          out: outAge,
          backend: 'file',
          locator_file: locatorFile,
        },
      },
    });
    const snap = await waitFor(4);
    const snapSc = snap.result?.structuredContent;
    if (snap.result?.isError) throw new Error(`snapshot_now failed: ${JSON.stringify(snapSc).slice(0, 500)}`);
    if (snapSc?.pushed !== true || snapSc?.backend !== 'file')
      throw new Error(`snapshot_now result unexpected: ${JSON.stringify(snapSc).slice(0, 300)}`);
    if (typeof snapSc.locator !== 'string' || !snapSc.locator.endsWith('.age'))
      throw new Error(`snapshot_now locator unexpected: ${JSON.stringify(snapSc.locator)}`);
    if (!/^[0-9a-f]{64}$/.test(snapSc.sha256 ?? ''))
      throw new Error(`snapshot_now sha256 unexpected: ${JSON.stringify(snapSc.sha256)}`);
    if (!(Number.isInteger(snapSc.size_bytes) && snapSc.size_bytes > 0))
      throw new Error(`snapshot_now size_bytes unexpected: ${JSON.stringify(snapSc.size_bytes)}`);

    // 2c. last_snapshot_status reads the save-locator file back
    send({
      jsonrpc: '2.0',
      id: 5,
      method: 'tools/call',
      params: { name: 'last_snapshot_status', arguments: { locator_file: locatorFile } },
    });
    const status = await waitFor(5);
    const statusSc = status.result?.structuredContent;
    if (status.result?.isError)
      throw new Error(`last_snapshot_status failed: ${JSON.stringify(statusSc).slice(0, 500)}`);
    const latest = statusSc?.latest;
    if (latest?.locator !== snapSc.locator)
      throw new Error(
        `last_snapshot_status locator mismatch: ${JSON.stringify(latest?.locator)} != ${JSON.stringify(snapSc.locator)}`,
      );
    if (latest?.backend !== 'file')
      throw new Error(`last_snapshot_status backend unexpected: ${JSON.stringify(latest?.backend)}`);
    if (latest?.sha256 !== snapSc.sha256) throw new Error(`last_snapshot_status sha256 mismatch`);
    if (!(typeof latest?.age_seconds === 'number' && latest.age_seconds >= 0 && latest.age_seconds < 600)) {
      throw new Error(`last_snapshot_status age_seconds not sane: ${JSON.stringify(latest?.age_seconds)}`);
    }

    // 2d. verify_restore pulls by locator and must reach a full PASS (the
    // private identity lives in this temp CIPHER_BRAIN_HOME).
    send({
      jsonrpc: '2.0',
      id: 6,
      method: 'tools/call',
      params: { name: 'verify_restore', arguments: { locator: snapSc.locator, backend: 'file' } },
    });
    const ver = await waitFor(6);
    const verSc = ver.result?.structuredContent;
    if (ver.result?.isError) throw new Error(`verify_restore failed: ${JSON.stringify(verSc).slice(0, 500)}`);
    if (verSc?.verdict !== 'PASS' || verSc?.exit_code !== 0 || verSc?.restorable_proven !== true) {
      throw new Error(`verify_restore expected a full PASS, got: ${JSON.stringify(verSc).slice(0, 500)}`);
    }
    if (!Array.isArray(verSc.checks) || verSc.checks.length === 0)
      throw new Error('verify_restore checks output missing');

    // 2e. verify_restore via locator_file — the save-locator file supplies the
    // locator, its backend AND the sha256 integrity pin in one (the CLI
    // --from-locator-file recovery path); the response must show the pin was
    // applied (pulled.sha256_pin + the sha256 check line) and carry no warning.
    send({
      jsonrpc: '2.0',
      id: 7,
      method: 'tools/call',
      params: { name: 'verify_restore', arguments: { locator_file: locatorFile } },
    });
    const verPinned = await waitFor(7);
    const verPinnedSc = verPinned.result?.structuredContent;
    if (verPinned.result?.isError)
      throw new Error(`verify_restore(locator_file) failed: ${JSON.stringify(verPinnedSc).slice(0, 500)}`);
    if (verPinnedSc?.verdict !== 'PASS' || verPinnedSc?.restorable_proven !== true) {
      throw new Error(
        `verify_restore(locator_file) expected a full PASS, got: ${JSON.stringify(verPinnedSc).slice(0, 500)}`,
      );
    }
    if (verPinnedSc?.pulled?.locator !== snapSc.locator || verPinnedSc?.pulled?.backend !== 'file') {
      throw new Error(`verify_restore(locator_file) pulled the wrong artifact: ${JSON.stringify(verPinnedSc?.pulled)}`);
    }
    if (verPinnedSc?.pulled?.sha256_pin !== snapSc.sha256) {
      throw new Error(
        `verify_restore(locator_file) did not apply the sha256 integrity pin: ${JSON.stringify(verPinnedSc?.pulled)}`,
      );
    }
    if (!(verPinnedSc.checks ?? []).some((l) => /\[PASS\] sha256 matches/.test(l))) {
      throw new Error(
        `verify_restore(locator_file) checks are missing the sha256 pin line: ${JSON.stringify(verPinnedSc.checks)}`,
      );
    }
    if (verPinnedSc?.warning !== undefined)
      throw new Error(`verify_restore(locator_file) unexpected warning: ${JSON.stringify(verPinnedSc.warning)}`);

    // 2f. negative control: an explicitly WRONG sha256 pin must fail CLOSED —
    // an error result with NO verdict field, never a PASS.
    const wrongSha = (snapSc.sha256[0] === '0' ? '1' : '0') + snapSc.sha256.slice(1);
    send({
      jsonrpc: '2.0',
      id: 8,
      method: 'tools/call',
      params: { name: 'verify_restore', arguments: { locator: snapSc.locator, backend: 'file', sha256: wrongSha } },
    });
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
    // issue #212: the structured error carries the stable CB-E001 code both inline in
    // `message` (same "[CB-E0xx] see MANAGEMENT.md#error-codes" suffix the CLI prints)
    // AND as its own machine-readable `cb_code` field.
    if (!/\[CB-E001\]/.test(verWrongSc?.message ?? '')) {
      throw new Error(`wrong-sha256 pin message lacks the CB-E001 code: ${JSON.stringify(verWrongSc).slice(0, 300)}`);
    }
    if (verWrongSc?.cb_code !== 'CB-E001') {
      throw new Error(`wrong-sha256 pin result lacks cb_code=CB-E001: ${JSON.stringify(verWrongSc).slice(0, 300)}`);
    }

    // 2g. restore_now: without confirm_write must refuse BEFORE any work (mirrors
    // the snapshot_now spend gate at 2a) — out_dir must not even be created. Uses a
    // deliberately-bogus locator (not snapSc.locator): if the gate were ever
    // bypassed, pull() would attempt (and fail) against a nonexistent object,
    // surfacing as a DIFFERENT error than ERR_CONFIRM_REQUIRED — proving the gate
    // runs before any pull, not just that out_dir happens to be untouched.
    const restoreOutDir = join(tmp, 'restored');
    send({
      jsonrpc: '2.0',
      id: 15,
      method: 'tools/call',
      params: {
        name: 'restore_now',
        arguments: { locator: 'does-not-exist-locator', backend: 'file', out_dir: restoreOutDir },
      },
    });
    const restoreGuard = await waitFor(15);
    const restoreGuardSc = restoreGuard.result?.structuredContent;
    if (!restoreGuard.result?.isError || restoreGuardSc?.code !== 'ERR_CONFIRM_REQUIRED') {
      throw new Error(
        `restore_now confirm_write gate is OFF: expected isError + ERR_CONFIRM_REQUIRED (even with a bogus locator), got ${JSON.stringify(restoreGuard.result).slice(0, 300)}`,
      );
    }
    if (existsSync(restoreOutDir)) {
      throw new Error(
        'restore_now confirm_write gate fired but out_dir was still created (gate must run before any work)',
      );
    }

    // 2h. restore_now REAL round-trip (issue #183): pull by locator, decrypt with
    // the identity in this temp CIPHER_BRAIN_HOME, and extract into out_dir — then
    // untar the restored `data.tar.gz` component (restore only extracts the OUTER
    // archive; per-dir components stay tarred, same as the CLI — see MANAGEMENT.md's
    // restore runbook) and assert hello.txt's content on disk matches what was
    // snapshotted, proving an actual disk write, not just a reported verdict.
    send({
      jsonrpc: '2.0',
      id: 16,
      method: 'tools/call',
      params: {
        name: 'restore_now',
        arguments: { locator: snapSc.locator, backend: 'file', out_dir: restoreOutDir, confirm_write: true },
      },
    });
    const restoreRes = await waitFor(16);
    const restoreResSc = restoreRes.result?.structuredContent;
    if (restoreRes.result?.isError)
      throw new Error(`restore_now failed: ${JSON.stringify(restoreResSc).slice(0, 500)}`);
    if (restoreResSc?.pulled?.locator !== snapSc.locator || restoreResSc?.pulled?.backend !== 'file') {
      throw new Error(`restore_now pulled the wrong artifact: ${JSON.stringify(restoreResSc?.pulled)}`);
    }
    if (restoreResSc?.out_dir !== restoreOutDir || restoreResSc?.pg_restored !== false) {
      throw new Error(`restore_now result unexpected: ${JSON.stringify(restoreResSc).slice(0, 300)}`);
    }
    const restoredArchive = join(restoreOutDir, 'data.tar.gz');
    if (!existsSync(restoredArchive)) throw new Error(`restore_now did not extract data.tar.gz into ${restoreOutDir}`);
    const restoreExtractDir = join(tmp, 'restored-extract');
    await mkdir(restoreExtractDir, { recursive: true });
    const untarRes = spawnSync('tar', ['-xzf', restoredArchive, '-C', restoreExtractDir], { encoding: 'utf8' });
    if (untarRes.status !== 0) throw new Error(`untarring restore_now's data.tar.gz failed: ${untarRes.stderr}`);
    const restoredContent = await readFile(join(restoreExtractDir, 'data', 'hello.txt'), 'utf8');
    if (restoredContent !== 'cipher-brain mcp smoke payload\n') {
      throw new Error(`restore_now restored content mismatch: ${JSON.stringify(restoredContent)}`);
    }

    // 2h-ii. restore_now file-input mode with a WRONG sha256 pin must fail closed
    // (fails BEFORE any decrypt/extract — restoreOutDir2 must never be created),
    // exercising the copy-then-hash-then-restore integrity check on the directly-
    // given `file` path (distinct from the pulled-artifact pin pull() itself checks).
    const restoreOutDir2 = join(tmp, 'restored-wrongsha');
    send({
      jsonrpc: '2.0',
      id: 17,
      method: 'tools/call',
      params: {
        name: 'restore_now',
        arguments: {
          file: outAge,
          out_dir: restoreOutDir2,
          confirm_write: true,
          sha256: '0'.repeat(64),
        },
      },
    });
    const restoreWrongSha = await waitFor(17);
    const restoreWrongShaSc = restoreWrongSha.result?.structuredContent;
    if (!restoreWrongSha.result?.isError || restoreWrongShaSc?.code !== 'ERR_INVALID_INPUT') {
      throw new Error(
        `restore_now file-input wrong-sha256 did not fail closed: expected isError + ERR_INVALID_INPUT, got ${JSON.stringify(restoreWrongSha.result).slice(0, 300)}`,
      );
    }
    if (existsSync(restoreOutDir2)) {
      throw new Error('restore_now file-input wrong-sha256 still created out_dir before refusing');
    }

    // 2i. estimate_cost on the free file backend (offline + deterministic —
    // exercises the fourth tool's dispatch without a network dependency).
    send({
      jsonrpc: '2.0',
      id: 9,
      method: 'tools/call',
      params: { name: 'estimate_cost', arguments: { file: outAge, backend: 'file' } },
    });
    const est = await waitFor(9);
    const estSc = est.result?.structuredContent;
    if (est.result?.isError) throw new Error(`estimate_cost failed: ${JSON.stringify(estSc).slice(0, 500)}`);
    if (estSc?.cost !== '0' || estSc?.size_bytes !== snapSc.size_bytes || !estSc?.note) {
      throw new Error(`estimate_cost(file) result unexpected: ${JSON.stringify(estSc).slice(0, 300)}`);
    }

    // 2i-ii. estimate_cost via size_bytes (the CLI `estimate` command's alternative —
    // it always sizes a real --in file, so this argument shape is MCP-only) exercises
    // the same shared estimateCost() (src/lib/estimate.ts) the file-arg call above did,
    // now via the OTHER branch of handleEstimateCost's own file/size_bytes resolution
    // (the part of the tool that did NOT move into the shared function).
    send({
      jsonrpc: '2.0',
      id: 12,
      method: 'tools/call',
      params: { name: 'estimate_cost', arguments: { size_bytes: 12345, backend: 'file' } },
    });
    const estBytes = await waitFor(12);
    const estBytesSc = estBytes.result?.structuredContent;
    if (estBytes.result?.isError)
      throw new Error(`estimate_cost(size_bytes) failed: ${JSON.stringify(estBytesSc).slice(0, 500)}`);
    if (estBytesSc?.cost !== '0' || estBytesSc?.size_bytes !== 12345 || !estBytesSc?.note) {
      throw new Error(`estimate_cost(size_bytes) result unexpected: ${JSON.stringify(estBytesSc).slice(0, 300)}`);
    }

    // 2i-iii. estimate_cost(backend: turbo) — offline, deterministic either way, but
    // the expected shape depends on whether the OPTIONAL @ardrive/turbo-sdk actually
    // resolves in this environment (it is not a devDependency, only an optional
    // peerDependency — package.json — so a frozen-lockfile install normally leaves it
    // absent, but a future lockfile change could add it): branch on its real presence
    // instead of assuming absence (same reasoning as scripts/cli-smoke.sh's estimate
    // --backend turbo case; both exercise the SAME estimateCost() call, #159).
    const turboSdkInstalled = existsSync(join(ROOT, 'node_modules', '@ardrive', 'turbo-sdk'));
    send({
      jsonrpc: '2.0',
      id: 13,
      method: 'tools/call',
      params: { name: 'estimate_cost', arguments: { size_bytes: 12345, backend: 'turbo' } },
    });
    const estTurbo = await waitFor(13);
    const estTurboSc = estTurbo.result?.structuredContent;
    if (estTurbo.result?.isError)
      throw new Error(`estimate_cost(turbo) failed: ${JSON.stringify(estTurboSc).slice(0, 500)}`);
    if (turboSdkInstalled) {
      if (estTurboSc?.backend !== 'turbo' || estTurboSc?.size_bytes !== 12345) {
        throw new Error(
          `estimate_cost(turbo, sdk installed) result unexpected: ${JSON.stringify(estTurboSc).slice(0, 300)}`,
        );
      }
    } else if (estTurboSc?.cost !== null || !/not installed/.test(estTurboSc?.note ?? '')) {
      throw new Error(
        `estimate_cost(turbo, sdk missing) result unexpected: ${JSON.stringify(estTurboSc).slice(0, 300)}`,
      );
    }

    // 2j. schedule_install: without confirm_install must refuse BEFORE any file is
    // written (mirrors the restore_now/snapshot_now gates above).
    send({
      jsonrpc: '2.0',
      id: 18,
      method: 'tools/call',
      params: { name: 'schedule_install', arguments: { backend: 'file', dirs: [data], no_load: true } },
    });
    const schedInstallGuard = await waitFor(18);
    const schedInstallGuardSc = schedInstallGuard.result?.structuredContent;
    if (!schedInstallGuard.result?.isError || schedInstallGuardSc?.code !== 'ERR_CONFIRM_REQUIRED') {
      throw new Error(
        `schedule_install confirm_install gate is OFF: expected isError + ERR_CONFIRM_REQUIRED, got ${JSON.stringify(schedInstallGuard.result).slice(0, 300)}`,
      );
    }
    if (existsSync(launchdDir)) {
      throw new Error('schedule_install confirm_install gate fired but launchdDir was still created');
    }
    if (existsSync(join(home, 'schedule'))) {
      throw new Error('schedule_install confirm_install gate fired but the runner/config dir was still created');
    }

    // 2j-ii. a paid backend without max_spend must refuse (install()'s own validation,
    // delegated to unchanged — proves the confirm_install gate does not shadow it, and
    // that this refusal fires before max_spend's absence would otherwise matter).
    send({
      jsonrpc: '2.0',
      id: 20,
      method: 'tools/call',
      params: {
        name: 'schedule_install',
        arguments: { backend: 'turbo', dirs: [data], no_load: true, confirm_install: true },
      },
    });
    const schedInstallNoSpend = await waitFor(20);
    if (
      !schedInstallNoSpend.result?.isError ||
      !/max-spend|max_spend/i.test(schedInstallNoSpend.result?.structuredContent?.message ?? '')
    ) {
      throw new Error(
        `schedule_install (backend=turbo, no max_spend) did not refuse for the expected reason: ${JSON.stringify(schedInstallNoSpend.result).slice(0, 300)}`,
      );
    }
    if (existsSync(join(home, 'schedule'))) {
      throw new Error(
        'schedule_install (backend=turbo, no max_spend) still wrote the runner/config dir before refusing',
      );
    }

    // 2k. schedule_install REAL --no-load install (issue #174 follow-up): registers
    // NOTHING with the real launchctl/crontab (no_load: true — this env's
    // CIPHER_BRAIN_LAUNCHD_DIR is already scoped to a temp dir, so even a real load
    // would be harmless, but no_load also proves the tool's own opt-out path works),
    // then schedule_status (below) reads back the SAME state this call wrote.
    send({
      jsonrpc: '2.0',
      id: 19,
      method: 'tools/call',
      params: {
        name: 'schedule_install',
        arguments: { backend: 'file', dirs: [data], no_load: true, confirm_install: true },
      },
    });
    const schedInstall = await waitFor(19);
    const schedInstallSc = schedInstall.result?.structuredContent;
    if (schedInstall.result?.isError)
      throw new Error(`schedule_install failed: ${JSON.stringify(schedInstallSc).slice(0, 500)}`);
    if (schedInstallSc?.backend !== 'file' || schedInstallSc?.at !== '03:30' || schedInstallSc?.no_load !== true) {
      throw new Error(`schedule_install result unexpected: ${JSON.stringify(schedInstallSc).slice(0, 300)}`);
    }

    // 2l. schedule_status — thin wrapper over the SAME schedule() the CLI's `schedule
    // status` dispatches to; asserts against the schedule_install call just above,
    // verbatim report lines rather than re-parsed fields (matching handleScheduleStatus's
    // "no re-implemented logic" design).
    send({ jsonrpc: '2.0', id: 10, method: 'tools/call', params: { name: 'schedule_status', arguments: {} } });
    const sched = await waitFor(10);
    const schedSc = sched.result?.structuredContent;
    if (sched.result?.isError) throw new Error(`schedule_status failed: ${JSON.stringify(schedSc).slice(0, 500)}`);
    if (!Array.isArray(schedSc?.report) || schedSc.report.length === 0) {
      throw new Error(`schedule_status report missing/empty: ${JSON.stringify(schedSc)}`);
    }
    if (!schedSc.report.some((l) => l === 'configured: daily at 03:30, backend file')) {
      throw new Error(`schedule_status report missing the configured line: ${JSON.stringify(schedSc.report)}`);
    }
    if (!schedSc.report.some((l) => /^next run: /.test(l))) {
      throw new Error(`schedule_status report missing the next-run line: ${JSON.stringify(schedSc.report)}`);
    }

    // 2m. schedule_status must REJECT unexpected arguments rather than silently
    // ignore them (the tool takes none — a stray field could otherwise mask a
    // client's mistaken attempt to scope the report to a different schedule).
    send({
      jsonrpc: '2.0',
      id: 11,
      method: 'tools/call',
      params: { name: 'schedule_status', arguments: { unexpected: true } },
    });
    const schedBad = await waitFor(11);
    const schedBadSc = schedBad.result?.structuredContent;
    if (schedBad.result?.isError !== true || schedBadSc?.code !== 'ERR_INVALID_INPUT') {
      throw new Error(
        `schedule_status did not reject an unexpected argument: ${JSON.stringify(schedBad.result).slice(0, 300)}`,
      );
    }

    // 2n. keygen against THIS server's home — which already has a real identity
    // (written by the CLI-driven keygen at the top of this run, not by the tool
    // itself) — must refuse rather than silently re-key a brain snapshots already
    // depend on. Complements the fresh-home keygen coverage in
    // runKeygenWalletTests() below by proving the refusal also holds for an
    // identity that pre-dates the MCP server's own lifetime.
    send({ jsonrpc: '2.0', id: 14, method: 'tools/call', params: { name: 'keygen', arguments: {} } });
    const keygenGuard = await waitFor(14);
    if (keygenGuard.result?.isError !== true)
      throw new Error(
        `keygen against a pre-existing identity did not refuse: ${JSON.stringify(keygenGuard.result).slice(0, 300)}`,
      );
    if (!/already exists/.test(keygenGuard.result?.structuredContent?.message ?? ''))
      throw new Error(`keygen refused for the wrong reason: ${JSON.stringify(keygenGuard.result?.structuredContent)}`);

    process.stdout.write(
      `MCP SMOKE: PASS — tools=[${names.join(', ')}], spend gate=ERR_CONFIRM_REQUIRED, ` +
        `file round-trip locator=${snapSc.locator.split('/').pop()}, status.age=${latest.age_seconds}s, verify=${verSc.verdict}, ` +
        `verify(locator_file pin)=${verPinnedSc.verdict}, wrong-pin=fail-closed, ` +
        `restore_now gate=ERR_CONFIRM_REQUIRED, restore_now round-trip content=ok, estimate(file)=0, ` +
        `estimate(size_bytes)=0, estimate(turbo, sdk ${turboSdkInstalled ? 'installed' : 'missing'})=ok, ` +
        `schedule_install gate=ERR_CONFIRM_REQUIRED, schedule_install no_load=ok, ` +
        `schedule_status.report.length=${schedSc.report.length}, keygen(pre-existing)=refused\n`,
    );
  } finally {
    try {
      child.stdin.end();
    } catch {
      /* ignore */
    }
    try {
      child.kill();
    } catch {
      /* ignore */
    }
  }
}

main().catch((err) => {
  process.stderr.write(`MCP SMOKE: FAIL — ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
});
