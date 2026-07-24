#!/usr/bin/env node
// Proof for #170: arUsdRate() (src/lib/estimate.ts) — the USD/AR rate behind
// `estimate`'s optional USD line — fetches CIPHER_BRAIN_AR_USD_RATE_URL directly via
// plain HTTP, NOT via @ardrive/turbo-sdk. Run against a COPY of the bundled
// dist/cli.mjs in a directory with NO node_modules (so `import('@ardrive/turbo-sdk')`
// is genuinely unresolvable there — the same isolation trick as
// selftest-arweave-nodeps.mjs, #31) with two IN-PROCESS local HTTP mocks standing in
// for the arweave gateway /price endpoint and the Turbo USD-rate endpoint. This proves
// both that the USD line appears with the SDK entirely absent, and that every
// documented arUsdRate() failure mode (non-200, malformed JSON, non-positive rate,
// connection-refused) degrades to "no usd line" rather than failing the (still useful)
// native cost estimate.
//
// The CLI is spawned ASYNC (spawn, not spawnSync) specifically so this script's own
// in-process http.createServer mocks can keep answering requests while it runs —
// spawnSync would block the event loop and starve them (the reason
// selftest-arweave-nodeps.mjs runs its mock gateway in a SEPARATE process instead).
import { mkdtemp, mkdir, writeFile, copyFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn, spawnSync } from 'node:child_process';
import { createServer } from 'node:http';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, '..');
let failed = false;
const pass = (m) => console.log(`[PASS] ${m}`);
const fail = (m) => {
  console.log(`[FAIL] ${m}`);
  failed = true;
};

const tmp = await mkdtemp(join(tmpdir(), 'cb-usdrate-'));

// Isolated copy of the bundled CLI — a dir with NO node_modules, so
// `import('@ardrive/turbo-sdk')` is genuinely unresolvable from it.
const distCli = join(ROOT, 'dist', 'cli.mjs');
const isoDir = join(tmp, 'iso');
await mkdir(isoDir, { recursive: true });
const isoBin = join(isoDir, 'cli.mjs');
await copyFile(distCli, isoBin).catch(() => {
  throw new Error('dist/cli.mjs not found — run `npm run build` first');
});

// control: confirm @ardrive/turbo-sdk is genuinely unresolvable from the isolated dir,
// so a USD line below actually proves "no SDK needed" (not a leaked node_modules).
const probe = spawnSync(
  'node',
  [
    '--input-type=module',
    '-e',
    "import('@ardrive/turbo-sdk').then(()=>process.exit(9)).catch(e=>process.exit(e&&e.code==='ERR_MODULE_NOT_FOUND'?0:9))",
  ],
  { cwd: isoDir, encoding: 'utf8' },
);
probe.status === 0
  ? pass('control: @ardrive/turbo-sdk is genuinely unresolvable from the isolated dir')
  : fail('control: @ardrive/turbo-sdk WAS resolvable — test is not isolating the dependency');

// A plain file to size — `estimate` only stats it, so its content is irrelevant.
const sizedFile = join(tmp, 'payload.bin');
await writeFile(sizedFile, Buffer.alloc(1024, 1));

const MOCK_WINSTON = '9999999';
const MOCK_RATE = 1.89;
const EXPECTED_USD = ((Number(MOCK_WINSTON) / 1e12) * MOCK_RATE).toFixed(6);

// Every mock server opened via startServer() is tracked here and closed in the
// top-level finally below — not just on the success path of whichever check opened
// it — so a rejected/timed-out runEstimate() partway through can't leave an earlier
// case's server dangling.
const openedServers = [];
const startServer = (handler) =>
  new Promise((resolve, reject) => {
    const s = createServer(handler);
    s.on('error', reject);
    s.listen(0, '127.0.0.1', () => {
      openedServers.push(s);
      resolve(s);
    });
  });
const serverUrl = (s) => `http://127.0.0.1:${s.address().port}`;

const priceServer = await startServer((_req, res) => {
  res.writeHead(200, { 'content-type': 'text/plain' });
  res.end(MOCK_WINSTON);
});

const runEstimate = (usdRateUrl) =>
  new Promise((resolve, reject) => {
    const child = spawn('node', [isoBin, 'estimate', '--in', sizedFile, '--backend', 'arweave'], {
      env: {
        ...process.env,
        CIPHER_BRAIN_AR_HOST: '127.0.0.1',
        CIPHER_BRAIN_AR_PORT: String(priceServer.address().port),
        CIPHER_BRAIN_AR_PROTOCOL: 'http',
        CIPHER_BRAIN_AR_USD_RATE_URL: usdRateUrl,
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => (stdout += d));
    child.stderr.on('data', (d) => (stderr += d));
    const to = setTimeout(() => {
      child.kill('SIGKILL');
      reject(new Error('estimate timed out'));
    }, 15000);
    child.on('close', (code) => {
      clearTimeout(to);
      resolve({ code, stdout, stderr });
    });
    child.on('error', reject);
  });

const expectUsdLine = (r, label) => {
  if (r.code !== 0) {
    fail(`estimate --backend arweave exited non-zero with ${label}: ${r.stderr.slice(0, 200)}`);
  } else if (!r.stdout.includes(`cost: ${MOCK_WINSTON} winston`)) {
    fail(`estimate did not report the mocked winston cost with ${label}: ${r.stdout}`);
  } else if (!r.stdout.includes(`approx: ~$${EXPECTED_USD} USD`)) {
    fail(`estimate with ${label} did not print the expected USD line: ${r.stdout}`);
  } else {
    pass(`estimate --backend arweave: USD line present with ${label} (@ardrive/turbo-sdk absent, #170)`);
  }
};

const expectNoUsdLine = (r, label) => {
  if (r.code !== 0) {
    fail(`estimate --backend arweave exited non-zero with ${label}: ${r.stderr.slice(0, 200)}`);
  } else if (!r.stdout.includes(`cost: ${MOCK_WINSTON} winston`)) {
    fail(`the native cost estimate broke with ${label}: ${r.stdout}`);
  } else if (r.stdout.includes('USD')) {
    fail(`${label} unexpectedly still produced a USD line: ${r.stdout}`);
  } else {
    pass(`estimate --backend arweave: ${label} degrades to no USD line — cost estimate still succeeds`);
  }
};

try {
  // (1) success: a working USD-rate mock -> the USD line appears, SDK absent.
  const rateOk = await startServer((_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ currency: 'usd', rate: MOCK_RATE }));
  });
  expectUsdLine(await runEstimate(serverUrl(rateOk)), 'a working USD-rate mock');

  // (2) non-200 response -> no usd line, native cost still succeeds
  const rate500 = await startServer((_req, res) => {
    res.writeHead(500);
    res.end('nope');
  });
  expectNoUsdLine(await runEstimate(serverUrl(rate500)), 'a non-200 USD-rate response');

  // (3) malformed JSON -> no usd line
  const rateBadJson = await startServer((_req, res) => {
    res.writeHead(200);
    res.end('not json');
  });
  expectNoUsdLine(await runEstimate(serverUrl(rateBadJson)), 'a malformed-JSON USD-rate response');

  // (4) non-positive rate -> no usd line
  const rateZero = await startServer((_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ currency: 'usd', rate: 0 }));
  });
  expectNoUsdLine(await runEstimate(serverUrl(rateZero)), 'a zero USD/AR rate');

  // (5) connection refused (network error) -> no usd line. fetch() rejects the same
  // way for a real timeout, so this exercises the same catch-all path a timeout would
  // without an actual multi-second sleep in this test.
  expectNoUsdLine(await runEstimate('http://127.0.0.1:1'), 'a connection-refused USD-rate endpoint');
} finally {
  priceServer.close();
  for (const s of openedServers) s.close();
}

console.log('');
if (failed) {
  console.log('USD RATE: FAIL');
  process.exit(1);
}
console.log('USD RATE: PASS (arUsdRate() works without @ardrive/turbo-sdk; every failure mode degrades gracefully)');
