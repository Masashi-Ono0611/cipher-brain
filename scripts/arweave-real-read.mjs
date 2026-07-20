#!/usr/bin/env node
// Operator check (NOT in CI — it hits the LIVE arweave.net gateway). Proves the
// arweave backend get() retrieves BOTH an ANS-104 *bundled* data item (the Turbo/
// Irys form produced by the pay-with-ETH/USDC path) AND a plain L1 tx. The arlocal
// selftest (npm run selftest:arweave) only exercises an L1 round-trip, so this is
// the piece that proves *bundled* reads — which the old get() could not do — work
// against real Arweave.
//
//   node scripts/arweave-real-read.mjs
//
// The fixtures are hardcoded, which is safe BECAUSE Arweave is permanent: a tx id
// that resolves today resolves forever, so these can't rot the way a mutable-store
// fixture would. We assert the retrieved bytes match a pinned SHA-256 (not just the
// length — same-length corruption must not pass), so a failure here is a real
// gateway/backend regression, never a false pass.
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';

const HOST = process.env.CIPHER_BRAIN_AR_HOST || 'arweave.net';
const PORT = process.env.CIPHER_BRAIN_AR_PORT || '443';
const PROTOCOL = process.env.CIPHER_BRAIN_AR_PROTOCOL || 'https';
const HERE = dirname(fileURLToPath(import.meta.url));
const BIN = join(HERE, '..', 'bin', 'cipher-brain.mjs');

const FIXTURES = [
  // bundled item: the old getData() chunk read returns nothing for this; the new
  // gateway-HTTP read retrieves it. This is the case the Turbo pay path produces.
  {
    kind: 'bundled (ANS-104)',
    id: 'jd4yLGqqJtWJYUpxF8rBzSOMEk0Js1Gh2iE3LQxhGRM',
    sha256: 'b6686641b052c431258d200f208898b45990393a34b8fe9d75550c4e2d2ec808',
  },
  // plain L1 tx: served by the chunk-read fallback when the gateway HTTP front is
  // flaky (it can 5xx for L1 ids), so both read paths stay covered.
  {
    kind: 'L1',
    id: 'ww_s6Lhed3hGZnMigPXjQjTzxPwBJj4M5jXdkT4DpSk',
    sha256: '88d85b66d56acacf76ed0f4b5c90a78f221824509f189e9be83ef16700c6e49b',
  },
];

let failed = false;
const pass = (m) => console.log(`[PASS] ${m}`);
const fail = (m) => {
  console.log(`[FAIL] ${m}`);
  failed = true;
};

const tmp = await mkdtemp(join(tmpdir(), 'cb-ar-real-'));
try {
  for (const f of FIXTURES) {
    const out = join(tmp, `${f.id}.bin`);
    const env = {
      ...process.env,
      CIPHER_BRAIN_AR_HOST: HOST,
      CIPHER_BRAIN_AR_PORT: PORT,
      CIPHER_BRAIN_AR_PROTOCOL: PROTOCOL,
    };
    const r = spawnSync('node', [BIN, 'pull', '--locator', f.id, '--backend', 'arweave', '--out', out], {
      encoding: 'utf8',
      env,
    });
    if (r.status !== 0) {
      fail(`${f.kind} ${f.id}: pull failed: ${(r.stderr || '').trim()}`);
      continue;
    }
    const got = createHash('sha256')
      .update(await readFile(out))
      .digest('hex');
    got === f.sha256
      ? pass(`${f.kind} ${f.id}: sha256 matches (byte-correct)`)
      : fail(`${f.kind} ${f.id}: sha256 ${got} != expected ${f.sha256}`);
  }
} catch (e) {
  fail(`exception: ${e.message}`);
} finally {
  await rm(tmp, { recursive: true, force: true });
}

console.log('');
console.log(
  failed
    ? 'ARWEAVE REAL READ: FAIL'
    : 'ARWEAVE REAL READ: PASS (bundled + L1 both retrieved byte-correct from the live gateway)',
);
process.exit(failed ? 1 : 0);
