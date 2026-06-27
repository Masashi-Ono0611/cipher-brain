#!/usr/bin/env node
// Operator check (NOT in CI — it does a REAL upload to Arweave via Turbo). Proves
// `cipher-brain push --backend turbo` end to end: encrypt a tiny payload, upload it FREE
// (<100KB) via Turbo signed by CIPHER_BRAIN_AR_WALLET, then pull it back from a public
// gateway (`--backend turbo`, which reuses the arweave reader) and decrypt it.
//
// Needs `npm install @ardrive/turbo-sdk` and a JWK at CIPHER_BRAIN_AR_WALLET. Uploads
// under 100KB are free, so the JWK needs no funds:
//   CIPHER_BRAIN_AR_WALLET=~/.cipher-brain/ar-demo-wallet.json node scripts/turbo-roundtrip.mjs
import { mkdtemp, mkdir, writeFile, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';

const HERE = dirname(fileURLToPath(import.meta.url));
const BIN = join(HERE, '..', 'bin', 'cipher-brain.mjs');
const sha = (b) => createHash('sha256').update(b).digest('hex');
let failed = false;
const pass = (m) => console.log(`[PASS] ${m}`);
const fail = (m) => { console.log(`[FAIL] ${m}`); failed = true; };

const wallet = process.env.CIPHER_BRAIN_AR_WALLET;
if (!wallet) { console.log('set CIPHER_BRAIN_AR_WALLET to a JWK (e.g. ~/.cipher-brain/ar-demo-wallet.json)'); process.exit(2); }

const tmp = await mkdtemp(join(tmpdir(), 'cb-turbo-'));
const env = { ...process.env, CIPHER_BRAIN_HOME: join(tmp, 'keys'), CIPHER_BRAIN_AR_WALLET: wallet };
const cb = (...args) => {
  const r = spawnSync('node', [BIN, ...args], { env, encoding: 'utf8' });
  if (r.status !== 0) throw new Error(`cb ${args.join(' ')} failed: ${r.stderr || r.stdout}`);
  return r.stdout.trim();
};

try {
  // small payload (<100KB ⇒ free Turbo upload)
  const src = join(tmp, 'brain');
  await mkdir(src, { recursive: true });
  const marker = 'turbo-' + randomBytes(8).toString('hex');
  await writeFile(join(src, 'note.txt'), marker + '\n');
  cb('keygen');
  cb('snapshot', '--dir', src, '--out', join(tmp, 'slice.age'));
  const cipher = await readFile(join(tmp, 'slice.age'));
  console.log(`· encrypted slice: ${cipher.length} B (${cipher.length < 100000 ? 'free tier' : 'PAID — >100KB'})`);

  console.log('· uploading via Turbo (real Arweave)…');
  const id = cb('push', '--in', join(tmp, 'slice.age'), '--backend', 'turbo');
  /^[A-Za-z0-9_-]{43}$/.test(id) ? pass(`turbo upload → data item id ${id}`) : fail(`not a 43-char id: ${id}`);

  console.log('· pulling back via --backend turbo from a public gateway, NO wallet (waiting for propagation)…');
  const pullEnv = { ...env };
  delete pullEnv.CIPHER_BRAIN_AR_WALLET; // a turbo PULL must need no wallet (fresh-machine recovery, runbook §3)
  const rp = spawnSync('node', [BIN, 'pull', '--locator', id, '--backend', 'turbo', '--out', join(tmp, 'got.age'), '--wait', '720'], { env: pullEnv, encoding: 'utf8' });
  if (rp.status !== 0) {
    fail(`pull failed: ${(rp.stderr || '').slice(-300)}`);
  } else {
    const got = await readFile(join(tmp, 'got.age'));
    sha(got) === sha(cipher) ? pass('no-wallet pull: bytes == uploaded ciphertext (byte-identical)') : fail('pulled bytes differ');
    cb('verify', '--in', join(tmp, 'got.age')).includes('VERDICT: PASS') ? pass('decrypts with the identity (VERDICT PASS)') : fail('verify did not pass');
  }
} catch (e) {
  fail(`exception: ${e.message}`);
} finally {
  await rm(tmp, { recursive: true, force: true });
}

console.log('');
console.log(failed ? 'TURBO ROUND-TRIP: FAIL' : 'TURBO ROUND-TRIP: PASS (real free Turbo upload → public-gateway pull → decrypt)');
process.exit(failed ? 1 : 0);
