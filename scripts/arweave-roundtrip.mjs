#!/usr/bin/env node
// Arweave backend parity proof (issue #9). Spins up a LOCAL arlocal gateway (no real
// AR, no network) and runs the cipher-brain pipeline against it:
//   snapshot -> push --backend arweave -> (mine) -> pull -> verify -> restore.
// It proves the StorageBackend abstraction holds for a backend whose locator (an
// Arweave tx id) is assigned AFTER upload and is NOT the ciphertext's content hash —
// the case file/ton (content-addressed locators) didn't exercise.
import Arweave from 'arweave';
import { mkdtemp, mkdir, writeFile, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn, spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';

const PORT = Number(process.env.CB_ARLOCAL_PORT || 1984);
const HERE = dirname(fileURLToPath(import.meta.url));
const BIN = join(HERE, '..', 'bin', 'cipher-brain.mjs');
const sha = (buf) => createHash('sha256').update(buf).digest('hex');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const TX_RE = /^[A-Za-z0-9_-]{43}$/; // base64url Arweave tx id

const log = (m) => console.error(`· ${m}`);
// arlocal runs in a SEPARATE process (scripts/arlocal-server.mjs) so the cb()
// spawns below don't inherit its sockets and deadlock — see that file's header.
log(`starting arlocal on :${PORT}`);
const arproc = spawn('node', [join(HERE, 'arlocal-server.mjs'), String(PORT)], { stdio: 'ignore' });
let ready = false;
for (let i = 0; i < 80; i++) { try { await fetch(`http://localhost:${PORT}/info`); ready = true; break; } catch { await sleep(250); } }
if (!ready) { arproc.kill('SIGKILL'); console.log('[FAIL] arlocal did not start'); process.exit(1); }
log('arlocal ready');
const ar = Arweave.init({ host: 'localhost', port: PORT, protocol: 'http' });
const tmp = await mkdtemp(join(tmpdir(), 'cb-arweave-'));
let failed = false;
const pass = (m) => console.log(`[PASS] ${m}`);
const fail = (m) => { console.log(`[FAIL] ${m}`); failed = true; };
const mine = () => fetch(`http://localhost:${PORT}/mine`).then((r) => r.text());

try {
  // a funded test wallet (arlocal mint — no real AR)
  const jwk = await ar.wallets.generate();
  const addr = await ar.wallets.jwkToAddress(jwk);
  const walletPath = join(tmp, 'wallet.json');
  await writeFile(walletPath, JSON.stringify(jwk));
  await fetch(`http://localhost:${PORT}/mint/${addr}/100000000000000`);
  log('wallet funded');

  const env = {
    ...process.env,
    CIPHER_BRAIN_HOME: join(tmp, 'keys'),
    CIPHER_BRAIN_AR_HOST: 'localhost',
    CIPHER_BRAIN_AR_PORT: String(PORT),
    CIPHER_BRAIN_AR_PROTOCOL: 'http',
    CIPHER_BRAIN_AR_WALLET: walletPath,
  };
  const cb = (...args) => {
    const r = spawnSync('node', [BIN, ...args], { env, encoding: 'utf8' });
    if (r.status !== 0) throw new Error(`cb ${args.join(' ')} failed (${r.status}): ${r.stderr || r.stdout}`);
    return r.stdout.trim();
  };

  // build a synthetic brain + snapshot it
  const src = join(tmp, 'brain');
  await mkdir(src, { recursive: true });
  const marker = 'arweave-marker-' + randomBytes(6).toString('hex');
  await writeFile(join(src, 'note.txt'), marker + '\n');
  log('keygen'); cb('keygen');
  log('snapshot'); cb('snapshot', '--dir', src, '--out', join(tmp, 'snap.age'));
  const cipher = await readFile(join(tmp, 'snap.age'));
  const cipherSha = sha(cipher);

  // push -> the locator is the Arweave tx id (assigned at upload, not the content hash)
  log('push --backend arweave'); const loc = cb('push', '--in', join(tmp, 'snap.age'), '--backend', 'arweave');
  log(`pushed, tx=${loc}`);
  TX_RE.test(loc) ? pass(`push -> tx id ${loc} (43-char base64url)`) : fail(`locator is not a tx id: ${loc}`);
  loc !== cipherSha ? pass('locator is NOT the ciphertext content hash (post-assigned, not content-addressed)')
                    : fail('locator equals the content hash — not the arweave case');

  log('mine'); await mine(); // arlocal: confirm the pending tx

  // a fresh machine that only has the tx id (NO upload wallet) fetches the bytes back
  const pullEnv = { ...env };
  delete pullEnv.CIPHER_BRAIN_AR_WALLET;
  log('pull (no wallet)');
  const rp = spawnSync('node', [BIN, 'pull', '--locator', loc, '--backend', 'arweave', '--out', join(tmp, 'got.age')], { env: pullEnv, encoding: 'utf8' });
  rp.status === 0 ? pass('pull works with only the tx id (no upload wallet needed)') : fail(`pull without wallet failed: ${rp.stderr}`);
  const got = await readFile(join(tmp, 'got.age'));
  sha(got) === cipherSha ? pass('pulled bytes == pushed ciphertext (byte-identical)') : fail('pulled bytes differ');

  // verify + decrypt the pulled ciphertext
  cb('verify', '--in', join(tmp, 'got.age')).includes('VERDICT: PASS')
    ? pass('verify VERDICT PASS on pulled') : fail('verify did not pass');
  cb('restore', '--in', join(tmp, 'got.age'), '--out-dir', join(tmp, 'out'));
  spawnSync('tar', ['-xzf', join(tmp, 'out', 'brain.tar.gz'), '-C', join(tmp, 'out')]);
  const restored = await readFile(join(tmp, 'out', 'brain', 'note.txt'), 'utf8');
  restored.includes(marker) ? pass('decrypt(pulled) == original plaintext') : fail('decrypted content mismatch');

  // negative control: an unknown tx id returns no bytes
  const badId = 'A'.repeat(43);
  const r = spawnSync('node', [BIN, 'pull', '--locator', badId, '--backend', 'arweave', '--out', join(tmp, 'bad.age')], { env, encoding: 'utf8' });
  r.status !== 0 ? pass('negative control: unknown tx id fails') : fail('unknown tx id unexpectedly succeeded');
} catch (e) {
  fail(`exception: ${e.message}`);
} finally {
  await rm(tmp, { recursive: true, force: true });
  arproc.kill('SIGTERM');
}

console.log('');
if (failed) { console.log('ARWEAVE ROUND-TRIP: FAIL'); process.exit(1); }
console.log('ARWEAVE ROUND-TRIP: PASS (abstraction holds for a post-assigned tx-id locator)');
