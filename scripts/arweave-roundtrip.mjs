#!/usr/bin/env node
// Arweave backend parity proof (issue #9). Spins up a LOCAL arlocal gateway (no real
// AR, no network) and runs the cipher-brain pipeline against it:
//   snapshot -> push --backend arweave -> (mine) -> pull -> verify -> restore.
// It proves the StorageBackend abstraction holds for a backend whose locator (an
// Arweave tx id) is assigned AFTER upload and is NOT the ciphertext's content hash —
// the case file (a content-addressed locator) didn't exercise.
import Arweave from 'arweave';
import { mkdtemp, mkdir, writeFile, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn, spawnSync } from 'node:child_process';
import { createServer } from 'node:http';
import { createHash, randomBytes } from 'node:crypto';
import { DEV_ARGS } from './dev-node-flags.mjs';

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
  await writeFile(walletPath, JSON.stringify(jwk), { mode: 0o600 }); // 0600: avoid the loose-perms warning (#35)
  await fetch(`http://localhost:${PORT}/mint/${addr}/100000000000000`);
  log('wallet funded');

  const env = {
    ...process.env,
    CIPHER_BRAIN_HOME: join(tmp, 'keys'),
    CIPHER_BRAIN_AR_HOST: 'localhost',
    CIPHER_BRAIN_AR_PORT: String(PORT),
    CIPHER_BRAIN_AR_PROTOCOL: 'http',
    CIPHER_BRAIN_AR_WALLET: walletPath,
    CIPHER_BRAIN_YES: '1', // arlocal (test) — no real funds; bypass the interactive --yes guard
    // $BIN (bin/cipher-brain.mjs) imports src/cli.ts directly (no build step); its
    // internal imports use the OUTPUT extension (`./lib/config.js`, #63), which plain
    // node needs help resolving back to the sibling .ts file — see
    // scripts/dev-ts-resolve-hook.mjs. DEV_ARGS (scripts/dev-node-flags.mjs) is passed
    // as literal argv elements on every spawnSync('node', [...DEV_ARGS, BIN, ...])
    // below — NEVER via env.NODE_OPTIONS, which is whitespace-split by node and would
    // break under a checkout path containing a space.
  };
  // AR_HOST=localhost is not the default arweave.net, so arGateways() yields only the
  // derived arlocal gateway (no public mirrors) — the test never egresses.
  const cb = (...args) => {
    const r = spawnSync('node', [...DEV_ARGS, BIN, ...args], { env, encoding: 'utf8' });
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

  // size guard (#37): the raw arweave backend posts one inline L1 tx; an oversized
  // artifact must be REJECTED up front with an actionable redirect to --backend turbo,
  // not buffered and 400'd. Force a tiny limit so the ~10 KB snapshot trips it.
  log('size guard: oversized L1 push is refused with a turbo redirect');
  const sg = spawnSync('node', [...DEV_ARGS, BIN, 'push', '--in', join(tmp, 'snap.age'), '--backend', 'arweave'],
    { env: { ...env, CIPHER_BRAIN_AR_L1_MAX: '1' }, encoding: 'utf8' });
  (sg.status !== 0 && /--backend turbo/.test(sg.stderr) && /exceeds/.test(sg.stderr))
    ? pass('size guard: oversized L1 push is refused with a turbo redirect')
    : fail(`size guard did not fire as expected: status=${sg.status} stderr=${(sg.stderr || '').slice(0, 160)}`);

  // spend cap (Codex review, #69 P1): the arweave backend must actually ENFORCE
  // CIPHER_BRAIN_MAX_SPEND before signing — not merely log that it "cannot pre-flight
  // the cost" and upload anyway. A `schedule install --backend arweave --max-spend n`
  // bakes CIPHER_BRAIN_YES=1 into the unattended runner, so this cap is the only thing
  // standing between an operator's requested budget and an uncapped nightly L1 spend.
  log('spend cap: a tiny CIPHER_BRAIN_MAX_SPEND aborts the L1 push before signing');
  const capFail = spawnSync('node', [...DEV_ARGS, BIN, 'push', '--in', join(tmp, 'snap.age'), '--backend', 'arweave'],
    { env: { ...env, CIPHER_BRAIN_MAX_SPEND: '1' }, encoding: 'utf8' });
  (capFail.status !== 0 && /L1 cost estimate/.test(capFail.stderr) && /exceeds CIPHER_BRAIN_MAX_SPEND/.test(capFail.stderr))
    ? pass('spend cap: a 1-winston cap aborts the upload with a real (not skipped) cost estimate')
    : fail(`spend cap did not abort as expected: status=${capFail.status} stderr=${(capFail.stderr || '').slice(0, 200)}`);

  log('spend cap: a generous CIPHER_BRAIN_MAX_SPEND still lets the push through');
  const capOk = spawnSync('node', [...DEV_ARGS, BIN, 'push', '--in', join(tmp, 'snap.age'), '--backend', 'arweave'],
    { env: { ...env, CIPHER_BRAIN_MAX_SPEND: '100000000000000' }, encoding: 'utf8' });
  (capOk.status === 0 && TX_RE.test(capOk.stdout.trim()))
    ? pass('spend cap: an under-cap CIPHER_BRAIN_MAX_SPEND still lets the push through')
    : fail(`under-cap push unexpectedly failed: status=${capOk.status} stderr=${(capOk.stderr || '').slice(0, 200)}`);

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
  const rp = spawnSync('node', [...DEV_ARGS, BIN, 'pull', '--locator', loc, '--backend', 'arweave', '--out', join(tmp, 'got.age')], { env: pullEnv, encoding: 'utf8' });
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

  // negative control: an unknown (but well-formed) tx id returns no bytes
  const badId = 'A'.repeat(43);
  const r = spawnSync('node', [...DEV_ARGS, BIN, 'pull', '--locator', badId, '--backend', 'arweave', '--out', join(tmp, 'bad.age')], { env, encoding: 'utf8' });
  r.status !== 0 ? pass('negative control: unknown tx id fails') : fail('unknown tx id unexpectedly succeeded');

  // guard: a malformed locator must be rejected BEFORE it is interpolated into the
  // gateway URL the get() HTTP read builds (path-traversal/SSRF guard)
  const bad2 = spawnSync('node', [...DEV_ARGS, BIN, 'pull', '--locator', '../../etc/passwd', '--backend', 'arweave', '--out', join(tmp, 'bad2.age')], { env, encoding: 'utf8' });
  (bad2.status !== 0 && /invalid tx id/.test(bad2.stderr))
    ? pass('guard: malformed locator rejected (no SSRF/path-traversal)')
    : fail('malformed locator was not rejected by the id guard');

  // fallback coverage: point the gateway HTTP read (path 1) at a dead address and
  // assert the L1 chunk-read fallback (path 2 = getData) still serves the bytes.
  // Without this the fallback is never exercised — arlocal serves GET /{id}, so the
  // happy path above always wins on path 1.
  const fbEnv = { ...env, CIPHER_BRAIN_AR_GATEWAY: 'http://127.0.0.1:1' }; // connection refused → path 1 fails fast
  const fb = spawnSync('node', [...DEV_ARGS, BIN, 'pull', '--locator', loc, '--backend', 'arweave', '--out', join(tmp, 'fb.age')], { env: fbEnv, encoding: 'utf8' });
  (fb.status === 0 && sha(await readFile(join(tmp, 'fb.age'))) === cipherSha)
    ? pass('fallback: L1 chunk read serves when the gateway HTTP path is dead')
    : fail(`fallback path did not serve via getData: ${fb.stderr || 'bytes differ'}`);

  // --wait retry (#19): a not-yet-available id with a wait budget retries (then still
  // fails for a truly-missing id). A short retry interval keeps the test fast.
  const wEnv = { ...env, CIPHER_BRAIN_PULL_RETRY_MS: '150' };
  const w = spawnSync('node', [...DEV_ARGS, BIN, 'pull', '--locator', 'B'.repeat(43), '--backend', 'arweave', '--out', join(tmp, 'w.age'), '--wait', '1'], { env: wEnv, encoding: 'utf8' });
  (w.status !== 0 && /retrying/.test(w.stderr))
    ? pass('--wait retries while not retrievable, then fails for a truly-missing id')
    : fail(`--wait did not retry as expected: status=${w.status} stderr=${(w.stderr || '').slice(0, 160)}`);

  // multi-gateway (#21): the first gateway is dead, the second (arlocal) serves — the
  // read loop must move past the dead gateway to produce the bytes. AR_PORT=1 dead-ends
  // the L1 chunk fallback so ONLY gateway-2's HTTP read can satisfy this (otherwise the
  // chunk read would mask a loop that never advanced).
  const mgEnv = { ...env, CIPHER_BRAIN_AR_PORT: '1', CIPHER_BRAIN_AR_GATEWAYS: `http://127.0.0.1:1,http://localhost:${PORT}` };
  const mg = spawnSync('node', [...DEV_ARGS, BIN, 'pull', '--locator', loc, '--backend', 'arweave', '--out', join(tmp, 'mg.age')], { env: mgEnv, encoding: 'utf8' });
  (mg.status === 0 && sha(await readFile(join(tmp, 'mg.age'))) === cipherSha)
    ? pass('multi-gateway: read falls through a dead gateway to a live one')
    : fail(`multi-gateway did not serve from the second gateway: ${mg.stderr || 'bytes differ'}`);

  // AGE_MAGIC gate (#29): a gateway that serves a non-ciphertext HTTP 200 (a soft-404
  // page / "tx pending" placeholder / CDN interstitial) must NOT be promoted to --out.
  // (1) bad-200 the ONLY gateway, L1 dead-ended (AR_PORT=1): pull must FAIL and leave
  //     no garbage at --out (the old code wrote the bad body and "succeeded").
  const badGw = createServer((_q, res) => { res.writeHead(200, { 'content-type': 'text/html' }); res.end('<html>tx pending — not ciphertext</html>'); });
  await new Promise((r) => badGw.listen(0, '127.0.0.1', r));
  const badPort = badGw.address().port;
  const bgOut = join(tmp, 'badgate.age');
  const bg = spawnSync('node', [...DEV_ARGS, BIN, 'pull', '--locator', loc, '--backend', 'arweave', '--out', bgOut],
    { env: { ...env, CIPHER_BRAIN_AR_PORT: '1', CIPHER_BRAIN_AR_GATEWAYS: `http://127.0.0.1:${badPort}` }, encoding: 'utf8' });
  let bgWrote = false; try { await readFile(bgOut); bgWrote = true; } catch { /* not written = good */ }
  (bg.status !== 0 && !bgWrote)
    ? pass('AGE_MAGIC gate: a non-ciphertext 200 is not promoted (pull fails, no garbage at --out)')
    : fail(`bad-200 body was promoted to --out (status=${bg.status}, wrote=${bgWrote})`);
  badGw.close();
  // (2) bad-200 first, healthy arlocal second: the read must FALL THROUGH to the good
  //     gateway and produce the real, byte-identical ciphertext.
  const badGw2 = createServer((_q, res) => { res.writeHead(200); res.end('not ciphertext'); });
  await new Promise((r) => badGw2.listen(0, '127.0.0.1', r));
  const badPort2 = badGw2.address().port;
  const ft = spawnSync('node', [...DEV_ARGS, BIN, 'pull', '--locator', loc, '--backend', 'arweave', '--out', join(tmp, 'ft.age')],
    { env: { ...env, CIPHER_BRAIN_AR_PORT: '1', CIPHER_BRAIN_AR_GATEWAYS: `http://127.0.0.1:${badPort2},http://localhost:${PORT}` }, encoding: 'utf8' });
  (ft.status === 0 && sha(await readFile(join(tmp, 'ft.age'))) === cipherSha)
    ? pass('AGE_MAGIC gate: read falls through a non-ciphertext 200 to a healthy gateway')
    : fail(`did not fall through bad-200 to a healthy gateway: ${ft.stderr || 'bytes differ'}`);
  badGw2.close();

  // User-Agent header: arweave.net redirects a bundled-item read to a sandbox subdomain
  // that 403s a header-less request (node:http.get sends no default UA, unlike the fetch
  // this replaced — the real-world full-brain pull regressed silently). A SEPARATE-process
  // stub (spawnSync blocks an in-process server) serves the ciphertext ONLY when a
  // User-Agent is present, 403 otherwise; the pull must succeed → proves cipher-brain
  // sends a UA. (A header-less read would 403 → fail → no bytes.)
  const uaSrvFile = join(tmp, 'ua-stub.mjs');
  await writeFile(uaSrvFile,
    "import {createServer} from 'node:http'; import {readFileSync} from 'node:fs';\n" +
    "const f=process.argv[2];\n" +
    "const s=createServer((q,res)=>{ if(!q.headers['user-agent']){res.writeHead(403);res.end('<html>403</html>');return;} res.writeHead(200);res.end(readFileSync(f)); });\n" +
    "s.listen(0,'127.0.0.1',()=>console.log('READY:'+s.address().port));\n");
  const uaSrv = spawn('node', [uaSrvFile, join(tmp, 'snap.age')], { stdio: ['ignore', 'pipe', 'pipe'] });
  const uaPort = await new Promise((res, rej) => {
    const to = setTimeout(() => rej(new Error('ua stub did not start')), 8000);
    uaSrv.stdout.on('data', (d) => { const m = String(d).match(/READY:(\d+)/); if (m) { clearTimeout(to); res(m[1]); } });
  });
  const ua = spawnSync('node', [...DEV_ARGS, BIN, 'pull', '--locator', loc, '--backend', 'arweave', '--out', join(tmp, 'ua.age')],
    { env: { ...env, CIPHER_BRAIN_AR_PORT: '1', CIPHER_BRAIN_AR_GATEWAYS: `http://127.0.0.1:${uaPort}` }, encoding: 'utf8' });
  (ua.status === 0 && sha(await readFile(join(tmp, 'ua.age'))) === cipherSha)
    ? pass('User-Agent: the gateway read sends a UA (a UA-gated gateway serves the ciphertext)')
    : fail(`gateway read did not send a UA (UA-gated gateway 403'd): status=${ua.status} ${ua.stderr?.slice(0, 160) || 'bytes differ'}`);
  uaSrv.kill('SIGKILL');

  // SSRF guard (#39): a gateway that 302-redirects to an internal/IMDS address must be
  // refused, not transparently followed. The stub runs in a SEPARATE process — the pull
  // below is spawnSync (blocking), so an in-process server could never answer it (the
  // same reason the nodeps mock is out-of-process). The redirect target comes from argv;
  // assert each pull (a) fails, (b) writes no --out, and (c) logs the SSRF refusal — i.e.
  // it never fetched the private/loopback target.
  const ssrfSrvFile = join(tmp, 'ssrf-stub.mjs');
  await writeFile(ssrfSrvFile,
    "import {createServer} from 'node:http';\n" +
    "const target=process.argv[2];\n" +
    "const s=createServer((q,res)=>{res.writeHead(302,{location:target});res.end();});\n" +
    "s.listen(0,'127.0.0.1',()=>console.log('READY:'+s.address().port));\n");
  // Two redirect forms: the dotted IMDS literal, and the canonical HEX-QUAD IPv4-mapped
  // loopback `[::ffff:7f00:1]` (= 127.0.0.1) — the form that bypassed a dotted-only guard.
  const ssrfCases = [
    { target: 'http://169.254.169.254/latest/meta-data/', desc: 'a redirect to a link-local/IMDS address is refused' },
    { target: 'http://[::ffff:7f00:1]/latest/meta-data/', desc: 'a redirect to a hex-quad IPv4-mapped loopback ([::ffff:7f00:1]) is refused' },
  ];
  for (const c of ssrfCases) {
    const ssrfSrv = spawn('node', [ssrfSrvFile, c.target], { stdio: ['ignore', 'pipe', 'pipe'] });
    const ssrfPort = await new Promise((res, rej) => {
      const to = setTimeout(() => rej(new Error('ssrf stub did not start')), 8000);
      ssrfSrv.stdout.on('data', (d) => { const m = String(d).match(/READY:(\d+)/); if (m) { clearTimeout(to); res(m[1]); } });
    });
    const ssrfOut = join(tmp, `ssrf-${ssrfPort}.age`);
    const ss = spawnSync('node', [...DEV_ARGS, BIN, 'pull', '--locator', loc, '--backend', 'arweave', '--out', ssrfOut],
      { env: { ...env, CIPHER_BRAIN_AR_PORT: '1', CIPHER_BRAIN_AR_GATEWAYS: `http://127.0.0.1:${ssrfPort}` }, encoding: 'utf8' });
    let ssrfWrote = false; try { await readFile(ssrfOut); ssrfWrote = true; } catch { /* not written = good */ }
    (ss.status !== 0 && !ssrfWrote && /SSRF guard|private\/loopback\/link-local/.test(ss.stderr))
      ? pass(`SSRF guard: ${c.desc}`)
      : fail(`SSRF redirect not refused (${c.target}; status=${ss.status}, wrote=${ssrfWrote}): ${(ss.stderr || '').slice(0, 200)}`);
    ssrfSrv.kill('SIGKILL');
  }
} catch (e) {
  fail(`exception: ${e.message}`);
} finally {
  await rm(tmp, { recursive: true, force: true });
  arproc.kill('SIGTERM');
}

console.log('');
if (failed) { console.log('ARWEAVE ROUND-TRIP: FAIL'); process.exit(1); }
console.log('ARWEAVE ROUND-TRIP: PASS (abstraction holds for a post-assigned tx-id locator)');
