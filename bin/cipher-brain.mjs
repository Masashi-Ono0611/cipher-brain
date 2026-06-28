#!/usr/bin/env node
// cipher-brain — encrypt a gbrain snapshot so only the key holder can read it.
//
// Threat model: the always-on machine (e.g. the Mac mini that runs gbrain) holds
// ONLY the recipient PUBLIC key, so it can produce snapshots but can never read
// them. The private identity — the "key only mine" — lives off the always-on box
// and is the sole thing that can restore. Compromising the snapshotting machine
// therefore leaks no brain content.
//
// Crypto: age (X25519 + ChaCha20-Poly1305) via the audited `age` binary. Each
// component (the pg_dump, each directory archive) is staged into a private (0700)
// temp dir, then the bundle is streamed `tar -> age` so the final ciphertext never
// loads into memory. The staged plaintext is erased on a normal failure (the
// snapshot finally-block) AND on Ctrl-C / SIGTERM / SIGHUP (a signal handler that
// rmSync's the active stage dir, since a signal tears the process down without
// unwinding the finally), so it doesn't linger. Staging needs scratch space ~the
// size of the snapshot, so point TMPDIR at a disk with room for large brains.
//
// Backend-agnostic: this produces ONE encrypted artifact (`*.age`). Where those
// bytes get parked (TON Storage / Arweave / anything) is a separate, pluggable
// concern — storage only ever sees ciphertext.

import { spawn } from 'node:child_process';
import { mkdir, writeFile, rm, chmod, access, stat, readFile, mkdtemp, copyFile, readdir, rename, link } from 'node:fs/promises';
import { createReadStream, createWriteStream, constants as FS, rmSync, mkdtempSync } from 'node:fs';
import { pipeline } from 'node:stream/promises';
import { Transform } from 'node:stream';
import { homedir, hostname, tmpdir } from 'node:os';
import { join, basename, dirname, resolve } from 'node:path';
import { createHash, randomBytes } from 'node:crypto';
import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';
import http from 'node:http';
import https from 'node:https';

const HOME = process.env.CIPHER_BRAIN_HOME || join(homedir(), '.cipher-brain');
const AGE = process.env.CIPHER_BRAIN_AGE || 'age';
const AGE_KEYGEN = process.env.CIPHER_BRAIN_AGE_KEYGEN || 'age-keygen';
const PG_BIN = process.env.CIPHER_BRAIN_PG_BIN || ''; // dir holding pg_dump/pg_restore; '' => PATH
const pgTool = (name) => (PG_BIN ? join(PG_BIN, name) : name);

const IDENTITY = join(HOME, 'identity.age');     // private key — required to restore
const RECIPIENT = join(HOME, 'recipient.txt');   // public key — all snapshot needs

const AGE_MAGIC = 'age-encryption.org/v1';

// Optional recipient allowlist. When set, snapshot refuses to encrypt unless EVERY
// effective recipient is on this list — so a tampered recipient.txt / an injected
// extra --recipient (which would silently re-key future snapshots to an attacker)
// is caught at the input, before any ciphertext is produced. Inline (space/comma/
// newline-separated age1… keys) OR a path to a file of them.
const PIN_RECIPIENTS = process.env.CIPHER_BRAIN_PIN_RECIPIENTS || '';
const AGE_PUBKEY_RE = /age1[0-9a-z]{50,63}/g; // an age X25519 recipient (age1 + bech32); bounded so two unseparated keys can't fuse

// ---------- storage backend config (pluggable: storage only ever sees ciphertext) ----------
const FILE_DIR = process.env.CIPHER_BRAIN_FILE_DIR || join(HOME, 'store'); // file backend object store
const TON_CLI = process.env.CIPHER_BRAIN_TON_CLI || 'storage-daemon-cli';
const TON_API = process.env.CIPHER_BRAIN_TON_API || '127.0.0.1:15555';     // storage-daemon control addr
const TON_CLIENT = process.env.CIPHER_BRAIN_TON_CLIENT || '';              // storage-daemon-cli -k <client key>
const TON_SERVER = process.env.CIPHER_BRAIN_TON_SERVER || '';              // storage-daemon-cli -p <server.pub>
const TON_TIMEOUT_S = Number(process.env.CIPHER_BRAIN_TON_TIMEOUT || 300); // pull: wait this long for download
const AR_HOST = process.env.CIPHER_BRAIN_AR_HOST || 'arweave.net';
const AR_PORT = Number(process.env.CIPHER_BRAIN_AR_PORT || 443);
const AR_PROTOCOL = process.env.CIPHER_BRAIN_AR_PROTOCOL || 'https';
const AR_WALLET = process.env.CIPHER_BRAIN_AR_WALLET || ''; // path to a JWK key file
const AR_PAID_BY = process.env.CIPHER_BRAIN_AR_PAID_BY || ''; // optional (turbo): an address that shared (delegated) Turbo Credits to the signer — passed as `paidBy` so the upload draws from that approval before the signer's own balance (the path for credits bought on a wallet we can't sign with, e.g. MetaMask, then shared to this JWK)
const AR_DEFAULT_EXTRA_GATEWAYS = ['https://permagate.io']; // public mirror(s) tried after the primary (override the whole list with CIPHER_BRAIN_AR_GATEWAYS)
const AR_HTTP_TIMEOUT_MS = Number(process.env.CIPHER_BRAIN_AR_HTTP_TIMEOUT || 60000); // bound the gateway read so a stall falls through to the L1 chunk fallback
// Spend guard: arweave/turbo uploads are irreversible and cost real funds. Require an
// explicit opt-in so an unattended nightly loop doesn't silently accumulate charges.
//   CIPHER_BRAIN_YES=1  — set in the cadence script to suppress the --yes prompt
//   CIPHER_BRAIN_MAX_SPEND — abort if the upload cost estimate (in the backend's native
//     unit: winston for arweave L1, winc for turbo) exceeds this value; 0/unset = no cap
//     (the --yes guard still fires). Prevents runaway spend without changing behaviour
//     when the upload is well under budget.
const CIPHER_YES = !!process.env.CIPHER_BRAIN_YES;
const AR_MAX_SPEND = process.env.CIPHER_BRAIN_MAX_SPEND ? BigInt(process.env.CIPHER_BRAIN_MAX_SPEND) : 0n;
// The raw `arweave` backend posts one inline L1 tx; gateways reject single-tx bodies
// past ~12 MiB. Guard at a conservative 10 MiB and redirect large uploads to `turbo`
// (which streams + ANS-104-bundles). Override for a deliberate large L1 post.
const AR_L1_MAX_BYTES = Number(process.env.CIPHER_BRAIN_AR_L1_MAX || 10 * 1024 * 1024);
// Overall wall-clock cap for the tar|age / age|tar streaming pipelines and the pre-stage
// tar, so a wedged binary (or a FIFO/special file under --dir) can't hang the CLI forever.
// Generous default (1h) — a real ~850 MB brain streams in seconds, so this only ever trips
// on a genuine hang. Override with CIPHER_BRAIN_PIPE_TIMEOUT (ms) for very large brains.
const PIPE_TIMEOUT_MS = Number(process.env.CIPHER_BRAIN_PIPE_TIMEOUT || 60 * 60 * 1000);

// ---------- small process helpers (array args only — no shell, no injection) ----------

// Every spawned child registers here while running, so the signal handler can SIGKILL
// them BEFORE it rmSync's the stage / .part — otherwise a signal delivered to node
// alone (e.g. launchd stopping the service, or `kill <pid>`) leaves the children alive
// to re-create the very files the handler just removed (a still-writing age would
// re-make ${out}.part after we unlinked it). See installStageSignalGuard().
const ACTIVE_CHILDREN = new Set();

function run(cmd, args, { input, timeoutMs } = {}) {
  return new Promise((res, rej) => {
    const p = spawn(cmd, args, { stdio: [input ? 'pipe' : 'ignore', 'pipe', 'pipe'] });
    ACTIVE_CHILDREN.add(p);
    const doneChild = () => ACTIVE_CHILDREN.delete(p);
    let out = '', err = '', timer;
    if (timeoutMs) {
      // a stuck child (e.g. a storage-daemon-cli call that never returns) must not
      // hang us forever — kill it and reject so callers can bound their own loops.
      timer = setTimeout(() => { p.kill('SIGKILL'); rej(new Error(`${cmd} timed out after ${timeoutMs}ms`)); }, timeoutMs);
    }
    p.stdout.on('data', (d) => (out += d));
    p.stderr.on('data', (d) => (err += d));
    p.on('error', (e) => { clearTimeout(timer); doneChild(); rej(e); });
    p.on('close', (code) => {
      clearTimeout(timer); doneChild();
      code === 0 ? res({ out, err }) : rej(new Error(`${cmd} exited ${code}: ${err.trim() || out.trim()}`));
    });
    if (input) { p.stdin.write(input); p.stdin.end(); }
  });
}

// Pipe producer.stdout -> consumer.stdin and wait for both. Used for the
// tar|age (snapshot) and age|tar (restore) streaming pipelines. `timeoutMs` bounds the
// WHOLE pipeline (like run()'s per-child timeout) so a wedged age/tar can't hang the CLI
// forever; on failure children are SIGTERM'd then SIGKILL'd ~2s later so a SIGTERM-ignoring
// child can't linger after the promise rejects.
function pipe2(prodCmd, prodArgs, consCmd, consArgs, { consStdout = 'inherit', timeoutMs } = {}) {
  return new Promise((res, rej) => {
    const prod = spawn(prodCmd, prodArgs, { stdio: ['ignore', 'pipe', 'pipe'] });
    const cons = spawn(consCmd, consArgs, { stdio: ['pipe', consStdout, 'pipe'] });
    ACTIVE_CHILDREN.add(prod); ACTIVE_CHILDREN.add(cons);
    const doneChildren = () => { ACTIVE_CHILDREN.delete(prod); ACTIVE_CHILDREN.delete(cons); };
    let pErr = '', cErr = '', left = 2, settled = false, timer, killTimer;
    const stopTimers = () => { clearTimeout(timer); clearTimeout(killTimer); };
    const fail = (e) => {
      if (settled) return;
      settled = true;
      stopTimers();
      doneChildren();
      prod.kill('SIGTERM'); cons.kill('SIGTERM'); // ask the survivor (or still-decrypting child) to stop
      // escalate: a child that ignores SIGTERM must not linger holding plaintext open.
      killTimer = setTimeout(() => { try { prod.kill('SIGKILL'); } catch {} try { cons.kill('SIGKILL'); } catch {} }, 2000);
      killTimer.unref?.(); // don't keep the event loop alive just for the escalation
      rej(e);
    };
    const ok = () => { if (settled) return; if (--left === 0) { settled = true; stopTimers(); doneChildren(); res(); } };
    if (timeoutMs) {
      timer = setTimeout(() => fail(new Error(`${prodCmd}|${consCmd} pipeline timed out after ${timeoutMs}ms`)), timeoutMs);
    }
    prod.stderr.on('data', (d) => (pErr += d));
    cons.stderr.on('data', (d) => (cErr += d));
    prod.on('error', fail);
    cons.on('error', fail);
    // If the consumer dies early, writing to its closed stdin emits EPIPE as an
    // async 'error' event — swallow it on the pipe ends so the real failure
    // surfaces via the close handler (a clean reject) instead of an uncaught crash
    // that would skip snapshot's finally-block and leave staged plaintext behind.
    prod.stdout.on('error', () => {});
    cons.stdin.on('error', () => {});
    prod.stdout.pipe(cons.stdin);
    prod.on('close', (c) => (c === 0 ? ok() : fail(new Error(`${prodCmd} exited ${c}: ${pErr.trim()}`))));
    cons.on('close', (c) => (c === 0 ? ok() : fail(new Error(`${consCmd} exited ${c}: ${cErr.trim()}`))));
  });
}

const exists = (p) => access(p, FS.F_OK).then(() => true).catch(() => false);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Warn (don't refuse) if a secret-bearing key file is group/other-accessible. The age
// identity is created 0600; an Arweave JWK is a spend-capable bearer credential (a Turbo
// Credit Share Approval is granted TO its address) yet may be dropped in with loose modes.
// We warn rather than hard-fail so an unusual-but-intentional setup still works.
async function warnIfLooseKeyPerms(path, what) {
  try {
    const { mode } = await stat(path);
    if (mode & 0o077) {
      process.stderr.write(`⚠  ${what} at ${path} is group/other-accessible (mode ${(mode & 0o777).toString(8)}); chmod 600 it — it is a secret.\n`);
    }
  } catch { /* unreadable / missing perms info — the caller's own read will surface real errors */ }
}

function sha256(file) {
  return new Promise((res, rej) => {
    const h = createHash('sha256');
    createReadStream(file).on('data', (d) => h.update(d)).on('end', () => res(h.digest('hex'))).on('error', rej);
  });
}

// ---------- storage backends ----------
// A StorageBackend is { put(file) -> locator, get(locator, outFile) }. Storage
// only ever sees the *.age ciphertext. The locator is whatever the backend
// assigns: a content hash for file/ton (known before upload), or a tx id for
// arweave (assigned AFTER upload) — the interface assumes neither.
async function backendFor(name) {
  if (name === 'file') return fileBackend();
  if (name === 'ton') return tonBackend();
  if (name === 'arweave') return arweaveBackend();
  if (name === 'turbo') return turboBackend();
  throw new Error(`unknown backend: ${name || '(none)'} — use --backend file|ton|arweave|turbo`);
}

// file backend: a local content-addressed store. Needs no daemon and no network,
// so CI can exercise push/pull end-to-end. locator = <FILE_DIR>/<sha256>.age
function fileBackend() {
  return {
    async put(file, _opts = {}) {
      await mkdir(FILE_DIR, { recursive: true });
      const locator = join(FILE_DIR, `${await sha256(file)}.age`);
      await copyFile(file, locator);
      return locator;
    },
    async get(locator, out) {
      if (!(await exists(locator))) throw new Error(`file backend: no object at ${locator}`);
      await mkdir(dirname(resolve(out)), { recursive: true });
      await copyFile(locator, out);
    },
  };
}

// ton backend: shells out to the official storage-daemon-cli. locator = hex BagID
// (a content fingerprint). The CLI takes ONE command string via -c, so the file
// path must be space-free (our temp paths are).
function tonArgs(cmd) {
  if (!TON_CLIENT || !TON_SERVER) {
    throw new Error('ton backend needs CIPHER_BRAIN_TON_CLIENT and CIPHER_BRAIN_TON_SERVER (storage-daemon-cli key paths)');
  }
  return ['-I', TON_API, '-k', TON_CLIENT, '-p', TON_SERVER, '-c', cmd];
}

// add-by-hash wants the hex BagID. In --json that is NOT the base64 `hash` field —
// the hex appears in the root_dir path. Prefer that; else decode base64 hash; else
// any bare 64-hex. (Confirmed against a real storage-daemon --json blob.)
function parseBagId(s) {
  let m = s.match(/torrent-files\/([0-9A-Fa-f]{64})/);
  if (m) return m[1].toUpperCase();
  try {
    const j = JSON.parse(s);
    const h = j.hash || (j.torrent && j.torrent.hash) || j.bag_id;
    if (h && /^[0-9A-Fa-f]{64}$/.test(h)) return h.toUpperCase();
    if (h && /^[A-Za-z0-9+/]+={0,2}$/.test(h)) {
      const buf = Buffer.from(h, 'base64');
      if (buf.length === 32) return buf.toString('hex').toUpperCase(); // a BagID is a 32-byte hash
    }
  } catch { /* not json, fall through */ }
  m = s.match(/\b[0-9A-Fa-f]{64}\b/);
  if (m) return m[0].toUpperCase();
  throw new Error(`could not parse BagID from: ${s.trim().slice(0, 200)}`);
}

// confirmed against a real `get --json`: the torrent block carries "completed": true
function bagComplete(s) {
  try {
    const j = JSON.parse(s);
    return (j.torrent || j).completed === true;
  } catch { /* not json */ }
  return /"completed"\s*:\s*true/.test(s);
}

// the daemon's -c is ONE space-delimited command string (not a shell), so any path
// embedded in it must be whitespace-free — quoting wouldn't help.
function assertNoSpace(p, what) {
  if (/\s/.test(p)) throw new Error(`ton backend: ${what} must not contain whitespace: ${p}`);
}

function tonBackend() {
  return {
    async put(file, _opts = {}) {
      assertNoSpace(file, 'file path');
      const { out } = await run(TON_CLI, tonArgs(`create --copy --json ${file}`));
      return parseBagId(out);
    },
    async get(locator, out) {
      assertNoSpace(locator, 'locator');
      const base = tmpdir();
      assertNoSpace(base, 'TMPDIR (point it at a space-free path for the ton backend)');
      const tmp = await mkdtemp(join(base, 'cipher-brain-pull-'));
      try {
        await run(TON_CLI, tonArgs(`add-by-hash ${locator} -d ${tmp} --json`), { timeoutMs: 30000 });
        const deadline = Date.now() + TON_TIMEOUT_S * 1000;
        for (;;) {
          // bound EACH poll: a hung `get` must not defeat the deadline below
          let g = '';
          try { ({ out: g } = await run(TON_CLI, tonArgs(`get ${locator} --json`), { timeoutMs: 15000 })); } catch { /* treat as not-yet-complete */ }
          if (bagComplete(g)) break;
          if (Date.now() > deadline) throw new Error(`ton backend: download of ${locator} did not complete in ${TON_TIMEOUT_S}s`);
          await sleep(3000);
        }
        const entries = await readdir(tmp, { recursive: true, withFileTypes: true });
        const files = entries.filter((d) => d.isFile()).map((d) => join(d.parentPath || tmp, d.name));
        if (files.length !== 1) throw new Error(`ton backend: expected 1 file in bag, got ${files.length}`);
        await mkdir(dirname(resolve(out)), { recursive: true });
        await copyFile(files[0], out);
      } finally {
        await rm(tmp, { recursive: true, force: true }); // don't leak the downloaded ciphertext
      }
    },
  };
}

// The public gateways to try (in order) for the HTTP read, before the L1 chunk
// fallback (#21). Override the whole list with CIPHER_BRAIN_AR_GATEWAYS (comma-
// separated), or pin a single one with CIPHER_BRAIN_AR_GATEWAY; otherwise the derived
// host (CIPHER_BRAIN_AR_HOST/PORT/PROTOCOL — arweave.net, or arlocal in tests) is tried
// first, then the extra public mirrors.
function arGateways() {
  if (process.env.CIPHER_BRAIN_AR_GATEWAYS) {
    const list = process.env.CIPHER_BRAIN_AR_GATEWAYS.split(',').map((s) => s.trim()).filter(Boolean);
    if (list.length) return list; // ignore an all-blank override → fall through to the default
  }
  if (process.env.CIPHER_BRAIN_AR_GATEWAY) return [process.env.CIPHER_BRAIN_AR_GATEWAY];
  // the derived host first, plus the public mirrors ONLY when the host is the default
  // arweave.net — a custom CIPHER_BRAIN_AR_HOST must not silently egress to them.
  const derived = `${AR_PROTOCOL}://${AR_HOST}:${AR_PORT}`;
  return [derived, ...(AR_HOST === 'arweave.net' ? AR_DEFAULT_EXTRA_GATEWAYS : [])];
}

// SSRF guard for redirect targets (#13/#39). A loopback / link-local / private address
// must never be the target of a gateway redirect — otherwise a compromised public mirror
// could 3xx a public-IP host into GETting an internal/IMDS endpoint (169.254.169.254,
// RFC1918, ::1). IPv4 + IPv6 (incl. IPv4-mapped). The INITIAL gateway URL is operator-
// configured and trusted (it may legitimately be 127.0.0.1 in tests); only redirect
// TARGETS — attacker-controlled — are screened here.
function isPrivateAddr(ip) {
  if (isIP(ip) === 4) {
    const [a, b] = ip.split('.').map(Number);
    if (a === 0 || a === 127 || a === 10) return true;            // this-host / loopback / private
    if (a === 169 && b === 254) return true;                      // link-local (AWS/GCP IMDS)
    if (a === 172 && b >= 16 && b <= 31) return true;             // private
    if (a === 192 && b === 168) return true;                      // private
    if (a === 100 && b >= 64 && b <= 127) return true;            // CGNAT (RFC 6598) — carrier/cloud internal
    if (a >= 224) return true;                                    // multicast / reserved
    return false;
  }
  const low = ip.toLowerCase().replace(/^\[|\]$/g, '');
  if (low === '::1' || low === '::') return true;                 // loopback / unspecified
  if (/^fe[89ab]/.test(low)) return true;                         // link-local fe80::/10 (fe80–febf)
  if (low.startsWith('fc') || low.startsWith('fd')) return true;  // unique-local
  // IPv4-mapped ::ffff:a.b.c.d — dotted form, OR the canonical hex-quad form
  // ::ffff:7f00:1 (which isIP() reports as v6, so it must be normalised here or a
  // hex-encoded loopback/IMDS literal would slip past the v4 checks above).
  const mDot = low.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mDot) return isPrivateAddr(mDot[1]);
  const mHex = low.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
  if (mHex) {
    const n = ((parseInt(mHex[1], 16) << 16) | parseInt(mHex[2], 16)) >>> 0;
    return isPrivateAddr([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff].join('.'));
  }
  return false;
}

// Reject a redirect target that is non-http(s) or resolves to a private/loopback/
// link-local address. Throws on refusal. On success returns the SCREENED address +
// family so the caller can PIN the connection to exactly the vetted IP — closing the
// DNS-rebinding TOCTOU where a low-TTL host returns a public IP for this check and a
// private one for the actual connect.
async function assertPublicRedirectTarget(u) {
  const parsed = new URL(u);
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error(`refusing non-http(s) redirect to ${u}`);
  }
  const host = parsed.hostname.replace(/^\[|\]$/g, '');
  const fam = isIP(host);
  const addrs = fam ? [{ address: host, family: fam }] : await lookup(host, { all: true });
  for (const { address } of addrs) {
    if (isPrivateAddr(address)) {
      throw new Error(`redirect to ${parsed.hostname} resolves to a private/loopback/link-local address (${address})`);
    }
  }
  return { address: addrs[0].address, family: addrs[0].family || isIP(addrs[0].address) };
}

// One GET over node:http(s), resolving with the IncomingMessage so the caller can read
// statusCode/headers AND stream the body. We use node:http instead of fetch because the
// Fetch standard's `redirect:'manual'` returns an opaque response (status 0, no Location),
// so manual SSRF-screened redirect following (#39) is impossible with fetch.
// `pin` (optional) is a {address, family} from assertPublicRedirectTarget: when set, the
// connection is pinned to that exact IP via a custom lookup, so the bytes come from the
// SAME address we screened (no DNS-rebinding between the check and the connect). The URL's
// hostname still drives the Host header / TLS SNI, so cert validation is unaffected.
function gatewayGet(url, signal, pin) {
  return new Promise((res, rej) => {
    const lib = url.startsWith('https:') ? https : http;
    // autoSelectFamily: match fetch/undici's happy-eyeballs so a dual-stack host
    // (e.g. `localhost` → ::1 then 127.0.0.1) connects to whichever family answers,
    // instead of failing on the first AAAA when the server is IPv4-only.
    const opts = { signal, autoSelectFamily: true };
    if (pin) opts.lookup = (_h, lopts, cb) => (lopts && lopts.all ? cb(null, [{ address: pin.address, family: pin.family }]) : cb(null, pin.address, pin.family));
    const req = lib.get(url, opts, (resp) => res(resp));
    req.on('error', rej);
  });
}

// Stream an Arweave gateway GET to `part`; resolve true iff it produced a non-empty
// file (the caller then promotes it to `out`). A STALL timeout (reset per chunk) bounds
// a stalled gateway WITHOUT capping a large but progressing transfer (#17). Accept ONLY
// HTTP 200 (a 202 "pending" / soft-404 means "not here, try the next gateway"). Redirects
// are followed MANUALLY (#39) so each hop's target is SSRF-screened before we fetch it.
async function streamArweaveGateway(url, part, timeoutMs) {
  const ctl = new AbortController();
  let stall;
  const arm = () => { clearTimeout(stall); stall = setTimeout(() => ctl.abort(), timeoutMs); };
  try {
    let current = url;
    let pin = null; // {address, family} screened for the NEXT request — pins out DNS-rebinding
    let resp;
    for (let hop = 0; ; hop++) {
      arm();
      resp = await gatewayGet(current, ctl.signal, pin);
      const sc = resp.statusCode;
      if (sc >= 300 && sc < 400 && resp.headers.location) {
        resp.resume(); // drain & discard the redirect body so the socket frees
        if (hop >= 3) { console.error(`arweave: too many redirects from ${url} — skipping gateway`); clearTimeout(stall); await rm(part, { force: true }); return false; }
        const next = new URL(resp.headers.location, current).href;
        try { pin = await assertPublicRedirectTarget(next); }
        catch (e) { console.error(`arweave: ${e.message} — refusing redirect, skipping gateway (SSRF guard)`); clearTimeout(stall); await rm(part, { force: true }); return false; }
        current = next;
        continue;
      }
      break; // not a redirect (or a 3xx with no Location) → handle the response below
    }
    if (resp.statusCode === 200) {
      const tap = new Transform({ transform(c, _e, cb) { arm(); cb(null, c); } }); // each chunk resets the stall deadline
      await pipeline(resp, tap, createWriteStream(part));
      clearTimeout(stall);
      // Accept the body only if it is actually age ciphertext (every stored object
      // is — push enforces the same header). A gateway that serves a non-ciphertext
      // HTTP 200 (a soft-404 page, a "tx pending" placeholder, a CDN interstitial)
      // must NOT be promoted: returning false here falls through to the next gateway,
      // then the L1 chunk read, then the retryable error that drives `pull --wait`,
      // instead of writing garbage to --out during the propagation window.
      if ((await stat(part)).size > 0 && (await readHead(part, 64)).startsWith(AGE_MAGIC)) return true;
    } else {
      resp.resume(); // drain a non-200 (202 pending / 404) so the socket frees
    }
  } catch { /* stall / network / mid-stream error — try the next gateway */ }
  finally { clearTimeout(stall); }
  await rm(part, { force: true });
  return false;
}

// arweave backend: stores the ciphertext as an Arweave transaction. The locator is
// the tx id — assigned AFTER upload, NOT a content hash — which is exactly the case
// the StorageBackend interface must handle (vs file/ton's pre-known content ids).
// The `arweave` SDK is imported LAZILY and only where it is actually needed — uploads
// (put) and the rare L1 chunk fallback. The primary READ path (gateway HTTP, path 1
// below) is pure native fetch, so a fresh machine recovers a bundled/Turbo brain from
// just the tx id with NO npm dependency — keeping the documented "tx id is all you need"
// recovery true (a missing `arweave` install no longer fails a gateway pull at construction).
async function arweaveBackend() {
  let _ar;
  const getAr = async () => {
    if (_ar) return _ar;
    let Arweave;
    try { Arweave = (await import('arweave')).default; }
    catch (e) {
      if (e && e.code === 'ERR_MODULE_NOT_FOUND') { const err = new Error('arweave backend needs the `arweave` package — run: npm install arweave'); err.sdkMissing = true; throw err; }
      throw e;
    }
    _ar = Arweave.init({ host: AR_HOST, port: AR_PORT, protocol: AR_PROTOCOL });
    return _ar;
  };
  const loadWallet = async () => {
    if (!AR_WALLET) throw new Error('arweave put needs CIPHER_BRAIN_AR_WALLET (path to a JWK key file)');
    await warnIfLooseKeyPerms(AR_WALLET, 'arweave JWK wallet');
    try { return JSON.parse(await readFile(AR_WALLET, 'utf8')); }
    catch (e) { throw new Error(`arweave: cannot read JWK wallet at ${AR_WALLET}: ${e.message}`); }
  };
  return {
    async put(file, _opts = {}) {
      // Fast size guard BEFORE buffering: the raw arweave backend posts the whole
      // artifact inline in ONE signed tx, and gateways reject single-tx bodies past
      // ~12 MiB — a brain-sized snapshot would buffer the lot and then fail with a bare
      // "HTTP 400". Redirect to the turbo backend (streams + ANS-104 bundles) instead.
      const { size: l1Size } = await stat(resolve(file));
      if (l1Size > AR_L1_MAX_BYTES) {
        throw new Error(`arweave: ${l1Size} bytes exceeds the ~${(AR_L1_MAX_BYTES / 1048576).toFixed(0)} MiB single-tx limit of the raw arweave backend — use --backend turbo (it streams + bundles large uploads). Override the limit with CIPHER_BRAIN_AR_L1_MAX if you really mean to post one large L1 tx.`);
      }
      const ar = await getAr(); // uploads genuinely need the SDK (createTransaction/sign/post)
      const jwk = await loadWallet(); // only uploads need a wallet/signature
      const data = await readFile(file); // small ciphertext fits one tx (guarded above); large blobs go via --backend turbo
      // inform before signing — the --yes guard in push() already confirmed intent;
      // this surfaces the size so the operator knows what they're committing to.
      // (ar.createTransaction fetches the network price internally when no reward is
      // preset, so we avoid a redundant pre-flight /price call here.)
      process.stderr.write(`arweave: L1 upload — ${data.length} bytes, wallet ${AR_WALLET}\n`);
      if (AR_MAX_SPEND > 0n) {
        process.stderr.write(`arweave: CIPHER_BRAIN_MAX_SPEND=${AR_MAX_SPEND} set — cannot pre-flight L1 cost without an extra network round-trip; the actual reward is set by createTransaction\n`);
      }
      const tx = await ar.createTransaction({ data }, jwk);
      tx.addTag('App-Name', 'cipher-brain');
      tx.addTag('Content-Type', 'application/octet-stream');
      await ar.transactions.sign(tx, jwk);
      const res = await ar.transactions.post(tx);
      if (res.status !== 200 && res.status !== 208) throw new Error(`arweave post failed: HTTP ${res.status}`);
      return tx.id; // 43-char base64url tx id
    },
    async get(locator, out) {
      // reads are unauthenticated — a fresh machine needs only the tx id, no wallet.
      // The locator is interpolated into a gateway URL below, so validate it is a
      // clean Arweave tx id first (this also closes a path-traversal/SSRF foot-gun).
      if (!/^[A-Za-z0-9_-]{43}$/.test(locator)) {
        throw new Error(`arweave: invalid tx id (expected 43-char base64url): ${locator}`);
      }
      await mkdir(dirname(resolve(out)), { recursive: true });
      const part = `${out}.part`;
      // 1) try each public gateway's HTTP endpoint in turn (#21). It serves ANS-104
      //    *bundled* data items (Turbo/Irys — the pay-with-ETH/USDC path), which the
      //    chunk read below cannot fetch. The body is STREAMED to disk (#17), so a
      //    multi-hundred-MB brain never loads into memory; .part is promoted only on a
      //    clean, non-empty download that is actually age ciphertext — a 202 / soft-404
      //    / non-ciphertext 200 error page is rejected by streamArweaveGateway's
      //    AGE_MAGIC check and falls through to the next gateway (then the chunk read).
      for (const gw of arGateways()) {
        if (await streamArweaveGateway(`${gw.replace(/\/+$/, '')}/${locator}`, part, AR_HTTP_TIMEOUT_MS)) {
          await rename(part, out);
          return;
        }
      }
      // 2) arweave-js chunk read — robust for L1 txs even when every gateway HTTP front
      //    is flaky (they can 5xx for L1 ids whose chunks the node still serves). This
      //    buffers in arweave-js, but it is the rare L1 fallback; a bundled brain takes
      //    the streamed path above. Needs the SDK: if `arweave` isn't installed, SKIP
      //    this fallback (the gateway path serves bundled items anyway) and let the
      //    retryable error below keep `--wait` polling — so a no-SDK machine still pulls.
      let ar = null;
      try { ar = await getAr(); } catch (e) { if (!e.sdkMissing) throw e; /* no SDK → skip L1 fallback */ }
      if (ar) {
        let d = null;
        try { d = await ar.transactions.getData(locator, { decode: true }); } catch { /* not found / chunk error → not (yet) available */ }
        if (d && d.length) { await writeFile(out, Buffer.from(d)); return; }
      }
      // a fresh upload may simply be propagating — mark this retryable so `pull --wait`
      // keeps trying (fatal errors like an invalid locator are NOT tagged, so they
      // fail fast even under --wait).
      const err = new Error(`arweave: no data for tx ${locator} (not mined / not found / not yet seeded)`);
      err.retryable = true;
      throw err;
    },
  };
}

// turbo backend: upload ciphertext to Arweave via a bundler (ar.io / ArDrive Turbo),
// payable with ETH/USDC — uploads <100KB are free, larger spend Turbo Credits funded to
// the signer's address (top up at app.ardrive.io with MetaMask, no key export). The data
// item is ANS-104 *bundled*, so reads reuse the arweave backend (multi-gateway, bundled-
// capable). @ardrive/turbo-sdk is heavy, so it is lazily imported ONLY when this backend
// is used (run `npm install @ardrive/turbo-sdk`).
function turboBackend() {
  return {
    async put(file, _opts = {}) {
      // import + wallet load live HERE (not the constructor) so a turbo PULL needs
      // neither @ardrive/turbo-sdk nor a wallet — only an upload does.
      let TurboFactory, ArweaveSigner;
      try { ({ TurboFactory, ArweaveSigner } = await import('@ardrive/turbo-sdk')); }
      catch (e) {
        if (e && e.code === 'ERR_MODULE_NOT_FOUND') throw new Error('turbo backend needs the `@ardrive/turbo-sdk` package — run: npm install @ardrive/turbo-sdk');
        throw e;
      }
      if (!AR_WALLET) throw new Error('turbo put needs CIPHER_BRAIN_AR_WALLET (a JWK signer; uploads <100KB are free, larger spend Turbo Credits funded to its address)');
      await warnIfLooseKeyPerms(AR_WALLET, 'turbo JWK wallet (spend-capable bearer key)');
      let jwk;
      try { jwk = JSON.parse(await readFile(AR_WALLET, 'utf8')); }
      catch (e) { throw new Error(`turbo: cannot read JWK wallet at ${AR_WALLET}: ${e.message}`); }
      const turbo = TurboFactory.authenticated({ signer: new ArweaveSigner(jwk) });
      const abs = resolve(file);
      const { size } = await stat(abs); // stream the file (don't buffer an ~850MB brain) and give Turbo its size
      // cost estimate + balance before committing to an irreversible spend.
      // Uploads <100KB are free (0 winc); larger ones draw from Turbo Credits.
      try {
        const [{ winc: uploadWincStr }] = await turbo.getUploadCosts({ bytes: [size] });
        const uploadWinc = BigInt(uploadWincStr);
        process.stderr.write(`turbo: upload cost estimate: ${uploadWinc} winc (~${(Number(uploadWinc) / 1e12).toFixed(8)} AR, ${size} bytes)\n`);
        try {
          const { winc: balWincStr } = await turbo.getBalance();
          const balWinc = BigInt(balWincStr);
          process.stderr.write(`turbo: Turbo Credit balance: ${balWinc} winc (~${(Number(balWinc) / 1e12).toFixed(8)} AR)\n`);
        } catch { /* paidBy wallet has no personal balance on this signer — non-fatal */ }
        if (AR_MAX_SPEND > 0n && uploadWinc > AR_MAX_SPEND) {
          throw new Error(`turbo: upload cost ${uploadWinc} winc exceeds CIPHER_BRAIN_MAX_SPEND=${AR_MAX_SPEND} — aborting to protect your wallet`);
        }
      } catch (e) {
        if (e.message && e.message.startsWith('turbo: upload cost')) throw e; // re-raise the cap guard
        process.stderr.write(`turbo: could not estimate upload cost (${e.message}); proceeding\n`);
      }
      // paidBy (x-paid-by header): when set, Turbo pays from a Credit Share Approval the
      // named address granted THIS signer, before the signer's own balance. It funds the
      // CLI path when credits were bought on a wallet we can't sign with (e.g. MetaMask)
      // and shared to this JWK. Not URL-interpolated (header only), but sanity-check the
      // shape (Arweave/Ethereum/Solana address) to reject header-breaking input.
      const dataItemOpts = { tags: [{ name: 'App-Name', value: 'cipher-brain' }, { name: 'Content-Type', value: 'application/octet-stream' }] };
      if (AR_PAID_BY) {
        if (!/^[A-Za-z0-9_-]{30,64}$/.test(AR_PAID_BY)) throw new Error(`turbo: CIPHER_BRAIN_AR_PAID_BY must be a plain wallet address (Arweave/Ethereum/Solana): ${AR_PAID_BY}`);
        dataItemOpts.paidBy = [AR_PAID_BY];
      }
      const res = await turbo.uploadFile({
        fileStreamFactory: () => createReadStream(abs),
        fileSizeFactory: () => size,
        dataItemOpts,
      });
      if (!res || !res.id) throw new Error(`turbo upload returned no data item id: ${JSON.stringify(res).slice(0, 200)}`);
      return res.id; // 43-char data item id — retrievable like any bundled item
    },
    // reads are identical to the arweave backend (Turbo items are bundled). Pure
    // delegation, so a turbo PULL needs neither @ardrive/turbo-sdk nor a wallet —
    // the "a fresh machine needs only the tx id" recovery property holds.
    get(locator, out) {
      return arweaveBackend().then((b) => b.get(locator, out));
    },
  };
}

const BOOL_FLAGS = new Set(['force', 'passphrase', 'yes']); // flags that take no value

function parseArgs(argv) {
  const o = { dirs: [], tables: [], recipients: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--dir') o.dirs.push(argv[++i]);
    else if (a === '--pg-table') o.tables.push(argv[++i]);
    else if (a === '--recipient') o.recipients.push(argv[++i]); // repeatable: key recovery
    else if (a.startsWith('--')) {
      const key = a.slice(2).replace(/-/g, '_');
      o[key] = BOOL_FLAGS.has(key) ? true : argv[++i];
    } else o._ = a;
  }
  return o;
}

// ---------- commands ----------

// Run a child with the parent's stdio so it can prompt on the TTY (age -p reads the
// passphrase interactively). Used only by keygen --passphrase, an interactive command.
function runInteractive(cmd, args) {
  return new Promise((res, rej) => {
    const p = spawn(cmd, args, { stdio: 'inherit' });
    p.on('error', rej);
    p.on('close', (code) => (code === 0 ? res() : rej(new Error(`${cmd} exited ${code}`))));
  });
}

async function keygen(o) {
  // 0700: HOME holds the private identity (and often the JWK wallet) — it must not be
  // world/group-listable. chmod too, in case it pre-existed with a looser mode.
  await mkdir(HOME, { recursive: true, mode: 0o700 });
  await chmod(HOME, 0o700).catch(() => {});
  if (await exists(IDENTITY)) {
    if (!o.force) {
      throw new Error(`identity already exists at ${IDENTITY} (refusing to overwrite — losing it = losing the brain). Pass --force only if you are certain.`);
    }
    await rm(IDENTITY, { force: true }); // age-keygen -o uses O_EXCL, so the old key must go first
  }
  let pub;
  if (o.passphrase) {
    // Passphrase-wrap the identity at rest (#36): generate the raw key to a temp file,
    // derive the recipient from it, then encrypt it with a scrypt passphrase via `age -p`
    // (which prompts interactively on the TTY). Decrypt is unchanged — `age -d -i` prompts
    // for the passphrase when the identity file is itself encrypted.
    const raw = `${IDENTITY}.${process.pid}.${randomBytes(4).toString('hex')}.raw`;
    // A Ctrl-C/SIGHUP at the interactive `age -p` prompt tears the process down without
    // unwinding the finally, so register the raw path with the signal guard too — it
    // rmSync's the unwrapped key synchronously before re-raising (the finally still
    // covers the normal-error path).
    installStageSignalGuard();
    ACTIVE_RAW_KEY = raw;
    try {
      await run(AGE_KEYGEN, ['-o', raw]);
      await chmod(raw, 0o600);
      pub = (await run(AGE_KEYGEN, ['-y', raw])).out.trim(); // derive recipient BEFORE wrapping (needs the plaintext)
      console.log('Set a passphrase to protect the identity at rest (you will enter it on restore/verify):');
      await runInteractive(AGE, ['-p', '-o', IDENTITY, raw]); // prompts for the passphrase on the TTY
      await chmod(IDENTITY, 0o600);
    } finally {
      await rm(raw, { force: true }); // never leave the unwrapped key behind
      ACTIVE_RAW_KEY = null;
    }
  } else {
    await run(AGE_KEYGEN, ['-o', IDENTITY]);
    await chmod(IDENTITY, 0o600);
    pub = (await run(AGE_KEYGEN, ['-y', IDENTITY])).out.trim(); // derive recipient (public key)
  }
  await writeFile(RECIPIENT, pub + '\n', { mode: 0o644 });
  console.log(`identity (PRIVATE, keep offline): ${IDENTITY}${o.passphrase ? ' (passphrase-wrapped)' : ''}`);
  console.log(`recipient (PUBLIC, safe to copy):  ${RECIPIENT}`);
  console.log(`recipient = ${pub}`);
  console.log('\n⚠  Back up the identity file now. If you lose it, the snapshots are unrecoverable.');
}

// Return EVERY recipient entry a value feeds to age: an `age1…` literal is one
// entry; anything else is read as a recipients file and split into its non-blank,
// non-comment lines (mirrors snapshot's own age1-or-file rule). We must enumerate
// whole LINES, not just age1… tokens — `age -R` also accepts SSH recipients
// (`ssh-ed25519 …`), so an attacker who appends an ssh line to a tampered
// recipient.txt would slip past an age1-only scan. The pin enforces the INPUTS,
// since age ciphertext never exposes its recipient pubkeys.
async function recipientEntries(rec) {
  if (rec.startsWith('age1')) return [rec.trim()];
  const text = await readFile(rec, 'utf8');
  return text.split('\n').map((l) => l.trim()).filter((l) => l && !l.startsWith('#'));
}

// Resolve CIPHER_BRAIN_PIN_RECIPIENTS to a set of allowed pubkeys. File-first: if the
// value names an existing file, read it (so a path that happens to contain "age1",
// e.g. age1-pins.txt, is not mistaken for an inline list); otherwise treat the value
// itself as an inline list of age1… keys. Parsed line-by-line, SKIPPING comment lines
// (mirrors recipientEntries) — a key left commented-out (e.g. a rotated/revoked one)
// must NOT count as allowed, or the pin could be defeated by a stale comment.
async function resolvePinnedRecipients(val) {
  const text = (await exists(val)) ? await readFile(val, 'utf8') : val;
  const keys = new Set();
  for (const line of text.split('\n')) {
    const l = line.trim();
    if (!l || l.startsWith('#')) continue;
    for (const m of l.matchAll(AGE_PUBKEY_RE)) keys.add(m[0]);
  }
  return keys;
}

// snapshot() stages the full *plaintext* brain into a 0700 temp dir and leans on
// its finally-block to erase it. But a signal (operator Ctrl-C, or launchd/shutdown
// SIGTERM in service mode) tears the process down WITHOUT unwinding the suspended
// async stack, so the finally never runs and the plaintext brain would linger in
// TMPDIR — the exact on-disk exposure the threat model exists to prevent. Track the
// active stage dir and erase it synchronously from a signal handler (async rm can't
// finish before the process dies), then re-raise so the exit code is correct.
let ACTIVE_STAGE = null;
let ACTIVE_OUT_PART = null; // the partial ${out}.part being written; erased on signal so no stray ciphertext lingers
let ACTIVE_RAW_KEY = null;  // the unwrapped identity temp during keygen --passphrase; erased on signal so the plaintext key never lingers
let SIGNAL_GUARD_INSTALLED = false;
function installStageSignalGuard() {
  if (SIGNAL_GUARD_INSTALLED) return;
  SIGNAL_GUARD_INSTALLED = true;
  for (const sig of ['SIGINT', 'SIGTERM', 'SIGHUP']) {
    const handler = () => {
      // Kill the pipeline children FIRST so a still-writing age/tar can't re-create the
      // stage or .part after we remove them (the signal may have hit node alone).
      for (const c of ACTIVE_CHILDREN) { try { c.kill('SIGKILL'); } catch {} }
      ACTIVE_CHILDREN.clear();
      if (ACTIVE_STAGE) { try { rmSync(ACTIVE_STAGE, { recursive: true, force: true }); } catch {} ACTIVE_STAGE = null; }
      if (ACTIVE_OUT_PART) { try { rmSync(ACTIVE_OUT_PART, { force: true }); } catch {} ACTIVE_OUT_PART = null; }
      if (ACTIVE_RAW_KEY) { try { rmSync(ACTIVE_RAW_KEY, { force: true }); } catch {} ACTIVE_RAW_KEY = null; }
      // adding a listener suppressed Node's default auto-terminate — remove only our
      // own handler (not any unrelated listener) and re-raise so the process exits
      // with the correct signal code instead of hanging.
      process.off(sig, handler);
      process.kill(process.pid, sig);
    };
    process.on(sig, handler);
  }
}

// Promote a finished .part to its final --out, no-clobber. Prefer link(): it is atomic
// and fails with EEXIST if out appeared meanwhile, giving a true exclusive no-clobber
// even under overlapping snapshots. But hard links are unsupported on exFAT/FAT and some
// network/cloud mounts (common backup media), where link throws EPERM/ENOTSUP — there,
// fall back to a re-checked rename (best-effort no-clobber with a tiny TOCTOU window,
// the same the original `age -o` write had). Atomicity-on-success holds either way.
async function promoteSnapshot(part, out) {
  const clobberErr = () => new Error(`${out} already exists — refusing to overwrite a prior snapshot (move it aside or choose a new --out)`);
  try {
    await link(part, out);
  } catch (e) {
    if (e && e.code === 'EEXIST') throw clobberErr();
    if (e && ['EPERM', 'ENOTSUP', 'EOPNOTSUPP', 'ENOSYS', 'EXDEV'].includes(e.code)) {
      if (await exists(out)) throw clobberErr();
      await rename(part, out);
      return;
    }
    throw e;
  }
  await rm(part, { force: true }); // drop the redundant link; out is the durable copy
}

async function snapshot(o) {
  if (!o.out) throw new Error('--out <file.age> required');
  if (!o.pg && o.dirs.length === 0) throw new Error('nothing to snapshot: pass --pg <conn> and/or --dir <path>');
  // No-clobber: refuse to overwrite an existing snapshot (this is a backup tool — a
  // silent overwrite could destroy a prior, possibly only, copy of the brain). The old
  // `age -o o.out` write left this to age's version-dependent overwrite policy; the
  // atomic rename below would ALWAYS clobber, so enforce the safe behavior explicitly.
  if (await exists(o.out)) throw new Error(`${o.out} already exists — refusing to overwrite a prior snapshot (move it aside or choose a new --out)`);
  // Recipients = who can decrypt. Each --recipient is an `age1...` pubkey OR a
  // file of pubkeys; default to the keypair's own recipient. Passing more than one
  // is key recovery: encrypt to a primary AND an offline backup key so that losing
  // the primary identity does NOT lose the brain (any one identity restores).
  const recArgs = [];
  const recs = o.recipients.length ? o.recipients : [RECIPIENT];
  for (const r of recs) {
    if (r.startsWith('age1')) recArgs.push('-r', r);
    else {
      if (!(await exists(r))) throw new Error(`no recipient at ${r} — run "cipher-brain keygen" first, or pass an age1... pubkey`);
      recArgs.push('-R', r);
    }
  }

  // Recipient pin (opt-in): fail-fast if any effective recipient is not allowlisted,
  // so a tampered recipient.txt or an injected extra --recipient cannot silently
  // re-key this (and every future) snapshot to an attacker.
  if (PIN_RECIPIENTS) {
    const allowed = await resolvePinnedRecipients(PIN_RECIPIENTS);
    if (allowed.size === 0) throw new Error('CIPHER_BRAIN_PIN_RECIPIENTS is set but lists no age1… pubkeys — refusing to snapshot');
    for (const r of recs) {
      const entries = await recipientEntries(r);
      if (entries.length === 0) throw new Error(`recipient "${r}" has no recipients to check against CIPHER_BRAIN_PIN_RECIPIENTS (refusing to snapshot)`);
      for (const e of entries) {
        // Fail-closed: every entry must be an allowlisted age1… key. A non-age1
        // recipient (e.g. an injected `ssh-ed25519 …` line) can't be on the
        // age1-only allowlist, so it is rejected — which is the point.
        if (!allowed.has(e)) throw new Error(`recipient "${e}" (via "${r}") is NOT in CIPHER_BRAIN_PIN_RECIPIENTS — refusing to snapshot (an unexpected recipient could decrypt your brain)`);
      }
    }
    console.error(`recipient pin OK: all recipient(s) are allowlisted`);
  }

  installStageSignalGuard();
  // mkdtempSync (not async mkdtemp) so dir-creation and the ACTIVE_STAGE assignment
  // happen in one tick with no event-loop yield between them — otherwise a signal that
  // lands during the await could fire the handler while ACTIVE_STAGE is still null and
  // leave the just-created stage dir behind.
  const stage = mkdtempSync(join(tmpdir(), 'cipher-brain-'));
  ACTIVE_STAGE = stage; // a signal now erases this staged plaintext (see installStageSignalGuard)
  try {
    const components = [];
    if (o.pg) {
      const dumpPath = join(stage, 'db.dump');
      const tableArgs = o.tables.flatMap((t) => ['-t', t]);
      await run(pgTool('pg_dump'), ['-Fc', '--no-owner', '--no-privileges', ...tableArgs, '-f', dumpPath, o.pg]);
      components.push({ name: 'db.dump', kind: 'pg_dump:custom', tables: o.tables.length ? o.tables : 'all' });
    }
    const usedNames = new Set();
    for (const d of o.dirs) {
      const abs = resolve(d);
      let name = basename(abs) + '.tar.gz';
      // multiple --dir with the same basename must not overwrite each other in the stage
      for (let n = 1; usedNames.has(name); n++) name = `${basename(abs)}-${n}.tar.gz`;
      usedNames.add(name);
      await run('tar', ['-czf', join(stage, name), '-C', dirname(abs), basename(abs)], { timeoutMs: PIPE_TIMEOUT_MS }); // a FIFO/special file under --dir can't hang the pre-stage tar
      components.push({ name, kind: 'dir', source: abs });
    }
    // manifest carries NO secrets — just what's inside, so restore is self-describing
    await writeFile(
      join(stage, 'manifest.json'),
      JSON.stringify({ tool: 'cipher-brain', schema: 1, host: hostname(), components }, null, 2) + '\n',
    );
    // tar the staged components into one stream, encrypt to all recipients. Write to a
    // PER-RUN-UNIQUE .part so overlapping snapshots to the same --out never share/clobber
    // each other's in-progress file, and rename only on success, so a mid-pipeline failure
    // (tar error, ENOSPC, a SIGTERM-killed age) never leaves a TRUNCATED *.age at o.out —
    // which would still start with the age magic and thus pass push()'s header-only gate,
    // letting an operator publish unrecoverable ciphertext to permanent paid storage.
    const part = `${o.out}.${process.pid}.${randomBytes(4).toString('hex')}.part`;
    ACTIVE_OUT_PART = part; // a signal now also erases this partial ciphertext
    try {
      await pipe2('tar', ['-cf', '-', '-C', stage, '.'], AGE, [...recArgs, '-o', part], { timeoutMs: PIPE_TIMEOUT_MS });
      await promoteSnapshot(part, o.out);
      ACTIVE_OUT_PART = null;
    } catch (e) {
      await rm(part, { force: true });
      ACTIVE_OUT_PART = null;
      throw e;
    }
    const sz = (await stat(o.out)).size;
    console.log(`wrote ${o.out} (${fmtBytes(sz)}, encrypted to ${recs.length} recipient(s): ${recs.join(', ')})`);
    console.log(`components: ${components.map((c) => c.name).join(', ')}`);
  } finally {
    await rm(stage, { recursive: true, force: true });
    ACTIVE_STAGE = null;
  }
}

async function restore(o) {
  if (!o.in) throw new Error('--in <file.age> required');
  if (!o.out_dir) throw new Error('--out-dir <dir> required');
  const identity = o.identity || IDENTITY;
  if (!(await exists(identity))) throw new Error(`no identity at ${identity} — cannot decrypt without the private key`);
  // age streams plaintext chunk-by-chunk, so a truncated/corrupt artifact errors only
  // AFTER tar has already extracted the leading components — leaving a partial tree.
  // Track whether we created out_dir so we can remove it (or warn) on a mid-stream fail.
  const outDirPreExisted = await exists(o.out_dir);
  await mkdir(o.out_dir, { recursive: true });
  // age -d -i identity in | tar -xf - -C out-dir
  // --no-same-owner/--no-same-permissions: a substituted/forged archive must not be
  // able to set hostile ownership or modes on extraction (defense-in-depth — the
  // bytes can be attacker-chosen if storage is compromised; see verify --sha256).
  try {
    await pipe2(AGE, ['-d', '-i', identity, o.in], 'tar', ['-xf', '-', '--no-same-owner', '--no-same-permissions', '-C', o.out_dir], { timeoutMs: PIPE_TIMEOUT_MS });
  } catch (e) {
    if (!outDirPreExisted) await rm(o.out_dir, { recursive: true, force: true });
    else console.error(`warning: ${o.out_dir} may now hold a partially-extracted tree (restore failed mid-stream) — discard it before trusting the contents`);
    throw e;
  }
  console.log(`restored components into ${o.out_dir}`);
  const manifestPath = join(o.out_dir, 'manifest.json');
  if (await exists(manifestPath)) console.log(await readFile(manifestPath, 'utf8'));
  if (o.pg) {
    const dump = join(o.out_dir, 'db.dump');
    if (!(await exists(dump))) throw new Error(`--pg given but no db.dump in snapshot`);
    await run(pgTool('pg_restore'), ['--no-owner', '--no-privileges', '--clean', '--if-exists', '-d', o.pg, dump]);
    console.log(`pg_restore -> ${o.pg} done`);
  }
}

// push/pull move the ciphertext to/from a storage backend. The verb is a dumb
// primitive against ONE backend endpoint; proving "fetched from elsewhere" (a
// second, independent node) is the operator script's job, not the verb's.
async function push(o) {
  if (!o.in) throw new Error('--in <file.age> required');
  if (!o.backend) throw new Error('--backend <file|ton|arweave|turbo> required'); // no silent default
  if (!(await exists(o.in))) throw new Error(`no such file: ${o.in}`);
  // storage must only ever see ciphertext — refuse to push a non-age artifact
  // (e.g. an accidental plaintext path), which would be the last gate before a
  // backend can publish bytes externally.
  if (!(await readHead(o.in, 64)).startsWith(AGE_MAGIC)) {
    throw new Error(`${o.in} is not age ciphertext (header mismatch) — refusing to push non-ciphertext to storage`);
  }
  const yes = !!o.yes || CIPHER_YES;
  // arweave and turbo are paid, permanent stores — require an explicit opt-in so
  // an unattended cadence loop doesn't silently accumulate charges. Set CIPHER_BRAIN_YES=1
  // in the nightly script (or pass --yes) to skip this prompt in automation.
  if ((o.backend === 'arweave' || o.backend === 'turbo') && !yes) {
    throw new Error(
      `${o.backend}: uploading to a permanent Arweave store spends real funds — ` +
      `re-run push with --yes or set CIPHER_BRAIN_YES=1 in the environment to confirm`
    );
  }
  const backend = await backendFor(o.backend);
  const locator = await backend.put(o.in, { yes });
  console.error(`pushed ${o.in} -> ${o.backend}:${locator}`);
  // --save-locator <path>: persist the returned locator so operators can back it up
  // alongside their identity (the two things a fresh machine needs to restore).
  // The file is rewritten on each push — it always holds the most recent locator.
  if (o.save_locator) {
    await mkdir(dirname(resolve(o.save_locator)), { recursive: true });
    // Record "<locator>\t<backend>\t<sha256>". The sha256 — computed here off the bytes
    // we just pushed — binds the locator to its ciphertext, so a recovery via
    // --from-locator-file is fail-closed: for arweave/turbo (locator != content hash) a
    // gateway/storage attacker can't later serve a substituted, still-age-decryptable
    // artifact. The hash is trustworthy because this file is backed up OFF-BOX (the same
    // trusted-source rule the existing --sha256 pin relies on).
    const digest = await sha256(o.in);
    // Atomic write: a crash / ENOSPC mid-rewrite must not leave the recovery pointer
    // empty AND destroy the previous good locator. Write a temp sibling, then rename.
    const tmp = `${o.save_locator}.${process.pid}.${randomBytes(4).toString('hex')}.tmp`;
    try {
      await writeFile(tmp, `${locator}\t${o.backend}\t${digest}\n`, { flag: 'w' });
      await rename(tmp, o.save_locator);
    } catch (e) {
      await rm(tmp, { force: true });
      throw e;
    }
    console.error(`locator saved -> ${o.save_locator}`);
  }
  console.log(locator); // stdout = locator ONLY, so a script can capture it
}

async function pull(o) {
  // --from-locator-file <path>: read the locator (and its backend) from a file written
  // by `push --save-locator`. This is the recovery path — a fresh machine that holds
  // only the identity + this one small file (both backed up off-box) can restore the
  // latest snapshot without ever having seen index.tsv. Explicit --locator/--backend
  // still win if both are also given.
  if (o.from_locator_file) {
    if (!(await exists(o.from_locator_file))) throw new Error(`no such locator file: ${o.from_locator_file}`);
    const line = (await readFile(o.from_locator_file, 'utf8')).split('\n').map((l) => l.trim()).find((l) => l && !l.startsWith('#'));
    if (!line) throw new Error(`locator file ${o.from_locator_file} has no locator line`);
    const [savedLoc, savedBackend, savedSha] = line.split('\t');
    // A truncated / hand-mangled file missing the backend column would otherwise fall
    // through to the generic "--backend required" error, hiding the real cause.
    if (!savedLoc || !savedBackend) {
      throw new Error(`locator file ${o.from_locator_file} must contain "<locator>\\t<backend>[\\t<sha256>]" — got: ${JSON.stringify(line)}`);
    }
    if (!o.locator) o.locator = savedLoc;
    if (!o.backend) o.backend = savedBackend;
    // Apply the saved integrity pin so recovery is fail-closed (a substituted ciphertext
    // is rejected); an explicit --sha256 still wins if the operator passed one.
    if (!o.sha256 && savedSha) o.sha256 = savedSha;
  }
  if (!o.locator) throw new Error('--locator <id> required (or --from-locator-file <path>)');
  if (!o.out) throw new Error('--out <file.age> required');
  if (!o.backend) throw new Error('--backend <file|ton|arweave|turbo> required');
  const backend = await backendFor(o.backend);
  // --wait <seconds>: keep retrying while the item is not yet retrievable. A fresh
  // Turbo/ArDrive upload takes ~5-8 min to propagate to the gateway (bundle -> mine
  // -> index); with --wait 0 (the default) pull fails immediately, preserving the old
  // behavior. CIPHER_BRAIN_PULL_RETRY_MS overrides the 30s retry interval (tests use it).
  const waitMs = (Number(o.wait) || 0) * 1000;       // `|| 0` OUTSIDE Number → a non-numeric --wait is 0, not NaN (no infinite loop)
  const retryMs = Number(process.env.CIPHER_BRAIN_PULL_RETRY_MS) || 30000;
  const deadline = Date.now() + waitMs;
  for (let attempt = 1; ; attempt++) {
    try {
      await backend.get(o.locator, o.out);
      break;
    } catch (e) {
      const remaining = deadline - Date.now();
      if (!e.retryable || remaining <= 0) throw e;    // fatal (bad locator etc.) or out of budget → fail now
      const naptime = Math.min(retryMs, remaining);   // honor a budget shorter than the retry interval
      console.error(`pull attempt ${attempt} not ready (${e.message}); retrying in ${Math.round(naptime / 1000)}s…`);
      await sleep(naptime);
    }
  }
  // --sha256 <hex>: bind the fetched bytes to a hash known out-of-band (from a TRUSTED
  // source, e.g. an off-box index.tsv — NOT the maybe-compromised snapshotting box).
  // For the post-assigned-id backends (arweave/turbo) the locator is not a content
  // hash, so without this a gateway/storage attacker could serve a rolled-back or
  // substituted (but still age-decryptable) ciphertext. Fail-closed: delete and error
  // on mismatch so a bad artifact never lands at --out.
  if (o.sha256) {
    const got = await sha256(o.out);
    if (got.toLowerCase() !== String(o.sha256).toLowerCase()) {
      await rm(o.out, { force: true });
      throw new Error(`sha256 mismatch: fetched ${got}, expected ${o.sha256} — deleted ${o.out} (the storage/gateway served bytes that do not match the pinned hash)`);
    }
    console.error(`sha256 OK: ${got}`);
  }
  console.error(`pulled ${o.backend}:${o.locator} -> ${o.out}`);
}

// verify is the falsifiable half. Three checks:
//   1. it is real age ciphertext (header),
//   2. a WRONG key is rejected (negative control), and
//   3. when the private identity is on THIS machine, that identity decrypts the
//      whole artifact into a well-formed bundle (positive control) — this is what
//      makes PASS mean "restorable by you", and it catches truncation/corruption
//      that a wrong-key test alone would miss.
// On a public-key-only box the positive control is skipped (no identity present),
// so verify there attests only the header + that a stranger's key cannot read it —
// and reports VERDICT: PARTIAL (exit 2), never PASS, so it is not read as proof the
// snapshot is restorable by you.
async function verify(o) {
  if (!o.in) throw new Error('--in <file.age> required');
  const sz = (await stat(o.in)).size;
  const head = await readHead(o.in, 64);
  const isAge = head.startsWith(AGE_MAGIC);
  console.log(`file: ${o.in} (${fmtBytes(sz)})`);
  console.log(`[${isAge ? 'PASS' : 'FAIL'}] age ciphertext header present`);

  // optional integrity pin: --sha256 binds the artifact to a hash known out-of-band
  // (e.g. from a trusted off-box index.tsv), catching a rolled-back/substituted
  // ciphertext that age would still decrypt. A mismatch is a hard FAIL.
  let hashOk = true;
  if (o.sha256) {
    const got = await sha256(o.in);
    hashOk = got.toLowerCase() === String(o.sha256).toLowerCase();
    console.log(`[${hashOk ? 'PASS' : 'FAIL'}] sha256 matches the expected hash${hashOk ? '' : ` (expected ${o.sha256}, got ${got})`}`);
  }

  // negative control: a throwaway key must NOT decrypt
  const tdir = await mkdtemp(join(tmpdir(), 'cipher-brain-verify-'));
  let wrongKeyRejected = false;
  try {
    const wrongId = join(tdir, 'wrong.age');
    await run(AGE_KEYGEN, ['-o', wrongId]);
    try { await run(AGE, ['-d', '-i', wrongId, o.in]); } catch { wrongKeyRejected = true; }
  } finally {
    await rm(tdir, { recursive: true, force: true });
  }
  console.log(`[${wrongKeyRejected ? 'PASS' : 'FAIL'}] a wrong key is rejected`);

  // positive control: your identity decrypts the whole thing into a well-formed
  // bundle. Streamed (age -d | tar -t) so it never buffers a multi-GB plaintext.
  const identity = o.identity || IDENTITY;
  let positiveOk = true;
  let positiveSkipped = false;
  if (await exists(identity)) {
    try {
      await pipe2(AGE, ['-d', '-i', identity, o.in], 'tar', ['-tf', '-'], { consStdout: 'ignore', timeoutMs: PIPE_TIMEOUT_MS });
      console.log('[PASS] your identity decrypts the artifact into a well-formed bundle');
    } catch {
      positiveOk = false;
      console.log('[FAIL] your identity could not decrypt the artifact (corrupt/truncated, or not encrypted to you)');
    }
  } else {
    positiveSkipped = true;
    console.log('[SKIP] positive control — no private identity on this machine (public-key-only box)');
  }

  // Three verdicts, not two. The header + wrong-key checks alone do NOT prove the
  // artifact is restorable BY YOU, so on a public-key-only box (positive control
  // skipped) we must NOT print PASS / exit 0 — a cron/log reading "PASS" would be
  // false-green and could mask a month of snapshots encrypted to a wrong/lost key.
  if (!isAge || !wrongKeyRejected || !positiveOk || !hashOk) {
    console.log('\nVERDICT: FAIL');
    process.exitCode = 1;
  } else if (positiveSkipped) {
    console.log('\nVERDICT: PARTIAL — header + wrong-key checks passed, but decryptability was NOT proven on this box (no private identity here). Run verify where the identity lives to prove it is restorable by you.');
    process.exitCode = 2; // distinct from PASS(0) and FAIL(1) so automation can tell them apart
  } else {
    console.log('\nVERDICT: PASS');
  }
}

// ---------- utils ----------

function readHead(path, n) {
  return new Promise((res, rej) => {
    const s = createReadStream(path, { start: 0, end: n - 1, encoding: 'utf8' });
    let d = '';
    s.on('data', (c) => (d += c));
    s.on('end', () => res(d));
    s.on('error', rej);
  });
}

function fmtBytes(n) {
  const u = ['B', 'KB', 'MB', 'GB'];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(i ? 1 : 0)} ${u[i]}`;
}

const HELP = `cipher-brain — encrypt a gbrain snapshot so only you can read it

  cipher-brain keygen [--passphrase] [--force]
      Create your age keypair: identity (PRIVATE) + recipient (PUBLIC).
      --passphrase wraps the identity at rest with a scrypt passphrase (prompted on the
      TTY); restore/verify then prompt for it. Identity = ${IDENTITY}

  cipher-brain snapshot --out <file.age> [--pg <conn>] [--pg-table <t>]... [--dir <path>]... [--recipient <pubkey|file>]...
      Bundle a pg_dump and/or directories, encrypt to the PUBLIC recipient(s).
      Pass --recipient more than once (a primary + an offline backup key) for key
      recovery: any one of those identities can restore. The snapshotting machine
      never needs a private key.

  cipher-brain restore --in <file.age> --out-dir <dir> [--identity <file>] [--pg <conn>]
      Decrypt with the PRIVATE identity; optionally pg_restore the db.dump.

  cipher-brain verify --in <file.age> [--identity <file>] [--sha256 <hex>]
      Assert it is real age ciphertext, a wrong key cannot open it, AND (when the
      private identity is on this box) that YOUR key decrypts it into a well-formed
      bundle. --sha256 also pins the artifact to an expected hash. VERDICT: PASS (exit 0)
      / FAIL (exit 1) / PARTIAL (exit 2 — decryptability not proven, e.g. public-key-only box).

  cipher-brain push --in <file.age> --backend <file|ton|arweave|turbo> [--yes] [--save-locator <path>]
      Upload ciphertext to storage. Prints ONLY the locator to stdout
      (file: store path; ton: hex BagID; arweave: tx id; turbo: ANS-104 data item id).
      Storage sees ciphertext only.
      arweave/turbo are paid permanent stores — require --yes or CIPHER_BRAIN_YES=1.
      --save-locator writes "<locator>\\t<backend>\\t<sha256>" to a file (rewritten
      atomically each push, so it always holds the LATEST + an integrity pin). Back this
      file up off-box next to your identity: it is the durable pointer a fresh machine
      needs to find the most recent snapshot. (For the file backend the locator is a
      LOCAL store path — only ton/arweave/turbo locators are portable to another machine.)

  cipher-brain pull (--locator <id> --backend <…> | --from-locator-file <path>) --out <file.age> [--wait <seconds>] [--sha256 <hex>]
      Fetch ciphertext by locator into --out. --from-locator-file reads the locator, its
      backend AND the saved sha256 from a file written by push --save-locator (the recovery
      path: identity + this file are all a fresh machine needs; the saved sha256 is applied
      as the integrity pin automatically). --wait retries while the item is not yet
      retrievable (a fresh Turbo/Arweave upload takes ~5-8 min to propagate); default 0.
      --sha256 fail-closes the fetch: the bytes must match the expected hash (sourced
      out-of-band from a trusted index) or --out is deleted and pull errors.

Env: CIPHER_BRAIN_HOME (default ~/.cipher-brain), CIPHER_BRAIN_AGE, CIPHER_BRAIN_PG_BIN (dir of pg_dump/pg_restore).
     CIPHER_BRAIN_PIN_RECIPIENTS (snapshot: allowlist of age1… pubkeys, inline or a file — refuse to encrypt to any other recipient).
Storage: CIPHER_BRAIN_FILE_DIR (file); CIPHER_BRAIN_TON_{CLI,API,CLIENT,SERVER,TIMEOUT} (ton);
         CIPHER_BRAIN_AR_{HOST,PORT,PROTOCOL,WALLET,GATEWAY,GATEWAYS,HTTP_TIMEOUT} (arweave; the 'arweave' npm package is needed only to PUSH or for the rare L1 chunk fallback — a gateway pull needs none);
         turbo: CIPHER_BRAIN_AR_WALLET (JWK signer) + optional CIPHER_BRAIN_AR_PAID_BY (an address sharing Turbo Credits to that signer); needs '@ardrive/turbo-sdk' to PUSH (a pull reuses the arweave gateway read, no SDK). Funding/credit-share details: docs/arweave-upload-runbook.md.
Spend: arweave/turbo PUSH needs --yes or CIPHER_BRAIN_YES=1 (paid, permanent); CIPHER_BRAIN_MAX_SPEND caps the turbo estimate (winc).`;

async function main() {
  const [cmd, ...rest] = process.argv.slice(2);
  const o = parseArgs(rest);
  switch (cmd) {
    case 'keygen': return keygen(o);
    case 'snapshot': return snapshot(o);
    case 'restore': return restore(o);
    case 'verify': return verify(o);
    case 'push': return push(o);
    case 'pull': return pull(o);
    case 'help': case '--help': case '-h': case undefined: console.log(HELP); return;
    default: console.error(`unknown command: ${cmd}\n`); console.log(HELP); process.exitCode = 2;
  }
}

main().catch((e) => { console.error(`error: ${e.message}`); process.exitCode = 1; });
