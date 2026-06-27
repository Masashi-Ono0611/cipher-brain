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
// loads into memory. The staged plaintext is erased even on failure (the snapshot
// finally-block), so it doesn't linger. Staging needs scratch space ~the size of
// the snapshot, so point TMPDIR at a disk with room for large brains.
//
// Backend-agnostic: this produces ONE encrypted artifact (`*.age`). Where those
// bytes get parked (TON Storage / Arweave / anything) is a separate, pluggable
// concern — storage only ever sees ciphertext.

import { spawn } from 'node:child_process';
import { mkdir, writeFile, rm, chmod, access, stat, readFile, mkdtemp, copyFile, readdir } from 'node:fs/promises';
import { createReadStream, constants as FS } from 'node:fs';
import { homedir, hostname, tmpdir } from 'node:os';
import { join, basename, dirname, resolve } from 'node:path';
import { createHash } from 'node:crypto';

const HOME = process.env.CIPHER_BRAIN_HOME || join(homedir(), '.cipher-brain');
const AGE = process.env.CIPHER_BRAIN_AGE || 'age';
const AGE_KEYGEN = process.env.CIPHER_BRAIN_AGE_KEYGEN || 'age-keygen';
const PG_BIN = process.env.CIPHER_BRAIN_PG_BIN || ''; // dir holding pg_dump/pg_restore; '' => PATH
const pgTool = (name) => (PG_BIN ? join(PG_BIN, name) : name);

const IDENTITY = join(HOME, 'identity.age');     // private key — required to restore
const RECIPIENT = join(HOME, 'recipient.txt');   // public key — all snapshot needs

const AGE_MAGIC = 'age-encryption.org/v1';

// ---------- storage backend config (pluggable: storage only ever sees ciphertext) ----------
const FILE_DIR = process.env.CIPHER_BRAIN_FILE_DIR || join(HOME, 'store'); // file backend object store
const TON_CLI = process.env.CIPHER_BRAIN_TON_CLI || 'storage-daemon-cli';
const TON_API = process.env.CIPHER_BRAIN_TON_API || '127.0.0.1:15555';     // storage-daemon control addr
const TON_CLIENT = process.env.CIPHER_BRAIN_TON_CLIENT || '';              // storage-daemon-cli -k <client key>
const TON_SERVER = process.env.CIPHER_BRAIN_TON_SERVER || '';              // storage-daemon-cli -p <server.pub>
const TON_TIMEOUT_S = Number(process.env.CIPHER_BRAIN_TON_TIMEOUT || 300); // pull: wait this long for download

// ---------- small process helpers (array args only — no shell, no injection) ----------

function run(cmd, args, { input, timeoutMs } = {}) {
  return new Promise((res, rej) => {
    const p = spawn(cmd, args, { stdio: [input ? 'pipe' : 'ignore', 'pipe', 'pipe'] });
    let out = '', err = '', timer;
    if (timeoutMs) {
      // a stuck child (e.g. a storage-daemon-cli call that never returns) must not
      // hang us forever — kill it and reject so callers can bound their own loops.
      timer = setTimeout(() => { p.kill('SIGKILL'); rej(new Error(`${cmd} timed out after ${timeoutMs}ms`)); }, timeoutMs);
    }
    p.stdout.on('data', (d) => (out += d));
    p.stderr.on('data', (d) => (err += d));
    p.on('error', (e) => { clearTimeout(timer); rej(e); });
    p.on('close', (code) => {
      clearTimeout(timer);
      code === 0 ? res({ out, err }) : rej(new Error(`${cmd} exited ${code}: ${err.trim() || out.trim()}`));
    });
    if (input) { p.stdin.write(input); p.stdin.end(); }
  });
}

// Pipe producer.stdout -> consumer.stdin and wait for both. Used for the
// tar|age (snapshot) and age|tar (restore) streaming pipelines.
function pipe2(prodCmd, prodArgs, consCmd, consArgs, { consStdout = 'inherit' } = {}) {
  return new Promise((res, rej) => {
    const prod = spawn(prodCmd, prodArgs, { stdio: ['ignore', 'pipe', 'pipe'] });
    const cons = spawn(consCmd, consArgs, { stdio: ['pipe', consStdout, 'pipe'] });
    let pErr = '', cErr = '', left = 2, settled = false;
    const fail = (e) => {
      if (settled) return;
      settled = true;
      prod.kill(); cons.kill(); // don't leave the survivor running (or still decrypting)
      rej(e);
    };
    const ok = () => { if (settled) return; if (--left === 0) { settled = true; res(); } };
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

function sha256(file) {
  return new Promise((res, rej) => {
    const h = createHash('sha256');
    createReadStream(file).on('data', (d) => h.update(d)).on('end', () => res(h.digest('hex'))).on('error', rej);
  });
}

// ---------- storage backends ----------
// A StorageBackend is { put(file) -> locator, get(locator, outFile) }. Storage
// only ever sees the *.age ciphertext; the locator is content-addressed.
function backendFor(name) {
  if (name === 'file') return fileBackend();
  if (name === 'ton') return tonBackend();
  throw new Error(`unknown backend: ${name || '(none)'} — use --backend file|ton`);
}

// file backend: a local content-addressed store. Needs no daemon and no network,
// so CI can exercise push/pull end-to-end. locator = <FILE_DIR>/<sha256>.age
function fileBackend() {
  return {
    async put(file) {
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
    async put(file) {
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

const BOOL_FLAGS = new Set(['force']); // flags that take no value

function parseArgs(argv) {
  const o = { dirs: [], tables: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--dir') o.dirs.push(argv[++i]);
    else if (a === '--pg-table') o.tables.push(argv[++i]);
    else if (a.startsWith('--')) {
      const key = a.slice(2).replace(/-/g, '_');
      o[key] = BOOL_FLAGS.has(key) ? true : argv[++i];
    } else o._ = a;
  }
  return o;
}

// ---------- commands ----------

async function keygen(o) {
  await mkdir(HOME, { recursive: true });
  if (await exists(IDENTITY)) {
    if (!o.force) {
      throw new Error(`identity already exists at ${IDENTITY} (refusing to overwrite — losing it = losing the brain). Pass --force only if you are certain.`);
    }
    await rm(IDENTITY, { force: true }); // age-keygen -o uses O_EXCL, so the old key must go first
  }
  await run(AGE_KEYGEN, ['-o', IDENTITY]);
  await chmod(IDENTITY, 0o600);
  const { out } = await run(AGE_KEYGEN, ['-y', IDENTITY]); // derive recipient (public key)
  const pub = out.trim();
  await writeFile(RECIPIENT, pub + '\n', { mode: 0o644 });
  console.log(`identity (PRIVATE, keep offline): ${IDENTITY}`);
  console.log(`recipient (PUBLIC, safe to copy):  ${RECIPIENT}`);
  console.log(`recipient = ${pub}`);
  console.log('\n⚠  Back up the identity file now. If you lose it, the snapshots are unrecoverable.');
}

async function snapshot(o) {
  if (!o.out) throw new Error('--out <file.age> required');
  if (!o.pg && o.dirs.length === 0) throw new Error('nothing to snapshot: pass --pg <conn> and/or --dir <path>');
  const recipientFile = o.recipient ? o.recipient : RECIPIENT;
  if (!(await exists(recipientFile))) throw new Error(`no recipient at ${recipientFile} — run "cipher-brain keygen" first (or pass --recipient <file>)`);

  const stage = await mkdtemp(join(tmpdir(), 'cipher-brain-'));
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
      await run('tar', ['-czf', join(stage, name), '-C', dirname(abs), basename(abs)]);
      components.push({ name, kind: 'dir', source: abs });
    }
    // manifest carries NO secrets — just what's inside, so restore is self-describing
    await writeFile(
      join(stage, 'manifest.json'),
      JSON.stringify({ tool: 'cipher-brain', schema: 1, host: hostname(), components }, null, 2) + '\n',
    );
    // tar the staged components into one stream, encrypt to the public recipient
    await pipe2('tar', ['-cf', '-', '-C', stage, '.'], AGE, ['-R', recipientFile, '-o', o.out]);
    const sz = (await stat(o.out)).size;
    console.log(`wrote ${o.out} (${fmtBytes(sz)}, encrypted to ${recipientFile})`);
    console.log(`components: ${components.map((c) => c.name).join(', ')}`);
  } finally {
    await rm(stage, { recursive: true, force: true });
  }
}

async function restore(o) {
  if (!o.in) throw new Error('--in <file.age> required');
  if (!o.out_dir) throw new Error('--out-dir <dir> required');
  const identity = o.identity || IDENTITY;
  if (!(await exists(identity))) throw new Error(`no identity at ${identity} — cannot decrypt without the private key`);
  await mkdir(o.out_dir, { recursive: true });
  // age -d -i identity in | tar -xf - -C out-dir
  await pipe2(AGE, ['-d', '-i', identity, o.in], 'tar', ['-xf', '-', '-C', o.out_dir]);
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
  if (!o.backend) throw new Error('--backend <file|ton> required'); // no silent default
  if (!(await exists(o.in))) throw new Error(`no such file: ${o.in}`);
  // storage must only ever see ciphertext — refuse to push a non-age artifact
  // (e.g. an accidental plaintext path), which would be the last gate before ton
  // can publish bytes externally.
  if (!(await readHead(o.in, 64)).startsWith(AGE_MAGIC)) {
    throw new Error(`${o.in} is not age ciphertext (header mismatch) — refusing to push non-ciphertext to storage`);
  }
  const locator = await backendFor(o.backend).put(o.in);
  console.error(`pushed ${o.in} -> ${o.backend}:${locator}`);
  console.log(locator); // stdout = locator ONLY, so a script can capture it
}

async function pull(o) {
  if (!o.locator) throw new Error('--locator <id> required');
  if (!o.out) throw new Error('--out <file.age> required');
  if (!o.backend) throw new Error('--backend <file|ton> required');
  await backendFor(o.backend).get(o.locator, o.out);
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
// so verify there only attests the header + that a stranger's key cannot read it.
async function verify(o) {
  if (!o.in) throw new Error('--in <file.age> required');
  const sz = (await stat(o.in)).size;
  const head = await readHead(o.in, 64);
  const isAge = head.startsWith(AGE_MAGIC);
  console.log(`file: ${o.in} (${fmtBytes(sz)})`);
  console.log(`[${isAge ? 'PASS' : 'FAIL'}] age ciphertext header present`);

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
  if (await exists(identity)) {
    try {
      await pipe2(AGE, ['-d', '-i', identity, o.in], 'tar', ['-tf', '-'], { consStdout: 'ignore' });
      console.log('[PASS] your identity decrypts the artifact into a well-formed bundle');
    } catch {
      positiveOk = false;
      console.log('[FAIL] your identity could not decrypt the artifact (corrupt/truncated, or not encrypted to you)');
    }
  } else {
    console.log('[SKIP] positive control — no private identity on this machine (public-key-only box)');
  }

  const ok = isAge && wrongKeyRejected && positiveOk;
  console.log(ok ? '\nVERDICT: PASS' : '\nVERDICT: FAIL');
  if (!ok) process.exitCode = 1;
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

  cipher-brain keygen
      Create your age keypair: identity (PRIVATE) + recipient (PUBLIC).
      Identity = ${IDENTITY}

  cipher-brain snapshot --out <file.age> [--pg <conn>] [--pg-table <t>]... [--dir <path>]... [--recipient <file>]
      Bundle a pg_dump and/or directories, encrypt to the PUBLIC recipient.
      The snapshotting machine never needs the private key.

  cipher-brain restore --in <file.age> --out-dir <dir> [--identity <file>] [--pg <conn>]
      Decrypt with the PRIVATE identity; optionally pg_restore the db.dump.

  cipher-brain verify --in <file.age>
      Assert it is real age ciphertext AND a wrong key cannot open it.

  cipher-brain push --in <file.age> --backend <file|ton>
      Upload ciphertext to storage. Prints ONLY the locator to stdout
      (file: store path; ton: hex BagID). Storage sees ciphertext only.

  cipher-brain pull --locator <id> --backend <file|ton> --out <file.age>
      Fetch ciphertext by locator into --out. Blocks until download completes.

Env: CIPHER_BRAIN_HOME (default ~/.cipher-brain), CIPHER_BRAIN_AGE, CIPHER_BRAIN_PG_BIN (dir of pg_dump/pg_restore).
Storage: CIPHER_BRAIN_FILE_DIR (file backend); CIPHER_BRAIN_TON_{CLI,API,CLIENT,SERVER,TIMEOUT} (ton backend).`;

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
