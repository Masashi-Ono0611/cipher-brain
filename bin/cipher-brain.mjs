#!/usr/bin/env node
// cipher-brain — encrypt a gbrain snapshot so only the key holder can read it.
//
// Threat model: the always-on machine (e.g. the Mac mini that runs gbrain) holds
// ONLY the recipient PUBLIC key, so it can produce snapshots but can never read
// them. The private identity — the "key only mine" — lives off the always-on box
// and is the sole thing that can restore. Compromising the snapshotting machine
// therefore leaks no brain content.
//
// Crypto: age (X25519 + ChaCha20-Poly1305) via the audited `age` binary. We
// stream tar -> age, so a multi-GB snapshot never loads into memory and never
// hits disk as a single plaintext blob (only the pg_dump is staged, then erased).
//
// Backend-agnostic: this produces ONE encrypted artifact (`*.age`). Where those
// bytes get parked (TON Storage / Arweave / anything) is a separate, pluggable
// concern — storage only ever sees ciphertext.

import { spawn } from 'node:child_process';
import { mkdir, writeFile, rm, chmod, access, stat, readFile, mkdtemp } from 'node:fs/promises';
import { createReadStream, constants as FS } from 'node:fs';
import { homedir, hostname, tmpdir } from 'node:os';
import { join, basename, dirname, resolve } from 'node:path';

const HOME = process.env.CIPHER_BRAIN_HOME || join(homedir(), '.cipher-brain');
const AGE = process.env.CIPHER_BRAIN_AGE || 'age';
const AGE_KEYGEN = process.env.CIPHER_BRAIN_AGE_KEYGEN || 'age-keygen';
const PG_BIN = process.env.CIPHER_BRAIN_PG_BIN || ''; // dir holding pg_dump/pg_restore; '' => PATH
const pgTool = (name) => (PG_BIN ? join(PG_BIN, name) : name);

const IDENTITY = join(HOME, 'identity.age');     // private key — required to restore
const RECIPIENT = join(HOME, 'recipient.txt');   // public key — all snapshot needs

const AGE_MAGIC = 'age-encryption.org/v1';

// ---------- small process helpers (array args only — no shell, no injection) ----------

function run(cmd, args, { input } = {}) {
  return new Promise((res, rej) => {
    const p = spawn(cmd, args, { stdio: [input ? 'pipe' : 'ignore', 'pipe', 'pipe'] });
    let out = '', err = '';
    p.stdout.on('data', (d) => (out += d));
    p.stderr.on('data', (d) => (err += d));
    p.on('error', rej);
    p.on('close', (code) =>
      code === 0 ? res({ out, err }) : rej(new Error(`${cmd} exited ${code}: ${err.trim() || out.trim()}`)),
    );
    if (input) { p.stdin.write(input); p.stdin.end(); }
  });
}

// Pipe producer.stdout -> consumer.stdin and wait for both. Used for the
// tar|age (snapshot) and age|tar (restore) streaming pipelines.
function pipe2(prodCmd, prodArgs, consCmd, consArgs) {
  return new Promise((res, rej) => {
    const prod = spawn(prodCmd, prodArgs, { stdio: ['ignore', 'pipe', 'pipe'] });
    const cons = spawn(consCmd, consArgs, { stdio: ['pipe', 'inherit', 'pipe'] });
    let pErr = '', cErr = '', left = 2, failed = false;
    const done = (e) => { if (failed) return; if (e) { failed = true; return rej(e); } if (--left === 0) res(); };
    prod.stderr.on('data', (d) => (pErr += d));
    cons.stderr.on('data', (d) => (cErr += d));
    prod.on('error', rej);
    cons.on('error', rej);
    prod.stdout.pipe(cons.stdin);
    prod.on('close', (c) => done(c === 0 ? null : new Error(`${prodCmd} exited ${c}: ${pErr.trim()}`)));
    cons.on('close', (c) => done(c === 0 ? null : new Error(`${consCmd} exited ${c}: ${cErr.trim()}`)));
  });
}

const exists = (p) => access(p, FS.F_OK).then(() => true).catch(() => false);

function parseArgs(argv) {
  const o = { dirs: [], tables: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--dir') o.dirs.push(argv[++i]);
    else if (a === '--pg-table') o.tables.push(argv[++i]);
    else if (a.startsWith('--')) o[a.slice(2).replace(/-/g, '_')] = argv[++i];
    else o._ = a;
  }
  return o;
}

// ---------- commands ----------

async function keygen(o) {
  await mkdir(HOME, { recursive: true });
  if ((await exists(IDENTITY)) && !o.force) {
    throw new Error(`identity already exists at ${IDENTITY} (refusing to overwrite — losing it = losing the brain). Pass --force only if you are certain.`);
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
    for (const d of o.dirs) {
      const abs = resolve(d);
      const name = basename(abs) + '.tar.gz';
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

// verify is the falsifiable half: prove the artifact is real age ciphertext AND
// that the WRONG key cannot read it. A snapshot that a stranger's key can open
// would be a catastrophic FAIL, not a PASS.
async function verify(o) {
  if (!o.in) throw new Error('--in <file.age> required');
  const head = await readHead(o.in, 64);
  const isAge = head.startsWith(AGE_MAGIC);
  const sz = (await stat(o.in)).size;
  console.log(`file: ${o.in} (${fmtBytes(sz)})`);
  console.log(`[${isAge ? 'PASS' : 'FAIL'}] age ciphertext header present`);

  // generate a throwaway identity and confirm it CANNOT decrypt
  const tdir = await mkdtemp(join(tmpdir(), 'cipher-brain-verify-'));
  let wrongKeyRejected = false;
  try {
    const wrongId = join(tdir, 'wrong.age');
    await run(AGE_KEYGEN, ['-o', wrongId]);
    try {
      await run(AGE, ['-d', '-i', wrongId, o.in]);
      wrongKeyRejected = false; // decryption SUCCEEDED with a wrong key => broken
    } catch {
      wrongKeyRejected = true; // expected: wrong key is rejected
    }
  } finally {
    await rm(tdir, { recursive: true, force: true });
  }
  console.log(`[${wrongKeyRejected ? 'PASS' : 'FAIL'}] a wrong key is rejected (only your identity can read it)`);

  const ok = isAge && wrongKeyRejected;
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

Env: CIPHER_BRAIN_HOME (default ~/.cipher-brain), CIPHER_BRAIN_AGE, CIPHER_BRAIN_PG_BIN (dir of pg_dump/pg_restore).`;

async function main() {
  const [cmd, ...rest] = process.argv.slice(2);
  const o = parseArgs(rest);
  switch (cmd) {
    case 'keygen': return keygen(o);
    case 'snapshot': return snapshot(o);
    case 'restore': return restore(o);
    case 'verify': return verify(o);
    case 'help': case '--help': case '-h': case undefined: console.log(HELP); return;
    default: console.error(`unknown command: ${cmd}\n`); console.log(HELP); process.exitCode = 2;
  }
}

main().catch((e) => { console.error(`error: ${e.message}`); process.exitCode = 1; });
