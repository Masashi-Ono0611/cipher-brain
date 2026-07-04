// crypt — the age encryption layer, in-process via typage (npm `age-encryption`,
// FiloSottile's official TypeScript implementation of age). This replaces the
// external `age` / `age-keygen` binaries (#64): the on-disk formats are IDENTICAL
// (age-encryption.org/v1 ciphertext, the standard identity text file, scrypt
// passphrase wrapping), so pre-existing snapshots and identities keep working and
// the reference `age` binary can still read everything we write — both directions
// are asserted in CI by scripts/selftest-interop.sh.
//
// The two pipeline helpers keep the old tar|age / age|tar process-pipe semantics:
// a whole-pipeline timeout, SIGTERM→SIGKILL escalation for the tar child, and
// reject-only-after-the-child-is-dead so a caller's cleanup (rm of .part / stage /
// out-dir) can never race a still-running process that would recreate the files.
import { createReadStream, createWriteStream } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { Encrypter, Decrypter, generateIdentity, identityToRecipient } from 'age-encryption';
import { AGE_MAGIC } from './config.mjs';
import { ACTIVE_CHILDREN } from './proc.mjs';

// ---------- keys ----------

export async function generateKeypair() {
  const identity = await generateIdentity(); // X25519 (AGE-SECRET-KEY-1…)
  const recipient = await identityToRecipient(identity);
  return { identity, recipient };
}

// The standard age-keygen file layout (comments + the secret key line), so the
// identity stays drop-in usable with `age -d -i` and any other age tooling.
export function identityFileText(identity, recipient) {
  return `# created: ${new Date().toISOString()}\n# public key: ${recipient}\n${identity}\n`;
}

export function newEncrypter(recipients) {
  const e = new Encrypter();
  for (const r of recipients) {
    try {
      e.addRecipient(r);
    } catch (err) {
      // Note this is STRICTER than `age -R`, which also accepted ssh-* recipient
      // lines — typage takes native age recipients only, so a stray ssh key in a
      // recipients file is now rejected here even without the recipient pin.
      throw new Error(`invalid recipient ${JSON.stringify(r)}: ${err.message}`);
    }
  }
  return e;
}

export function newDecrypter(identities) {
  const d = new Decrypter();
  for (const i of identities) d.addIdentity(i);
  return d;
}

// scrypt-wrap an identity file's text at rest (keygen --passphrase). Same format
// `age -p` produces, so either implementation can unwrap the other's file.
export function wrapIdentity(text, passphrase) {
  const e = new Encrypter();
  e.setPassphrase(passphrase);
  return e.encrypt(text);
}

// Read an identity file and return its identity lines. A passphrase-wrapped file
// (it IS age ciphertext, so it starts with the age magic) is unwrapped first —
// prompting on the TTY, or taking CIPHER_BRAIN_PASSPHRASE for automation.
export async function loadIdentities(path) {
  const raw = await readFile(path);
  let text;
  if (raw.subarray(0, AGE_MAGIC.length).toString('latin1') === AGE_MAGIC) {
    const pass = await askPassphrase(`Enter passphrase for ${path}: `);
    try {
      text = await unwrap(raw, pass);
    } catch (e) {
      throw new Error(`could not unwrap ${path} (wrong passphrase?): ${e.message}`);
    }
  } else {
    text = raw.toString('utf8');
  }
  const ids = text.split('\n').map((l) => l.trim()).filter((l) => l && !l.startsWith('#'));
  if (ids.length === 0) throw new Error(`no identities found in ${path}`);
  return ids;
}

async function unwrap(raw, pass) {
  const d = new Decrypter();
  d.addPassphrase(pass);
  return d.decrypt(new Uint8Array(raw), 'text');
}

// ---------- passphrase prompting ----------

// CIPHER_BRAIN_PASSPHRASE (env) skips the prompt — for unattended restore/verify
// and the CI interop test. Otherwise read hidden from the TTY (like `age -p`).
export async function askPassphrase(question) {
  const env = process.env.CIPHER_BRAIN_PASSPHRASE;
  if (env) return env;
  return promptHidden(question);
}

export async function askNewPassphrase() {
  const env = process.env.CIPHER_BRAIN_PASSPHRASE;
  if (env) return env;
  const a = await promptHidden('Enter passphrase: ');
  if (!a) throw new Error('empty passphrase — refusing to wrap the identity with nothing');
  const b = await promptHidden('Confirm passphrase: ');
  if (a !== b) throw new Error('passphrases do not match');
  return a;
}

function promptHidden(question) {
  return new Promise((resolve, reject) => {
    const { stdin } = process;
    if (!stdin.isTTY) {
      return reject(new Error('a passphrase is required but stdin is not a TTY — set CIPHER_BRAIN_PASSPHRASE for non-interactive use'));
    }
    process.stderr.write(question); // prompt on stderr so stdout stays machine-readable
    const wasRaw = stdin.isRaw;
    stdin.setRawMode(true);
    stdin.resume();
    let buf = '';
    const cleanup = () => { stdin.off('data', onData); stdin.setRawMode(wasRaw); stdin.pause(); process.stderr.write('\n'); };
    const onData = (d) => {
      for (const ch of d.toString('utf8')) {
        if (ch === '\u0003') { cleanup(); return reject(new Error('interrupted')); } // Ctrl-C (raw mode eats the signal)
        if (ch === '\r' || ch === '\n') { cleanup(); return resolve(buf); }
        if (ch === '\u007f' || ch === '\b') { buf = buf.slice(0, -1); continue; }
        buf += ch;
      }
    };
    stdin.on('data', onData);
  });
}

// ---------- streaming pipelines ----------

// tar(child) stdout → typage encrypt (WebStream) → outPath, all streaming (bounded
// RSS regardless of snapshot size). Success requires BOTH the encrypted stream to be
// fully written AND the producer to exit 0: a tar that dies mid-way merely EOFs its
// stdout, which the encrypter would happily finalize into VALID ciphertext of a
// truncated archive — gating on the exit code turns that into a hard failure (the
// caller then removes the .part).
export function encryptToFile(encrypter, prodCmd, prodArgs, outPath, { timeoutMs } = {}) {
  return new Promise((resolve, reject) => {
    const prod = spawn(prodCmd, prodArgs, { stdio: ['ignore', 'pipe', 'pipe'] });
    ACTIVE_CHILDREN.add(prod);
    const out = createWriteStream(outPath);
    let pErr = '', settled = false, pipelineDone = false, prodClosed = false, timer, killTimer;
    const childExit = () => new Promise((r) => {
      if (prod.exitCode !== null || prod.signalCode !== null) return r();
      prod.once('close', r);
    });
    const fail = (e) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try { prod.kill('SIGTERM'); } catch {}
      // escalate: a SIGTERM-ignoring child must not linger holding the pipeline open
      killTimer = setTimeout(() => { try { prod.kill('SIGKILL'); } catch {} }, 2000);
      killTimer.unref?.();
      prod.stdout.destroy(); // unblock the encrypt reader so its promise settles too
      out.destroy();
      // Reject ONLY after the child is dead — the caller's catch/finally (rm of
      // .part / stage) must never race a still-writing tar (same discipline the
      // old pipe2() had; the signal guard covers signals in the meantime).
      childExit().then(() => { clearTimeout(killTimer); ACTIVE_CHILDREN.delete(prod); reject(e); });
    };
    const maybeDone = () => {
      if (settled || !pipelineDone || !prodClosed) return;
      settled = true;
      clearTimeout(timer);
      ACTIVE_CHILDREN.delete(prod);
      resolve();
    };
    if (timeoutMs) timer = setTimeout(() => fail(new Error(`${prodCmd}|age pipeline timed out after ${timeoutMs}ms`)), timeoutMs);
    prod.stderr.on('data', (d) => (pErr += d));
    prod.on('error', fail);
    prod.on('close', (code, signal) => {
      prodClosed = true;
      if (code !== 0) return fail(new Error(`${prodCmd} exited ${signal ? `on ${signal}` : code}: ${pErr.trim()}`));
      maybeDone();
    });
    (async () => {
      const ct = await encrypter.encrypt(Readable.toWeb(prod.stdout));
      await pipeline(Readable.fromWeb(ct), out);
    })().then(
      () => { pipelineDone = true; maybeDone(); },
      (e) => fail(new Error(`age encrypt failed: ${e.message}`)),
    );
  });
}

// inPath → typage decrypt (WebStream) → child (tar) stdin, all streaming. A wrong
// key / foreign ciphertext throws at the header, BEFORE the consumer sees a byte; a
// truncated or corrupt payload errors mid-stream and the whole call rejects even if
// tar exited 0 on the resulting EOF — a partial extraction must never look like
// success. Success = decrypt stream fully delivered AND the consumer exited 0.
export function decryptToChild(decrypter, inPath, consCmd, consArgs, { consStdout = 'inherit', timeoutMs } = {}) {
  return new Promise((resolve, reject) => {
    const cons = spawn(consCmd, consArgs, { stdio: ['pipe', consStdout, 'pipe'] });
    ACTIVE_CHILDREN.add(cons);
    const src = createReadStream(inPath);
    let cErr = '', settled = false, pipelineDone = false, consClosed = false, timer, killTimer;
    const childExit = () => new Promise((r) => {
      if (cons.exitCode !== null || cons.signalCode !== null) return r();
      cons.once('close', r);
    });
    const fail = (e) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try { cons.kill('SIGTERM'); } catch {}
      killTimer = setTimeout(() => { try { cons.kill('SIGKILL'); } catch {} }, 2000);
      killTimer.unref?.();
      src.destroy();
      childExit().then(() => { clearTimeout(killTimer); ACTIVE_CHILDREN.delete(cons); reject(e); });
    };
    const maybeDone = () => {
      if (settled || !pipelineDone || !consClosed) return;
      settled = true;
      clearTimeout(timer);
      ACTIVE_CHILDREN.delete(cons);
      resolve();
    };
    if (timeoutMs) timer = setTimeout(() => fail(new Error(`age|${consCmd} pipeline timed out after ${timeoutMs}ms`)), timeoutMs);
    cons.stderr.on('data', (d) => (cErr += d));
    cons.on('error', fail);
    // EPIPE when the consumer dies early — swallow on the pipe end so the real
    // failure surfaces via the close handler instead of an uncaught crash.
    cons.stdin.on('error', () => {});
    cons.on('close', (code, signal) => {
      consClosed = true;
      if (code !== 0) return fail(new Error(`${consCmd} exited ${signal ? `on ${signal}` : code}: ${cErr.trim()}`));
      maybeDone();
    });
    (async () => {
      const pt = await decrypter.decrypt(Readable.toWeb(src));
      await pipeline(Readable.fromWeb(pt), cons.stdin);
    })().then(
      () => { pipelineDone = true; maybeDone(); },
      (e) => fail(new Error(`age decrypt failed: ${e.message}`)),
    );
  });
}

// verify's negative control: a freshly generated (wrong) key must NOT open the
// artifact. The header check needs no payload read, so this is fast on any size.
export async function wrongKeyRejects(path) {
  const d = newDecrypter([await generateIdentity()]);
  const src = createReadStream(path);
  try {
    const pt = await d.decrypt(Readable.toWeb(src));
    await pt.cancel(); // should be unreachable — but never read a payload we didn't ask for
    return false;
  } catch {
    return true;
  } finally {
    src.destroy();
  }
}
