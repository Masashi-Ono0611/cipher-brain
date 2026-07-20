// keygen + identity/recipient helpers.
import { mkdir, writeFile, rm, rename, chmod, readFile } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import { HOME, IDENTITY, RECIPIENT, AGE_PUBKEY_RE } from './config.js';
import { generateKeypair, identityFileText, askNewPassphrase, wrapIdentity } from './crypt.js';
import { exists } from './util.js';
import type { CliOptions } from './types.js';

// Core of keygen(), parameterized over WHERE to write (home dir + identity/recipient
// paths) instead of the global HOME/IDENTITY/RECIPIENT constants — extracted so a
// second caller (the `init` wizard, src/lib/wizard.ts) can generate a keypair at a
// wizard-chosen path (e.g. an offline backup keypair under `<HOME>-backup`) using the
// EXACT SAME generation logic keygen() uses, instead of a duplicated hand-roll. This
// refactor changes NO observable behavior of keygen() itself (same checks, same
// writes, same exclusive-create semantics) — keygen() below is now a thin wrapper
// that calls this with the module's global paths and prints its existing messages.
export interface KeygenAtOpts {
  home: string;
  identityPath: string;
  recipientPath: string;
  passphrase?: boolean;
  force?: boolean;
}

export interface KeygenAtResult {
  recipient: string;
  wrapped: boolean;
}

// Write `payload` to `path`, choosing an ordering that never destroys an existing
// file before its replacement is fully durable on disk (#122):
//  - !force: exclusive create ('wx') directly at `path` — the OS itself refuses if
//    something is already there. This also catches a concurrent keygen that raced
//    past keygenAt()'s own pre-flight exists() check below (the same TOCTOU guard
//    the original identity write already relied on).
//  - force: `path` may legitimately hold the file being REPLACED. The new payload
//    is written to a freshly, exclusively-created sibling temp file FIRST, and only
//    THEN rename()'d over `path` — an atomic swap (same technique wizard.ts's own
//    recovery-kit write and snapshot.ts's promoteSnapshot() already use). `path`'s
//    old content is only ever touched by the rename succeeding, i.e. once the new
//    payload already sits fully-written on disk — so a failure BEFORE this point
//    (e.g. a mistyped passphrase confirmation, Ctrl-C) can never delete anything.
async function writeKeyFile(path: string, payload: string | Uint8Array, mode: number, force: boolean): Promise<void> {
  if (!force) {
    await writeFile(path, payload, { mode, flag: 'wx' });
    return;
  }
  const tmp = `${path}.${process.pid}.${randomBytes(4).toString('hex')}.tmp`;
  await writeFile(tmp, payload, { mode, flag: 'wx' });
  try {
    await rename(tmp, path);
  } catch (e) {
    await rm(tmp, { force: true });
    throw e;
  }
}

export async function keygenAt(opts: KeygenAtOpts): Promise<KeygenAtResult> {
  // 0700: the home dir holds the private identity (and often the JWK wallet) — it must
  // not be world/group-listable. chmod too, in case it pre-existed with a looser mode.
  // Fail closed (#119): if this chmod fails (owner mismatch from an earlier sudo/root
  // creation, a read-only mount, an immutable attribute, ...) do NOT silently proceed
  // to write a secret identity into a directory whose permissions could not be
  // verified/corrected — propagate the error instead of swallowing it.
  await mkdir(opts.home, { recursive: true, mode: 0o700 });
  await chmod(opts.home, 0o700);

  // Both targets are checked BEFORE anything is generated or written (#121):
  // recipient.txt now gets the SAME no-clobber protection identity.age already had,
  // instead of the plain writeFile() the code below used to fall through to, which
  // silently truncated/replaced an existing recipient.txt with no --force gate at
  // all — letting whoever can trigger a keygen re-key every FUTURE snapshot a
  // pinned recipient.txt was meant to protect against. Checked identity-first so the
  // (unchanged) identity refusal still wins when BOTH already exist.
  if (await exists(opts.identityPath) && !opts.force) {
    throw new Error(`identity already exists at ${opts.identityPath} (refusing to overwrite — losing it = losing the brain). Pass --force only if you are certain.`);
  }
  if (await exists(opts.recipientPath) && !opts.force) {
    throw new Error(`recipient already exists at ${opts.recipientPath} (refusing to overwrite — a silently re-keyed recipient.txt would re-key every FUTURE snapshot). Pass --force only if you are certain.`);
  }
  // The key is generated in-process (typage) and — on the passphrase path — wrapped
  // in memory too (#36): unlike the old external `age -p` flow there is no unwrapped
  // temp file on disk, so nothing can linger even on Ctrl-C at the prompt.
  const { identity, recipient } = await generateKeypair();
  const text = identityFileText(identity, recipient); // the standard age-keygen file layout
  let payload: string | Uint8Array = text;
  let wrapped = false;
  if (opts.passphrase) {
    console.log('Set a passphrase to protect the identity at rest (you will enter it on restore/verify):');
    payload = await wrapIdentity(text, await askNewPassphrase()); // scrypt, same format `age -p` writes
    wrapped = true;
  }
  // Both the new identity and the new recipient are fully prepared by this point —
  // only from here on is an existing file (--force) ever touched, and even then via
  // write-new-then-rename, never delete-then-write (#122; see writeKeyFile above).
  await writeKeyFile(opts.identityPath, payload, 0o600, !!opts.force);
  await writeKeyFile(opts.recipientPath, recipient + '\n', 0o644, !!opts.force);
  return { recipient, wrapped };
}

export async function keygen(o: CliOptions): Promise<void> {
  const { recipient, wrapped } = await keygenAt({ home: HOME, identityPath: IDENTITY, recipientPath: RECIPIENT, passphrase: o.passphrase, force: o.force });
  console.log(`identity (PRIVATE, keep offline): ${IDENTITY}${wrapped ? ' (passphrase-wrapped)' : ''}`);
  console.log(`recipient (PUBLIC, safe to copy):  ${RECIPIENT}`);
  console.log(`recipient = ${recipient}`);
  console.log('\n⚠  Back up the identity file now. If you lose it, the snapshots are unrecoverable.');
}

// Return EVERY recipient entry a value feeds to the encrypter: an existing path is
// read as a recipients file and split into its non-blank, non-comment lines;
// anything else is treated as one literal (typically `age1…`) entry. File-existence
// is checked FIRST (#120) — the same precedence resolvePinnedRecipients() below
// deliberately uses — so a recipients FILE whose name happens to start with `age1`
// (e.g. `age1-backup-keys.txt`) is read as a file, not mistaken for an inline
// literal. We must enumerate whole LINES, not just age1… tokens — a non-age1 line
// (e.g. an injected `ssh-ed25519 …`) in a tampered recipient.txt would slip past an
// age1-only scan. The pin enforces the INPUTS, since age ciphertext never exposes
// its recipient pubkeys. (typage itself also rejects non-native recipients —
// defense in depth.)
export async function recipientEntries(rec: string): Promise<string[]> {
  if (!(await exists(rec))) return [rec.trim()];
  const text = await readFile(rec, 'utf8');
  return text.split('\n').map((l) => l.trim()).filter((l) => l && !l.startsWith('#'));
}

// Resolve CIPHER_BRAIN_PIN_RECIPIENTS to a set of allowed pubkeys. File-first: if the
// value names an existing file, read it (so a path that happens to contain "age1",
// e.g. age1-pins.txt, is not mistaken for an inline list); otherwise treat the value
// itself as an inline list of age1… keys. Parsed line-by-line, SKIPPING comment lines
// (mirrors recipientEntries) — a key left commented-out (e.g. a rotated/revoked one)
// must NOT count as allowed, or the pin could be defeated by a stale comment.
export async function resolvePinnedRecipients(val: string): Promise<Set<string>> {
  const text = (await exists(val)) ? await readFile(val, 'utf8') : val;
  const keys = new Set<string>();
  for (const line of text.split('\n')) {
    const l = line.trim();
    if (!l || l.startsWith('#')) continue;
    for (const m of l.matchAll(AGE_PUBKEY_RE)) keys.add(m[0]);
  }
  return keys;
}
