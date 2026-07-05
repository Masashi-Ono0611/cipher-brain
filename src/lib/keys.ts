// keygen + identity/recipient helpers.
import { mkdir, writeFile, rm, chmod, readFile } from 'node:fs/promises';
import { HOME, IDENTITY, RECIPIENT, AGE_PUBKEY_RE } from './config.js';
import { generateKeypair, identityFileText, askNewPassphrase, wrapIdentity } from './crypt.js';
import { exists } from './util.js';
import type { CliOptions } from './types.js';

export async function keygen(o: CliOptions): Promise<void> {
  // 0700: HOME holds the private identity (and often the JWK wallet) — it must not be
  // world/group-listable. chmod too, in case it pre-existed with a looser mode.
  await mkdir(HOME, { recursive: true, mode: 0o700 });
  await chmod(HOME, 0o700).catch(() => {});
  if (await exists(IDENTITY)) {
    if (!o.force) {
      throw new Error(`identity already exists at ${IDENTITY} (refusing to overwrite — losing it = losing the brain). Pass --force only if you are certain.`);
    }
    await rm(IDENTITY, { force: true }); // the exclusive write below refuses to clobber, so the old key must go first
  }
  // The key is generated in-process (typage) and — on the passphrase path — wrapped
  // in memory too (#36): unlike the old external `age -p` flow there is no unwrapped
  // temp file on disk, so nothing can linger even on Ctrl-C at the prompt.
  const { identity, recipient } = await generateKeypair();
  const text = identityFileText(identity, recipient); // the standard age-keygen file layout
  let payload: string | Uint8Array = text;
  if (o.passphrase) {
    console.log('Set a passphrase to protect the identity at rest (you will enter it on restore/verify):');
    payload = await wrapIdentity(text, await askNewPassphrase()); // scrypt, same format `age -p` writes
  }
  // wx: exclusive create — a concurrent keygen that won the race must not be clobbered
  await writeFile(IDENTITY, payload, { mode: 0o600, flag: 'wx' });
  await writeFile(RECIPIENT, recipient + '\n', { mode: 0o644 });
  console.log(`identity (PRIVATE, keep offline): ${IDENTITY}${o.passphrase ? ' (passphrase-wrapped)' : ''}`);
  console.log(`recipient (PUBLIC, safe to copy):  ${RECIPIENT}`);
  console.log(`recipient = ${recipient}`);
  console.log('\n⚠  Back up the identity file now. If you lose it, the snapshots are unrecoverable.');
}

// Return EVERY recipient entry a value feeds to the encrypter: an `age1…` literal
// is one entry; anything else is read as a recipients file and split into its
// non-blank, non-comment lines (mirrors snapshot's own age1-or-file rule). We must
// enumerate whole LINES, not just age1… tokens — a non-age1 line (e.g. an injected
// `ssh-ed25519 …`) in a tampered recipient.txt would slip past an age1-only scan.
// The pin enforces the INPUTS, since age ciphertext never exposes its recipient
// pubkeys. (typage itself also rejects non-native recipients — defense in depth.)
export async function recipientEntries(rec: string): Promise<string[]> {
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
