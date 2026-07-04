// keygen + identity/recipient helpers.
import { mkdir, writeFile, rm, chmod, readFile } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import { HOME, AGE, AGE_KEYGEN, IDENTITY, RECIPIENT, AGE_PUBKEY_RE } from './config.mjs';
import { run, runInteractive } from './proc.mjs';
import { exists } from './util.mjs';
import { installStageSignalGuard, setActiveRawKey } from './signal-guard.mjs';

export async function keygen(o) {
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
    setActiveRawKey(raw);
    try {
      await run(AGE_KEYGEN, ['-o', raw]);
      await chmod(raw, 0o600);
      pub = (await run(AGE_KEYGEN, ['-y', raw])).out.trim(); // derive recipient BEFORE wrapping (needs the plaintext)
      console.log('Set a passphrase to protect the identity at rest (you will enter it on restore/verify):');
      await runInteractive(AGE, ['-p', '-o', IDENTITY, raw]); // prompts for the passphrase on the TTY
      await chmod(IDENTITY, 0o600);
    } finally {
      await rm(raw, { force: true }); // never leave the unwrapped key behind
      setActiveRawKey(null);
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
export async function recipientEntries(rec) {
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
export async function resolvePinnedRecipients(val) {
  const text = (await exists(val)) ? await readFile(val, 'utf8') : val;
  const keys = new Set();
  for (const line of text.split('\n')) {
    const l = line.trim();
    if (!l || l.startsWith('#')) continue;
    for (const m of l.matchAll(AGE_PUBKEY_RE)) keys.add(m[0]);
  }
  return keys;
}
