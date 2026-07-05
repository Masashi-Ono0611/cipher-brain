// push/pull move the ciphertext to/from a storage backend. The verb is a dumb
// primitive against ONE backend endpoint; proving "fetched from elsewhere" (a
// second, independent node) is the operator script's job, not the verb's.
import { mkdir, writeFile, rm, readFile, rename } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { randomBytes } from 'node:crypto';
import { AGE_MAGIC, CIPHER_YES } from './config.mjs';
import { exists, sleep, sha256, readHead } from './util.mjs';
import { backendFor } from './backends/index.mjs';

// The plaintext content digest for the artifact being pushed: an explicit --digest
// wins, else the "<in>.digest" sidecar snapshot writes next to its output. Returns
// lowercased hex or null — never throws: the digest only powers the --skip-unchanged
// optimization and the 4th save-locator field, so a missing/unreadable piece must
// degrade to "no digest" (proceed normally), never to an error.
async function contentDigestFor(o) {
  if (o.digest) return String(o.digest).trim().toLowerCase();
  try {
    const line = (await readFile(`${o.in}.digest`, 'utf8')).split('\n').map((l) => l.trim()).find((l) => l && !l.startsWith('#'));
    return line ? line.toLowerCase() : null;
  } catch { return null; }
}

// The recipients fingerprint for the artifact being pushed: read from the
// "<in>.recipients-fingerprint" sidecar snapshot writes next to its output. Mirrors
// contentDigestFor's contract exactly (never throws — a missing/unreadable sidecar
// just means "unknown", not an error). This is the SEPARATE signal (alongside, never
// mixed into, content_digest) that --skip-unchanged additionally requires to match:
// without it, an unchanged plaintext re-encrypted to a DIFFERENT recipient set (a
// newly added offline recovery key, or a removed/revoked key) would still return the
// OLD locator — the new key could never decrypt it, and/or a revoked key still could
// (#70 review round 2, a real security regression, not just a correctness nit).
async function recipientsFingerprintFor(o) {
  try {
    const line = (await readFile(`${o.in}.recipients-fingerprint`, 'utf8')).split('\n').map((l) => l.trim()).find((l) => l && !l.startsWith('#'));
    return line ? line.toLowerCase() : null;
  } catch { return null; }
}

// Parse the FIRST locator line of a save-locator file into its (up to 5) fields.
// Returns null when the file is missing/empty — callers treat that as "no previous
// push recorded". The 3-field legacy format, the 4-field one (+content_digest) and
// the 5-field one (+recipients_fingerprint) all parse here identically.
async function readSavedLocatorLine(path) {
  let text;
  try { text = await readFile(path, 'utf8'); } catch { return null; }
  const line = text.split('\n').map((l) => l.trim()).find((l) => l && !l.startsWith('#'));
  if (!line) return null;
  const [locator, backend, sha, contentDigest, recipientsFingerprint] = line.split('\t');
  return { locator, backend, sha, contentDigest, recipientsFingerprint };
}

export async function push(o) {
  if (!o.in) throw new Error('--in <file.age> required');
  if (!o.backend) throw new Error('--backend <file|ton|arweave|turbo> required'); // no silent default
  if (!(await exists(o.in))) throw new Error(`no such file: ${o.in}`);
  // storage must only ever see ciphertext — refuse to push a non-age artifact
  // (e.g. an accidental plaintext path), which would be the last gate before a
  // backend can publish bytes externally.
  if (!(await readHead(o.in, 64)).startsWith(AGE_MAGIC)) {
    throw new Error(`${o.in} is not age ciphertext (header mismatch) — refusing to push non-ciphertext to storage`);
  }
  // --skip-unchanged: don't re-push (and, on arweave/turbo, re-pay for) content that
  // has not changed since the previous push. TWO independent signals must BOTH match
  // the current --save-locator entry for the same backend before a skip fires:
  //   1. the PLAINTEXT content digest (the "<out>.digest" sidecar) — it can never be
  //      the ciphertext hash, because age's ephemeral file key makes identical content
  //      encrypt to different bytes every run;
  //   2. the recipients fingerprint (the "<out>.recipients-fingerprint" sidecar) — the
  //      set of age1… keys THIS ciphertext was actually encrypted to. Without this
  //      second check, re-snapshotting unchanged plaintext under a CHANGED recipient
  //      set (a newly added offline recovery key, or a removed/revoked one) would
  //      still skip and return the OLD locator — whose ciphertext the new key can
  //      never decrypt, and/or a revoked key still can (#70 review round 2, a real
  //      security regression, not just a correctness nit).
  // Both are compared against the current --save-locator file's fields (4th =
  // content_digest, 5th = recipients_fingerprint). Any missing piece on EITHER side
  // (no sidecar/--digest, a legacy 3/4-field file, a different backend) proceeds
  // normally: skip is an optimization that only fires when BOTH signals are known and
  // equal — an unknown signal must never be treated as "unchanged". --force pushes
  // anyway. Checked before the paid-backend consent gate: a skipped push contacts
  // nothing and spends nothing.
  if (o.skip_unchanged) {
    if (!o.save_locator) throw new Error('--skip-unchanged requires --save-locator <file> (the previous content digest and recipients fingerprint live in its 4th/5th fields)');
    if (!o.force) {
      const cur = await contentDigestFor(o);
      const curRecipients = await recipientsFingerprintFor(o);
      const prev = await readSavedLocatorLine(o.save_locator);
      const contentUnchanged = cur && prev && prev.locator && prev.backend === o.backend && prev.contentDigest && prev.contentDigest.toLowerCase() === cur;
      const recipientsUnchanged = curRecipients && prev && prev.recipientsFingerprint && prev.recipientsFingerprint.toLowerCase() === curRecipients;
      if (contentUnchanged && recipientsUnchanged) {
        console.error(`SKIPPED: content and recipients unchanged (digest ${cur}) — already pushed to ${o.backend} as ${prev.locator} (--force to push anyway)`);
        console.log(prev.locator); // stdout contract unchanged: a script still captures a valid locator
        return;
      }
    }
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
    // Record "<locator>\t<backend>\t<sha256>[\t<content_digest>[\t<recipients_fingerprint>]]".
    // The sha256 — computed here off the bytes we just pushed — binds the locator to
    // its ciphertext, so a recovery via --from-locator-file is fail-closed: for
    // arweave/turbo (locator != content hash) a gateway/storage attacker can't later
    // serve a substituted, still-age-decryptable artifact. The hash is trustworthy
    // because this file is backed up OFF-BOX (the same trusted-source rule the
    // existing --sha256 pin relies on). The 4th field is the PLAINTEXT content digest
    // (from the "<in>.digest" sidecar / --digest); the 5th is the recipients
    // fingerprint (from the "<in>.recipients-fingerprint" sidecar) — both are the
    // comparison targets for the next push --skip-unchanged. The 5th field is only
    // ever written alongside a present 4th (never in its place — a positional format
    // can't safely encode "5th but not 4th"); omitted when no signal is available
    // (parsers accept all three widths).
    const digest = await sha256(o.in);
    const contentDigest = await contentDigestFor(o);
    const recipientsFingerprint = await recipientsFingerprintFor(o);
    const fields = [locator, o.backend, digest];
    if (contentDigest) {
      fields.push(contentDigest);
      if (recipientsFingerprint) fields.push(recipientsFingerprint);
    }
    // Atomic write: a crash / ENOSPC mid-rewrite must not leave the recovery pointer
    // empty AND destroy the previous good locator. Write a temp sibling, then rename.
    const tmp = `${o.save_locator}.${process.pid}.${randomBytes(4).toString('hex')}.tmp`;
    try {
      await writeFile(tmp, `${fields.join('\t')}\n`, { flag: 'w' });
      await rename(tmp, o.save_locator);
    } catch (e) {
      await rm(tmp, { force: true });
      throw e;
    }
    console.error(`locator saved -> ${o.save_locator}`);
  }
  console.log(locator); // stdout = locator ONLY, so a script can capture it
}

export async function pull(o) {
  // --from-locator-file <path>: read the locator (and its backend) from a file written
  // by `push --save-locator`. This is the recovery path — a fresh machine that holds
  // only the identity + this one small file (both backed up off-box) can restore the
  // latest snapshot without ever having seen index.tsv. Explicit --locator/--backend
  // still win if both are also given.
  if (o.from_locator_file) {
    if (!(await exists(o.from_locator_file))) throw new Error(`no such locator file: ${o.from_locator_file}`);
    const line = (await readFile(o.from_locator_file, 'utf8')).split('\n').map((l) => l.trim()).find((l) => l && !l.startsWith('#'));
    if (!line) throw new Error(`locator file ${o.from_locator_file} has no locator line`);
    // Accept the legacy 3-field line, the 4-field one (a trailing content_digest,
    // written since --skip-unchanged) AND the 5-field one (+recipients_fingerprint):
    // recovery of every existing save-locator file must keep working, so extra
    // columns are simply ignored here.
    const [savedLoc, savedBackend, savedSha] = line.split('\t');
    // A truncated / hand-mangled file missing the backend column would otherwise fall
    // through to the generic "--backend required" error, hiding the real cause.
    if (!savedLoc || !savedBackend) {
      throw new Error(`locator file ${o.from_locator_file} must contain "<locator>\\t<backend>[\\t<sha256>[\\t<content_digest>[\\t<recipients_fingerprint>]]]" — got: ${JSON.stringify(line)}`);
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
