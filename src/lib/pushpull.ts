// push/pull move the ciphertext to/from a storage backend. The verb is a dumb
// primitive against ONE backend endpoint; proving "fetched from elsewhere" (a
// second, independent node) is the operator script's job, not the verb's.
import { mkdir, writeFile, rm, readFile, rename, link, stat } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { randomBytes } from 'node:crypto';
import { AGE_MAGIC, CIPHER_YES } from './config.js';
import { exists, sleep, sha256, readHead, errMsg, RetryableError } from './util.js';
import { backendFor } from './backends/index.js';
import { estimateCost, formatEstimate } from './estimate.js';
import type { CliOptions } from './types.js';

// The plaintext content digest for the artifact being pushed: an explicit --digest
// wins, else the "<in>.digest" sidecar snapshot writes next to its output. Returns
// lowercased hex or null — never throws: the digest only powers the --skip-unchanged
// optimization and the 4th save-locator field, so a missing/unreadable piece must
// degrade to "no digest" (proceed normally), never to an error.
async function contentDigestFor(o: CliOptions): Promise<string | null> {
  if (o.digest) return String(o.digest).trim().toLowerCase();
  try {
    const line = (await readFile(`${o.in}.digest`, 'utf8'))
      .split('\n')
      .map((l) => l.trim())
      .find((l) => l && !l.startsWith('#'));
    return line ? line.toLowerCase() : null;
  } catch {
    return null;
  }
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
async function recipientsFingerprintFor(o: CliOptions): Promise<string | null> {
  try {
    const line = (await readFile(`${o.in}.recipients-fingerprint`, 'utf8'))
      .split('\n')
      .map((l) => l.trim())
      .find((l) => l && !l.startsWith('#'));
    return line ? line.toLowerCase() : null;
  } catch {
    return null;
  }
}

// Thrown when backend.put() (the actual, possibly PAID/PERMANENT upload) already
// succeeded but the LOCAL --save-locator bookkeeping afterward (mkdir, digest, the
// temp-write+rename) then threw. This is the ONE failure shape a caller must treat
// completely differently from every other push() error: the remote artifact already
// exists (and, on arweave/turbo, money was already spent) — a caller that reacts to
// ANY push() rejection by assuming "nothing happened yet" (e.g. deleting the only
// identity that can decrypt what was just uploaded) would turn a mere bookkeeping
// hiccup into permanent, unrecoverable loss. `locator` is carried on the error
// itself because this is the only place that value still exists once push() has
// otherwise failed to persist it anywhere.
export class PushLocatorWriteError extends Error {
  readonly locator: string;
  constructor(locator: string, cause: unknown) {
    super(
      `upload succeeded (locator: ${locator}) but writing --save-locator failed: ${cause instanceof Error ? cause.message : String(cause)}`,
    );
    this.name = 'PushLocatorWriteError';
    this.locator = locator;
  }
}

interface SavedLocator {
  locator: string;
  backend: string;
  sha: string | undefined;
  contentDigest: string | undefined;
  recipientsFingerprint: string | undefined;
  sigLocator: string | undefined; // #214: where the "<in>.minisig" sidecar was pushed, if any
}

// Parse the FIRST locator line of a save-locator file into its (up to 6) fields.
// Returns null when the file is missing/empty — callers treat that as "no previous
// push recorded". The 3-field legacy format, the 4-field one (+content_digest), the
// 5-field one (+recipients_fingerprint) and the 6-field one (+sig_locator, #214) all
// parse here identically.
async function readSavedLocatorLine(path: string): Promise<SavedLocator | null> {
  let text: string;
  try {
    text = await readFile(path, 'utf8');
  } catch {
    return null;
  }
  const line = text
    .split('\n')
    .map((l) => l.trim())
    .find((l) => l && !l.startsWith('#'));
  if (!line) return null;
  const [locator, backend, sha, contentDigest, recipientsFingerprint, sigLocator] = line.split('\t');
  return { locator, backend, sha, contentDigest, recipientsFingerprint, sigLocator };
}

// Returns whether an upload actually happened: false for the --skip-unchanged
// early return below (nothing was pushed), true once backend.put() has really
// run. cli.ts uses this (not the raw --backend flag alone) to decide whether a
// push actually reached a paid backend — issue #195: a SKIPPED push must never
// be treated as "an upload succeeded".
export async function push(o: CliOptions): Promise<boolean> {
  if (!o.in) throw new Error('--in <file.age> required');
  if (!o.backend) throw new Error('--backend <file|arweave|turbo|rclone> required'); // no silent default
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
    if (!o.save_locator)
      throw new Error(
        '--skip-unchanged requires --save-locator <file> (the previous content digest and recipients fingerprint live in its 4th/5th fields)',
      );
    if (!o.force) {
      const cur = await contentDigestFor(o);
      const curRecipients = await recipientsFingerprintFor(o);
      const prev = await readSavedLocatorLine(o.save_locator);
      const contentUnchanged = !!(
        cur &&
        prev?.locator &&
        prev.backend === o.backend &&
        prev.contentDigest &&
        prev.contentDigest.toLowerCase() === cur
      );
      const recipientsUnchanged = !!(
        curRecipients &&
        prev?.recipientsFingerprint &&
        prev.recipientsFingerprint.toLowerCase() === curRecipients
      );
      if (contentUnchanged && recipientsUnchanged && prev) {
        console.error(
          `SKIPPED: content and recipients unchanged (digest ${cur}) — already pushed to ${o.backend} as ${prev.locator} (--force to push anyway)`,
        );
        console.log(prev.locator); // stdout contract unchanged: a script still captures a valid locator
        return false;
      }
    }
  }
  // arweave and turbo are paid, permanent stores. #160: the cost estimate must be
  // VISIBLE in the SAME terminal output the --yes/CIPHER_BRAIN_YES consent decision is
  // made against — previously push() asked "this spends real funds, confirm?" with no
  // number attached, and the actual estimate (ar.transactions.getPrice() in
  // arweave.ts / getUploadCosts() in turbo.ts) only ran INSIDE backend.put(), i.e. only
  // AFTER the operator had already said yes. Compute + print it FIRST here, using the
  // exact estimateCost() math the `estimate` command and the MCP estimate_cost tool
  // already use (src/lib/estimate.ts, #159) — not a second, divergent computation —
  // so a blind "--yes" is no longer required to learn the amount.
  //
  // This step is deliberately display-only: CIPHER_BRAIN_MAX_SPEND enforcement stays
  // exactly where #105's fail-closed fix left it, INSIDE each backend's put()
  // (arweave.ts/turbo.ts — verified unchanged, git log --grep 105 / -- those files).
  // Duplicating the cap check here would create a second enforcement point to keep in
  // sync, and this early estimate can go stale by the time put() actually signs
  // (a real, independent price query, moments apart) — the backend's own re-check
  // immediately before signing is, and remains, the sole authority on whether an
  // upload proceeds. Skipped for the free `file` backend (no cost, nothing to show).
  if (o.backend === 'arweave' || o.backend === 'turbo') {
    const { size: sizeBytes } = await stat(o.in);
    const est = await estimateCost(o.backend, sizeBytes);
    // Wording deliberately avoids the literal substring "--yes"/"CIPHER_BRAIN_YES" here:
    // selftest.sh's "CIPHER_BRAIN_YES=1 no longer hits the gate" check greps stderr for
    // those tokens to detect the ACTUAL consent-gate error below — this informational
    // header must never produce a false match of that check.
    console.error(`${o.backend}: cost estimate (shown before the upload-consent check below):`);
    for (const line of formatEstimate(est)) console.error(`  ${line}`);
  }
  const yes = !!o.yes || CIPHER_YES;
  // arweave and turbo are paid, permanent stores — require an explicit opt-in so
  // an unattended cadence loop doesn't silently accumulate charges. Set CIPHER_BRAIN_YES=1
  // in the nightly script (or pass --yes) to skip this prompt in automation.
  if ((o.backend === 'arweave' || o.backend === 'turbo') && !yes) {
    throw new Error(
      `${o.backend}: uploading to a permanent Arweave store spends real funds — ` +
        `re-run push with --yes or set CIPHER_BRAIN_YES=1 in the environment to confirm`,
    );
  }
  const backend = await backendFor(o.backend);
  // `remote` is only meaningful to the rclone backend (its --remote <name>:<path>
  // destination — types.ts's PutOpts) — every other backend's put() ignores it, same
  // as `yes` is only meaningful to arweave/turbo.
  const locator = await backend.put(o.in, { yes, remote: o.remote });
  console.error(`pushed ${o.in} -> ${o.backend}:${locator}`);
  // Authenticity sidecar (#214): if snapshot() wrote a "<in>.minisig" next to the
  // ciphertext, upload it too — same backend, same already-granted consent (`yes`
  // covers the whole push() call, not a per-file re-prompt for a few-hundred-byte
  // signature). Automatic whenever the sidecar exists; a pre-#214 push (no sidecar)
  // is byte-for-byte unchanged. The rclone backend needs its OWN distinct --remote
  // destination per file (its locator IS that destination string, unlike every other
  // backend's content-addressed/post-assigned one) — derived here as "<remote>.minisig",
  // a deterministic sibling of the ciphertext's own --remote.
  const sigPath = `${o.in}.minisig`;
  let sigLocator: string | undefined;
  if (await exists(sigPath)) {
    sigLocator = await backend.put(sigPath, { yes, remote: o.remote ? `${o.remote}.minisig` : undefined });
    console.error(`pushed ${sigPath} -> ${o.backend}:${sigLocator}`);
  }
  // --save-locator <path>: persist the returned locator so operators can back it up
  // alongside their identity (the two things a fresh machine needs to restore).
  // The file is rewritten on each push — it always holds the most recent locator.
  // Everything from here on is LOCAL bookkeeping AFTER the upload above already
  // succeeded — the point of no return already passed. Wrap the whole block so any
  // failure here (ENOSPC, a permission error, a directory sitting where the locator
  // file should be, ...) surfaces as PushLocatorWriteError instead of an ordinary
  // Error: a caller must be able to tell "the upload itself never happened" apart
  // from "the upload happened, only recording where it went then failed" — the two
  // demand opposite recovery behavior (see wizard.ts's push() catch for the caller
  // that actually depends on this distinction).
  if (o.save_locator) {
    try {
      await mkdir(dirname(resolve(o.save_locator)), { recursive: true });
      // Record "<locator>\t<backend>\t<sha256>[\t<content_digest>[\t<recipients_fingerprint>[\t<sig_locator>]]]".
      // The sha256 — computed here off the bytes we just pushed — binds the locator to
      // its ciphertext, so a recovery via --from-locator-file is fail-closed: for
      // arweave/turbo (locator != content hash) a gateway/storage attacker can't later
      // serve a substituted, still-age-decryptable artifact. The hash is trustworthy
      // because this file is backed up OFF-BOX (the same trusted-source rule the
      // existing --sha256 pin relies on). The 4th field is the PLAINTEXT content digest
      // (from the "<in>.digest" sidecar / --digest); the 5th is the recipients
      // fingerprint (from the "<in>.recipients-fingerprint" sidecar) — both are the
      // comparison targets for the next push --skip-unchanged. The 6th (#214) is where
      // the "<in>.minisig" sidecar landed, if one was pushed above — pull's
      // --from-locator-file reads it back to also fetch the signature alongside the
      // ciphertext. This is a POSITIONAL format, so sigLocator can only occupy the 6th
      // slot if slots 4/5 exist too — when contentDigest/recipientsFingerprint are
      // themselves missing (an --in not produced by this cipher-brain's own snapshot,
      // e.g. a foreign or pre-digest-era artifact) they're written as empty fields
      // rather than omitted, so sigLocator still lands in its correct position instead
      // of silently being dropped (readSavedLocatorLine's positional destructuring reads
      // an empty field as falsy, same as a genuinely-absent one, for --skip-unchanged).
      const digest = await sha256(o.in);
      const contentDigest = await contentDigestFor(o);
      const recipientsFingerprint = await recipientsFingerprintFor(o);
      const fields = [locator, o.backend, digest];
      if (contentDigest || recipientsFingerprint || sigLocator) {
        fields.push(contentDigest ?? '');
        if (recipientsFingerprint || sigLocator) {
          fields.push(recipientsFingerprint ?? '');
          if (sigLocator) fields.push(sigLocator);
        }
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
    } catch (e) {
      throw new PushLocatorWriteError(locator, e);
    }
  }
  console.log(locator); // stdout = locator ONLY, so a script can capture it
  return true;
}

// Promote a completed pull's temp part to --out, no-clobber (#107). Mirrors
// snapshot.ts's promoteSnapshot exactly: prefer link(), atomic and fails with EEXIST if
// `out` appeared meanwhile — a true exclusive no-clobber even under overlapping pulls.
// Hard links are unsupported on exFAT/FAT and some network/cloud mounts (common backup
// media), where link throws EPERM/ENOTSUP — there, fall back to an exclusive create
// (writeFile with the 'wx' flag) as the no-clobber GATE instead of a racy
// exists()-then-rename() check-then-act: 'wx' atomically fails with EEXIST if `out`
// already exists, so of two overlapping pulls at most one can win the create — the
// loser sees EEXIST and refuses, same as the link() path. The winner then owns `out`
// and folds the real content in via rename() (itself atomic). Residual: an unclean kill
// between the create and the rename can leave an empty placeholder at `out` — but that
// fails SAFE (a later run sees EEXIST and refuses with the same clobberErr) rather than
// a silent, undetectable clobber.
async function promoteNoClobber(part: string, out: string): Promise<void> {
  const clobberErr = () =>
    new Error(
      `${out} already exists — refusing to overwrite it with a pull result (move it aside, choose a new --out, or pass --force)`,
    );
  try {
    await link(part, out);
  } catch (e) {
    const err = e as NodeJS.ErrnoException;
    if (err && err.code === 'EEXIST') throw clobberErr();
    if (err?.code && ['EPERM', 'ENOTSUP', 'EOPNOTSUPP', 'ENOSYS', 'EXDEV'].includes(err.code)) {
      try {
        await writeFile(out, '', { flag: 'wx' });
      } catch (createErr) {
        const ce = createErr as NodeJS.ErrnoException;
        if (ce && ce.code === 'EEXIST') throw clobberErr();
        throw createErr;
      }
      try {
        await rename(part, out);
      } catch (renameErr) {
        try {
          await rm(out, { force: true });
        } catch {
          /* ignore — never mask the real renameErr */
        }
        throw renameErr;
      }
      return;
    }
    throw e;
  }
  await rm(part, { force: true }); // drop the redundant link; out is the durable copy
}

export async function pull(o: CliOptions): Promise<void> {
  // --from-locator-file <path>: read the locator (and its backend) from a file written
  // by `push --save-locator`. This is the recovery path — a fresh machine that holds
  // only the identity + this one small file (both backed up off-box) can restore the
  // latest snapshot without ever having seen index.tsv. Explicit --locator/--backend
  // still win if both are also given.
  if (o.from_locator_file) {
    if (!(await exists(o.from_locator_file))) throw new Error(`no such locator file: ${o.from_locator_file}`);
    const line = (await readFile(o.from_locator_file, 'utf8'))
      .split('\n')
      .map((l) => l.trim())
      .find((l) => l && !l.startsWith('#'));
    if (!line) throw new Error(`locator file ${o.from_locator_file} has no locator line`);
    // Accept the legacy 3-field line, the 4-field one (a trailing content_digest,
    // written since --skip-unchanged), the 5-field one (+recipients_fingerprint) AND
    // the 6-field one (+sig_locator, #214): recovery of every existing save-locator
    // file must keep working, so extra columns are simply ignored here.
    const [savedLoc, savedBackend, savedSha, , , savedSigLocator] = line.split('\t');
    // A truncated / hand-mangled file missing the backend column would otherwise fall
    // through to the generic "--backend required" error, hiding the real cause.
    if (!savedLoc || !savedBackend) {
      throw new Error(
        `locator file ${o.from_locator_file} must contain "<locator>\\t<backend>[\\t<sha256>[\\t<content_digest>[\\t<recipients_fingerprint>[\\t<sig_locator>]]]]" — got: ${JSON.stringify(line)}`,
      );
    }
    if (!o.locator) o.locator = savedLoc;
    if (!o.backend) o.backend = savedBackend;
    // Apply the saved integrity pin so recovery is fail-closed (a substituted ciphertext
    // is rejected); an explicit --sha256 still wins if the operator passed one.
    if (!o.sha256 && savedSha) o.sha256 = savedSha;
    // Same idea for the authenticity sidecar (#214): if push recorded where "<in>.minisig"
    // landed, fetch it alongside the ciphertext below (best-effort — see the fetch site).
    if (!o.sig_locator && savedSigLocator) o.sig_locator = savedSigLocator;
  }
  // rclone backend (#204): its locator IS the "<remote>:<path>" string (see
  // backends/rclone.ts) — --remote is accepted here as the same value --locator
  // would take, so a pull can mirror push's own --remote flag instead of forcing the
  // operator to know that the two happen to be interchangeable for this backend.
  // An explicit --locator still wins if both are somehow given.
  if (o.backend === 'rclone' && !o.locator && o.remote) o.locator = o.remote;
  if (!o.locator) throw new Error('--locator <id> required (or --from-locator-file <path>, or --remote for rclone)');
  if (!o.out) throw new Error('--out <file.age> required');
  if (!o.backend) throw new Error('--backend <file|arweave|turbo|rclone> required');
  // No-clobber (#107): refuse to overwrite an existing --out by default. wizard.ts's
  // printed recovery command reuses a FIXED path ("~/restored.age"), so a second pull
  // (a different backup, or a re-run of the recovery steps) would otherwise destroy
  // whatever the first pull already fetched with no warning — every backend's get()
  // (file.ts's copyFile, arweave.ts's stream-then-rename, which turbo.ts also delegates
  // to) writes unconditionally. Mirrors snapshot.ts's exists() gate on --out
  // (src/lib/snapshot.ts). Checked up front, before the possibly long --wait retry loop
  // below, so a doomed pull fails fast; --force opts into overwriting.
  if (!o.force && (await exists(o.out))) {
    throw new Error(
      `${o.out} already exists — refusing to overwrite it with a pull result (move it aside, choose a new --out, or pass --force)`,
    );
  }
  const backend = await backendFor(o.backend);
  // --wait <seconds>: keep retrying while the item is not yet retrievable. A fresh
  // Turbo/ArDrive upload takes ~5-8 min to propagate to the gateway (bundle -> mine
  // -> index); with --wait 0 (the default) pull fails immediately, preserving the old
  // behavior. CIPHER_BRAIN_PULL_RETRY_MS overrides the 30s retry interval (tests use it).
  const waitMs = (Number(o.wait) || 0) * 1000; // `|| 0` OUTSIDE Number → a non-numeric --wait is 0, not NaN (no infinite loop)
  // Unlike waitMs above (where "unset" and "explicit 0" both correctly mean 0ms — a
  // bare `|| 0` is safe there), retryMs's default (30000) and its explicit-zero value
  // (0, immediate retry — the natural choice for a test avoiding a real sleep) are
  // DIFFERENT, so a bare `Number(env) || 30000` (the #108 bug) breaks: Number("0") is
  // 0, and 0 is falsy, so `|| 30000` silently overrides the very value it was asked to
  // apply. Unset or empty falls back to the 30000ms default; anything else that parses
  // as a number is honored AS GIVEN, including 0.
  const retryMsEnv = process.env.CIPHER_BRAIN_PULL_RETRY_MS;
  const retryMsNum = retryMsEnv !== undefined && retryMsEnv !== '' ? Number(retryMsEnv) : NaN;
  const retryMs = Number.isFinite(retryMsNum) ? retryMsNum : 30000; // unset/empty/non-numeric -> default; anything else (incl. 0) is respected
  const deadline = Date.now() + waitMs;
  // Fetch into a PER-RUN-UNIQUE temp sibling of --out, never --out itself (#107): this
  // keeps --out completely untouched until the fetched bytes are verified good, so
  // neither a failed/retried attempt nor a --sha256 mismatch below (which previously
  // deleted --out itself) can ever harm a file that was already there. The final
  // promotion is the same atomic no-clobber pattern snapshot.ts's promoteSnapshot uses
  // for its own --out write (promoteNoClobber above).
  const part = `${o.out}.${process.pid}.${randomBytes(4).toString('hex')}.part`;
  try {
    for (let attempt = 1; ; attempt++) {
      try {
        await backend.get(o.locator, part);
        break;
      } catch (e) {
        const remaining = deadline - Date.now();
        if (!(e instanceof RetryableError) || remaining <= 0) throw e; // fatal (bad locator etc.) or out of budget → fail now
        const naptime = Math.min(retryMs, remaining); // honor a budget shorter than the retry interval
        console.error(`pull attempt ${attempt} not ready (${e.message}); retrying in ${Math.round(naptime / 1000)}s…`);
        await sleep(naptime);
      }
    }
    // --sha256 <hex>: bind the fetched bytes to a hash known out-of-band (from a TRUSTED
    // source, e.g. an off-box index.tsv — NOT the maybe-compromised snapshotting box).
    // For the post-assigned-id backends (arweave/turbo) the locator is not a content
    // hash, so without this a gateway/storage attacker could serve a rolled-back or
    // substituted (but still age-decryptable) ciphertext. Checked against the TEMP part
    // (never --out), so a mismatch here can never touch a pre-existing --out.
    if (o.sha256) {
      const got = await sha256(part);
      if (got.toLowerCase() !== String(o.sha256).toLowerCase()) {
        throw new Error(
          `sha256 mismatch: fetched ${got}, expected ${o.sha256} (the storage/gateway served bytes that do not match the pinned hash — nothing was written to ${o.out})`,
        );
      }
      console.error(`sha256 OK: ${got}`);
    }
    // Promote the verified fetch to --out. --force is the explicit opt-in to overwrite
    // (rename() atomically replaces an existing --out on POSIX); without it,
    // promoteNoClobber refuses if --out appeared since the check above (TOCTOU-safe).
    if (o.force) await rename(part, o.out);
    else await promoteNoClobber(part, o.out);
  } catch (e) {
    await rm(part, { force: true });
    throw e;
  }
  console.error(`pulled ${o.backend}:${o.locator} -> ${o.out}`);
  // Authenticity sidecar (#214): --sig-locator (explicit, or read from
  // --from-locator-file's 6th field above) says where push() parked the "<in>.minisig"
  // that was signed alongside this ciphertext — fetch it too, into "<out>.minisig", so
  // restore/verify on THIS machine has something to check. Best-effort and entirely
  // separate from the main fetch's own retry/--sha256/no-clobber machinery above: the
  // ciphertext is already safely at --out by this point, so a problem fetching the
  // (non-essential, additive) signature must only warn, never undo or fail the pull —
  // restore/verify's own "no signature -> WARN, not FAIL" contract (#214) already
  // covers a missing sidecar gracefully.
  const sigOut = `${o.out}.minisig`;
  if (o.sig_locator) {
    // Mirror --out's own --force gate above: --force already replaced --out with a
    // NEW ciphertext, so leaving a STALE .minisig sidecar next to it would make the
    // freshly-pulled artifact fail verification against a signature over the OLD
    // bytes — --force must refresh both together, not just the ciphertext.
    if ((await exists(sigOut)) && !o.force) {
      console.error(`warning: ${sigOut} already exists — not overwriting it with the fetched signature`);
    } else {
      try {
        await backend.get(o.sig_locator, sigOut);
        console.error(`pulled ${o.backend}:${o.sig_locator} -> ${sigOut}`);
      } catch (e) {
        console.error(
          `warning: could not fetch the authenticity signature (${o.backend}:${o.sig_locator} -> ${sigOut}): ${errMsg(e)}`,
        );
      }
    }
  } else if (o.force && (await exists(sigOut))) {
    // --force with NO sig_locator for THIS pull (the artifact being pulled has no
    // known signature) still just replaced --out's ciphertext — a stale .minisig
    // from a PRIOR pull into the same path would otherwise be silently signed over
    // the OLD bytes, and restore/verify would report a confusing "invalid signature"
    // for content that is simply unsigned. Removing it here is a straight loss of
    // (already-stale) information, never a loss of anything about THIS artifact.
    await rm(sigOut, { force: true });
    console.error(`removed stale ${sigOut} (this pull has no known signature to replace it with)`);
  }
}
