// snapshot — stage components (pg_dump / dirs / manifest.json), then stream tar|age.
import { mkdir, writeFile, rm, stat, rename, link, readdir, readlink } from 'node:fs/promises';
import { mkdtempSync } from 'node:fs';
import { hostname, tmpdir } from 'node:os';
import { join, basename, dirname, resolve, relative, sep } from 'node:path';
import { randomBytes, createHash } from 'node:crypto';
import { RECIPIENT, PIN_RECIPIENTS, PIPE_TIMEOUT_MS, pgTool } from './config.mjs';
import { run } from './proc.mjs';
import { newEncrypter, encryptToFile } from './crypt.mjs';
import { exists, fmtBytes, sha256 } from './util.mjs';
import { recipientEntries, resolvePinnedRecipients } from './keys.mjs';
import { resolveProfilePaths } from './profiles.mjs';
import { installStageSignalGuard, setActiveStage, setActiveOutPart } from './signal-guard.mjs';

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

const hexOf = (s) => createHash('sha256').update(s).digest('hex');

// Deterministic PLAINTEXT content digest of one source path — the signal behind
// `push --skip-unchanged`. It has to come from the plaintext side: age generates an
// ephemeral file key per run, so identical content encrypts to DIFFERENT ciphertext
// bytes every time — the ciphertext sha256 can never say "unchanged". Explicitly
// independent of mtimes and of the tar byte stream (tar records mtimes/order):
//   - file → the file's sha256
//   - dir  → sha256 over the "\n"-joined, path-sorted lines
//            "<relpath>\t<kind>\t<per-file sha256>\t<size>" for everything under it.
//            Symlinks hash their target string; other specials (FIFOs, sockets) hash
//            as a bare kind marker — reading them could hang, and their presence
//            still perturbs the digest.
async function contentDigestOfPath(abs) {
  if (!(await stat(abs)).isDirectory()) return sha256(abs);
  const lines = [];
  for (const d of await readdir(abs, { recursive: true, withFileTypes: true })) {
    const full = join(d.parentPath, d.name);
    const rel = relative(abs, full).split(sep).join('/'); // POSIX-normalized so the digest is platform-stable
    if (d.isFile()) lines.push(`${rel}\tf\t${await sha256(full)}\t${(await stat(full)).size}`);
    else if (d.isSymbolicLink()) lines.push(`${rel}\tl\t${hexOf(await readlink(full))}\t0`);
    else if (d.isDirectory()) lines.push(`${rel}\td\t-\t0`);
    else lines.push(`${rel}\ts\t-\t0`);
  }
  lines.sort();
  return hexOf(lines.join('\n') + '\n');
}

export async function snapshot(o) {
  if (!o.out) throw new Error('--out <file.age> required');
  // --profile is a thin veneer over --dir: it resolves to concrete source paths
  // (see profiles.mjs) staged exactly like explicit --dir flags. Profile paths
  // come first; any extra --dir flags the user passed are appended after them.
  if (o.profile) o.dirs = [...(await resolveProfilePaths(o)), ...o.dirs];
  if (!o.pg && o.dirs.length === 0) throw new Error('nothing to snapshot: pass --profile <name>, --pg <conn> and/or --dir <path>');
  // No-clobber: refuse to overwrite an existing snapshot (this is a backup tool — a
  // silent overwrite could destroy a prior, possibly only, copy of the brain). The old
  // `age -o o.out` write left this to age's version-dependent overwrite policy; the
  // atomic rename below would ALWAYS clobber, so enforce the safe behavior explicitly.
  if (await exists(o.out)) throw new Error(`${o.out} already exists — refusing to overwrite a prior snapshot (move it aside or choose a new --out)`);
  // Recipients = who can decrypt. Each --recipient is an `age1...` pubkey OR a
  // file of pubkeys; default to the keypair's own recipient. Passing more than one
  // is key recovery: encrypt to a primary AND an offline backup key so that losing
  // the primary identity does NOT lose the brain (any one identity restores).
  const recs = o.recipients.length ? o.recipients : [RECIPIENT];
  const entriesByRec = new Map(); // recipient arg -> its effective age1… entries
  for (const r of recs) {
    if (!r.startsWith('age1') && !(await exists(r))) {
      throw new Error(`no recipient at ${r} — run "cipher-brain keygen" first, or pass an age1... pubkey`);
    }
    entriesByRec.set(r, await recipientEntries(r));
  }

  // Fail-fast on a flattened recipient list of ZERO entries (e.g. every recipients
  // file held only blank/comment lines): typage would happily encrypt to an EMPTY
  // stanza list — valid-looking ciphertext that NO identity can ever decrypt. The
  // old external `age -R` errored here; so must we, and at THIS point — before any
  // plaintext is staged or a .part is opened — so a refused run leaves nothing behind.
  const recipientList = [...entriesByRec.values()].flat();
  if (recipientList.length === 0) {
    throw new Error(`recipient file(s) ${recs.join(', ')} resolved to ZERO recipients (only blank/comment lines?) — refusing to snapshot: encrypting to an empty recipient list would create a snapshot NO identity can ever decrypt`);
  }

  // Recipient pin (opt-in): fail-fast if any effective recipient is not allowlisted,
  // so a tampered recipient.txt or an injected extra --recipient cannot silently
  // re-key this (and every future) snapshot to an attacker.
  if (PIN_RECIPIENTS) {
    const allowed = await resolvePinnedRecipients(PIN_RECIPIENTS);
    if (allowed.size === 0) throw new Error('CIPHER_BRAIN_PIN_RECIPIENTS is set but lists no age1… pubkeys — refusing to snapshot');
    for (const r of recs) {
      const entries = entriesByRec.get(r);
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

  // The #1 footgun (documented in MANAGEMENT.md): a snapshot recoverable by exactly one
  // key — lose that identity and the brain is gone. The cadence examples use two keys, but
  // a copy-the-README run can forget the backup. Count DISTINCT effective recipient keys
  // (not --recipient args): a file may hold several keys, and two args may name the same
  // one — so dedupe across all entries. Warn loudly (stderr → unattended logs) on exactly one.
  const effectiveKeys = new Set();
  for (const entries of entriesByRec.values()) for (const e of entries) effectiveKeys.add(e);
  if (effectiveKeys.size === 1) {
    console.error('⚠  snapshot encrypted to a SINGLE recipient key — if you lose that identity the brain is UNRECOVERABLE. Add a second --recipient (an offline backup public key) for key recovery; see MANAGEMENT.md.');
  }

  // Build the encrypter up front: an invalid recipient line (typage takes native age
  // recipients only) must fail HERE, before any plaintext is staged or a .part opened.
  const encrypter = newEncrypter(recipientList);

  installStageSignalGuard();
  // mkdtempSync (not async mkdtemp) so dir-creation and the ACTIVE_STAGE assignment
  // happen in one tick with no event-loop yield between them — otherwise a signal that
  // lands during the await could fire the handler while ACTIVE_STAGE is still null and
  // leave the just-created stage dir behind.
  const stage = mkdtempSync(join(tmpdir(), 'cipher-brain-'));
  setActiveStage(stage); // a signal now erases this staged plaintext (see installStageSignalGuard)
  const createdAt = new Date().toISOString(); // when this snapshot run began (top-level)
  try {
    const components = [];
    if (o.pg) {
      const dumpPath = join(stage, 'db.dump');
      const tableArgs = o.tables.flatMap((t) => ['-t', t]);
      await run(pgTool('pg_dump'), ['-Fc', '--no-owner', '--no-privileges', ...tableArgs, '-f', dumpPath, o.pg]);
      // captured_at right AFTER pg_dump (pg_dump -Fc is internally point-in-time consistent
      // via one REPEATABLE READ txn; only the DB↔file boundary needs aligning — #44).
      // content_digest = sha256 of the dump bytes. Honest note: pg_dump output may not
      // be byte-stable across runs even for identical data (internal ordering, embedded
      // metadata), so DB sources will rarely trigger --skip-unchanged — that is
      // conservative (an unnecessary push, never a wrongly skipped one) and fine.
      components.push({ name: 'db.dump', kind: 'pg_dump:custom', tables: o.tables.length ? o.tables : 'all', content_digest: await sha256(dumpPath), captured_at: new Date().toISOString() });
    }
    const usedNames = new Set();
    for (const d of o.dirs) {
      const abs = resolve(d);
      let name = basename(abs) + '.tar.gz';
      // multiple --dir with the same basename must not overwrite each other in the stage
      for (let n = 1; usedNames.has(name); n++) name = `${basename(abs)}-${n}.tar.gz`;
      usedNames.add(name);
      // a path can be a directory OR a single file (profiles pass e.g. CLAUDE.md,
      // a ChatGPT export zip) — tar archives both; record which in the manifest.
      const kind = (await stat(abs)).isDirectory() ? 'dir' : 'file';
      // content_digest BEFORE the tar (of the SOURCE, not the archive): tar bytes embed
      // mtimes, so hashing them would defeat the mtime-independence --skip-unchanged needs.
      const contentDigest = await contentDigestOfPath(abs);
      await run('tar', ['-czf', join(stage, name), '-C', dirname(abs), basename(abs)], { timeoutMs: PIPE_TIMEOUT_MS }); // a FIFO/special file under --dir can't hang the pre-stage tar
      components.push({ name, kind, source: abs, content_digest: contentDigest, captured_at: new Date().toISOString() }); // skew vs the DB is now detectable on restore
    }
    // Combined content digest = sha256 of the per-component digests joined in
    // component order. Same content in the same component order → same digest,
    // regardless of mtimes or the (ephemeral-file-key) ciphertext bytes.
    const contentDigest = hexOf(components.map((c) => c.content_digest).join('\n') + '\n');
    // manifest carries NO secrets — just what's inside (+ capture timestamps so a
    // DB↔files skew is detectable after the fact, + which --profile produced it,
    // if any), so restore is self-describing.
    await writeFile(
      join(stage, 'manifest.json'),
      JSON.stringify({ tool: 'cipher-brain', schema: 1, host: hostname(), created_at: createdAt, content_digest: contentDigest, ...(o.profile ? { profile: o.profile } : {}), components }, null, 2) + '\n',
    );
    // tar the staged components into one stream, encrypt to all recipients (in-process
    // typage, streaming — bounded RSS at any snapshot size). Write to a PER-RUN-UNIQUE
    // .part so overlapping snapshots to the same --out never share/clobber each other's
    // in-progress file, and rename only on success, so a mid-pipeline failure (tar
    // error, ENOSPC, a killed run) never leaves a TRUNCATED *.age at o.out — which
    // would still start with the age magic and thus pass push()'s header-only gate,
    // letting an operator publish unrecoverable ciphertext to permanent paid storage.
    const part = `${o.out}.${process.pid}.${randomBytes(4).toString('hex')}.part`;
    setActiveOutPart(part); // a signal now also erases this partial ciphertext
    try {
      await encryptToFile(encrypter, 'tar', ['-cf', '-', '-C', stage, '.'], part, { timeoutMs: PIPE_TIMEOUT_MS });
      await promoteSnapshot(part, o.out);
      setActiveOutPart(null);
    } catch (e) {
      await rm(part, { force: true });
      setActiveOutPart(null);
      throw e;
    }
    // Plaintext digest sidecar next to the output — what lets `push --skip-unchanged`
    // detect "content unchanged" WITHOUT decrypting anything (the manifest copy sits
    // inside the ciphertext). A content digest leaks no content. Best-effort: the
    // snapshot itself is already durable at o.out, so a sidecar write failure only
    // costs the skip optimization, never the backup.
    try {
      await writeFile(`${o.out}.digest`, contentDigest + '\n');
    } catch (e) {
      console.error(`warning: could not write digest sidecar ${o.out}.digest (${e.message}) — push --skip-unchanged will not have a digest for this snapshot`);
    }
    const sz = (await stat(o.out)).size;
    console.log(`wrote ${o.out} (${fmtBytes(sz)}, encrypted to ${recs.length} recipient(s): ${recs.join(', ')})`);
    console.log(`components: ${components.map((c) => c.name).join(', ')}`);
    console.log(`content digest: ${contentDigest} (sidecar: ${o.out}.digest)`);
  } finally {
    await rm(stage, { recursive: true, force: true });
    setActiveStage(null);
  }
}
