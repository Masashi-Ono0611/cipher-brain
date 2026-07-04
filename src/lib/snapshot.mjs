// snapshot — stage components (pg_dump / dirs / manifest.json), then stream tar|age.
import { mkdir, writeFile, rm, stat, rename, link } from 'node:fs/promises';
import { mkdtempSync } from 'node:fs';
import { hostname, tmpdir } from 'node:os';
import { join, basename, dirname, resolve } from 'node:path';
import { randomBytes } from 'node:crypto';
import { AGE, RECIPIENT, PIN_RECIPIENTS, PIPE_TIMEOUT_MS, pgTool } from './config.mjs';
import { run, pipe2 } from './proc.mjs';
import { exists, fmtBytes } from './util.mjs';
import { recipientEntries, resolvePinnedRecipients } from './identity.mjs';
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

export async function snapshot(o) {
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

  // The #1 footgun (documented in MANAGEMENT.md): a snapshot recoverable by exactly one
  // key — lose that identity and the brain is gone. The cadence examples use two keys, but
  // a copy-the-README run can forget the backup. Count DISTINCT effective recipient keys
  // (not --recipient args): a file may hold several keys, and two args may name the same
  // one — so dedupe across all entries. Warn loudly (stderr → unattended logs) on exactly one.
  const effectiveKeys = new Set();
  for (const r of recs) for (const e of await recipientEntries(r)) effectiveKeys.add(e);
  if (effectiveKeys.size === 1) {
    console.error('⚠  snapshot encrypted to a SINGLE recipient key — if you lose that identity the brain is UNRECOVERABLE. Add a second --recipient (an offline backup public key) for key recovery; see MANAGEMENT.md.');
  }

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
      components.push({ name: 'db.dump', kind: 'pg_dump:custom', tables: o.tables.length ? o.tables : 'all', captured_at: new Date().toISOString() });
    }
    const usedNames = new Set();
    for (const d of o.dirs) {
      const abs = resolve(d);
      let name = basename(abs) + '.tar.gz';
      // multiple --dir with the same basename must not overwrite each other in the stage
      for (let n = 1; usedNames.has(name); n++) name = `${basename(abs)}-${n}.tar.gz`;
      usedNames.add(name);
      await run('tar', ['-czf', join(stage, name), '-C', dirname(abs), basename(abs)], { timeoutMs: PIPE_TIMEOUT_MS }); // a FIFO/special file under --dir can't hang the pre-stage tar
      components.push({ name, kind: 'dir', source: abs, captured_at: new Date().toISOString() }); // skew vs the DB is now detectable on restore
    }
    // manifest carries NO secrets — just what's inside (+ capture timestamps so a
    // DB↔files skew is detectable after the fact), so restore is self-describing.
    await writeFile(
      join(stage, 'manifest.json'),
      JSON.stringify({ tool: 'cipher-brain', schema: 1, host: hostname(), created_at: createdAt, components }, null, 2) + '\n',
    );
    // tar the staged components into one stream, encrypt to all recipients. Write to a
    // PER-RUN-UNIQUE .part so overlapping snapshots to the same --out never share/clobber
    // each other's in-progress file, and rename only on success, so a mid-pipeline failure
    // (tar error, ENOSPC, a SIGTERM-killed age) never leaves a TRUNCATED *.age at o.out —
    // which would still start with the age magic and thus pass push()'s header-only gate,
    // letting an operator publish unrecoverable ciphertext to permanent paid storage.
    const part = `${o.out}.${process.pid}.${randomBytes(4).toString('hex')}.part`;
    setActiveOutPart(part); // a signal now also erases this partial ciphertext
    try {
      await pipe2('tar', ['-cf', '-', '-C', stage, '.'], AGE, [...recArgs, '-o', part], { timeoutMs: PIPE_TIMEOUT_MS });
      await promoteSnapshot(part, o.out);
      setActiveOutPart(null);
    } catch (e) {
      await rm(part, { force: true });
      setActiveOutPart(null);
      throw e;
    }
    const sz = (await stat(o.out)).size;
    console.log(`wrote ${o.out} (${fmtBytes(sz)}, encrypted to ${recs.length} recipient(s): ${recs.join(', ')})`);
    console.log(`components: ${components.map((c) => c.name).join(', ')}`);
  } finally {
    await rm(stage, { recursive: true, force: true });
    setActiveStage(null);
  }
}
