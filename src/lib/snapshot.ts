// snapshot — stage components (pg_dump / dirs / manifest.json), then stream tar|age.
import { mkdir, writeFile, rm, stat, lstat, rename, link, readdir, readlink } from 'node:fs/promises';
import { mkdtempSync } from 'node:fs';
import { hostname, tmpdir } from 'node:os';
import { join, basename, dirname, resolve, relative, sep } from 'node:path';
import { randomBytes, createHash } from 'node:crypto';
import { RECIPIENT, PIN_RECIPIENTS, PIPE_TIMEOUT_MS, pgTool } from './config.js';
import { run } from './proc.js';
import { newEncrypter, encryptToFile } from './crypt.js';
import { exists, fmtBytes, sha256, errMsg } from './util.js';
import { recipientEntries, resolvePinnedRecipients } from './keys.js';
import { resolveProfilePaths } from './profiles.js';
import { installStageSignalGuard, setActiveStage, setActiveOutPart } from './signal-guard.js';
import {
  assertGitleaksAvailable,
  scanForSecrets,
  reportSecretFindings,
  type ScanSecretsMode,
  type SecretFinding,
} from './secrets-scan.js';
import type { CliOptions } from './types.js';

// Promote a finished .part to its final --out, no-clobber. Prefer link(): it is atomic
// and fails with EEXIST if out appeared meanwhile, giving a true exclusive no-clobber
// even under overlapping snapshots. But hard links are unsupported on exFAT/FAT and some
// network/cloud mounts (common backup media), where link throws EPERM/ENOTSUP — there,
// fall back to an exclusive create (writeFile with the 'wx' flag, the same no-clobber
// idiom keys.ts/wizard.ts already use) as the no-clobber GATE, instead of a racy
// exists()-then-rename() check-then-act: 'wx' atomically fails with EEXIST if `out`
// already exists, so of two overlapping snapshots at most one can win the create — the
// loser sees EEXIST and refuses, same as the link() path. The winner then owns `out`
// and folds the real content in via rename() (itself atomic: readers see either the
// empty placeholder or the complete file, never a torn write). The promotion DECISION
// is now race-free either way; no TOCTOU window remains there. Residual: an unclean
// kill (SIGKILL bypasses any in-process cleanup, on the link() path too) between the
// create and the rename can leave an empty placeholder at `out` — but that fails SAFE
// (a later run sees EEXIST and refuses with the same clobberErr, an operator can `rm`
// the empty file and retry) rather than the silent, undetectable clobber this fix closes.
async function promoteSnapshot(part: string, out: string): Promise<void> {
  const clobberErr = () =>
    new Error(`${out} already exists — refusing to overwrite a prior snapshot (move it aside or choose a new --out)`);
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
        // best-effort: undo the placeholder create so a retry doesn't see a false
        // EEXIST; swallow any cleanup error so it never masks the real renameErr.
        try {
          await rm(out, { force: true });
        } catch {
          /* ignore */
        }
        throw renameErr;
      }
      return;
    }
    throw e;
  }
  await rm(part, { force: true }); // drop the redundant link; out is the durable copy
}

const hexOf = (s: string): string => createHash('sha256').update(s).digest('hex');

// Mode string shared by every tuple line below: octal rwx bits, what tar actually
// archives alongside an entry's bytes.
const modeOf = (st: { mode: number }): string => (st.mode & 0o777).toString(8).padStart(3, '0');

// One file's tuple line — the SAME format whether the file is the sole top-level
// source (a --dir-equivalent arg that is actually a single file: profile files/zips
// are explicitly supported this way) or one entry inside a directory walk. Sharing
// this helper (rather than a second, ad-hoc "just hash the file" path for the
// top-level-file case) is what makes a chmod-only change to a single-file source
// perturb the digest exactly like a chmod-only change to a file nested in a --dir
// source does (#70 review round 3).
async function fileTupleLine(rel: string, full: string): Promise<string> {
  const st = await stat(full);
  return `${rel}\tf\t${await sha256(full)}\t${st.size}\t${modeOf(st)}`;
}

// Deterministic PLAINTEXT content digest of one source path — the signal behind
// `push --skip-unchanged`. It has to come from the plaintext side: age generates an
// ephemeral file key per run, so identical content encrypts to DIFFERENT ciphertext
// bytes every time — the ciphertext sha256 can never say "unchanged". Explicitly
// independent of mtimes and of the tar byte stream (tar records mtimes/order):
//   - top-level symlink → the link's OWN identity (what it points to), never its
//            target's content. tar archives an explicit symlink argument as the
//            link itself (bsdtar/GNU tar both default to not dereferencing — the
//            same class of bug profiles.ts's realpath-dereference comment fixes
//            for --vault/--zip/claude-code paths), so a target swapped for a
//            different path — even one with byte-identical content — changes
//            what actually gets archived and must change the digest too.
//   - top-level file → hexOf of ITS OWN tuple line (fileTupleLine, same format a
//            nested file gets inside a directory walk) — so a chmod-only change to
//            a single-file source (e.g. a --profile file) changes the digest just
//            like it would for the same file nested in a --dir (#70 review round 3).
//   - top-level special (FIFO/socket/device: not a symlink, not a directory, not a
//            regular file) → the SAME bare kind marker the nested-walk's `else`
//            branch below hashes for a special file found inside a --dir, NEVER a
//            fileTupleLine read: a FIFO only yields bytes once something writes to
//            the other end, so sha256()-ing it (as a plain "unconditionally a
//            regular file" read would) can hang forever — outside PIPE_TIMEOUT_MS,
//            which only bounds the tar step, not this digest read (#70 review round 4).
//   - dir  → sha256 over the "\n"-joined, path-sorted lines
//            "<relpath>\t<kind>\t<per-file sha256>\t<size>\t<mode>" for everything
//            under it, PLUS one synthetic "." line carrying the top-level directory's
//            OWN mode (a chmod on the --dir arg itself, touching no file inside it,
//            still changes what tar archives and must still change the digest — #70
//            review round 3). The trailing <mode> (files and directories, octal rwx
//            bits) is what tar actually archives alongside the entry — `chmod +x
//            script.sh` or tightening a secret file/dir to 0600/0700 changes the tar
//            entry's permission bits without touching content, so a restore from a
//            digest that ignored mode could silently carry stale/wrong permissions
//            past --skip-unchanged (#70 review round 2 & 3). Nested symlinks hash
//            their target string; other specials (FIFOs, sockets) hash as a bare kind
//            marker — reading them could hang, and their presence still perturbs the
//            digest.
async function contentDigestOfPath(abs: string): Promise<string> {
  const top = await lstat(abs);
  if (top.isSymbolicLink()) return hexOf(`l\t${await readlink(abs)}`);
  if (!top.isDirectory() && !top.isFile()) return hexOf('s\t-\t0'); // FIFO/socket/device — never read, could hang
  if (!top.isDirectory()) return hexOf((await fileTupleLine(basename(abs), abs)) + '\n');
  const lines = [`.\td\t-\t0\t${modeOf(top)}`]; // the --dir arg's own mode, never covered by readdir below
  for (const d of await readdir(abs, { recursive: true, withFileTypes: true })) {
    const full = join(d.parentPath, d.name);
    const rel = relative(abs, full).split(sep).join('/'); // POSIX-normalized so the digest is platform-stable
    if (d.isFile()) lines.push(await fileTupleLine(rel, full));
    else if (d.isSymbolicLink()) lines.push(`${rel}\tl\t${hexOf(await readlink(full))}\t0`);
    else if (d.isDirectory()) lines.push(`${rel}\td\t-\t0\t${modeOf(await stat(full))}`);
    else lines.push(`${rel}\ts\t-\t0`);
  }
  lines.sort();
  return hexOf(lines.join('\n') + '\n');
}

// One entry in the manifest's `components` array — either the pg_dump (kind
// 'pg_dump:custom', no `source`) or one staged --dir/--profile path (kind 'dir'/'file').
interface ManifestComponent {
  name: string;
  kind: string;
  source?: string;
  tables?: string[] | 'all';
  content_digest: string;
  captured_at: string;
  // Present only when --scan-secrets was passed (#215): gitleaks rule-ID + count for
  // this component, NEVER the matched secret/file path/line (see secrets-scan.ts).
  secrets_scan?: SecretFinding[];
}

export async function snapshot(o: CliOptions): Promise<void> {
  if (!o.out) throw new Error('--out <file.age> required');
  // --profile is a thin veneer over --dir: it resolves to concrete source paths
  // (see profiles.ts) staged exactly like explicit --dir flags. Profile paths
  // come first; any extra --dir flags the user passed are appended after them.
  if (o.profile) o.dirs = [...(await resolveProfilePaths(o)), ...o.dirs];
  if (!o.pg && o.dirs.length === 0)
    throw new Error('nothing to snapshot: pass --profile <name>, --pg <conn> and/or --dir <path>');
  // --scan-secrets warn|deny (#215): gitleaks over each --dir/--profile source's staged
  // plaintext before it is archived+encrypted. Validated AND gitleaks-availability-checked
  // here, before any pg_dump/tar/staging work below — the same fail-fast posture the
  // --out parent dir / recipient checks below already follow.
  let scanMode: ScanSecretsMode | undefined;
  if (o.scan_secrets !== undefined) {
    if (o.scan_secrets !== 'warn' && o.scan_secrets !== 'deny')
      throw new Error(`--scan-secrets must be "warn" or "deny" (got ${JSON.stringify(o.scan_secrets)})`);
    scanMode = o.scan_secrets;
    await assertGitleaksAvailable();
  }
  // No-clobber: refuse to overwrite an existing snapshot (this is a backup tool — a
  // silent overwrite could destroy a prior, possibly only, copy of the brain). The old
  // `age -o o.out` write left this to age's version-dependent overwrite policy; the
  // atomic rename below would ALWAYS clobber, so enforce the safe behavior explicitly.
  if (await exists(o.out))
    throw new Error(
      `${o.out} already exists — refusing to overwrite a prior snapshot (move it aside or choose a new --out)`,
    );
  // Fail-fast (#109) on a bad --out PARENT directory (a typo'd path, an unwritable
  // mount) HERE — before pg_dump / --dir tar+extract+digest work below, which can take
  // minutes for a large brain. Without this, the bad path only surfaces once
  // encryptToFile's createWriteStream(part) tries to open the .part sibling deep into
  // the run (part lives next to o.out, so its parent dir is the same one). Mirrors the
  // mkdir(dirname(resolve(out)), { recursive: true }) file.ts:36 / arweave.ts:280
  // already do before their own writes; a no-op if the directory already exists, a real
  // ENOTDIR/EACCES if the path is genuinely bad.
  await mkdir(dirname(resolve(o.out)), { recursive: true });
  // Recipients = who can decrypt. Each --recipient is an `age1...` pubkey OR a
  // file of pubkeys; default to the keypair's own recipient. Passing more than one
  // is key recovery: encrypt to a primary AND an offline backup key so that losing
  // the primary identity does NOT lose the brain (any one identity restores).
  const recs = o.recipients.length ? o.recipients : [RECIPIENT];
  const entriesByRec = new Map<string, string[]>(); // recipient arg -> its effective age1… entries
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
    throw new Error(
      `recipient file(s) ${recs.join(', ')} resolved to ZERO recipients (only blank/comment lines?) — refusing to snapshot: encrypting to an empty recipient list would create a snapshot NO identity can ever decrypt`,
    );
  }

  // Recipient pin (opt-in): fail-fast if any effective recipient is not allowlisted,
  // so a tampered recipient.txt or an injected extra --recipient cannot silently
  // re-key this (and every future) snapshot to an attacker.
  //
  // PIN_RECIPIENTS is `string | undefined`, not just a falsy check: `undefined` means
  // the var is genuinely unset (no pin configured, check skipped). An explicitly empty
  // string (CIPHER_BRAIN_PIN_RECIPIENTS="") is a misconfiguration — most likely a
  // broken template in an unattended cron/systemd unit — and must fail CLOSED, not be
  // silently treated as "no pin" (which would defeat the whole point of the pin).
  if (PIN_RECIPIENTS !== undefined) {
    if (PIN_RECIPIENTS === '') {
      throw new Error(
        'CIPHER_BRAIN_PIN_RECIPIENTS is set but empty — refusing to snapshot (an explicitly empty pin looks like a misconfiguration; unset the variable entirely to run without an allowlist)',
      );
    }
    const allowed = await resolvePinnedRecipients(PIN_RECIPIENTS);
    if (allowed.size === 0)
      throw new Error('CIPHER_BRAIN_PIN_RECIPIENTS is set but lists no age1… pubkeys — refusing to snapshot');
    for (const r of recs) {
      const entries = entriesByRec.get(r) ?? [];
      if (entries.length === 0)
        throw new Error(
          `recipient "${r}" has no recipients to check against CIPHER_BRAIN_PIN_RECIPIENTS (refusing to snapshot)`,
        );
      for (const e of entries) {
        // Fail-closed: every entry must be an allowlisted age1… key. A non-age1
        // recipient (e.g. an injected `ssh-ed25519 …` line) can't be on the
        // age1-only allowlist, so it is rejected — which is the point.
        if (!allowed.has(e))
          throw new Error(
            `recipient "${e}" (via "${r}") is NOT in CIPHER_BRAIN_PIN_RECIPIENTS — refusing to snapshot (an unexpected recipient could decrypt your brain)`,
          );
      }
    }
    console.error(`recipient pin OK: all recipient(s) are allowlisted`);
  }

  // The #1 footgun (documented in MANAGEMENT.md): a snapshot recoverable by exactly one
  // key — lose that identity and the brain is gone. The cadence examples use two keys, but
  // a copy-the-README run can forget the backup. Count DISTINCT effective recipient keys
  // (not --recipient args): a file may hold several keys, and two args may name the same
  // one — so dedupe across all entries. Warn loudly (stderr → unattended logs) on exactly one.
  const effectiveKeys = new Set<string>();
  for (const entries of entriesByRec.values()) for (const e of entries) effectiveKeys.add(e);
  if (effectiveKeys.size === 1) {
    console.error(
      '⚠  snapshot encrypted to a SINGLE recipient key — if you lose that identity the brain is UNRECOVERABLE. Add a second --recipient (an offline backup public key) for key recovery; see MANAGEMENT.md.',
    );
  }

  // Recipients fingerprint: sha256 over the SORTED, de-duplicated set of effective
  // age1… recipient keys used to encrypt THIS run — sorted + newline-joined so it is
  // independent of --recipient arg order and of which arg/file each key came from
  // (only the resulting SET matters, same dedupe as effectiveKeys above). This is a
  // SEPARATE signal from content_digest (which stays pure-plaintext, unaffected by
  // recipients) that `push --skip-unchanged` additionally folds in (src/lib/
  // pushpull.ts): without it, re-snapshotting unchanged plaintext under a CHANGED
  // recipient set (a newly added offline recovery key, or a removed/revoked key)
  // would still skip and return the OLD locator — the new key could never decrypt
  // it, and/or a revoked key still could, even though the operator believes the
  // "current" backup no longer trusts it (#70 review round 2, real regression).
  const recipientsFingerprint = hexOf([...effectiveKeys].sort().join('\n') + '\n');

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
    const components: ManifestComponent[] = [];
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
      components.push({
        name: 'db.dump',
        kind: 'pg_dump:custom',
        tables: o.tables.length ? o.tables : 'all',
        content_digest: await sha256(dumpPath),
        captured_at: new Date().toISOString(),
      });
    }
    const usedNames = new Set<string>();
    for (const d of o.dirs) {
      const abs = resolve(d);
      let name = basename(abs) + '.tar.gz';
      // multiple --dir with the same basename must not overwrite each other in the stage
      for (let n = 1; usedNames.has(name); n++) name = `${basename(abs)}-${n}.tar.gz`;
      usedNames.add(name);
      // a path can be a directory, a single file (profiles pass e.g. CLAUDE.md,
      // a ChatGPT export zip), or a top-level symlink — tar archives all three;
      // record which in the manifest. lstat() (not stat()) so this matches what
      // the tar -czf call below actually archives: a top-level symlink argument
      // is NOT dereferenced by GNU tar/bsdtar (same fact contentDigestOfPath's
      // lstat-based check above already relies on), so a directory-symlink here
      // must be recorded as 'symlink', never 'dir' — 'dir' would claim the
      // archive holds the target's tree when it actually holds just the link.
      // lstat() also does not throw on a DANGLING symlink (stat() would ENOENT
      // before tar ever ran), so a broken symlink source is now archived (as a
      // symlink entry) instead of failing snapshot() outright.
      const topStat = await lstat(abs);
      const kind = topStat.isSymbolicLink() ? 'symlink' : topStat.isDirectory() ? 'dir' : 'file';
      const archivePath = join(stage, name);
      await run('tar', ['-czf', archivePath, '-C', dirname(abs), '--', basename(abs)], { timeoutMs: PIPE_TIMEOUT_MS }); // a FIFO/special file under --dir can't hang the pre-stage tar; the -- guards a basename that could otherwise be parsed as an option (e.g. a leading '-')
      // content_digest AFTER the tar, computed from the ARCHIVE'S OWN bytes (extract to a
      // throwaway dir and hash THAT with the unchanged contentDigestOfPath) rather than a
      // second, independent read of the live source. Two independent reads (a digest walk,
      // then tar's own read) leave a race: a source mutated in the narrow window between
      // them would archive NEW bytes while the digest still describes the OLD ones — a
      // stale-looking "unchanged" digest sitting next to genuinely different archived
      // content (#70 review). Hashing what tar itself just wrote closes that gap: the
      // digest can never describe content other than what got archived. Still independent
      // of mtimes/order and of the tar byte stream itself — contentDigestOfPath only reads
      // content bytes / symlink targets from the extraction, never tar's own headers.
      // -p (--preserve-permissions, supported by both GNU tar and macOS bsdtar — this
      // repo's CI matrix runs both) makes the re-read apply the ARCHIVE's stored mode
      // bits exactly, instead of masking them through this process's umask. A plain
      // `tar -xzf` (no -p) applies umask on extraction, so under a restrictive umask a
      // mode-only source change (e.g. 0644 -> 0600) can extract to the SAME mode both
      // times even though the tar header bytes differ — silently hiding the change
      // from the digest this verification re-read is supposed to prove (#70 review
      // round 3).
      const extractDir = join(stage, `.extract-${name}`);
      await mkdir(extractDir);
      let contentDigest: string;
      let secretsScan: SecretFinding[] | undefined;
      try {
        await run('tar', ['-xzf', archivePath, '-C', extractDir, '-p'], { timeoutMs: PIPE_TIMEOUT_MS });
        contentDigest = await contentDigestOfPath(join(extractDir, basename(abs)));
        // Scan the SAME extracted root the digest above just read (join(extractDir,
        // basename(abs)), NOT extractDir itself — gitleaks looks for "(target
        // path)/.gitleaks.toml", so passing the actual source root is what lets a
        // .gitleaks.toml dropped at the top of the scanned source be discovered, matching
        // the doc'd "drop a .gitleaks.toml into a scanned source" story; scanning the
        // parent extractDir one level up would look for it in the wrong place, multi-model
        // review finding) — the exact plaintext about to be folded into the final tar|age
        // stream, before extractDir is erased in the finally below. deny throws here,
        // unwinding out through this function's own try/finally (stage cleanup still
        // runs); warn just logs and falls through.
        if (scanMode) {
          secretsScan = await scanForSecrets(join(extractDir, basename(abs)));
          reportSecretFindings(name, secretsScan, scanMode);
        }
      } finally {
        // must not leak into the snapshot: the final encryptToFile below tars stage/. whole
        await rm(extractDir, { recursive: true, force: true });
      }
      components.push({
        name,
        kind,
        source: abs,
        content_digest: contentDigest,
        captured_at: new Date().toISOString(),
        ...(scanMode ? { secrets_scan: secretsScan ?? [] } : {}),
      }); // skew vs the DB is now detectable on restore
    }
    // Combined content digest = sha256 over each component's (declared identity, kind,
    // content_digest) joined in component order. Identity, not just bytes: hashing bare
    // content digests would leave `--dir old-path` and `--dir new-path` (or a renamed
    // --vault-like source) indistinguishable whenever the underlying bytes happen to be
    // byte-identical, so --skip-unchanged could return the OLD locator — whose restored
    // manifest/archive still labels things under the old name/path — for what was actually
    // asked to be a differently-named/sourced snapshot (#70 review). Identity is
    // deliberately the DECLARED source path (or name, for pg_dump which has no source
    // path) — never anything volatile like mtime. Same content, same identity, same
    // component order → same digest, regardless of mtimes or the (ephemeral-file-key)
    // ciphertext bytes.
    const contentDigest = hexOf(
      components.map((c) => `${c.source ?? c.name}\t${c.kind}\t${c.content_digest}`).join('\n') + '\n',
    );
    // manifest carries NO secrets — just what's inside (+ capture timestamps so a
    // DB↔files skew is detectable after the fact, + which --profile produced it,
    // if any), so restore is self-describing. recipients_fingerprint sits alongside
    // content_digest as a SEPARATE field — content_digest stays pure-plaintext
    // (unaffected by who can decrypt); recipients_fingerprint is the additional
    // signal push --skip-unchanged folds in (see its definition above).
    await writeFile(
      join(stage, 'manifest.json'),
      JSON.stringify(
        {
          tool: 'cipher-brain',
          schema: 1,
          host: hostname(),
          created_at: createdAt,
          content_digest: contentDigest,
          recipients_fingerprint: recipientsFingerprint,
          ...(o.profile ? { profile: o.profile } : {}),
          ...(scanMode ? { scan_secrets_mode: scanMode } : {}),
          components,
        },
        null,
        2,
      ) + '\n',
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
    // costs the skip optimization, never the backup. Kept as its OWN single-line file
    // (never a second line appended here) — existing readers (push's contentDigestFor,
    // the selftest's `cat *.digest` comparisons) assume this file IS the content digest
    // verbatim; the recipients fingerprint is a genuinely separate signal and gets its
    // own sidecar right below, never folded into this one.
    try {
      await writeFile(`${o.out}.digest`, contentDigest + '\n');
    } catch (e) {
      console.error(
        `warning: could not write digest sidecar ${o.out}.digest (${errMsg(e)}) — push --skip-unchanged will not have a digest for this snapshot`,
      );
    }
    // Recipients fingerprint sidecar — the SEPARATE signal (#70 review round 2) that
    // push --skip-unchanged additionally requires to match before it will skip (see
    // src/lib/pushpull.ts). A leaked age1… pubkey is not a secret (it's the whole
    // point of a "recipient" — safe to copy), so this sidecar carries no secrets
    // either. Best-effort, same as the content digest sidecar above.
    try {
      await writeFile(`${o.out}.recipients-fingerprint`, recipientsFingerprint + '\n');
    } catch (e) {
      console.error(
        `warning: could not write recipients-fingerprint sidecar ${o.out}.recipients-fingerprint (${errMsg(e)}) — push --skip-unchanged will not have a recipients fingerprint for this snapshot`,
      );
    }
    const sz = (await stat(o.out)).size;
    console.log(`wrote ${o.out} (${fmtBytes(sz)}, encrypted to ${recs.length} recipient(s): ${recs.join(', ')})`);
    console.log(`components: ${components.map((c) => c.name).join(', ')}`);
    console.log(`content digest: ${contentDigest} (sidecar: ${o.out}.digest)`);
    console.log(`recipients fingerprint: ${recipientsFingerprint} (sidecar: ${o.out}.recipients-fingerprint)`);
  } finally {
    await rm(stage, { recursive: true, force: true });
    setActiveStage(null);
  }
}
