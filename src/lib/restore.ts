// restore + verify — the decrypt half and its falsifiable proof.
import { rm, stat, readFile } from 'node:fs/promises';
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { AGE_MAGIC, CIPHER_YES, IDENTITY, PIPE_TIMEOUT_MS, pgTool } from './config.js';
import { run } from './proc.js';
import { loadIdentities, newDecrypter, decryptToChild, wrongKeyRejects } from './crypt.js';
import { exists, sha256, readHead, fmtBytes } from './util.js';
import { installStageSignalGuard, setActiveRestoreOutDir } from './signal-guard.js';
import type { CliOptions } from './types.js';

export async function restore(o: CliOptions): Promise<void> {
  if (!o.in) throw new Error('--in <file.age> required');
  if (!o.out_dir) throw new Error('--out-dir <dir> required');
  // pg_restore --clean --if-exists below DROPS and replaces objects in the target
  // database — an irreversible operation. Same consent gate as push's paid-backend
  // guard (pushpull.ts): require --yes or CIPHER_BRAIN_YES=1 up front, before any
  // decrypt/extract work happens, mirroring the "fail before out_dir is even created"
  // discipline the identity check below already follows.
  if (o.pg && !(o.yes || CIPHER_YES)) {
    throw new Error(
      `--pg ${o.pg}: pg_restore --clean --if-exists will DROP and replace objects in that database — ` +
      `re-run restore with --yes or set CIPHER_BRAIN_YES=1 to confirm`
    );
  }
  const identity = o.identity || IDENTITY;
  if (!(await exists(identity))) throw new Error(`no identity at ${identity} — cannot decrypt without the private key`);
  // Load the identity FIRST (this prompts for the passphrase if the file is wrapped)
  // so a wrong passphrase / unreadable identity fails before out_dir is even created.
  const decrypter = newDecrypter(await loadIdentities(identity));
  // age streams plaintext chunk-by-chunk, so a truncated/corrupt artifact errors only
  // AFTER tar has already extracted the leading components — leaving a partial tree.
  // Track whether we created out_dir so we can remove it (or warn) on a mid-stream fail.
  // The tar child spawned below lands in the same ACTIVE_CHILDREN set snapshot's tar
  // does (see proc.ts), but until now nothing ever installed a signal guard for
  // restore() — a SIGINT/SIGTERM/SIGHUP mid-extract hit Node's default handler, the
  // tar child was never killed, and out_dir was left with a silently partial tree
  // with no cleanup and no warning (#95). installStageSignalGuard() is idempotent, so
  // calling it here is safe whether or not a snapshot() in the same process already did.
  installStageSignalGuard();
  // mkdirSync (not async mkdir), and its return value (not a separate exists() check)
  // decides outDirPreExisted: recursive mkdirSync returns undefined when the path
  // already fully existed, or the first path segment it created otherwise — a single
  // atomic syscall sequence with no TOCTOU gap between "check" and "create" (an
  // async exists() followed by mkdir leaves a window where something else could
  // create out_dir in between, misclassifying it as "we created this, safe to erase").
  // It also keeps dir-creation and the registration below in one tick with no
  // event-loop yield — same discipline snapshot() uses for ACTIVE_STAGE (mkdtempSync +
  // setActiveStage, see signal-guard.ts): otherwise a signal landing during an await
  // could fire before out_dir is registered and leave a freshly-created empty dir
  // untracked.
  const outDirPreExisted = mkdirSync(o.out_dir, { recursive: true }) === undefined;
  // Register out_dir with the guard so a mid-extract signal is handled the same way
  // snapshot's stage/.part are: erase it if we created it ourselves, or otherwise flag
  // it (see installStageSignalGuard) rather than destroy content we don't own.
  setActiveRestoreOutDir(o.out_dir, outDirPreExisted);
  // decrypt(in) | tar -xf - -C out-dir
  // --no-same-owner/--no-same-permissions: a substituted/forged archive must not be
  // able to set hostile ownership or modes on extraction (defense-in-depth — the
  // bytes can be attacker-chosen if storage is compromised; see verify --sha256).
  // --keep-old-files (GNU tar and bsdtar both support this exact long-form flag): when
  // --out-dir already held files before this run (outDirPreExisted), extraction must
  // not silently clobber them — skip a colliding name rather than overwrite it.
  try {
    await decryptToChild(decrypter, o.in, 'tar', ['-xf', '-', '--no-same-owner', '--no-same-permissions', '--keep-old-files', '-C', o.out_dir], { timeoutMs: PIPE_TIMEOUT_MS });
  } catch (e) {
    if (!outDirPreExisted) await rm(o.out_dir, { recursive: true, force: true });
    else console.error(`warning: ${o.out_dir} may now hold a partially-extracted tree (restore failed mid-stream) — discard it before trusting the contents`);
    throw e;
  } finally {
    // the extract is settled (cleanly, or the catch above already ran its own
    // non-signal cleanup) — a later signal (e.g. during pg_restore below) must not
    // touch out_dir anymore.
    setActiveRestoreOutDir(null);
  }
  console.log(`restored components into ${o.out_dir}`);
  const manifestPath = join(o.out_dir, 'manifest.json');
  if (await exists(manifestPath)) console.log(await readFile(manifestPath, 'utf8'));
  if (o.pg) {
    const dump = join(o.out_dir, 'db.dump');
    if (!(await exists(dump))) throw new Error(`--pg given but no db.dump in snapshot`);
    await run(pgTool('pg_restore'), ['--no-owner', '--no-privileges', '--clean', '--if-exists', '-d', o.pg, dump], { timeoutMs: PIPE_TIMEOUT_MS });
    console.log(`pg_restore -> ${o.pg} done`);
  }
}

// verify is the falsifiable half. Three checks:
//   1. it is real age ciphertext (header),
//   2. a WRONG key is rejected (negative control), and
//   3. when the private identity is on THIS machine, that identity decrypts the
//      whole artifact into a well-formed bundle (positive control) — this is what
//      makes PASS mean "restorable by you", and it catches truncation/corruption
//      that a wrong-key test alone would miss.
// On a public-key-only box the positive control is skipped (no identity present),
// so verify there attests only the header + that a stranger's key cannot read it —
// and reports VERDICT: PARTIAL (exit 2), never PASS, so it is not read as proof the
// snapshot is restorable by you.
export async function verify(o: CliOptions): Promise<void> {
  if (!o.in) throw new Error('--in <file.age> required');
  const sz = (await stat(o.in)).size;
  const head = await readHead(o.in, 64);
  const isAge = head.startsWith(AGE_MAGIC);
  console.log(`file: ${o.in} (${fmtBytes(sz)})`);
  console.log(`[${isAge ? 'PASS' : 'FAIL'}] age ciphertext header present`);

  // optional integrity pin: --sha256 binds the artifact to a hash known out-of-band
  // (e.g. from a trusted off-box index.tsv), catching a rolled-back/substituted
  // ciphertext that age would still decrypt. A mismatch is a hard FAIL.
  let hashOk = true;
  if (o.sha256) {
    const got = await sha256(o.in);
    hashOk = got.toLowerCase() === String(o.sha256).toLowerCase();
    console.log(`[${hashOk ? 'PASS' : 'FAIL'}] sha256 matches the expected hash${hashOk ? '' : ` (expected ${o.sha256}, got ${got})`}`);
  }

  // negative control: a throwaway key must NOT decrypt (header-only check — fast on any size)
  const wrongKeyRejected = await wrongKeyRejects(o.in);
  console.log(`[${wrongKeyRejected ? 'PASS' : 'FAIL'}] a wrong key is rejected`);

  // positive control: your identity decrypts the whole thing into a well-formed
  // bundle. Streamed (decrypt | tar -t) so it never buffers a multi-GB plaintext.
  const identity = o.identity || IDENTITY;
  let positiveOk = true;
  let positiveSkipped = false;
  if (await exists(identity)) {
    try {
      const decrypter = newDecrypter(await loadIdentities(identity)); // prompts if passphrase-wrapped
      await decryptToChild(decrypter, o.in, 'tar', ['-tf', '-'], { consStdout: 'ignore', timeoutMs: PIPE_TIMEOUT_MS });
      console.log('[PASS] your identity decrypts the artifact into a well-formed bundle');
    } catch {
      positiveOk = false;
      console.log('[FAIL] your identity could not decrypt the artifact (corrupt/truncated, or not encrypted to you)');
    }
  } else {
    positiveSkipped = true;
    console.log('[SKIP] positive control — no private identity on this machine (public-key-only box)');
  }

  // Three verdicts, not two. The header + wrong-key checks alone do NOT prove the
  // artifact is restorable BY YOU, so on a public-key-only box (positive control
  // skipped) we must NOT print PASS / exit 0 — a cron/log reading "PASS" would be
  // false-green and could mask a month of snapshots encrypted to a wrong/lost key.
  if (!isAge || !wrongKeyRejected || !positiveOk || !hashOk) {
    console.log('\nVERDICT: FAIL');
    process.exitCode = 1;
  } else if (positiveSkipped) {
    console.log('\nVERDICT: PARTIAL — header + wrong-key checks passed, but decryptability was NOT proven on this box (no private identity here). Run verify where the identity lives to prove it is restorable by you.');
    process.exitCode = 2; // distinct from PASS(0) and FAIL(1) so automation can tell them apart
  } else {
    console.log('\nVERDICT: PASS');
  }
}
