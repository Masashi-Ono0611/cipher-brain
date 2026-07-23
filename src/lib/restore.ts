// restore + verify — the decrypt half and its falsifiable proof.
import { rm, stat, readFile, writeFile } from 'node:fs/promises';
import { mkdirSync } from 'node:fs';
import { join, relative } from 'node:path';
import { createHash } from 'node:crypto';
import { AGE_MAGIC, CIPHER_YES, IDENTITY, PIPE_TIMEOUT_MS, pgTool } from './config.js';
import { run } from './proc.js';
import { loadIdentities, newDecrypter, decryptToChild, wrongKeyRejects } from './crypt.js';
import { exists, sha256, readHead, fmtBytes, redactPgConn, errMsg } from './util.js';
import { installStageSignalGuard, setActiveRestoreOutDir } from './signal-guard.js';
import { moodForVerdict, printMascot } from './ui.js';
import type { CliOptions } from './types.js';

// GNU tar's --keep-old-files, unlike bsdtar's identically-named flag, treats an
// existing-file collision as a FATAL error (exit 2, "Cannot open: File exists")
// rather than silently skipping it — so on Linux the very protection this flag is
// meant to give would instead trip the SAME code path that handles a truncated/
// corrupt artifact, misreporting "a file was protected" as "the restore failed"
// (#112 fix regressed ubuntu-latest CI, both Node 22 and 24 — confirmed locally
// against a real GNU tar 1.35 via `brew install gnu-tar`). GNU tar's
// --skip-old-files is the flag that actually matches bsdtar's --keep-old-files
// semantics (skip existing files silently, exit 0) — but bsdtar does not
// understand --skip-old-files at all ("Option --skip-old-files is not
// supported"), so neither flag alone behaves the same on both. Detect the tar
// flavor once via `tar --version` (GNU tar's output starts with "tar (GNU tar)
// …"; bsdtar's does not mention GNU at all) and pick whichever flag gives the
// SAME behavior (skip silently, exit 0) on it.
async function tarNoClobberFlag(): Promise<string> {
  try {
    const { out } = await run('tar', ['--version']);
    return out.includes('GNU tar') ? '--skip-old-files' : '--keep-old-files';
  } catch {
    return '--keep-old-files'; // conservative default if `tar --version` itself fails to run
  }
}

// One row of the mapping restore's auto-expand step prints/writes: the ORIGINAL absolute
// source path a component was captured from (manifest.components[].source), alongside
// where its extracted content ended up under --out-dir/expanded/.
interface ExpandedRow {
  dir: string; // the expanded directory's path, relative to --out-dir (for display)
  name: string; // the component's *.tar.gz filename inside --out-dir
  source: string; // the original absolute path this component was captured from
}

// The subset of snapshot.ts's ManifestComponent this file actually reads off
// already-written JSON — kept local (not imported from snapshot.ts) since restore only
// cares about a couple of fields, not the writer's exact shape, and JSON.parse's output
// is `any` regardless.
interface RestoreManifestComponent {
  name?: unknown;
  kind?: unknown;
  source?: unknown;
}

// Cap on the human-legible part of an encoded directory name (see encodeSourcePath) —
// keeps `<index>-<encoded>` comfortably under common 255-byte filename limits even for a
// deeply nested source path, before any truncation suffix is appended.
const PATH_ENCODE_MAX = 160;

// Encode an absolute source path into a filesystem-safe directory-name fragment: drop the
// leading separator(s), then replace anything that is not an ASCII alnum/dot/dash/
// underscore with '_'. Deliberately NOT collision-proof by itself (two different paths
// could in principle encode to the same string) — expandComponents() below always
// prefixes the directory name with the component's own 1-based sequence number, which
// alone guarantees no two components ever land in the same directory (manifest
// component order is stable per snapshot). This function only needs to stay human-
// legible enough to recognize the source at a glance.
function encodeSourcePath(abs: string): string {
  const flat = abs.replace(/^[/\\]+/, '').replace(/[^A-Za-z0-9._-]+/g, '_');
  if (flat.length <= PATH_ENCODE_MAX) return flat;
  // A very long/deeply-nested path could otherwise blow past a filesystem's per-component
  // name limit once the numeric prefix is added. Truncate, then append a short digest of
  // the FULL original path — purely so a human skimming expanded/ can still tell two
  // long, similarly-prefixed paths apart (the numeric prefix already makes the directory
  // itself unique regardless of this hash).
  const digest = createHash('sha256').update(abs).digest('hex').slice(0, 8);
  return `${flat.slice(0, PATH_ENCODE_MAX)}-${digest}`;
}

// Auto-expand every --dir/--profile component's staged tarball under
// <out-dir>/expanded/<NNN>-<encoded source path>/, keyed to the component's ORIGINAL
// absolute source path (manifest.components[].source) rather than its on-disk name — see
// #181: multiple --dir sources sharing a basename (e.g. many `~/.claude/projects/*/
// memory/` dirs under --profile claude-code) all restore to opaque, indistinguishable
// names like memory.tar.gz / memory-1.tar.gz / memory-2.tar.gz, and manually cross-
// referencing the manifest to untar each one correctly does not scale past a handful of
// components.
//
// A component with a `source` field is exactly a --dir/--profile component: pg_dump's
// component (kind 'pg_dump:custom') never has one, so filtering on `source` alone already
// excludes it — restore's --pg flow (pg_restore into a live connection) and this
// filesystem-only expansion never touch the same component, and neither needs the other
// to run first.
//
// Best-effort throughout: this is a convenience layer on top of an ALREADY-successful
// restore (the outer tar extraction above has already landed every component's raw
// *.tar.gz in --out-dir) — a problem here (a malformed manifest, one corrupt archive) is
// reported on stderr and skipped rather than failing the whole restore; the raw tarballs
// restore already extracted remain there as the fallback either way.
async function expandComponents(outDir: string): Promise<void> {
  const manifestPath = join(outDir, 'manifest.json');
  if (!(await exists(manifestPath))) return; // nothing to key expansion off of
  let components: RestoreManifestComponent[];
  try {
    const parsed: unknown = JSON.parse(await readFile(manifestPath, 'utf8'));
    const raw = (parsed as { components?: unknown })?.components;
    components = Array.isArray(raw) ? raw : [];
  } catch (e) {
    console.error(`warning: could not parse ${manifestPath} — skipping component auto-expand (${errMsg(e)})`);
    return;
  }
  const expandable = components.filter(
    (c): c is { name: string; source: string } =>
      typeof c.source === 'string' && typeof c.name === 'string' && c.name.endsWith('.tar.gz'),
  );
  if (expandable.length === 0) return;

  const expandedRoot = join(outDir, 'expanded');
  mkdirSync(expandedRoot, { recursive: true });
  const noClobberFlag = await tarNoClobberFlag();
  const rows: ExpandedRow[] = [];
  for (let i = 0; i < expandable.length; i++) {
    const c = expandable[i];
    const archivePath = join(outDir, c.name);
    // Absent when the outer extract's own no-clobber skip left it out (a pre-existing
    // --out-dir already held a same-named file) — nothing to expand in that case.
    if (!(await exists(archivePath))) continue;
    const dirName = `${String(i + 1).padStart(3, '0')}-${encodeSourcePath(c.source)}`;
    const targetDir = join(expandedRoot, dirName);
    mkdirSync(targetDir, { recursive: true });
    try {
      // Same no-clobber posture as the outer extract in restore() below: re-running
      // restore into an --out-dir that already holds a prior expansion of this exact
      // component must not silently overwrite what's there.
      await run(
        'tar',
        ['-xzf', archivePath, '--no-same-owner', '--no-same-permissions', noClobberFlag, '-C', targetDir],
        { timeoutMs: PIPE_TIMEOUT_MS },
      );
    } catch (e) {
      console.error(
        `warning: could not expand ${c.name} into ${targetDir} (${errMsg(e)}) — the raw ${c.name} is still in ${outDir}`,
      );
      continue;
    }
    rows.push({ dir: relative(outDir, targetDir), name: c.name, source: c.source });
  }
  if (rows.length === 0) return;

  const readme =
    [
      '# cipher-brain restore: expanded components',
      '',
      'Each row maps a directory under expanded/ back to the ABSOLUTE path it was',
      'captured from. Nothing was written back to that original path — restore never',
      'writes over a live location automatically; review the contents and copy them back',
      'yourself if that is what you want.',
      '',
      '<expanded dir>\t<-\t<original source path>\t(<component file>)',
      ...rows.map((r) => `${r.dir}\t<-\t${r.source}\t(${r.name})`),
    ].join('\n') + '\n';
  await writeFile(join(expandedRoot, 'README.txt'), readme);

  console.log(`expanded ${rows.length} component(s) into ${expandedRoot} (see expanded/README.txt):`);
  for (const r of rows) console.log(`  ${r.dir}  <-  ${r.source}`);
}

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
      `--pg ${redactPgConn(o.pg)}: pg_restore --clean --if-exists will DROP and replace objects in that database — ` +
        `re-run restore with --yes or set CIPHER_BRAIN_YES=1 to confirm`,
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
  // The no-clobber flag (see tarNoClobberFlag above): when --out-dir already held
  // files before this run (outDirPreExisted), extraction must not silently clobber
  // them — skip a colliding name rather than overwrite it, on EITHER tar flavor.
  const noClobberFlag = await tarNoClobberFlag();
  try {
    await decryptToChild(
      decrypter,
      o.in,
      'tar',
      ['-xf', '-', '--no-same-owner', '--no-same-permissions', noClobberFlag, '-C', o.out_dir],
      { timeoutMs: PIPE_TIMEOUT_MS },
    );
  } catch (e) {
    if (!outDirPreExisted) await rm(o.out_dir, { recursive: true, force: true });
    else
      console.error(
        `warning: ${o.out_dir} may now hold a partially-extracted tree (restore failed mid-stream) — discard it before trusting the contents`,
      );
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
  // Auto-expand --dir/--profile components (#181) — independent of --pg below: it only
  // ever touches components that carry a `source`, which pg_dump's never does, so the two
  // flows never race or duplicate work, and neither has to run before the other. --no-
  // expand-components is the opt-out for anyone who wants exactly the pre-#181 behavior
  // (raw *.tar.gz files only, manual untar).
  if (!o.no_expand_components) await expandComponents(o.out_dir);
  if (o.pg) {
    const dump = join(o.out_dir, 'db.dump');
    if (!(await exists(dump))) throw new Error(`--pg given but no db.dump in snapshot`);
    await run(pgTool('pg_restore'), ['--no-owner', '--no-privileges', '--clean', '--if-exists', '-d', o.pg, dump], {
      timeoutMs: PIPE_TIMEOUT_MS,
    });
    console.log(`pg_restore -> ${redactPgConn(o.pg)} done`);
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
    console.log(
      `[${hashOk ? 'PASS' : 'FAIL'}] sha256 matches the expected hash${hashOk ? '' : ` (expected ${o.sha256}, got ${got})`}`,
    );
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
  let verdict: 'PASS' | 'FAIL' | 'PARTIAL';
  if (!isAge || !wrongKeyRejected || !positiveOk || !hashOk) {
    verdict = 'FAIL';
    console.log('\nVERDICT: FAIL');
    process.exitCode = 1;
  } else if (positiveSkipped) {
    verdict = 'PARTIAL';
    console.log(
      '\nVERDICT: PARTIAL — header + wrong-key checks passed, but decryptability was NOT proven on this box (no private identity here). Run verify where the identity lives to prove it is restorable by you.',
    );
    process.exitCode = 2; // distinct from PASS(0) and FAIL(1) so automation can tell them apart
  } else {
    verdict = 'PASS';
    console.log('\nVERDICT: PASS');
  }
  // Human-facing decoration only (mascot faced for the verdict) — see
  // printMascot in ui.ts for why this is EPIPE-safe against a caller piping/
  // grepping verify's output for the VERDICT line.
  printMascot(moodForVerdict(verdict));
}
