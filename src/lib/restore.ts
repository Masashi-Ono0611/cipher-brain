// restore + verify — the decrypt half and its falsifiable proof.
import { rm, stat, readFile, writeFile, readdir, rename, lstat } from 'node:fs/promises';
import { mkdirSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative } from 'node:path';
import { createHash, randomBytes } from 'node:crypto';
import {
  AGE_MAGIC,
  CIPHER_YES,
  IDENTITY,
  PIPE_TIMEOUT_MS,
  SIGN_RECIPIENT,
  NON_CONTENT_ADDRESSED_BACKENDS,
  pgTool,
} from './config.js';
import { run } from './proc.js';
import { loadIdentities, newDecrypter, decryptToChild, wrongKeyRejects } from './crypt.js';
import { checkArtifactSignature } from './minisign.js';
import { exists, requireFile, sha256, readHead, fmtBytes, redactPgConn, errMsg, rmrf } from './util.js';
import { installStageSignalGuard, setActiveRestoreOutDir, setActiveVerifyScratchDir } from './signal-guard.js';
import { didYouMean } from './suggest.js';
import { moodForVerdict, printMascot, printJson } from './ui.js';
import { pull, signatureGap } from './pushpull.js';
import type { CliOptions } from './types.js';

// #228: this file's StrykerJS mutation run (`npm run mutation-test`) is deliberately
// scoped, with the ignore-comment markers below, to ONLY isSafeComponentName() and
// encodeSourcePath() — the two manifest-field guards PR #198's review finding was
// about, and the ones scripts/selftest-properties.mjs property-tests. Everything else
// in this file (the tar/pg_restore process orchestration, signal-guard wiring, the
// verify() report) has no fast in-process test oracle for Stryker to run per mutant —
// mutating it would only produce "survived" noise, not a security signal. See
// stryker.conf.json's own header comment for the full scope statement.
// Stryker disable all

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
// where its extracted content ended up under --out-dir/expanded/. Both `name` and
// `source` are stored here ALREADY sanitized (see sanitizeForDisplay) — this is the
// exact shape that reaches stdout and README.txt.
interface ExpandedRow {
  dir: string; // the expanded directory's path, relative to --out-dir (for display)
  name: string; // the component's *.tar.gz filename inside --out-dir (sanitized)
  source: string; // the original absolute source path (sanitized)
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
//
// Exported (#228) so scripts/selftest-properties.mjs can state its length-bound
// property in terms of the same constant, instead of a second, driftable copy of 160.
export const PATH_ENCODE_MAX = 160;

// Encode an absolute source path into a filesystem-safe directory-name fragment: drop the
// leading separator(s), then replace anything that is not an ASCII alnum/dot/dash/
// underscore with '_'. Deliberately NOT collision-proof by itself (two different paths
// could in principle encode to the same string) — expandComponents() below always
// prefixes the directory name with the component's own 1-based sequence number, which
// alone guarantees no two components ever land in the same directory (manifest
// component order is stable per snapshot). This function only needs to stay human-
// legible enough to recognize the source at a glance.
//
// Exported (#228) so scripts/selftest-properties.mjs can property-test, for ANY input
// string (manifest.components[].source is attacker-controlled — see the block above),
// that the output never contains a path separator — the invariant expandComponents()
// below relies on to build a single, un-escapable directory-name segment out of it.
// Stryker restore all
export function encodeSourcePath(abs: string): string {
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
// Stryker disable all

// ---- manifest.json is attacker-controlled data — the guards below are why ----
// age is public-key encryption: ANYONE holding a recipient's PUBLIC key can construct
// ciphertext encrypted to it and hand it over claiming to be "your backup" (this
// project's own key-recovery setup can even involve deliberately sharing a recipient
// public key with an offline-backup holder — see MANAGEMENT.md's "Key recovery"). A
// forged manifest.json inside such ciphertext is therefore something restore must
// defend against, not just malformed input to fail loudly on — a component's `name`/
// `source` fields must never be trusted as a safe filesystem path or a terminal-safe
// string before expandComponents() below does exactly that.

// A component's manifest `name` must be a bare filename directly under --out-dir: no
// directory separator, no dot-segment. Without this check, a forged name like
// "../../../etc/cron.d/evil.tar.gz" passed to join(outDir, name) would resolve OUTSIDE
// --out-dir entirely (path traversal via a crafted manifest).
//
// Exported (#228) so scripts/selftest-properties.mjs can property-test the actual
// security invariant PR #198 was about — for ANY string, if this returns true then
// join(outDir, name) must stay inside outDir — instead of only the handful of
// traversal strings a human thinks to hand-write.
// Stryker restore all
export function isSafeComponentName(name: string): boolean {
  if (name.length === 0 || name.includes('/') || name.includes('\\')) return false;
  if (name === '.' || name === '..') return false;
  return true;
}
// Stryker disable all

// Strip ASCII control characters (0x00-0x1F, 0x7F) from a manifest-derived string
// before it is ever printed to stdout/stderr or written into README.txt. A forged
// source/name value could otherwise smuggle a carriage return or ANSI escape sequence
// into terminal output or a log file — log-line forgery / terminal-escape injection —
// not merely an unreadable-but-harmless display glitch.
function sanitizeForDisplay(s: string): string {
  return s.replace(/[\x00-\x1F\x7F]/g, '?');
}

// Refuse to proceed through a pre-existing SYMLINK at `p`. mkdirSync({recursive:true})
// and a plain writeFile() both FOLLOW an existing symlink rather than refusing it — so
// a symlink planted at an otherwise-predictable expand path (e.g. by the SAME outer tar
// extract that a crafted manifest/archive already ran against --out-dir, before
// expandComponents() ever runs) could silently redirect a later tar-extract or
// README.txt write to anywhere on disk the restoring user can write, entirely outside
// --out-dir. lstat() (never stat()) is what actually SEES the symlink instead of
// resolving through it, the same discipline snapshot.ts's own symlink handling already
// follows. A path that does not exist yet is safe (nothing to follow); anything else
// that exists and is not a symlink is left for the caller's own mkdir/writeFile.
async function refuseIfSymlink(p: string, what: string): Promise<void> {
  try {
    const st = await lstat(p);
    if (st.isSymbolicLink()) {
      throw new Error(
        `${what} at ${p} is a symlink — refusing to follow it (a crafted manifest could use this to write outside --out-dir)`,
      );
    }
  } catch (e) {
    if ((e as NodeJS.ErrnoException)?.code === 'ENOENT') return; // nothing there yet — safe
    throw e;
  }
}

// Merge every entry of `src` into `dest` WITHOUT ever overwriting something already
// there — the same no-clobber posture the outer restore extract keeps. Recurses only
// into subdirectories that already exist on BOTH sides; everything else (a new file, a
// new subdirectory, a symlink, or any other entry kind tar can produce, e.g. a FIFO) is
// moved into place with a single rename() rather than a byte-copy — rename works
// identically for every entry type and needs no per-kind special-casing (unlike a copy,
// which would need one path per file kind and cannot recreate some special files at
// all). Used only when re-expanding INTO an out-dir that already holds a prior
// expansion of this exact component (see expandComponents below); a first-time
// expansion instead renames the whole freshly-extracted tree into place in one atomic
// step and never calls this at all.
async function mergeNoClobber(src: string, dest: string): Promise<void> {
  for (const entry of await readdir(src, { withFileTypes: true })) {
    const s = join(src, entry.name);
    const d = join(dest, entry.name);
    if (entry.isDirectory() && (await exists(d))) {
      await mergeNoClobber(s, d);
    } else if (!(await exists(d))) {
      await rename(s, d);
    }
    // else: `d` already exists and is not a directory to merge into — leave it
    // (no-clobber); the finally block in expandComponents() drops whatever's left
    // under `src` (the scratch dir) once this returns.
  }
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
    console.error(
      `warning: could not parse ${manifestPath} — skipping component auto-expand (${sanitizeForDisplay(errMsg(e))})`,
    );
    return;
  }
  const candidates = components.filter(
    (c): c is { name: string; source: string } =>
      typeof c.source === 'string' && typeof c.name === 'string' && c.name.endsWith('.tar.gz'),
  );
  if (candidates.length === 0) return;

  const expandedRoot = join(outDir, 'expanded');
  try {
    await refuseIfSymlink(expandedRoot, 'expand root');
  } catch (e) {
    console.error(`warning: ${errMsg(e)} — skipping component auto-expand entirely`);
    return;
  }
  mkdirSync(expandedRoot, { recursive: true });
  const rows: ExpandedRow[] = [];
  for (let i = 0; i < candidates.length; i++) {
    const c = candidates[i];
    // A forged manifest `name` (e.g. "../../../etc/cron.d/evil.tar.gz") must never be
    // trusted as a path component — see the threat-model note above encodeSourcePath.
    // Reject anything that is not a bare filename and move on to the next component;
    // this is the ONLY thing that ever builds `archivePath` from `c.name`.
    if (!isSafeComponentName(c.name)) {
      console.error(
        `warning: skipping component with an unsafe manifest name "${sanitizeForDisplay(c.name)}" ` +
          '(contains a path separator or is a dot-segment) — refusing to treat manifest.json\'s "name" as a path',
      );
      continue;
    }
    const archivePath = join(outDir, c.name);
    // Absent when the outer extract's own no-clobber skip left it out (a pre-existing
    // --out-dir already held a same-named file) — nothing to expand in that case.
    if (!(await exists(archivePath))) continue;

    const dirName = `${String(i + 1).padStart(3, '0')}-${encodeSourcePath(c.source)}`;
    const targetDir = join(expandedRoot, dirName);
    try {
      await refuseIfSymlink(targetDir, 'expanded component directory');
    } catch (e) {
      console.error(`warning: ${errMsg(e)} — skipping ${sanitizeForDisplay(c.name)}`);
      continue;
    }
    // A prior run's expansion of this exact component, if any — re-running restore
    // into the same --out-dir merges into it (mergeNoClobber below) rather than
    // clobbering it; a first-time expansion instead renames the whole freshly-
    // extracted tree into place atomically (see the scratchDir handling below).
    const targetExisted = await exists(targetDir);
    // Extract into a fresh, uniquely-named SCRATCH directory first — never straight
    // into targetDir. A tar that dies mid-stream then leaves nothing behind under
    // targetDir's real name (the finally block below always removes the scratch dir),
    // instead of a half-written tree that a later no-clobber re-run could never
    // repair (no-clobber only ever SKIPS an existing name; it has no way to tell a
    // complete extraction from a truncated one).
    const scratchDir = `${targetDir}.expand-${process.pid}-${randomBytes(4).toString('hex')}`;
    try {
      await refuseIfSymlink(scratchDir, 'expand scratch directory'); // defense in depth: this name should never pre-exist
      mkdirSync(scratchDir, { recursive: true });
      await run('tar', ['-xzf', archivePath, '--no-same-owner', '--no-same-permissions', '-C', scratchDir], {
        timeoutMs: PIPE_TIMEOUT_MS,
      });
      if (targetExisted) await mergeNoClobber(scratchDir, targetDir);
      else await rename(scratchDir, targetDir);
    } catch (e) {
      console.error(
        `warning: could not expand ${sanitizeForDisplay(c.name)} into ${targetDir} (${sanitizeForDisplay(errMsg(e))}) — the raw ${sanitizeForDisplay(c.name)} is still in ${outDir}`,
      );
      continue;
    } finally {
      await rm(scratchDir, { recursive: true, force: true }); // no-op once rename() has already moved it away
    }
    rows.push({
      dir: relative(outDir, targetDir),
      name: sanitizeForDisplay(c.name),
      source: sanitizeForDisplay(c.source),
    });
  }
  if (rows.length === 0) return;

  const readmePath = join(expandedRoot, 'README.txt');
  try {
    await refuseIfSymlink(readmePath, 'expanded/README.txt');
    // A prior run already wrote this mapping (re-running restore into the same
    // --out-dir reprocesses the same manifest, so the rows would be identical) —
    // leave it untouched rather than clobbering or duplicating it via append, the
    // same no-clobber posture the expanded component directories themselves keep.
    if (!(await exists(readmePath))) {
      const readmeLines = [
        '# cipher-brain restore: expanded components',
        '',
        'Each row maps a directory under expanded/ back to the ABSOLUTE path it was',
        'captured from. Nothing was written back to that original path — restore never',
        'writes over a live location automatically; review the contents and copy them back',
        'yourself if that is what you want.',
        '',
        '<expanded dir>\t<-\t<original source path>\t(<component file>)',
        ...rows.map((r) => `${r.dir}\t<-\t${r.source}\t(${r.name})`),
      ];
      await writeFile(readmePath, `${readmeLines.join('\n')}\n`);
    }
  } catch (e) {
    console.error(`warning: ${errMsg(e)} — the expanded directories above are still there, just without a README.txt`);
  }

  console.log(`expanded ${rows.length} component(s) into ${expandedRoot} (see expanded/README.txt):`);
  for (const r of rows) console.log(`  ${r.dir}  <-  ${r.source}`);
}

// restore() itself (unlike push(), which is shared with the MCP server and the
// init wizard) is called ONLY from cli.ts — no other caller reuses it — so it is
// safe to print the mood mascot right here rather than at a dispatch call site:
// happy on a clean return, sad on any thrown failure (issue #194). Decoration
// only, on stderr (see printMascot in ui.ts), so it never touches the extracted
// files or any machine-readable output.
export async function restore(o: CliOptions): Promise<void> {
  try {
    await restoreImpl(o);
  } catch (e) {
    printMascot('sad');
    throw e;
  }
  // Deliberately OUTSIDE the try: printMascot('happy') itself throwing (e.g. some
  // unforeseen console.error failure) must never be misreported as restoreImpl
  // failing — if it were still inside the try, that throw would land in the catch
  // above and print 'sad' + rethrow over a restore that actually already
  // succeeded (multi-model review finding on PR #200).
  printMascot('happy');
}

async function restoreImpl(o: CliOptions): Promise<void> {
  if (!o.in) throw new Error('--in <file.age> required');
  // #277: `--out` is what names the destination on snapshot/pull/wallet create, so
  // typing it here is the natural mistake — and parseArgs accepts it (it is a valid
  // flag SOMEWHERE) and then nothing reads it, leaving a bare "--out-dir required"
  // that reads as if no destination had been given at all. Name what was ignored.
  // #300: the "did you mean" wording itself comes from src/lib/suggest.ts, the one
  // place that phrases it — the MCP server refuses unknown tool arguments with the
  // same idiom, and two hand-written copies would drift. Only the PHRASING is shared:
  // which flag was meant is known outright here, so this message never depends on a
  // fuzzy match firing.
  if (!o.out_dir) {
    throw new Error(
      o.out
        ? `--out-dir <dir> required (restore extracts into a directory; you passed --out, which restore does not read — ${didYouMean('--out-dir')})`
        : '--out-dir <dir> required',
    );
  }
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
  // #267: deliberately AFTER the consent gate above, not before it — a missing --in
  // must not demote the irreversible-pg_restore warning to second place (multi-model
  // review finding). Still before ANY decrypt work, which is the point: a missing
  // --in used to reach the age call and surface as "age decrypt failed: ENOENT …
  // [CB-E002]", a code MANAGEMENT.md documents as "wrong identity, or a corrupt/
  // truncated artifact" — a key audit in answer to a typo.
  await requireFile(o.in);
  // Authenticity check FIRST (#214), before any decryption or even the age identity
  // check below: age proves confidentiality + tamper detection, but NOT authenticity
  // (a recipient's public key is not secret — anyone holding it can forge ciphertext
  // that decrypts cleanly). A tampered/forged *.minisig always refuses outright. An
  // ABSENT signature (unsigned/legacy artifact) or an absent signing public key on this
  // box are non-fatal (warn and continue) BY DEFAULT — so this never breaks a pre-#214
  // backup or an existing setup that hasn't run `keygen --sign` — UNLESS --require-
  // signature opts into strict mode, in which case an attacker who simply deletes the
  // .minisig sidecar (rather than forging one) no longer silently succeeds either.
  const signRecipient = o.sign_recipient || SIGN_RECIPIENT;
  // An EXPLICITLY-named --sign-recipient that doesn't exist is a configuration typo,
  // not "authenticity isn't set up yet" — silently falling back to no_pubkey/SKIP here
  // would make a mistyped path look identical to a deliberately unconfigured one. Only
  // the DEFAULT path missing means "not opted in yet" (see snapshot.ts's --sign-identity
  // for the same distinction on the signing side).
  if (o.sign_recipient && !(await exists(o.sign_recipient))) {
    throw new Error(`--sign-recipient ${o.sign_recipient} does not exist`);
  }
  const sigCheck = await checkArtifactSignature(o.in, signRecipient);
  if (sigCheck.status === 'invalid') {
    throw new Error(`refusing to restore ${o.in}: ${sigCheck.reason}`);
  }
  if (sigCheck.status === 'verified') {
    console.log(`[PASS] minisign authenticity signature verified (${o.in}.minisig)`);
  } else if (o.require_signature) {
    throw new Error(`refusing to restore ${o.in}: --require-signature was given but ${sigCheck.reason}`);
  } else {
    console.error(`warning: ${sigCheck.reason}`);
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

// The result runFileChecks() computes over one already-on-disk *.age file — the same
// shape verify --level quick always reported, factored out so --level remote/drill (#209
// below) can run the identical checks against a file they just pulled into a scratch
// location, instead of a second, divergent implementation of "is this ciphertext good".
interface FileCheckResult {
  file: string;
  sizeBytes: number;
  checks: {
    age_header: boolean;
    sha256_match: boolean | null;
    signature: 'pass' | 'fail' | 'skip';
    wrong_key_rejected: boolean | 'skip';
    positive_control: 'pass' | 'fail' | 'skip';
  };
  verdict: 'PASS' | 'FAIL' | 'PARTIAL';
}

// The human-readable "VERDICT: …" line's wording, factored out of runFileChecks below so
// finishVerify can print the SAME sentence for a verdict runFileChecks itself was told
// NOT to print yet (--level drill's FAIL/PARTIAL early-return, below — its overall
// verdict still depends on a restore step that never runs in that case, so the line
// belongs to finishVerify there, not to runFileChecks) — one wording, not two copies
// that could drift apart on the PARTIAL sentence (#209 review).
function printFileCheckVerdict(verdict: 'PASS' | 'FAIL' | 'PARTIAL'): void {
  if (verdict === 'FAIL') console.log('\nVERDICT: FAIL');
  else if (verdict === 'PARTIAL') {
    console.log(
      '\nVERDICT: PARTIAL — header + wrong-key checks passed, but decryptability was NOT proven on this box (no private identity here). Run verify where the identity lives to prove it is restorable by you.',
    );
  } else {
    console.log('\nVERDICT: PASS');
  }
}

// runFileChecks is the falsifiable half. Three checks:
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
//
// Prints its own narrative (gated by !o.json, exactly like verify always has) and sets
// process.exitCode to match ITS verdict — a caller that goes on to do more after this
// (verify --level drill's full-restore step, below) simply sets process.exitCode again
// once it knows the combined outcome; whichever runs last wins, so nothing needs undoing.
// `printVerdictLine` only suppresses the "VERDICT: …" line itself (still gated by !o.json
// either way) — --level drill passes false here because ITS verdict depends on a step
// that hasn't run yet when this returns, and printing an interim one would be read as
// final.
async function runFileChecks(o: CliOptions, printVerdictLine: boolean): Promise<FileCheckResult> {
  if (!o.in) throw new Error('--in <file.age> required');
  await requireFile(o.in); // #267: before stat(), so a typo is not a raw ENOENT
  const sz = (await stat(o.in)).size;
  const head = await readHead(o.in, 64);
  const isAge = head.startsWith(AGE_MAGIC);
  if (!o.json) {
    console.log(`file: ${o.in} (${fmtBytes(sz)})`);
    console.log(`[${isAge ? 'PASS' : 'FAIL'}] age ciphertext header present`);
  }

  // optional integrity pin: --sha256 binds the artifact to a hash known out-of-band
  // (e.g. from a trusted off-box index.tsv), catching a rolled-back/substituted
  // ciphertext that age would still decrypt. A mismatch is a hard FAIL. `hashOk` stays
  // `null` (not checked, not a pass/fail) when --sha256 was not given at all.
  let hashOk: boolean | null = null;
  let gotHash: string | undefined;
  if (o.sha256) {
    gotHash = await sha256(o.in);
    hashOk = gotHash.toLowerCase() === String(o.sha256).toLowerCase();
    if (!o.json) {
      console.log(
        `[${hashOk ? 'PASS' : 'FAIL'}] sha256 matches the expected hash${hashOk ? '' : ` (expected ${o.sha256}, got ${gotHash})`}`,
      );
    }
  }

  // authenticity (#214): does a *.minisig sidecar next to --in verify against the
  // configured signing public key? `null` (not 'pass'/'fail') when there is nothing
  // to check — no sidecar (unsigned/legacy artifact) or no signing public key on this
  // box — mirrors hashOk's own null-means-skipped contract above; a tampered/forged
  // signature is the only case this fails, and (per #214) it also SKIPS the positive
  // control below rather than decrypting an artifact already known to be untrustworthy.
  const signRecipient = o.sign_recipient || SIGN_RECIPIENT;
  // An EXPLICITLY-named --sign-recipient that doesn't exist is a configuration typo,
  // not "authenticity isn't set up yet" (see restoreImpl's identical guard above).
  if (o.sign_recipient && !(await exists(o.sign_recipient))) {
    throw new Error(`--sign-recipient ${o.sign_recipient} does not exist`);
  }
  const sigCheck = await checkArtifactSignature(o.in, signRecipient);
  let sigOk: boolean | null = sigCheck.status === 'verified' ? true : sigCheck.status === 'invalid' ? false : null;
  // --require-signature (#214): an absent signature or absent signing public key is a
  // SKIP by default (backward compatible with unsigned/pre-#214 artifacts) — this
  // upgrades that to a hard FAIL, so an attacker who deletes the .minisig sidecar
  // instead of forging one no longer silently passes either, for callers who opt in.
  if (sigOk === null && o.require_signature) sigOk = false;
  if (!o.json) {
    if (sigOk === null) console.log(`[SKIP] minisign authenticity signature — ${sigCheck.reason}`);
    else
      console.log(
        `[${sigOk ? 'PASS' : 'FAIL'}] minisign authenticity signature verified${sigOk ? '' : ` (${sigCheck.reason})`}`,
      );
  }

  // negative control: a throwaway key must NOT decrypt (header-only check — fast on any
  // size). Skipped when the signature above is already known INVALID — every decrypt
  // attempt against an artifact known to be tampered/forged is one this module claims
  // never happens once authenticity fails (#214), and this is itself a decrypt attempt
  // (with a throwaway key, but still one), so it must not run either.
  let wrongKeyRejected = true;
  let wrongKeyCheckSkipped = false;
  if (sigOk === false) {
    wrongKeyCheckSkipped = true;
    if (!o.json) console.log('[SKIP] a wrong key is rejected — skipped (the authenticity signature above failed)');
  } else {
    wrongKeyRejected = await wrongKeyRejects(o.in);
    if (!o.json) console.log(`[${wrongKeyRejected ? 'PASS' : 'FAIL'}] a wrong key is rejected`);
  }

  // positive control: your identity decrypts the whole thing into a well-formed
  // bundle. Streamed (decrypt | tar -t) so it never buffers a multi-GB plaintext.
  // Skipped outright (never attempted) when the signature above was checked and found
  // INVALID — decrypting an artifact already known to be tampered/forged proves
  // nothing and (per #214) restore's own equivalent check refuses outright rather
  // than decrypt, so verify's report should not imply this one just "went ahead".
  const identity = o.identity || IDENTITY;
  let positiveOk = true;
  let positiveSkipped = false;
  if (sigOk === false) {
    positiveSkipped = true;
    if (!o.json) console.log('[SKIP] positive control — skipped (the authenticity signature above failed)');
  } else if (await exists(identity)) {
    try {
      const decrypter = newDecrypter(await loadIdentities(identity)); // prompts if passphrase-wrapped
      await decryptToChild(decrypter, o.in, 'tar', ['-tf', '-'], { consStdout: 'ignore', timeoutMs: PIPE_TIMEOUT_MS });
      if (!o.json) console.log('[PASS] your identity decrypts the artifact into a well-formed bundle');
    } catch {
      positiveOk = false;
      if (!o.json)
        console.log('[FAIL] your identity could not decrypt the artifact (corrupt/truncated, or not encrypted to you)');
    }
  } else {
    positiveSkipped = true;
    if (!o.json) console.log('[SKIP] positive control — no private identity on this machine (public-key-only box)');
  }

  // Three verdicts, not two. The header + wrong-key checks alone do NOT prove the
  // artifact is restorable BY YOU, so on a public-key-only box (positive control
  // skipped) we must NOT print PASS / exit 0 — a cron/log reading "PASS" would be
  // false-green and could mask a month of snapshots encrypted to a wrong/lost key.
  let verdict: 'PASS' | 'FAIL' | 'PARTIAL';
  if (!isAge || !wrongKeyRejected || !positiveOk || hashOk === false || sigOk === false) {
    verdict = 'FAIL';
    if (!o.json && printVerdictLine) printFileCheckVerdict('FAIL');
    process.exitCode = 1;
  } else if (positiveSkipped) {
    verdict = 'PARTIAL';
    if (!o.json && printVerdictLine) printFileCheckVerdict('PARTIAL');
    process.exitCode = 2; // distinct from PASS(0) and FAIL(1) so automation can tell them apart
  } else {
    verdict = 'PASS';
    if (!o.json && printVerdictLine) printFileCheckVerdict('PASS');
  }

  return {
    file: o.in,
    sizeBytes: sz,
    checks: {
      age_header: isAge,
      sha256_match: hashOk, // null when --sha256 was not passed (check skipped, not failed)
      signature: sigOk === null ? 'skip' : sigOk ? 'pass' : 'fail', // #214: 'skip' when unsigned or no signing pubkey on this box
      wrong_key_rejected: wrongKeyCheckSkipped ? 'skip' : wrongKeyRejected, // #214: 'skip' when the authenticity signature above already failed
      positive_control: positiveSkipped ? 'skip' : positiveOk ? 'pass' : 'fail',
    },
    verdict,
  };
}

// Shared tail for --level quick and --level remote (drill's final report is its own,
// below, since its verdict also depends on the restore step that runs after
// runFileChecks) — --json: the SAME checks/verdict runFileChecks computed, as one
// machine-readable line on stdout instead of the human-readable report — never a
// re-implementation, so this can never disagree with either the human-readable report
// above or the MCP verify_restore tool (#211). `extra` (added by #209's --level remote)
// is spread in between checks and verdict so a --level quick caller's JSON shape is
// completely unaffected (extra is never passed there).
//
// `printVerdictLine` (default false): quick and remote already had runFileChecks itself
// print the "VERDICT: …" line (they pass printVerdictLine=true THERE, so finishVerify
// must not print a second one here — the default covers that). --level drill's own
// FAIL/PARTIAL early return (below) is the one caller that passes true here: it told
// runFileChecks NOT to print one (drill's overall verdict still depended on the restore
// step at that point), but once drill decides to SKIP that step, r.verdict IS the final
// answer and the promised "VERDICT: FAIL/PARTIAL" line was going unprinted entirely —
// silently downgrading a documented contract to only an exit code (#209 review).
function finishVerify(
  o: CliOptions,
  r: FileCheckResult,
  extra?: Record<string, unknown>,
  printVerdictLine = false,
): void {
  const exitCode = process.exitCode ?? 0;
  if (!o.json && printVerdictLine) printFileCheckVerdict(r.verdict);
  if (o.json) {
    printJson({
      file: r.file,
      size_bytes: r.sizeBytes,
      checks: r.checks,
      ...(extra ?? {}),
      verdict: r.verdict,
      exit_code: exitCode,
    });
  }
  // Human-facing decoration only (mascot faced for the verdict) — see printMascot in
  // ui.ts for why this is EPIPE-safe against a caller piping/grepping verify's output
  // for the VERDICT line. Never printed on --json (ui.ts: "nothing here should be
  // called on a --json / piped path") — it writes to stderr only, so it would never
  // corrupt the JSON on stdout, but a --json caller asked for machine-readable output
  // only, not ASCII-art decoration alongside it.
  if (!o.json) printMascot(moodForVerdict(r.verdict));
}

// verify --level quick|remote|drill (issue #209): three progressively deeper checks that
// the ciphertext is actually durable, not just three ways to read the SAME local file.
//   quick  (default, unchanged since before #209): everything runFileChecks does above,
//          against --in as given — a structural check, no network access, restic
//          `check`'s speed class. Rejects --locator/--backend/--from-locator-file: those
//          name something to FETCH, and quick never fetches anything.
//   remote: pulls the artifact by --locator/--backend (or --from-locator-file) into a
//           scratch temp file, then runs the SAME runFileChecks against THAT — restic
//           `check --read-data-subset`'s idea, proving the object is still actually
//           retrievable from storage and unchanged, not merely that a local copy still
//           parses.
//   drill:  does everything remote does, and — only once those checks reach PASS — ALSO
//           decrypts and extracts the pulled artifact into a scratch out-dir (the same
//           restoreImpl() the `restore` command runs), the full pull -> decrypt -> extract
//           rehearsal MANAGEMENT.md's restore runbook / identity backup drill describe.
//           Never runs pg_restore even if --pg is given (see the refusal below) — a
//           verification drill must not write to a live database. The scratch directory
//           (pulled ciphertext + extracted plaintext) is always removed afterward, success
//           or failure — this proves restorability, it does not perform a real restore.
export async function verify(o: CliOptions): Promise<void> {
  const level = o.level ?? 'quick';
  if (level !== 'quick' && level !== 'remote' && level !== 'drill') {
    throw new Error(`--level must be quick, remote or drill (got "${o.level}")`);
  }

  if (level === 'quick') {
    if (o.locator || o.backend || o.from_locator_file) {
      throw new Error(
        '--level quick checks the LOCAL --in file only — it never fetches from storage, so --locator/' +
          '--backend/--from-locator-file have nothing to do here (--level remote or --level drill fetch by ' +
          'those instead of taking --in)',
      );
    }
    const r = await runFileChecks(o, true);
    finishVerify(o, r);
    return;
  }

  // remote and drill both start the same way: actually fetch the artifact. That fetch IS
  // the point of both — --level quick can only ever look at bytes already on this
  // machine, so it can never prove the storage side of "will this still be here".
  if (o.in) {
    throw new Error(
      `--level ${level} fetches the artifact from storage itself — pass --locator/--backend or ` +
        '--from-locator-file (like pull does), not --in, which only names a file already on this machine ' +
        '(that is what --level quick checks)',
    );
  }
  if (!o.from_locator_file && !(o.locator && o.backend)) {
    throw new Error(
      `--level ${level} requires --locator <id> --backend <name>, or --from-locator-file <path> — the ` +
        'artifact to actually fetch and check',
    );
  }
  if (level === 'drill' && o.pg) {
    throw new Error(
      '--level drill never runs pg_restore, even when --pg is given — a verification drill must not write ' +
        'to a live database. Use `restore --pg <conn>` separately if you actually want to recover into one.',
    );
  }

  // installStageSignalGuard() (idempotent) BEFORE the scratch dir exists — remote/drill
  // reach here without restoreImpl() ever having called it (that only happens for drill,
  // and only once its own checks already reached PASS), so without this call up front a
  // signal during the fetch/checks below would hit no handler at all.
  installStageSignalGuard();
  let scratchRoot: string | null = null;
  try {
    // mkdtempSync (not async mkdtemp), and setActiveVerifyScratchDir called immediately
    // after with no await between them — same one-tick discipline snapshot.ts's own
    // ACTIVE_STAGE registration uses (see signal-guard.ts): a signal landing during an
    // await could otherwise fire the handler while this scratch dir is still untracked,
    // leaking it (multi-model review finding on PR #332 — the ORIGINAL bug this whole
    // function needed to close, not just drill's later decrypt+extract step).
    scratchRoot = mkdtempSync(join(tmpdir(), 'cipher-brain-verify-'));
    setActiveVerifyScratchDir(scratchRoot);
    const target = join(scratchRoot, 'pulled.age');
    // A fresh CliOptions object, not a spread of `o`: pull() only needs to know WHERE to
    // fetch from and WHERE to land it, and building it explicitly means no other field a
    // future CliOptions grows can leak into a pull call that was never meant to see it.
    const pullOpts: CliOptions = {
      locator: o.locator,
      backend: o.backend,
      from_locator_file: o.from_locator_file,
      sha256: o.sha256,
      out: target,
      dirs: [],
      tables: [],
      recipients: [],
    };
    // pull()'s own narrative (retries, the "sha256 OK: …" confirmation, "pulled x -> y",
    // and — the reason this is captured rather than left to print directly — a warning
    // naming WHY an authenticity signature sidecar could not be fetched) goes to
    // console.error. Captured here, not silenced: every line is replayed to the real
    // stderr immediately below (success or failure), so this changes nothing an operator
    // actually sees — it only ALSO makes pull()'s log available to signatureGap() so a
    // deleted/unfetchable .minisig sidecar can be told apart from an artifact that was
    // simply never signed (src/mcp.ts's verify_restore/restore_now already do exactly
    // this over MCP, #312; --json here had no equivalent at all, #209 review).
    const pullLog: string[] = [];
    const prevConsoleError = console.error;
    console.error = (...a: unknown[]) => {
      pullLog.push(a.map(String).join(' '));
    };
    try {
      try {
        await pull(pullOpts);
      } finally {
        console.error = prevConsoleError;
        for (const line of pullLog) console.error(line);
      }
    } catch (e) {
      // Remote retrievability is exactly what --level remote/drill exists to test — a
      // fetch failure here (not-yet-propagated, deleted, wrong locator, sha256 mismatch, a
      // dead gateway) IS the verdict, not a crash: report FAIL the same way an on-disk
      // check would, rather than letting pull()'s exception propagate raw past this point.
      const msg = errMsg(e);
      if (!o.json) {
        console.log(`level: ${level}`);
        console.log(
          `[FAIL] could not fetch the artifact from ${pullOpts.backend ?? '(unresolved backend)'}` +
            `${pullOpts.locator ? `:${pullOpts.locator}` : ''} (${msg})`,
        );
        console.log('\nVERDICT: FAIL');
      }
      process.exitCode = 1;
      if (o.json) {
        printJson({
          level,
          pulled: {
            backend: pullOpts.backend ?? null,
            locator: pullOpts.locator ?? null,
            // Present even on a failed fetch (previously absent here, unlike every OTHER
            // `pulled` shape below) — the same field, the same meaning, regardless of
            // outcome, rather than a caller having to know it only sometimes exists
            // (#209 review).
            sha256_pin: pullOpts.sha256 ?? null,
            fetched: false,
            error: msg,
          },
          verdict: 'FAIL',
          exit_code: 1,
        });
      }
      if (!o.json) printMascot('sad');
      return;
    }
    // sig_locator is pull()'s own bookkeeping, filled in on `pullOpts` (the SAME object
    // reference passed to pull() above) when --from-locator-file recorded one — read
    // AFTER the call, exactly like signatureGap()'s other two callers in src/mcp.ts do.
    const sigGap = signatureGap(pullLog, pullOpts.sig_locator);
    const pulledInfo = {
      backend: pullOpts.backend,
      locator: pullOpts.locator,
      sha256_pin: pullOpts.sha256 ?? null,
      fetched: true,
      ...(sigGap ? { signature: sigGap } : {}),
    };
    if (!o.json) {
      console.log(`level: ${level}`);
      console.log(`[PASS] fetched from ${pullOpts.backend}:${pullOpts.locator} (remote retrievability confirmed)`);
      if (!pullOpts.sha256 && pullOpts.backend && NON_CONTENT_ADDRESSED_BACKENDS.has(pullOpts.backend)) {
        console.log(
          `warning: no sha256 pin was applied — ${pullOpts.backend} locators are not content hashes ` +
            '(post-assigned ids for arweave/turbo, an operator-chosen remote path for rclone), so a ' +
            'substituted/rolled-back object served at the same locator would not be detected here (pass ' +
            '--sha256, or use --from-locator-file, to fail closed)',
        );
      }
    }

    // Same checks as --level quick, run against the just-pulled file. --level remote's
    // own verdict line prints normally here (drill's does not — its overall verdict still
    // depends on the restore step below, so printing one now would read as final).
    const r = await runFileChecks({ ...o, in: target, sha256: pullOpts.sha256 }, level === 'remote');

    if (level === 'remote') {
      finishVerify(o, r, { level, pulled: pulledInfo });
      return;
    }

    // drill only goes on to a real decrypt+extract once the checks above actually reached
    // PASS. FAIL means the artifact itself is bad (wrong key rejected it, a tampered
    // signature, a hash mismatch, corrupt bytes, …) — restoreImpl() below would just
    // rethrow the identical problem restore's own checks already report, proving nothing
    // new. PARTIAL means there is no private identity on this box at all, so restoreImpl()
    // cannot even start (it requires one) — nothing left to drill either.
    if (r.verdict !== 'PASS') {
      if (!o.json) {
        console.log(
          r.verdict === 'PARTIAL'
            ? '[SKIP] full restore drill — no private identity on this box to decrypt with'
            : '[SKIP] full restore drill — the checks above already failed',
        );
      }
      finishVerify(o, r, { level, pulled: pulledInfo, full_restore: 'skip' }, true);
      return;
    }

    // restoreImpl(), NOT restore(): restore() prints its own mood mascot on success/failure
    // (issue #194), and a drill's own final mascot below would double up with it. Its
    // stdout narrative (the manifest.json dump, "restored components into …", the
    // component auto-expand summary) is captured rather than left to print directly, so a
    // --json drill still emits exactly one JSON line on stdout — the same contract #211
    // already holds --level quick/remote to.
    const restoreOutDir = join(scratchRoot, 'restored');
    // A fresh CliOptions object, NOT a spread of `o`: restoreImpl() reads o.pg and would
    // run pg_restore --clean --if-exists (an irreversible DROP) if it were passed through
    // here — refused above already, but this also means no OTHER field a future CliOptions
    // grows can reach restoreImpl() from a verify call unnoticed either.
    const restoreOpts: CliOptions = {
      in: target,
      out_dir: restoreOutDir,
      identity: o.identity,
      sign_recipient: o.sign_recipient,
      require_signature: o.require_signature,
      dirs: [],
      tables: [],
      recipients: [],
    };
    const restoreStdout: string[] = [];
    const prevLog = console.log;
    console.log = (...a: unknown[]) => {
      restoreStdout.push(a.map(String).join(' '));
    };
    let restoreOk = true;
    let restoreErr: string | undefined;
    try {
      await restoreImpl(restoreOpts);
    } catch (e) {
      restoreOk = false;
      restoreErr = errMsg(e);
    } finally {
      console.log = prevLog;
    }
    if (!o.json) {
      if (restoreOk) for (const line of restoreStdout) console.log(`  ${line}`);
      console.log(
        restoreOk
          ? '[PASS] full restore (decrypt + extract, incl. component auto-expand) into a scratch directory succeeded'
          : `[FAIL] full restore into a scratch directory failed (${restoreErr})`,
      );
    }
    const finalVerdict: 'PASS' | 'FAIL' = restoreOk ? 'PASS' : 'FAIL';
    if (!o.json) console.log(`\nVERDICT: ${finalVerdict}`);
    process.exitCode = finalVerdict === 'PASS' ? 0 : 1;
    if (o.json) {
      printJson({
        level,
        pulled: pulledInfo,
        checks: r.checks,
        full_restore: restoreOk,
        ...(restoreErr ? { full_restore_error: restoreErr } : {}),
        verdict: finalVerdict,
        exit_code: process.exitCode,
      });
    }
    if (!o.json) printMascot(finalVerdict === 'PASS' ? 'happy' : 'sad');
  } finally {
    // Best-effort, same posture as mcp.ts's own scratch-tmpdir cleanup (handleVerifyRestore/
    // handleRestoreNow) — always removed, whether the fetch, the checks, or the restore
    // step failed. Nothing here is meant to survive past this call: --level remote never
    // writes plaintext at all, and --level drill's whole point is proving restorability
    // without performing an actual restore. rmrf (util.ts), not a plain rm(): a --dir
    // source captured with a restrictive mode (or a component tarball that recorded one)
    // can leave a read-only directory under here even though the extract itself passes
    // --no-same-permissions, and force:true alone does not retry past the EACCES that
    // causes (#209 review). Only cleared from the signal guard AFTER removal actually
    // finishes — a signal arriving mid-rmrf must still find scratchRoot tracked.
    if (scratchRoot) {
      await rmrf(scratchRoot);
      setActiveVerifyScratchDir(null);
    }
  }
}
