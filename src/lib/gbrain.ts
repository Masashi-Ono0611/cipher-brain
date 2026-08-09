// gbrain — engine detection for the second brain this tool was built for (#367).
//
// gbrain ships TWO storage engines behind one contract, and PGLite (Postgres 17
// compiled to WASM, whose whole database is a DIRECTORY on disk) is the zero-config
// DEFAULT — not Postgres. cipher-brain had assumed a Postgres server unconditionally
// wherever it touched gbrain, so a default-configuration gbrain user was told their
// real data lives somewhere it does not, and had a live single-writer store copied
// out from under them with no consistency guard. Both consumers (the init wizard and
// snapshot's --dir staging) now branch on what is actually there.
//
// Credit: the engine defaults, the torn-store failure signature, and the
// `gbrain pglite-repair` recovery command are all gbrain's own — see
// https://github.com/garrytan/gbrain (v0.42.75.0 and its README's engine section).
// Nothing is copied from it; the rules below are reimplemented from the documented
// config contract and described here in our own words.
import type { Dirent } from 'node:fs';
import { readdir, readFile, stat } from 'node:fs/promises';
import { dirname, isAbsolute, join, resolve } from 'node:path';

export type GbrainEngine = 'pglite' | 'postgres';

/** What a gbrain config file says about where the brain lives. See detectGbrainEngine. */
export interface GbrainEngineInfo {
  engine: GbrainEngine;
  /**
   * The configured PGLite store, as an ABSOLUTE path — present only on a PGLite brain
   * whose config records `database_path`. Absent means "PGLite, but the config does not
   * say where", which callers must treat as unknown rather than guessing a location.
   */
  dataPath?: string;
}

/**
 * What a gbrain home is configured for, mirroring gbrain's OWN resolution order for the
 * config file: an explicit `engine` field wins; otherwise the presence of
 * `database_path` (the on-disk PGLite data directory) implies PGLite; otherwise
 * Postgres. Anything unreadable or unparseable falls back to 'postgres' — the pre-#367
 * assumption, so a malformed config can never make this the thing that breaks a run.
 *
 * READS EXACTLY TWO FIELDS, AND RETURNS THE VERDICT PLUS `database_path`. `config.json`
 * holds API keys, so nothing else in it is logged, echoed, copied, or returned. That is
 * a hard constraint on this function, not an implementation detail — an added "return
 * the parsed config for convenience" is how a key ends up in a transcript, and that
 * remains forbidden.
 *
 * `database_path` is the ONE deliberate exemption (multi-model review, P1). Returning
 * only a yes/no verdict forced the wizard to hard-code `~/.gbrain` when it told the
 * operator whether their chosen directories covered the store — so a brain configured
 * at, say, `/srv/gbrain` was confirmed as covered by a backup that did not contain the
 * database at all. That is the exact failure #367 exists to eliminate, in a new form.
 * The field is a filesystem path, not a credential, and it is the only way to answer
 * the question correctly. Nothing else follows it out of this function.
 *
 * A relative `database_path` is resolved against the CONFIG FILE's own directory. gbrain
 * itself hands the raw value to PGLite, which resolves it against whatever process cwd
 * gbrain happens to have — not something we can know from here, and not stable enough to
 * copy. The config's directory is the one anchor that is always well-defined, and the
 * wizard prints the resolved path, so an operator can see the assumption and correct it.
 * In practice gbrain writes an absolute path and this never comes up.
 *
 * FILE ONLY — `GBRAIN_DATABASE_URL` / `DATABASE_URL` are deliberately NOT consulted,
 * and gbrain's own runtime resolution must not be imported here to "fix" that. gbrain
 * lets such an env var win outright and force Postgres (it even clears `database_path`
 * in its merged config), which is right for the question IT is asking — "which engine
 * will this process connect to right now?". cipher-brain is asking a different one:
 * "what is on this disk, and does copying it need a warning?". An exported
 * DATABASE_URL does not make an existing PGLite directory stop existing, stop holding
 * data, or stop tearing when copied mid-write. Upstream hit exactly this as a P1 in a
 * gbrain doctor check (garrytan/gbrain#3879): a temporarily-exported DATABASE_URL made
 * a live PGLite brain look like Postgres and the check went on to advise deleting data
 * that was in use. Reading config.json directly was the fix there too. It also keeps
 * the wizard's advice from depending on which shell the operator launched it from.
 */
export async function detectGbrainEngine(configPath: string): Promise<GbrainEngineInfo> {
  try {
    const parsed: unknown = JSON.parse(await readFile(configPath, 'utf8'));
    if (typeof parsed !== 'object' || parsed === null) return { engine: 'postgres' };
    const cfg = parsed as { engine?: unknown; database_path?: unknown };
    const raw = typeof cfg.database_path === 'string' && cfg.database_path.length > 0 ? cfg.database_path : null;
    const dataPath = raw ? (isAbsolute(raw) ? resolve(raw) : resolve(dirname(configPath), raw)) : undefined;
    if (cfg.engine === 'pglite') return { engine: 'pglite', ...(dataPath ? { dataPath } : {}) };
    if (cfg.engine === 'postgres') return { engine: 'postgres' }; // an explicit engine wins; a stale path is not the store
    return raw ? { engine: 'pglite', ...(dataPath ? { dataPath } : {}) } : { engine: 'postgres' };
  } catch {
    return { engine: 'postgres' };
  }
}

/**
 * Is `storePath` inside (or equal to) at least one of `dirs`? Both sides are resolved
 * first, and the containment test is on path SEGMENTS (`${d}/`), never a bare string
 * prefix — otherwise `--dir /srv/gb` would report `/srv/gbrain` as covered.
 */
export function pathCoveredBy(storePath: string, dirs: readonly string[]): boolean {
  const target = resolve(storePath);
  return dirs.some((d) => {
    const root = resolve(d);
    return target === root || target.startsWith(`${root}/`);
  });
}

// A PGLite store IS a PostgreSQL data directory, and carries Postgres's own two
// unmistakable markers: the PG_VERSION stamp file and the pg_wal/ directory. Keying on
// both (rather than, say, the directory's name, which the operator chooses via
// `database_path`) is what lets this find a store anywhere the scan reaches.
//
// WHAT THESE MARKERS DO NOT TELL US (multi-model review): they identify a Postgres-FORMAT
// data directory, not gbrain specifically — an ordinary PostgreSQL server's datadir under
// a --dir looks exactly the same, and there is no marker inside the directory that
// distinguishes a PGLite store from a server one. So the warnings below say "PostgreSQL
// data directory", name PGLite only as the reason a gbrain user has one, and offer
// `gbrain pglite-repair` as something to try IF it is a gbrain store rather than as a
// prescription. The hazard being warned about — copying a live cluster's files — is
// identical either way, which is why one detector legitimately covers both.
//
// The filesystem is the AUTHORITY here, and it answers alone: the detection below never
// consults config.json or the environment. What is about to be tar'd is what is on disk,
// so a store that a config no longer points at — or that an exported DATABASE_URL claims
// has been superseded — still gets the warning. That is precisely the case where an
// operator is most likely to be surprised, and the cost of being wrong is asymmetric: a
// spurious warning is noise, a missed one is a backup that looks fine until it is needed.
const PG_VERSION = 'PG_VERSION';
const PG_WAL = 'pg_wal';

/**
 * Cheap CANDIDATE filter: do these entry names, read from ONE directory, look like a
 * data directory? Names only — the listing path has no type information to work with —
 * so every hit is confirmed against the filesystem by confirmDataDir below.
 */
const marksDataDir = (names: Iterable<string>): boolean => {
  let version = false;
  let wal = false;
  for (const n of names) {
    if (n === PG_VERSION) version = true;
    else if (n === PG_WAL) wal = true;
    if (version && wal) return true;
  }
  return false;
};

/**
 * Confirm a candidate: PG_VERSION must be a FILE and pg_wal must be a DIRECTORY. A
 * directory named PG_VERSION, or a file named pg_wal, is not a cluster — matching on
 * names alone let both through (multi-model review). Two stat() calls per candidate,
 * and candidates are rare, so this costs nothing measurable.
 *
 * stat(), not lstat(): Postgres supports pg_wal being a symlink onto another volume, and
 * such a cluster is still a cluster. (tar archives that symlink as a link rather than
 * following it, which makes the resulting copy worse, not better — one more reason to
 * warn.)
 */
async function confirmDataDir(absDir: string): Promise<boolean> {
  try {
    const [version, wal] = await Promise.all([stat(join(absDir, PG_VERSION)), stat(join(absDir, PG_WAL))]);
    return version.isFile() && wal.isDirectory();
  } catch {
    return false; // either marker missing or unreadable — not something to warn about
  }
}

/** One PostgreSQL data directory found at or under a scanned source root. */
export interface PgDataDirFinding {
  /** POSIX path relative to the scanned root; `''` means the root itself is the store. */
  rel: string;
  /**
   * How many paths inside this store a `.cipherbrainignore` rule keeps OUT of the
   * archive. 0 = the whole store is archived (the ordinary case). Anything above 0 is
   * strictly worse than an inconsistent copy — see pgDataDirTruncatedWarning.
   */
  excludedInside: number;
}

/** A path that lies strictly INSIDE `dir` (`''` = the scan root, so everything is inside it). */
const strictlyUnder = (p: string, dir: string): boolean => (dir === '' ? p.length > 0 : p.startsWith(`${dir}/`));

/**
 * PostgreSQL data directories at or under `rootAbs`.
 *
 * `listing`, when given, must be the COMPLETE set of paths the caller's own walk saw —
 * BOTH what it will archive and what it filtered out. snapshot passes scanDir's
 * `tarEntries` plus its excluded entries, so the detection runs entirely in memory: no
 * second traversal of a tree the caller just finished walking, at any depth.
 *
 * Passing only the archived half is a bug that hides the worst case (multi-model review,
 * measured): an ignore rule matching `pg_wal/` removes a marker, detection goes quiet,
 * and the run that produces a store which cannot open AT ALL is the one that says
 * nothing. `excludedInside` exists so that case gets its own, louder warning.
 *
 * WITHOUT a listing there is no walk to borrow, and this reads the root and its
 * IMMEDIATE subdirectories only — deliberately bounded, so pointing --dir at a large
 * tree does not pay for a full recursive walk just to produce an advisory. That covers
 * both layouts that occur in practice: --dir aimed straight at the store, and
 * `--dir ~/.gbrain` with the store one level down at the configured `database_path`. A
 * store nested deeper than one level is NOT found on this path, and the docs say so in
 * those words rather than promising "anywhere under the source" — see selftest
 * `selftest-gbrain-pglite.sh` (c), which pins the boundary in both directions.
 */
export async function findPgDataDirs(
  rootAbs: string,
  listing?: { included: readonly string[]; excluded: readonly string[] },
): Promise<PgDataDirFinding[]> {
  const candidates: string[] = [];
  if (listing) {
    // Group every known path by its parent directory ('' = the root itself), then apply
    // the candidate test to each group's child names.
    const childNames = new Map<string, string[]>([['', []]]);
    for (const rel of [...listing.included, ...listing.excluded]) {
      const cut = rel.lastIndexOf('/');
      const parent = cut === -1 ? '' : rel.slice(0, cut);
      const name = cut === -1 ? rel : rel.slice(cut + 1);
      const bucket = childNames.get(parent);
      if (bucket) bucket.push(name);
      else childNames.set(parent, [name]);
    }
    for (const [dir, names] of childNames) if (marksDataDir(names)) candidates.push(dir);
  } else {
    let top: Dirent[];
    try {
      top = await readdir(rootAbs, { withFileTypes: true });
    } catch {
      return []; // not a directory, or unreadable — nothing to advise about
    }
    if (marksDataDir(top.map((e) => e.name))) candidates.push('');
    else {
      for (const e of top) {
        if (!e.isDirectory()) continue;
        try {
          if (marksDataDir(await readdir(join(rootAbs, e.name)))) candidates.push(e.name);
        } catch {
          /* unreadable subdirectory — skip it, this is advisory only */
        }
      }
    }
  }
  const findings: PgDataDirFinding[] = [];
  for (const rel of candidates.sort()) {
    if (!(await confirmDataDir(rel ? join(rootAbs, rel) : rootAbs))) continue;
    findings.push({
      rel,
      excludedInside: listing ? listing.excluded.filter((p) => strictlyUnder(p, rel)).length : 0,
    });
  }
  return findings;
}

/** How a finding is named to the operator: the --dir they passed, plus where inside it. */
const storeLabel = (sourceLabel: string, rel: string): string => (rel ? `${sourceLabel}/${rel}` : sourceLabel);

/**
 * The warning for a source that carries a PostgreSQL data directory. Exported so the
 * selftest pins the wording against the single place it is written.
 *
 * A WARNING, never a refusal (#367): the whole point of `schedule install` is an
 * unattended nightly run, and a backup tool that declines to back up is worse than one
 * that backs up loudly.
 *
 * WHAT IT MAY AND MAY NOT CLAIM (multi-model review, P3). The load-bearing fact is a
 * documented property of PostgreSQL, not a reproduction: a running cluster's files
 * cannot be copied at the file level outside its own backup API, because a copy that
 * spans time captures different files at different instants and can tear a page
 * mid-write. What happens NEXT is genuinely uncertain — crash recovery salvages most
 * such copies, an inconsistent one can also open and carry latent damage, and a
 * WAL-focused repair cannot fix every kind of inconsistency. Fifteen bounded attempts
 * to produce a torn copy on one machine produced none, which is exactly why this says
 * "may" throughout and offers the repair command as something to try rather than as a
 * promise. Do not strengthen this wording without evidence that outranks that.
 */
export const pgDataDirCopyWarning = (sourceLabel: string, rel: string): string =>
  `"${storeLabel(sourceLabel, rel)}" is a PostgreSQL data directory — gbrain's default engine, PGLite, keeps its ` +
  `whole database as one. It is archived as a plain tar of that directory, and PostgreSQL does not support ` +
  `file-level copies of a running cluster outside its own backup API: the files can be captured at different ` +
  `instants, so the copy may be internally inconsistent. Crash recovery salvages most such copies, but it is not ` +
  `guaranteed to, and an inconsistent copy can also open with latent damage. verify will not tell you either way ` +
  `— it checks the ciphertext, which is well-formed regardless. Stop the writer (for gbrain, "gbrain serve") for ` +
  `the duration of the snapshot. Unlike --pg, which pg_dump makes point-in-time consistent, nothing here does it ` +
  `for you. If a restored gbrain store then fails to open, "gbrain pglite-repair" is worth trying.`;

/**
 * The STRONGER warning: an ignore rule removes part of a data directory from the archive.
 *
 * This is not the same hazard and must not share the sentence above (multi-model review,
 * measured): a mid-write copy MAY be inconsistent, whereas a data directory missing
 * pieces of itself cannot be opened at all — a cluster is only usable whole. It is also
 * the case the pre-fix code silently swallowed, because the excluded marker was the very
 * thing detection was looking for. Quiescing gbrain does not help here; removing the
 * rule does, so that is what this says.
 */
export const pgDataDirTruncatedWarning = (sourceLabel: string, rel: string, excludedInside: number): string =>
  `"${storeLabel(sourceLabel, rel)}" is a PostgreSQL data directory (gbrain's PGLite store is one) and a ` +
  `.cipherbrainignore rule keeps ${excludedInside} path(s) INSIDE it out of this snapshot. A data directory is ` +
  `only usable whole: this is not the "maybe inconsistent" risk of copying a live cluster, it is a copy that ` +
  `cannot be opened at all, and verify will still pass on it. Remove the ignore rule that matches inside this ` +
  `directory, or point --dir somewhere that does not contain it.`;
