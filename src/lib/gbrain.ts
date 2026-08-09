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
import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';

export type GbrainEngine = 'pglite' | 'postgres';

/**
 * Which engine a gbrain home is configured for, mirroring gbrain's OWN resolution
 * order for the config file: an explicit `engine` field wins; otherwise the presence
 * of `database_path` (the on-disk PGLite data directory) implies PGLite; otherwise
 * Postgres. Anything unreadable or unparseable falls back to 'postgres' — the
 * pre-#367 assumption, so a malformed config can never make this the thing that
 * breaks a run.
 *
 * READS EXACTLY TWO FIELDS AND RETURNS ONLY THE VERDICT. `config.json` holds API
 * keys: nothing from it is logged, echoed, copied, or returned to a caller. That is
 * a hard constraint on this function, not an implementation detail — an added
 * "return the parsed config for convenience" is how a key ends up in a transcript.
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
export async function detectGbrainEngine(configPath: string): Promise<GbrainEngine> {
  try {
    const parsed: unknown = JSON.parse(await readFile(configPath, 'utf8'));
    if (typeof parsed !== 'object' || parsed === null) return 'postgres';
    const cfg = parsed as { engine?: unknown; database_path?: unknown };
    if (cfg.engine === 'pglite' || cfg.engine === 'postgres') return cfg.engine;
    return typeof cfg.database_path === 'string' && cfg.database_path.length > 0 ? 'pglite' : 'postgres';
  } catch {
    return 'postgres';
  }
}

// A PGLite store is a real Postgres data directory, so it carries Postgres's own two
// unmistakable markers: the PG_VERSION stamp file and the pg_wal/ directory. Keying on
// both (rather than, say, the directory's name, which the operator chooses via
// `database_path`) is what makes this work for a store anywhere under a --dir.
//
// The filesystem is the AUTHORITY for the snapshot warning, and it answers alone: the
// detection below never consults config.json or the environment. What is about to be
// tar'd is what is on disk, so a store that a config no longer points at — or that an
// exported DATABASE_URL claims has been superseded — still gets the warning. That is
// precisely the case where an operator is most likely to be surprised, and the cost of
// being wrong is asymmetric: a spurious warning is noise, a missed one is a backup that
// looks fine until the day it is needed.
const PG_VERSION = 'PG_VERSION';
const PG_WAL = 'pg_wal';

/** Do these directory-entry names, read from ONE directory, mark it as a PGLite/Postgres data dir? */
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
 * PGLite data directories at or under `rootAbs`, as POSIX paths relative to it —
 * `''` meaning the root IS one. Empty array = nothing found.
 *
 * `knownRelPaths`, when given, is a COMPLETE listing of the paths under the root that
 * a caller has already walked (snapshot's scanDir hands over exactly that). The
 * detection then runs entirely in memory against that list: no second traversal of a
 * tree the caller just finished walking, at any depth.
 *
 * Without it, fall back to reading the root and its immediate subdirectories — enough
 * to catch both real layouts (a --dir pointed straight at the store, and the common
 * `--dir ~/.gbrain` with the store one level down at the configured `database_path`),
 * bounded so that pointing --dir at a large tree does not pay for a full recursive
 * walk just to produce a warning. A store buried deeper than that is not detected;
 * this is a best-effort advisory, and missing one is a missing warning, never a
 * failed or silently-altered snapshot.
 */
export async function findPgliteDataDirs(rootAbs: string, knownRelPaths?: readonly string[]): Promise<string[]> {
  if (knownRelPaths) {
    // Group every known path by its parent directory ('' = the root itself), then apply
    // the same two-marker test to each group's child names.
    const childNames = new Map<string, string[]>([['', []]]);
    for (const rel of knownRelPaths) {
      const cut = rel.lastIndexOf('/');
      const parent = cut === -1 ? '' : rel.slice(0, cut);
      const name = cut === -1 ? rel : rel.slice(cut + 1);
      const bucket = childNames.get(parent);
      if (bucket) bucket.push(name);
      else childNames.set(parent, [name]);
    }
    const hits: string[] = [];
    for (const [dir, names] of childNames) if (marksDataDir(names)) hits.push(dir);
    return hits.sort();
  }
  let top: Dirent[];
  try {
    top = await readdir(rootAbs, { withFileTypes: true });
  } catch {
    return []; // not a directory, or unreadable — nothing to advise about
  }
  if (marksDataDir(top.map((e) => e.name))) return ['']; // the root IS the store: no point descending into it
  const hits: string[] = [];
  for (const e of top) {
    if (!e.isDirectory()) continue;
    try {
      if (marksDataDir(await readdir(join(rootAbs, e.name)))) hits.push(e.name);
    } catch {
      /* unreadable subdirectory — skip it, this is advisory only */
    }
  }
  return hits.sort();
}

/**
 * The warning text for a source that carries a live PGLite store. Exported so the
 * selftest can pin the wording it greps for against the single place it is written.
 *
 * A WARNING, never a refusal (#367): the whole point of `schedule install` is an
 * unattended nightly run, and a backup tool that declines to back up is worse than
 * one that backs up loudly. The specific hazard is that PGLite is single-writer and
 * this is a plain tar of a directory a running gbrain may be mid-write in — unlike
 * the --pg path, which gets point-in-time consistency from `pg_dump -Fc` for free.
 * `verify` cannot catch a torn store either: the ciphertext and its digest are
 * internally consistent, and the damage only shows up at restore time.
 */
export const pgliteQuiesceWarning = (sourceLabel: string): string =>
  `"${sourceLabel}" contains a live PGLite data directory (gbrain's default engine). PGLite is single-writer ` +
  `and this is archived as a plain tar of that directory, so a copy taken while gbrain is writing can be torn — ` +
  `unlike --pg, which pg_dump makes point-in-time consistent. verify cannot detect this: the ciphertext is ` +
  `internally consistent and the damage only appears at restore time. Stop gbrain (or its "gbrain serve") for ` +
  `the duration of the snapshot. A restored store that will not open is repairable with "gbrain pglite-repair".`;
