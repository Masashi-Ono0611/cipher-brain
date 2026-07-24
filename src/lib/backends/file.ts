// file backend: a local content-addressed store. Needs no daemon and no network,
// so CI can exercise push/pull end-to-end. locator = <FILE_DIR>/<sha256><ext>
import { mkdir, copyFile } from 'node:fs/promises';
import { join, dirname, resolve, basename, extname } from 'node:path';
import { FILE_DIR } from '../config.js';
import { exists, sha256 } from '../util.js';
import type { StorageBackend, PutOpts } from '../types.js';

// locators produced by put() always have this shape (basename of `<sha256><ext>`).
// ".age" is the ciphertext extension every --in push() itself accepts; ".minisig" is
// the ONLY other extension push() ever hands this backend — the detached authenticity
// sidecar (#214), uploaded alongside the ciphertext it signs (see push() in
// pushpull.ts). A tight allowlist, not an open regex: same "narrow validated shape"
// defense-in-depth this file already applied to age ciphertext (an untrusted locator,
// e.g. from a tampered --save-locator file, must never resolve outside FILE_DIR OR to
// an unexpected extension).
const LOCATOR_SHAPE_RE = /^[0-9a-f]{64}\.(age|minisig)$/;

export function fileBackend(): StorageBackend {
  return {
    async put(file: string, _opts: PutOpts = {}): Promise<string> {
      await mkdir(FILE_DIR, { recursive: true });
      // Preserve the pushed file's own extension instead of assuming every object is
      // ciphertext (#214: a *.minisig sidecar pushed through this SAME backend must not
      // be misnamed "<sha>.age") — content-addressed either way, so this is purely a
      // display/routing convenience, never a correctness dependency. Falls back to
      // ".age" for an extensionless input (unchanged behavior for every pre-#214 caller,
      // which only ever pushed *.age files).
      const ext = extname(file) || '.age';
      const locator = join(FILE_DIR, `${await sha256(file)}${ext}`);
      await copyFile(file, locator);
      return locator;
    },
    async get(locator: string, out: string): Promise<void> {
      // The locator may come from an untrusted channel (e.g. a tampered
      // --save-locator file, see cli.ts), so it must not be used as a raw
      // filesystem path without validation first — this closes an arbitrary
      // local file read / path-traversal foot-gun. Mirrors the tx-id regex
      // check arweave.ts's get() already does for its own locator format.
      // put() only ever writes direct children of FILE_DIR shaped
      // <sha256>.age, so require both here.
      const resolved = resolve(locator);
      if (dirname(resolved) !== resolve(FILE_DIR)) {
        throw new Error(`file backend: locator is outside FILE_DIR: ${locator}`);
      }
      if (!LOCATOR_SHAPE_RE.test(basename(resolved))) {
        throw new Error(`file backend: locator does not match the expected <sha256>.age shape: ${locator}`);
      }
      if (!(await exists(resolved))) throw new Error(`file backend: no object at ${resolved}`);
      await mkdir(dirname(resolve(out)), { recursive: true });
      await copyFile(resolved, out);
    },
  };
}
