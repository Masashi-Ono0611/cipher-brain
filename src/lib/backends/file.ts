// file backend: a local content-addressed store. Needs no daemon and no network,
// so CI can exercise push/pull end-to-end. locator = <FILE_DIR>/<sha256>.age
import { mkdir, copyFile } from 'node:fs/promises';
import { join, dirname, resolve, basename } from 'node:path';
import { FILE_DIR } from '../config.js';
import { exists, sha256 } from '../util.js';
import type { StorageBackend, PutOpts } from '../types.js';

// locators produced by put() always have this shape (basename of `<sha256>.age`).
const LOCATOR_SHAPE_RE = /^[0-9a-f]{64}\.age$/;

export function fileBackend(): StorageBackend {
  return {
    async put(file: string, _opts: PutOpts = {}): Promise<string> {
      await mkdir(FILE_DIR, { recursive: true });
      const locator = join(FILE_DIR, `${await sha256(file)}.age`);
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
