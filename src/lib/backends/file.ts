// file backend: a local content-addressed store. Needs no daemon and no network,
// so CI can exercise push/pull end-to-end. locator = <FILE_DIR>/<sha256>.age
import { mkdir, copyFile } from 'node:fs/promises';
import { join, dirname, resolve } from 'node:path';
import { FILE_DIR } from '../config.js';
import { exists, sha256 } from '../util.js';
import type { StorageBackend, PutOpts } from '../types.js';

export function fileBackend(): StorageBackend {
  return {
    async put(file: string, _opts: PutOpts = {}): Promise<string> {
      await mkdir(FILE_DIR, { recursive: true });
      const locator = join(FILE_DIR, `${await sha256(file)}.age`);
      await copyFile(file, locator);
      return locator;
    },
    async get(locator: string, out: string): Promise<void> {
      if (!(await exists(locator))) throw new Error(`file backend: no object at ${locator}`);
      await mkdir(dirname(resolve(out)), { recursive: true });
      await copyFile(locator, out);
    },
  };
}
