// file backend: a local content-addressed store. Needs no daemon and no network,
// so CI can exercise push/pull end-to-end. locator = <FILE_DIR>/<sha256>.age
import { mkdir, copyFile } from 'node:fs/promises';
import { join, dirname, resolve } from 'node:path';
import { FILE_DIR } from '../config.mjs';
import { exists, sha256 } from '../util.mjs';

export function fileBackend() {
  return {
    async put(file, _opts = {}) {
      await mkdir(FILE_DIR, { recursive: true });
      const locator = join(FILE_DIR, `${await sha256(file)}.age`);
      await copyFile(file, locator);
      return locator;
    },
    async get(locator, out) {
      if (!(await exists(locator))) throw new Error(`file backend: no object at ${locator}`);
      await mkdir(dirname(resolve(out)), { recursive: true });
      await copyFile(locator, out);
    },
  };
}
