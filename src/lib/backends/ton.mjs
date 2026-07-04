// ton backend: shells out to the official storage-daemon-cli. locator = hex BagID
// (a content fingerprint). The CLI takes ONE command string via -c, so the file
// path must be space-free (our temp paths are).
import { mkdir, rm, mkdtemp, copyFile, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, dirname, resolve } from 'node:path';
import { TON_CLI, TON_API, TON_CLIENT, TON_SERVER, TON_TIMEOUT_S } from '../config.mjs';
import { run } from '../proc.mjs';
import { sleep } from '../util.mjs';

function tonArgs(cmd) {
  if (!TON_CLIENT || !TON_SERVER) {
    throw new Error('ton backend needs CIPHER_BRAIN_TON_CLIENT and CIPHER_BRAIN_TON_SERVER (storage-daemon-cli key paths)');
  }
  return ['-I', TON_API, '-k', TON_CLIENT, '-p', TON_SERVER, '-c', cmd];
}

// add-by-hash wants the hex BagID. In --json that is NOT the base64 `hash` field —
// the hex appears in the root_dir path. Prefer that; else decode base64 hash; else
// any bare 64-hex. (Confirmed against a real storage-daemon --json blob.)
function parseBagId(s) {
  let m = s.match(/torrent-files\/([0-9A-Fa-f]{64})/);
  if (m) return m[1].toUpperCase();
  try {
    const j = JSON.parse(s);
    const h = j.hash || (j.torrent && j.torrent.hash) || j.bag_id;
    if (h && /^[0-9A-Fa-f]{64}$/.test(h)) return h.toUpperCase();
    if (h && /^[A-Za-z0-9+/]+={0,2}$/.test(h)) {
      const buf = Buffer.from(h, 'base64');
      if (buf.length === 32) return buf.toString('hex').toUpperCase(); // a BagID is a 32-byte hash
    }
  } catch { /* not json, fall through */ }
  m = s.match(/\b[0-9A-Fa-f]{64}\b/);
  if (m) return m[0].toUpperCase();
  throw new Error(`could not parse BagID from: ${s.trim().slice(0, 200)}`);
}

// confirmed against a real `get --json`: the torrent block carries "completed": true
function bagComplete(s) {
  try {
    const j = JSON.parse(s);
    return (j.torrent || j).completed === true;
  } catch { /* not json */ }
  return /"completed"\s*:\s*true/.test(s);
}

// the daemon's -c is ONE space-delimited command string (not a shell), so any path
// embedded in it must be whitespace-free — quoting wouldn't help.
function assertNoSpace(p, what) {
  if (/\s/.test(p)) throw new Error(`ton backend: ${what} must not contain whitespace: ${p}`);
}

export function tonBackend() {
  return {
    async put(file, _opts = {}) {
      assertNoSpace(file, 'file path');
      const { out } = await run(TON_CLI, tonArgs(`create --copy --json ${file}`));
      return parseBagId(out);
    },
    async get(locator, out) {
      assertNoSpace(locator, 'locator');
      const base = tmpdir();
      assertNoSpace(base, 'TMPDIR (point it at a space-free path for the ton backend)');
      const tmp = await mkdtemp(join(base, 'cipher-brain-pull-'));
      try {
        await run(TON_CLI, tonArgs(`add-by-hash ${locator} -d ${tmp} --json`), { timeoutMs: 30000 });
        const deadline = Date.now() + TON_TIMEOUT_S * 1000;
        for (;;) {
          // bound EACH poll: a hung `get` must not defeat the deadline below
          let g = '';
          try { ({ out: g } = await run(TON_CLI, tonArgs(`get ${locator} --json`), { timeoutMs: 15000 })); } catch { /* treat as not-yet-complete */ }
          if (bagComplete(g)) break;
          if (Date.now() > deadline) throw new Error(`ton backend: download of ${locator} did not complete in ${TON_TIMEOUT_S}s`);
          await sleep(3000);
        }
        const entries = await readdir(tmp, { recursive: true, withFileTypes: true });
        const files = entries.filter((d) => d.isFile()).map((d) => join(d.parentPath || tmp, d.name));
        if (files.length !== 1) throw new Error(`ton backend: expected 1 file in bag, got ${files.length}`);
        await mkdir(dirname(resolve(out)), { recursive: true });
        await copyFile(files[0], out);
      } finally {
        await rm(tmp, { recursive: true, force: true }); // don't leak the downloaded ciphertext
      }
    },
  };
}
