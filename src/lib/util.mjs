// ---------- utils ----------
import { access, stat } from 'node:fs/promises';
import { createReadStream, constants as FS } from 'node:fs';
import { createHash } from 'node:crypto';

export const exists = (p) => access(p, FS.F_OK).then(() => true).catch(() => false);
export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Warn (don't refuse) if a secret-bearing key file is group/other-accessible. The age
// identity is created 0600; an Arweave JWK is a spend-capable bearer credential (a Turbo
// Credit Share Approval is granted TO its address) yet may be dropped in with loose modes.
// We warn rather than hard-fail so an unusual-but-intentional setup still works.
export async function warnIfLooseKeyPerms(path, what) {
  try {
    const { mode } = await stat(path);
    if (mode & 0o077) {
      process.stderr.write(`⚠  ${what} at ${path} is group/other-accessible (mode ${(mode & 0o777).toString(8)}); chmod 600 it — it is a secret.\n`);
    }
  } catch { /* unreadable / missing perms info — the caller's own read will surface real errors */ }
}

export function sha256(file) {
  return new Promise((res, rej) => {
    const h = createHash('sha256');
    createReadStream(file).on('data', (d) => h.update(d)).on('end', () => res(h.digest('hex'))).on('error', rej);
  });
}

export function readHead(path, n) {
  return new Promise((res, rej) => {
    const s = createReadStream(path, { start: 0, end: n - 1, encoding: 'utf8' });
    let d = '';
    s.on('data', (c) => (d += c));
    s.on('end', () => res(d));
    s.on('error', rej);
  });
}

export function fmtBytes(n) {
  const u = ['B', 'KB', 'MB', 'GB'];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(i ? 1 : 0)} ${u[i]}`;
}
