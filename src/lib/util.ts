// ---------- utils ----------
import { access, stat } from 'node:fs/promises';
import { createReadStream, constants as FS } from 'node:fs';
import { createHash } from 'node:crypto';

export const exists = (p: string): Promise<boolean> => access(p, FS.F_OK).then(() => true).catch(() => false);
export const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

// Warn (don't refuse) if a secret-bearing key file is group/other-accessible. The age
// identity is created 0600; an Arweave JWK is a spend-capable bearer credential (a Turbo
// Credit Share Approval is granted TO its address) yet may be dropped in with loose modes.
// We warn rather than hard-fail so an unusual-but-intentional setup still works.
export async function warnIfLooseKeyPerms(path: string, what: string): Promise<void> {
  try {
    const { mode } = await stat(path);
    if (mode & 0o077) {
      process.stderr.write(`⚠  ${what} at ${path} is group/other-accessible (mode ${(mode & 0o777).toString(8)}); chmod 600 it — it is a secret.\n`);
    }
  } catch { /* unreadable / missing perms info — the caller's own read will surface real errors */ }
}

export function sha256(file: string): Promise<string> {
  return new Promise((res, rej) => {
    const h = createHash('sha256');
    createReadStream(file).on('data', (d) => h.update(d)).on('end', () => res(h.digest('hex'))).on('error', rej);
  });
}

export function readHead(path: string, n: number): Promise<string> {
  return new Promise((res, rej) => {
    const s = createReadStream(path, { start: 0, end: n - 1, encoding: 'utf8' });
    let d = '';
    s.on('data', (c) => (d += c));
    s.on('end', () => res(d));
    s.on('error', rej);
  });
}

// A caught value is `unknown` under strict TS (useUnknownInCatchVariables) — this codebase
// catches a LOT of errors just to report `.message`, so centralize the narrowing here
// instead of an `as Error` cast (or worse, `any`) at every call site.
export function errMsg(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

export function fmtBytes(n: number): string {
  const u = ['B', 'KB', 'MB', 'GB'];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(i ? 1 : 0)} ${u[i]}`;
}

// ---------- shared error subclasses ----------
// Real, checkable (`instanceof`) markers instead of duck-typed properties bolted onto a
// plain Error (the pattern the original .mjs used, e.g. `err.retryable = true`) — strict
// TS can't safely narrow an arbitrary property access on `unknown` catch bindings, and an
// `instanceof` check is exactly the kind of real type safety this conversion is for.

// pull() (pushpull.ts) retries while a backend's get() throws this — a fresh Turbo/Arweave
// upload that has not yet propagated, not a fatal error (bad locator, network down, etc).
export class RetryableError extends Error {
  readonly retryable = true as const;
}

// arweave.ts's get() throws this when the `arweave` package itself is not installed — the
// caller (the L1 chunk fallback) treats it as "skip this optional path", not a hard failure.
export class SdkMissingError extends Error {
  readonly sdkMissing = true as const;
}
