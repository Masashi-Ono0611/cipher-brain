// ---------- utils ----------
import { access, lstat, stat } from 'node:fs/promises';
import { createReadStream, statSync, constants as FS } from 'node:fs';
import { createHash } from 'node:crypto';

export const exists = (p: string): Promise<boolean> =>
  access(p, FS.F_OK)
    .then(() => true)
    .catch(() => false);
export const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

// Refuse up front when a path the user pointed at is not there (issue #267).
// A command that reads a path goes through one of these BEFORE opening it, so a
// mistyped path always produces the same one-line answer naming the path — never
// a raw Node errno string (`ENOENT: no such file or directory, stat '…'`), and
// never an error whose CB-E0xx code claims a different cause. `restore` used to
// let a missing --in fall through to the decrypt call and surface as
// "age decrypt failed: ENOENT … [CB-E002]", i.e. "your identity is probably wrong
// or the artifact is corrupt" — the worst possible answer to a typo, at the worst
// possible moment. push/estimate already had this check inline; these helpers give
// the call sites that skipped it the same one, with the same wording.
//
// requireFile follows symlinks (access(F_OK)): for an --in that must actually be
// READ, a dangling symlink is as unusable as a missing file and should say so.
// Only ENOENT/ENOTDIR (the path, or a directory component of it, is not there)
// become "no such file" — EACCES, ELOOP and friends are rethrown untouched, since
// relabelling "permission denied" as "missing" is the same misdiagnosis this issue
// is about, one level down. push/estimate route
// through here too, so all five commands share one implementation and one wording.
// Thrown by requireFile/requirePath for the one condition they translate. The CLI does
// not care — errMsg() renders it exactly like the plain Error it replaces — but the MCP
// server needs to tell "the caller named a path that is not there" (bad input) apart
// from any other failure (#293), and matching on message text to do that would be
// exactly the kind of fragile coupling this codebase has been removing. A type is the
// same signal without the string.
export class MissingPathError extends Error {}

export async function requireFile(path: string, what = 'file'): Promise<void> {
  try {
    await access(path, FS.F_OK);
  } catch (e) {
    const code = (e as NodeJS.ErrnoException)?.code;
    if (code !== 'ENOENT' && code !== 'ENOTDIR') throw e;
    throw new MissingPathError(`no such ${what}: ${path}`);
  }
}

// requirePath does NOT follow symlinks — deliberately, and this is not
// interchangeable with requireFile. A snapshot source may be a directory, a plain
// file, or a top-level symlink, and a DANGLING symlink is a source snapshot
// archives on purpose (as a symlink entry — see snapshot.ts's lstat comment);
// checking it with access() would start rejecting a case that works today.
// A non-ENOENT failure (EACCES, ELOOP, …) is rethrown untouched rather than
// relabelled "no such …", which would be the same misdiagnosis this fixes.
export async function requirePath(path: string, what = 'path'): Promise<void> {
  try {
    await lstat(path);
  } catch (e) {
    if ((e as NodeJS.ErrnoException)?.code !== 'ENOENT') throw e;
    throw new MissingPathError(`no such ${what}: ${path}`);
  }
}

// Warn (don't refuse) if a secret-bearing key file is group/other-accessible. The age
// identity is created 0600; an Arweave JWK is a spend-capable bearer credential (a Turbo
// Credit Share Approval is granted TO its address) yet may be dropped in with loose modes.
// We warn rather than hard-fail so an unusual-but-intentional setup still works.
// One wording, two call shapes. config.ts has to check its own file from a MODULE
// BODY, which cannot await, so it needs the sync form — and duplicating the sentence
// there would be the same drift this codebase keeps removing.
const loosePermsWarning = (path: string, what: string, mode: number): string =>
  `⚠  ${what} at ${path} is group/other-accessible (mode ${(mode & 0o777).toString(8)}); chmod 600 it — it is a secret.\n`;

export async function warnIfLooseKeyPerms(path: string, what: string): Promise<void> {
  try {
    const { mode } = await stat(path);
    if (mode & 0o077) process.stderr.write(loosePermsWarning(path, what, mode));
  } catch {
    /* unreadable / missing perms info — the caller's own read will surface real errors */
  }
}

export function warnIfLooseKeyPermsSync(path: string, what: string): void {
  try {
    const { mode } = statSync(path);
    if (mode & 0o077) process.stderr.write(loosePermsWarning(path, what, mode));
  } catch {
    /* same posture as the async form above */
  }
}

export function sha256(file: string): Promise<string> {
  return new Promise((res, rej) => {
    const h = createHash('sha256');
    createReadStream(file)
      .on('data', (d) => h.update(d))
      .on('end', () => res(h.digest('hex')))
      .on('error', rej);
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
  while (n >= 1024 && i < u.length - 1) {
    n /= 1024;
    i++;
  }
  return `${n.toFixed(i ? 1 : 0)} ${u[i]}`;
}

// A Postgres connection string (--pg, wizard.ts's recovery kit, restore.ts's pg_restore
// consent gate) can embed a password. Anywhere one of these is printed for REFERENCE
// (a long-lived kit document, an error/log line) — never as an argv passed to pg_dump/
// pg_restore itself, which need the real credential — strip it first (Fugu review
// finding); the username alone is left visible — it is not itself a secret, and this
// project's own docs already print it in the clear (e.g. README's
// `postgres://user@localhost:5432/gbrain` examples). Falls back to a conservative regex
// redact for a non-URL keyword/value DSN (e.g. "host=... password=..."), which --pg
// accepts just as pg_dump/pg_restore themselves do but the WHATWG URL parser cannot.
// The two standard libpq keywords that can carry a credential value (the connection
// password, and the passphrase for an --sslkey client certificate) — checked
// case-insensitively below since libpq's own keyword matching is (Grok review).
const PG_SECRET_KEYS = /^(password|sslpassword)$/i;

export function redactPgConn(conn: string): string {
  try {
    const u = new URL(conn);
    if (u.password) u.password = '';
    // libpq connection URIs also accept a credential as an ordinary query parameter
    // (postgres://user@host/db?password=...) — the user:pass@ authority form above is
    // not the only place it can hide (Fugu review finding, round 2). Iterate keys
    // rather than a fixed .has('password') lookup: URLSearchParams keys are
    // case-sensitive, so a literal check would miss e.g. ?Password= (Grok review).
    for (const key of [...u.searchParams.keys()]) {
      if (PG_SECRET_KEYS.test(key)) u.searchParams.set(key, 'REDACTED');
    }
    return u.toString();
  } catch {
    // Keyword/value DSN form (e.g. "host=... password=..."). A value may be a bare
    // token, or quoted (single OR double — Grok review noted only single was handled;
    // libpq's own conninfo grammar only recognizes single quotes, but matching both is
    // a strictly safer over-match here) optionally containing escaped characters (e.g.
    // password='a\'b c') — match any of these shapes rather than only \S+, which would
    // leave a trailing fragment of a quoted, space-containing secret unredacted.
    const secretVal = `(?:'(?:[^'\\\\]|\\\\.)*'|"(?:[^"\\\\]|\\\\.)*"|\\S+)`;
    return conn
      .replace(/:\/\/([^:@/]+):[^@/]*@/, '://$1@')
      .replace(new RegExp(`\\b(password|sslpassword)=${secretVal}`, 'gi'), '$1=REDACTED');
  }
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
