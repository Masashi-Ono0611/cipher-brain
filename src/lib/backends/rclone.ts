// rclone backend (#204): a thin subprocess wrapper around the `rclone` binary.
// restic and kopia both integrate rclone as a "meta-backend" instead of reimplementing
// each cloud provider's auth/protocol themselves — this backend takes the same
// approach: cypher-brain never talks to S3/GCS/B2/Dropbox/etc directly, it only ever
// shells out to `rclone copyto`, delegating auth, protocol and retries entirely to
// whatever remote the operator has already configured in their own rclone.conf (or a
// config-less on-the-fly remote, e.g. `:local:/path`). Only ciphertext ever crosses
// this backend — same threat model as every other one (push() already refuses to
// push a non-age artifact before any backend is invoked).
import { mkdir } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { RCLONE_BIN, PIPE_TIMEOUT_MS } from '../config.js';
import { run } from '../proc.js';
import { progressReporter, progressIntervalMs, type ProgressReporter } from '../progress.js';
import type { StorageBackend, PutOpts } from '../types.js';

// Runs `rclone <args>` (array args via proc.ts's run() — no shell, so a remote name
// or path can never be interpreted as a second command). Translates a missing binary
// (ENOENT) into an actionable message instead of node's bare "spawn rclone ENOENT" —
// the single most likely first-run failure for an operator who hasn't installed
// rclone yet. Any other failure (bad remote name, network error, auth failure, ...)
// is rclone's own stderr, already surfaced by run()'s non-zero-exit Error.
// Progress flags (#283). rclone already accounts the transfer; we only ask it to say so
// at OUR cadence — asking for one line per second and dropping 29 of every 30 would be
// the same silence with more work. `--use-json-log` is what makes this parsing rather
// than screen-scraping: the JSON line carries `stats.bytes`/`stats.totalBytes` as
// numbers (verified against rclone v1.74.4), so no human-readable "30.090 MiB" is ever
// converted back into bytes. `--stats-log-level NOTICE` is required because stats are
// logged at INFO by default, which the default `--log-level NOTICE` filters out.
const statsFlags = (intervalMs: number): string[] => [
  '--stats',
  `${Math.max(1, Math.round(intervalMs / 1000))}s`,
  '--stats-one-line',
  '--stats-log-level',
  'NOTICE',
  '--use-json-log',
];

/**
 * The full argv for an rclone subcommand, with the `--` boundary placed by construction.
 *
 * This exists because getting it wrong is silent-looking and confusing: `--` ends option
 * parsing, so appending the stats flags AFTER it makes rclone read them as positional
 * arguments and fail with "Command copyto needs 2 arguments maximum: you provided 8".
 * Building the line here — flags before `--`, paths after — means a future flag cannot be
 * added on the wrong side of it, and the ordering is pinned by a test rather than by
 * whoever edits the call site next.
 */
export function rcloneArgs(subcommand: string, positionals: string[], intervalMs: number | null): string[] {
  return [subcommand, ...(intervalMs === null ? [] : statsFlags(intervalMs)), '--', ...positionals];
}

// How many of rclone's own messages to keep for a failure. See the catch below.
const MSG_TAIL = 5;

/**
 * One rclone JSON-log line, classified. Exported so the parsing contract — the fragile
 * part of this, because it is someone else's output format — can be tested against a
 * REAL captured line without a real transfer (scripts/selftest-progress.mjs).
 *
 * Returns a `stats` result for a progress line, a `msg` result for anything else rclone
 * says, or null for a line carrying neither.
 */
export type RcloneLogLine = { stats: { bytes: number; total: number } } | { msg: string } | null;

export function parseRcloneLogLine(line: string): RcloneLogLine {
  let frame: { msg?: unknown; object?: unknown; stats?: { bytes?: unknown; totalBytes?: unknown } };
  try {
    frame = JSON.parse(line);
  } catch {
    // Not JSON — rclone can still write plain text before logging is configured (the
    // "Config file not found - using defaults" notice arrives this way in some setups).
    // Keep it for the failure path rather than discarding it.
    const text = line.trim();
    return text === '' ? null : { msg: text };
  }
  const bytes = frame?.stats?.bytes;
  const total = frame?.stats?.totalBytes;
  if (typeof bytes === 'number' && typeof total === 'number') return { stats: { bytes, total } };
  if (typeof frame?.msg === 'string' && frame.msg.trim() !== '') {
    // `object` names the path/remote the message is about, and JSON-log mode is the only
    // reason it is a separate field rather than part of the sentence. Dropping it loses
    // WHICH file failed — "directory not found" instead of "Local file system at
    // /nope: directory not found".
    const obj = typeof frame.object === 'string' && frame.object.trim() !== '' ? `${frame.object.trim()}: ` : '';
    return { msg: `${obj}${frame.msg.trim()}` };
  }
  return null;
}

// Runs `rclone <args>` (array args via proc.ts's run() — no shell, so a remote name
// or path can never be interpreted as a second command). Translates a missing binary
// (ENOENT) into an actionable message instead of node's bare "spawn rclone ENOENT" —
// the single most likely first-run failure for an operator who hasn't installed
// rclone yet.
//
// When `progress` is given, the call runs in JSON-log mode. That has a cost worth
// naming: rclone's own error text stops being plain English on stderr, so run()'s
// non-zero-exit Error would otherwise quote a JSON blob at the operator. Hence `msgs` —
// every non-stats line is kept (bounded, with its `object` so the message still names
// what it is about), and rclone's OWN failure is re-thrown carrying those instead.
//
// "rclone's own failure" is the important qualifier. The substitution applies ONLY to a
// non-zero exit; a timeout, a spawn failure or anything else run() reports keeps its
// original message. Replacing unconditionally would let a routine notice — "Config file
// not found - using defaults" arrives on almost every run — stand in for
// "rclone timed out after 3600000ms", which is a different problem with a different fix
//.
async function runRclone(subcommand: string, positionals: string[], progress?: ProgressReporter): Promise<void> {
  const msgs: string[] = [];
  const onStderrLine = progress
    ? (line: string) => {
        const parsed = parseRcloneLogLine(line);
        if (parsed === null) return;
        if ('stats' in parsed) {
          progress.report(parsed.stats.bytes, parsed.stats.total);
          return; // a stats line is not an error message; it must not crowd out one
        }
        msgs.push(parsed.msg);
        if (msgs.length > MSG_TAIL) msgs.shift();
      }
    : undefined;
  try {
    await run(RCLONE_BIN, rcloneArgs(subcommand, positionals, progress ? progressIntervalMs() : null), {
      timeoutMs: PIPE_TIMEOUT_MS,
      onStderrLine,
    });
  } catch (e) {
    const err = e as NodeJS.ErrnoException;
    if (err?.code === 'ENOENT') {
      throw new Error(
        `rclone backend: '${RCLONE_BIN}' not found on PATH — install rclone (https://rclone.org/downloads/) ` +
          `and configure a remote (rclone config), or set CYPHER_BRAIN_RCLONE_BIN to its path`,
      );
    }
    // run() builds this exact prefix for a non-zero exit (`${cmd} exited ${code}: ...`),
    // which is the only case where the message body is rclone's JSON rather than ours.
    const isExitFailure = typeof err?.message === 'string' && err.message.startsWith(`${RCLONE_BIN} exited `);
    if (isExitFailure && msgs.length > 0) throw new Error(`rclone backend: ${msgs.join('; ')}`);
    throw e;
  }
}

// push --save-locator writes "<locator>\t<backend>\t<sha256>[...]" (one line, tab-
// delimited — pushpull.ts's readSavedLocatorLine()); a locator containing a tab or
// newline would shift/corrupt that file's fields, and (per file.ts's own comment) a
// locator may itself arrive over an UNTRUSTED channel (a tampered --save-locator
// file feeding pull's --from-locator-file). Reject those bytes outright rather than
// silently mangling recovery — arweave/file don't need this check because their
// locator shapes (a 43-char base64url id / <sha256>.age) structurally can't contain
// either; rclone's is a free-form string, so it must be checked explicitly here.
function assertSafeRemote(value: string, what: string): void {
  if (/[\t\r\n]/.test(value)) {
    throw new Error(
      `rclone backend: ${what} must not contain a tab or newline (breaks the tab-delimited save-locator file): ${JSON.stringify(value)}`,
    );
  }
}

// The locator IS the "<remote>:<path>" string itself — the same idea as the file
// backend using a local filesystem path as its locator (types.ts's StorageBackend
// doc comment). push --save-locator records it verbatim; pull hands it straight
// back to `rclone copyto` to fetch. Unlike arweave/turbo, this is known BEFORE
// upload (the caller chose it via --remote), not assigned after.
export function rcloneBackend(): StorageBackend {
  return {
    async put(file: string, opts: PutOpts = {}): Promise<string> {
      const remote = opts.remote;
      if (!remote) throw new Error('rclone backend: --remote <rclone-remote-name>:<path> required');
      assertSafeRemote(remote, '--remote');
      // `--` ends option parsing (rclone's cobra/pflag CLI, same convention as GNU
      // getopt) so a --remote value that happens to start with `-` (accidentally, or
      // via a tampered save-locator file feeding pull's locator back in here) is
      // always treated as the positional source/destination, never as an rclone flag.
      await runRclone('copyto', [resolve(file), remote], progressReporter('rclone push'));
      return remote;
    },
    async get(locator: string, out: string): Promise<void> {
      assertSafeRemote(locator, 'locator');
      await mkdir(dirname(resolve(out)), { recursive: true });
      await runRclone('copyto', [locator, resolve(out)], progressReporter('rclone pull'));
    },
  };
}
