// rclone backend (#204): a thin subprocess wrapper around the `rclone` binary.
// restic and kopia both integrate rclone as a "meta-backend" instead of reimplementing
// each cloud provider's auth/protocol themselves — this backend takes the same
// approach: cipher-brain never talks to S3/GCS/B2/Dropbox/etc directly, it only ever
// shells out to `rclone copyto`, delegating auth, protocol and retries entirely to
// whatever remote the operator has already configured in their own rclone.conf (or a
// config-less on-the-fly remote, e.g. `:local:/path`). Only ciphertext ever crosses
// this backend — same threat model as every other one (push() already refuses to
// push a non-age artifact before any backend is invoked).
import { mkdir } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { RCLONE_BIN, PIPE_TIMEOUT_MS } from '../config.js';
import { run } from '../proc.js';
import type { StorageBackend, PutOpts } from '../types.js';

// Runs `rclone <args>` (array args via proc.ts's run() — no shell, so a remote name
// or path can never be interpreted as a second command). Translates a missing binary
// (ENOENT) into an actionable message instead of node's bare "spawn rclone ENOENT" —
// the single most likely first-run failure for an operator who hasn't installed
// rclone yet. Any other failure (bad remote name, network error, auth failure, ...)
// is rclone's own stderr, already surfaced by run()'s non-zero-exit Error.
async function runRclone(args: string[]): Promise<void> {
  try {
    await run(RCLONE_BIN, args, { timeoutMs: PIPE_TIMEOUT_MS });
  } catch (e) {
    const err = e as NodeJS.ErrnoException;
    if (err?.code === 'ENOENT') {
      throw new Error(
        `rclone backend: '${RCLONE_BIN}' not found on PATH — install rclone (https://rclone.org/downloads/) ` +
          `and configure a remote (rclone config), or set CIPHER_BRAIN_RCLONE_BIN to its path`,
      );
    }
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
      await runRclone(['copyto', '--', resolve(file), remote]);
      return remote;
    },
    async get(locator: string, out: string): Promise<void> {
      assertSafeRemote(locator, 'locator');
      await mkdir(dirname(resolve(out)), { recursive: true });
      await runRclone(['copyto', '--', locator, resolve(out)]);
    },
  };
}
