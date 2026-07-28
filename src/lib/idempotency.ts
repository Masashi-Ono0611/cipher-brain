// Idempotency-key bookkeeping for cipher-brain-mcp's paid tools (issue #220): an AI
// agent's own retry logic — a network blip after snapshot_now already pushed to
// arweave/turbo, say — must never be able to spend twice for what the agent believes is
// one call. Stripe's Idempotency-Key pattern is the model (docs/prior-art.md): the caller
// names a key, and a repeat call carrying the SAME key gets back the FIRST call's result
// instead of doing the paid work again.
//
// Storage follows the same shape push --skip-unchanged already uses (src/lib/pushpull.ts):
// a small file under CIPHER_BRAIN_HOME, read before the paid work and written after it
// succeeds — no new persistence mechanism, no database, no lock server, no new runtime
// dependency. Unlike the save-locator file (one line, always overwritten with the latest
// push), this is a JSONL log because more than one DISTINCT key can be live at once — an
// agent may have several snapshot_now calls in flight (or recently completed) under
// different keys, and each needs its own remembered result. There is no consumer of this
// file OUTSIDE cipher-brain-mcp itself (no operator hand-edits or greps it the way they do
// a save-locator), so there is no positional-TSV backward-compatibility surface to
// preserve, and JSON-per-line is simpler to extend than a growing positional format would
// be.
import { readFile, writeFile, rename, rm, mkdir } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { randomBytes } from 'node:crypto';

// One stored line. `fingerprint` is an opaque, caller-computed digest of whatever fields
// define "the same call" for that tool (snapshot_now's is dirs/pg/recipients/out/backend/
// scan_secrets — see mcp.ts's snapshotNowFingerprint) — this module never inspects it,
// only compares it for equality, so a future second idempotent tool can define its own
// notion of "same call" without this file changing.
interface StoredLine {
  key: string;
  tool: string;
  recordedAt: string;
  fingerprint: string;
  result: Record<string, unknown>;
}

export interface IdempotencyLookupResult {
  /** The fingerprint the ORIGINAL call was recorded with — compared against the current call's own. */
  readonly fingerprint: string;
  /** The original call's structured result, replayed byte-for-byte on a cache hit — never re-derived. */
  readonly result: Record<string, unknown>;
}

// Every line is read + parsed on both lookup and record — this file is not expected to
// hold more than a handful of live entries at once (recordIdempotencyResult below drops
// every expired one on each write), so there is no need for an index or a streaming
// parser.
async function readAllRecords(path: string): Promise<StoredLine[]> {
  let text: string;
  try {
    text = await readFile(path, 'utf8');
  } catch {
    return []; // missing file == no prior calls recorded, never an error
  }
  const records: StoredLine[] = [];
  for (const line of text.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      const parsed = JSON.parse(trimmed);
      if (
        parsed &&
        typeof parsed === 'object' &&
        typeof parsed.key === 'string' &&
        typeof parsed.tool === 'string' &&
        typeof parsed.recordedAt === 'string' &&
        typeof parsed.fingerprint === 'string' &&
        parsed.result &&
        typeof parsed.result === 'object'
      ) {
        records.push(parsed as StoredLine);
      }
      // A line that parses but does not have this shape is silently dropped, same as a
      // line that does not parse at all (below) — this log is a fast path/safety net, and
      // a lookup that misses because of a malformed line falls through to "do the real
      // work", which is the SAFE direction to fail. A corrupt line must never be read as
      // a false cache hit for someone else's key.
    } catch {
      /* malformed line (a truncated write, a hand edit) — drop it, never let it crash a lookup or a write */
    }
  }
  return records;
}

const isFresh = (recordedAt: string, ttlSeconds: number, now: number): boolean => {
  const t = Date.parse(recordedAt);
  return Number.isFinite(t) && now - t < ttlSeconds * 1000;
};

/**
 * Look up the still-fresh recorded result for (tool, key), if any. Returns undefined on a
 * miss — no prior call, an expired one, or a key/tool that never matched — which the
 * caller must treat identically to "do the real work": this cache is only ever a fast
 * path to a result the tool would have produced anyway, never its own source of truth.
 *
 * The returned `fingerprint` is the ORIGINAL call's, for the caller to compare against the
 * current call's own — a mismatch means the same key was reused for a genuinely different
 * request, which the caller (mcp.ts) refuses rather than silently answering with the wrong
 * one's result.
 */
export async function lookupIdempotencyResult(
  path: string,
  tool: string,
  key: string,
  ttlSeconds: number,
  now: number = Date.now(),
): Promise<IdempotencyLookupResult | undefined> {
  const records = await readAllRecords(path);
  // Newest-first: recordIdempotencyResult always drops any prior entry for the SAME
  // (tool, key) before writing a new one, so in the steady state at most one entry per
  // key exists — this order only matters if an old file (written before a code change, or
  // hand-edited) somehow carries a duplicate, in which case the most recent write is the
  // one worth trusting.
  for (let i = records.length - 1; i >= 0; i--) {
    const r = records[i];
    if (r.tool === tool && r.key === key && isFresh(r.recordedAt, ttlSeconds, now)) {
      return { fingerprint: r.fingerprint, result: r.result };
    }
  }
  return undefined;
}

/**
 * Record a successful result for (tool, key), for a future lookupIdempotencyResult to
 * replay. Rewrites the whole file rather than merely appending, DROPPING every entry that
 * is either expired or for the SAME (tool, key) being written now — a superseded write,
 * which only happens after a TTL expiry or the PushLocatorWriteError partial-success path
 * in mcp.ts, never after a bare cache hit (that returns before this is ever called) — so
 * the file stays bounded to roughly one line per still-live key instead of growing
 * forever, while every OTHER key's still-fresh entry survives untouched.
 *
 * Atomic write (temp sibling + rename), the SAME pattern push()'s --save-locator write
 * uses (src/lib/pushpull.ts): a crash mid-write must leave either the old file or the new
 * one intact, never a truncated one that a later lookup would silently read as "no prior
 * calls" for every key at once.
 */
export async function recordIdempotencyResult(
  path: string,
  tool: string,
  key: string,
  fingerprint: string,
  result: Record<string, unknown>,
  ttlSeconds: number,
  now: number = Date.now(),
): Promise<void> {
  const existing = await readAllRecords(path);
  const kept = existing.filter((r) => !(r.tool === tool && r.key === key) && isFresh(r.recordedAt, ttlSeconds, now));
  const fresh: StoredLine = { key, tool, recordedAt: new Date(now).toISOString(), fingerprint, result };
  const lines = [...kept, fresh].map((r) => JSON.stringify(r));
  await mkdir(dirname(resolve(path)), { recursive: true });
  const tmp = `${path}.${process.pid}.${randomBytes(4).toString('hex')}.tmp`;
  try {
    await writeFile(tmp, `${lines.join('\n')}\n`, { flag: 'w' });
    await rename(tmp, path);
  } catch (e) {
    await rm(tmp, { force: true });
    throw e;
  }
}
