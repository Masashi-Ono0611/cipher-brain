// progress — the ONE place that decides how often a long transfer reports, and what
// that line looks like (#283).
//
// `push`/`pull` used to print a cost estimate and then nothing until they finished, so
// a multi-hundred-MB upload was minutes of silence indistinguishable from a hang. Both
// backends that can be slow already produce the numbers — @ardrive/turbo-sdk emits
// `events.onProgress`, and rclone prints a stats line per interval — so nothing here
// measures anything; it only rate-limits and formats.
//
// Two properties are deliberate and are the reason this is a module rather than a
// couple of lines in each backend:
//
//  - CADENCE IS NOT A CONSTANT. The generated nightly runner does `exec >>"$LOG" 2>&1`
//    (schedule.ts) and nothing rotates or caps those logs — one file per day, kept
//    forever. A per-second line on a 30-minute upload would be ~1800 lines every night
//    for as long as the schedule exists. The MCP server has the same problem in a
//    different shape: captureCall() collects stderr per call, and the tools that surface
//    it (snapshot_now's `log`) put these lines in the tool RESULT, so cadence sets
//    response size. So an interactive run (stderr is a TTY) reports often, and
//    everything else reports rarely.
//
//  - IT WRITES WITH console.error, NOT process.stderr.write. mcp.ts rebinds
//    console.error and captures it; a direct process.stderr.write bypasses that capture
//    and never reaches the MCP client at all. Progress an agent cannot see misses the
//    caller who most needs it — an agent cannot look at a terminal to decide whether to
//    keep waiting. NOTE this makes the lines AVAILABLE, not universally visible:
//    verify_restore/restore_now discard the CaptureResult of their pull, so the arweave
//    download progress is collected and dropped there. Tracked separately.
import { fmtBytes } from './util.js';

/** How often to report, by whether a human is watching. */
export const TTY_INTERVAL_MS = 2_000;
export const NON_TTY_INTERVAL_MS = 30_000;

export interface ProgressReporter {
  /**
   * Offer a sample. Emits at most one line per interval, and never two lines for the
   * same byte count — a backend may call this far more often than it should print.
   */
  report(processed: number, total: number): void;
}

export interface ProgressOpts {
  /** Overrides the TTY-derived cadence. Tests use it; callers should not. */
  intervalMs?: number;
  /** Injectable clock and sink, so the cadence rule can be tested without sleeping. */
  now?: () => number;
  write?: (line: string) => void;
}

// "36s" / "4m 12s" / "1h 02m" — seconds only below a minute, because an ETA of
// "0h 00m 36s" reads as precision this estimate does not have.
function fmtEta(seconds: number): string {
  const s = Math.max(0, Math.round(seconds));
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ${String(s % 60).padStart(2, '0')}s`;
  return `${Math.floor(m / 60)}h ${String(m % 60).padStart(2, '0')}m`;
}

/**
 * The cadence a reporter would use right now. Exported because a child process that
 * produces its own progress (rclone's `--stats <interval>`) has to be told how often to
 * produce it — asking a subprocess for one line per second and then dropping 29 of every
 * 30 would be the same silence with more work.
 */
// process.stderr.isTTY is undefined (not false) when stderr is not a character device,
// which is why this is a truthiness check rather than === false.
export const progressIntervalMs = (): number => (process.stderr.isTTY ? TTY_INTERVAL_MS : NON_TTY_INTERVAL_MS);

export function progressReporter(component: string, opts: ProgressOpts = {}): ProgressReporter {
  const now = opts.now ?? (() => Date.now());
  const interval = opts.intervalMs ?? progressIntervalMs();
  const write = opts.write ?? ((line: string) => console.error(line));

  // The rate window is anchored HERE, when the reporter is made, not at the first
  // sample. Callers create one immediately before starting the transfer they report on,
  // so this is that transfer's own start — and anchoring at the first sample instead
  // would mean the first emitted line always had zero elapsed time and therefore no rate
  // and no ETA. With a 30s unattended cadence that first line is often the only one.
  let startedAt = now();
  // Bytes already counted when the window was anchored. Zero at construction (the
  // transfer has not started); on a rollback it becomes the restarted attempt's position,
  // so the rate stays "bytes moved during the window I actually timed".
  let anchorProcessed = 0;
  let lastEmitAt = 0;
  let lastProcessed = -1;

  return {
    report(processed: number, total: number): void {
      const t = now();
      // A COUNTER THAT WENT BACKWARDS is a restarted transfer, not a slow one: rclone
      // retries a failed copy from zero, and a resumed upload re-reports from its new
      // origin. Averaging across the abandoned attempt yields a rate and an ETA that
      // describe neither attempt — measured at "80% then 20%" producing a confident
      // "1 B/s, ETA 80s" (multi-model review finding). Re-anchor instead, so the numbers
      // describe the attempt actually running.
      if (processed < lastProcessed) {
        startedAt = t;
        anchorProcessed = processed;
        lastEmitAt = 0;
        lastProcessed = -1;
      }
      // Nothing has moved since the last line — a repeat would read as progress.
      if (processed === lastProcessed) return;
      // A sample of 0 bytes carries no information beyond "started", which the
      // surrounding push/pull output already says.
      if (processed <= 0) return;
      if (lastEmitAt !== 0 && t - lastEmitAt < interval) return;

      const elapsed = (t - startedAt) / 1000;
      // Rate and ETA are OMITTED, not shown as 0, until there is enough of a window to
      // mean anything — a confidently wrong "0 B/s, ETA -" is worse than no estimate.
      const moved = processed - anchorProcessed;
      const rate = elapsed >= 1 && moved > 0 ? moved / elapsed : null;
      const parts: string[] = [];
      if (total > 0) parts.push(`${Math.min(100, Math.floor((processed / total) * 100))}%`);
      parts.push(total > 0 ? `${fmtBytes(processed)}/${fmtBytes(total)}` : fmtBytes(processed));
      if (rate !== null) {
        parts.push(`${fmtBytes(rate)}/s`);
        if (total > processed) parts.push(`ETA ${fmtEta((total - processed) / rate)}`);
      }
      write(`${component}: ${parts.join(' ')}`);
      lastEmitAt = t;
      lastProcessed = processed;
    },
  };
}
