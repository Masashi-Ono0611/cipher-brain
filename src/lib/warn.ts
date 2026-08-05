// warn — the single chokepoint for runtime warnings a HUMAN must see (#347).
//
// Measured motivation: a real monthly push was driven end-to-end by an AI agent, and
// every crafted line — including `⚠ snapshot encrypted to a SINGLE recipient key —
// … UNRECOVERABLE`, a warning that exists precisely to reach a human — landed in a
// background log the human never read. The human saw exactly the fragments the agent
// happened to quote. Two structural holes made that silent: warnings written straight
// to `process.stderr.write` bypass the MCP server's per-call capture entirely (it
// intercepts console.error, not the raw stream), and nothing marked which stderr lines
// were load-bearing versus decoration, so an agent had no contract to relay by.
//
// Every ⚠-class runtime warning goes through warn():
//   - it prints immediately (console.error — which the MCP server's captureCall DOES
//     intercept, closing the bypass), prefixed with the glyph, and
//   - it is recorded, so the run can be SUMMARIZED at the end: the CLI prints a
//     relay-me block after the command (cli.ts), and MCP tool results carry a
//     `warnings` array (mcp.ts) — one recording, two surfaces, no site-by-site drift.
//
// Interactive wizard prose and command OUTPUT (e.g. `wallet create`'s "back it up
// now") are not warnings and stay out; this is for incidental hazards noticed along
// the way, the lines that must survive one hop of indirection.
import { installEpipeGuard } from './ui.js';

const recorded: string[] = [];

/** Print a warning now (stderr, ⚠-prefixed) and record it for the end-of-run summary. */
export function warn(message: string): void {
  recorded.push(message);
  installEpipeGuard();
  console.error(`⚠  ${message}`);
}

/** All warnings recorded since the last drain, clearing the record (one run = one drain). */
export function drainWarnings(): string[] {
  return recorded.splice(0);
}

/**
 * The end-of-run summary block as lines (empty array when there is nothing to say).
 * Pure formatting, exported so it can be pinned by tests: numbering restarts at 1,
 * and a multi-line warning's continuation lines indent to sit under its own text —
 * width-aware, so item 10 does not shear its continuations out of column.
 */
export function formatWarningSummary(warnings: string[]): string[] {
  if (warnings.length === 0) return [];
  const lines = [
    '',
    `⚠  run summary — ${warnings.length} warning(s) a human should see (an agent relaying this run: show these verbatim):`,
  ];
  warnings.forEach((w, i) => {
    const prefix = `   ${i + 1}. `;
    lines.push(prefix + w.split('\n').join(`\n${' '.repeat(prefix.length)}`));
  });
  return lines;
}
