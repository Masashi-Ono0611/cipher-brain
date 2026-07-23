// Tiny pure-ASCII mascot for cipher-brain's human-facing TTY output (README
// banner, `--help`, and the `verify` VERDICT line) — see issue #147.
//
// This ASCII-fies the repo's OWN existing mascot brand rather than inventing a
// new one: `mascot.svg` / `favicon.svg` (both already in this repo — the
// landing page's cypherpunk hooded dog in sunglasses, with binary-digit "10"
// / "01" reflections in the lenses) is the source of truth for the motif. It
// is a small, un-hooded-eared, sunglassed dog face, NOT the sibling project
// mira-harness's cat (mira-harness src/ui.ts, commit 5f5e489) — no ears/paws,
// a hood peak + rectangular lenses instead.
//
// The bracket style on each lens doubles as a verification signal: `[..]`
// (square, "on straight") vs `(..)` (round, "slipping") — see FACES below.
//
// Kept strictly ASCII (no unicode, not even the accent glyphs mira-harness
// allows itself) so it renders identically in any terminal/locale with zero
// alignment risk — decoration only, never part of machine-readable output
// (nothing here should be called on a --json / piped path).

/** PARTIAL mirrors `verify`'s third VERDICT (decryptability not proven on this
 *  box): one lens still square ("proven"), the other slipped round
 *  ("unproven") — a literal "half verified" face. */
export type Mood = 'neutral' | 'happy' | 'sad' | 'partial';

/** lensL/lensR: `[10]` (square, "sunglasses on straight") vs `(10)` (round,
 *  "sunglasses slipping") — verification-completeness, not emotion. mouth is
 *  the emotion: `-` neutral, `u` grin, `n` frown, `~` uncertain. */
const FACES: Record<Mood, { lensL: string; lensR: string; mouth: string }> = {
  neutral: { lensL: '[10]', lensR: '[01]', mouth: '-' },
  happy: { lensL: '[10]', lensR: '[01]', mouth: 'u' },
  sad: { lensL: '(10)', lensR: '(01)', mouth: 'n' },
  partial: { lensL: '[10]', lensR: '(01)', mouth: '~' },
};

/**
 * The hooded-dog-in-sunglasses mascot, faced for `mood`. Used by the README
 * banner (neutral), `cipher-brain --help` (neutral), and `verify`'s VERDICT
 * line (mood mapped from PASS/FAIL/PARTIAL via `moodForVerdict`).
 */
export function mascot(mood: Mood = 'neutral'): string[] {
  const f = FACES[mood];
  return [
    '   ,--^--,',
    '  /           \\',
    ` | ${f.lensL}  ${f.lensR} |`,
    ` |     ${f.mouth}      |`,
    '  \\___________/',
  ];
}

/** Maps `verify`'s three VERDICT strings onto a mascot mood: PASS is happy,
 *  FAIL is sad, PARTIAL (decryptability not proven on this box) is the
 *  one-lens-slipped "not fully verified" face. */
export function moodForVerdict(verdict: 'PASS' | 'FAIL' | 'PARTIAL'): Mood {
  if (verdict === 'PASS') return 'happy';
  if (verdict === 'FAIL') return 'sad';
  return 'partial';
}

// A closed downstream pipe surfaces as an EPIPE 'error' event on process.stderr
// ASYNCHRONOUSLY (Node re-throws it from inside its own event-loop dispatch a
// tick later — a try/catch around the write call does NOT see it), so the only
// reliable guard is a no-op 'error' listener on the stream itself, same idea as
// crypt.ts's `cons.stdin?.on('error', () => {})` for the age|tar pipeline.
// Installed lazily (only once printMascot is actually used) and only once.
let epipeGuardInstalled = false;
/** Exported so other decoration-only, STDERR-only modules (wisdom.ts's
 *  founder's note / precursor quotes, issue #195) can install the same
 *  EPIPE guard without duplicating it. */
export function installEpipeGuard(): void {
  if (epipeGuardInstalled) return;
  epipeGuardInstalled = true;
  process.stderr.on('error', (e: NodeJS.ErrnoException) => {
    if (e.code !== 'EPIPE') throw e;
  });
}

/**
 * Print the mascot to STDERR — decoration only, so it never lands in a
 * command's machine-readable stdout. A caller piping/grepping that stdout for
 * a specific line (e.g. `verify ... | grep -q 'VERDICT: PASS'`, or the same
 * with `2>&1` merging stderr in first) closes its end of the pipe the instant
 * it matches, which can be BEFORE this later, decoration-only write lands —
 * without the guard above, Node throws an uncaught EPIPE and kills the CLI.
 * A downstream reader that already got what it needed must never crash us.
 */
export function printMascot(mood: Mood): void {
  installEpipeGuard();
  console.error(mascot(mood).join('\n'));
}
