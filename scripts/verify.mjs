#!/usr/bin/env node
// `npm run verify` — runs the suite (npm run verify:suite) under an ISOLATED TMPDIR and
// asserts that directory is empty afterwards (#328).
//
// The suite generates real age private keys. Two selftests used to leave theirs in TMPDIR,
// so every run added one and they accumulated — 157 `identity.age` files on one box before
// #329 fixed them. This is the check that catches the next script to forget.
//
// WHY A WRAPPER, and not two links in the `&&` chain, which is what I tried first:
//
//  - The check has to run when the suite FAILS. Behind `&&` it did not, so a run that
//    failed after leaking never reached it — and the next run's "before" snapshot adopted
//    the leaked directory as its baseline, hiding it permanently.
//  - Two runs at once (two worktrees, say) shared one TMPDIR and one state file, so each
//    reported the other's live directories. An isolated TMPDIR per run removes that
//    entirely, and removes the need to keep a list of "our" filename prefixes in step with
//    the source — anything created in here is ours by construction.
//
// WHAT IT DOES NOT COVER, measured rather than assumed: BSD `mktemp -d` (macOS) IGNORES
// TMPDIR unless given an explicit template, so the bash selftests' directories land outside
// this dir and are not watched. They are not leaking today — one full run adds zero — and
// they all clean up via EXIT traps. A bash script that wants to be covered should follow
// scripts/cli-smoke.sh and pass `"${TMPDIR:-/tmp}/cb-<name>-XXXXXX"`.
import { spawn } from 'node:child_process';
import { mkdtemp, readdir, rm } from 'node:fs/promises';
import { constants, tmpdir } from 'node:os';
import { join } from 'node:path';

const realTmp = tmpdir();
const sandbox = await mkdtemp(join(realTmp, 'cb-verify-'));

// `detached` puts the suite in its own process group, so a Ctrl-C in the terminal reaches
// THIS process only and the handler below decides what happens next. Without it the child
// dies at the same instant the wrapper does, and the sandbox is never inspected — which is
// the worst moment to skip it: a selftest killed mid-`try` never runs its `finally`, so an
// interrupted run is exactly when key material is most likely to be left behind
// (multi-model review).
const suite = spawn('npm', ['run', 'verify:suite'], {
  stdio: 'inherit',
  detached: true,
  // TMP/TEMP alongside TMPDIR so a dependency reading either lands here too.
  env: {
    ...process.env,
    TMPDIR: sandbox,
    TMP: sandbox,
    TEMP: sandbox,
    // Node puts its compile cache under TMPDIR when nothing says otherwise — npm's own CLI
    // calls enableCompileCache() — so it would land in the sandbox and be reported as a
    // leak on every run. Pinned outside. An ignore-list entry would have worked too, but
    // would quietly grow every time some tool decided to keep something there.
    NODE_COMPILE_CACHE: join(realTmp, 'cb-verify-node-cache'),
  },
});

const settled = new Promise((resolve) => {
  suite.on('close', (code, signal) => resolve({ code, signal }));
  suite.on('error', () => resolve({ code: 1, signal: null }));
});

// Forward the signal to the whole child group, then fall through to the inspection below
// and re-raise on ourselves so the caller still sees a signal death rather than a plain
// exit code.
let forwarded = null;
for (const sig of ['SIGINT', 'SIGTERM', 'SIGHUP']) {
  process.on(sig, () => {
    forwarded ??= sig;
    try {
      process.kill(-suite.pid, sig);
    } catch {
      /* already gone */
    }
  });
}

const { code, signal } = await settled;

// From here on, whatever happened to the suite, the sandbox gets inspected. That is the
// whole point of this being a wrapper rather than another link in the `&&` chain.
let left;
try {
  left = await readdir(sandbox);
} catch (e) {
  // A guard that cannot see must not report "clean" — that is the fail-open this replaced.
  console.error(`\n[FAIL] temp hygiene: could not inspect ${sandbox} (${e.message})`);
  process.exit(code || 1);
}

// Exit the way the suite did. A signal death is re-raised rather than flattened to 1, so a
// Ctrl-C still looks like a Ctrl-C to whatever ran this.
const finish = (hygieneFailed) => {
  if (signal || forwarded) {
    const sig = signal ?? forwarded;
    const num = constants.signals[sig];
    if (num) {
      process.removeAllListeners(sig);
      process.kill(process.pid, sig);
      // If the signal is somehow ignored, fall through to the conventional 128+n.
      process.exit(128 + num);
    }
    process.exit(1);
  }
  if (code !== 0) process.exit(code ?? 1);
  process.exit(hygieneFailed ? 1 : 0);
};

if (left.length === 0) {
  try {
    await rm(sandbox, { recursive: true, force: true });
  } catch (e) {
    // The directory is empty — readdir just said so — so this is a filesystem oddity, not
    // key material left behind. Worth saying, not worth failing a suite over.
    console.error(`warning: temp hygiene: could not remove the empty sandbox ${sandbox} (${e.message})`);
  }
  if (code === 0 && !signal && !forwarded) console.log('[PASS] temp hygiene: the suite left nothing in its own TMPDIR');
  finish(false);
}

// Name what is in them: "a temp dir was left" and "a private key was left" are different
// sizes of problem, and the message should say which one this is.
const withKeys = [];
for (const name of left) {
  const inner = await readdir(join(sandbox, name), { recursive: true }).catch(() => []);
  if (inner.some((f) => String(f).endsWith('identity.age'))) withKeys.push(name);
}

console.error(`\n[FAIL] temp hygiene: the suite left ${left.length} entry(ies) in its TMPDIR (#328)`);
for (const n of left) console.error(`  ${n}${withKeys.includes(n) ? '   <-- contains identity.age' : ''}`);
console.error(`  kept at ${sandbox} for inspection — remove it once you have looked`);
console.error(
  'Whichever script created these must remove them in a finally/trap. The suite generates ' +
    'real age private keys, and leaving them in TMPDIR is the thing snapshot() spends a ' +
    'signal handler avoiding everywhere else.',
);
if (signal || forwarded) {
  console.error("(the run was interrupted, so a selftest's own finally/trap may simply not have run)");
} else if (code !== 0) {
  console.error('\n(the suite itself also failed — fix that first; the above is additional)');
}
finish(true);
