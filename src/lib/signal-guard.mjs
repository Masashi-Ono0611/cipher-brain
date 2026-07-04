// snapshot() stages the full *plaintext* brain into a 0700 temp dir and leans on
// its finally-block to erase it. But a signal (operator Ctrl-C, or launchd/shutdown
// SIGTERM in service mode) tears the process down WITHOUT unwinding the suspended
// async stack, so the finally never runs and the plaintext brain would linger in
// TMPDIR — the exact on-disk exposure the threat model exists to prevent. Track the
// active stage dir and erase it synchronously from a signal handler (async rm can't
// finish before the process dies), then re-raise so the exit code is correct.
import { rmSync } from 'node:fs';
import { ACTIVE_CHILDREN } from './proc.mjs';

let ACTIVE_STAGE = null;
let ACTIVE_OUT_PART = null; // the partial ${out}.part being written; erased on signal so no stray ciphertext lingers
let SIGNAL_GUARD_INSTALLED = false;

// ESM live bindings are read-only from the importing side, so the module that owns a
// stage / .part (snapshot) registers them through these setters.
export const setActiveStage = (v) => { ACTIVE_STAGE = v; };
export const setActiveOutPart = (v) => { ACTIVE_OUT_PART = v; };

export function installStageSignalGuard() {
  if (SIGNAL_GUARD_INSTALLED) return;
  SIGNAL_GUARD_INSTALLED = true;
  for (const sig of ['SIGINT', 'SIGTERM', 'SIGHUP']) {
    const handler = () => {
      // Kill the pipeline children FIRST so a still-writing age/tar can't re-create the
      // stage or .part after we remove them (the signal may have hit node alone).
      for (const c of ACTIVE_CHILDREN) { try { c.kill('SIGKILL'); } catch {} }
      ACTIVE_CHILDREN.clear();
      if (ACTIVE_STAGE) { try { rmSync(ACTIVE_STAGE, { recursive: true, force: true }); } catch {} ACTIVE_STAGE = null; }
      if (ACTIVE_OUT_PART) { try { rmSync(ACTIVE_OUT_PART, { force: true }); } catch {} ACTIVE_OUT_PART = null; }
      // adding a listener suppressed Node's default auto-terminate — remove only our
      // own handler (not any unrelated listener) and re-raise so the process exits
      // with the correct signal code instead of hanging.
      process.off(sig, handler);
      process.kill(process.pid, sig);
    };
    process.on(sig, handler);
  }
}
