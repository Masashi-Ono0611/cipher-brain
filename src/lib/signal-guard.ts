// snapshot() stages the full *plaintext* brain into a 0700 temp dir and leans on
// its finally-block to erase it, and restore() decrypts straight into --out-dir.
// But a signal (operator Ctrl-C, or launchd/shutdown SIGTERM in service mode) tears
// the process down WITHOUT unwinding the suspended async stack, so the finally never
// runs and either the staged plaintext brain or a partially-extracted --out-dir would
// linger — the exact on-disk exposure the threat model exists to prevent. Track the
// active stage dir / .part / restore out-dir and clean them up synchronously from a
// signal handler (async rm/fs calls can't finish before the process dies), then
// re-raise so the exit code is correct.
import { rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { ACTIVE_CHILDREN } from './proc.js';

let ACTIVE_STAGE: string | null = null;
let ACTIVE_OUT_PART: string | null = null; // the partial ${out}.part being written; erased on signal so no stray ciphertext lingers
let ACTIVE_RESTORE_OUT_DIR: string | null = null; // restore()'s --out-dir while a tar extract is in flight
let ACTIVE_RESTORE_OUT_DIR_PREEXISTED = false; // whether restore() created out-dir itself (safe to erase) or it was already there (must not be destroyed)
let SIGNAL_GUARD_INSTALLED = false;

// ESM live bindings are read-only from the importing side, so the module that owns a
// stage / .part (snapshot) or an out-dir (restore) registers them through these setters.
export const setActiveStage = (v: string | null): void => {
  ACTIVE_STAGE = v;
};
export const setActiveOutPart = (v: string | null): void => {
  ACTIVE_OUT_PART = v;
};
// restore() calls this right after it creates/confirms --out-dir and before the tar
// child starts extracting into it, then clears it (v=null) once the extract settles
// (success, or its own catch-block cleanup already ran) — a LATER signal (e.g. during
// a subsequent pg_restore) must not touch out-dir anymore. `preExisted` mirrors
// restore()'s own non-signal cleanup rule: if restore() created out-dir itself it is
// safe to erase outright on signal; if the caller pointed at a directory that was
// already there, deleting it would destroy content we don't own, so the handler
// instead drops a synchronous sentinel flagging it unsafe to trust.
export const setActiveRestoreOutDir = (v: string | null, preExisted = false): void => {
  ACTIVE_RESTORE_OUT_DIR = v;
  ACTIVE_RESTORE_OUT_DIR_PREEXISTED = preExisted;
};

export function installStageSignalGuard(): void {
  if (SIGNAL_GUARD_INSTALLED) return;
  SIGNAL_GUARD_INSTALLED = true;
  const signals: NodeJS.Signals[] = ['SIGINT', 'SIGTERM', 'SIGHUP'];
  for (const sig of signals) {
    const handler = () => {
      // Kill the pipeline children FIRST so a still-writing age/tar can't re-create the
      // stage, .part, or out-dir contents after we remove/flag them (the signal may
      // have hit node alone).
      for (const c of ACTIVE_CHILDREN) {
        try {
          c.kill('SIGKILL');
        } catch {}
      }
      ACTIVE_CHILDREN.clear();
      if (ACTIVE_STAGE) {
        try {
          rmSync(ACTIVE_STAGE, { recursive: true, force: true });
        } catch {}
        ACTIVE_STAGE = null;
      }
      if (ACTIVE_OUT_PART) {
        try {
          rmSync(ACTIVE_OUT_PART, { force: true });
        } catch {}
        ACTIVE_OUT_PART = null;
      }
      if (ACTIVE_RESTORE_OUT_DIR) {
        if (!ACTIVE_RESTORE_OUT_DIR_PREEXISTED) {
          try {
            rmSync(ACTIVE_RESTORE_OUT_DIR, { recursive: true, force: true });
          } catch {}
        } else {
          // can't safely delete a directory the caller already owned before restore()
          // touched it — drop a durable sentinel instead (a console.error here could be
          // lost: the process is about to die and stderr writes are not guaranteed to
          // flush before that happens).
          try {
            writeFileSync(
              join(ACTIVE_RESTORE_OUT_DIR, '.cipher-brain-restore-INCOMPLETE'),
              `restore interrupted by ${sig} at ${new Date().toISOString()} — this directory may hold a partially-extracted tree; discard it before trusting the contents\n`,
            );
          } catch {}
        }
        ACTIVE_RESTORE_OUT_DIR = null;
        ACTIVE_RESTORE_OUT_DIR_PREEXISTED = false;
      }
      // adding a listener suppressed Node's default auto-terminate — remove only our
      // own handler (not any unrelated listener) and re-raise so the process exits
      // with the correct signal code instead of hanging.
      process.off(sig, handler);
      process.kill(process.pid, sig);
    };
    process.on(sig, handler);
  }
}
