// ---------- small process helpers (array args only — no shell, no injection) ----------
import { spawn, type ChildProcess } from 'node:child_process';

// Every spawned child registers here while running, so the signal handler can SIGKILL
// them BEFORE it rmSync's the stage / .part — otherwise a signal delivered to node
// alone (e.g. launchd stopping the service, or `kill <pid>`) leaves the children alive
// to re-create the very files the handler just removed (a still-streaming tar would
// keep feeding the pipeline after we unlinked its output). See installStageSignalGuard().
export const ACTIVE_CHILDREN: Set<ChildProcess> = new Set();

export interface RunOpts {
  input?: string;
  timeoutMs?: number;
}

export interface RunResult {
  out: string;
  err: string;
}

export function run(cmd: string, args: string[], { input, timeoutMs }: RunOpts = {}): Promise<RunResult> {
  return new Promise((res, rej) => {
    const p = spawn(cmd, args, { stdio: [input ? 'pipe' : 'ignore', 'pipe', 'pipe'] });
    ACTIVE_CHILDREN.add(p);
    const doneChild = () => ACTIVE_CHILDREN.delete(p);
    let out = '', err = '';
    let timer: ReturnType<typeof setTimeout> | undefined;
    if (timeoutMs) {
      // a stuck child (e.g. a storage-daemon-cli call that never returns) must not
      // hang us forever — kill it and reject so callers can bound their own loops.
      timer = setTimeout(() => { p.kill('SIGKILL'); rej(new Error(`${cmd} timed out after ${timeoutMs}ms`)); }, timeoutMs);
    }
    p.stdout?.on('data', (d) => (out += d));
    p.stderr?.on('data', (d) => (err += d));
    p.on('error', (e) => { clearTimeout(timer); doneChild(); rej(e); });
    p.on('close', (code) => {
      clearTimeout(timer); doneChild();
      code === 0 ? res({ out, err }) : rej(new Error(`${cmd} exited ${code}: ${err.trim() || out.trim()}`));
    });
    if (input) { p.stdin?.write(input); p.stdin?.end(); }
  });
}

// The tar|age (snapshot) and age|tar (restore) streaming pipelines live in
// crypt.mjs (encryptToFile / decryptToChild) — the encryption half runs
// in-process (typage), so only ONE child (tar) is spawned per pipeline.
