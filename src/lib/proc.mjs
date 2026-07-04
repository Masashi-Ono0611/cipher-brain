// ---------- small process helpers (array args only — no shell, no injection) ----------
import { spawn } from 'node:child_process';

// Every spawned child registers here while running, so the signal handler can SIGKILL
// them BEFORE it rmSync's the stage / .part — otherwise a signal delivered to node
// alone (e.g. launchd stopping the service, or `kill <pid>`) leaves the children alive
// to re-create the very files the handler just removed (a still-writing age would
// re-make ${out}.part after we unlinked it). See installStageSignalGuard().
export const ACTIVE_CHILDREN = new Set();

export function run(cmd, args, { input, timeoutMs } = {}) {
  return new Promise((res, rej) => {
    const p = spawn(cmd, args, { stdio: [input ? 'pipe' : 'ignore', 'pipe', 'pipe'] });
    ACTIVE_CHILDREN.add(p);
    const doneChild = () => ACTIVE_CHILDREN.delete(p);
    let out = '', err = '', timer;
    if (timeoutMs) {
      // a stuck child (e.g. a storage-daemon-cli call that never returns) must not
      // hang us forever — kill it and reject so callers can bound their own loops.
      timer = setTimeout(() => { p.kill('SIGKILL'); rej(new Error(`${cmd} timed out after ${timeoutMs}ms`)); }, timeoutMs);
    }
    p.stdout.on('data', (d) => (out += d));
    p.stderr.on('data', (d) => (err += d));
    p.on('error', (e) => { clearTimeout(timer); doneChild(); rej(e); });
    p.on('close', (code) => {
      clearTimeout(timer); doneChild();
      code === 0 ? res({ out, err }) : rej(new Error(`${cmd} exited ${code}: ${err.trim() || out.trim()}`));
    });
    if (input) { p.stdin.write(input); p.stdin.end(); }
  });
}

// Pipe producer.stdout -> consumer.stdin and wait for both. Used for the
// tar|age (snapshot) and age|tar (restore) streaming pipelines. `timeoutMs` bounds the
// WHOLE pipeline (like run()'s per-child timeout) so a wedged age/tar can't hang the CLI
// forever; on failure children are SIGTERM'd then SIGKILL'd ~2s later so a SIGTERM-ignoring
// child can't linger after the promise rejects.
export function pipe2(prodCmd, prodArgs, consCmd, consArgs, { consStdout = 'inherit', timeoutMs } = {}) {
  return new Promise((res, rej) => {
    const prod = spawn(prodCmd, prodArgs, { stdio: ['ignore', 'pipe', 'pipe'] });
    const cons = spawn(consCmd, consArgs, { stdio: ['pipe', consStdout, 'pipe'] });
    ACTIVE_CHILDREN.add(prod); ACTIVE_CHILDREN.add(cons);
    const doneChildren = () => { ACTIVE_CHILDREN.delete(prod); ACTIVE_CHILDREN.delete(cons); };
    let pErr = '', cErr = '', left = 2, settled = false, timer, killTimer;
    const stopTimers = () => { clearTimeout(timer); clearTimeout(killTimer); };
    // resolve once a child has actually exited (close/exit), or immediately if it already has
    const childExit = (c) => new Promise((r) => {
      if (c.exitCode !== null || c.signalCode !== null) return r();
      c.once('close', r); c.once('exit', r);
    });
    const fail = (e) => {
      if (settled) return;
      settled = true;
      stopTimers();
      prod.kill('SIGTERM'); cons.kill('SIGTERM'); // ask the survivor (or still-decrypting child) to stop
      // escalate: a child that ignores SIGTERM must not linger holding plaintext open.
      killTimer = setTimeout(() => { try { prod.kill('SIGKILL'); } catch {} try { cons.kill('SIGKILL'); } catch {} }, 2000);
      killTimer.unref?.(); // don't keep the event loop alive just for the escalation
      // Reject ONLY after both children are dead — otherwise the caller's catch/finally
      // (rm of .part / stage / out-dir) could race a still-writing age/tar that then
      // recreates partial plaintext or ciphertext after we cleaned up (same recreate-
      // after-unlink hazard the signal guard fixes). Children stay in ACTIVE_CHILDREN
      // until they exit, so a signal in the meantime still SIGKILLs them.
      Promise.all([childExit(prod), childExit(cons)]).then(() => { clearTimeout(killTimer); doneChildren(); rej(e); });
    };
    const ok = () => { if (settled) return; if (--left === 0) { settled = true; stopTimers(); doneChildren(); res(); } };
    if (timeoutMs) {
      timer = setTimeout(() => fail(new Error(`${prodCmd}|${consCmd} pipeline timed out after ${timeoutMs}ms`)), timeoutMs);
    }
    prod.stderr.on('data', (d) => (pErr += d));
    cons.stderr.on('data', (d) => (cErr += d));
    prod.on('error', fail);
    cons.on('error', fail);
    // If the consumer dies early, writing to its closed stdin emits EPIPE as an
    // async 'error' event — swallow it on the pipe ends so the real failure
    // surfaces via the close handler (a clean reject) instead of an uncaught crash
    // that would skip snapshot's finally-block and leave staged plaintext behind.
    prod.stdout.on('error', () => {});
    cons.stdin.on('error', () => {});
    prod.stdout.pipe(cons.stdin);
    prod.on('close', (c) => (c === 0 ? ok() : fail(new Error(`${prodCmd} exited ${c}: ${pErr.trim()}`))));
    cons.on('close', (c) => (c === 0 ? ok() : fail(new Error(`${consCmd} exited ${c}: ${cErr.trim()}`))));
  });
}

// Run a child with the parent's stdio so it can prompt on the TTY (age -p reads the
// passphrase interactively). Used only by keygen --passphrase, an interactive command.
export function runInteractive(cmd, args) {
  return new Promise((res, rej) => {
    const p = spawn(cmd, args, { stdio: 'inherit' });
    p.on('error', rej);
    p.on('close', (code) => (code === 0 ? res() : rej(new Error(`${cmd} exited ${code}`))));
  });
}
