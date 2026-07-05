// Shared re-exec helper for bin/cipher-brain.mjs and bin/cipher-brain-mcp.mjs. Both
// shims try a plain `import` of their real entrypoint first and only fall back to this
// when that import fails with the tell-tale ERR_MODULE_NOT_FOUND (see those files for
// the full "why" — running straight from src/*.ts with no build step).
//
// Round-2 Codex review found two bugs in the original inline version of this fallback
// (both files used to build a NODE_OPTIONS string and call child_process.spawnSync):
//
//  1. Space-in-path corruption. NODE_OPTIONS is parsed by splitting on whitespace, so
//     interpolating an absolute filesystem path straight into a NODE_OPTIONS string
//     (`--import ${loader}`) breaks if the repo checkout lives under a directory
//     containing a space (e.g. "My Projects/cipher-brain") — the path silently splits
//     into two bogus tokens and the loader fails to register. Fix: never put the loader
//     path into a NODE_OPTIONS string. Pass `--experimental-strip-types` and `--import
//     <loader>` as literal argv elements to the child `node` invocation instead — argv
//     arrays given to spawn/spawnSync go straight to execve and are never shell- or
//     whitespace-split, unlike an env-var string, so a space in the path is harmless.
//  2. Orphaned child on signal. spawnSync blocks the parent synchronously and does not
//     forward signals sent to the parent's PID to the child. MCP/CLI clients manage the
//     server/process by signaling the PID they launched (this wrapper), not the child it
//     spawns, so a SIGTERM/SIGINT/SIGHUP to the wrapper left the child running and still
//     holding stdio after the client believed the process had stopped. Fix: use async
//     spawn, forward SIGINT/SIGTERM/SIGHUP from the wrapper to the child, and wait for
//     the child to actually exit before the wrapper exits (mirroring its signal/code).
export async function reexecUnderDevLoader(callerUrl, extraArgv) {
  const { spawn } = await import('node:child_process');
  const { fileURLToPath } = await import('node:url');
  const path = await import('node:path');

  const thisFile = fileURLToPath(callerUrl);
  // Co-located with dev-cli-loader.mjs, so resolve relative to THIS module's own URL
  // rather than the caller's — keeps the path correct regardless of which bin/*.mjs
  // shim is doing the re-exec.
  const loader = path.join(path.dirname(fileURLToPath(import.meta.url)), 'dev-cli-loader.mjs');

  const nodeArgv = ['--experimental-strip-types', '--import', loader, thisFile, ...extraArgv];

  const child = spawn(process.execPath, nodeArgv, {
    stdio: 'inherit',
    env: { ...process.env, CIPHER_BRAIN_DEV_SHIM_REEXEC: '1' },
  });

  const forwardedSignals = ['SIGINT', 'SIGTERM', 'SIGHUP'];
  const forwardSignal = (signal) => {
    // Guard against forwarding after the child has already exited (e.g. a second
    // signal arriving while we are already tearing down).
    if (child.exitCode === null && child.signalCode === null) {
      child.kill(signal);
    }
  };
  for (const signal of forwardedSignals) process.on(signal, forwardSignal);

  const [code, signal] = await new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('exit', (code, signal) => resolve([code, signal]));
  });

  for (const signal of forwardedSignals) process.removeListener(signal, forwardSignal);

  if (signal) {
    // Mirror the child's signal-based termination on the wrapper itself so a process
    // manager watching THIS pid observes the same signal rather than a plain exit(0/1).
    // Set a POSIX-convention exit code as a fallback in case the re-raised signal is,
    // for whatever reason, not delivered before the event loop would otherwise drain.
    process.exitCode = 128;
    process.kill(process.pid, signal);
    return;
  }
  process.exit(code === null ? 1 : code);
}
