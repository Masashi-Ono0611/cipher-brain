#!/usr/bin/env node
// Thin shim so `npm link` / the bash selftests / a bare source checkout run the CLI
// straight from the repo with no build step. The real CLI (arg parsing + command
// dispatch) lives in src/cli.ts; the bundled single-file build lands at dist/cli.mjs
// (`npm run build`) and never touches this file.
//
// src/cli.ts's internal imports use the OUTPUT extension (`./lib/config.js`, matching
// the eventual dist/tsc convention — #63), which plain node's module resolution does
// NOT remap to the sibling `.ts` file on its own — scripts/dev-ts-resolve-hook.mjs
// fixes that, but a resolve hook must be `register()`ed before the failing import
// happens, and (on Node < 22.18/23.6, where TS type-stripping isn't on by default yet)
// --experimental-strip-types must be a startup flag, not something turned on from
// inside an already-running plain-.mjs process. Internal callers (npm scripts,
// selftest*.sh, cli-smoke.sh) preload both via
// NODE_OPTIONS="--experimental-strip-types --import scripts/dev-cli-loader.mjs" set on
// the shell before invoking `node`.
//
// A bare `node bin/cipher-brain.mjs` (what README.md documents) has neither, so this
// shim tries the plain import first and, ONLY if that fails with the tell-tale
// resolution error, self-re-execs as a child `node` process with the NODE_OPTIONS
// above — forwarding argv/stdio/exit code — so the documented zero-setup command
// keeps working with no manual env-var dance. This costs one extra process spawn on
// that fallback path only; it never fires for the compiled/shipped `dist/cli.mjs`,
// nor for callers that already export the right NODE_OPTIONS (the import just
// succeeds on the first try).
try {
  await import('../src/cli.js');
} catch (err) {
  const alreadyReexeced = process.env.CIPHER_BRAIN_DEV_SHIM_REEXEC === '1';
  if (alreadyReexeced || !(err && err.code === 'ERR_MODULE_NOT_FOUND')) {
    throw err;
  }
  const { spawnSync } = await import('node:child_process');
  const { fileURLToPath } = await import('node:url');
  const path = await import('node:path');

  const thisFile = fileURLToPath(import.meta.url);
  const loader = path.join(path.dirname(thisFile), '..', 'scripts', 'dev-cli-loader.mjs');
  const devNodeOptions = ['--experimental-strip-types', `--import ${loader}`, process.env.NODE_OPTIONS]
    .filter(Boolean)
    .join(' ');

  const result = spawnSync(process.execPath, [thisFile, ...process.argv.slice(2)], {
    stdio: 'inherit',
    env: { ...process.env, NODE_OPTIONS: devNodeOptions, CIPHER_BRAIN_DEV_SHIM_REEXEC: '1' },
  });
  if (result.error) throw result.error;
  process.exit(result.status === null ? 1 : result.status);
}
