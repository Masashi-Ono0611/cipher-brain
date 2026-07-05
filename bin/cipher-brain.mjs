#!/usr/bin/env node
// Thin shim so `npm link` / the bash selftests run straight from the repo with no
// build step. The real CLI (arg parsing + command dispatch) lives in src/cli.ts;
// the bundled single-file build lands at dist/cli.mjs (`npm run build`).
//
// src/cli.ts's internal imports use the OUTPUT extension (`./lib/config.js`,
// matching the eventual dist/tsc convention — #63), which plain node's built-in
// TypeScript support (type-stripping) does NOT remap back to the sibling `.ts`
// file on its own. Every caller of this shim (npm scripts, selftest*.sh,
// cli-smoke.sh) sets NODE_OPTIONS="--experimental-strip-types --import
// scripts/dev-cli-loader.mjs" so plain `node bin/cipher-brain.mjs` resolves it —
// see scripts/dev-ts-resolve-hook.mjs for why. Running this file directly
// without that NODE_OPTIONS (e.g. a bare `./bin/cipher-brain.mjs`) will fail to
// resolve src/lib/*.js; `npm run build && node dist/cli.mjs` always works with
// no extra setup.
import '../src/cli.js';
