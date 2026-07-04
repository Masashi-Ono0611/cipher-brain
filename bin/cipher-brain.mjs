#!/usr/bin/env node
// Thin shim so `npm link` / the bash selftests run straight from the repo with no
// build step. The real CLI (arg parsing + command dispatch) lives in src/cli.mjs;
// the bundled single-file build lands at dist/cli.mjs (`npm run build`).
import '../src/cli.mjs';
