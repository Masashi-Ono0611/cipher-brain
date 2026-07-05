// Bootstrap for running bin/cipher-brain{,-mcp}.mjs straight from src/*.ts with plain
// `node` — preloaded via NODE_OPTIONS="--experimental-strip-types --import
// <this file>" (set once, near the top, by every selftest*.sh / cli-smoke.sh /
// large-file-test.sh script — see scripts/dev-ts-resolve-hook.mjs for the why).
// --experimental-strip-types is passed alongside on the command line/NODE_OPTIONS
// (not set here) because it must be active before this file's own resolution runs.
import { register } from 'node:module';

register('./dev-ts-resolve-hook.mjs', import.meta.url);
