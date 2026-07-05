// Node module-customization resolve hook (loaded via scripts/dev-cli-loader.mjs, which
// registers this file with node:module's register()). Purpose: let the bash selftests
// run the CLI/MCP straight from src/*.ts with plain `node` (no build step) — #63
// converted src/**/*.mjs to TypeScript, and every internal import now uses the OUTPUT
// extension (e.g. `./lib/config.js`, matching the eventual dist/tsc convention, NOT the
// source's own .ts extension). Node's built-in type-stripping (--experimental-strip-types,
// see scripts/dev-cli-loader.mjs) happily loads a .ts file, but its module resolution does
// NOT remap a `.js` specifier to a sibling `.ts` file the way tsc's NodeNext resolution
// (and Bun's runtime resolver) do — so without this hook, `node bin/cipher-brain.mjs`
// fails immediately on the first internal import.
//
// Deliberately plain `node`, not `bun`: bun's own resolver already handles the `.js`->`.ts`
// remap, but its WHATWG stream / pipeline error propagation differs from Node's in at
// least one case this codebase's selftest exercises (a truncated age artifact's decrypt
// failure surfacing through a piped TransformStream) — the shipped CLI runs under plain
// Node in production (dist/cli.mjs), so the dev/selftest shim must match that runtime
// to test the real behavior, not a Bun-specific one.
export async function resolve(specifier, context, nextResolve) {
  try {
    return await nextResolve(specifier, context);
  } catch (err) {
    if (specifier.endsWith('.js') && err && err.code === 'ERR_MODULE_NOT_FOUND') {
      return nextResolve(`${specifier.slice(0, -3)}.ts`, context);
    }
    throw err;
  }
}
