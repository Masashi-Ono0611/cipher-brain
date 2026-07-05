#!/usr/bin/env node
// Thin shim so the MCP server runs straight from the repo with no build step (same
// pattern as bin/cipher-brain.mjs). The server lives in src/mcp.ts; the bundled
// single-file build lands at dist/mcp.mjs (`npm run build`). See bin/cipher-brain.mjs
// for why a bare `node bin/cipher-brain-mcp.mjs` needs (and, via the self-re-exec
// below, transparently gets) --experimental-strip-types plus the dev resolve-hook
// import to resolve src/mcp.ts's internal `.js`-specifier imports under plain node.
//
// The re-exec itself (argv-safe flag passing, signal forwarding so a client killing
// this wrapper's PID doesn't orphan the child) lives in scripts/dev-shim-reexec.mjs —
// shared with bin/cipher-brain.mjs so the fix only needs to exist in one place.
try {
  await import('../src/mcp.js');
} catch (err) {
  const alreadyReexeced = process.env.CIPHER_BRAIN_DEV_SHIM_REEXEC === '1';
  if (alreadyReexeced || !(err && err.code === 'ERR_MODULE_NOT_FOUND')) {
    throw err;
  }
  const { reexecUnderDevLoader } = await import('../scripts/dev-shim-reexec.mjs');
  await reexecUnderDevLoader(import.meta.url, process.argv.slice(2));
}
