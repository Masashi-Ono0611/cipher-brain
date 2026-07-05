#!/usr/bin/env node
// Thin shim so the MCP server runs straight from the repo with no build step (same
// pattern as bin/cipher-brain.mjs). The server lives in src/mcp.ts; the bundled
// single-file build lands at dist/mcp.mjs (`npm run build`). See bin/cipher-brain.mjs
// for why a bare `node bin/cipher-brain-mcp.mjs` needs (and, via the self-re-exec
// below, transparently gets) --experimental-strip-types plus the dev resolve-hook
// import to resolve src/mcp.ts's internal `.js`-specifier imports under plain node.
try {
  await import('../src/mcp.js');
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
