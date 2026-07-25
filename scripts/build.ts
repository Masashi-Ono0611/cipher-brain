// scripts/build.ts — bundle the CLI with Bun.
//
//   - entries: src/cli.ts → dist/cli.mjs and src/mcp.ts → dist/mcp.mjs (each a
//     self-contained file; the shipped artifacts a fresh machine can run with
//     plain `node dist/cli.mjs` / `node dist/mcp.mjs`). Bun.build strips the TS
//     types itself (no separate tsc emit step for the shipped dist/ — #63's
//     `tsc --noEmit` typecheck gate runs SEPARATELY, see package.json
//     "typecheck"); the `naming` override below still forces the OUTPUT
//     extension to .mjs regardless of the .ts source extension, so dist/,
//     the `bin` field and every existing selftest/smoke script are unchanged.
//   - format: ESM (the source is ESM, "type": "module"), target: node (engines
//     node>=22); the built CLI runs on plain Node, never Bun — consumers use
//     `npx` / `node`.
//   - a shebang banner is prepended so dist/cli.mjs is directly executable.
//
// The externals list is DERIVED from package.json (dependencies +
// peerDependencies) so it never drifts when a dep is added — minus the INLINE
// set, which is bundled INTO dist so the shipped artifacts stay self-contained:
//   - `age-encryption` (typage) IS the crypto layer — it must land inside
//     dist/cli.mjs so the shipped CLI runs with zero runtime deps (#64).
//   - `@modelcontextprotocol/sdk` is inlined so dist/mcp.mjs runs on a fresh
//     machine with no node_modules at all (#65).
//   - `ignore` (the .cipherbrainignore matcher, #216) is a small, dependency-free,
//     always-needed part of `snapshot`'s normal path (not a lazily-imported optional
//     backend like arweave/turbo below) — it must land inside dist/cli.mjs for the
//     same #64 reason age-encryption does, or the shipped CLI would need node_modules
//     just to run `snapshot` on a fresh machine (selftest-arweave-nodeps.mjs's
//     isolated-dir copy of dist/cli.mjs has none, and would fail to even start).
//   - the lazily-imported optional backends — `arweave` and `@ardrive/turbo-sdk`
//     — stay external: bundling them would break the documented "a gateway pull
//     needs no npm dependency" recovery property (and the selftest that proves it).

import { readFileSync, rmSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { extractSection, RUNBOOK_HEADING } from '../src/lib/runbook.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const dist = join(root, 'dist');

const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')) as {
  dependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
};

const INLINE = new Set(['age-encryption', '@modelcontextprotocol/sdk', 'ignore']);

const external = [...Object.keys(pkg.dependencies ?? {}), ...Object.keys(pkg.peerDependencies ?? {})].filter(
  (d) => !INLINE.has(d),
);

// #285: the MCP `restore-runbook` prompt serves MANAGEMENT.md's "## Restore runbook"
// section, but MANAGEMENT.md is NOT part of the published package (`files: ["dist"]`),
// so an installed server cannot read it. Inline it here instead of keeping a second
// copy in src/ — the same slicing helper the dev fallback uses, so the two paths cannot
// diverge (src/lib/runbook.ts). Failing loudly matters: a prompt that resolves to an
// empty string looks like a working feature while handing an agent no procedure.
const runbook = extractSection(readFileSync(join(root, 'MANAGEMENT.md'), 'utf8'), RUNBOOK_HEADING);
if (!runbook) {
  console.error(
    `build: no "${RUNBOOK_HEADING}" section found in MANAGEMENT.md — the MCP restore-runbook prompt would ship empty`,
  );
  process.exit(1);
}

rmSync(dist, { recursive: true, force: true });
const result = await Bun.build({
  entrypoints: [join(root, 'src/cli.ts'), join(root, 'src/mcp.ts')],
  outdir: dist,
  target: 'node',
  format: 'esm',
  external,
  naming: '[dir]/[name].mjs', // force the OUTPUT extension to .mjs (Bun defaults .ts sources to .js too)
  banner: '#!/usr/bin/env node',
  define: { __CIPHER_BRAIN_RESTORE_RUNBOOK__: JSON.stringify(runbook) },
});
if (!result.success) {
  for (const message of result.logs) console.error(message);
  process.exit(1);
}
// stderr, not stdout: this also runs as `prepack`, and `npm pack --json`
// consumers parse stdout as JSON — a stdout status line would corrupt it.
console.error(`✓ bun build → dist/ (${result.outputs.length} files, ${external.length} externals)`);
