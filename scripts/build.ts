// scripts/build.ts — bundle the CLI with Bun (adapted from ton-mesh-harness).
//
//   - entry: src/cli.mjs → dist/cli.mjs (one self-contained file; the shipped
//     artifact a fresh machine can run with plain `node dist/cli.mjs`).
//   - format: ESM (the source is ESM .mjs), target: node (engines node>=22);
//     the built CLI runs on plain Node, never Bun — consumers use `npx` / `node`.
//   - a shebang banner is prepended so dist/cli.mjs is directly executable.
//
// The externals list is DERIVED from package.json (dependencies +
// peerDependencies) so it never drifts when a dep is added. In particular the
// lazily-imported optional backends — `arweave` and `@ardrive/turbo-sdk` — stay
// external: bundling them would break the documented "a gateway pull needs no
// npm dependency" recovery property (and the selftest that proves it).
//
// INLINE is the deliberate exception (same pattern ton-mesh-harness uses for
// @ton/walletkit): `age-encryption` (typage) IS the crypto layer — it must land
// inside dist/cli.mjs so the shipped CLI runs with zero runtime deps (#64).

import { readFileSync, rmSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const dist = join(root, 'dist')

const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')) as {
  dependencies?: Record<string, string>
  peerDependencies?: Record<string, string>
}

const INLINE = new Set(['age-encryption'])

const external = [
  ...Object.keys(pkg.dependencies ?? {}),
  ...Object.keys(pkg.peerDependencies ?? {}),
].filter((d) => !INLINE.has(d))

rmSync(dist, { recursive: true, force: true })
const result = await Bun.build({
  entrypoints: [join(root, 'src/cli.mjs')],
  outdir: dist,
  target: 'node',
  format: 'esm',
  external,
  naming: '[dir]/[name].mjs', // keep the source's .mjs extension (Bun defaults to .js)
  banner: '#!/usr/bin/env node',
})
if (!result.success) {
  for (const message of result.logs) console.error(message)
  process.exit(1)
}
console.log(`✓ bun build → dist/ (${result.outputs.length} files, ${external.length} externals)`)
