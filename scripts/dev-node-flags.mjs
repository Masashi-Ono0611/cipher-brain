// Shared dev-mode Node flags for running bin/cipher-brain.mjs straight against
// src/*.ts (no build step) under plain node — see scripts/dev-ts-resolve-hook.mjs
// for why both flags are required (#63).
//
// DEV_ARGS is a plain argv array — prepend it to a spawnSync('node', [...]) argv
// list immediately before BIN, e.g. spawnSync('node', [...DEV_ARGS, BIN, ...args]).
//
// NEVER pass these via a spawnSync `env.NODE_OPTIONS` string instead: env vars are
// always plain strings, so building "--experimental-strip-types --import <path>"
// that way is whitespace-split by node, breaking under a checkout directory with a
// space in it. Argv arrays passed to spawnSync go straight to execve and are never
// whitespace-split, so a space in the path is harmless here — the same reason
// scripts/dev-shim-reexec.mjs (the shim these dev flags feed into) uses argv, not
// NODE_OPTIONS.
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));

export const DEV_ARGS = ['--experimental-strip-types', '--import', join(HERE, 'dev-cli-loader.mjs')];
