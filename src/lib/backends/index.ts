// ---------- storage backends ----------
// A StorageBackend is { put(file) -> locator, get(locator, outFile) }. Storage
// only ever sees the *.age ciphertext. The locator is whatever the backend
// assigns: a content hash for file (known before upload), or a tx id for
// arweave (assigned AFTER upload) — the interface assumes neither.
import { fileBackend } from './file.js';
import { arweaveBackend } from './arweave.js';
import { turboBackend } from './turbo.js';
import { rcloneBackend } from './rclone.js';
import type { StorageBackend } from '../types.js';

// The `init` wizard's interactive backend choices — NOT the complete/canonical list
// of every --backend `backendFor` below accepts (that list is `backendFor`'s own
// if-chain; a NEW caller needing the full set should read it from there, not assume
// this constant is exhaustive). Exported (mirrors profiles.ts's PROFILE_NAMES) so the
// wizard prompt reads its OFFERED choices from one place instead of hand-rolling a
// second copy that could drift.
//
// `rclone` (#204) is deliberately excluded from this wizard-choices list: unlike
// file/arweave/turbo it needs an extra --remote value the interactive wizard never
// collects, so offering it in that prompt would let an operator pick it, sail past
// the wizard's own paid-backend checks, and only then fail deep inside push() with a
// "--remote required" error (the exact bad-UX shape issue #161's wallet-presence
// check exists to avoid for arweave/turbo). It is still fully supported by
// `backendFor` below — and by the `push`/`pull`/`estimate` CLI commands — for direct
// CLI use; only the wizard's own prompt omits it.
export const BACKEND_NAMES = ['file', 'arweave', 'turbo'] as const;

export async function backendFor(name: string | undefined): Promise<StorageBackend> {
  if (name === 'file') return fileBackend();
  if (name === 'arweave') return arweaveBackend();
  if (name === 'turbo') return turboBackend();
  if (name === 'rclone') return rcloneBackend();
  throw new Error(`unknown backend: ${name || '(none)'} — use --backend file|arweave|turbo|rclone`);
}
