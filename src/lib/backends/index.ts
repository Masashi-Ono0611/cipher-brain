// ---------- storage backends ----------
// A StorageBackend is { put(file) -> locator, get(locator, outFile) }. Storage
// only ever sees the *.age ciphertext. The locator is whatever the backend
// assigns: a content hash for file/ton (known before upload), or a tx id for
// arweave (assigned AFTER upload) — the interface assumes neither.
import { fileBackend } from './file.js';
import { tonBackend } from './ton.js';
import { arweaveBackend } from './arweave.js';
import { turboBackend } from './turbo.js';
import type { StorageBackend } from '../types.js';

export async function backendFor(name: string | undefined): Promise<StorageBackend> {
  if (name === 'file') return fileBackend();
  if (name === 'ton') return tonBackend();
  if (name === 'arweave') return arweaveBackend();
  if (name === 'turbo') return turboBackend();
  throw new Error(`unknown backend: ${name || '(none)'} — use --backend file|ton|arweave|turbo`);
}
