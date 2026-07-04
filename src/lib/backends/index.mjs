// ---------- storage backends ----------
// A StorageBackend is { put(file) -> locator, get(locator, outFile) }. Storage
// only ever sees the *.age ciphertext. The locator is whatever the backend
// assigns: a content hash for file/ton (known before upload), or a tx id for
// arweave (assigned AFTER upload) — the interface assumes neither.
import { fileBackend } from './file.mjs';
import { tonBackend } from './ton.mjs';
import { arweaveBackend } from './arweave.mjs';
import { turboBackend } from './turbo.mjs';

export async function backendFor(name) {
  if (name === 'file') return fileBackend();
  if (name === 'ton') return tonBackend();
  if (name === 'arweave') return arweaveBackend();
  if (name === 'turbo') return turboBackend();
  throw new Error(`unknown backend: ${name || '(none)'} — use --backend file|ton|arweave|turbo`);
}
