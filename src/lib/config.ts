// config — env-driven paths, binaries and tunables shared by every module.
import { homedir } from 'node:os';
import { join } from 'node:path';

export const HOME = process.env.CIPHER_BRAIN_HOME || join(homedir(), '.cipher-brain');
// #64: age runs in-process (typage, bundled) — the external-binary overrides are obsolete.
for (const v of ['CIPHER_BRAIN_AGE', 'CIPHER_BRAIN_AGE_KEYGEN']) {
  if (process.env[v]) console.error(`cipher-brain: ${v} is deprecated and ignored — age is bundled in-process (typage); no external age binary is used`);
}
export const PG_BIN = process.env.CIPHER_BRAIN_PG_BIN || ''; // dir holding pg_dump/pg_restore; '' => PATH
export const pgTool = (name: string): string => (PG_BIN ? join(PG_BIN, name) : name);

export const IDENTITY = join(HOME, 'identity.age');     // private key — required to restore
export const RECIPIENT = join(HOME, 'recipient.txt');   // public key — all snapshot needs

export const AGE_MAGIC = 'age-encryption.org/v1';

// Optional recipient allowlist. When set, snapshot refuses to encrypt unless EVERY
// effective recipient is on this list — so a tampered recipient.txt / an injected
// extra --recipient (which would silently re-key future snapshots to an attacker)
// is caught at the input, before any ciphertext is produced. Inline (space/comma/
// newline-separated age1… keys) OR a path to a file of them.
export const PIN_RECIPIENTS = process.env.CIPHER_BRAIN_PIN_RECIPIENTS || '';
export const AGE_PUBKEY_RE = /age1[0-9a-z]{50,63}/g; // an age X25519 recipient (age1 + bech32); bounded so two unseparated keys can't fuse

// ---------- storage backend config (pluggable: storage only ever sees ciphertext) ----------
export const FILE_DIR = process.env.CIPHER_BRAIN_FILE_DIR || join(HOME, 'store'); // file backend object store
export const AR_HOST = process.env.CIPHER_BRAIN_AR_HOST || 'arweave.net';
export const AR_PORT = Number(process.env.CIPHER_BRAIN_AR_PORT || 443);
export const AR_PROTOCOL = process.env.CIPHER_BRAIN_AR_PROTOCOL || 'https';
export const AR_WALLET = process.env.CIPHER_BRAIN_AR_WALLET || ''; // path to a JWK key file
export const AR_PAID_BY = process.env.CIPHER_BRAIN_AR_PAID_BY || ''; // optional (turbo): an address that shared (delegated) Turbo Credits to the signer — passed as `paidBy` so the upload draws from that approval before the signer's own balance (the path for credits bought on a wallet we can't sign with, e.g. MetaMask, then shared to this JWK)
export const AR_DEFAULT_EXTRA_GATEWAYS = ['https://permagate.io']; // public mirror(s) tried after the primary (override the whole list with CIPHER_BRAIN_AR_GATEWAYS)
export const AR_HTTP_TIMEOUT_MS = Number(process.env.CIPHER_BRAIN_AR_HTTP_TIMEOUT || 60000); // bound the gateway read so a stall falls through to the L1 chunk fallback
// Spend guard: arweave/turbo uploads are irreversible and cost real funds. Require an
// explicit opt-in so an unattended nightly loop doesn't silently accumulate charges.
//   CIPHER_BRAIN_YES=1  — set in the nightly runner (`schedule install` writes it for paid backends) to suppress the --yes prompt
//   CIPHER_BRAIN_MAX_SPEND — abort if the upload cost estimate (in the backend's native
//     unit: winston for arweave L1, winc for turbo) exceeds this value; 0/unset = no cap
//     (the --yes guard still fires). Prevents runaway spend without changing behaviour
//     when the upload is well under budget.
export const CIPHER_YES = !!process.env.CIPHER_BRAIN_YES;
export const AR_MAX_SPEND = process.env.CIPHER_BRAIN_MAX_SPEND ? BigInt(process.env.CIPHER_BRAIN_MAX_SPEND) : 0n;
// The raw `arweave` backend posts one inline L1 tx; gateways reject single-tx bodies
// past ~12 MiB. Guard at a conservative 10 MiB and redirect large uploads to `turbo`
// (which streams + ANS-104-bundles). Override for a deliberate large L1 post.
export const AR_L1_MAX_BYTES = Number(process.env.CIPHER_BRAIN_AR_L1_MAX || 10 * 1024 * 1024);
// Overall wall-clock cap for the tar|age / age|tar streaming pipelines and the pre-stage
// tar, so a wedged binary (or a FIFO/special file under --dir) can't hang the CLI forever.
// Generous default (1h) — a real ~850 MB brain streams in seconds, so this only ever trips
// on a genuine hang. Override with CIPHER_BRAIN_PIPE_TIMEOUT (ms) for very large brains.
export const PIPE_TIMEOUT_MS = Number(process.env.CIPHER_BRAIN_PIPE_TIMEOUT || 60 * 60 * 1000);
