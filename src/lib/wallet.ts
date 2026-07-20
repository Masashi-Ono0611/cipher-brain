// wallet — generate/inspect the Arweave JWK signer CIPHER_BRAIN_AR_WALLET points at
// (issue #158). A JWK is the only credential the arweave/turbo backends need to spend
// (L1 AR or Turbo Credits) from an address; until this subcommand existed, getting one
// meant reaching for an external tool (arweave-js, a browser wallet, …) with no
// guarantee the result matched what CIPHER_BRAIN_AR_WALLET expects, and no bridge from
// "here is the JWK cipher-brain will use" to "here is the address to fund" —
// docs/arweave-upload-runbook.md funds via a DIFFERENT, browser-based wallet
// (app.ardrive.io) with nothing tying the two together.
//
// `create` reuses keys.ts's writeKeyFile — the same fail-closed, no-clobber-unless
// --force, exclusive-create-then-atomic-rename write the age identity already gets
// (#91/#122) — so the JWK gets identical hardening instead of a hand-rolled second
// write path. `address` (and `create`'s own derivation) is pure offline crypto (no
// network call), so both only ever need the `arweave` package installed, same as the
// arweave/turbo backends that consume the resulting file.
import { mkdir, readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { HOME, AR_WALLET } from './config.js';
import { writeKeyFile } from './keys.js';
import { exists, errMsg, warnIfLooseKeyPerms, SdkMissingError } from './util.js';
import type { CliOptions } from './types.js';

// Minimal shape actually used here — hand-rolled rather than statically importing the
// `arweave` package's own types, mirroring backends/arweave.ts's ArweaveClient: the SDK
// stays a LAZY, optional import (it is only a peerDependency) so a machine without it
// installed only fails at the call site that actually needs it, never at module load.
interface ArweaveWalletClient {
  wallets: {
    generate(): Promise<unknown>;
    jwkToAddress(jwk: unknown): Promise<string>;
  };
}

async function getArweave(): Promise<ArweaveWalletClient> {
  let ArweaveCtor: { init(opts: Record<string, unknown>): ArweaveWalletClient };
  try {
    ArweaveCtor = (await import('arweave')).default as unknown as typeof ArweaveCtor;
  } catch (e) {
    if (e && (e as NodeJS.ErrnoException).code === 'ERR_MODULE_NOT_FOUND')
      throw new SdkMissingError('wallet needs the `arweave` package — run: npm install arweave');
    throw e;
  }
  // No host/port/protocol needed: wallets.generate()/jwkToAddress() are local RSA
  // keypair generation + a hash of the public modulus — neither ever calls the network.
  return ArweaveCtor.init({});
}

async function walletCreate(o: CliOptions): Promise<void> {
  const outPath = o.out || join(HOME, 'wallet.json');
  // No-clobber by default (same posture as keygen's --force precedent), checked BEFORE
  // the JWK is generated so a refusal never even spends the RSA keygen work.
  if ((await exists(outPath)) && !o.force) {
    throw new Error(
      `wallet already exists at ${outPath} (refusing to overwrite — losing it = losing spend authority over any AR/Turbo Credits already sent to its address). Pass --force only if you are certain.`,
    );
  }
  const ar = await getArweave();
  const jwk = await ar.wallets.generate();
  const address = await ar.wallets.jwkToAddress(jwk);
  await mkdir(dirname(outPath), { recursive: true, mode: 0o700 });
  await writeKeyFile(outPath, JSON.stringify(jwk), 0o600, !!o.force);
  console.log(`wallet (PRIVATE, keep offline): ${outPath}`);
  console.log(`address (PUBLIC, safe to share — fund THIS address): ${address}`);
  console.log(
    `\n⚠  Back up the wallet file now. Fund the address above (app.ardrive.io / turbo.ar.io — crypto or a card), then set CIPHER_BRAIN_AR_WALLET=${outPath}.`,
  );
}

async function walletAddress(o: CliOptions): Promise<void> {
  const walletPath = o.wallet || AR_WALLET;
  if (!walletPath) throw new Error('wallet address needs --wallet <path> or CIPHER_BRAIN_AR_WALLET');
  await warnIfLooseKeyPerms(walletPath, 'arweave JWK wallet');
  let jwk: unknown;
  try {
    jwk = JSON.parse(await readFile(walletPath, 'utf8'));
  } catch (e) {
    throw new Error(`wallet address: cannot read JWK wallet at ${walletPath}: ${errMsg(e)}`);
  }
  const ar = await getArweave();
  console.log(await ar.wallets.jwkToAddress(jwk));
}

export async function wallet(o: CliOptions): Promise<void> {
  switch (o._) {
    case 'create':
      return walletCreate(o);
    case 'address':
      return walletAddress(o);
    default:
      throw new Error(`wallet: expected create | address, got: ${o._ || '(nothing)'}`);
  }
}
