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
import { mkdir, chmod, readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { HOME, AR_WALLET, AR_PAID_BY } from './config.js';
import { writeKeyFile } from './keys.js';
import {
  exists,
  errMsg,
  warnIfLooseKeyPerms,
  SdkMissingError,
  isWalletAddress,
  sameWalletAddress,
  sdkImportAdvice,
} from './util.js';
import { fetchBalance, type CreditApproval } from './balance.js';
import { warn } from './warn.js';
import { arUsdRate, turboUsdRate, usdApprox } from './estimate.js';
import { printJson } from './ui.js';
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
    const problem = sdkImportAdvice(e, 'arweave');
    // 'absent' keeps SdkMissingError (its semantics everywhere are "the OPTIONAL thing
    // is not installed"); 'broken' must NOT — an installed-but-unusable package is a
    // real failure, and dressing it as "missing" invites skip-it handling (Codex
    // review, Critical on the arweave chunk-fallback path).
    if (problem?.kind === 'absent') throw new SdkMissingError(`wallet: ${problem.advice}`);
    if (problem !== null) throw new Error(`wallet: ${problem.advice}`);
    throw e;
  }
  // No host/port/protocol needed: wallets.generate()/jwkToAddress() are local RSA
  // keypair generation + a hash of the public modulus — neither ever calls the network.
  return ArweaveCtor.init({});
}

// The default path `wallet create` writes to when --out is omitted. Pulled out to a
// module-level constant (rather than inlined at each call site) so `walletAddress`'s
// fallback below reuses the exact same path `walletCreate` just wrote to (#164) instead
// of re-deriving it and risking the two drifting apart. Exported so `doctor` (#201) can
// check the SAME default path's permissions rather than re-deriving it a third time.
export const WALLET_DEFAULT_PATH = join(HOME, 'wallet.json');

async function walletCreate(o: CliOptions): Promise<void> {
  const usingDefaultPath = !o.out;
  const outPath = o.out || WALLET_DEFAULT_PATH;
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
  const dir = dirname(outPath);
  await mkdir(dir, { recursive: true, mode: 0o700 });
  // mkdir's `mode` is only applied when it actually CREATES the directory — a
  // pre-existing dir is left at whatever mode it already had. On the DEFAULT path
  // (HOME, the same directory keygenAt() owns for key material) fail closed the same
  // way keygenAt() does for #119: re-chmod even if it pre-existed with a looser mode.
  // A user-chosen --out directory is NOT assumed to be cipher-brain-owned (it could be
  // a shared dir holding unrelated files), so this re-chmod is scoped to the default
  // path only — --out still gets a freshly-created dir at 0700, just not a forced
  // re-chmod of a pre-existing one.
  if (usingDefaultPath) await chmod(dir, 0o700);
  await writeKeyFile(outPath, JSON.stringify(jwk), 0o600, !!o.force);
  console.log(`wallet (PRIVATE, keep offline): ${outPath}`);
  console.log(`address (PUBLIC, safe to share — fund THIS address): ${address}`);
  console.log(
    `\n⚠  Back up the wallet file now. Fund the address above (app.ardrive.io / turbo.ar.io — crypto or a card), then set CIPHER_BRAIN_AR_WALLET=${outPath}.`,
  );
}

// Shared "is there a usable wallet?" check — reused by wizard.ts's paid-backend
// pre-check (issue #161) so it can steer a user away from the "spends real funds"
// consent prompt BEFORE CIPHER_BRAIN_AR_WALLET is even set, rather than letting the
// wizard discover the same problem deep inside push() and roll everything back
// (issue #161's motivation). Mirrors exactly what backends/arweave.ts's/turbo.ts's own
// put() already require (set AND present on disk) — this does not read/parse the file
// (that stays at the real call sites: walletAddress above, the two backends' put()),
// it only answers the yes/no question those sites would otherwise fail deep inside.
export async function walletConfigured(walletPath: string = AR_WALLET): Promise<boolean> {
  return !!walletPath && (await exists(walletPath));
}

// Derive the address a JWK spends from. Shared by `address` and `balance` so the two
// can never disagree about WHICH wallet they are talking about — the exact confusion
// #164 fixed for the default-path fallback, now that a second subcommand asks the same
// question. `what` names the caller in the error, since "cannot read JWK wallet" is far
// more useful when it says which command wanted it.
async function addressFromWallet(o: CliOptions, what: string): Promise<string> {
  // Falls back to the same default `wallet create` writes to when neither --wallet nor
  // CIPHER_BRAIN_AR_WALLET is set, so `wallet create` (no --out) followed by `wallet
  // address` (no --wallet) just works (#164) instead of erroring out. If nothing exists
  // there, readFile below still fails closed with a clear "cannot read" error.
  const walletPath = o.wallet || AR_WALLET || WALLET_DEFAULT_PATH;
  await warnIfLooseKeyPerms(walletPath, 'arweave JWK wallet');
  let jwk: unknown;
  try {
    jwk = JSON.parse(await readFile(walletPath, 'utf8'));
  } catch (e) {
    throw new Error(`${what}: cannot read JWK wallet at ${walletPath}: ${errMsg(e)}`);
  }
  const ar = await getArweave();
  return ar.wallets.jwkToAddress(jwk);
}

async function walletAddress(o: CliOptions): Promise<void> {
  console.log(await addressFromWallet(o, 'wallet address'));
}

// "expires 2026-08-11T14:05:07Z (in 6 days)" — the relative part is the one that
// actually answers "do I need to redo this before my next push?", which an ISO timestamp
// alone does not at a glance.
function fmtExpiry(a: CreditApproval): string {
  if (a.expires_at === null) return 'no expiry';
  // Shown as UNKNOWN rather than quietly printed as if it were a date: this is the one
  // line telling the operator whether the approval will still be there at push time.
  if (!a.expiry_known) return `expiry UNKNOWN (unreadable: ${a.expires_at})`;
  if (a.expired) return `EXPIRED ${a.expires_at}`;
  const days = (Date.parse(a.expires_at) - Date.now()) / 86_400_000;
  const rel = days >= 1 ? `in ${Math.floor(days)} day(s)` : `in under a day`;
  return `expires ${a.expires_at} (${rel})`;
}

function printApprovals(list: CreditApproval[], heading: string, peerLabel: (a: CreditApproval) => string): void {
  if (list.length === 0) return;
  console.log(`\n${heading}`);
  for (const a of list) {
    console.log(`  ${peerLabel(a)}`);
    console.log(`    remaining ${a.remaining} winc (of ${a.approved} approved, ${a.used} used) — ${fmtExpiry(a)}`);
  }
}

async function walletBalance(o: CliOptions): Promise<void> {
  // --address queries any address WITHOUT a key — the payment service serves balances by
  // public address. That is the whole point for the funding flow: the wallet holding the
  // credits you just bought (a browser/MetaMask wallet) is precisely the one whose JWK
  // this machine does not have, so requiring a signer would put the most important
  // address of the top-up out of reach. It also means this path needs neither the
  // `arweave` package nor a wallet file.
  const address = o.address ?? (await addressFromWallet(o, 'wallet balance'));
  // Validated HERE, before any network call, even though fetchBalance re-checks: input we
  // are about to reject should not first send a request anywhere (Codex review). The
  // check inside fetchBalance stays — it guards the function itself, not just this path.
  if (!isWalletAddress(address))
    throw new Error(`wallet balance: not a wallet address (Arweave/Ethereum/Solana): ${JSON.stringify(address)}`);
  // Fetched once and passed in, rather than let fetchBalance reach for it, so the JSON
  // and human paths price the same numbers off the same rate. Null (rate unavailable)
  // degrades to omitting USD, never to failing the balance — same posture as the cost
  // estimate's USD line (#170). Turbo's credit rate, not AR spot (#343): these ARE turbo
  // credits, and their honest USD value is what replacing them with fiat costs; AR spot
  // is only the fallback when the price sheet is down.
  // Provenance is kept, not just the number (Codex review): a USD figure that might be
  // the credit price or might be the visibly-lower AR spot must say which it is, or the
  // fallback silently changes the meaning of the line.
  const credit = await turboUsdRate();
  const spot = credit === null ? await arUsdRate() : null;
  const pricing =
    credit !== null
      ? { rate: credit.ratePer1e12Winc, source: 'turbo-credit' as const }
      : spot !== null
        ? { rate: spot, source: 'ar-spot' as const }
        : null;
  const rateLabel = credit !== null ? 'Turbo credit rate' : 'AR spot — credit price sheet unavailable';
  const bal = await fetchBalance(address, pricing);
  if (o.json) return printJson(bal);

  const ar = (w: string) => `${w} winc (~${(Number(w) / 1e12).toFixed(8)} AR)`;
  console.log(`address           : ${bal.address}`);
  console.log(`own balance       : ${ar(bal.own)}`);
  console.log(
    `spendable balance : ${ar(bal.effective)}${pricing !== null ? ` = ${usdApprox(BigInt(bal.effective), pricing.rate)} (${rateLabel})` : ''}`,
  );
  printApprovals(
    bal.received_approvals,
    'received credit share approvals (this address can spend these):',
    (a) => `from ${a.payer}`,
  );
  printApprovals(
    bal.given_approvals,
    'given credit share approvals (delegated away to others):',
    (a) => `to ${a.recipient}`,
  );
  // The gap #341 is about: an approval is only reachable at push time when
  // CIPHER_BRAIN_AR_PAID_BY names its payer, so a balance that LOOKS spendable here can
  // still fail an upload. Say so at the one moment the operator is looking at both.
  // "Usable" means a push could actually draw on it: a known, unexpired deadline AND winc
  // left. An exhausted or unevaluatable approval is the trap this whole command exists to
  // expose — pointing at one and saying "set PAID_BY to spend this" is exactly the false
  // green light #341 is about (Codex review). It also must not satisfy the PAID_BY-match
  // check below, or such an approval would silence the warning that names the problem.
  const usable = bal.received_approvals.filter((a) => a.expiry_known && !a.expired && BigInt(a.remaining) > 0n);
  if (usable.length > 0 && !AR_PAID_BY) {
    warn(
      `${usable.length} received approval(s) above are NOT reachable by a push yet: set ` +
        `CIPHER_BRAIN_AR_PAID_BY=<payer address> so the upload draws from one (see docs/arweave-upload-runbook.md).`,
    );
  } else if (AR_PAID_BY && !usable.some((a) => sameWalletAddress(a.payer, AR_PAID_BY))) {
    warn(
      `CIPHER_BRAIN_AR_PAID_BY=${AR_PAID_BY} matches no live approval to this address — ` +
        `a push using it will fall back to the own balance above.`,
    );
  }
}

export async function wallet(o: CliOptions): Promise<void> {
  switch (o._) {
    case 'create':
      return walletCreate(o);
    case 'address':
      return walletAddress(o);
    case 'balance':
      return walletBalance(o);
    default:
      throw new Error(`wallet: expected create | address | balance, got: ${o._ || '(nothing)'}`);
  }
}
