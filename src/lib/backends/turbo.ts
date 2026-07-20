// turbo backend: upload ciphertext to Arweave via a bundler (ar.io / ArDrive Turbo),
// payable with ETH/USDC — uploads <100KB are free, larger spend Turbo Credits funded to
// the signer's address (top up at app.ardrive.io with MetaMask, no key export). The data
// item is ANS-104 *bundled*, so reads reuse the arweave backend (multi-gateway, bundled-
// capable). @ardrive/turbo-sdk is heavy, so it is lazily imported ONLY when this backend
// is used (run `npm install @ardrive/turbo-sdk`).
import { stat, readFile } from 'node:fs/promises';
import { createReadStream } from 'node:fs';
import { resolve } from 'node:path';
import { AR_WALLET, AR_PAID_BY, AR_MAX_SPEND, AR_HTTP_TIMEOUT_MS } from '../config.js';
import { warnIfLooseKeyPerms, fmtBytes, errMsg } from '../util.js';
import { arweaveBackend } from './arweave.js';
import type { StorageBackend, PutOpts } from '../types.js';

// Current USD price of 1 AR via the Turbo pricing endpoint the SDK exposes (winc is
// pegged 1:1 to winston; 1 AR = 1e12 of either, so one rate converts both). Returns a
// positive number or null on ANY failure — SDK not installed, offline, odd response —
// and is raced against AR_HTTP_TIMEOUT_MS: the USD line is a courtesy estimate that
// must never block, fail, or stall a push (or an MCP estimate).
export async function arUsdRate(): Promise<number | null> {
  try {
    const { TurboFactory } = await import('@ardrive/turbo-sdk');
    const timeout = new Promise<null>((resolve) => {
      const t = setTimeout(() => resolve(null), AR_HTTP_TIMEOUT_MS);
      if (typeof t.unref === 'function') t.unref(); // don't keep the process alive for a lost race
    });
    const res = await Promise.race([TurboFactory.unauthenticated().getFiatToAR({ currency: 'usd' }), timeout]);
    const rate = Number(res?.rate);
    return Number.isFinite(rate) && rate > 0 ? rate : null;
  } catch {
    return null;
  }
}

// "~$X USD" for a native amount (winc or winston) at the given USD/AR rate.
// More decimals for sub-cent estimates so a tiny nightly push isn't shown as $0.00.
export const usdApprox = (nativeAmount: bigint | number, rate: number): string => {
  const usd = (Number(nativeAmount) / 1e12) * rate;
  return `~$${usd.toFixed(usd >= 0.01 ? 2 : 6)} USD`;
};

export function turboBackend(): StorageBackend {
  return {
    async put(file: string, _opts: PutOpts = {}): Promise<string> {
      // import + wallet load live HERE (not the constructor) so a turbo PULL needs
      // neither @ardrive/turbo-sdk nor a wallet — only an upload does.
      let TurboFactory: typeof import('@ardrive/turbo-sdk').TurboFactory;
      let ArweaveSigner: typeof import('@ardrive/turbo-sdk').ArweaveSigner;
      try { ({ TurboFactory, ArweaveSigner } = await import('@ardrive/turbo-sdk')); }
      catch (e) {
        if (e && (e as NodeJS.ErrnoException).code === 'ERR_MODULE_NOT_FOUND') throw new Error('turbo backend needs the `@ardrive/turbo-sdk` package — run: npm install @ardrive/turbo-sdk');
        throw e;
      }
      if (!AR_WALLET) throw new Error('turbo put needs CIPHER_BRAIN_AR_WALLET (a JWK signer; uploads <100KB are free, larger spend Turbo Credits funded to its address)');
      await warnIfLooseKeyPerms(AR_WALLET, 'turbo JWK wallet (spend-capable bearer key)');
      let jwk: unknown;
      try { jwk = JSON.parse(await readFile(AR_WALLET, 'utf8')); }
      catch (e) { throw new Error(`turbo: cannot read JWK wallet at ${AR_WALLET}: ${errMsg(e)}`); }
      const turbo = TurboFactory.authenticated({ signer: new ArweaveSigner(jwk) });
      const abs = resolve(file);
      const { size } = await stat(abs); // stream the file (don't buffer an ~850MB brain) and give Turbo its size
      // cost estimate + balance before committing to an irreversible spend.
      // Uploads <100KB are free (0 winc); larger ones draw from Turbo Credits.
      let uploadWinc: bigint | null = null;
      try {
        const [{ winc: uploadWincStr }] = await turbo.getUploadCosts({ bytes: [size] });
        uploadWinc = BigInt(uploadWincStr);
        process.stderr.write(`turbo: upload cost estimate: ${uploadWinc} winc (~${(Number(uploadWinc) / 1e12).toFixed(8)} AR, ${size} bytes)\n`);
        // Human-readable USD approximation next to the native estimate (#70). arUsdRate
        // never throws (null on any failure), so a dead pricing endpoint can neither
        // block the push nor skip the CIPHER_BRAIN_MAX_SPEND cap check below.
        const rate = await arUsdRate();
        if (rate !== null) {
          process.stderr.write(`turbo: approx cost: ${fmtBytes(size)} -> ${usdApprox(uploadWinc, rate)} (at ~$${rate.toFixed(2)}/AR; rate-dependent estimate, not a quote)\n`);
        }
        try {
          const { winc: balWincStr } = await turbo.getBalance();
          const balWinc = BigInt(balWincStr);
          process.stderr.write(`turbo: Turbo Credit balance: ${balWinc} winc (~${(Number(balWinc) / 1e12).toFixed(8)} AR)\n`);
        } catch { /* paidBy wallet has no personal balance on this signer — non-fatal */ }
      } catch (e) {
        // A cost-estimate failure (getUploadCosts reject, empty-array destructure, bad
        // BigInt conversion, ...) must NOT be treated as "proceed anyway" when a spend cap
        // is configured — that would fail-open an irreversible paid upload straight past
        // the cap the user set to protect their wallet (#105). Fail-closed here; only
        // fail-open (log + continue, pre-existing behavior) when no cap is in effect.
        if (AR_MAX_SPEND > 0n) {
          throw new Error(`turbo: could not estimate upload cost (${errMsg(e)}) while CIPHER_BRAIN_MAX_SPEND=${AR_MAX_SPEND} is set — aborting (fail-closed) because the spend cap cannot be verified; set CIPHER_BRAIN_MAX_SPEND=0 to disable the cap and upload uncapped`);
        }
        process.stderr.write(`turbo: could not estimate upload cost (${errMsg(e)}); proceeding\n`);
      }
      // The cap check lives OUTSIDE the estimate try/catch above so a failed estimate can
      // never suppress it (the original bug: both lived in the same try, so any exception
      // — not just the cap guard's own — fell into a catch-all "proceeding" log). uploadWinc
      // is null only when the cap is unset (fail-open path above already ran), so this is a
      // no-op in that case.
      if (AR_MAX_SPEND > 0n && uploadWinc !== null && uploadWinc > AR_MAX_SPEND) {
        throw new Error(`turbo: upload cost ${uploadWinc} winc exceeds CIPHER_BRAIN_MAX_SPEND=${AR_MAX_SPEND} — aborting to protect your wallet`);
      }
      // paidBy (x-paid-by header): when set, Turbo pays from a Credit Share Approval the
      // named address granted THIS signer, before the signer's own balance. It funds the
      // CLI path when credits were bought on a wallet we can't sign with (e.g. MetaMask)
      // and shared to this JWK. Not URL-interpolated (header only), but sanity-check the
      // shape (Arweave/Ethereum/Solana address) to reject header-breaking input.
      const dataItemOpts: { tags: { name: string; value: string }[]; paidBy?: string[] } = { tags: [{ name: 'App-Name', value: 'cipher-brain' }, { name: 'Content-Type', value: 'application/octet-stream' }] };
      if (AR_PAID_BY) {
        if (!/^[A-Za-z0-9_-]{30,64}$/.test(AR_PAID_BY)) throw new Error(`turbo: CIPHER_BRAIN_AR_PAID_BY must be a plain wallet address (Arweave/Ethereum/Solana): ${AR_PAID_BY}`);
        dataItemOpts.paidBy = [AR_PAID_BY];
      }
      const res = await turbo.uploadFile({
        fileStreamFactory: () => createReadStream(abs),
        fileSizeFactory: () => size,
        dataItemOpts,
      });
      if (!res || !res.id) throw new Error(`turbo upload returned no data item id: ${JSON.stringify(res).slice(0, 200)}`);
      return res.id; // 43-char data item id — retrievable like any bundled item
    },
    // reads are identical to the arweave backend (Turbo items are bundled). Pure
    // delegation, so a turbo PULL needs neither @ardrive/turbo-sdk nor a wallet —
    // the "a fresh machine needs only the tx id" recovery property holds.
    get(locator: string, out: string): Promise<void> {
      return arweaveBackend().then((b) => b.get(locator, out));
    },
  };
}
