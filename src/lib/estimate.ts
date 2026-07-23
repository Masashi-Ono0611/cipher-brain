// Cost-estimation math, shared by every surface that needs it: the CLI `estimate`
// command below, the MCP `estimate_cost` tool (src/mcp.ts), and the paid backends'
// own pre-flight cost estimate (src/lib/backends/{arweave,turbo}.ts, via arUsdRate/
// usdApprox) — one home so this math is never re-implemented per surface (#159).
import { stat } from 'node:fs/promises';
import { AR_HOST, AR_PORT, AR_PROTOCOL, AR_HTTP_TIMEOUT_MS, AR_USD_RATE_URL } from './config.js';
import { exists, errMsg, fmtBytes } from './util.js';
import type { CliOptions } from './types.js';

export interface CostEstimate {
  backend: string;
  size_bytes: number;
  cost: string | null; // native units (winc/winston), "0" for file, or null when unavailable
  unit?: 'winc' | 'winston';
  approx_ar?: number;
  usd_estimate?: number;
  note: string;
}

// Current USD price of 1 AR via a plain, unauthenticated GET against Turbo's public
// rate endpoint (AR_USD_RATE_URL — no @ardrive/turbo-sdk involved, #170: that SDK is an
// optional peerDependency most installs don't have, and this is just one public JSON
// endpoint under it). winc is pegged 1:1 to winston; 1 AR = 1e12 of either, so one rate
// converts both. Returns a positive number or null on ANY failure — non-200, malformed
// JSON, non-finite/non-positive rate, network error, timeout — and is raced against
// AR_HTTP_TIMEOUT_MS: the USD line is a courtesy estimate that must never block, fail,
// or stall a push (or an estimate).
export async function arUsdRate(): Promise<number | null> {
  try {
    const ctl = AbortSignal.timeout(AR_HTTP_TIMEOUT_MS);
    const res = await fetch(AR_USD_RATE_URL, { signal: ctl });
    if (!res.ok) return null;
    const body: unknown = await res.json();
    const rate = Number((body as { rate?: unknown } | null)?.rate);
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

// Estimate what pushing `sizeBytes` to `backend` would cost, WITHOUT uploading
// anything (price queries only). `backend` must be one of file|arweave|turbo|rclone —
// any other value is a caller bug (mcp.ts validates via requireBackend before calling
// this; the CLI estimate() below validates too), so it is rejected explicitly
// rather than silently falling through to the arweave branch.
export async function estimateCost(backend: string, sizeBytes: number): Promise<CostEstimate> {
  if (backend === 'file') {
    return {
      backend,
      size_bytes: sizeBytes,
      cost: '0',
      note: 'file backend is a local content-addressed store — no upload cost (disk space only).',
    };
  }

  if (backend === 'rclone') {
    return {
      backend,
      size_bytes: sizeBytes,
      cost: '0',
      note:
        'rclone backend delegates the transfer to the rclone binary and the configured remote (#204) — ' +
        'cipher-brain has no visibility into that remote pricing, so unlike arweave/turbo this is not a ' +
        'real cost query. Any transfer/storage cost is whatever the cloud contract for that remote charges.',
    };
  }

  if (backend === 'turbo') {
    let TurboFactory: typeof import('@ardrive/turbo-sdk').TurboFactory;
    try {
      ({ TurboFactory } = await import('@ardrive/turbo-sdk'));
    } catch (e) {
      if (e && (e as NodeJS.ErrnoException).code === 'ERR_MODULE_NOT_FOUND') {
        return {
          backend,
          size_bytes: sizeBytes,
          cost: null,
          note: 'estimate unavailable (optional dependency not installed) — run: npm install @ardrive/turbo-sdk. Uploads <100KB are free; larger ones spend Turbo Credits.',
        };
      }
      throw e;
    }
    try {
      const turbo = TurboFactory.unauthenticated();
      // Bounded the same way arUsdRate() below bounds its own Turbo SDK call: the SDK
      // exposes no timeout/AbortSignal option on getUploadCosts(), so an unresponsive
      // Turbo pricing endpoint would otherwise hang this call indefinitely — and, since
      // push() now calls estimateCost() BEFORE its --yes consent gate (#160), that hang
      // would block a `push` before the operator ever gets to answer --yes, not just a
      // read-only `estimate` invocation. A race against AR_HTTP_TIMEOUT_MS doesn't cancel
      // the underlying request (the SDK gives no cancellation hook either), only bounds
      // how long THIS call waits for it — the same trade-off arUsdRate() already makes.
      const timeout = new Promise<null>((resolve) => {
        const t = setTimeout(() => resolve(null), AR_HTTP_TIMEOUT_MS);
        if (typeof t.unref === 'function') t.unref();
      });
      const res = await Promise.race([turbo.getUploadCosts({ bytes: [sizeBytes] }), timeout]);
      if (res === null) {
        return {
          backend,
          size_bytes: sizeBytes,
          cost: null,
          note: `estimate unavailable (Turbo pricing query timed out after ${AR_HTTP_TIMEOUT_MS}ms)`,
        };
      }
      const [{ winc }] = res;
      // usd_estimate is OPTIONAL: arUsdRate returns null on any rate-fetch failure,
      // and a missing rate must never fail the (still useful) native estimate.
      const rate = await arUsdRate();
      return {
        backend,
        size_bytes: sizeBytes,
        cost: String(winc),
        unit: 'winc',
        approx_ar: Number(BigInt(winc)) / 1e12,
        ...(rate !== null ? { usd_estimate: Number(((Number(BigInt(winc)) / 1e12) * rate).toFixed(6)) } : {}),
        note: 'Turbo upload cost estimate (uploads <100KB are free). Paid with Turbo Credits (fundable via ETH/USDC/fiat).',
      };
    } catch (e) {
      return {
        backend,
        size_bytes: sizeBytes,
        cost: null,
        note: `estimate unavailable (Turbo pricing query failed: ${errMsg(e)})`,
      };
    }
  }

  if (backend === 'arweave') {
    // the raw L1 backend: the gateway /price endpoint returns the network reward in
    // winston for a payload of this size — the same price createTransaction would
    // fetch at push time (src/lib/backends/arweave.ts's put()).
    try {
      const ctl = AbortSignal.timeout(AR_HTTP_TIMEOUT_MS);
      const res = await fetch(`${AR_PROTOCOL}://${AR_HOST}:${AR_PORT}/price/${sizeBytes}`, { signal: ctl });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const winston = (await res.text()).trim();
      if (!/^\d+$/.test(winston)) throw new Error(`unexpected price response: ${winston.slice(0, 80)}`);
      // Same optional usd_estimate as the turbo branch (winston and winc are both
      // 1e12-per-AR, so one USD/AR rate converts either); null rate → field omitted.
      const rate = await arUsdRate();
      return {
        backend,
        size_bytes: sizeBytes,
        cost: winston,
        unit: 'winston',
        approx_ar: Number(BigInt(winston)) / 1e12,
        ...(rate !== null ? { usd_estimate: Number(((Number(BigInt(winston)) / 1e12) * rate).toFixed(6)) } : {}),
        note: 'Arweave L1 network price (the reward createTransaction would set at push time). Paid in AR from the JWK wallet.',
      };
    } catch (e) {
      return {
        backend,
        size_bytes: sizeBytes,
        cost: null,
        note: `estimate unavailable (gateway price query failed: ${errMsg(e)})`,
      };
    }
  }

  throw new Error(`unknown backend: ${backend} — use file|arweave|turbo|rclone`);
}

// Render a CostEstimate as human-readable lines — SHARED by the CLI `estimate` command
// below (its whole stdout output) and push()'s pre-consent estimate display
// (src/lib/pushpull.ts, on stderr — push's stdout is reserved for the final locator
// only — #160): one formatting so the number a `push --backend arweave` operator sees
// before confirming --yes is presented identically to `cipher-brain estimate`'s report,
// not a second, divergent rendering.
export function formatEstimate(e: CostEstimate): string[] {
  const lines = [`backend: ${e.backend}`, `size: ${e.size_bytes} bytes (${fmtBytes(e.size_bytes)})`];
  if (e.cost === null) {
    lines.push('cost: unavailable');
  } else {
    lines.push(`cost: ${e.cost}${e.unit ? ` ${e.unit}` : ''}`);
    if (e.approx_ar !== undefined) lines.push(`approx: ~${e.approx_ar.toFixed(8)} AR`);
    if (e.usd_estimate !== undefined) {
      lines.push(`approx: ~$${e.usd_estimate.toFixed(e.usd_estimate >= 0.01 ? 2 : 6)} USD`);
    }
  }
  lines.push(`note: ${e.note}`);
  return lines;
}

// CLI `estimate` command: size --in the same way push does (a real byte count off
// disk, not a guess) and print the SAME estimateCost() computation the MCP
// estimate_cost tool returns, as a human-readable report — WITHOUT uploading
// anything. `size_bytes` (the MCP tool's alternative to `file`) has no CLI
// equivalent — --in is always a real file on disk here.
export async function estimate(o: CliOptions): Promise<void> {
  if (!o.in) throw new Error('--in <file.age> required');
  if (!o.backend) throw new Error('--backend <file|arweave|turbo|rclone> required');
  if (!(await exists(o.in))) throw new Error(`no such file: ${o.in}`);
  const st = await stat(o.in);
  if (!st.isFile())
    throw new Error(`${o.in} is not a regular file (cannot size a directory/special file for an estimate)`);
  const result = await estimateCost(o.backend, st.size);
  for (const line of formatEstimate(result)) console.log(line);
}
