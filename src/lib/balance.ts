// balance.ts — read an address's Turbo Credit state from the payment service (#345).
//
// Motivation: a paid push draws from the SIGNER's own balance OR from a Credit Share
// Approval another wallet delegated to it (CIPHER_BRAIN_AR_PAID_BY — the flow
// docs/arweave-upload-runbook.md documents for credits bought on a browser wallet that
// cannot sign here). Until this module existed there was no way to ask "what can this
// address actually spend?" without hand-writing a @ardrive/turbo-sdk script, which is
// what funding a real push devolved into.
//
// No SDK: this is a plain unauthenticated GET keyed on a PUBLIC address, so it follows
// the #170 precedent set by arUsdRate() rather than pulling in an optional
// peerDependency — which matters twice over, since that dependency is exactly what #344
// found unusable inside a dependency-heavy checkout. Reading a balance is the one thing
// that must keep working when the push path's optional dep does not.
import { AR_BALANCE_URL, AR_HTTP_TIMEOUT_MS } from './config.js';
import { errMsg, isWalletAddress } from './util.js';

// One approval — either received (someone funds THIS address) or given (this address
// funds someone else). Native winc amounts stay strings for the same reason the rest of
// the cost surface keeps them strings (#268): they are 64-bit-ish integers that must not
// round-trip through a float on the way to a --json consumer.
export interface CreditApproval {
  payer: string;
  recipient: string;
  approved: string; // winc originally delegated
  used: string; // winc already spent against it
  remaining: string; // approved - used, floored at 0
  expires_at: string | null; // ISO-8601, or null for an approval that never expires
  expired: boolean; // expires_at is in the past AS OF THIS CALL
  // Whether the expiry could be determined at all. An approval that never expires is
  // KNOWN (expires_at null, expired false); one whose expirationDate is malformed or
  // unparseable is NOT — and `expired: false` alone would let that be read as "still
  // good" (Codex review). Callers gating advice on an approval must require this.
  expiry_known: boolean;
}

// Every field REQUIRED and nullable rather than optional, matching CostEstimate's shape
// contract (#268): a --json consumer gets one stable object, so `usd_estimate === null`
// reads as "no rate available" instead of looking like a bug in the caller.
export interface WalletBalance {
  address: string;
  own: string; // winc the address itself holds
  effective: string; // own + approvals it can draw on — what a push can actually spend
  unit: 'winc';
  approx_ar: number; // effective, in AR
  usd_estimate: number | null; // effective, in USD; null when the rate could not be fetched
  received_approvals: CreditApproval[];
  given_approvals: CreditApproval[];
}

// The payment service's wire shape. Hand-rolled (not imported from the SDK) for the same
// reason the fetch is: this module must not depend on that package being installed.
interface WireApproval {
  payingAddress?: unknown;
  approvedAddress?: unknown;
  approvedWincAmount?: unknown;
  usedWincAmount?: unknown;
  expirationDate?: unknown;
}
interface WireBalance {
  winc?: unknown;
  effectiveBalance?: unknown;
  receivedApprovals?: unknown;
  givenApprovals?: unknown;
}

// Parse a winc field. The service sends these as decimal strings; anything else (number,
// null, "12.5", "-1") is a shape we do not understand, and guessing at it in code that
// gates an irreversible spend is how a fail-open gets built. Reject loudly instead —
// same posture turbo.ts's put() takes on a malformed getUploadCosts winc.
function wincField(v: unknown, what: string): bigint {
  if (typeof v !== 'string' || !/^\d+$/.test(v))
    throw new Error(`balance: ${what} is not a non-negative integer string: ${JSON.stringify(v)}`);
  return BigInt(v);
}

function parseApproval(a: WireApproval): CreditApproval {
  const approved = wincField(a.approvedWincAmount, 'approvedWincAmount');
  const used = wincField(a.usedWincAmount, 'usedWincAmount');
  // Clamped rather than allowed to go negative: `used > approved` should be impossible,
  // but if the service ever reports it, "0 remaining" is the safe reading — a negative
  // number here would flow into the shortfall arithmetic callers do against it.
  const remaining = used > approved ? 0n : approved - used;
  // Three distinct states, kept distinct on purpose. Absent/null = never expires (known).
  // A parseable string = a real deadline (known). Anything else — a number, an object, an
  // unparseable string — is an expiry we cannot evaluate, and neither "expired" nor "not
  // expired" is an honest answer for it, so it is reported as UNKNOWN rather than being
  // rounded to the convenient one.
  const absent = a.expirationDate === undefined || a.expirationDate === null;
  const raw = typeof a.expirationDate === 'string' ? a.expirationDate : null;
  const parsed = raw !== null ? Date.parse(raw) : Number.NaN;
  // Date.parse alone is NOT enough to claim the expiry is known, and this is measured,
  // not theoretical: Date.parse('2026-02-30') does not fail — it silently rolls over to
  // March 2. A deadline that drifts two days is a wrong answer to "is this still good?",
  // so the parse is required to ROUND-TRIP back to the same calendar day (Codex review
  // round 3). Deliberately narrow: only the ISO-8601 UTC form the payment service
  // actually emits is accepted. An offset form like +09:00 would be reported UNKNOWN
  // rather than guessed at — the conservative direction, and the raw value is still
  // shown to the operator either way.
  const known =
    absent ||
    (raw !== null &&
      Number.isFinite(parsed) &&
      /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/.test(raw) &&
      new Date(parsed).toISOString().startsWith(raw.slice(0, 10)));
  return {
    payer: typeof a.payingAddress === 'string' ? a.payingAddress : '(unknown)',
    recipient: typeof a.approvedAddress === 'string' ? a.approvedAddress : '(unknown)',
    approved: approved.toString(),
    used: used.toString(),
    remaining: remaining.toString(),
    // A non-string expirationDate is surfaced as its JSON rather than dropped to null:
    // "no expiry" and "an expiry I could not read" must not look identical to a human.
    expires_at: absent ? null : (raw ?? JSON.stringify(a.expirationDate)),
    // Still not "expired" — crying expired about an approval the service honours is its
    // own kind of wrong. expiry_known carries the uncertainty instead.
    expired: Number.isFinite(parsed) && parsed <= Date.now(),
    expiry_known: known,
  };
}

// Absent is fine — a leaner/older response simply has no approvals to report, and [] is
// the truthful reading. Present-but-not-an-array is NOT fine: silently flattening it to
// [] would report "you have no approvals" about a body that was trying to tell us
// otherwise, which is the same fail-open shape wincField() refuses above (Codex review).
// An explicit `null` is accepted as [] on purpose, and this is NOT the same call as
// wincField's rejection of null: `null` is the idiomatic JSON spelling of "this list is
// empty", whereas a null WINC is a required scalar going missing. Round-2 review flagged
// the asymmetry — it is deliberate, not an oversight.
function parseApprovals(v: unknown, what: string): CreditApproval[] {
  if (v === undefined || v === null) return [];
  if (!Array.isArray(v)) throw new Error(`balance: ${what} is present but not an array: ${JSON.stringify(v)}`);
  return v.map((a) => parseApproval(a as WireApproval));
}

/**
 * Fetch `address`'s spendable state from the Turbo payment service.
 *
 * Throws on any failure (bad address shape, non-200, malformed body, timeout). That is
 * deliberate and differs from arUsdRate()'s null-on-anything: a USD line is a courtesy
 * that must never block a push, whereas every caller of THIS function is either
 * answering "how much can I spend?" as its whole job (`wallet balance`) or gating a
 * spend on the answer. A silent null there would read as "no funds" or "fine, proceed"
 * depending on the caller — both wrong.
 */
export async function fetchBalance(address: string, rate: number | null = null): Promise<WalletBalance> {
  if (!isWalletAddress(address))
    throw new Error(`balance: not a wallet address (Arweave/Ethereum/Solana): ${JSON.stringify(address)}`);
  // Built through URL/searchParams rather than string concatenation so an override that
  // already carries a query or fragment (CIPHER_BRAIN_AR_BALANCE_URL=".../balance?x=1")
  // gets a well-formed URL instead of a second "?" (Codex review).
  let url: URL;
  try {
    url = new URL(AR_BALANCE_URL);
  } catch {
    throw new Error(`balance: CIPHER_BRAIN_AR_BALANCE_URL is not a valid URL: ${JSON.stringify(AR_BALANCE_URL)}`);
  }
  url.searchParams.set('address', address);
  let body: unknown;
  try {
    const res = await fetch(url, { signal: AbortSignal.timeout(AR_HTTP_TIMEOUT_MS) });
    // 404 is ambiguous on this service and must NOT be blanket-treated as "zero" — a
    // measured fact, not a guess: an address it has never seen answers 404 "User Not
    // Found", while a mistyped/moved endpoint answers 404 "Not Found". Reading both as a
    // zero balance would turn a wrong CIPHER_BRAIN_AR_BALANCE_URL into a confident "you
    // have no funds" on a spend-adjacent path (Codex review). So the "never funded"
    // reading is granted ONLY to the body that actually says so; any other 404 falls
    // through to the error below, which names both possibilities.
    if (res.status === 404) {
      const text = await res.text().catch(() => '');
      if (/user not found/i.test(text))
        return {
          address,
          own: '0',
          effective: '0',
          unit: 'winc',
          approx_ar: 0,
          usd_estimate: rate !== null ? 0 : null,
          received_approvals: [],
          given_approvals: [],
        };
      throw new Error(
        `HTTP 404 (${JSON.stringify(text.slice(0, 80))}) — this is NOT the service's "address never funded" reply, ` +
          `so the endpoint itself is likely wrong; check CIPHER_BRAIN_AR_BALANCE_URL`,
      );
    }
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    body = await res.json();
  } catch (e) {
    throw new Error(`balance: could not read ${address} from ${AR_BALANCE_URL}: ${errMsg(e)}`);
  }
  const w = (body ?? {}) as WireBalance;
  const own = wincField(w.winc, 'winc');
  // effectiveBalance is the service's own "own + what approvals let you draw" figure, so
  // it is taken as authoritative rather than recomputed from the approval list here —
  // only the service knows which approvals it will actually honour at spend time (expiry
  // handling, per-payer rules). Older/leaner responses may omit it; fall back to `own`,
  // which is the conservative direction (understating spendable credit cannot green-light
  // a push that will fail).
  const effective = w.effectiveBalance === undefined ? own : wincField(w.effectiveBalance, 'effectiveBalance');
  const approxAr = Number(effective) / 1e12;
  return {
    address,
    own: own.toString(),
    effective: effective.toString(),
    unit: 'winc',
    approx_ar: approxAr,
    usd_estimate: rate !== null ? Number((approxAr * rate).toFixed(6)) : null,
    received_approvals: parseApprovals(w.receivedApprovals, 'receivedApprovals'),
    given_approvals: parseApprovals(w.givenApprovals, 'givenApprovals'),
  };
}
