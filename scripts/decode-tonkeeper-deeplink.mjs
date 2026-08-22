#!/usr/bin/env node
// Decode + assert a Tonkeeper transfer deeplink printed by `publish-latest`
// (scripts/selftest-ton-dns.sh's own decoder, kept as a real file rather than an inline
// heredoc so the parsing logic is readable and independently runnable).
//
// Usage: node decode-tonkeeper-deeplink.mjs <deeplink-url> <expected-64-hex-bag-id>
// Exits 0 and prints "OK: ..." when the link's `bin` param decodes to a change_dns_record
// (op 0x4eb1f0f9, query_id 0, key = sha256("storage") as uint256) BOC whose value cell
// embeds exactly the expected bag id bytes; exits non-zero with a [FAIL] line otherwise.
// (multi-model review W5: query_id and the record key were previously loaded but never
// checked against anything — verified here, not just skipped past.)
import { createHash } from 'node:crypto';
import { Cell } from '@ton/ton';

const [, , deeplinkArg, expectedBagIdArg] = process.argv;
if (!deeplinkArg || !expectedBagIdArg) {
  console.error('[FAIL] usage: decode-tonkeeper-deeplink.mjs <deeplink-url> <expected-bag-id>');
  process.exit(2);
}

const EXPECTED_STORAGE_KEY = BigInt(`0x${createHash('sha256').update('storage').digest('hex')}`);

function fromBase64Url(s) {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/');
  const pad = b64.length % 4 === 0 ? '' : '='.repeat(4 - (b64.length % 4));
  return Buffer.from(b64 + pad, 'base64');
}

try {
  const url = new URL(deeplinkArg);
  const bin = url.searchParams.get('bin');
  if (!bin) throw new Error('deeplink has no ?bin= param');
  const boc = fromBase64Url(bin);
  const cell = Cell.fromBoc(boc)[0];
  const s = cell.beginParse();
  const op = s.loadUint(32);
  if (op !== 0x4eb1f0f9) throw new Error(`op is 0x${op.toString(16)}, expected 0x4eb1f0f9 (change_dns_record)`);
  const queryId = s.loadUintBig(64);
  if (queryId !== 0n) throw new Error(`query_id is ${queryId}, expected 0`);
  const key = s.loadUintBig(256); // exceeds a safe JS number — must load as bigint
  if (key !== EXPECTED_STORAGE_KEY) {
    throw new Error(`dns record key 0x${key.toString(16)} != sha256("storage") 0x${EXPECTED_STORAGE_KEY.toString(16)}`);
  }
  const flag = s.loadBit();
  if (!flag) throw new Error('flag bit is 0 (delete) — expected 1 (set)');
  const value = s.loadRef().beginParse();
  const magic = value.loadUint(16);
  if (magic !== 0x7473)
    throw new Error(`value cell magic is 0x${magic.toString(16)}, expected 0x7473 (dns_storage_address)`);
  const bagHex = value.loadBuffer(32).toString('hex');
  const expected = expectedBagIdArg.toLowerCase();
  if (bagHex !== expected) throw new Error(`embedded bag id ${bagHex} != expected ${expected}`);
  console.log(`OK: op=0x4eb1f0f9 query_id=0 key=sha256("storage") magic=0x7473 bagId=${bagHex}`);
} catch (e) {
  console.error(`[FAIL] ${e instanceof Error ? e.message : String(e)}`);
  process.exit(1);
}
