#!/usr/bin/env node
// A mock tonapi.io for scripts/selftest-ton-dns.sh — stands in for the two REST
// endpoints src/lib/ton-dns.ts's `publish-latest` reads (domain -> NFT item address, and
// polling the domain's DNS resolution), so the selftest exercises the REAL fetch/parse
// code with no real network call. CYPHER_BRAIN_TON_TONAPI_URL points at this server.
//
// GET /v2/dns/<domain>          -> {item: {address: MOCK_TONAPI_ADDRESS}}   (any domain)
// GET /v2/dns/<domain>/resolve  -> {} until the MOCK_TONAPI_FLIP_AFTER'th call to this
//                                   endpoint, then {storage: MOCK_TONAPI_BAG_ID} — so the
//                                   selftest's --wait poll genuinely sees a NOT-YET ->
//                                   CONFIRMED flip, not an instantly-true record.
//
// Argv: --port <n>. Env: MOCK_TONAPI_ADDRESS, MOCK_TONAPI_BAG_ID, MOCK_TONAPI_FLIP_AFTER
// (default 1 — resolves on the very first poll).
import { createServer } from 'node:http';

const args = process.argv.slice(2);
const opt = (name) => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
};
const port = Number(opt('--port'));
const address = process.env.MOCK_TONAPI_ADDRESS;
const bagId = process.env.MOCK_TONAPI_BAG_ID;
const flipAfter = Number(process.env.MOCK_TONAPI_FLIP_AFTER || '1');

if (!port || !address || !bagId) {
  console.error('mock-tonapi: --port, MOCK_TONAPI_ADDRESS and MOCK_TONAPI_BAG_ID are all required');
  process.exit(2);
}

let resolveCalls = 0;

const srv = createServer((req, res) => {
  const url = new URL(req.url, `http://127.0.0.1:${port}`);
  const reply = (code, obj) => {
    res.writeHead(code, { 'content-type': 'application/json' });
    res.end(JSON.stringify(obj));
  };
  const m = url.pathname.match(/^\/v2\/dns\/[^/]+(\/resolve)?$/);
  if (!m) return reply(404, { error: `mock-tonapi: no such endpoint ${url.pathname}` });
  if (m[1] === '/resolve') {
    resolveCalls += 1;
    if (resolveCalls >= flipAfter) return reply(200, { storage: bagId });
    return reply(200, {});
  }
  return reply(200, { item: { address } });
});
srv.listen(port, '127.0.0.1');
