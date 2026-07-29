#!/usr/bin/env node
// age spec conformance, against age's OWN reference test vectors (#228): C2SP/CCTV
// (https://github.com/C2SP/CCTV/tree/main/age), published on npm as `cctv-age` by
// FiloSottile — the author of both the age spec and typage (the `age-encryption`
// package this repo's crypt.ts is built on, see its own header comment). Same
// "prefer an existing implementation" posture CONTRIBUTING.md asks for everywhere
// else: this repo does not maintain its own set of malformed-age-file edge cases,
// it runs the ones the spec's author already wrote and publishes for exactly this
// purpose (its own README: "the simplest, most universal integration [...] attempt
// to decrypt the test files, check the operation only succeeds if `expect` is
// `success`, and compare the decrypted payload").
//
// What this checks, and what it deliberately does not (stated narrowly, same
// discipline as this repo's other selftests): all 143 vectors are run through
// typage's public Decrypter/armor API exactly as crypt.ts uses it, and each
// outcome (decrypts to the expected payload hash / throws) is checked against the
// vector's `expect` field. For a `payload failure` vector the spec says "whatever
// payload decrypted successfully before the error must match the hash" — this
// project's decrypt calls are always given a whole in-memory Uint8Array (never a
// stream typage would surface partial output through, see crypt.ts), so a
// `payload failure` vector's ONLY observable behavior here is "decrypt() rejects",
// which is exactly what is asserted; the partial-output half of that vector's claim
// is not independently checked (there is nothing partial for this call shape to
// observe). This is a conformance check of the DEPENDENCY (does typage behave per
// spec), not of this repo's own code — that is scripts/selftest-properties.mjs's job.
import { Decrypter, armor } from 'age-encryption';
import * as vectors from 'cctv-age';
import { createHash } from 'node:crypto';
import { inflateSync } from 'node:zlib';

let failed = 0;
let passed = 0;
const fail = (name, detail) => {
  failed++;
  console.log(`[FAIL] ${name} — ${detail}`);
};

// Each vector file (see cctv-age's own README for the authoritative format
// description) is: a textual header (key: value lines), a blank line, then the raw
// age-encrypted file — optionally zlib-compressed (`compressed: zlib`, so the
// vector file itself stays small) and/or ASCII-armored (`armored: yes`).
function parseVector(bytes) {
  // latin1, not utf8: the header is pure ASCII by construction, and decoding as
  // utf8 would throw or mangle bytes on a vector whose BODY (immediately
  // following) happens to contain a byte sequence that is not valid utf8 —
  // several `armor_*`/`hmac_*` vectors are exactly that, by design.
  const text = Buffer.from(bytes).toString('latin1');
  const headerEnd = text.indexOf('\n\n');
  if (headerEnd < 0) throw new Error('no blank line separating header from body');
  const fields = { identity: [], passphrase: [] };
  for (const line of text.slice(0, headerEnd).split('\n')) {
    const m = line.match(/^([a-zA-Z ]+): (.*)$/);
    if (!m) continue; // "files with unknown keys should be ignored" (cctv-age README)
    const [, key, value] = m;
    if (key === 'identity' || key === 'passphrase') fields[key].push(value);
    else fields[key] = value;
  }
  let body = bytes.subarray(headerEnd + 2);
  if (fields.compressed === 'zlib') body = inflateSync(body);
  return { fields, body };
}

for (const [name, raw] of Object.entries(vectors)) {
  const { fields, body } = parseVector(raw);
  let file;
  try {
    file = fields.armored === 'yes' ? armor.decode(Buffer.from(body).toString('utf8')) : body;
  } catch (e) {
    if (fields.expect === 'armor failure') passed++;
    else fail(name, `expected "${fields.expect}", but armor.decode() itself threw: ${e.message}`);
    continue;
  }
  const d = new Decrypter();
  for (const identity of fields.identity) d.addIdentity(identity);
  for (const passphrase of fields.passphrase) d.addPassphrase(passphrase);
  try {
    const plaintext = await d.decrypt(file);
    const hash = createHash('sha256').update(plaintext).digest('hex');
    if (fields.expect !== 'success') {
      fail(name, `expected "${fields.expect}" to fail decryption, but it decrypted successfully`);
    } else if (hash !== fields.payload) {
      fail(name, `decrypted, but the payload hash did not match (got ${hash}, want ${fields.payload})`);
    } else {
      passed++;
    }
  } catch (e) {
    if (fields.expect === 'success') fail(name, `expected "success", but decrypt() threw: ${e.message}`);
    else passed++; // any of: no match / HMAC failure / header failure / payload failure
  }
}

console.log(`${passed}/${passed + failed} cctv-age vectors conformed to their \`expect\` field`);
if (failed > 0) process.exit(1);
