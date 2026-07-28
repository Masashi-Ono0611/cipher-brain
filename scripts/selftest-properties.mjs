#!/usr/bin/env node
// Property-based tests (#228), using fast-check (the de facto standard for JS/TS —
// CONTRIBUTING.md's "prefer an existing implementation" applies here just as much as it
// does to age/rclone/gitleaks: this project does not roll its own input generator/shrinker).
//
// Every existing selftest*.{sh,mjs} in this repo is example-based: a handful of
// hand-picked inputs, run once. That catches regressions in cases someone already
// thought of. It does NOT answer "does this invariant hold for inputs nobody thought
// to write by hand" — which is exactly the gap PR #198's review finding fell into: a
// forged manifest `name` like "../../../etc/cron.d/evil.tar.gz" is one hand-picked
// string, but the actual security claim ("no name a manifest can contain ever escapes
// --out-dir") is a claim about ALL strings. fast-check generates hundreds of inputs
// per run (including its own library of known-nasty edge cases: empty strings, lone
// surrogates, control characters, very long strings) and shrinks any failure to a
// minimal counterexample.
//
// Scope, stated narrowly on purpose (same discipline as selftest-error-codes.mjs's own
// header): this file property-tests THREE specific, already-identified invariants — the
// two manifest-field guards in src/lib/restore.ts (#198's vulnerability class) and the
// age encrypt/decrypt roundtrip in src/lib/crypt.ts. It does not attempt to fuzz the
// whole CLI surface, and it is not a substitute for scripts/selftest-cctv-age.mjs (which
// checks typage's CONFORMANCE to the age spec using upstream's own vectors — a different
// question from "does OUR code's usage of typage roundtrip correctly").
import fc from 'fast-check';
import { join, resolve, sep } from 'node:path';
import { isSafeComponentName, encodeSourcePath, PATH_ENCODE_MAX } from '../src/lib/restore.ts';
import { generateKeypair, newEncrypter, newDecrypter } from '../src/lib/crypt.ts';

let failed = 0;
const check = (name, cond, detail) => {
  if (cond) {
    console.log(`[PASS] ${name}`);
  } else {
    failed++;
    console.log(`[FAIL] ${name}${detail ? ` — ${detail}` : ''}`);
  }
};

// Runs an fc property and reports it the same way every other check() in this file
// does — fc.assert() throws on the first (already-shrunk) counterexample, so a plain
// try/catch is all the translation needed.
async function property(name, prop, params) {
  try {
    await fc.assert(prop, { numRuns: 200, ...params });
    check(name, true);
  } catch (e) {
    check(name, false, e.message.split('\n')[0]);
  }
}

// ---- restore.ts: isSafeComponentName (#198's vulnerability class) ----
//
// `unit: 'binary'` (not fc.string()'s default `unit: 'grapheme-ascii'`) generates raw
// UTF-16 code units -- control characters, lone surrogates, and the full Unicode range,
// not just printable ASCII. A manifest's `source`/component-name fields are attacker-
// controlled bytes, not necessarily well-formed text, so the property below needs to
// see those shapes to actually test what its own name promises ("for any input").
const wideString = (opts) => fc.string({ unit: 'binary', ...opts });

// A dedicated arbitrary for path-traversal-SHAPED strings, alongside generic wideString()
// — plain random unicode rarely happens to contain "..", so without this the property
// would spend almost all its budget on inputs that were never going to be interesting.
// `fc.oneof` weights both, so the suite still gets broad coverage AND concentrated
// coverage of the actual attack shape.
const pathSegment = fc.oneof(
  fc.constant('..'),
  fc.constant('.'),
  wideString({ minLength: 0, maxLength: 8 }).filter((s) => !s.includes('/') && !s.includes('\\')),
);
const traversalLike = fc
  .tuple(
    fc.array(pathSegment, { minLength: 1, maxLength: 6 }),
    fc.constantFrom('/', '\\'),
    fc.boolean(), // leading separator, e.g. "/etc/passwd"
  )
  .map(([segs, s, leading]) => (leading ? s : '') + segs.join(s));
const nameArb = fc.oneof(wideString(), traversalLike);

await property(
  'isSafeComponentName: an accepted name never resolves outside outDir',
  (() => {
    const outDir = join(sep, 'restore', 'out-dir'); // a fixed, fake absolute root — no real I/O
    const rootResolved = resolve(outDir);
    return fc.property(nameArb, (name) => {
      if (!isSafeComponentName(name)) return true; // rejected — nothing to check here
      const joined = resolve(join(outDir, name));
      // Either it landed EXACTLY on outDir (only possible for a name that resolves to
      // "", which isSafeComponentName already refuses via its length check — kept as a
      // belt-and-suspenders equality check, not an escape hatch) or strictly inside it.
      return joined === rootResolved || joined.startsWith(rootResolved + sep);
    });
  })(),
);

// The property above proves accepted names are SAFE — it says nothing about whether
// isSafeComponentName is too eager to reject (a function that always returns false
// would trivially satisfy it too: nothing is ever accepted, so nothing is ever checked).
// This second property closes that gap by pinning the other half of the same contract
// its own doc comment states ("a bare filename directly under --out-dir: no directory
// separator, no dot-segment") — every ordinary, non-adversarial filename must still be
// ACCEPTED, and every string containing a separator or a bare dot-segment must still be
// REJECTED. Together the two properties fully specify the function's truth table.
await property(
  'isSafeComponentName: accepts exactly the bare, non-dot-segment filenames its doc comment promises',
  fc.property(nameArb, (name) => {
    const structurallySafe =
      name.length > 0 && !name.includes('/') && !name.includes('\\') && name !== '.' && name !== '..';
    return isSafeComponentName(name) === structurallySafe;
  }),
);

// Pin the exact exploit string the code comment above isSafeComponentName documents —
// an example-based regression alongside the properties above, the same "both together"
// posture CONTRIBUTING.md's own quality bar expects (a property proves the invariant in
// general; this pins the one concrete case a reviewer will recognize on sight).
check(
  'isSafeComponentName: rejects the #198 example verbatim',
  isSafeComponentName('../../../etc/cron.d/evil.tar.gz') === false,
);

// ---- restore.ts: encodeSourcePath (the `source` field's guard) ----
//
// encodeSourcePath()'s output is used as ONE path segment (prefixed with a numeric
// index, see restore.ts) — it must never smuggle a '/' or '\\' through, regardless of
// what a forged manifest's `source` field contains, or that numeric-prefix defense
// stops guaranteeing a single directory-name segment. `sourceArb` deliberately spans
// well past PATH_ENCODE_MAX (160) so the truncate-and-hash branch is exercised too,
// not just the short-input passthrough — a length-only regression in that branch
// would otherwise never come up against a generator that only ever produces short
// strings.
// Boundary-exact lengths around PATH_ENCODE_MAX (160): random sampling alone rarely
// lands on the EXACT length the truncate-vs-passthrough branch flips on, no matter how
// many runs -- these constants guarantee the mutation-testing kill oracle actually sees
// the boundary (off-by-one <= vs < mutants, "always truncate"/"never truncate" mutants).
const boundaryLengthArb = fc.oneof(
  fc.constant('a'.repeat(159)),
  fc.constant('a'.repeat(160)),
  fc.constant('a'.repeat(161)),
);
const sourceArb = fc.oneof(
  wideString(),
  wideString({ minLength: 200, maxLength: 500 }),
  traversalLike,
  boundaryLengthArb,
);
// numRuns raised for these two: wideString()'s full binary-code-unit domain is vastly
// larger than the old ASCII-only default, so the mutation-testing kill oracle (a mutant
// that misbehaves only on specific narrow inputs, e.g. one particular character class in
// encodeSourcePath's own replace regex) needs more samples to stay as likely to land on
// a triggering input as it was against the smaller domain -- 200 runs alone let real
// mutation-score coverage regress after the string arbitrary was widened.
await property(
  'encodeSourcePath: never emits a path separator, for any input',
  fc.property(sourceArb, (source) => {
    const encoded = encodeSourcePath(source);
    return !encoded.includes('/') && !encoded.includes('\\');
  }),
  { numRuns: 1000 },
);

// The per-component directory name is `<3-digit index>-<encoded>` (restore.ts) — this
// pins encodeSourcePath()'s own documented contribution to that budget: comfortably
// under common 255-byte filename limits regardless of how long/deeply-nested the
// forged `source` string is. `+ 9` = a '-' plus the 8-hex-char digest suffix.
await property(
  'encodeSourcePath: output length never exceeds PATH_ENCODE_MAX + digest suffix, for any input',
  fc.property(sourceArb, (source) => encodeSourcePath(source).length <= PATH_ENCODE_MAX + 9),
  { numRuns: 1000 },
);

// ---- crypt.ts: generateKeypair / newEncrypter / newDecrypter roundtrip ----
//
// Through this repo's OWN wrapper functions (not age-encryption's Encrypter/Decrypter
// directly — those are already exercised for spec conformance by
// scripts/selftest-cctv-age.mjs; the point here is this repo's usage of them).
// The existing selftest*.sh suite already exercises this end-to-end via the real CLI
// (spawning tar, real files) — this property test complements it in-process (no
// subprocess, no disk I/O) across randomized plaintext SIZE, randomized RECIPIENT
// COUNT/CHOICE, and both the plain-X25519 and post-quantum-hybrid (#205) keypair
// kinds — dimensions the hand-written selftests each fix to one or two values.
await property(
  "keypair roundtrip: any plaintext, any recipient count/kind, decrypts byte-identical for any recipient's identity",
  fc.asyncProperty(
    fc.uint8Array({ minLength: 0, maxLength: 4096 }),
    fc.array(fc.boolean(), { minLength: 1, maxLength: 5 }), // one bool per recipient: pq or plain X25519
    async (plaintext, pqFlags) => {
      const keypairs = await Promise.all(pqFlags.map((pq) => generateKeypair({ pq })));
      const encrypter = newEncrypter(keypairs.map((k) => k.recipient));
      const ciphertext = await encrypter.encrypt(plaintext);

      // Every recipient's identity must decrypt it, not just the first — an encrypt
      // call for N recipients that only the first can actually read would be a much
      // worse bug than any single test picking one identity at random could ever catch.
      for (const { identity } of keypairs) {
        const decrypter = newDecrypter([identity]);
        const decrypted = await decrypter.decrypt(ciphertext);
        if (Buffer.compare(Buffer.from(decrypted), Buffer.from(plaintext)) !== 0) return false;
      }
      return true;
    },
  ),
  { numRuns: 100 },
);

// newEncrypter()'s error path (an invalid recipient string) — the roundtrip property
// above only ever feeds it recipients generateKeypair() itself just produced, so it
// never exercises the reject-and-rewrap-the-error branch at all. `age1` is the native
// recipient prefix (see crypt.ts's own comment on this function); excluding it keeps
// this property from accidentally generating something that happens to parse.
await property(
  "newEncrypter: rejects a non-age recipient with an error naming it, doesn't just crash opaquely",
  fc.property(
    wideString().filter((s) => !s.startsWith('age1')),
    (bogus) => {
      try {
        newEncrypter([bogus]);
        return false; // must not have been accepted as a recipient
      } catch (e) {
        // crypt.ts's rejection throws `invalid recipient ${JSON.stringify(r)}: ...` --
        // check the REJECTED VALUE actually appears (JSON.stringify'd, so control
        // characters/quotes in `bogus` are escaped the same way), not just the generic
        // phrase every rejection shares. A prior version of this test only checked the
        // phrase, which would still pass if the value were silently dropped.
        return (
          e instanceof Error && e.message.includes('invalid recipient') && e.message.includes(JSON.stringify(bogus))
        );
      }
    },
  ),
);

if (failed > 0) {
  console.error(`\n${failed} propert${failed === 1 ? 'y' : 'ies'} failed`);
  process.exit(1);
}
console.log('\nall properties held');
