#!/usr/bin/env node
// #363: @ardrive/turbo-sdk is an optionalDependency — a normal `bun install` /
// `npm install` must resolve it AND its transitive tree correctly. The
// --no-save era this replaces left broken hoists in a real checkout (viem
// importing the 1.x-era `@noble/hashes/sha3` subpath from a hoisted 2.x copy
// whose `exports` no longer defines it), which a directory-exists check would
// have called healthy — so this asserts the SDK actually LOADS, and that the
// one export the turbo backend uses (estimate.ts / backends/turbo.ts both go
// through TurboFactory) is really there.
//
// If this fails after an install: the lockfile/resolver no longer owns the
// SDK's tree — see the "Installing where dependencies clash" fallback in
// docs/arweave-upload-runbook.md, and #363 for the failure class.
try {
  const sdk = await import('@ardrive/turbo-sdk');
  if (typeof sdk.TurboFactory?.unauthenticated !== 'function') {
    console.error('[FAIL] @ardrive/turbo-sdk loaded but TurboFactory.unauthenticated is not a function');
    process.exit(1);
  }
  console.log('[PASS] @ardrive/turbo-sdk resolves and loads (optionalDependency, #363)');
} catch (e) {
  console.error(`[FAIL] @ardrive/turbo-sdk failed to load: ${e instanceof Error ? e.message : String(e)}`);
  process.exit(1);
}
