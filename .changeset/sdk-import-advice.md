---
'cypher-brain': patch
---

A failed lazy SDK import now gives advice matched to WHY it failed. "run: npm install
@ardrive/turbo-sdk" was measured to be exactly the wrong advice on a real push: with the
SDK present but its transitive `viem` missing (the turbo-sdk → x402 chain inside a
dependency-heavy checkout), npm install had already "succeeded" and repeating it changes
nothing — and an `@noble/hashes` exports/version clash (`ERR_PACKAGE_PATH_NOT_EXPORTED`)
previously escaped as a raw stack trace with no advice at all. Both classes are now
caught across all four lazy-import sites (turbo push, turbo estimate, wallet, arweave
L1), name the interfering module, and point at the isolated-directory pattern newly
documented in docs/arweave-upload-runbook.md ("Installing where dependencies clash") —
the exact pattern that real push used to complete. A genuinely absent SDK keeps its
plain npm-install advice, and non-import failures pass through untouched.
