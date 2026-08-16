---
"cypher-brain": patch
---

`@ardrive/turbo-sdk` moves from an optional *peer* dependency (which package
managers never auto-install) to a real `optionalDependency`, so a normal
`npm install` / `bun install` resolves and nests its transitive tree
correctly. The old `npm install --no-save` install path left broken hoists —
viem importing the 1.x-era `@noble/hashes/sha3` subpath from a hoisted 2.x
copy — that recurred every time the checkout's dependencies were touched
(#363, first classified in #344). The lazy `import()` and the absent/broken
install advice are unchanged (`--omit=optional` installs still get guided),
`arweave` stays an optional peer, and a new `selftest:turbo-dep` suite step
asserts the SDK actually loads in the checkout. README/runbook install
instructions updated; the isolated-directory workaround is reframed as a
fallback for exotic environments rather than the documented happy path.
