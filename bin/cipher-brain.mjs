#!/usr/bin/env node
// Pre-rename entry point, kept so anything that baked this path in before the
// cipher-brain -> cypher-brain rename (a `schedule install` runner on a source checkout,
// a shell alias, a doc) keeps working. Everything lives in bin/cypher-brain.mjs.
await import('./cypher-brain.mjs');
