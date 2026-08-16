---
'cypher-brain': patch
---

A snapshot interrupted mid-secret-scan no longer leaves the gitleaks report directory
behind. `scanForSecrets` was the one tracked-temp-dir site whose registration did not
bracket the directory's life on disk at either end: it created the directory with the
async `mkdtemp` and registered it with the signal guard only after that `await` resolved,
and its `finally` cleared the registration *before* awaiting the removal. A signal landing
in either gap fired the handler while the slot was still null, so the directory survived —
the exact failure the guard exists to prevent, and the reason the SIGINT regression test
flaked one CI cell (its `cipher-brain-*` leftover glob counts this directory too). It now
creates and registers in one tick with `mkdtempSync`, and removes before deregistering —
the ordering `snapshot()` already documents and relies on for its plaintext stage dir.
