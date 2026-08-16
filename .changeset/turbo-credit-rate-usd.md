---
'cypher-brain': patch
---

USD approximations now price each backend in its own truthful unit. A `turbo` upload
spends Turbo Credits, and credits sell at Turbo's fiat rate (fees included) — pricing
them at AR spot understated a real 459 MB push's out-of-pocket cost by ~35% ("~$8.71"
shown; ≈$13.1 actually paid for the credits, minutes apart; the same push re-priced at
the credit rate reads ~$13.56). `push --backend turbo`, `estimate --backend turbo` and
`wallet balance` now derive USD from Turbo's own price sheet (`GET /v1/rates`, new
`CIPHER_BRAIN_AR_TURBO_RATES_URL` override), each line saying which rate priced it, and
fall back to explicitly-labeled AR spot ("buying the credits typically costs more than
this") only when the sheet is unavailable or unusable. `wallet balance --json` carries
the provenance too (`usd_rate_source: 'turbo-credit' | 'ar-spot' | null`). The raw `arweave` L1 backend keeps AR spot on purpose:
that spend is real AR, where market value IS the honest price. Existing
`CIPHER_BRAIN_AR_USD_RATE_URL` semantics are unchanged.
