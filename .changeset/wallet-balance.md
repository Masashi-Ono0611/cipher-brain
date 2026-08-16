---
'cypher-brain': minor
---

New `wallet balance` reports what an address can actually spend on `turbo`: its own Turbo
Credit balance, its spendable balance (own + Credit Share Approvals delegated to it), and
every approval received/given with the winc remaining and when it expires. Funding a paid
push previously answered none of this — "did my purchase land, did the share land, how
much is left" needed a hand-written `@ardrive/turbo-sdk` script. This does not: like the
USD rate (#170) it is a plain unauthenticated GET keyed on a PUBLIC address, so no SDK
and no signature. `--address` queries any address without a key or wallet file — the
wallet holding freshly bought credits is precisely the one whose JWK the pushing machine
does not have. It also warns when a received approval exists that `CIPHER_BRAIN_AR_PAID_BY`
does not name, since a push cannot draw on an approval it is not told about.
