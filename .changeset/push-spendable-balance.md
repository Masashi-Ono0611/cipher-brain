---
'cypher-brain': patch
---

`push --backend turbo` now reports what THIS upload can actually draw on, not just the
signer's own balance. In the funding flow `docs/arweave-upload-runbook.md` documents —
credits bought on a browser wallet that cannot sign here, then shared to the JWK — the
signer's own balance is structurally 0, so the one figure printed before an irreversible
paid upload was guaranteed to read `Turbo Credit balance: 0 winc` even as the upload went
on to spend successfully from an approval. It now prints the reachable credit (own
balance + the live approvals `CIPHER_BRAIN_AR_PAID_BY` actually selects, each named with
its remaining winc and expiry) — deliberately NOT the service's `effectiveBalance`, which
sums approvals from every payer including ones this upload cannot touch; credit stranded
that way is called out as unreachable instead of shown as spendable. A balance that
cannot be read now says so instead of being silently omitted, which had made "no balance
shown" indistinguishable from "no balance". The local `@ardrive/turbo-sdk` type
declaration is corrected too: it declared `winc` as the response's only field, the same
wrong belief at the type level.
