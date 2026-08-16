---
"cypher-brain": patch
---

Test-only: the push-balance-report selftest pinned its credit-share approval to the
literal expiry the live service returned (2026-08-11), so `summarizeBalance()` — which
judges expiry against the real clock — started reporting the fixture's approval as
unreachable the day it lapsed, and nine assertions went red without any code change. The
fixture now expires seven days from the run's clock, the span the service actually grants.
