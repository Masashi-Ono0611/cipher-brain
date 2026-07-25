---
"cipher-brain": patch
---

`schedule install` now bakes `CIPHER_BRAIN_AR_USD_RATE_URL` into the generated
runner. It was dropped, so an operator who had pointed the AR/USD rate endpoint
somewhere else still got a scheduled paid push that contacted the default
`payment.ardrive.io` — an egress the interactive run they tested did not make.
The variable is also documented in `--help` now; it was readable only from the
source.
