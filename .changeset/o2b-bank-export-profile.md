---
"cipher-brain": minor
---

Add `--profile o2b --export <path>`, a one-flag source preset for [Open Second
Brain](https://github.com/itechmeat/open-second-brain)'s `o2b brain bank-export`
bundle. It follows the existing `chatgpt-export` profile almost exactly: the
bundle is archived as one opaque file, never extracted, so restore hands it back
byte-identical. `schedule install` and the `init` wizard support the new
`--export` flag the same way they already support `--vault`/`--zip`.

Upstream does not fix a filename or extension for bank-export's `--out` (its own
test suite writes bundles named `bank.json`/`b.json`), so cipher-brain's own
`.json`-extension check (mirroring `chatgpt-export`'s `.zip` check) is this
project's convention, not an upstream requirement — point `bank-export --out` at
a `*.json` path for this profile to accept it.
