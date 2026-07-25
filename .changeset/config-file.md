---
"cipher-brain": minor
---

Settings can now live in a file. `$CIPHER_BRAIN_HOME/config.env` (`KEY=value` per
line) supplies any `CIPHER_BRAIN_*` setting to both the CLI and the MCP server,
so an always-on box's wallet, gateway and spend cap no longer have to be
re-established in every shell.

An explicit environment variable still wins over the file. `CIPHER_BRAIN_HOME`
is the one setting the file cannot provide — the file is found inside it — and a
file that tries is warned about rather than quietly ignored. An unknown
`CIPHER_BRAIN_*` key is refused instead of being a no-op, so a
`CIPHER_BRAIN_MAXSPEND` typo cannot silently drop a spend cap; keys outside that
namespace are left alone. Secrets are allowed, with a warning when the file is
group- or other-readable.

`schedule install` is unchanged: it still bakes the values in effect at install
time into the runner, so editing this file does not alter what an
already-installed nightly run does. `schedule status` now names the config file
it loaded.
