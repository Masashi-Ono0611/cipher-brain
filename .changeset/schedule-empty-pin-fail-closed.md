---
"cipher-brain": patch
---

`schedule install` no longer strips an explicitly empty `CIPHER_BRAIN_PIN_RECIPIENTS`
out of the generated nightly runner. An empty pin is deliberately not the same thing
as an unset one — a snapshot refuses to run on it, so a broken cron/systemd template
that renders `CIPHER_BRAIN_PIN_RECIPIENTS=""` cannot silently disable the recipient
allowlist. The install-time env capture dropped every falsy value, which collapsed the
two cases: the interactive path failed closed on an empty pin while the unattended
scheduled path it generated ran with no allowlist at all, and because that runner sets
`CIPHER_BRAIN_NO_CONFIG_FILE=1`, `$CIPHER_BRAIN_HOME/config.env` could not put the pin
back either.

An explicitly empty value is now baked into the runner verbatim, so the scheduled run
reaches the same fail-closed check the interactive one does. A genuinely unset variable
is still dropped, and an empty value is never path-resolved (that would have turned it
into the directory `schedule install` happened to run from).
