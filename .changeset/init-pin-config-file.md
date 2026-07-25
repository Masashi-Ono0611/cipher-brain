---
"cipher-brain": patch
---

`cipher-brain init` now points the recipient-pin step at
`$CIPHER_BRAIN_HOME/config.env` instead of your shell rc, both on screen and in
the printed recovery kit. It used to say the setting was read from the
environment and not from any file `init` controls — untrue since the config file
landed — and a shell rc is read only by the interactive shells you open
yourself, which is the one place the pin does not need to be: the unattended
nightly run that `schedule install` sets up starts with a bare environment, and
that is exactly the run a recipient allowlist exists to protect. The suggested
line is now `KEY=value` config-file syntax; `init` still only suggests it and
never writes the file for you.
