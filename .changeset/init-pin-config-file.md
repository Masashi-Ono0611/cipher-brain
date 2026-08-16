---
"cypher-brain": patch
---

`cipher-brain init` now points the recipient-pin step at
`$CIPHER_BRAIN_HOME/config.env` instead of your shell rc, both on screen and in
the printed recovery kit. It used to say the setting was read from the
environment and not from any file `init` controls — untrue since the config file
landed. A shell rc is read only by the interactive shells you open yourself, so
it leaves out the unattended nightly run `schedule install` sets up: launchd and
cron start that with a bare environment, and `schedule install` bakes in what is
in effect when you run it. A value in the config file covers both. The suggested
line is now `KEY=value` config-file syntax, and the step says outright that it
applies from the next run onward; `init` still only suggests it and never writes
the file for you.
