---
"cipher-brain": minor
---

`cipher-brain init`'s interactive prompts now run on
[@clack/prompts](https://github.com/bombshell-dev/clack) instead of a hand-rolled
`node:readline` reader. The wizard asks the exact same questions, in the exact
same order, with the exact same defaults — only the input widget changed.

Two concrete improvements come from the library itself, at no extra cost:

- **NO_COLOR / terminal-width awareness.** Every prompt's rendering goes through
  Node's own `util.styleText`, which already checks `NO_COLOR`/`FORCE_COLOR`/TTY
  status before emitting any escape code, and clack wraps long lines to the
  terminal's actual width.
- **Ctrl+C during a prompt now rolls back cleanly.** Previously, interrupting the
  wizard mid-run forwarded a real `SIGINT` to the process and killed it outside
  of `init()`'s own try/catch — anything already written (a fresh identity, a
  backup keypair) was silently left behind. clack decodes Ctrl+C as ordinary
  input instead, so it now throws inside the wizard's existing error path and
  triggers the same rollback (or, if a snapshot was already pushed, the same
  "preserved, not rolled back" reporting) as any other failure partway through.

The yes/no prompts (`askYesNo`) are now a two-option toggle rather than parsed
free text, which structurally closes the failure mode issue #96 fixed by hand
(an unrecognized answer like `"yeah"` being silently read as "no" on a
security-relevant default-yes prompt) — there is no longer a text answer to
misread in the first place.

The recovery-kit generation logic (issue #68/#214), rollback bookkeeping, and
every prompt's question/default/validation behavior are unchanged; only the
input layer was swapped.
