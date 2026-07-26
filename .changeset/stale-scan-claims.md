---
'cipher-brain': patch
---

Corrects four places that still described the secret scan as opt-in.

#316 made `--scan-secrets` default to `warn` and added `off`, but left these behind: the MCP
tool table's `schedule_install` row still said "off by default", `src/lib/secrets-scan.ts`'s
own header still called itself an "opt-in gitleaks integration", and three comments still
enumerated the modes as `warn|deny`. Docs that contradict the code are worse than no docs
for exactly the reader who checks before trusting a default.

The `schedule_install` row also now states the part that matters operationally: install
resolves the **effective** mode even when none is given and bakes it in, so the nightly
never re-derives a default from whatever is on `PATH` months later.
