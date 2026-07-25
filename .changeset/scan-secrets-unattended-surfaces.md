---
"cipher-brain": minor
---

The `--scan-secrets warn|deny` gitleaks gate is now available from the two
surfaces that run without anyone watching, not just an interactive `snapshot`.

`schedule install --scan-secrets warn|deny` bakes it into the generated nightly
runner. Previously the flag was accepted, exited 0, and was silently discarded —
the runner it wrote never scanned, so an operator who asked for the strictest gate
on their unattended push to a write-once store got no gate at all. Install now
also resolves `gitleaks` and adds its directory to the runner's `PATH` (`launchd`
and `cron` do not inherit yours), and refuses to install if it cannot be resolved,
rather than registering a schedule that could never scan. `schedule status` (and
its `--json` / MCP equivalents) reports whether an installed schedule scans.

The MCP `snapshot_now` tool gains a `scan_secrets` field with the same
`"warn"|"deny"` values; the field simply did not exist before, so no MCP-driven
snapshot could be scanned. Its result reports the mode that actually ran (`null`
when none did).

The default is unchanged and still **off on every surface** — this adds the
ability to ask for the scan, not a new policy. Asking for it on a machine without
`gitleaks` remains a hard failure rather than a silent skip.
