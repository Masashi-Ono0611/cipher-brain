---
'cipher-brain': minor
---

The `--scan-secrets` gitleaks gate is now reachable from the surfaces that run unattended.

`schedule install --scan-secrets warn|deny` bakes it into the generated nightly; the flag
used to be accepted, exit 0, and be discarded, so the runner never scanned. Install now
resolves `gitleaks` and pins its absolute path into the runner as `CIPHER_BRAIN_GITLEAKS_BIN`
(usable directly too), and refuses to install if it cannot be resolved. `schedule status`
reports the configured mode.

The MCP `snapshot_now` and `schedule_install` tools gain a `scan_secrets` field; it did not
exist before, so no MCP-driven snapshot could be scanned.

Asking for the scan where it would inspect nothing — a `--pg`-only snapshot, or `--dry-run` —
is now refused rather than reported as a scan that ran.
