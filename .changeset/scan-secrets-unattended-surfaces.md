---
"cipher-brain": minor
---

The `--scan-secrets warn|deny` gitleaks gate is now available from the two
surfaces that run without anyone watching, not just an interactive `snapshot`.

`schedule install --scan-secrets warn|deny` bakes it into the generated nightly
runner. Previously the flag was accepted, exited 0, and was silently discarded —
the runner it wrote never scanned, so an operator who asked for the strictest gate
on their unattended push to a write-once store got no gate at all. Install now
also resolves `gitleaks` and pins the absolute path it found into the runner as
`CIPHER_BRAIN_GITLEAKS_BIN` (`launchd` and `cron` do not inherit your `PATH`, and a
different `gitleaks` on theirs must not quietly take its place), and refuses to
install if it cannot be resolved, rather than registering a schedule that could
never scan. `schedule status` (and its `--json` / MCP equivalents) reports the scan
mode an installed schedule is configured with.

`CIPHER_BRAIN_GITLEAKS_BIN` is also usable directly, like `CIPHER_BRAIN_RCLONE_BIN`:
point it at a `gitleaks` that is not on `PATH`.

The MCP `snapshot_now` and `schedule_install` tools gain a `scan_secrets` field
with the same `"warn"|"deny"` values; the field simply did not exist before, so
no MCP-driven snapshot or MCP-installed nightly could be scanned. Both report the
mode that actually ran or was baked in (`null` when none was).

Asking for the scan where it would inspect nothing is now **refused** rather than
reported: the gate covers `--dir`/`--profile` staged plaintext, so a `--pg`-only
snapshot or schedule used to record the mode in the manifest while scanning zero
components, and `--dry-run --scan-secrets` used to exit 0 having staged nothing to
scan (not even validating the mode). Being told a snapshot was scanned when it was
not is worse than being told it was not scanned.

Relatedly, a value-taking flag whose value is missing is now an error naming the
flag — both when it is the last argument (`… --scan-secrets`) and when the next
argument looks like another flag that it would otherwise have swallowed
(`--out --scan-secrets deny`, or the mistyped `--out --scan-secret deny`, which
used to write an *unscanned* snapshot to a file named after the flag). It used to
read as "flag omitted", which for an optional flag meant silently doing nothing —
the same failure mode as the bug above. This applies to every value flag, not just
`--scan-secrets`. Write `./--name` for a value that genuinely starts with dashes.

The default is unchanged and still **off on every surface** — this adds the
ability to ask for the scan, not a new policy. Asking for it on a machine without
`gitleaks` remains a hard failure rather than a silent skip.

One limit is now stated in the docs rather than left to be discovered: gitleaks
does not look inside archives, so a zip/tar source — notably
`--profile chatgpt-export`, which archives the export zip as-is — is scanned only
as opaque bytes, and a secret inside it is not found even though the run reports
the mode.
