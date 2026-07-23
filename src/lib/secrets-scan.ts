// secrets-scan — opt-in gitleaks integration for `snapshot --scan-secrets warn|deny` (#215).
//
// Threat model this closes: the primary storage backends (Arweave/Turbo) are WRITE-ONCE,
// UN-DELETABLE. Today nothing inspects the CONTENTS of a --dir/--profile source before it
// is archived and encrypted, so an accidentally-included API key/token/password would be
// permanently committed to that backend — encryption alone does not help if the age
// identity is later lost or broken (see #205's post-quantum motivation for the same
// concern from the other direction). Rather than reinvent secret detection, this fully
// delegates to gitleaks (github.com/gitleaks/gitleaks) — an established scanner whose
// default ruleset and `.gitleaks.toml` customization/allowlisting the operator can already
// drop into a scanned source directory, exactly as they would for a git repo.
//
// Privacy of the scan's OWN output: gitleaks' `--redact` blanks the matched secret text in
// its JSON report, but this module goes further and never even reads that far — only
// `RuleID` is extracted back out, so no file path, line number, or match text from
// gitleaks' report ever reaches the manifest or console (matches the issue's "rule ID・
// 件数のみ" scope exactly).
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { run } from './proc.js';
import { errMsg } from './util.js';

export type ScanSecretsMode = 'warn' | 'deny';

export interface SecretFinding {
  rule_id: string;
  count: number;
}

interface GitleaksRawFinding {
  RuleID?: string;
}

export const SCAN_SECRETS_INSTALL_HINT =
  '--scan-secrets requires the gitleaks binary on PATH (https://github.com/gitleaks/gitleaks) ' +
  '— install it with `brew install gitleaks` (macOS/Linuxbrew) or see ' +
  'https://github.com/gitleaks/gitleaks#installing for other platforms.';

// `command -v` (POSIX shell builtin, portable macOS/Linux) — same reasoning schedule.ts's
// resolvePgDumpDir already documents for pg_dump: resolves against THIS process's PATH,
// and gives one clear actionable error instead of a bare spawn ENOENT bubbling out of a
// scan step deep into a snapshot run.
async function gitleaksAvailable(): Promise<boolean> {
  try {
    const r = await run('sh', ['-c', 'command -v gitleaks']);
    return r.out.trim().length > 0;
  } catch {
    return false;
  }
}

// Fail fast, BEFORE any pg_dump/tar/staging work runs (mirrors the existing fail-fast
// checks at the top of snapshot() — a bad --out parent dir, an unresolvable recipient,
// etc.) — checked once per snapshot() call, not once per --dir source.
export async function assertGitleaksAvailable(): Promise<void> {
  if (!(await gitleaksAvailable())) throw new Error(SCAN_SECRETS_INSTALL_HINT);
}

// Scans `dir` (a directory of already-staged PLAINTEXT — the exact bytes about to be
// archived) and returns rule-ID -> count, nothing else. `--exit-code 0` deliberately
// overrides gitleaks' own default (1 when leaks are found): this keeps run()'s existing
// "reject on any non-zero exit" meaning "gitleaks itself failed to run" (bad path,
// corrupt --config, a gitleaks crash) — "leaks were found" is instead read back out of
// the JSON report body, so it can never be confused with a genuine invocation error.
export async function scanForSecrets(dir: string): Promise<SecretFinding[]> {
  const reportDir = await mkdtemp(join(tmpdir(), 'cipher-brain-gitleaks-'));
  const reportPath = join(reportDir, 'report.json');
  try {
    await run('gitleaks', [
      'dir',
      '--no-banner',
      '--redact',
      '--report-format',
      'json',
      '--report-path',
      reportPath,
      '--exit-code',
      '0',
      dir,
    ]);
    // A missing/unparsable report must NOT be treated as "no findings" (fail OPEN) — gitleaks
    // itself exited 0 (only proves the scan ran, not that the report is trustworthy), so a
    // truncated write / disk-full / permissions hiccup here would otherwise let --scan-secrets
    // deny silently proceed as if the source were clean. Fail closed: surface it as a real
    // error instead (multi-model review finding).
    let raw: GitleaksRawFinding[];
    try {
      raw = JSON.parse(await readFile(reportPath, 'utf8')) as GitleaksRawFinding[];
    } catch (e) {
      throw new Error(
        `gitleaks ran but its report at ${reportPath} could not be read/parsed (${errMsg(e)}) — refusing to treat this as "no findings"`,
      );
    }
    const counts = new Map<string, number>();
    for (const f of raw) {
      const id = f.RuleID || 'unknown';
      counts.set(id, (counts.get(id) ?? 0) + 1);
    }
    return [...counts.entries()]
      .map(([rule_id, count]) => ({ rule_id, count }))
      .sort((a, b) => a.rule_id.localeCompare(b.rule_id));
  } finally {
    await rm(reportDir, { recursive: true, force: true });
  }
}

// warn: log and proceed. deny: refuse the whole snapshot. `label` is the manifest
// component name (e.g. "obsidian.tar.gz") — identifies WHICH source without ever
// surfacing the finding's own file path.
export function reportSecretFindings(label: string, findings: SecretFinding[], mode: ScanSecretsMode): void {
  if (findings.length === 0) return;
  const total = findings.reduce((n, f) => n + f.count, 0);
  const summary = findings.map((f) => `${f.rule_id}×${f.count}`).join(', ');
  if (mode === 'deny') {
    throw new Error(
      `gitleaks found ${total} potential secret(s) in "${label}" (${summary}) — refusing to snapshot ` +
        `(--scan-secrets=deny). Remove/rotate them, add a .gitleaks.toml allowlist under the scanned ` +
        `source if this is a false positive, or rerun with --scan-secrets=warn to proceed anyway.`,
    );
  }
  console.error(
    `⚠  gitleaks found ${total} potential secret(s) in "${label}" (${summary}) — proceeding ` +
      `(--scan-secrets=warn). This snapshot is about to be encrypted and may go to an UN-DELETABLE ` +
      `backend (Arweave/Turbo) — review before pushing.`,
  );
}
