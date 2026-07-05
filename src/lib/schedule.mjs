// schedule — make the nightly snapshot+push unattended (issue #69, part of #60).
//
// `schedule install` turns the MANAGEMENT.md "Cadence" recipe into two generated
// artifacts instead of a hand-rolled script:
//   1. a runner (nightly.sh) under the schedule dir — the snapshot+push pipeline
//      composed from the SAME flags snapshot/push take, with dated output names,
//      --save-locator, an index.tsv append, and (paid backends only) the
//      CIPHER_BRAIN_YES=1 + CIPHER_BRAIN_MAX_SPEND spend-guard lines;
//   2. the platform trigger — macOS: a launchd plist in ~/Library/LaunchAgents;
//      Linux: a crontab entry tagged `# cipher-brain-nightly` so uninstall can
//      remove exactly its own line.
//
// Every generated file is DETERMINISTIC for a given set of inputs (no embedded
// timestamps) — dates appear only where the RUNNER computes them at run time.
// The runner logs each run to <schedule>/logs/nightly-YYYY-MM-DD.log and always
// leaves a final "OK rc=0" / "FAILED rc=N" line, so a later heartbeat feature
// (and `schedule status` today) can tail the newest log for the outcome.
//
// Testability: CIPHER_BRAIN_SCHEDULE_DIR overrides the schedule dir and
// CIPHER_BRAIN_LAUNCHD_DIR the plist dir, and --no-load writes the artifacts
// without touching launchctl/crontab — so the selftest never registers anything
// on the machine that runs it.

import { mkdir, writeFile, readFile, rm, readdir, chmod } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { homedir } from 'node:os';
import { join, resolve, basename, dirname } from 'node:path';
import { HOME } from './config.mjs';
import { exists } from './util.mjs';

export const SCHEDULE_DIR = process.env.CIPHER_BRAIN_SCHEDULE_DIR || join(HOME, 'schedule');
const LAUNCHD_DIR = process.env.CIPHER_BRAIN_LAUNCHD_DIR || join(homedir(), 'Library', 'LaunchAgents');
const LABEL = 'dev.cipher-brain.nightly';
const CRON_MARKER = '# cipher-brain-nightly'; // idempotent uninstall: remove exactly the lines that carry this tag

const RUNNER = join(SCHEDULE_DIR, 'nightly.sh');
const CONFIG = join(SCHEDULE_DIR, 'schedule.json');
const LOGS_DIR = join(SCHEDULE_DIR, 'logs');
const SNAPS_DIR = join(SCHEDULE_DIR, 'snapshots');
const PLIST = join(LAUNCHD_DIR, `${LABEL}.plist`);
const CRON_ENTRY_FILE = join(SCHEDULE_DIR, 'cron.entry'); // Linux: the exact registered line, kept as an artifact for status/uninstall

const BACKENDS = new Set(['file', 'ton', 'arweave', 'turbo']);
const PAID = new Set(['arweave', 'turbo']);

// POSIX single-quote an arbitrary string for embedding in the generated script.
const shq = (s) => `'${String(s).replace(/'/g, `'\\''`)}'`;

const parseAt = (at) => {
  const m = /^([01]?\d|2[0-3]):([0-5]\d)$/.exec(at);
  if (!m) throw new Error(`--at must be HH:MM (24h), got: ${at}`);
  return { hour: Number(m[1]), minute: Number(m[2]) };
};

function sh(cmd, args, { input } = {}) {
  return spawnSync(cmd, args, { encoding: 'utf8', input });
}

// ---------- generated artifact bodies (deterministic) ----------

function runnerBody(cfg) {
  const cb = `${shq(cfg.node)} ${shq(cfg.cli)}`;
  // Environment the trigger will NOT have (launchd/cron start with a bare env):
  // bake the values that were in effect at install time so the unattended run
  // resolves the same keys/stores the operator tested with.
  const envLines = [`export CIPHER_BRAIN_HOME=${shq(cfg.home)}`];
  // Every CIPHER_BRAIN_* var src/lib/config.mjs reads that a snapshot+push run could need,
  // EXCEPT: CIPHER_BRAIN_HOME (baked above unconditionally), CIPHER_BRAIN_YES/MAX_SPEND
  // (baked separately below, only for paid backends), CIPHER_BRAIN_AGE/AGE_KEYGEN
  // (deprecated — age is bundled in-process now), and CIPHER_BRAIN_PASSPHRASE (only read
  // by the decrypt path — restore/verify/pull's decrypt-proof — which the nightly runner
  // never exercises; it only encrypts). launchd/cron start with a BARE env, so anything
  // here that was set at install time and is silently dropped makes a scheduled run of a
  // non-default backend (ton/turbo/a custom arweave gateway) fail or fall back to the
  // WRONG default compared to the interactive setup the operator actually tested.
  for (const v of [
    'CIPHER_BRAIN_FILE_DIR', 'CIPHER_BRAIN_PG_BIN', 'CIPHER_BRAIN_PIN_RECIPIENTS',
    'CIPHER_BRAIN_TON_CLI', 'CIPHER_BRAIN_TON_API', 'CIPHER_BRAIN_TON_CLIENT', 'CIPHER_BRAIN_TON_SERVER', 'CIPHER_BRAIN_TON_TIMEOUT',
    'CIPHER_BRAIN_AR_HOST', 'CIPHER_BRAIN_AR_PORT', 'CIPHER_BRAIN_AR_PROTOCOL', 'CIPHER_BRAIN_AR_WALLET', 'CIPHER_BRAIN_AR_PAID_BY',
    'CIPHER_BRAIN_AR_HTTP_TIMEOUT', 'CIPHER_BRAIN_AR_L1_MAX', 'CIPHER_BRAIN_PIPE_TIMEOUT',
  ]) {
    if (process.env[v]) envLines.push(`export ${v}=${shq(process.env[v])}`);
  }
  const spendLines = [];
  if (PAID.has(cfg.backend)) {
    spendLines.push(
      `# ${cfg.backend} is a paid, PERMANENT store. CIPHER_BRAIN_YES=1 grants the unattended`,
      `# upload consent that an interactive run gives with --yes; CIPHER_BRAIN_MAX_SPEND caps`,
      `# each upload in the native unit of the backend (winc for turbo, winston for arweave L1)`,
      `# and aborts the push when the cost estimate exceeds it. REVIEW this cap.`,
      `export CIPHER_BRAIN_YES=1`,
      `export CIPHER_BRAIN_MAX_SPEND=${cfg.max_spend}`,
    );
    if (!process.env.CIPHER_BRAIN_AR_WALLET) {
      spendLines.push(`# export CIPHER_BRAIN_AR_WALLET="$HOME/.cipher-brain/wallet.json"   # JWK signer — required to push via ${cfg.backend}`);
    }
  }
  const snapshotArgs = [];
  if (cfg.profile) snapshotArgs.push('--profile', shq(cfg.profile));
  if (cfg.vault) snapshotArgs.push('--vault', shq(cfg.vault));
  if (cfg.zip) snapshotArgs.push('--zip', shq(cfg.zip));
  if (cfg.force_vault) snapshotArgs.push('--force-vault');
  if (cfg.pg) snapshotArgs.push('--pg', shq(cfg.pg));
  for (const t of cfg.tables) snapshotArgs.push('--pg-table', shq(t));
  for (const d of cfg.dirs) snapshotArgs.push('--dir', shq(d));
  for (const r of cfg.recipients) snapshotArgs.push('--recipient', shq(r));
  return `#!/usr/bin/env bash
# nightly.sh — generated by \`cipher-brain schedule install\`. Do NOT edit in place:
# re-run install to change anything (this file is overwritten). If cipher-brain or
# node moves, re-run install so the absolute paths below stay valid.
# One unattended run of the snapshot+push pipeline (MANAGEMENT.md "Cadence").
set -euo pipefail

SCHEDULE_DIR=${shq(cfg.schedule_dir)}
LOG_DIR="$SCHEDULE_DIR/logs"
SNAP_DIR="$SCHEDULE_DIR/snapshots"
mkdir -p "$LOG_DIR" "$SNAP_DIR"
LOG="$LOG_DIR/nightly-$(date +%F).log"
exec >>"$LOG" 2>&1
# Every run ends with a machine-readable status line a heartbeat monitor can tail:
# "OK rc=0" on success, "FAILED rc=N" on any failure (set -e exits at the first error).
trap 'rc=$?; if [ "$rc" -eq 0 ]; then echo "OK rc=0"; else echo "FAILED rc=$rc"; fi' EXIT

${envLines.join('\n')}
${spendLines.length ? spendLines.join('\n') + '\n' : ''}
sha256_of() { if command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | cut -d ' ' -f 1; else sha256sum "$1" | cut -d ' ' -f 1; fi; }

echo "== cipher-brain nightly run start: $(date -u +%FT%TZ) =="
# Retry-safe naming: snapshot.mjs refuses to overwrite an existing --out (by design —
# see src/lib/snapshot.mjs), so a name keyed on the date ALONE collides the moment this
# runner is invoked twice on the same day (a manual test on install day, or a legitimate
# retry after a transient failure). Key on date+time-of-day instead, and disambiguate
# with a numeric suffix in the rare case two invocations land in the same second — this
# loop guarantees every invocation gets its own --out, so a same-day re-run never wedges
# the next (cron/launchd-triggered) run.
STAMP="$(date +%Y%m%dT%H%M%S)"
OUT="$SNAP_DIR/brain-$STAMP.age"
n=1
while [ -e "$OUT" ]; do
  n=$((n + 1))
  OUT="$SNAP_DIR/brain-$STAMP-$n.age"
done
${cb} snapshot ${snapshotArgs.join(' ')} --out "$OUT"
LOC=$(${cb} push --in "$OUT" --backend ${shq(cfg.backend)} --save-locator ${shq(cfg.save_locator)})
printf '%s\\t%s\\t%s\\n' "$(date -u +%FT%TZ)" "$LOC" "$(sha256_of "$OUT")" >> ${shq(cfg.index_file)}
echo "pushed -> ${cfg.backend}:$LOC"
`;
}

function plistBody(cfg) {
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>${xmlEscape(LABEL)}</string>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/bash</string>
    <string>${xmlEscape(cfg.runner)}</string>
  </array>
  <key>StartCalendarInterval</key>
  <dict>
    <key>Hour</key><integer>${cfg.hour}</integer>
    <key>Minute</key><integer>${cfg.minute}</integer>
  </dict>
  <key>StandardOutPath</key><string>${xmlEscape(cfg.logs_dir)}/launchd.out.log</string>
  <key>StandardErrorPath</key><string>${xmlEscape(cfg.logs_dir)}/launchd.err.log</string>
</dict>
</plist>
`;
}

const cronLine = (cfg) => `${cfg.minute} ${cfg.hour} * * * /bin/bash "${cfg.runner}" ${CRON_MARKER}`;

// Escape a string for embedding as PLIST XML text content (e.g. inside <string>…</string>).
// & must go first, or the entities the other replacements introduce would themselves be
// re-escaped. Without this, a path containing any of these characters (plausible in a
// $HOME or username, e.g. "O'Brien & Co") produces invalid XML that `launchctl bootstrap`
// rejects even though the runner itself was generated fine.
const xmlEscape = (s) => String(s)
  .replace(/&/g, '&amp;')
  .replace(/</g, '&lt;')
  .replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;')
  .replace(/'/g, '&apos;');

// ---------- trigger registration ----------

function loadLaunchd() {
  const uid = process.getuid();
  sh('launchctl', ['bootout', `gui/${uid}/${LABEL}`]); // clear a prior registration; failure = was not loaded, fine
  const r = sh('launchctl', ['bootstrap', `gui/${uid}`, PLIST]);
  if (r.error || r.status !== 0) {
    throw new Error(`launchctl bootstrap failed: ${(r.stderr || '').trim() || r.error?.message || `exit ${r.status}`} — artifacts are written; retry with: launchctl bootstrap gui/${uid} ${PLIST}`);
  }
}

function crontabText() {
  const r = sh('crontab', ['-l']);
  if (r.error) throw new Error(`crontab not available: ${r.error.message}`);
  return r.status === 0 ? r.stdout : ''; // non-zero = no crontab for this user yet
}

function loadCron(entry) {
  const kept = crontabText().split('\n').filter((l) => l.trim() && !l.includes(CRON_MARKER));
  const next = [...kept, entry].join('\n') + '\n';
  const r = sh('crontab', ['-'], { input: next });
  if (r.error || r.status !== 0) throw new Error(`crontab write failed: ${(r.stderr || '').trim() || r.error?.message || `exit ${r.status}`}`);
}

// Resolve pg_dump's directory the SAME way config.mjs's PG_BIN is consumed (a directory
// holding pg_dump/pg_restore, joined with the tool name — see config.mjs pgTool()), NOT
// the pg_dump binary path itself. `command -v` is a POSIX shell builtin (portable across
// macOS/Linux, unlike the `which` binary which isn't guaranteed present), run via `sh -c`
// so it resolves against THIS process's current PATH — the same env `schedule install`
// is running in.
function resolvePgDumpDir() {
  const r = sh('sh', ['-c', 'command -v pg_dump']);
  const found = r.status === 0 ? r.stdout.trim() : '';
  return found ? dirname(resolve(found)) : null;
}

// ---------- subcommands ----------

async function install(o) {
  if (!o.backend) throw new Error('--backend <file|ton|arweave|turbo> required');
  if (!BACKENDS.has(o.backend)) throw new Error(`unknown backend: ${o.backend} (expected file|ton|arweave|turbo)`);
  if (!o.pg && o.dirs.length === 0 && !o.profile) {
    throw new Error('nothing to snapshot: pass --profile <name>, --pg <conn> and/or --dir <path>');
  }
  // launchd/cron start with a BARE env — they do NOT inherit the interactive shell's PATH,
  // so a --pg snapshot that resolves pg_dump via PATH interactively (the common Homebrew /
  // Postgres.app setup) would find pg_dump right now but fail every scheduled run. Resolve
  // a default HERE, in the same env this install command is running in, and bake it in
  // (same mechanism as every other CIPHER_BRAIN_* var above) instead of requiring the user
  // to already know to set CIPHER_BRAIN_PG_BIN. An explicit CIPHER_BRAIN_PG_BIN is left
  // untouched (respected as-is by the envLines loop in runnerBody).
  if (o.pg && !process.env.CIPHER_BRAIN_PG_BIN) {
    const dir = resolvePgDumpDir();
    if (!dir) {
      throw new Error(`--pg requires pg_dump for the unattended run — could not resolve it (command -v pg_dump found nothing on PATH); install the postgresql client tools or pass CIPHER_BRAIN_PG_BIN=<dir containing pg_dump/pg_restore>`);
    }
    process.env.CIPHER_BRAIN_PG_BIN = dir;
    console.error(`resolved pg_dump -> ${join(dir, 'pg_dump')} (baked into the runner as CIPHER_BRAIN_PG_BIN — launchd/cron do not inherit PATH)`);
  }
  const at = o.at || '03:30';
  const { hour, minute } = parseAt(at);
  // The one thing this feature must never create: unattended spending without a cap.
  // A paid backend gets CIPHER_BRAIN_YES=1 baked into the runner, so a spend cap is
  // MANDATORY here — refuse to install rather than schedule an uncapped nightly upload.
  if (PAID.has(o.backend)) {
    if (!o.max_spend) {
      throw new Error(`--backend ${o.backend} is a paid store: --max-spend <n> is required for an unattended schedule (native units: winc for turbo, winston for arweave L1) — the runner gets CIPHER_BRAIN_YES=1, so it must also get a spend cap`);
    }
    if (!/^\d+$/.test(String(o.max_spend)) || BigInt(o.max_spend) <= 0n) {
      throw new Error(`--max-spend must be a positive integer (native units), got: ${o.max_spend}`);
    }
  } else if (o.max_spend) {
    throw new Error(`--max-spend only applies to the paid backends (arweave|turbo); --backend ${o.backend} is free`);
  }

  const cfg = {
    schema: 1,
    at, hour, minute,
    backend: o.backend,
    ...(o.profile ? { profile: o.profile } : {}),
    // --vault/--zip are always filesystem paths (a directory / a zip file) — resolve
    // NOW, against the cwd `schedule install` is run from, exactly like --dir below.
    // launchd/cron invoke the generated runner from a DIFFERENT (often unrelated) cwd,
    // so a relative string baked in verbatim would resolve to a different file (or
    // nothing) at scheduled-run time even though it worked interactively at install time.
    ...(o.vault ? { vault: resolve(o.vault) } : {}),
    ...(o.zip ? { zip: resolve(o.zip) } : {}),
    ...(o.force_vault ? { force_vault: true } : {}),
    ...(o.pg ? { pg: o.pg } : {}),
    tables: o.tables,
    dirs: o.dirs.map((d) => resolve(d)),
    // --recipient is EITHER an inline age1... public key (leave verbatim — it is not a
    // path) OR a path to a recipients file (resolve it, same reasoning as --vault/--zip
    // above: it must still name the same file when the runner is invoked from a
    // different cwd by launchd/cron).
    recipients: o.recipients.map((r) => (r.startsWith('age1') ? r : resolve(r))),
    save_locator: resolve(o.save_locator || join(HOME, 'latest-locator.tsv')),
    index_file: resolve(o.index_file || join(SCHEDULE_DIR, 'index.tsv')),
    ...(o.max_spend ? { max_spend: String(o.max_spend) } : {}),
    home: HOME,
    schedule_dir: SCHEDULE_DIR,
    logs_dir: LOGS_DIR,
    runner: RUNNER,
    node: process.execPath,
    cli: resolve(process.argv[1]),
    trigger: process.platform === 'darwin'
      ? { type: 'launchd', path: PLIST }
      : { type: 'cron', entry_file: CRON_ENTRY_FILE },
  };

  await mkdir(LOGS_DIR, { recursive: true });
  await mkdir(SNAPS_DIR, { recursive: true });
  await writeFile(RUNNER, runnerBody(cfg));
  await chmod(RUNNER, 0o755);
  console.error(`runner written -> ${RUNNER}`);

  if (cfg.trigger.type === 'launchd') {
    await mkdir(LAUNCHD_DIR, { recursive: true });
    await writeFile(PLIST, plistBody(cfg));
    console.error(`launchd plist written -> ${PLIST}`);
  } else {
    await writeFile(CRON_ENTRY_FILE, cronLine(cfg) + '\n');
    console.error(`cron entry written -> ${CRON_ENTRY_FILE}`);
  }
  await writeFile(CONFIG, JSON.stringify(cfg, null, 2) + '\n');

  if (o.no_load) {
    console.error('--no-load: artifacts written, trigger NOT registered (launchctl/crontab untouched)');
  } else if (cfg.trigger.type === 'launchd') {
    loadLaunchd();
    console.error(`launchd job loaded: ${LABEL}`);
  } else {
    loadCron(cronLine(cfg));
    console.error(`crontab entry registered (${CRON_MARKER})`);
  }

  // The write-window rationale (MANAGEMENT.md "Avoid the write window"): a run pg_dumps
  // the DB and tars the files at different instants, so it must not straddle the nightly
  // re-synthesis of the source.
  console.error(`scheduled daily at ${at} — run well after the source re-synthesizes overnight, so the DB and files are captured from the same settled state`);
  if (PAID.has(cfg.backend)) {
    console.error(`review CIPHER_BRAIN_MAX_SPEND=${cfg.max_spend} in ${RUNNER} — every unattended ${cfg.backend} push is capped at that estimate (native units)`);
  }
  console.error(`runs log to ${LOGS_DIR}/nightly-YYYY-MM-DD.log (final line: "OK rc=0" or "FAILED rc=N"); check with: cipher-brain schedule status`);
}

async function readConfig() {
  if (!(await exists(CONFIG))) {
    throw new Error(`schedule not installed (no ${CONFIG}) — run: cipher-brain schedule install`);
  }
  return JSON.parse(await readFile(CONFIG, 'utf8'));
}

async function lastLog() {
  let names = [];
  try {
    names = (await readdir(LOGS_DIR)).filter((n) => /^nightly-\d{4}-\d{2}-\d{2}\.log$/.test(n)).sort();
  } catch { /* logs dir absent = no runs yet */ }
  if (names.length === 0) return null;
  const name = names[names.length - 1];
  const lines = (await readFile(join(LOGS_DIR, name), 'utf8')).split('\n').filter((l) => l.trim());
  // The runner guarantees a trailing OK/FAILED rc line per run; take the last one.
  const rcLine = [...lines].reverse().find((l) => /^(OK|FAILED) rc=\d+$/.test(l)) || lines[lines.length - 1] || '(empty log)';
  return { name, rcLine };
}

function nextRunAt(hour, minute) {
  const next = new Date();
  next.setHours(hour, minute, 0, 0);
  if (next.getTime() <= Date.now()) next.setDate(next.getDate() + 1);
  const p = (n) => String(n).padStart(2, '0');
  return `${next.getFullYear()}-${p(next.getMonth() + 1)}-${p(next.getDate())} ${p(next.getHours())}:${p(next.getMinutes())}`;
}

async function status() {
  const cfg = await readConfig();
  console.log(`configured: daily at ${cfg.at}, backend ${cfg.backend}`);
  console.log(`runner: ${cfg.runner}`);
  if (cfg.trigger.type === 'launchd') {
    const r = sh('launchctl', ['print', `gui/${process.getuid()}/${LABEL}`]);
    const loaded = !r.error && r.status === 0;
    console.log(`trigger: launchd ${cfg.trigger.path} (loaded: ${loaded ? 'yes' : 'no'})`);
  } else {
    let loaded = 'unknown';
    const r = sh('crontab', ['-l']);
    if (!r.error) loaded = r.status === 0 && r.stdout.includes(CRON_MARKER) ? 'yes' : 'no';
    console.log(`trigger: cron "${cronLine(cfg)}" (registered: ${loaded})`);
  }
  const last = await lastLog();
  console.log(last ? `last run: ${last.name} — ${last.rcLine}` : 'last run: none yet');
  console.log(`next run: ${nextRunAt(cfg.hour, cfg.minute)} (local)`);
}

async function uninstall(o) {
  const removed = [];
  if (process.platform === 'darwin') {
    if (!o.no_load) sh('launchctl', ['bootout', `gui/${process.getuid()}/${LABEL}`]); // failure = was not loaded
    if (await exists(PLIST)) { await rm(PLIST); removed.push(`launchd plist ${PLIST}`); }
  } else {
    if (!o.no_load) {
      const lines = crontabText().split('\n').filter((l) => l.trim());
      const kept = lines.filter((l) => !l.includes(CRON_MARKER));
      if (kept.length !== lines.length) {
        const r = sh('crontab', ['-'], { input: kept.length ? kept.join('\n') + '\n' : '' });
        if (r.error || r.status !== 0) throw new Error(`crontab write failed: ${(r.stderr || '').trim() || r.error?.message || `exit ${r.status}`}`);
        removed.push(`crontab entry (${CRON_MARKER})`);
      }
    }
    if (await exists(CRON_ENTRY_FILE)) { await rm(CRON_ENTRY_FILE); removed.push(`cron entry file ${CRON_ENTRY_FILE}`); }
  }
  for (const [p, what] of [[RUNNER, 'runner'], [CONFIG, 'config']]) {
    if (await exists(p)) { await rm(p); removed.push(`${what} ${p}`); }
  }
  if (removed.length === 0) {
    console.error('nothing to remove — schedule is not installed');
  } else {
    for (const r of removed) console.error(`removed: ${r}`);
    console.error(`kept: logs (${LOGS_DIR}), snapshots (${SNAPS_DIR}) and index.tsv — they are your data, delete manually if unwanted`);
  }
}

export async function schedule(o) {
  switch (o._) {
    case 'install': return install(o);
    case 'status': return status();
    case 'uninstall': return uninstall(o);
    default: throw new Error(`schedule: expected install | uninstall | status, got: ${o._ || '(nothing)'}`);
  }
}
