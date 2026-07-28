// doctor — a read-only environment health check (#201).
//
// Several past issues were each a report of ONE way this tool's setup can silently be
// unsafe: #91 (loadIdentities() never checked identity permissions), #119 (a chmod
// failure on $CIPHER_BRAIN_HOME was swallowed instead of failing closed), #35 (the
// Arweave JWK wallet got weaker permission hygiene than the age identity), #101
// (CIPHER_BRAIN_PIN_RECIPIENTS="" used to fail OPEN, disabling the allowlist), #99 (the
// offline backup keypair's suggested default path sits on the SAME disk as the primary
// identity). Every one of those is fixed now (loadIdentities/keygenAt/wallet.ts all
// warn or fail closed on loose permissions today; snapshot.ts fail-closes on an empty
// pin) — but a fix landing once does not mean it STAYS true on a given machine: a
// config file can be hand-edited, a chmod can be undone, a home directory can be moved
// between machines. This command re-checks all of it, and adds the two things none of
// the individual fixes could: an identity/recipient pairing check, and the last
// scheduled run's outcome (reusing schedule.ts's own status computation).
//
// Design borrowed from Open Second Brain's `o2b brain doctor` (docs/prior-art.md,
// #201's issue comment) and adapted to this project's read-only posture:
//   1. health_score discounts KNOWN, already-flagged issues rather than re-charging the
//      FULL penalty for the same one on every single run — a check that just turned
//      WARN/FAIL for the first time costs more than one you have already seen and not
//      fixed yet, so the score mostly answers "did anything get WORSE since I last
//      looked" rather than "have I fixed literally everything yet" (which would sit low
//      forever for a risk you have deliberately accepted). It is a DISCOUNT, not a full
//      exclusion, on purpose: a lingering FAIL still pulls the score down, so it can
//      never read a healthy-looking 100/100 next to VERDICT: FAIL.
//   2. Each WARN/FAIL is marked known ("carryover", already seen last run) or 🆕 new
//      (first time), so a fresh problem does not get lost in a wall of ones you already
//      know about.
//   3. Every WARN/FAIL carries the exact remediation command, not just a description of
//      the problem.
//
// "Known vs new" needs a memory of the LAST run, so doctor keeps a small bookkeeping
// file at $CIPHER_BRAIN_HOME/doctor-state.json — check ids and timestamps only, never
// key material. It is written best-effort and ONLY when CIPHER_BRAIN_HOME already
// exists: doctor's whole premise is inspecting an EXISTING setup, so it must never
// create that directory just to leave its own bookkeeping file on a machine that has
// nothing set up yet (that would also stop being a purely read-only diagnostic).
import { stat, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { identityToRecipient } from 'age-encryption';
import {
  HOME,
  IDENTITY,
  RECIPIENT,
  SIGN_IDENTITY,
  AR_WALLET,
  PIN_RECIPIENTS,
  CONFIG_FILE_PATH,
  AGE_MAGIC,
  AGE_ARMOR_HEADER,
} from './config.js';
import { exists, errMsg } from './util.js';
import { recipientEntries, resolvePinnedRecipients } from './keys.js';
import { WALLET_DEFAULT_PATH } from './wallet.js';
import { scheduleStatusReport } from './schedule.js';
import { printJson, printMascot, moodForVerdict } from './ui.js';
import type { CliOptions } from './types.js';

type CheckStatus = 'pass' | 'warn' | 'fail' | 'skip';

interface DoctorCheck {
  id: string;
  status: CheckStatus;
  message: string;
  remediation?: string;
}

type DoctorMarker = 'new' | 'carryover' | null;

interface DoctorCheckResult extends DoctorCheck {
  marker: DoctorMarker;
  /** ISO date this check FIRST turned WARN/FAIL — only set for warn/fail results. */
  since?: string;
}

interface DoctorResolved {
  id: string;
  message: string;
}

export interface DoctorReport {
  readonly checks: readonly DoctorCheckResult[];
  readonly resolved: readonly DoctorResolved[];
  readonly health_score: number;
  readonly new_count: number;
  readonly carryover_count: number;
  readonly verdict: 'PASS' | 'FAIL' | 'PARTIAL';
  readonly state_path: string;
  readonly state_saved: boolean;
}

// ---------- individual checks ----------

const loosePerms = (mode: number): boolean => (mode & 0o077) !== 0;
const octal = (mode: number): string => (mode & 0o777).toString(8);

async function checkHomeDirPerms(): Promise<DoctorCheck> {
  const id = 'home-dir-perms';
  if (!(await exists(HOME))) {
    return {
      id,
      status: 'skip',
      message: `no CIPHER_BRAIN_HOME directory yet at ${HOME} — run 'cipher-brain keygen' or 'cipher-brain init' to create one`,
    };
  }
  const { mode } = await stat(HOME);
  if (loosePerms(mode)) {
    return {
      id,
      status: 'fail',
      message: `CIPHER_BRAIN_HOME (${HOME}) is group/other-accessible (mode ${octal(mode)}) — it holds the private identity`,
      remediation: `chmod 700 ${HOME}`,
    };
  }
  return { id, status: 'pass', message: `CIPHER_BRAIN_HOME permissions are 0700 (${HOME})` };
}

// Shared by identity.age, sign-identity.key and the wallet JWK — all three are secret
// key material that should be 0600, and each already gets a warnIfLooseKeyPerms() call
// on its own read path (crypt.ts/minisign.ts/wallet.ts); this is the same check, framed
// as a re-runnable diagnostic instead of a side effect of some other command.
async function checkKeyPerms(id: string, path: string, label: string): Promise<DoctorCheck> {
  if (!(await exists(path))) {
    return { id, status: 'skip', message: `no ${label} at ${path} — nothing to check` };
  }
  const { mode } = await stat(path);
  if (loosePerms(mode)) {
    return {
      id,
      status: 'fail',
      message: `${label} at ${path} is group/other-accessible (mode ${octal(mode)}) — it is a secret`,
      remediation: `chmod 600 ${path}`,
    };
  }
  return { id, status: 'pass', message: `${label} permissions are 0600 (${path})` };
}

// Does the age identity actually derive the public key recipient.txt records? A
// mismatch means one of the two files was replaced independently of the other — a
// stale recipient.txt copied from elsewhere, or an identity restored from the wrong
// backup. Skipped (not failed) when the identity is passphrase-wrapped: unwrapping it
// needs a passphrase prompt, which a routine diagnostic should not spring on someone
// running it non-interactively (e.g. from a script) — the check that DOES prove
// end-to-end restorability, `cipher-brain verify`, already prompts for exactly that
// when it needs to.
async function checkIdentityRecipientPairing(): Promise<DoctorCheck> {
  const id = 'identity-recipient-pairing';
  if (!(await exists(IDENTITY)) || !(await exists(RECIPIENT))) {
    return { id, status: 'skip', message: 'no identity/recipient pair to check yet' };
  }
  const raw = await readFile(IDENTITY);
  const rawText = raw.toString('utf8');
  const wrapped =
    raw.subarray(0, AGE_MAGIC.length).toString('latin1') === AGE_MAGIC ||
    rawText.trimStart().startsWith(AGE_ARMOR_HEADER);
  if (wrapped) {
    return {
      id,
      status: 'skip',
      message: `${IDENTITY} is passphrase-wrapped — skipped rather than prompting during a routine diagnostic (run 'cipher-brain verify --in <a snapshot>' to prove restorability instead)`,
    };
  }
  const idLines = rawText
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith('#'));
  if (idLines.length === 0) {
    return {
      id,
      status: 'fail',
      message: `${IDENTITY} has no identity lines`,
      remediation: 'cipher-brain keygen --force',
    };
  }
  let derived: string[];
  try {
    derived = await Promise.all(idLines.map((l) => identityToRecipient(l)));
  } catch (e) {
    return { id, status: 'fail', message: `could not derive a public key from ${IDENTITY}: ${errMsg(e)}` };
  }
  const actual = new Set(await recipientEntries(RECIPIENT));
  const matches = derived.some((d) => actual.has(d));
  if (!matches) {
    return {
      id,
      status: 'fail',
      message: `${IDENTITY} does not match ${RECIPIENT} — deriving its public key gives a different value than what recipient.txt records; one of the two files was likely replaced independently`,
      remediation: `restore the correct pairing from a backup, or run 'cipher-brain keygen --force' to regenerate a fresh, MATCHING pair (only if you accept that any snapshot already encrypted under the old key stays recoverable solely by the old identity)`,
    };
  }
  return { id, status: 'pass', message: `${IDENTITY} matches the public key recorded in ${RECIPIENT}` };
}

// #101 is fixed at snapshot() time (an explicitly empty pin fails closed rather than
// silently disabling the allowlist) — but that failure only surfaces the NEXT time
// something snapshots, possibly unattended at 03:30. Catching it here, ahead of time,
// is the whole point of a doctor command: the same misconfiguration, found before it
// breaks a run instead of during one.
async function checkPinRecipients(): Promise<DoctorCheck[]> {
  const configId = 'pin-recipients-config';
  if (PIN_RECIPIENTS === undefined) {
    return [
      {
        id: configId,
        status: 'skip',
        message: 'CIPHER_BRAIN_PIN_RECIPIENTS is not set — no recipient allowlist configured (optional)',
      },
    ];
  }
  if (PIN_RECIPIENTS === '') {
    return [
      {
        id: configId,
        status: 'fail',
        message:
          'CIPHER_BRAIN_PIN_RECIPIENTS is set but EMPTY — every "cipher-brain snapshot" now refuses to run until this is fixed (fail-closed behavior, #101)',
        remediation: `unset CIPHER_BRAIN_PIN_RECIPIENTS (remove it from the environment, or from ${CONFIG_FILE_PATH}) to run without an allowlist, or set it to the age1… recipient(s) you intend to pin`,
      },
    ];
  }
  let allowed: Set<string>;
  try {
    allowed = await resolvePinnedRecipients(PIN_RECIPIENTS);
  } catch (e) {
    return [{ id: configId, status: 'fail', message: `could not resolve CIPHER_BRAIN_PIN_RECIPIENTS: ${errMsg(e)}` }];
  }
  if (allowed.size === 0) {
    return [
      {
        id: configId,
        status: 'fail',
        message:
          'CIPHER_BRAIN_PIN_RECIPIENTS is set but names no recognizable age1… recipient (a typo, or every entry is commented out)',
        remediation: 'fix the value/file, or unset CIPHER_BRAIN_PIN_RECIPIENTS to run without an allowlist',
      },
    ];
  }
  const results: DoctorCheck[] = [
    { id: configId, status: 'pass', message: `CIPHER_BRAIN_PIN_RECIPIENTS resolves to ${allowed.size} recipient(s)` },
  ];
  const includedId = 'pin-recipients-primary-included';
  if (!(await exists(RECIPIENT))) {
    results.push({
      id: includedId,
      status: 'skip',
      message: 'no primary recipient.txt to check against the allowlist yet',
    });
    return results;
  }
  const primary = await recipientEntries(RECIPIENT);
  const included = primary.some((r) => allowed.has(r));
  if (!included) {
    results.push({
      id: includedId,
      status: 'warn',
      message: `the primary recipient (${RECIPIENT}) is NOT in the CIPHER_BRAIN_PIN_RECIPIENTS allowlist — a plain "cipher-brain snapshot" with no --recipient override will be refused`,
      remediation: 'add the primary recipient to the allowlist, or always pass --recipient with a pinned key',
    });
  } else {
    results.push({
      id: includedId,
      status: 'pass',
      message: 'the primary recipient is included in the CIPHER_BRAIN_PIN_RECIPIENTS allowlist',
    });
  }
  return results;
}

// #99's fix was UX-only (the `init` wizard warns "same disk unless you change this" and
// suggests a default path) — there is no enforced separation, so this can only ever
// check the wizard's OWN suggested default (`${HOME}-backup`, wizard.ts's
// defaultBackupHome); a backup keypair generated at a custom path is invisible here.
const DEFAULT_BACKUP_HOME = `${HOME}-backup`;

async function checkOfflineBackupDisk(): Promise<DoctorCheck> {
  const id = 'offline-backup-different-disk';
  const backupIdentity = join(DEFAULT_BACKUP_HOME, 'identity.age');
  if (!(await exists(HOME)) || !(await exists(backupIdentity))) {
    return {
      id,
      status: 'skip',
      message: `no offline backup keypair found at the default location (${backupIdentity}) — this check only recognizes the 'init' wizard's suggested default path; a custom path is not detectable`,
    };
  }
  const [homeStat, backupStat] = await Promise.all([stat(HOME), stat(backupIdentity)]);
  if (homeStat.dev === backupStat.dev) {
    return {
      id,
      status: 'warn',
      message: `the offline backup keypair (${backupIdentity}) is on the SAME disk as the primary identity (${IDENTITY}) — a single disk failure could lose both`,
      remediation: `move ${DEFAULT_BACKUP_HOME} to a different disk or machine (e.g. an encrypted USB drive kept off-box)`,
    };
  }
  return {
    id,
    status: 'pass',
    message: 'the offline backup keypair is on a different disk/device than the primary identity',
  };
}

// Reuses schedule.ts's OWN status computation (scheduleStatusReport) rather than
// re-parsing logs itself, so this can never disagree with `cipher-brain schedule
// status` about what the last run did.
async function checkSchedule(): Promise<DoctorCheck[]> {
  let report: Awaited<ReturnType<typeof scheduleStatusReport>>;
  try {
    report = await scheduleStatusReport();
  } catch {
    return [
      {
        id: 'schedule-last-run',
        status: 'skip',
        message: 'no schedule installed (optional) — run "cipher-brain schedule install" to automate nightly snapshots',
      },
    ];
  }
  const results: DoctorCheck[] = [];
  if (!report.last_run) {
    results.push({ id: 'schedule-last-run', status: 'pass', message: 'schedule installed, no runs recorded yet' });
  } else if (report.last_run.rc_line.startsWith('FAILED')) {
    results.push({
      id: 'schedule-last-run',
      status: 'fail',
      message: `last scheduled run (${report.last_run.log}) failed: ${report.last_run.rc_line}`,
      remediation: `inspect ${report.last_run.log} in the schedule's logs directory for the cause, fix it, then confirm with a manual snapshot+push before trusting the next unattended run`,
    });
  } else {
    results.push({
      id: 'schedule-last-run',
      status: 'pass',
      message: `last scheduled run (${report.last_run.log}) succeeded: ${report.last_run.rc_line}`,
    });
  }
  if (report.trigger.loaded === 'no') {
    results.push({
      id: 'schedule-trigger-loaded',
      status: 'warn',
      message: `the ${report.trigger.type} trigger is written but not currently loaded/registered — scheduled runs will not happen`,
      remediation: 'cipher-brain schedule install (re-run with the same flags to re-register)',
    });
  } else {
    results.push({
      id: 'schedule-trigger-loaded',
      status: 'pass',
      message: `the ${report.trigger.type} trigger is registered`,
    });
  }
  return results;
}

// ---------- known-vs-new bookkeeping ----------

const STATE_SCHEMA = 1;

interface DoctorStateFile {
  schema: number;
  last_run: string;
  non_passing: Record<string, { status: 'warn' | 'fail'; since: string }>;
}

const doctorStatePath = (): string => join(HOME, 'doctor-state.json');

async function loadDoctorState(statePath: string): Promise<DoctorStateFile | null> {
  try {
    const parsed = JSON.parse(await readFile(statePath, 'utf8')) as Partial<DoctorStateFile>;
    if (parsed.schema !== STATE_SCHEMA || typeof parsed.non_passing !== 'object' || parsed.non_passing === null) {
      return null; // unknown/corrupt shape — treat as "no history" rather than guessing
    }
    return parsed as DoctorStateFile;
  } catch {
    return null; // missing (first-ever run) or unreadable
  }
}

async function saveDoctorState(
  statePath: string,
  nonPassing: DoctorStateFile['non_passing'],
  nowIso: string,
): Promise<boolean> {
  if (!(await exists(HOME))) return false; // never create HOME just to leave this file behind
  try {
    const body: DoctorStateFile = { schema: STATE_SCHEMA, last_run: nowIso, non_passing: nonPassing };
    await writeFile(statePath, `${JSON.stringify(body, null, 2)}\n`, { mode: 0o644 });
    return true;
  } catch {
    return false; // best-effort: a read-only CIPHER_BRAIN_HOME still gets a full report
  }
}

// ---------- report assembly + printing ----------

const STATUS_TAG: Record<CheckStatus, string> = { pass: 'PASS', warn: 'WARN', fail: 'FAIL', skip: 'SKIP' };

function printDoctorReport(report: DoctorReport): void {
  console.log('cipher-brain doctor — environment health check\n');
  for (const c of report.checks) {
    const marker =
      c.marker === 'new'
        ? ' \u{1F195} new'
        : c.marker === 'carryover'
          ? ` (known since ${(c.since ?? '').slice(0, 10)})`
          : '';
    console.log(`[${STATUS_TAG[c.status]}]${marker} ${c.message}`);
    if (c.remediation) console.log(`         remediation: ${c.remediation}`);
  }
  if (report.resolved.length > 0) {
    console.log('\nResolved since last run:');
    for (const r of report.resolved) console.log(`  [RESOLVED] ${r.message}`);
  }
  const scoreNote =
    report.new_count === 0 && report.carryover_count === 0
      ? '(no issues found)'
      : `(${report.new_count} new issue(s) counted in full; ${report.carryover_count} known, already-flagged issue(s) counted at a reduced weight — see remediation above)`;
  console.log(`\nhealth_score: ${report.health_score}/100 ${scoreNote}`);
  console.log(`VERDICT: ${report.verdict}`);
  if (!report.state_saved && (report.new_count > 0 || report.carryover_count > 0)) {
    console.log(
      `(note: could not persist ${report.state_path} — known-vs-new tracking will not carry over to the next run)`,
    );
  }
}

export async function computeDoctorReport(): Promise<DoctorReport> {
  const checks: DoctorCheck[] = [
    await checkHomeDirPerms(),
    await checkKeyPerms('identity-perms', IDENTITY, 'age identity (private key)'),
    await checkKeyPerms('sign-identity-perms', SIGN_IDENTITY, 'signing identity (private key)'),
    await checkKeyPerms('wallet-perms', AR_WALLET || WALLET_DEFAULT_PATH, 'arweave JWK wallet'),
    await checkIdentityRecipientPairing(),
    ...(await checkPinRecipients()),
    await checkOfflineBackupDisk(),
    ...(await checkSchedule()),
  ];

  const statePath = doctorStatePath();
  const prior = await loadDoctorState(statePath);
  const nowIso = new Date().toISOString();

  const results: DoctorCheckResult[] = [];
  const nextNonPassing: DoctorStateFile['non_passing'] = {};
  for (const c of checks) {
    if (c.status === 'warn' || c.status === 'fail') {
      const priorEntry = prior?.non_passing[c.id];
      const since = priorEntry?.since ?? nowIso;
      nextNonPassing[c.id] = { status: c.status, since };
      results.push({ ...c, marker: priorEntry ? 'carryover' : 'new', since });
    } else {
      results.push({ ...c, marker: null });
    }
  }

  const resolved: DoctorResolved[] = [];
  if (prior) {
    for (const [id, entry] of Object.entries(prior.non_passing)) {
      if (!(id in nextNonPassing)) {
        resolved.push({
          id,
          message: `${id}: previously ${entry.status} (since ${entry.since.slice(0, 10)}) — no longer flagged (fixed, or the check no longer applies this run)`,
        });
      }
    }
  }

  const stateSaved = await saveDoctorState(statePath, nextNonPassing, nowIso);

  // A NEW warn/fail costs more than the SAME one seen last run too — that discount (not
  // a full exclusion) is what "known issues excluded from the score" means here: a
  // lingering, already-flagged problem still pulls the score down (so a FAIL still
  // reads FAIL, never a misleading 100/100 next to VERDICT: FAIL), it just does not
  // re-trigger the FULL "something just got worse" penalty on every single run you
  // happen to check again without having fixed it yet.
  let healthScore = 100;
  let newCount = 0;
  let carryoverCount = 0;
  for (const r of results) {
    if (r.marker === 'new') {
      newCount++;
      healthScore -= r.status === 'fail' ? 30 : 10;
    } else if (r.marker === 'carryover') {
      carryoverCount++;
      healthScore -= r.status === 'fail' ? 10 : 3;
    }
  }
  healthScore = Math.max(0, healthScore);

  const anyFail = results.some((r) => r.status === 'fail');
  const anyWarn = results.some((r) => r.status === 'warn');
  const verdict: DoctorReport['verdict'] = anyFail ? 'FAIL' : anyWarn ? 'PARTIAL' : 'PASS';

  return {
    checks: results,
    resolved,
    health_score: healthScore,
    new_count: newCount,
    carryover_count: carryoverCount,
    verdict,
    state_path: statePath,
    state_saved: stateSaved,
  };
}

export async function doctor(o: CliOptions): Promise<void> {
  const report = await computeDoctorReport();
  if (o.json) {
    printJson(report);
  } else {
    printDoctorReport(report);
  }
  if (report.verdict === 'FAIL') process.exitCode = 1;
  else if (report.verdict === 'PARTIAL') process.exitCode = 2; // same convention as `verify`
  if (!o.json) printMascot(moodForVerdict(report.verdict));
}
