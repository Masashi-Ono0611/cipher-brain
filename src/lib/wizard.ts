// wizard — `cipher-brain init`: an interactive, end-to-end setup wizard for a FRESH
// machine (issue #68). It walks keygen -> backup-key guidance -> passphrase wrap ->
// recipient pin -> profile selection -> first snapshot+push -> a printable recovery
// kit, in one sitting.
//
// This is an ORCHESTRATION layer over the EXISTING primitives (keygen/snapshot/push)
// — it adds no new crypto, storage or consent logic of its own. Every safety check
// those primitives already enforce (identity no-clobber, the paid-backend --yes gate,
// the recipient-pin allowlist, snapshot's single-recipient warning, etc.) still fires
// exactly as it does when those commands are run directly, because the wizard calls
// the SAME functions with the SAME options — it never bypasses or duplicates them.
//
// Interactivity: non-secret yes/no and path/text prompts use node:readline/promises
// (visible echo, stdlib, zero dependency) via askLine/askYesNo below. Anything secret
// (the passphrase) reuses crypt.ts's EXISTING promptHidden-backed askNewPassphrase +
// wrapIdentity — never reimplemented here. `init` is fundamentally an interactive
// command: it refuses immediately (requireTTY) if stdin is not a TTY — the same
// non-interactive-safety posture promptHidden already has — rather than hanging or
// behaving unpredictably under a CI/pipe invocation.
import { createInterface } from 'node:readline/promises';
import { readFile, writeFile, mkdir, rm, rename } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { homedir, userInfo } from 'node:os';
import { randomBytes } from 'node:crypto';
import { HOME, IDENTITY, RECIPIENT } from './config.js';
import { keygen, keygenAt } from './keys.js';
import { askNewPassphrase, wrapIdentity } from './crypt.js';
import { PROFILE_NAMES } from './profiles.js';
import { snapshot } from './snapshot.js';
import { push, PushLocatorWriteError } from './pushpull.js';
import { BACKEND_NAMES } from './backends/index.js';
import { exists, errMsg } from './util.js';
import type { CliOptions } from './types.js';

type Rl = ReturnType<typeof createInterface>;

// `init` is fundamentally interactive: a plain non-TTY invocation (piped/redirected
// stdin, a CI job with no terminal attached) must refuse cleanly here rather than
// hang forever on the first prompt (readline's question() never resolves on a stream
// that reaches EOF without a line — proven while building this: `init < /dev/null`
// hangs, it does not error). This mirrors promptHidden's own TTY posture (crypt.ts),
// but — same shape as that module's OWN escape hatch, where CIPHER_BRAIN_PASSPHRASE
// lets automation skip the hidden prompt entirely rather than needing a real TTY —
// deliberate automation (this repo's own scripts/selftest-init.sh) opts in with
// CIPHER_BRAIN_INIT_ALLOW_NONINTERACTIVE=1 instead of needing a genuine pseudo-tty.
// A real terminal never needs to set this; it exists solely so the wizard's own
// scripted end-to-end selftest can drive it deterministically.
function requireTTY(): void {
  if (process.stdin.isTTY) return;
  if (process.env.CIPHER_BRAIN_INIT_ALLOW_NONINTERACTIVE === '1') return;
  throw new Error(
    'cipher-brain init is an interactive wizard and requires stdin to be a TTY — run it directly in a ' +
    'terminal, not via a pipe, a redirected file, or in CI (same posture keygen --passphrase already has ' +
    'for its passphrase prompt). For a non-interactive/scripted setup, drive the individual commands it ' +
    'wraps (keygen, snapshot, push, schedule) by hand instead; see MANAGEMENT.md.',
  );
}

async function askLine(rl: Rl, question: string, def = ''): Promise<string> {
  const answer = (await rl.question(question)).trim();
  return answer || def;
}

// A wizard prompt reads its answer as a plain string — no shell is ever involved, so a
// leading `~` in a path-like answer (a very natural thing to type, e.g. `~/vault`) is
// NOT expanded the way it would be if the same string were a shell argument to the
// equivalent manual CLI flag. Left alone this silently produces a wrong path (a literal
// `~`-named entry relative to cwd, or a nonexistent path) instead of the user's actual
// home directory. Mirrors just the common shell cases — bare `~` and `~/...` — not full
// `~username` expansion (out of scope here). Applied at every prompt below that collects
// a filesystem path.
function expandHome(path: string): string {
  if (path === '~') return homedir();
  if (path.startsWith('~/')) return join(homedir(), path.slice(2));
  return path;
}

async function askYesNo(rl: Rl, question: string, def: boolean): Promise<boolean> {
  const answer = (await askLine(rl, `${question} [${def ? 'Y/n' : 'y/N'}] `)).toLowerCase();
  if (!answer) return def;
  return answer === 'y' || answer === 'yes';
}

// The recovery kit is a long-lived, physically-stored document, and a Postgres
// connection string can embed a password (unlike the age identity, which the kit's
// whole job IS to carry off-machine, the DB credential is only shown here for
// REFERENCE — "this was the source, do not restore into it"). Strip a password before
// it goes in (Fugu review finding); the username alone is left visible — it is not
// itself a secret, and this project's own docs already print it in the clear (e.g.
// README's `postgres://user@localhost:5432/gbrain` examples, and this wizard's own
// peer-auth-style default a few lines below). Falls back to a conservative regex
// redact for a non-URL keyword/value DSN (e.g. "host=... password=..."), which --pg
// accepts just as pg_dump/pg_restore themselves do but the WHATWG URL parser cannot.
// The two standard libpq keywords that can carry a credential value (the connection
// password, and the passphrase for an --sslkey client certificate) — checked
// case-insensitively below since libpq's own keyword matching is (Grok review).
const PG_SECRET_KEYS = /^(password|sslpassword)$/i;

function redactPgConn(conn: string): string {
  try {
    const u = new URL(conn);
    if (u.password) u.password = '';
    // libpq connection URIs also accept a credential as an ordinary query parameter
    // (postgres://user@host/db?password=...) — the user:pass@ authority form above is
    // not the only place it can hide (Fugu review finding, round 2). Iterate keys
    // rather than a fixed .has('password') lookup: URLSearchParams keys are
    // case-sensitive, so a literal check would miss e.g. ?Password= (Grok review).
    for (const key of [...u.searchParams.keys()]) {
      if (PG_SECRET_KEYS.test(key)) u.searchParams.set(key, 'REDACTED');
    }
    return u.toString();
  } catch {
    // Keyword/value DSN form (e.g. "host=... password=..."). A value may be a bare
    // token, or quoted (single OR double — Grok review noted only single was handled;
    // libpq's own conninfo grammar only recognizes single quotes, but matching both is
    // a strictly safer over-match here) optionally containing escaped characters (e.g.
    // password='a\'b c') — match any of these shapes rather than only \S+, which would
    // leave a trailing fragment of a quoted, space-containing secret unredacted.
    const secretVal = `(?:'(?:[^'\\\\]|\\\\.)*'|"(?:[^"\\\\]|\\\\.)*"|\\S+)`;
    return conn.replace(/:\/\/([^:@/]+):[^@/]*@/, '://$1@').replace(new RegExp(`\\b(password|sslpassword)=${secretVal}`, 'gi'), '$1=REDACTED');
  }
}

interface BackupKey {
  identityPath: string;
  recipientPath: string;
  recipient: string;
  identityText: string; // the raw file contents (unwrapped) — inlined into the kit
}

// The recovery kit: one printable plain-text page (Bitwarden-emergency-kit style),
// chosen over HTML->PDF deliberately (see issue #68 / cli.ts's file-header comment on
// the INLINE-vs-external Bun.build split) — zero new dependencies, greppable, and
// printable from any editor. Content mirrors MANAGEMENT.md's "Key recovery" section:
// the backup identity (if any) is INLINED here since printing this page IS how it
// leaves the machine to go offline; the primary identity is only referenced by
// location (it is already durably on this machine and duplicating a live secret into
// a file whose whole purpose is to also leave the building would only multiply risk).
interface KitInputs {
  primaryIdentityPath: string;
  primaryRecipient: string;
  backup: BackupKey | null;
  pinRecipientsLine: string | null;
  savedLocatorLine: string;
  profile: string;
  backend: string;
  pg: string | null; // the --pg connection string used, if a Postgres dump was included (issue #84)
  generatedAt: string;
}

function buildRecoveryKit(k: KitInputs): string {
  const lines: string[] = [];
  lines.push('='.repeat(72));
  lines.push('CIPHER-BRAIN RECOVERY KIT — KEEP THIS OFFLINE / PHYSICALLY SECURE');
  lines.push('This file contains SECRET key material. Anyone holding it can decrypt');
  lines.push('every cipher-brain snapshot encrypted to the key(s) below. Print it,');
  lines.push('store it somewhere physically secure (a safe, a password manager secure');
  lines.push('note, a trusted person) AWAY from this machine, then treat it like cash.');
  lines.push('='.repeat(72));
  lines.push('');
  lines.push(`Kit generated: ${k.generatedAt}`);
  lines.push(`Profile used:  ${k.profile}`);
  lines.push(`Backend used:  ${k.backend}`);
  lines.push(`Postgres dump: ${k.pg ? `included (connection: ${redactPgConn(k.pg)})` : 'not included'}`);
  lines.push('');
  lines.push('--- PRIMARY IDENTITY (already on this machine — not duplicated here) ---');
  lines.push(`Location:  ${k.primaryIdentityPath}`);
  lines.push(`Recipient (public, safe to share): ${k.primaryRecipient}`);
  lines.push('');
  if (k.backup) {
    lines.push('--- BACKUP IDENTITY (SECRET — this is what lets a fresh machine restore) ---');
    lines.push(`Location on THIS machine (move it off-box): ${k.backup.identityPath}`);
    lines.push(`Recipient (public, safe to share): ${k.backup.recipient}`);
    lines.push('');
    lines.push('BEGIN BACKUP IDENTITY FILE');
    lines.push(k.backup.identityText.replace(/\n+$/, ''));
    lines.push('END BACKUP IDENTITY FILE');
    lines.push('');
  } else {
    lines.push('--- BACKUP IDENTITY ---');
    lines.push('None was generated during init. The PRIMARY identity above is the only key');
    lines.push('that can restore — losing it loses the brain. MANAGEMENT.md "Key recovery #1"');
    lines.push('recommends adding an offline backup key: CIPHER_BRAIN_HOME=<path> cipher-brain keygen');
    lines.push('');
  }
  lines.push('--- LATEST SAVE-LOCATOR (back this up off-box, next to the backup identity) ---');
  lines.push('BEGIN SAVE-LOCATOR LINE');
  lines.push(k.savedLocatorLine);
  lines.push('END SAVE-LOCATOR LINE');
  lines.push('');
  lines.push('--- CIPHER_BRAIN_PIN_RECIPIENTS (add to your shell rc, e.g. ~/.zshrc or ~/.bashrc) ---');
  lines.push(k.pinRecipientsLine ?? '(skipped during init — see MANAGEMENT.md / "cipher-brain help" for what this does)');
  lines.push('');
  lines.push('--- RECOVERY STEPS (run these on ANY machine with Node >=22.6 and this npm package installed) ---');
  // Deliberately do NOT auto-append --pg (with the SOURCE connection string) to the
  // restore commands below: pg_restore --clean --if-exists DROPS/replaces objects in
  // whatever database --pg names, so blindly reusing the dump's SOURCE as the restore
  // TARGET on a verbatim copy-paste risks clobbering a live database. MANAGEMENT.md's
  // own restore runbook is explicit about this ("rebuild into a SCRATCH database, never
  // straight over a live one") — the Postgres block below points there instead of
  // encouraging a single dangerous copy-paste command (Fugu review finding).
  if (k.backend === 'file') {
    lines.push('!!! LOCATOR IS LOCAL-ONLY: this backup used the "file" backend, so the save-locator line above');
    lines.push('    points at a path inside a local object store (CIPHER_BRAIN_FILE_DIR) on THIS machine — it');
    lines.push('    is NOT reachable from a different machine unless that whole store directory is also copied');
    lines.push('    there. Step 4 below (pull --from-locator-file) will fail on another machine as written. For');
    lines.push('    genuine cross-machine recovery, re-run push with a network backend (arweave/turbo), or');
    lines.push('    manually copy the file-backend store alongside this kit. See MANAGEMENT.md "Key recovery #3".');
    lines.push('');
  }
  if (k.backup) {
    lines.push('An operator with ZERO prior knowledge of this repo can follow these verbatim. The two marker');
    lines.push('blocks above (each a single BEGIN/END pair, unique in this file) are the two things you copy:');
    lines.push('  1) npm install -g cipher-brain          (or: npx cipher-brain@latest <command>)');
    lines.push('  2) Copy the BACKUP IDENTITY block above (the lines between its BEGIN and END markers,');
    lines.push('     not including the marker lines themselves) into its own file, e.g.: ~/restore-identity.age');
    lines.push('  3) Copy the SAVE-LOCATOR line above (between its BEGIN and END markers) into its own');
    lines.push('     file, e.g.: ~/restore-locator.tsv');
    lines.push('  4) cipher-brain pull --from-locator-file ~/restore-locator.tsv --out ~/restored.age');
    lines.push('  5) cipher-brain restore --in ~/restored.age --out-dir ~/restored --identity ~/restore-identity.age');
    lines.push('     (if the identity above is passphrase-wrapped, this step prompts for that passphrase)');
  } else {
    lines.push('!!! NO BACKUP IDENTITY IS IN THIS KIT: true kit-only recovery — restoring on a fresh machine');
    lines.push('    with ZERO other prior knowledge — is NOT possible right now. The only thing that can');
    lines.push('    decrypt any snapshot encrypted so far is the PRIMARY identity above, and it was');
    lines.push('    deliberately NOT copied into this kit (it already lives durably on THIS machine — printing');
    lines.push('    a backup identity into the kit is how a SECOND key leaves the machine; there is no second');
    lines.push('    key here). See MANAGEMENT.md "Key recovery #1".');
    lines.push('');
    lines.push('Your actual options:');
    lines.push('  * Restore using the PRIMARY identity itself, wherever it currently lives (this machine, or');
    lines.push(`    a copy of it you separately made outside of this kit): ${k.primaryIdentityPath}`);
    lines.push('    (possibly passphrase-protected, per step 3 of the wizard — restore then prompts for it).');
    lines.push('    Copy the SAVE-LOCATOR line above into its own file, e.g. ~/restore-locator.tsv, then:');
    lines.push('      cipher-brain pull --from-locator-file ~/restore-locator.tsv --out ~/restored.age');
    lines.push(`      cipher-brain restore --in ~/restored.age --out-dir ~/restored --identity ${k.primaryIdentityPath}`);
    lines.push('  * For real kit-based portable recovery (any machine, zero prior knowledge), a backup');
    lines.push('    identity has to exist and be inlined in the kit. To get there: generate one —');
    lines.push('    "CIPHER_BRAIN_HOME=<path> cipher-brain keygen" — then re-snapshot encrypting to BOTH the');
    lines.push('    primary recipient.txt (next to the primary identity above) and the new backup');
    lines.push('    recipient.txt (see MANAGEMENT.md "Key recovery #1"), then generate a fresh kit so it');
    lines.push('    inlines the new backup identity.');
    lines.push('  * The SAVE-LOCATOR and CIPHER_BRAIN_PIN_RECIPIENTS sections above are still valid, useful');
    lines.push('    information regardless of the above — only "restore using just this kit alone" carries');
    lines.push('    this caveat.');
  }
  if (k.pg) {
    lines.push('');
    lines.push('!!! THIS BACKUP ALSO INCLUDES A POSTGRES DUMP: the restore command(s) above extract db.dump into');
    lines.push('    --out-dir but deliberately do NOT pg_restore it (no --pg is included above).');
    lines.push(`    Its SOURCE connection was: ${redactPgConn(k.pg)}`);
    lines.push('    Do NOT pg_restore into that same database — "pg_restore --clean --if-exists" DROPS/replaces');
    lines.push('    objects in whatever database --pg names. Add --pg pointing at a SCRATCH database (never the');
    lines.push('    source above) to the restore command; see MANAGEMENT.md "Restore runbook" step 4 for the');
    lines.push('    exact pattern.');
  }
  lines.push('');
  lines.push('--- WHAT TO DO WITH THIS FILE ---');
  lines.push('Print this page and store it securely, physically away from this machine. Once it');
  lines.push('is secured, you MAY delete this file from disk — that is a manual step; cipher-brain');
  lines.push('does not delete it for you.');
  lines.push('');
  return lines.join('\n');
}

export async function init(_o: CliOptions): Promise<void> {
  requireTTY();
  if (await exists(IDENTITY)) {
    throw new Error(
      `an identity already exists at ${IDENTITY} — "cipher-brain init" is for a FRESH setup, not overwriting ` +
      `one. To redo it deliberately, run "cipher-brain keygen --force" (overwrites the identity — you lose ` +
      `access to anything only that identity could decrypt) or drive keygen/snapshot/push/schedule by hand; ` +
      `see MANAGEMENT.md.`,
    );
  }

  console.log('cipher-brain init — interactive setup: keygen, key recovery, first snapshot + push, recovery kit.\n');

  let rl = createInterface({ input: process.stdin, output: process.stdout });
  try {
    // ---------- 1. primary keygen (reuses keygen() verbatim — no reimplementation) ----------
    console.log('== 1/6: generating your primary identity ==');
    // keygen() -> keygenAt() (keys.ts) writes identity.age THEN recipient.txt — if the
    // recipient.txt write throws (a pre-existing dir at that path, ENOSPC, a permission
    // error, a concurrent process, ...) identity.age is already on disk but keygen()
    // still rejects. This call is BEFORE the rollback-tracking try below even starts
    // (deliberately — everything inside that try is retry-safe via the catch further
    // down), so without this its own try/catch a partial keygen here would leave an
    // orphaned identity.age that nothing ever cleans up: every future `init` on this
    // CIPHER_BRAIN_HOME hits the "identity already exists" refusal forever, with no
    // rollback path to escape it (unlike every failure inside the try below).
    // IDENTITY itself is provably absent here — the exists() refusal above already
    // guarantees that, unconditionally, before this try even starts. RECIPIENT is not
    // covered by that same guarantee: it could already sit on disk as an orphan from
    // some earlier, unrelated mistake (a stray recipient.txt with no matching
    // identity.age) even though IDENTITY is absent. Checking THAT before this call —
    // and only deleting it in the catch if it did not already exist — keeps this
    // rollback to "only what this invocation itself created", the same principle the
    // backup-key rollback below applies.
    const recipientPreExisted = await exists(RECIPIENT);
    try {
      await keygen({ dirs: [], tables: [], recipients: [] });
    } catch (e) {
      await rm(IDENTITY, { force: true });
      if (!recipientPreExisted) await rm(RECIPIENT, { force: true });
      throw e;
    }

    // From here on, THIS invocation just created the primary identity — the exists()
    // refusal above already guarantees it did not exist before this run started, so any
    // failure in the rest of the flow (an invalid answer, a declined paid-backend
    // consent, a missing optional dependency, a recovery-kit write error, ...) must not
    // leave that identity behind. `init` refuses unconditionally whenever IDENTITY
    // already exists, so a half-finished run would otherwise permanently block a clean
    // retry — the user's only escape would be the scarier, undocumented-to-them
    // `keygen --force`. Roll back exactly what THIS run created (never anything from a
    // prior, already-completed setup — that case never reaches here, it was refused
    // above before this try started), then re-throw so the original error still
    // surfaces unchanged.
    let backup: BackupKey | null = null;
    // Set the moment snapshot() below actually succeeds — never before. snapshot()'s own
    // promote step (promoteSnapshot in snapshot.ts) only renames/links its .part onto
    // o.out on success, so if snapshot() itself throws, o.out (and its sidecars) were
    // never created and there is nothing here to roll back. If a LATER step fails (push,
    // the recovery-kit write, ...), the dated snapshot file it did produce — plus its
    // `.digest` / `.recipients-fingerprint` sidecars — must still be deleted: snapshot()
    // refuses to overwrite an existing --out (no-clobber), and the wizard's --out is
    // dated per-day, so leaving them behind would make a same-day retry fail again at
    // this exact step even though the rollback below already cleared the identity.
    let snapshotOutPath: string | null = null;
    // True once push() below actually returns successfully. From that point on the
    // ciphertext already exists, durably, in the chosen backend's store — for
    // arweave/turbo that store is PAID and PERMANENT (irreversible; real funds were
    // just spent), and even the free "file" backend now has an object keyed to these
    // identities. The primary/backup identities are the ONLY thing that can ever
    // decrypt that artifact from here on, so once this flips true the catch block
    // below must NEVER delete them, no matter what fails afterward (kit write,
    // chmod, ...) — doing so would turn "the kit step needs a retry" into "a
    // permanent, already-paid-for snapshot with no key left able to decrypt it,
    // ever." Only failures BEFORE this flips true still get the full rollback below.
    let pushSucceeded = false;
    let pushedBackend: string | null = null;
    let pushedLocatorPath: string | null = null;
    try {
      // ---------- 2. backup key guidance (MANAGEMENT.md Key recovery #1) ----------
      console.log('\n== 2/6: offline backup key (recommended) ==');
      console.log(
        'cipher-brain gives you two independent defenses against losing the primary identity; the first is a\n' +
        'second, OFFLINE backup keypair. If you encrypt every snapshot to BOTH the primary and the backup\n' +
        'public key, either identity alone can restore — see MANAGEMENT.md "Key recovery #1".',
      );
      if (await askYesNo(rl, 'Generate an offline backup keypair now?', true)) {
        // Shown BEFORE the path prompt (and BEFORE keygenAt() below writes anything) —
        // not after, like it used to be. The old order printed this warning only once
        // the keypair was already on disk and a "backup identity written to: ..." success
        // line had already gone by, which reads as "done" and makes a one-line warning
        // easy to skim past. The default path below (`${HOME}-backup`) sits right next to
        // the primary identity on the SAME disk, so the "move this off-box" instruction
        // needs to land before the user accepts that default, not after.
        console.log('⚠  This will still be written ON this machine — move it OFF-BOX (encrypted USB, a second');
        console.log('   location, a trusted person) once it is written; the recovery kit at the end restates this.');
        const defaultBackupHome = `${HOME}-backup`;
        const backupHome = expandHome(await askLine(rl, `Path for the backup keypair (same disk unless you change this) [${defaultBackupHome}]: `, defaultBackupHome));
        const identityPath = join(backupHome, 'identity.age');
        const recipientPath = join(backupHome, 'recipient.txt');
        // Same partial-write hazard as the primary keygen above (identity.age written,
        // then recipient.txt's write throws) — but here it CANNOT rely on the outer
        // catch's `if (backup) { rm(...) }` rollback, because `backup` itself is only
        // assigned a few lines below, AFTER this call returns successfully. If
        // keygenAt() throws here, `backup` is still null when that catch runs, so its
        // rollback branch never fires and the orphaned backup identity.age survives.
        // Clean up right here, independent of the `backup` variable's later assignment.
        //
        // Unlike the primary keygen above, this path CANNOT assume identityPath/
        // recipientPath are absent beforehand — backupHome is a user-typed answer, and
        // nothing stops them from pointing it at a directory that already holds a REAL,
        // previously-set-up backup identity (e.g. re-running this step against their
        // existing offline backup location). keygenAt() itself already refuses to
        // overwrite an existing identityPath (see keys.ts) and throws BEFORE writing
        // anything in that case — so an unconditional rm here would delete that real,
        // pre-existing backup identity for no reason other than "keygenAt declined to
        // clobber it", which is strictly worse than the partial-write hazard this catch
        // exists to fix (a blocked retry vs. permanent, unrecoverable loss of a real
        // key). Check existence of each target BEFORE calling keygenAt, and only remove
        // whichever ones did NOT already exist beforehand.
        const identityPreExisted = await exists(identityPath);
        const recipientPreExisted = await exists(recipientPath);
        let recipient: string;
        try {
          ({ recipient } = await keygenAt({ home: backupHome, identityPath, recipientPath }));
        } catch (e) {
          if (!identityPreExisted) await rm(identityPath, { force: true });
          if (!recipientPreExisted) await rm(recipientPath, { force: true });
          throw e;
        }
        const identityText = await readFile(identityPath, 'utf8');
        backup = { identityPath, recipientPath, recipient, identityText };
        console.log(`backup identity written to: ${identityPath}`);
      } else {
        console.log('Skipping the backup key. You can add one later at any time: CIPHER_BRAIN_HOME=<path> cipher-brain keygen');
      }

      // ---------- 3. passphrase wrap the primary identity (MANAGEMENT.md Key recovery #2) ----------
      console.log('\n== 3/6: protect the primary identity at rest (recommended) ==');
      console.log(
        'The identity file just written is a bare secret guarded only by file permissions (0600) — anyone who\n' +
        'copies it off this machine can decrypt every snapshot. A passphrase wrap (scrypt, the same "keygen\n' +
        '--passphrase" flag uses) makes an exfiltrated identity file useless without it. See MANAGEMENT.md\n' +
        '"Key recovery #2".',
      );
      if (await askYesNo(rl, 'Protect the primary identity with a passphrase now?', false)) {
        // Reuses the EXACT same pieces keygen --passphrase uses (askNewPassphrase / wrapIdentity from
        // crypt.ts) — the identity was just written unwrapped above, so this wraps it in place rather
        // than re-generating (keygenAt's own wrap-at-creation path is for a keypair that does not exist
        // yet; here we already have the one we want to protect).
        //
        // askNewPassphrase() -> promptHidden (crypt.ts) puts stdin into raw mode and manages its OWN
        // 'data' listener directly, bypassing readline entirely. Doing that while this wizard's OWN
        // readline Interface is still attached to the SAME stdin is a real bug under a genuine TTY: two
        // competing consumers of one stdin leave it unable to deliver input to a LATER rl.question() —
        // confirmed empirically with a real pty harness (python's stdlib pty module driving this exact
        // path): the wizard silently exited after this step, never reaching step 4's prompt. Fully close
        // this interface before the hidden-prompt path, then open a fresh one for the remaining prompts.
        rl.close();
        const text = await readFile(IDENTITY, 'utf8');
        const payload = await wrapIdentity(text, await askNewPassphrase());
        await writeFile(IDENTITY, payload, { mode: 0o600 });
        console.log(`identity re-written, passphrase-wrapped: ${IDENTITY}`);
        rl = createInterface({ input: process.stdin, output: process.stdout });
      } else {
        console.log('Skipping the passphrase wrap. You can wrap it later by re-running keygen --passphrase --force,');
        console.log('or by full-disk-encrypting the machine that holds the identity (MANAGEMENT.md recommends both).');
      }

      // ---------- 4. recipient pin suggestion (CIPHER_BRAIN_PIN_RECIPIENTS) ----------
      console.log('\n== 4/6: recipient pin (optional, recommended) ==');
      console.log(
        'CIPHER_BRAIN_PIN_RECIPIENTS is an env var snapshot reads at run time: when set, it refuses to encrypt\n' +
        'to any recipient NOT on the list — so a tampered recipient.txt, or an injected extra --recipient, can\n' +
        'never silently re-key your snapshots to an attacker. It is not something init can "turn on" for you\n' +
        'persistently (it is read from the environment at snapshot time, not a file init controls) — the most\n' +
        'this wizard can do is suggest the exact line to add to your shell rc file yourself.',
      );
      let pinRecipientsLine: string | null = null;
      if (await askYesNo(rl, 'Show a suggested CIPHER_BRAIN_PIN_RECIPIENTS line for your shell rc file?', true)) {
        const primaryPub = (await readFile(RECIPIENT, 'utf8')).trim();
        const defaultLine = `export CIPHER_BRAIN_PIN_RECIPIENTS="${[primaryPub, backup?.recipient].filter(Boolean).join(' ')}"`;
        pinRecipientsLine = await askLine(rl, `Suggested line (edit or press Enter to accept):\n${defaultLine}\n> `, defaultLine);
        console.log(`\nAdd this to your shell rc (~/.zshrc / ~/.bashrc), then open a new shell:\n${pinRecipientsLine}`);
      } else {
        console.log('Skipping the recipient pin suggestion.');
      }

      // ---------- 5. profile selection ----------
      console.log('\n== 5/6: what to back up ==');
      console.log(`Available profiles (one-flag source presets): ${PROFILE_NAMES.join(', ')}. Or "none" to point at`);
      console.log('directories yourself (the same as passing --dir manually to snapshot later).');
      const profileChoice = await askLine(rl, `Profile [none/${PROFILE_NAMES.join('/')}] (default none): `, 'none');
      const snapshotOpts: CliOptions = { dirs: [], tables: [], recipients: [] };
      if (profileChoice === 'none') {
        const dirsInput = await askLine(rl, 'Directory path(s) to back up, comma-separated (at least one, required): ');
        const dirs = dirsInput.split(',').map((d) => expandHome(d.trim())).filter(Boolean);
        if (dirs.length === 0) throw new Error('no directory given — "cipher-brain init" cannot produce an empty snapshot; re-run and pass at least one path, or pick a profile');
        snapshotOpts.dirs = dirs;
      } else if (PROFILE_NAMES.includes(profileChoice)) {
        snapshotOpts.profile = profileChoice;
        if (profileChoice === 'obsidian') snapshotOpts.vault = expandHome(await askLine(rl, 'Path to your Obsidian vault (must contain .obsidian/): '));
        if (profileChoice === 'chatgpt-export') snapshotOpts.zip = expandHome(await askLine(rl, 'Path to the official ChatGPT export .zip: '));
      } else {
        throw new Error(`unknown profile "${profileChoice}" — valid choices: none, ${PROFILE_NAMES.join(', ')}`);
      }

      // gbrain (this project's headline use case — README/MANAGEMENT.md) keeps its
      // ACTUAL data (pages, embeddings, timeline, graph) in Postgres — the ~/.gbrain
      // directory above is only its config/cache. There is no gbrain-specific profile
      // (PROFILE_NAMES), so the natural-looking answer above ("none" + ~/.gbrain)
      // silently backs up only the config and never the real data (issue #84). Only
      // ask when a local gbrain config is actually detected: everyone else's flow is
      // completely unchanged, and init already documents that anything beyond its
      // opinionated fast path is driven by hand (see requireTTY's own message above).
      const gbrainConfigPath = join(homedir(), '.gbrain', 'config.json');
      if (await exists(gbrainConfigPath)) {
        console.log(`\nDetected a gbrain config at ${gbrainConfigPath} — gbrain's actual data (pages, embeddings,`);
        console.log('timeline, graph) lives in Postgres, not in that directory alone. Requires pg_dump/pg_restore');
        console.log('on PATH — see README "Prerequisites for --pg".');
        if (await askYesNo(rl, 'Include a Postgres database dump (--pg) for gbrain in this backup?', true)) {
          // Default to the CURRENT machine's OS user — local Postgres setups commonly use
          // peer auth keyed to it (matches README's own --pg examples), so this is a real
          // guess rather than a literal "you" placeholder nobody's account is ever named
          // (Fugu review finding: a bare-Enter accept should not likely fail pg_dump).
          let osUser = 'you';
          try { osUser = userInfo().username; } catch { /* keep the 'you' fallback */ }
          // percent-encode: a username with '@', ':', '/', or a space would otherwise
          // corrupt the URI's own authority parsing (Fugu review finding).
          const defaultPg = `postgres://${encodeURIComponent(osUser)}@localhost:5432/gbrain`;
          snapshotOpts.pg = await askLine(rl, `Postgres connection string [${defaultPg}]: `, defaultPg);
        }
      }

      // ---------- 6. initial snapshot + push ----------
      console.log('\n== 6/6: first snapshot + push ==');
      console.log(`Storage backends: ${BACKEND_NAMES.join(', ')}. arweave/turbo are PAID, permanent stores.`);
      const backend = await askLine(rl, `Backend [${BACKEND_NAMES.join('/')}] (default file): `, 'file');
      if (!(BACKEND_NAMES as readonly string[]).includes(backend)) {
        throw new Error(`unknown backend "${backend}" — valid choices: ${BACKEND_NAMES.join(', ')}`);
      }
      const paid = backend === 'arweave' || backend === 'turbo';
      if (paid) {
        const consent = await askYesNo(
          rl,
          `${backend} is a PAID, PERMANENT store — uploading spends real funds and cannot be undone. Proceed?`,
          false,
        );
        if (!consent) {
          throw new Error(`aborted before spending — re-run "cipher-brain init" and choose "file" (free) instead, or run keygen/snapshot/push by hand once you are ready to pay; see MANAGEMENT.md.`);
        }
      } else if (backend === 'file') {
        // issue #85: "file" is the silent Enter-key default, and it is NOT offsite —
        // the recovery kit's own "LOCATOR IS LOCAL-ONLY" block (buildRecoveryKit above)
        // already says so, but until now that warning was invisible unless someone
        // opened the printed kit. Surface it here, interactively, before the push
        // happens, and again in the completion summary below.
        console.log(
          '\n⚠  "file" stores the pushed ciphertext ONLY on this machine (CIPHER_BRAIN_FILE_DIR) — it is NOT\n' +
          '   reachable from any other machine. If this machine is lost, this backup cannot be recovered\n' +
          '   elsewhere. For real offsite recovery, re-run and choose arweave or turbo (paid) instead; see\n' +
          '   MANAGEMENT.md "Key recovery #3".',
        );
      }

      snapshotOpts.recipients = [RECIPIENT, ...(backup ? [backup.recipientPath] : [])];
      const dateStamp = new Date().toISOString().slice(0, 10);
      const outPath = join(HOME, `brain-${dateStamp}.age`);
      snapshotOpts.out = outPath;
      await snapshot(snapshotOpts);
      snapshotOutPath = outPath; // recorded only now — snapshot() has durably written it

      const locatorPath = join(HOME, 'latest-locator.tsv');
      const pushOpts: CliOptions = { dirs: [], tables: [], recipients: [] };
      pushOpts.in = outPath;
      pushOpts.backend = backend;
      pushOpts.save_locator = locatorPath;
      // The wizard's own explicit, just-asked confirmation above IS the human consent
      // push()'s paid-backend gate requires — set the same --yes equivalent a human
      // would pass on the command line. The gate itself is UNCHANGED and still fires
      // for anyone who does not go through this confirmation (push.ts is untouched).
      if (paid) pushOpts.yes = true;
      let savedLocatorLine: string;
      try {
        await push(pushOpts);
        // Push has now durably happened — see the pushSucceeded declaration above for
        // why the catch block's rollback boundary hinges on exactly this line.
        pushSucceeded = true;
        pushedBackend = backend;
        pushedLocatorPath = locatorPath;
        savedLocatorLine = (await readFile(locatorPath, 'utf8')).split('\n').find((l) => l.trim()) ?? '';
      } catch (pushErr) {
        if (pushErr instanceof PushLocatorWriteError) {
          // The upload itself (backend.put()) already succeeded — see
          // PushLocatorWriteError's own doc comment in pushpull.ts. The remote
          // artifact durably exists (permanently, on arweave/turbo) even though
          // locatorPath was never written, so this is exactly as unrollbackable as
          // an ordinary successful push: flip pushSucceeded so the outer catch below
          // preserves the identities/snapshot instead of deleting them, but leave
          // pushedLocatorPath null (there genuinely is no locator FILE on disk this
          // time — only the value inside pushErr.locator, which the thrown error
          // below surfaces for the operator to record by hand).
          pushSucceeded = true;
          pushedBackend = backend;
          pushedLocatorPath = null;
          throw new Error(
            `${pushErr.message}\nACTION REQUIRED: the upload already happened and cannot be undone — hand-record ` +
            `this locator now, since --save-locator itself failed to: locator="${pushErr.locator}" backend="${backend}". ` +
            `Without recording it, this snapshot is unrecoverable even though it durably exists in the backend.`,
          );
        }
        // Any other push() failure (declined paid-backend consent, a network error
        // during backend.put() itself, etc.) means the upload never happened —
        // pushSucceeded stays false and the pre-push rollback path below still fires.
        throw pushErr;
      }

      // ---------- recovery kit ----------
      const primaryRecipient = (await readFile(RECIPIENT, 'utf8')).trim();
      const defaultKitPath = join(homedir(), 'recovery-kit.txt');
      const kitPath = expandHome(await askLine(rl, `\nPath to write the recovery kit [${defaultKitPath}]: `, defaultKitPath));
      const kitText = buildRecoveryKit({
        primaryIdentityPath: IDENTITY,
        primaryRecipient,
        backup,
        pinRecipientsLine,
        savedLocatorLine,
        profile: profileChoice,
        backend,
        pg: snapshotOpts.pg ?? null,
        generatedAt: new Date().toISOString(),
      });
      // Write-then-chmod (the prior approach) has a real exposure window: if kitPath
      // already exists at a looser mode (e.g. a stray 0644 file, a re-run at the same
      // path), writeFile() replaces its CONTENT first — the secret (the inlined backup
      // identity) briefly sits in a world/group-readable file — and only chmod()
      // AFTERWARD narrows it to 0600. Eliminate the window entirely instead: create a
      // distinctly-named temp sibling with `wx` (exclusive create — refuses to reuse an
      // existing, possibly-loose-mode inode) and `mode: 0o600` from the instant of
      // creation, so the secret is never observable at a loose mode even momentarily,
      // then atomically rename() it over kitPath — same temp-then-rename convention
      // pushpull.ts's save-locator write and snapshot.ts's promote-on-success step
      // already use for this codebase's other durable/secret-bearing writes. rename()
      // replacing an existing kitPath is fine here: only the NEW content must never be
      // exposed insecurely, the old kit content (if any) does not need preserving.
      await mkdir(dirname(kitPath), { recursive: true });
      const kitTmpPath = `${kitPath}.${process.pid}.${randomBytes(4).toString('hex')}.tmp`;
      try {
        await writeFile(kitTmpPath, kitText, { flag: 'wx', mode: 0o600 });
        await rename(kitTmpPath, kitPath);
      } catch (e) {
        await rm(kitTmpPath, { force: true });
        throw e;
      }

      console.log('\n=== cipher-brain init: complete ===');
      console.log(`primary identity:  ${IDENTITY}`);
      if (backup) console.log(`backup identity:   ${backup.identityPath}  (move this OFF this machine)`);
      console.log(`snapshot:          ${outPath}`);
      if (snapshotOpts.pg) console.log('postgres:          included (pg_dump)');
      const backendWarning = backend === 'file' ? '  ⚠  LOCAL-ONLY — not reachable from another machine, see MANAGEMENT.md "Key recovery #3"' : '';
      console.log(`pushed to:         ${backend} (locator saved: ${locatorPath})${backendWarning}`);
      console.log(`recovery kit:      ${kitPath}`);
      console.log('\nNext: print the recovery kit and store it securely, physically away from this machine.');
      if (backup) console.log('Also move the backup identity directory off this machine (encrypted USB, a second');
      if (backup) console.log(`location, a trusted person): ${backup.identityPath.replace(/identity\.age$/, '')}`);
      console.log('Once the kit is secured, you may delete it from disk yourself — cipher-brain does not do this for you.');
    } catch (err) {
      if (pushSucceeded) {
        // Push already happened — see the pushSucceeded declaration above. The
        // ciphertext is now durably stored (permanently and irreversibly if the
        // backend was arweave/turbo, real funds already spent) and these identities
        // are the ONLY way anyone will ever decrypt it. Deleting them here to "unblock
        // a retry" would be strictly worse than the retry annoyance this rollback
        // exists to fix: it would make an already-paid-for, already-permanent snapshot
        // unrecoverable forever. Preserve everything and tell the user exactly what
        // already succeeded and what remains on disk untouched.
        const permanentNote = pushedBackend === 'arweave' || pushedBackend === 'turbo'
          ? ' That backend is PAID and PERMANENT — the upload already happened and cannot be undone or refunded.'
          : '';
        const preserved = [
          `primary identity: ${IDENTITY}`,
          `primary recipient: ${RECIPIENT}`,
          ...(backup ? [`backup identity: ${backup.identityPath}`, `backup recipient: ${backup.recipientPath}`] : []),
          ...(snapshotOutPath ? [`snapshot: ${snapshotOutPath}`] : []),
        ].join('; ');
        // pushedLocatorPath is null exactly when PushLocatorWriteError fired above:
        // the upload succeeded but --save-locator's own file was never written, so
        // there is no path to print here — printing the literal `null` would read as
        // a bug rather than the "go read the error below" instruction it actually is.
        const locatorNote = pushedLocatorPath ? `locator saved: ${pushedLocatorPath}` : 'NOT SAVED — see error below for the value to record by hand';
        throw new Error(
          `cipher-brain init: the snapshot was already created and pushed to "${pushedBackend}" successfully ` +
          `(${locatorNote}).${permanentNote} A LATER step then failed: ` +
          `${errMsg(err)}\nNothing was rolled back — these files are PRESERVED and must NOT be deleted: ${preserved}. ` +
          `Fix the cause above, then either construct the recovery kit by hand from those paths (see ` +
          `MANAGEMENT.md), or re-run "cipher-brain init" once you have moved/backed up the above yourself — it ` +
          `will refuse immediately because an identity already exists at ${IDENTITY}; that refusal is expected ` +
          `and correct here, since your snapshot+push already succeeded and these keys must stay exactly where ` +
          `they are.`,
        );
      }
      // Roll back exactly what THIS run wrote — the primary identity/recipient this
      // invocation just generated in step 1, plus the backup identity/recipient if step
      // 2 generated one, plus the snapshot output + its sidecars if step 6's snapshot()
      // call itself succeeded before a LATER step (push, the recovery-kit write) failed
      // — so a subsequent `cipher-brain init` retry finds nothing at IDENTITY (starts
      // genuinely clean instead of hitting the pre-existing-identity refusal above) AND
      // finds no leftover --out at the same dated path (starts genuinely clean instead
      // of hitting snapshot()'s own no-clobber refusal at this step). This branch only
      // runs for failures BEFORE push() succeeded (see pushSucceeded above) — once push
      // has succeeded, the branch above takes over and preserves everything instead.
      await rm(IDENTITY, { force: true });
      await rm(RECIPIENT, { force: true });
      if (backup) {
        await rm(backup.identityPath, { force: true });
        await rm(backup.recipientPath, { force: true });
      }
      if (snapshotOutPath) {
        await rm(snapshotOutPath, { force: true });
        await rm(`${snapshotOutPath}.digest`, { force: true });
        await rm(`${snapshotOutPath}.recipients-fingerprint`, { force: true });
      }
      throw err;
    }
  } finally {
    rl.close();
  }
}
