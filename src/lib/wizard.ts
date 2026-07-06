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
import { readFile, writeFile, mkdir, chmod } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { homedir } from 'node:os';
import { HOME, IDENTITY, RECIPIENT } from './config.js';
import { keygen, keygenAt } from './keys.js';
import { askNewPassphrase, wrapIdentity } from './crypt.js';
import { PROFILE_NAMES } from './profiles.js';
import { snapshot } from './snapshot.js';
import { push } from './pushpull.js';
import { BACKEND_NAMES } from './backends/index.js';
import { exists } from './util.js';
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

async function askYesNo(rl: Rl, question: string, def: boolean): Promise<boolean> {
  const answer = (await askLine(rl, `${question} [${def ? 'Y/n' : 'y/N'}] `)).toLowerCase();
  if (!answer) return def;
  return answer === 'y' || answer === 'yes';
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
    await keygen({ dirs: [], tables: [], recipients: [] });

    // ---------- 2. backup key guidance (MANAGEMENT.md Key recovery #1) ----------
    console.log('\n== 2/6: offline backup key (recommended) ==');
    console.log(
      'cipher-brain gives you two independent defenses against losing the primary identity; the first is a\n' +
      'second, OFFLINE backup keypair. If you encrypt every snapshot to BOTH the primary and the backup\n' +
      'public key, either identity alone can restore — see MANAGEMENT.md "Key recovery #1".',
    );
    let backup: BackupKey | null = null;
    if (await askYesNo(rl, 'Generate an offline backup keypair now?', true)) {
      const defaultBackupHome = `${HOME}-backup`;
      const backupHome = await askLine(rl, `Path for the backup keypair [${defaultBackupHome}]: `, defaultBackupHome);
      const identityPath = join(backupHome, 'identity.age');
      const recipientPath = join(backupHome, 'recipient.txt');
      const { recipient } = await keygenAt({ home: backupHome, identityPath, recipientPath });
      const identityText = await readFile(identityPath, 'utf8');
      backup = { identityPath, recipientPath, recipient, identityText };
      console.log(`backup identity written to: ${identityPath}`);
      console.log('⚠  This is still ON this machine. Move it OFF-BOX (encrypted USB, a second location, a trusted');
      console.log('   person) once you are done — the recovery kit at the end of this wizard restates this.');
    } else {
      console.log('Skipping the backup key. You can add one later at any time: CIPHER_BRAIN_HOME=<path> cipher-brain keygen');
    }

    // ---------- 3. passphrase wrap the primary identity (MANAGEMENT.md Key recovery #2) ----------
    console.log('\n== 3/6: protect the primary identity at rest ==');
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
      const dirs = dirsInput.split(',').map((d) => d.trim()).filter(Boolean);
      if (dirs.length === 0) throw new Error('no directory given — "cipher-brain init" cannot produce an empty snapshot; re-run and pass at least one path, or pick a profile');
      snapshotOpts.dirs = dirs;
    } else if (PROFILE_NAMES.includes(profileChoice)) {
      snapshotOpts.profile = profileChoice;
      if (profileChoice === 'obsidian') snapshotOpts.vault = await askLine(rl, 'Path to your Obsidian vault (must contain .obsidian/): ');
      if (profileChoice === 'chatgpt-export') snapshotOpts.zip = await askLine(rl, 'Path to the official ChatGPT export .zip: ');
    } else {
      throw new Error(`unknown profile "${profileChoice}" — valid choices: none, ${PROFILE_NAMES.join(', ')}`);
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
    }

    snapshotOpts.recipients = [RECIPIENT, ...(backup ? [backup.recipientPath] : [])];
    const dateStamp = new Date().toISOString().slice(0, 10);
    const outPath = join(HOME, `brain-${dateStamp}.age`);
    snapshotOpts.out = outPath;
    await snapshot(snapshotOpts);

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
    await push(pushOpts);
    const savedLocatorLine = (await readFile(locatorPath, 'utf8')).split('\n').find((l) => l.trim()) ?? '';

    // ---------- recovery kit ----------
    const primaryRecipient = (await readFile(RECIPIENT, 'utf8')).trim();
    const defaultKitPath = join(homedir(), 'recovery-kit.txt');
    const kitPath = await askLine(rl, `\nPath to write the recovery kit [${defaultKitPath}]: `, defaultKitPath);
    const kitText = buildRecoveryKit({
      primaryIdentityPath: IDENTITY,
      primaryRecipient,
      backup,
      pinRecipientsLine,
      savedLocatorLine,
      profile: profileChoice,
      backend,
      generatedAt: new Date().toISOString(),
    });
    await mkdir(dirname(kitPath), { recursive: true });
    await writeFile(kitPath, kitText, { mode: 0o600 });
    // `mode` above only applies when writeFile CREATES the file — if kitPath already
    // existed (e.g. a stray file, a re-run at the same path) with a looser mode, the
    // write only replaces its content and the old permissive mode carries over. This
    // file inlines a secret (the backup identity), so the final mode must be
    // guaranteed regardless of what existed before — same "chmod too, in case it
    // pre-existed with a looser mode" discipline keygenAt() already applies to the
    // identity home dir (keys.ts).
    await chmod(kitPath, 0o600);

    console.log('\n=== cipher-brain init: complete ===');
    console.log(`primary identity:  ${IDENTITY}`);
    if (backup) console.log(`backup identity:   ${backup.identityPath}  (move this OFF this machine)`);
    console.log(`snapshot:          ${outPath}`);
    console.log(`pushed to:         ${backend} (locator saved: ${locatorPath})`);
    console.log(`recovery kit:      ${kitPath}`);
    console.log('\nNext: print the recovery kit and store it securely, physically away from this machine.');
    if (backup) console.log('Also move the backup identity directory off this machine (encrypted USB, a second');
    if (backup) console.log(`location, a trusted person): ${backup.identityPath.replace(/identity\.age$/, '')}`);
    console.log('Once the kit is secured, you may delete it from disk yourself — cipher-brain does not do this for you.');
  } finally {
    rl.close();
  }
}
