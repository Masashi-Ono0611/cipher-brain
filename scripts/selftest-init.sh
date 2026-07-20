#!/usr/bin/env bash
# Selftest for `cipher-brain init` (issue #68): the interactive setup wizard + its
# printable recovery kit. Covers both of the issue's acceptance criteria:
#
#   (1) "a fresh machine can go from init to first push through interaction alone" —
#       proven by driving a REAL child process's stdin with a scripted sequence of
#       answers via scripts/drive-init.mjs, which paces each answer to the prompt it
#       actually answers. A static `printf '...' | cb init` does NOT work here: this
#       wizard does real async work (keygen, disk writes) between prompts, and
#       Node's readline (non-TTY/piped mode) silently DROPS extra buffered 'line'
#       events that arrive while no question() is currently pending — dumping every
#       answer upfront wedges the wizard on a later prompt forever (confirmed while
#       building this test; see drive-init.mjs's header for the full explanation).
#
#   (2) THE DRILL: "using ONLY the recovery kit's contents, restore succeeds on a
#       different machine" — see the "THE DRILL" section below. It parses ONLY the
#       kit file's own text (never touches the wizard's live CIPHER_BRAIN_HOME) and
#       restores in a separate, fully isolated temp dir, the same "simulate a fresh
#       machine" discipline scripts/selftest-arweave-nodeps.mjs and
#       scripts/selftest-recovery.sh already use for their own recovery claims.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/bin/cipher-brain.mjs"
# BIN_DEV_ARGS: literal argv flags to run bin/cipher-brain.mjs against src/*.ts (no
# build step) under plain node — see scripts/dev-node-flags.sh (never an exported
# NODE_OPTIONS string — whitespace-split, breaks under a checkout path with a space).
source "$ROOT/scripts/dev-node-flags.sh"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
cb() { node "${BIN_DEV_ARGS[@]}" "$BIN" "$@"; }

# with_timeout: a regression here (e.g. the wizard hanging on a dropped prompt) must
# FAIL LOUDLY within a bounded time, not hang the whole suite (rules/shell-ops.md —
# every poll/gate/interactive-drive call needs its OWN deadline, not just an outer
# one). Identical to the helper already used in scripts/selftest-storage.sh.
with_timeout() {
  local s=$1; shift
  "$@" & local c=$!
  ( sleep "$s"; kill -9 "$c" 2>/dev/null ) >/dev/null 2>&1 & local w=$!
  wait "$c" 2>/dev/null; local rc=$?
  kill -9 "$w" 2>/dev/null; wait "$w" 2>/dev/null
  return $rc
}

# file_mode: portable octal permission-bits lookup. GNU coreutils `stat` (Linux,
# this repo's ubuntu-latest CI matrix cells) and BSD `stat` (macOS) both accept a
# `-f`/`-c` flag, but the SAME flag letter means something different on each: BSD
# `-f FORMAT` takes a custom format string, while GNU `-f` means "display
# filesystem status" (a totally different report) — GNU's format flag is `-c`
# instead. Trying BSD syntax (`stat -f '%Lp' path`) FIRST on Linux does not error;
# it silently prints filesystem info instead of the file's mode, corrupting
# whatever captures it. Try GNU syntax first — it is a no-op on macOS (BSD stat has
# no `-c` option, so it fails cleanly and falls through) — then fall back to BSD.
file_mode() {
  stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1"
}

echo "== (a) init refuses when an identity already exists (init is for a FRESH setup only) =="
EXISTS_HOME="$TMP/exists-home"
CIPHER_BRAIN_HOME="$EXISTS_HOME" cb keygen > /dev/null
if CIPHER_BRAIN_HOME="$EXISTS_HOME" CIPHER_BRAIN_INIT_ALLOW_NONINTERACTIVE=1 \
  with_timeout 10 node "${BIN_DEV_ARGS[@]}" "$BIN" init < /dev/null > "$TMP/exists.log" 2>&1; then
  echo "[FAIL] init did not refuse with a pre-existing identity"; cat "$TMP/exists.log"; exit 1
fi
grep -qi "already exists" "$TMP/exists.log" || { echo "[FAIL] refusal does not name the existing identity"; cat "$TMP/exists.log"; exit 1; }
grep -qi "keygen --force" "$TMP/exists.log" || { echo "[FAIL] refusal does not point at keygen --force"; cat "$TMP/exists.log"; exit 1; }
echo "[PASS] init refuses a pre-existing identity and points at keygen --force"

echo "== (b) init refuses promptly (no hang) when stdin is not a TTY and no escape hatch is set =="
TTY_HOME="$TMP/tty-check-home"
if CIPHER_BRAIN_HOME="$TTY_HOME" with_timeout 10 node "${BIN_DEV_ARGS[@]}" "$BIN" init < /dev/null > "$TMP/tty.log" 2>&1; then
  echo "[FAIL] init did not refuse a non-TTY stdin"; cat "$TMP/tty.log"; exit 1
fi
grep -qi "requires stdin to be a TTY" "$TMP/tty.log" || { echo "[FAIL] refusal does not mention the TTY requirement"; cat "$TMP/tty.log"; exit 1; }
[ ! -f "$TTY_HOME/identity.age" ] || { echo "[FAIL] an identity was written despite the TTY refusal"; exit 1; }
echo "[PASS] init refuses promptly (bounded by with_timeout, no hang) when stdin is not a TTY"

echo "== (c) profile=none with an empty directory answer refuses cleanly (no empty snapshot) =="
NODIR_HOME="$TMP/nodir-home"
cat > "$TMP/qa-nodir.json" <<JSON
[
  ["Generate an offline backup keypair now?", "n"],
  ["Protect the primary identity with a passphrase now?", "n"],
  ["Show a suggested CIPHER_BRAIN_PIN_RECIPIENTS line", "n"],
  ["Profile [none/", ""],
  ["Directory path(s) to back up", ""]
]
JSON
if CIPHER_BRAIN_HOME="$NODIR_HOME" CIPHER_BRAIN_INIT_ALLOW_NONINTERACTIVE=1 \
  with_timeout 30 node "$ROOT/scripts/drive-init.mjs" --qa "$TMP/qa-nodir.json" --out "$TMP/nodir.log" \
  -- node "${BIN_DEV_ARGS[@]}" "$BIN" init; then
  echo "[FAIL] init accepted an empty directory list for profile=none"; cat "$TMP/nodir.log"; exit 1
fi
grep -qi "no directory given" "$TMP/nodir.log" || { echo "[FAIL] refusal does not explain the missing directory"; cat "$TMP/nodir.log"; exit 1; }
echo "[PASS] init refuses profile=none with no directory given"

echo "== (d) THE SCRIPTED END-TO-END RUN (issue #68 acceptance criterion 1): init -> first push, driven entirely via a scripted stdin sequence =="
SRC="$TMP/brain-src"; mkdir -p "$SRC"
MARKER="drill-thought-$(od -An -N6 -tx1 /dev/urandom | tr -d ' ')"
printf '%s\n' "$MARKER" > "$SRC/note.txt"

WIZ_HOME="$TMP/wiz-home"; mkdir -p "$WIZ_HOME"    # HOME override: os.homedir()-based defaults (kit path) stay inside TMP
WIZ_CB_HOME="$TMP/wiz-cb-home"                    # CIPHER_BRAIN_HOME: primary identity/recipient/store paths
WIZ_STORE="$TMP/wiz-store"                        # file backend store dir
KIT_PATH="$WIZ_HOME/recovery-kit.txt"
BACKUP_HOME="${WIZ_CB_HOME}-backup"               # the default sibling path the wizard suggests for the backup key

# The realistic path from the issue: file backend, no profile, backup key YES,
# passphrase NO, pin-recipients SKIP.
cat > "$TMP/qa.json" <<JSON
[
  ["Generate an offline backup keypair now?", "y"],
  ["Path for the backup keypair", ""],
  ["Protect the primary identity with a passphrase now?", "n"],
  ["Show a suggested CIPHER_BRAIN_PIN_RECIPIENTS line", "n"],
  ["Profile [none/", ""],
  ["Directory path(s) to back up", "$SRC"],
  ["Backend [file/", ""],
  ["Path to write the recovery kit", "$KIT_PATH"]
]
JSON

CIPHER_BRAIN_HOME="$WIZ_CB_HOME" CIPHER_BRAIN_FILE_DIR="$WIZ_STORE" HOME="$WIZ_HOME" CIPHER_BRAIN_INIT_ALLOW_NONINTERACTIVE=1 \
  with_timeout 90 node "$ROOT/scripts/drive-init.mjs" --qa "$TMP/qa.json" --out "$TMP/wizard.log" \
  -- node "${BIN_DEV_ARGS[@]}" "$BIN" init \
  || { echo "[FAIL] the scripted end-to-end wizard run did not complete"; cat "$TMP/wizard.log"; exit 1; }
grep -q 'cipher-brain init: complete' "$TMP/wizard.log" || { echo "[FAIL] wizard log lacks its own completion marker"; cat "$TMP/wizard.log"; exit 1; }
echo "[PASS] scripted stdin sequence drove init end-to-end: keygen -> backup key(yes) -> passphrase(skip) -> pin(skip) -> profile(none) -> snapshot -> push"

[ -f "$WIZ_CB_HOME/identity.age" ] || { echo "[FAIL] primary identity was not written"; exit 1; }
[ -f "$WIZ_CB_HOME/recipient.txt" ] || { echo "[FAIL] primary recipient was not written"; exit 1; }
grep -q '^AGE-SECRET-KEY-1' "$WIZ_CB_HOME/identity.age" || { echo "[FAIL] primary identity is not a plain unwrapped age identity (passphrase step should have been skipped)"; exit 1; }
[ -f "$BACKUP_HOME/identity.age" ] || { echo "[FAIL] backup identity was not written at the default sibling path"; exit 1; }
[ -f "$BACKUP_HOME/recipient.txt" ] || { echo "[FAIL] backup recipient was not written"; exit 1; }
echo "[PASS] primary + backup identities/recipients written; primary is unwrapped as scripted"

LOCFILE="$WIZ_CB_HOME/latest-locator.tsv"
[ -f "$LOCFILE" ] || { echo "[FAIL] --save-locator file not written by the wizard's push"; exit 1; }
[ "$(awk -F'\t' '{print NF; exit}' "$LOCFILE")" = "5" ] || { echo "[FAIL] locator file is not 5 tab-separated fields"; cat "$LOCFILE"; exit 1; }
[ "$(awk -F'\t' '{print $2; exit}' "$LOCFILE")" = "file" ] || { echo "[FAIL] locator file backend != file"; exit 1; }
echo "[PASS] push wrote a 5-field --save-locator file for the file backend"

SNAP="$(find "$WIZ_CB_HOME" -maxdepth 1 -name 'brain-*.age' | head -n1)"
[ -n "$SNAP" ] || { echo "[FAIL] no brain-*.age snapshot found under CIPHER_BRAIN_HOME"; exit 1; }
CIPHER_BRAIN_HOME="$WIZ_CB_HOME" cb verify --in "$SNAP" > "$TMP/verify.log" 2>&1 || { echo "[FAIL] verify on the wizard's own snapshot failed"; cat "$TMP/verify.log"; exit 1; }
grep -q 'VERDICT: PASS' "$TMP/verify.log" || { echo "[FAIL] verify verdict on the wizard's snapshot is not PASS"; cat "$TMP/verify.log"; exit 1; }
echo "[PASS] the wizard's own snapshot verifies (real ciphertext, wrong key rejected, primary identity decrypts it)"

echo "== (e) recovery kit content structure =="
[ -f "$KIT_PATH" ] || { echo "[FAIL] recovery kit was not written at the requested path"; exit 1; }
KITMODE="$(file_mode "$KIT_PATH")"
[ "$KITMODE" = "600" ] || { echo "[FAIL] recovery kit is not mode 600 (got $KITMODE) — it contains a secret identity"; exit 1; }
grep -q 'KEEP THIS OFFLINE / PHYSICALLY SECURE' "$KIT_PATH" || { echo "[FAIL] kit missing the warning banner"; exit 1; }
grep -q -- '--- PRIMARY IDENTITY' "$KIT_PATH" || { echo "[FAIL] kit missing the PRIMARY IDENTITY section"; exit 1; }
grep -qF "$WIZ_CB_HOME/identity.age" "$KIT_PATH" || { echo "[FAIL] kit does not reference the primary identity's location"; exit 1; }
grep -q -- '--- BACKUP IDENTITY (SECRET' "$KIT_PATH" || { echo "[FAIL] kit missing the BACKUP IDENTITY section"; exit 1; }
grep -q '^AGE-SECRET-KEY-1' "$KIT_PATH" || { echo "[FAIL] kit does not inline the backup identity's secret key line"; exit 1; }
grep -qF "$(head -n1 "$LOCFILE")" "$KIT_PATH" || { echo "[FAIL] kit does not inline the exact save-locator line"; exit 1; }
grep -q 'skipped during init' "$KIT_PATH" || { echo "[FAIL] kit does not note the recipient-pin suggestion was skipped"; exit 1; }
grep -q 'cipher-brain pull --from-locator-file' "$KIT_PATH" || { echo "[FAIL] kit missing the recovery pull command"; exit 1; }
grep -q 'cipher-brain restore --in' "$KIT_PATH" || { echo "[FAIL] kit missing the recovery restore command"; exit 1; }
grep -q 'WHAT TO DO WITH THIS FILE' "$KIT_PATH" || { echo "[FAIL] kit missing the disposal-instructions section"; exit 1; }
grep -q 'LOCATOR IS LOCAL-ONLY' "$KIT_PATH" || { echo "[FAIL] kit used the file backend but does not warn that its save-locator is local-only"; exit 1; }
echo "[PASS] kit: mode 600, warning banner, primary location, backup identity inlined, exact locator line, pin-skip note, recovery commands, disposal note, file-backend local-only warning"

echo "== (e2) file backend: interactive warning + completion summary both surface the local-only risk (issue #85) =="
# Before the fix, the kit-only warning above (grepped in (e)) was the ONLY place a
# file-backend user ever saw this — invisible unless they opened the printed kit.
# Test (d)'s own run ($TMP/wizard.log) already selected the file backend (its default
# Enter-key answer), so reuse that transcript rather than scripting a whole new run.
grep -qF 'stores the pushed ciphertext ONLY on this machine' "$TMP/wizard.log" || { echo "[FAIL] wizard.log does not show the interactive file-backend warning"; cat "$TMP/wizard.log"; exit 1; }
grep -qF 'LOCAL-ONLY — not reachable from another machine' "$TMP/wizard.log" || { echo "[FAIL] completion summary does not annotate the file backend as local-only"; cat "$TMP/wizard.log"; exit 1; }
echo "[PASS] choosing the file backend prints an interactive warning, and the completion summary flags it as local-only"

echo "== (f) passphrase=yes path completes end-to-end (readline/promptHidden interaction fix) =="
# CIPHER_BRAIN_PASSPHRASE (crypt.ts's own automation escape hatch) makes
# askNewPassphrase() return immediately without touching stdin's raw mode, so this
# run does NOT reproduce the raw-TTY nuance itself (that was proven separately with
# a real pty harness, not part of this repo's test suite) — what it DOES prove is
# that the wizard's own readline Interface survives being closed and re-created
# around the passphrase step: every prompt AFTER "Protect the primary identity..."
# (recipient-pin, profile, directory, backend, kit path) must still be answered by
# this scripted driver, which only works if the wizard's later rl.question() calls
# are actually receiving input again.
F_HOME="$TMP/pass-home"; mkdir -p "$F_HOME"
F_CB_HOME="$TMP/pass-cb-home"
F_STORE="$TMP/pass-store"
F_SRC="$TMP/pass-src"; mkdir -p "$F_SRC"
printf 'pass-marker\n' > "$F_SRC/note.txt"
F_KIT_PATH="$F_HOME/recovery-kit.txt"
mkdir -p "$(dirname "$F_KIT_PATH")"
: > "$F_KIT_PATH"; chmod 644 "$F_KIT_PATH" # pre-existing, permissive-mode file — proves the chmod-after-write fix below too
PRE_KIT_MODE="$(file_mode "$F_KIT_PATH")"
[ "$PRE_KIT_MODE" = "644" ] || { echo "[FAIL] test setup: could not pre-create the kit path at mode 644"; exit 1; }

cat > "$TMP/qa-pass.json" <<JSON
[
  ["Generate an offline backup keypair now?", "n"],
  ["Protect the primary identity with a passphrase now?", "y"],
  ["Show a suggested CIPHER_BRAIN_PIN_RECIPIENTS line", "n"],
  ["Profile [none/", ""],
  ["Directory path(s) to back up", "$F_SRC"],
  ["Backend [file/", ""],
  ["Path to write the recovery kit", "$F_KIT_PATH"]
]
JSON

CIPHER_BRAIN_HOME="$F_CB_HOME" CIPHER_BRAIN_FILE_DIR="$F_STORE" HOME="$F_HOME" \
  CIPHER_BRAIN_INIT_ALLOW_NONINTERACTIVE=1 CIPHER_BRAIN_PASSPHRASE="test-selftest-passphrase" \
  with_timeout 90 node "$ROOT/scripts/drive-init.mjs" --qa "$TMP/qa-pass.json" --out "$TMP/wizard-pass.log" \
  -- node "${BIN_DEV_ARGS[@]}" "$BIN" init \
  || { echo "[FAIL] the passphrase=yes scripted run did not complete"; cat "$TMP/wizard-pass.log"; exit 1; }
grep -q 'cipher-brain init: complete' "$TMP/wizard-pass.log" || { echo "[FAIL] passphrase=yes run: wizard log lacks its own completion marker"; cat "$TMP/wizard-pass.log"; exit 1; }
grep -qa '^-> scrypt ' "$F_CB_HOME/identity.age" || { echo "[FAIL] passphrase=yes run: identity is not scrypt-wrapped (passphrase step did not actually run)"; exit 1; }
echo "[PASS] passphrase=yes path reaches every later prompt and completes (snapshot -> push -> kit) after the readline interface is closed/re-created"

POST_KIT_MODE="$(file_mode "$F_KIT_PATH")"
[ -f "$F_KIT_PATH" ] || { echo "[FAIL] recovery kit was not written at the pre-existing path"; exit 1; }
[ "$POST_KIT_MODE" = "600" ] || { echo "[FAIL] kit path pre-existed at mode 644 but ended up mode $POST_KIT_MODE (want 600) — a secret-bearing kit must not inherit a looser pre-existing mode"; exit 1; }
echo "[PASS] a kit path that pre-existed at mode 644 ends up mode 600 after the wizard writes it"

# 6th-round P2 fix: write-then-chmod (the OLD approach) had a real exposure window —
# a pre-existing looser-mode file gets its CONTENT replaced first and only chmod'd
# to 0600 afterward, so the secret briefly sits at the pre-existing mode. The fix
# writes a distinctly-named `.tmp` sibling at mode 0600 from the instant of creation
# (`wx` — exclusive create, never reuses the loose-mode inode), then atomically
# rename()s it over kitPath — which makes the insecure window impossible BY
# CONSTRUCTION rather than by a race that is merely unlikely to lose. This can't be
# proven by racing a background poll (a construction-level guarantee has no window
# to catch even in principle); what CAN be proven here: (1) the tmp sibling never
# survives a successful run (it was renamed away, not left behind or leaked), and
# (2) the final file actually contains the real secret content (a scrypt-wrapped
# passphrase run's kit — not the empty placeholder it started as), at 0600 (already
# checked above).
TMP_KIT_LEFTOVER="$(find "$(dirname "$F_KIT_PATH")" -maxdepth 1 -name "$(basename "$F_KIT_PATH").*.tmp" 2>/dev/null | head -n1)"
[ -z "$TMP_KIT_LEFTOVER" ] || { echo "[FAIL] a .tmp sibling of the recovery kit survived a successful write: $TMP_KIT_LEFTOVER"; exit 1; }
[ -s "$F_KIT_PATH" ] || { echo "[FAIL] recovery kit is empty — still the pre-existing placeholder, not the wizard's real content"; exit 1; }
grep -q 'KEEP THIS OFFLINE / PHYSICALLY SECURE' "$F_KIT_PATH" || { echo "[FAIL] recovery kit does not contain the wizard's real content — write-then-rename did not actually replace the placeholder"; exit 1; }
echo "[PASS] the pre-existing-644 kit path ends up with NO leftover .tmp sibling and real secret content at mode 600 (write-at-0600-then-rename fix — no write-then-chmod exposure window)"

echo "== (g) recovery kit honesty when the backup key was skipped (test f's own run: backup=NO) =="
# Test (f) above already drove backup=NO through to a completed kit (F_KIT_PATH) —
# reuse it rather than scripting a whole new duplicate wizard run just for this.
# Without a backup identity, the ONLY thing that can decrypt is the PRIMARY
# identity, which deliberately never leaves the machine via the kit (MANAGEMENT.md
# "Key recovery #1") — so the kit must NOT tell the reader to copy/use a BACKUP
# IDENTITY block that was never generated, and MUST explain the honest alternative.
grep -q -- '--- BACKUP IDENTITY ---' "$F_KIT_PATH" || { echo "[FAIL] no-backup kit missing the plain (no-key) BACKUP IDENTITY section"; exit 1; }
if grep -q 'BEGIN BACKUP IDENTITY FILE' "$F_KIT_PATH"; then echo "[FAIL] no-backup kit unexpectedly inlines a BACKUP IDENTITY FILE block"; exit 1; fi
if grep -q 'Copy the BACKUP IDENTITY block above' "$F_KIT_PATH"; then echo "[FAIL] no-backup kit still tells the reader to copy a BACKUP IDENTITY block that was never generated"; exit 1; fi
grep -q 'NO BACKUP IDENTITY IS IN THIS KIT' "$F_KIT_PATH" || { echo "[FAIL] no-backup kit does not warn that kit-only recovery on a fresh machine is not possible"; exit 1; }
grep -qF "$F_CB_HOME/identity.age" "$F_KIT_PATH" || { echo "[FAIL] no-backup kit does not point at the primary identity as the only thing that can restore"; exit 1; }
grep -q 'cipher-brain keygen' "$F_KIT_PATH" || { echo "[FAIL] no-backup kit does not explain generating a backup key for real kit-only recovery later"; exit 1; }
grep -q 'still valid, useful' "$F_KIT_PATH" || { echo "[FAIL] no-backup kit does not note the save-locator/pin-recipients sections remain valid regardless"; exit 1; }
echo "[PASS] no-backup kit is honest: no BACKUP IDENTITY block or dependent instructions, explains primary-identity-only recovery + the keygen path to real kit-only recovery later"

echo "== (h) rollback + clean retry: a failure AFTER identity creation must not brick a retry (P2 fix) =="
# The primary identity is created in step 1/6, well before later prompts that can
# fail/abort (an unknown backend name, an empty directory answer, ...). Before the
# fix, any such later failure left the identity behind — and `init` refuses
# unconditionally whenever an identity already exists — so a typo'd retry was
# permanently stuck needing the scarier `keygen --force`. Drive a run that succeeds
# through backup-key generation (so BOTH primary and backup identities exist) and
# THEN fails at the very last prompt (an unrecognized backend name), then prove (1)
# the rollback actually deleted every file this run wrote, and (2) a second, genuine
# `cipher-brain init` run against the SAME CIPHER_BRAIN_HOME starts clean and
# completes — the retry story working end-to-end, not just files disappearing.
RB_HOME="$TMP/rollback-home"; mkdir -p "$RB_HOME"
RB_CB_HOME="$TMP/rollback-cb-home"
RB_STORE="$TMP/rollback-store"
RB_SRC="$TMP/rollback-src"; mkdir -p "$RB_SRC"
printf 'rollback-marker\n' > "$RB_SRC/note.txt"
RB_BACKUP_HOME="${RB_CB_HOME}-backup" # the default sibling path the wizard suggests for the backup key

cat > "$TMP/qa-rollback-fail.json" <<JSON
[
  ["Generate an offline backup keypair now?", "y"],
  ["Path for the backup keypair", ""],
  ["Protect the primary identity with a passphrase now?", "n"],
  ["Show a suggested CIPHER_BRAIN_PIN_RECIPIENTS line", "n"],
  ["Profile [none/", ""],
  ["Directory path(s) to back up", "$RB_SRC"],
  ["Backend [file/", "not-a-real-backend"]
]
JSON

if CIPHER_BRAIN_HOME="$RB_CB_HOME" CIPHER_BRAIN_FILE_DIR="$RB_STORE" HOME="$RB_HOME" CIPHER_BRAIN_INIT_ALLOW_NONINTERACTIVE=1 \
  with_timeout 60 node "$ROOT/scripts/drive-init.mjs" --qa "$TMP/qa-rollback-fail.json" --out "$TMP/rollback-fail.log" \
  -- node "${BIN_DEV_ARGS[@]}" "$BIN" init; then
  echo "[FAIL] init did not fail on an unknown backend name"; cat "$TMP/rollback-fail.log"; exit 1
fi
grep -qi "unknown backend" "$TMP/rollback-fail.log" || { echo "[FAIL] failure was not the expected unknown-backend error"; cat "$TMP/rollback-fail.log"; exit 1; }
[ ! -f "$RB_CB_HOME/identity.age" ] || { echo "[FAIL] primary identity survived a post-creation failure — rollback did not run"; exit 1; }
[ ! -f "$RB_CB_HOME/recipient.txt" ] || { echo "[FAIL] primary recipient survived a post-creation failure"; exit 1; }
[ ! -f "$RB_BACKUP_HOME/identity.age" ] || { echo "[FAIL] backup identity survived a post-creation failure"; exit 1; }
[ ! -f "$RB_BACKUP_HOME/recipient.txt" ] || { echo "[FAIL] backup recipient survived a post-creation failure"; exit 1; }
echo "[PASS] a failure AFTER identity creation rolls back the primary + backup identity/recipient files this run wrote"

RB_KIT_PATH="$RB_HOME/recovery-kit.txt"
cat > "$TMP/qa-rollback-retry.json" <<JSON
[
  ["Generate an offline backup keypair now?", "n"],
  ["Protect the primary identity with a passphrase now?", "n"],
  ["Show a suggested CIPHER_BRAIN_PIN_RECIPIENTS line", "n"],
  ["Profile [none/", ""],
  ["Directory path(s) to back up", "$RB_SRC"],
  ["Backend [file/", ""],
  ["Path to write the recovery kit", "$RB_KIT_PATH"]
]
JSON

CIPHER_BRAIN_HOME="$RB_CB_HOME" CIPHER_BRAIN_FILE_DIR="$RB_STORE" HOME="$RB_HOME" CIPHER_BRAIN_INIT_ALLOW_NONINTERACTIVE=1 \
  with_timeout 60 node "$ROOT/scripts/drive-init.mjs" --qa "$TMP/qa-rollback-retry.json" --out "$TMP/rollback-retry.log" \
  -- node "${BIN_DEV_ARGS[@]}" "$BIN" init \
  || { echo "[FAIL] retry after rollback did not complete (pre-existing-identity refusal or another regression)"; cat "$TMP/rollback-retry.log"; exit 1; }
grep -q 'cipher-brain init: complete' "$TMP/rollback-retry.log" || { echo "[FAIL] retry after rollback lacks its own completion marker"; cat "$TMP/rollback-retry.log"; exit 1; }
[ -f "$RB_CB_HOME/identity.age" ] || { echo "[FAIL] retry did not write a fresh primary identity"; exit 1; }
echo "[PASS] a second 'cipher-brain init' run against the same CIPHER_BRAIN_HOME starts clean and completes after rollback (the retry story actually works, not just file deletion)"

echo "== (i) '~' in interactive path answers expands to HOME, the same way a shell would (P3 fix) =="
# Path-like answers are read as plain strings (no shell involved), so a leading '~'
# would otherwise resolve to a literal '~'-named entry relative to cwd instead of the
# real home directory. Answer BOTH the directory-to-back-up prompt and the
# recovery-kit path prompt with a '~/...' path inside a controlled HOME fixture: if
# expansion did not happen, snapshot's tar step would try to read a nonexistent
# literal './~/...' path and the whole run would fail before completing.
TILDE_HOME="$TMP/tilde-home"; mkdir -p "$TILDE_HOME"
TILDE_SRC_REL="tilde-src" # answered as "~/$TILDE_SRC_REL"
mkdir -p "$TILDE_HOME/$TILDE_SRC_REL"
TILDE_MARKER="tilde-thought-$(od -An -N6 -tx1 /dev/urandom | tr -d ' ')"
printf '%s\n' "$TILDE_MARKER" > "$TILDE_HOME/$TILDE_SRC_REL/note.txt"
TILDE_CB_HOME="$TMP/tilde-cb-home"
TILDE_STORE="$TMP/tilde-store"

cat > "$TMP/qa-tilde.json" <<JSON
[
  ["Generate an offline backup keypair now?", "n"],
  ["Protect the primary identity with a passphrase now?", "n"],
  ["Show a suggested CIPHER_BRAIN_PIN_RECIPIENTS line", "n"],
  ["Profile [none/", ""],
  ["Directory path(s) to back up", "~/$TILDE_SRC_REL"],
  ["Backend [file/", ""],
  ["Path to write the recovery kit", "~/tilde-recovery-kit.txt"]
]
JSON

CIPHER_BRAIN_HOME="$TILDE_CB_HOME" CIPHER_BRAIN_FILE_DIR="$TILDE_STORE" HOME="$TILDE_HOME" CIPHER_BRAIN_INIT_ALLOW_NONINTERACTIVE=1 \
  with_timeout 60 node "$ROOT/scripts/drive-init.mjs" --qa "$TMP/qa-tilde.json" --out "$TMP/tilde.log" \
  -- node "${BIN_DEV_ARGS[@]}" "$BIN" init \
  || { echo "[FAIL] the '~'-path scripted run did not complete (path expansion likely did not happen)"; cat "$TMP/tilde.log"; exit 1; }
grep -q 'cipher-brain init: complete' "$TMP/tilde.log" || { echo "[FAIL] '~'-path run lacks its own completion marker"; cat "$TMP/tilde.log"; exit 1; }
[ -f "$TILDE_HOME/tilde-recovery-kit.txt" ] || { echo "[FAIL] recovery kit was not written under the expanded HOME (~/tilde-recovery-kit.txt did not expand)"; exit 1; }
[ ! -e "$ROOT/~" ] || { echo "[FAIL] a literal '~' file/dir was created relative to cwd — '~' was not expanded"; exit 1; }
echo "[PASS] '~/...' directory-to-back-up and recovery-kit path answers both expanded to the real HOME, matching shell behavior"

echo "== (j0) a failure BEFORE push() succeeds still rolls back the identity AND the snapshot artifact =="
# Establishes the OTHER side of the 6th-round P2 rollback-boundary fix: everything
# BEFORE push() succeeds must still roll back exactly as before (only failures AFTER
# a successful push change behavior — see (j)/(j2) below). Fail deterministically
# inside push()'s file-backend put() by pointing CIPHER_BRAIN_FILE_DIR at a path
# whose PARENT is a plain FILE, so fileBackend().put()'s own
# `mkdir(FILE_DIR, { recursive: true })` throws ENOTDIR before push() ever returns —
# i.e. before pushSucceeded flips true in wizard.ts. The QA script intentionally
# stops at the backend prompt: push() throws before the recovery-kit path is ever
# asked, so scripting that prompt would leave it unconsumed and fail drive-init.mjs
# itself (ed1f2d6) rather than testing what we want here.
J0_HOME="$TMP/prepush-rollback-home"; mkdir -p "$J0_HOME"
J0_CB_HOME="$TMP/prepush-rollback-cb-home"
J0_STORE_BLOCKED_PARENT="$TMP/prepush-rollback-store-blocked-parent"
: > "$J0_STORE_BLOCKED_PARENT" # plain FILE — FILE_DIR nests a dir UNDER this
J0_STORE="$J0_STORE_BLOCKED_PARENT/subdir-store"
J0_SRC="$TMP/prepush-rollback-src"; mkdir -p "$J0_SRC"
printf 'prepush-rollback-marker\n' > "$J0_SRC/note.txt"

cat > "$TMP/qa-prepush-rollback-fail.json" <<JSON
[
  ["Generate an offline backup keypair now?", "n"],
  ["Protect the primary identity with a passphrase now?", "n"],
  ["Show a suggested CIPHER_BRAIN_PIN_RECIPIENTS line", "n"],
  ["Profile [none/", ""],
  ["Directory path(s) to back up", "$J0_SRC"],
  ["Backend [file/", ""]
]
JSON

if CIPHER_BRAIN_HOME="$J0_CB_HOME" CIPHER_BRAIN_FILE_DIR="$J0_STORE" HOME="$J0_HOME" CIPHER_BRAIN_INIT_ALLOW_NONINTERACTIVE=1 \
  with_timeout 60 node "$ROOT/scripts/drive-init.mjs" --qa "$TMP/qa-prepush-rollback-fail.json" --out "$TMP/prepush-rollback-fail.log" \
  -- node "${BIN_DEV_ARGS[@]}" "$BIN" init; then
  echo "[FAIL] init did not fail when the file backend's store dir has a blocked parent"; cat "$TMP/prepush-rollback-fail.log"; exit 1
fi
grep -qi "ENOTDIR\|not a directory" "$TMP/prepush-rollback-fail.log" || { echo "[FAIL] failure was not the expected pre-push ENOTDIR error"; cat "$TMP/prepush-rollback-fail.log"; exit 1; }
[ ! -f "$J0_CB_HOME/identity.age" ] || { echo "[FAIL] primary identity survived a PRE-push failure — rollback should still fire here"; exit 1; }
[ ! -f "$J0_CB_HOME/recipient.txt" ] || { echo "[FAIL] primary recipient survived a PRE-push failure"; exit 1; }
J0_LEFTOVER="$(find "$J0_CB_HOME" -maxdepth 1 -name 'brain-*.age*' 2>/dev/null | head -n1)"
[ -z "$J0_LEFTOVER" ] || { echo "[FAIL] a snapshot artifact/sidecar survived a PRE-push failure: $J0_LEFTOVER"; exit 1; }
echo "[PASS] a failure BEFORE push() succeeds (push() itself throwing) still rolls back the identity AND the snapshot artifact + sidecars, exactly as before the P2 fix"

echo "== (j) a failure AFTER push() succeeds preserves the identity + snapshot instead of rolling them back (6th-round P2 fix) =="
# The OLD behavior (5th round, fb293ff/0565194) rolled back the identity + snapshot
# artifact for ANY post-creation failure, including one AFTER push() had already
# durably written the ciphertext to the backend's store. For a paid backend
# (arweave/turbo) that upload is PERMANENT and IRREVERSIBLE — deleting the only keys
# that can ever decrypt it would turn a mere "kit step needs a retry" into
# unrecoverable data + money loss. Reuses the exact repro that used to prove the OLD
# (now-wrong) behavior: make the very last step — the recovery kit's own
# mkdir/write — fail by pre-creating the kit path's PARENT as a plain FILE, so
# mkdir(dirname(kitPath), { recursive: true }) throws ENOTDIR AFTER snapshot() and
# push() have both already succeeded.
SNAP_HOME="$TMP/snap-preserve-home"; mkdir -p "$SNAP_HOME"
SNAP_CB_HOME="$TMP/snap-preserve-cb-home"
SNAP_STORE="$TMP/snap-preserve-store"
SNAP_SRC="$TMP/snap-preserve-src"; mkdir -p "$SNAP_SRC"
printf 'snap-preserve-marker\n' > "$SNAP_SRC/note.txt"
BLOCKED_PARENT="$SNAP_HOME/blocked-kit-parent"
: > "$BLOCKED_PARENT" # plain FILE — the kit path nests a dir UNDER this, so mkdir -p
                      # must traverse it as a parent component (ENOTDIR), not just
                      # target it directly (which would be EEXIST instead)
BLOCKED_KIT_PATH="$BLOCKED_PARENT/subdir/recovery-kit.txt"

cat > "$TMP/qa-snap-preserve-fail.json" <<JSON
[
  ["Generate an offline backup keypair now?", "n"],
  ["Protect the primary identity with a passphrase now?", "n"],
  ["Show a suggested CIPHER_BRAIN_PIN_RECIPIENTS line", "n"],
  ["Profile [none/", ""],
  ["Directory path(s) to back up", "$SNAP_SRC"],
  ["Backend [file/", ""],
  ["Path to write the recovery kit", "$BLOCKED_KIT_PATH"]
]
JSON

if CIPHER_BRAIN_HOME="$SNAP_CB_HOME" CIPHER_BRAIN_FILE_DIR="$SNAP_STORE" HOME="$SNAP_HOME" CIPHER_BRAIN_INIT_ALLOW_NONINTERACTIVE=1 \
  with_timeout 60 node "$ROOT/scripts/drive-init.mjs" --qa "$TMP/qa-snap-preserve-fail.json" --out "$TMP/snap-preserve-fail.log" \
  -- node "${BIN_DEV_ARGS[@]}" "$BIN" init; then
  echo "[FAIL] init did not fail when the recovery-kit path's parent is a plain file"; cat "$TMP/snap-preserve-fail.log"; exit 1
fi
grep -qi "ENOTDIR\|not a directory" "$TMP/snap-preserve-fail.log" || { echo "[FAIL] failure was not the expected kit-write ENOTDIR error"; cat "$TMP/snap-preserve-fail.log"; exit 1; }
[ -f "$SNAP_CB_HOME/identity.age" ] || { echo "[FAIL] primary identity was DELETED after a successful push — this is the data-loss regression the P2 fix prevents"; exit 1; }
[ -f "$SNAP_CB_HOME/recipient.txt" ] || { echo "[FAIL] primary recipient was DELETED after a successful push"; exit 1; }
SNAP_SURVIVOR="$(find "$SNAP_CB_HOME" -maxdepth 1 -name 'brain-*.age' 2>/dev/null | head -n1)"
[ -n "$SNAP_SURVIVOR" ] || { echo "[FAIL] the dated snapshot artifact was DELETED after a successful push"; exit 1; }
grep -qi "already created and pushed" "$TMP/snap-preserve-fail.log" || { echo "[FAIL] failure message does not clearly state the snapshot was already pushed"; cat "$TMP/snap-preserve-fail.log"; exit 1; }
grep -qi "PRESERVED" "$TMP/snap-preserve-fail.log" || { echo "[FAIL] failure message does not clearly say the identity/snapshot files are preserved"; cat "$TMP/snap-preserve-fail.log"; exit 1; }
grep -qF "$SNAP_CB_HOME/identity.age" "$TMP/snap-preserve-fail.log" || { echo "[FAIL] failure message does not name the preserved primary identity path"; cat "$TMP/snap-preserve-fail.log"; exit 1; }
echo "[PASS] a failure AFTER push() succeeds (kit write) preserves the identity, recipient, AND the dated snapshot artifact — nothing is rolled back — and the error clearly states what already succeeded and what is preserved"

echo "== (j2) retry after a post-push failure correctly REFUSES — identity + snapshot are still there, not silently regenerated =="
# Because (j) above no longer deletes anything, a same-day retry against the SAME
# CIPHER_BRAIN_HOME must hit the ordinary pre-existing-identity refusal (test (a)) —
# starting "clean" here would be wrong: it would silently abandon the real,
# already-pushed snapshot (and, on a paid backend, already-spent money) in favor of
# a brand new identity that cannot decrypt it.
if CIPHER_BRAIN_HOME="$SNAP_CB_HOME" CIPHER_BRAIN_INIT_ALLOW_NONINTERACTIVE=1 \
  with_timeout 10 node "${BIN_DEV_ARGS[@]}" "$BIN" init < /dev/null > "$TMP/snap-preserve-retry.log" 2>&1; then
  echo "[FAIL] a retry after a post-push failure did not refuse — it should, since the identity/snapshot are preserved"; cat "$TMP/snap-preserve-retry.log"; exit 1
fi
grep -qi "already exists" "$TMP/snap-preserve-retry.log" || { echo "[FAIL] retry's refusal was not the expected pre-existing-identity error"; cat "$TMP/snap-preserve-retry.log"; exit 1; }
[ -f "$SNAP_CB_HOME/identity.age" ] || { echo "[FAIL] the preserved primary identity vanished between the two runs"; exit 1; }
[ -n "$(find "$SNAP_CB_HOME" -maxdepth 1 -name 'brain-*.age' 2>/dev/null | head -n1)" ] || { echo "[FAIL] the preserved snapshot artifact vanished between the two runs"; exit 1; }
echo "[PASS] a second 'cipher-brain init' run against the same CIPHER_BRAIN_HOME correctly refuses (identity + snapshot from the successful push are still there, exactly as promised) instead of silently starting over"

echo "== (k) push() succeeding but --save-locator's own write failing preserves everything + surfaces the locator (7th-round P1 fix, finding 1) =="
# backend.put() (the actual, possibly PAID/PERMANENT upload) is the point of no
# return; --save-locator's own bookkeeping write happens strictly AFTER it. Force
# JUST that local write to fail (not the upload) by pre-creating the locator's
# target path as a DIRECTORY: push()'s tmp-write succeeds (a distinctly-named
# sibling filename), but its rename(tmp, save_locator) then fails EISDIR — same
# "blocking file/dir at the exact target path" technique (j)/(j2) already use for
# the kit path. Before the P1 fix, push() rejecting here (regardless of WHY) made
# the wizard treat the whole run as if nothing had happened yet and delete the
# primary identity — even though the upload above it already durably succeeded.
K_HOME="$TMP/locator-preserve-home"; mkdir -p "$K_HOME"
K_CB_HOME="$TMP/locator-preserve-cb-home"
K_STORE="$TMP/locator-preserve-store"
K_SRC="$TMP/locator-preserve-src"; mkdir -p "$K_SRC"
printf 'locator-preserve-marker\n' > "$K_SRC/note.txt"
K_LOCATOR_PATH="$K_CB_HOME/latest-locator.tsv"
mkdir -p "$K_LOCATOR_PATH"  # pre-create AS A DIRECTORY at the wizard's fixed --save-locator path

cat > "$TMP/qa-locator-preserve-fail.json" <<JSON
[
  ["Generate an offline backup keypair now?", "n"],
  ["Protect the primary identity with a passphrase now?", "n"],
  ["Show a suggested CIPHER_BRAIN_PIN_RECIPIENTS line", "n"],
  ["Profile [none/", ""],
  ["Directory path(s) to back up", "$K_SRC"],
  ["Backend [file/", ""]
]
JSON
# (Same reasoning as (j0)'s QA script: push() throws right after the backend prompt,
# before the recovery-kit path is ever asked — scripting that prompt would leave it
# unconsumed and fail drive-init.mjs itself rather than testing what we want here.)

if CIPHER_BRAIN_HOME="$K_CB_HOME" CIPHER_BRAIN_FILE_DIR="$K_STORE" HOME="$K_HOME" CIPHER_BRAIN_INIT_ALLOW_NONINTERACTIVE=1 \
  with_timeout 60 node "$ROOT/scripts/drive-init.mjs" --qa "$TMP/qa-locator-preserve-fail.json" --out "$TMP/locator-preserve-fail.log" \
  -- node "${BIN_DEV_ARGS[@]}" "$BIN" init; then
  echo "[FAIL] init did not fail when --save-locator's target path is a directory"; cat "$TMP/locator-preserve-fail.log"; exit 1
fi
grep -qi "EISDIR\|is a directory" "$TMP/locator-preserve-fail.log" || { echo "[FAIL] failure was not the expected locator-write EISDIR error"; cat "$TMP/locator-preserve-fail.log"; exit 1; }
grep -qi "ACTION REQUIRED" "$TMP/locator-preserve-fail.log" || { echo "[FAIL] failure message does not carry the ACTION REQUIRED hand-record instruction"; cat "$TMP/locator-preserve-fail.log"; exit 1; }
grep -qi "already happened and cannot be undone" "$TMP/locator-preserve-fail.log" || { echo "[FAIL] failure message does not state the upload already happened"; cat "$TMP/locator-preserve-fail.log"; exit 1; }
grep -q "NOT SAVED" "$TMP/locator-preserve-fail.log" || { echo "[FAIL] the outer message still prints a stale/null locator path instead of NOT SAVED"; cat "$TMP/locator-preserve-fail.log"; exit 1; }
grep -qF "$K_STORE" "$TMP/locator-preserve-fail.log" || { echo "[FAIL] failure message does not surface the backend's locator value for hand-recording"; cat "$TMP/locator-preserve-fail.log"; exit 1; }
[ -n "$(find "$K_STORE" -maxdepth 1 -name '*.age' 2>/dev/null | head -n1)" ] || { echo "[FAIL] no object landed in the file-backend store — the upload itself did not actually happen, this test proves nothing"; exit 1; }
[ -f "$K_CB_HOME/identity.age" ] || { echo "[FAIL] primary identity was DELETED after a successful push (locator-write failure wrongly treated as pre-push) — the finding-1 regression"; exit 1; }
[ -f "$K_CB_HOME/recipient.txt" ] || { echo "[FAIL] primary recipient was DELETED after a successful push"; exit 1; }
K_SNAP="$(find "$K_CB_HOME" -maxdepth 1 -name 'brain-*.age' 2>/dev/null | head -n1)"
[ -n "$K_SNAP" ] || { echo "[FAIL] the dated snapshot artifact was DELETED after a successful push"; exit 1; }
K_TMP_LEFTOVER="$(find "$K_CB_HOME" -maxdepth 1 -name 'latest-locator.tsv.*.tmp' 2>/dev/null | head -n1)"
[ -z "$K_TMP_LEFTOVER" ] || { echo "[FAIL] a .tmp sibling of the locator file survived: $K_TMP_LEFTOVER"; exit 1; }
echo "[PASS] a locator-write failure AFTER a successful push preserves the identity, recipient, AND the dated snapshot artifact — the error surfaces the ACTION-REQUIRED locator value instead of losing it"

echo "== (k2) retry after the finding-1 locator-write failure correctly REFUSES (identity + snapshot preserved, exactly as (j2)) =="
if CIPHER_BRAIN_HOME="$K_CB_HOME" CIPHER_BRAIN_INIT_ALLOW_NONINTERACTIVE=1 \
  with_timeout 10 node "${BIN_DEV_ARGS[@]}" "$BIN" init < /dev/null > "$TMP/locator-preserve-retry.log" 2>&1; then
  echo "[FAIL] a retry after a finding-1 locator-write failure did not refuse — it should, since the identity/snapshot are preserved"; cat "$TMP/locator-preserve-retry.log"; exit 1
fi
grep -qi "already exists" "$TMP/locator-preserve-retry.log" || { echo "[FAIL] retry's refusal was not the expected pre-existing-identity error"; cat "$TMP/locator-preserve-retry.log"; exit 1; }
echo "[PASS] a second 'cipher-brain init' run against the same CIPHER_BRAIN_HOME correctly refuses instead of silently starting over on top of the preserved, already-uploaded snapshot"

echo "== (l) partial backup keygen (identity.age written, recipient.txt write denied) doesn't orphan a backup identity (7th-round P2 fix, finding 2b) =="
# keygenAt() (keys.ts) writes identity.age (wx, exclusive-create) THEN recipient.txt.
# Pre-create the backup keypair's recipient.txt as a WRITE-DENIED (0444) regular file
# so identity.age's write still succeeds but recipient.txt's write throws EACCES —
# reproducing "identity.age written, recipient.txt write then throws" deterministically,
# without needing root/quota tricks. Before the fix, the wizard's OWN `backup` variable
# is only assigned AFTER this call returns, so the outer catch's `if (backup) { rm... }`
# rollback never runs for it — the freshly-written backup identity.age is orphaned even
# though the (unrelated) primary identity gets cleaned up by the pre-existing generic
# rollback (pushSucceeded is still false here).
L_HOME="$TMP/backup-partial-home"; mkdir -p "$L_HOME"
L_CB_HOME="$TMP/backup-partial-cb-home"
L_STORE="$TMP/backup-partial-store"
L_SRC="$TMP/backup-partial-src"; mkdir -p "$L_SRC"
printf 'backup-partial-marker\n' > "$L_SRC/note.txt"
L_BACKUP_HOME="${L_CB_HOME}-backup" # the default sibling path the wizard suggests for the backup key
mkdir -p "$L_BACKUP_HOME"
L_BLOCKED_RECIPIENT="$L_BACKUP_HOME/recipient.txt"
printf 'stale\n' > "$L_BLOCKED_RECIPIENT"
chmod 444 "$L_BLOCKED_RECIPIENT"

cat > "$TMP/qa-backup-partial-fail.json" <<JSON
[
  ["Generate an offline backup keypair now?", "y"],
  ["Path for the backup keypair", ""]
]
JSON
# (Push never happens on this run — it fails in step 2/6, long before step 6 — so the
# QA script stops right after the one prompt this failure is reached through.)

if CIPHER_BRAIN_HOME="$L_CB_HOME" CIPHER_BRAIN_FILE_DIR="$L_STORE" HOME="$L_HOME" CIPHER_BRAIN_INIT_ALLOW_NONINTERACTIVE=1 \
  with_timeout 30 node "$ROOT/scripts/drive-init.mjs" --qa "$TMP/qa-backup-partial-fail.json" --out "$TMP/backup-partial-fail.log" \
  -- node "${BIN_DEV_ARGS[@]}" "$BIN" init; then
  echo "[FAIL] init did not fail when the backup keypair's recipient.txt path is write-denied"; cat "$TMP/backup-partial-fail.log"; exit 1
fi
grep -qi "EACCES\|permission denied" "$TMP/backup-partial-fail.log" || { echo "[FAIL] failure was not the expected recipient.txt permission error"; cat "$TMP/backup-partial-fail.log"; exit 1; }
[ ! -f "$L_BACKUP_HOME/identity.age" ] || { echo "[FAIL] the orphaned backup identity.age survived a partial backup keygen — the finding-2b regression"; exit 1; }
[ ! -f "$L_CB_HOME/identity.age" ] || { echo "[FAIL] primary identity survived (the pre-existing generic rollback should still have cleared it)"; exit 1; }
echo "[PASS] a partial backup keygen (identity.age written, recipient.txt write denied) leaves NO orphaned backup identity behind"

echo "== (l2) retry after the finding-2b cleanup succeeds (same default backup path, backup=yes again) =="
# Before the fix this retry would be BLOCKED exactly like (h)'s original bug: the
# orphaned backup identity.age would make THIS SAME keygenAt() call refuse with its own
# "identity already exists" error (keys.ts), a second, independent brick beyond the
# primary-identity refusal (h) already covers. After the fix there is nothing left at
# that path, so a genuine retry (same answers) completes end-to-end.
#
# The round-8 fix (finding 1, backup-key site) changed WHICH files that cleanup is
# allowed to touch: it now only removes a target it can prove this SAME invocation
# just created — never something that pre-existed, since a pre-existing file at that
# path might be a REAL, previously-set-up backup identity (see test (l3) below). This
# test's own recipient.txt fixture (L_BLOCKED_RECIPIENT, chmod 444) pre-existed before
# (l)'s run even started, so it is now correctly left in place by the wizard, exactly
# like it would leave a real one alone — the wizard cannot tell "stale test fixture"
# apart from "real pre-existing key" any more than it can tell "stale" apart from
# "genuine" in general, and must not guess. A real user would notice the leftover
# obstruction from the failed run and clear it by hand before retrying; simulate
# exactly that one manual step here so this test still proves the REST of the retry
# story (a clean retry succeeds once nothing is actually left in the way).
rm -f "$L_BLOCKED_RECIPIENT"

cat > "$TMP/qa-backup-partial-retry.json" <<JSON
[
  ["Generate an offline backup keypair now?", "y"],
  ["Path for the backup keypair", ""],
  ["Protect the primary identity with a passphrase now?", "n"],
  ["Show a suggested CIPHER_BRAIN_PIN_RECIPIENTS line", "n"],
  ["Profile [none/", ""],
  ["Directory path(s) to back up", "$L_SRC"],
  ["Backend [file/", ""],
  ["Path to write the recovery kit", "$L_HOME/recovery-kit.txt"]
]
JSON
CIPHER_BRAIN_HOME="$L_CB_HOME" CIPHER_BRAIN_FILE_DIR="$L_STORE" HOME="$L_HOME" CIPHER_BRAIN_INIT_ALLOW_NONINTERACTIVE=1 \
  with_timeout 60 node "$ROOT/scripts/drive-init.mjs" --qa "$TMP/qa-backup-partial-retry.json" --out "$TMP/backup-partial-retry.log" \
  -- node "${BIN_DEV_ARGS[@]}" "$BIN" init \
  || { echo "[FAIL] retry after the finding-2b cleanup did not complete (orphan still blocking, or another regression)"; cat "$TMP/backup-partial-retry.log"; exit 1; }
grep -q 'cipher-brain init: complete' "$TMP/backup-partial-retry.log" || { echo "[FAIL] retry after finding-2b cleanup lacks its own completion marker"; cat "$TMP/backup-partial-retry.log"; exit 1; }
[ -f "$L_BACKUP_HOME/identity.age" ] || { echo "[FAIL] retry did not write a fresh backup identity at the same default path"; exit 1; }
echo "[PASS] a retry against the same CIPHER_BRAIN_HOME (same default backup path, backup=yes again) succeeds after the finding-2b cleanup — no leftover orphan blocks it"

echo "== (l3) pointing the backup-path prompt at an EXISTING real backup identity refuses without destroying it (round-8 regression fix) =="
# Round 7's own fix (6177702) wrapped the backup keygenAt() call in a try/catch that
# unconditionally rm'd identityPath/recipientPath on ANY failure, before rethrowing.
# keygenAt() (keys.ts) has its own precondition check — it throws BEFORE writing
# anything if identityPath already exists — so pointing the backup-path prompt at a
# directory that already holds a REAL, previously-set-up backup identity (e.g.
# re-running this step against an existing offline backup location) made that catch
# delete the real key for no reason other than "keygenAt declined to overwrite it":
# strictly worse than the bug it was fixing (permanent, unrecoverable key loss vs. a
# blocked retry). Prove the fix: a REAL backup identity pre-exists at the answered
# path (created via a real keygen, not a hand-rolled stand-in), keygenAt still
# refuses (unchanged behavior), and the pre-existing files survive completely
# untouched — byte-identical, not just "still present".
M_HOME="$TMP/backup-preexist-home"; mkdir -p "$M_HOME"
M_CB_HOME="$TMP/backup-preexist-cb-home"
M_STORE="$TMP/backup-preexist-store"
M_SRC="$TMP/backup-preexist-src"; mkdir -p "$M_SRC"
printf 'backup-preexist-marker\n' > "$M_SRC/note.txt"
M_BACKUP_HOME="$TMP/backup-preexist-existing-backup" # a REAL, already-set-up backup identity lives here BEFORE the wizard ever runs

CIPHER_BRAIN_HOME="$M_BACKUP_HOME" cb keygen > "$TMP/backup-preexist-setup.log" 2>&1 \
  || { echo "[FAIL] test setup: could not create a real pre-existing backup identity"; cat "$TMP/backup-preexist-setup.log"; exit 1; }
[ -f "$M_BACKUP_HOME/identity.age" ] || { echo "[FAIL] test setup: pre-existing backup identity.age was not created"; exit 1; }
[ -f "$M_BACKUP_HOME/recipient.txt" ] || { echo "[FAIL] test setup: pre-existing backup recipient.txt was not created"; exit 1; }
cp "$M_BACKUP_HOME/identity.age" "$TMP/backup-preexist-identity.age.orig"
cp "$M_BACKUP_HOME/recipient.txt" "$TMP/backup-preexist-recipient.txt.orig"

cat > "$TMP/qa-backup-preexist-fail.json" <<JSON
[
  ["Generate an offline backup keypair now?", "y"],
  ["Path for the backup keypair", "$M_BACKUP_HOME"]
]
JSON
# (Same as test (l): the failure happens in step 2/6, well before push — the QA
# script stops right after the one prompt this failure is reached through.)

if CIPHER_BRAIN_HOME="$M_CB_HOME" CIPHER_BRAIN_FILE_DIR="$M_STORE" HOME="$M_HOME" CIPHER_BRAIN_INIT_ALLOW_NONINTERACTIVE=1 \
  with_timeout 30 node "$ROOT/scripts/drive-init.mjs" --qa "$TMP/qa-backup-preexist-fail.json" --out "$TMP/backup-preexist-fail.log" \
  -- node "${BIN_DEV_ARGS[@]}" "$BIN" init; then
  echo "[FAIL] init did not refuse when the backup-path prompt points at an existing real backup identity"; cat "$TMP/backup-preexist-fail.log"; exit 1
fi
grep -qi "identity already exists" "$TMP/backup-preexist-fail.log" || { echo "[FAIL] failure was not keygenAt's own pre-existing-identity refusal"; cat "$TMP/backup-preexist-fail.log"; exit 1; }
[ -f "$M_BACKUP_HOME/identity.age" ] || { echo "[FAIL] the PRE-EXISTING real backup identity.age was DELETED — the round-8 regression"; exit 1; }
[ -f "$M_BACKUP_HOME/recipient.txt" ] || { echo "[FAIL] the PRE-EXISTING real backup recipient.txt was DELETED — the round-8 regression"; exit 1; }
cmp -s "$M_BACKUP_HOME/identity.age" "$TMP/backup-preexist-identity.age.orig" || { echo "[FAIL] the pre-existing backup identity.age survived but its CONTENT changed — not byte-identical"; exit 1; }
cmp -s "$M_BACKUP_HOME/recipient.txt" "$TMP/backup-preexist-recipient.txt.orig" || { echo "[FAIL] the pre-existing backup recipient.txt survived but its CONTENT changed — not byte-identical"; exit 1; }
[ ! -f "$M_CB_HOME/identity.age" ] || { echo "[FAIL] primary identity survived (the pre-existing generic rollback should still have cleared it)"; exit 1; }
echo "[PASS] pointing the backup-path prompt at a pre-existing real backup identity refuses (keygenAt's own guard, unchanged) and leaves it completely untouched, byte-identical — the round-8 regression is fixed"

echo "== THE DRILL (issue #68 acceptance criterion 2): kit-ONLY restore on a simulated fresh, fully isolated machine =="
# Isolation: a BRAND NEW temp dir with NO shared CIPHER_BRAIN_HOME, no leftover
# identity/config from the run above — the same "simulate a fresh machine"
# discipline scripts/selftest-arweave-nodeps.mjs and scripts/selftest-recovery.sh
# already use for their own recovery claims. Only what the KIT FILE ITSELF contains
# is extracted and used; the wizard's live CIPHER_BRAIN_HOME/BACKUP_HOME above are
# never read from here on. The file backend's store dir stands in for "the network"
# (same precedent selftest-recovery.sh uses for its own disk-death simulation) — a
# fresh machine in real life would reach arweave/turbo over the network instead.
DRILL="$TMP/drill-fresh-machine"; mkdir -p "$DRILL"

# Exact-line-anchored (^...$) so the human-readable prose in the kit's "RECOVERY
# STEPS" section — which describes these same two block names in a sentence — can
# never be mistaken for the real BEGIN/END delimiter lines.
awk '/^BEGIN BACKUP IDENTITY FILE$/{f=1;next}/^END BACKUP IDENTITY FILE$/{f=0}f' "$KIT_PATH" > "$DRILL/restore-identity.age"
awk '/^BEGIN SAVE-LOCATOR LINE$/{f=1;next}/^END SAVE-LOCATOR LINE$/{f=0}f' "$KIT_PATH" > "$DRILL/restore-locator.tsv"
[ -s "$DRILL/restore-identity.age" ] || { echo "DRILL RESULT: [FAIL] extracted backup identity from the kit is empty"; exit 1; }
[ -s "$DRILL/restore-locator.tsv" ] || { echo "DRILL RESULT: [FAIL] extracted save-locator line from the kit is empty"; exit 1; }
grep -q '^AGE-SECRET-KEY-1' "$DRILL/restore-identity.age" || { echo "DRILL RESULT: [FAIL] extracted identity does not look like an age secret key"; exit 1; }

CIPHER_BRAIN_FILE_DIR="$WIZ_STORE" HOME="$DRILL" CIPHER_BRAIN_HOME="$DRILL/no-such-home" \
  cb pull --from-locator-file "$DRILL/restore-locator.tsv" --out "$DRILL/restored.age" > "$TMP/drill-pull.log" 2>&1 \
  || { echo "DRILL RESULT: [FAIL] pull --from-locator-file (kit's locator alone) failed"; cat "$TMP/drill-pull.log"; exit 1; }
CIPHER_BRAIN_HOME="$DRILL/no-such-home" \
  cb restore --in "$DRILL/restored.age" --out-dir "$DRILL/restored" --identity "$DRILL/restore-identity.age" > "$TMP/drill-restore.log" 2>&1 \
  || { echo "DRILL RESULT: [FAIL] restore --identity (kit's backup identity alone) failed"; cat "$TMP/drill-restore.log"; exit 1; }

TARFILE="$(find "$DRILL/restored" -maxdepth 1 -name '*.tar.gz' | head -n1)"
[ -n "$TARFILE" ] || { echo "DRILL RESULT: [FAIL] no archived component found in the restored tree"; exit 1; }
tar -xzf "$TARFILE" -C "$DRILL/restored"
RESTORED_SRC_DIR="$DRILL/restored/$(basename "$SRC")"
[ -d "$RESTORED_SRC_DIR" ] || { echo "DRILL RESULT: [FAIL] restored tree does not contain the extracted source directory"; exit 1; }
diff -r "$SRC" "$RESTORED_SRC_DIR" > "$TMP/drill-diff.log" 2>&1 \
  || { echo "DRILL RESULT: [FAIL] restored content differs from the source"; cat "$TMP/drill-diff.log"; exit 1; }
grep -q "$MARKER" "$RESTORED_SRC_DIR/note.txt" || { echo "DRILL RESULT: [FAIL] restored content does not contain the source's unique marker"; exit 1; }
echo "DRILL RESULT: [PASS] kit-only restore on a simulated fresh, isolated machine is byte-identical to the original source (issue #68 acceptance criterion 2 — recorded)"

echo "== (m) a detected gbrain config prompts for --pg and actually threads it into the snapshot (issue #84) =="
# Before the fix, --pg was unreachable from `init` at all (grep never found it in
# wizard.ts) — a gbrain user answering the profile/directory prompts naturally (none +
# ~/.gbrain) got a backup of gbrain's CONFIG only, never its real data (Postgres). Prove
# both halves: (1) the new prompt actually appears when a local gbrain config exists,
# defaulting to YES, and (2) the resulting snapshot/kit genuinely carry a pg_dump
# component end-to-end — not just a flag the wizard silently drops. pg_dump is SHIMMED
# (via CIPHER_BRAIN_PG_BIN) so this needs no real Postgres server, the same technique
# scripts/selftest-schedule.sh's own --pg test already uses.
PG_HOME="$TMP/pg-home"; mkdir -p "$PG_HOME/.gbrain"
printf '{"schema_pack":"gbrain-base-v2"}\n' > "$PG_HOME/.gbrain/config.json"
PG_CB_HOME="$TMP/pg-cb-home"
PG_STORE="$TMP/pg-store"
PG_SRC="$TMP/pg-src"; mkdir -p "$PG_SRC"
printf 'pg-marker\n' > "$PG_SRC/note.txt"
PG_KIT_PATH="$PG_HOME/recovery-kit.txt"
TEST_PG_CONN="postgres://tester@localhost:5432/gbrain-selftest"

FAKE_PGBIN="$TMP/fake-pgbin-snapshot"; mkdir -p "$FAKE_PGBIN"
cat > "$FAKE_PGBIN/pg_dump" <<'SHIM'
#!/usr/bin/env bash
# args: -Fc --no-owner --no-privileges [-t table ...] -f <dumpPath> <conn> — find -f's value
out=""; prev=""
for a in "$@"; do
  if [ "$prev" = "-f" ]; then out="$a"; fi
  prev="$a"
done
printf 'fake-pg-dump-content\n' > "$out"
exit 0
SHIM
chmod +x "$FAKE_PGBIN/pg_dump"

cat > "$TMP/qa-pg.json" <<JSON
[
  ["Generate an offline backup keypair now?", "n"],
  ["Protect the primary identity with a passphrase now?", "n"],
  ["Show a suggested CIPHER_BRAIN_PIN_RECIPIENTS line", "n"],
  ["Profile [none/", ""],
  ["Directory path(s) to back up", "$PG_SRC"],
  ["Include a Postgres database dump", ""],
  ["Postgres connection string", "$TEST_PG_CONN"],
  ["Backend [file/", ""],
  ["Path to write the recovery kit", "$PG_KIT_PATH"]
]
JSON

CIPHER_BRAIN_HOME="$PG_CB_HOME" CIPHER_BRAIN_FILE_DIR="$PG_STORE" HOME="$PG_HOME" CIPHER_BRAIN_INIT_ALLOW_NONINTERACTIVE=1 CIPHER_BRAIN_PG_BIN="$FAKE_PGBIN" \
  with_timeout 90 node "$ROOT/scripts/drive-init.mjs" --qa "$TMP/qa-pg.json" --out "$TMP/wizard-pg.log" \
  -- node "${BIN_DEV_ARGS[@]}" "$BIN" init \
  || { echo "[FAIL] the gbrain-detected pg scripted run did not complete"; cat "$TMP/wizard-pg.log"; exit 1; }
grep -q 'cipher-brain init: complete' "$TMP/wizard-pg.log" || { echo "[FAIL] pg run: wizard log lacks its own completion marker"; cat "$TMP/wizard-pg.log"; exit 1; }
grep -qF "Detected a gbrain config at $PG_HOME/.gbrain/config.json" "$TMP/wizard-pg.log" || { echo "[FAIL] wizard did not detect the gbrain config fixture"; cat "$TMP/wizard-pg.log"; exit 1; }
grep -q 'postgres:          included (pg_dump)' "$TMP/wizard-pg.log" || { echo "[FAIL] completion summary does not report the Postgres dump as included"; cat "$TMP/wizard-pg.log"; exit 1; }
echo "[PASS] a detected gbrain config prompts for --pg (defaulting to yes) and the wizard reports it as included"

PG_SNAP="$(find "$PG_CB_HOME" -maxdepth 1 -name 'brain-*.age' | head -n1)"
[ -n "$PG_SNAP" ] || { echo "[FAIL] no brain-*.age snapshot found for the pg run"; exit 1; }
PG_RESTORE_DIR="$TMP/pg-restored"
CIPHER_BRAIN_HOME="$PG_CB_HOME" cb restore --in "$PG_SNAP" --out-dir "$PG_RESTORE_DIR" > "$TMP/pg-restore.log" 2>&1 \
  || { echo "[FAIL] restoring the pg run's snapshot failed"; cat "$TMP/pg-restore.log"; exit 1; }
[ -f "$PG_RESTORE_DIR/db.dump" ] || { echo "[FAIL] restored tree has no db.dump — --pg was not actually threaded into snapshot()"; exit 1; }
grep -qF 'fake-pg-dump-content' "$PG_RESTORE_DIR/db.dump" || { echo "[FAIL] db.dump does not contain the shimmed pg_dump output — the wizard is not really invoking pg_dump"; exit 1; }
grep -q 'pg_dump:custom' "$PG_RESTORE_DIR/manifest.json" || { echo "[FAIL] manifest.json does not record a pg_dump:custom component"; cat "$PG_RESTORE_DIR/manifest.json"; exit 1; }
echo "[PASS] the snapshot genuinely contains a pg_dump component (shimmed pg_dump was invoked and its real output archived, not just a flag threaded through)"

[ -f "$PG_KIT_PATH" ] || { echo "[FAIL] recovery kit was not written for the pg run"; exit 1; }
grep -qF "Postgres dump: included (connection: $TEST_PG_CONN)" "$PG_KIT_PATH" || { echo "[FAIL] kit header does not record the Postgres connection used"; cat "$PG_KIT_PATH"; exit 1; }
grep -q 'THIS BACKUP ALSO INCLUDES A POSTGRES DUMP' "$PG_KIT_PATH" || { echo "[FAIL] kit is missing the pg-restore safety block"; cat "$PG_KIT_PATH"; exit 1; }
grep -qF "Its SOURCE connection was: $TEST_PG_CONN" "$PG_KIT_PATH" || { echo "[FAIL] pg-restore safety block does not name the source connection"; cat "$PG_KIT_PATH"; exit 1; }
grep -q 'SCRATCH database' "$PG_KIT_PATH" || { echo "[FAIL] pg-restore safety block does not point at a SCRATCH database"; cat "$PG_KIT_PATH"; exit 1; }
# Fugu review finding: the printed restore command must NOT auto-embed the SOURCE
# connection as the restore --pg target — pg_restore --clean would DROP/replace objects
# in whatever database --pg names, so a verbatim copy-paste could clobber a live DB.
if grep -qF -- "--pg \"$TEST_PG_CONN\"" "$PG_KIT_PATH"; then echo "[FAIL] kit restore command auto-embeds the SOURCE connection as --pg — copy-paste risks clobbering the live database"; cat "$PG_KIT_PATH"; exit 1; fi
echo "[PASS] the recovery kit records the Postgres connection used and warns to restore into a SCRATCH database instead of auto-embedding --pg with the source"

echo
echo "INIT SELFTEST PASS"
