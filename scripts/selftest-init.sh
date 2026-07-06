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
echo "[PASS] a kit path that pre-existed at mode 644 ends up mode 600 after the wizard writes it (chmod-after-write fix)"

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

echo "== (j) rollback also removes the snapshot artifact + sidecars when a step AFTER snapshot() fails (5th-round P2 fix) =="
# The fb293ff rollback (test h above) deletes the identity/recipient files on any
# post-creation failure, but did NOT delete the dated snapshot output (--out) or its
# .digest / .recipients-fingerprint sidecars if the failure happened AFTER snapshot()
# itself succeeded (e.g. push, or the recovery-kit write, fails afterward).
# snapshot()'s own promote step (promoteSnapshot in snapshot.ts) refuses to overwrite
# an existing --out, and the wizard's --out is dated per-day — so leaving that file
# behind means a same-day retry regenerates the identity fine, then fails AGAIN at
# the snapshot step with a "file already exists" error. Fail deterministically AFTER
# both snapshot() and push() succeed by making the very last step — the recovery
# kit's own mkdir/write — fail: pre-create the kit path's PARENT as a plain FILE (not
# a directory), so mkdir(dirname(kitPath), { recursive: true }) throws ENOTDIR.
SNAP_HOME="$TMP/snap-rollback-home"; mkdir -p "$SNAP_HOME"
SNAP_CB_HOME="$TMP/snap-rollback-cb-home"
SNAP_STORE="$TMP/snap-rollback-store"
SNAP_SRC="$TMP/snap-rollback-src"; mkdir -p "$SNAP_SRC"
printf 'snap-rollback-marker\n' > "$SNAP_SRC/note.txt"
BLOCKED_PARENT="$SNAP_HOME/blocked-kit-parent"
: > "$BLOCKED_PARENT" # plain FILE — the kit path nests a dir UNDER this, so mkdir -p
                      # must traverse it as a parent component (ENOTDIR), not just
                      # target it directly (which would be EEXIST instead)
BLOCKED_KIT_PATH="$BLOCKED_PARENT/subdir/recovery-kit.txt"

cat > "$TMP/qa-snap-rollback-fail.json" <<JSON
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
  with_timeout 60 node "$ROOT/scripts/drive-init.mjs" --qa "$TMP/qa-snap-rollback-fail.json" --out "$TMP/snap-rollback-fail.log" \
  -- node "${BIN_DEV_ARGS[@]}" "$BIN" init; then
  echo "[FAIL] init did not fail when the recovery-kit path's parent is a plain file"; cat "$TMP/snap-rollback-fail.log"; exit 1
fi
grep -qi "ENOTDIR\|not a directory" "$TMP/snap-rollback-fail.log" || { echo "[FAIL] failure was not the expected kit-write ENOTDIR error"; cat "$TMP/snap-rollback-fail.log"; exit 1; }
[ ! -f "$SNAP_CB_HOME/identity.age" ] || { echo "[FAIL] primary identity survived a post-snapshot failure"; exit 1; }
[ ! -f "$SNAP_CB_HOME/recipient.txt" ] || { echo "[FAIL] primary recipient survived a post-snapshot failure"; exit 1; }
SNAP_LEFTOVER="$(find "$SNAP_CB_HOME" -maxdepth 1 -name 'brain-*.age*' 2>/dev/null | head -n1)"
[ -z "$SNAP_LEFTOVER" ] || { echo "[FAIL] a snapshot artifact/sidecar survived a post-snapshot failure: $SNAP_LEFTOVER"; exit 1; }
echo "[PASS] a failure AFTER snapshot() succeeds (kit write) rolls back the identity AND the dated snapshot artifact + its .digest/.recipients-fingerprint sidecars"

echo "== (j2) retry after the snapshot-artifact rollback completes cleanly (same day, same --out path) =="
rm -f "$BLOCKED_PARENT" # unblock: this run gets a real directory for the kit path this time
SNAP_KIT_PATH="$SNAP_HOME/recovery-kit.txt"
cat > "$TMP/qa-snap-rollback-retry.json" <<JSON
[
  ["Generate an offline backup keypair now?", "n"],
  ["Protect the primary identity with a passphrase now?", "n"],
  ["Show a suggested CIPHER_BRAIN_PIN_RECIPIENTS line", "n"],
  ["Profile [none/", ""],
  ["Directory path(s) to back up", "$SNAP_SRC"],
  ["Backend [file/", ""],
  ["Path to write the recovery kit", "$SNAP_KIT_PATH"]
]
JSON

CIPHER_BRAIN_HOME="$SNAP_CB_HOME" CIPHER_BRAIN_FILE_DIR="$SNAP_STORE" HOME="$SNAP_HOME" CIPHER_BRAIN_INIT_ALLOW_NONINTERACTIVE=1 \
  with_timeout 60 node "$ROOT/scripts/drive-init.mjs" --qa "$TMP/qa-snap-rollback-retry.json" --out "$TMP/snap-rollback-retry.log" \
  -- node "${BIN_DEV_ARGS[@]}" "$BIN" init \
  || { echo "[FAIL] retry after the snapshot-artifact rollback did not complete (a leftover --out likely still blocked the same-day snapshot path)"; cat "$TMP/snap-rollback-retry.log"; exit 1; }
grep -q 'cipher-brain init: complete' "$TMP/snap-rollback-retry.log" || { echo "[FAIL] retry after snapshot-artifact rollback lacks its own completion marker"; cat "$TMP/snap-rollback-retry.log"; exit 1; }
[ -f "$SNAP_CB_HOME/identity.age" ] || { echo "[FAIL] retry did not write a fresh primary identity"; exit 1; }
[ -n "$(find "$SNAP_CB_HOME" -maxdepth 1 -name 'brain-*.age' 2>/dev/null | head -n1)" ] || { echo "[FAIL] retry did not produce a snapshot file"; exit 1; }
echo "[PASS] a second 'cipher-brain init' run against the same CIPHER_BRAIN_HOME (same day, same dated --out) starts clean and completes after the snapshot-artifact rollback"

echo "== THE DRILL (issue #68 acceptance criterion 2): kit-ONLY restore on a simulated fresh, fully isolated machine =="
# Isolation: a BRAND NEW temp dir with NO shared CIPHER_BRAIN_HOME, no leftover
# identity/config from the run above — the same "simulate a fresh machine"
# discipline scripts/selftest-arweave-nodeps.mjs and scripts/selftest-recovery.sh
# already use for their own recovery claims. Only what the KIT FILE ITSELF contains
# is extracted and used; the wizard's live CIPHER_BRAIN_HOME/BACKUP_HOME above are
# never read from here on. The file backend's store dir stands in for "the network"
# (same precedent selftest-recovery.sh uses for its own disk-death simulation) — a
# fresh machine in real life would reach arweave/turbo/ton over the network instead.
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

echo
echo "INIT SELFTEST PASS"
