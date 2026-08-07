#!/usr/bin/env bash
# `recovery-kit` selftest (#364): the standalone kit regeneration renders the
# SAME canonical kit init does (shared builder in src/lib/recoverykit.ts),
# pointed at the CURRENT push's locator. Proves:
#   - the kit carries the exact save-locator line (locator + sha) of the push,
#   - --out writes 0600 and refuses an existing file without --force,
#   - --inline-identity REFUSES an unwrapped identity (the guard the flag
#     exists for) and accepts a wrapped+armored one,
#   - --backup-identity inlines an unwrapped backup with a LOUD warning, and
#     a wrapped backup without --backup-recipient is refused,
#   - a regenerated kit reports profile/Postgres as unknown, never guessed.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/bin/cipher-brain.mjs"
source "$ROOT/scripts/dev-node-flags.sh"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
HOME_DIR="$TMP/home"; BACKUP="$TMP/keys-backup"
cb() { CIPHER_BRAIN_HOME="$HOME_DIR" CIPHER_BRAIN_FILE_DIR="$TMP/store" node "${BIN_DEV_ARGS[@]}" "$BIN" "$@"; }

echo "== setup: keygen + snapshot + push --backend file --save-locator =="
cb keygen >/dev/null
CIPHER_BRAIN_HOME="$BACKUP" node "${BIN_DEV_ARGS[@]}" "$BIN" keygen >/dev/null
SRC="$TMP/brain"; mkdir -p "$SRC"; printf 'kit-selftest\n' > "$SRC/note.txt"
cb snapshot --dir "$SRC" --out "$TMP/snap.age" >/dev/null
LOCF="$TMP/loc.tsv"
cb push --in "$TMP/snap.age" --backend file --save-locator "$LOCF" >/dev/null
LOCLINE="$(grep -v '^#' "$LOCF" | grep -m1 .)"

echo "== kit to stdout carries the exact save-locator line and unknown markers =="
KIT="$TMP/kit-stdout.txt"
cb recovery-kit --from-locator-file "$LOCF" > "$KIT"
grep -qF "$LOCLINE" "$KIT" || { echo "[FAIL] kit does not carry the save-locator line verbatim"; exit 1; }
grep -q 'CIPHER-BRAIN RECOVERY KIT' "$KIT" || { echo "[FAIL] kit header missing"; exit 1; }
grep -q 'not recorded — kit regenerated' "$KIT" || { echo "[FAIL] regenerated kit must mark profile unknown"; exit 1; }
grep -q 'Postgres dump: unknown' "$KIT" || { echo "[FAIL] regenerated kit must mark the pg column unknown"; exit 1; }
grep -q 'LOCATOR IS LOCAL-ONLY' "$KIT" || { echo "[FAIL] file-backend kit must carry the local-only warning"; exit 1; }
grep -q 'NO BACKUP IDENTITY IS IN THIS KIT' "$KIT" || { echo "[FAIL] no-backup kit must say kit-only recovery is impossible"; exit 1; }
echo "[PASS] stdout kit: verbatim locator line + honest unknown/local-only/no-backup marks"

echo "== --out writes 0600 and no-clobbers without --force =="
OUT="$TMP/kit.txt"
cb recovery-kit --from-locator-file "$LOCF" --out "$OUT" >/dev/null
MODE="$(stat -f %Lp "$OUT" 2>/dev/null || stat -c %a "$OUT")"
[ "$MODE" = "600" ] || { echo "[FAIL] kit written with mode $MODE, expected 600"; exit 1; }
if cb recovery-kit --from-locator-file "$LOCF" --out "$OUT" >/dev/null 2>"$TMP/clobber.err"; then
  echo "[FAIL] second --out to the same path must refuse without --force"; exit 1
fi
grep -q 'refusing to overwrite' "$TMP/clobber.err" || { echo "[FAIL] no-clobber refusal must say why"; exit 1; }
cb recovery-kit --from-locator-file "$LOCF" --out "$OUT" --force >/dev/null
echo "[PASS] --out is 0600, no-clobber by default, --force overrides"

echo "== --inline-identity refuses an UNWRAPPED identity (the guard, #364) =="
if cb recovery-kit --from-locator-file "$LOCF" --inline-identity >/dev/null 2>"$TMP/inline.err"; then
  echo "[FAIL] inlining a bare private key must be refused"; exit 1
fi
grep -q 'NOT passphrase-wrapped' "$TMP/inline.err" || { echo "[FAIL] refusal must name the wrap requirement"; exit 1; }
echo "[PASS] unwrapped primary is refused for --inline-identity"

echo "== --inline-identity accepts a wrapped+armored identity =="
# The guard checks the identity file's SHAPE (no AGE-SECRET-KEY line + armor
# markers) — synthesize that shape rather than driving an interactive
# passphrase wrap; the crypto itself is loadIdentities()' job, tested elsewhere.
WRAPPED_HOME="$TMP/home-wrapped"; mkdir -p "$WRAPPED_HOME"
cp "$HOME_DIR/recipient.txt" "$WRAPPED_HOME/recipient.txt"
printf -- '-----BEGIN AGE ENCRYPTED FILE-----\nYWdlLWVuY3J5cHRpb24ub3JnL3YxCg==\n-----END AGE ENCRYPTED FILE-----\n' > "$WRAPPED_HOME/identity.age"
WKIT="$TMP/kit-wrapped.txt"
CIPHER_BRAIN_HOME="$WRAPPED_HOME" CIPHER_BRAIN_FILE_DIR="$TMP/store" node "${BIN_DEV_ARGS[@]}" "$BIN" \
  recovery-kit --from-locator-file "$LOCF" --inline-identity > "$WKIT"
grep -q 'BEGIN PRIMARY IDENTITY FILE' "$WKIT" || { echo "[FAIL] wrapped identity was not inlined"; exit 1; }
grep -q 'passphrase-wrapped copy inlined' "$WKIT" || { echo "[FAIL] inlined kit must flag the section header"; exit 1; }
grep -q 'The two marker' "$WKIT" || { echo "[FAIL] inlined kit must switch to the verbatim recovery steps"; exit 1; }
echo "[PASS] wrapped+armored primary inlines, with the kit-only recovery steps"

echo "== --backup-identity: unwrapped inlines with a LOUD warning =="
BKIT="$TMP/kit-backup.txt"
cb recovery-kit --from-locator-file "$LOCF" --backup-identity "$BACKUP/identity.age" > "$BKIT" 2>"$TMP/backup.err"
grep -q 'BEGIN BACKUP IDENTITY FILE' "$BKIT" || { echo "[FAIL] backup identity was not inlined"; exit 1; }
grep -q 'age1' "$BKIT" || { echo "[FAIL] derived backup recipient missing from the kit"; exit 1; }
grep -q 'NOT passphrase-wrapped' "$TMP/backup.err" || { echo "[FAIL] unwrapped backup must warn on stderr"; exit 1; }
echo "[PASS] unwrapped backup inlines + warns; recipient derived without a flag"

echo "== --backup-identity: wrapped without --backup-recipient is refused =="
printf -- '-----BEGIN AGE ENCRYPTED FILE-----\nYWdlLWVuY3J5cHRpb24ub3JnL3YxCg==\n-----END AGE ENCRYPTED FILE-----\n' > "$TMP/wrapped-backup.age"
if cb recovery-kit --from-locator-file "$LOCF" --backup-identity "$TMP/wrapped-backup.age" >/dev/null 2>"$TMP/wb.err"; then
  echo "[FAIL] wrapped backup without --backup-recipient must be refused"; exit 1
fi
grep -q 'backup-recipient' "$TMP/wb.err" || { echo "[FAIL] refusal must name --backup-recipient"; exit 1; }
cb recovery-kit --from-locator-file "$LOCF" --backup-identity "$TMP/wrapped-backup.age" \
  --backup-recipient "$BACKUP/recipient.txt" > "$TMP/kit-wb.txt"
grep -q 'BEGIN BACKUP IDENTITY FILE' "$TMP/kit-wb.txt" || { echo "[FAIL] wrapped backup + recipient did not inline"; exit 1; }
echo "[PASS] wrapped backup needs --backup-recipient, then inlines"

echo "== missing/empty locator file fails closed =="
if cb recovery-kit --from-locator-file "$TMP/nope.tsv" >/dev/null 2>&1; then
  echo "[FAIL] a missing locator file must be an error"; exit 1
fi
if cb recovery-kit >/dev/null 2>"$TMP/noflag.err"; then
  echo "[FAIL] recovery-kit without --from-locator-file must be an error"; exit 1
fi
grep -q 'from-locator-file' "$TMP/noflag.err" || { echo "[FAIL] the error must name the missing flag"; exit 1; }
echo "[PASS] fails closed on a missing flag or unreadable locator file"

echo
echo "RECOVERY-KIT SELFTEST: PASS"
