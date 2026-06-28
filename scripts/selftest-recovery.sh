#!/usr/bin/env bash
# Key-recovery + versioning proof (issue #3), daemon-free so CI can gate it.
# Encrypts a snapshot to a PRIMARY *and* an offline BACKUP key, then shows:
#   - the primary identity restores,
#   - the BACKUP identity restores too (so losing the primary != losing the brain),
#   - an unrelated third identity cannot,
#   - two different snapshots are independently restorable (versioning).
set -euo pipefail

BIN="$(cd "$(dirname "$0")/.." && pwd)/bin/cipher-brain.mjs"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
PRIMARY="$TMP/keys-primary"; BACKUP="$TMP/keys-backup"; THIRD="$TMP/keys-third"
cb() { CIPHER_BRAIN_HOME="$1" node "$BIN" "${@:2}"; }

echo "== three independent keypairs =="
cb "$PRIMARY" keygen >/dev/null
cb "$BACKUP"  keygen >/dev/null
cb "$THIRD"   keygen >/dev/null

SRC="$TMP/brain"; mkdir -p "$SRC"
printf 'brain-v1-%s\n' "$(od -An -N4 -tx1 /dev/urandom | tr -d ' ')" > "$SRC/note.txt"
V1MARK=$(cat "$SRC/note.txt")

echo "== snapshot v1 -> encrypt to PRIMARY *and* BACKUP =="
cb "$PRIMARY" snapshot --dir "$SRC" \
  --recipient "$PRIMARY/recipient.txt" --recipient "$BACKUP/recipient.txt" --out "$TMP/v1.age"

echo "== primary identity restores =="
cb "$PRIMARY" restore --in "$TMP/v1.age" --out-dir "$TMP/r-primary" >/dev/null
tar -xzf "$TMP/r-primary/brain.tar.gz" -C "$TMP/r-primary"
diff -r "$SRC" "$TMP/r-primary/brain" || { echo "[FAIL] primary restore content mismatch"; exit 1; }
echo "[PASS] primary identity restores"

echo "== BACKUP identity restores too (key recovery: primary not needed) =="
cb "$BACKUP" restore --in "$TMP/v1.age" --out-dir "$TMP/r-backup" >/dev/null
tar -xzf "$TMP/r-backup/brain.tar.gz" -C "$TMP/r-backup"
diff -r "$SRC" "$TMP/r-backup/brain" || { echo "[FAIL] backup restore content mismatch"; exit 1; }
echo "[PASS] BACKUP key restores without the primary identity"

echo "== an unrelated third identity cannot restore =="
if cb "$THIRD" restore --in "$TMP/v1.age" --out-dir "$TMP/r-third" 2>/dev/null; then
  echo "[FAIL] a non-recipient identity restored"; exit 1
fi
echo "[PASS] non-recipient identity is rejected"

echo "== versioning: a second snapshot is independently restorable =="
printf 'brain-v2-%s\n' "$(od -An -N4 -tx1 /dev/urandom | tr -d ' ')" > "$SRC/note.txt"
V2MARK=$(cat "$SRC/note.txt")
cb "$PRIMARY" snapshot --dir "$SRC" --recipient "$PRIMARY/recipient.txt" --out "$TMP/v2.age"
cb "$PRIMARY" restore --in "$TMP/v1.age" --out-dir "$TMP/rv1" >/dev/null
cb "$PRIMARY" restore --in "$TMP/v2.age" --out-dir "$TMP/rv2" >/dev/null
tar -xzf "$TMP/rv1/brain.tar.gz" -C "$TMP/rv1"; tar -xzf "$TMP/rv2/brain.tar.gz" -C "$TMP/rv2"
grep -q "$V1MARK" "$TMP/rv1/brain/note.txt" && grep -q "$V2MARK" "$TMP/rv2/brain/note.txt" \
  && echo "[PASS] both versions restore to their own content" || { echo "[FAIL] version mismatch"; exit 1; }

echo "== durable locator: a fresh machine with the identity but NO index.tsv recovers via --save-locator =="
# A "latest" snapshot encrypted to BOTH keys (so the off-box backup identity can open it),
# pushed to the file backend with the locator saved off-box. Then simulate disk-death:
# the only things that survive are (a) the BACKUP identity and (b) the saved locator file
# — NOT index.tsv, NOT the store path typed by hand. Recovery must find the bytes from the
# locator file alone.
printf 'brain-latest-%s\n' "$(od -An -N4 -tx1 /dev/urandom | tr -d ' ')" > "$SRC/note.txt"
LATESTMARK=$(cat "$SRC/note.txt")
cb "$PRIMARY" snapshot --dir "$SRC" \
  --recipient "$PRIMARY/recipient.txt" --recipient "$BACKUP/recipient.txt" --out "$TMP/latest.age"
STORE="$TMP/store"; LOCFILE="$TMP/offbox/latest-locator.tsv"
CIPHER_BRAIN_FILE_DIR="$STORE" cb "$PRIMARY" push --in "$TMP/latest.age" --backend file \
  --save-locator "$LOCFILE" >/dev/null
test -f "$LOCFILE" || { echo "[FAIL] --save-locator wrote no file"; exit 1; }
# the saved file must carry the backend AND an integrity pin (sha256) so pull needs no
# other knowledge and is fail-closed against a substituted ciphertext.
SAVED_BACKEND=$(cut -f2 "$LOCFILE"); SAVED_SHA=$(cut -f3 "$LOCFILE")
[ "$SAVED_BACKEND" = "file" ] || { echo "[FAIL] locator file backend column != file"; cat "$LOCFILE"; exit 1; }
[ "$SAVED_SHA" = "$(shasum -a 256 "$TMP/latest.age" | cut -d' ' -f1)" ] \
  || { echo "[FAIL] locator file sha256 column does not match the ciphertext"; cat "$LOCFILE"; exit 1; }
echo "[PASS] push --save-locator wrote <locator>\\t<backend>\\t<sha256>"
# fresh machine: BACKUP identity present, index.tsv absent, only the locator file + store
CIPHER_BRAIN_FILE_DIR="$STORE" cb "$BACKUP" pull --from-locator-file "$LOCFILE" --out "$TMP/recovered.age" >/dev/null
cmp -s "$TMP/latest.age" "$TMP/recovered.age" || { echo "[FAIL] --from-locator-file fetched different bytes"; exit 1; }
cb "$BACKUP" restore --in "$TMP/recovered.age" --out-dir "$TMP/r-loc" >/dev/null
tar -xzf "$TMP/r-loc/brain.tar.gz" -C "$TMP/r-loc"
grep -q "$LATESTMARK" "$TMP/r-loc/brain/note.txt" \
  && echo "[PASS] fresh machine recovered latest snapshot from identity + saved locator alone" \
  || { echo "[FAIL] locator-file recovery content mismatch"; exit 1; }
# the saved sha256 must actually fail-close: corrupt the stored object and confirm a
# --from-locator-file pull rejects it (the integrity pin fires) and leaves no --out.
STORED_OBJ=$(cut -f1 "$LOCFILE")
cp "$STORED_OBJ" "$TMP/obj.bak"
printf 'TAMPERED' >> "$STORED_OBJ"   # same locator (path), different bytes
if CIPHER_BRAIN_FILE_DIR="$STORE" cb "$BACKUP" pull --from-locator-file "$LOCFILE" --out "$TMP/tampered.age" 2>/dev/null; then
  echo "[FAIL] recovery accepted a tampered ciphertext (integrity pin did not fire)"; exit 1
fi
test ! -f "$TMP/tampered.age" || { echo "[FAIL] tampered --out was left behind (not fail-closed)"; exit 1; }
cp "$TMP/obj.bak" "$STORED_OBJ"      # restore the good object
echo "[PASS] saved sha256 fail-closes recovery against a substituted ciphertext"
# malformed locator file (no backend column) must error clearly, not fall through to the
# generic "--backend required" message.
printf 'just-a-locator-no-tab\n' > "$TMP/bad-locator.tsv"
set +e
BADOUT=$(CIPHER_BRAIN_FILE_DIR="$STORE" cb "$BACKUP" pull --from-locator-file "$TMP/bad-locator.tsv" --out "$TMP/x.age" 2>&1); BADRC=$?
set -e
[ "$BADRC" != "0" ] || { echo "[FAIL] malformed locator file did not error"; exit 1; }
printf '%s' "$BADOUT" | grep -q "must contain" || { echo "[FAIL] malformed locator file error is not specific"; echo "$BADOUT"; exit 1; }
echo "[PASS] malformed locator file (missing backend) errors clearly"
# --save-locator must be overwrite-only (always the LATEST), not appended
printf 'brain-v3-%s\n' "$(od -An -N4 -tx1 /dev/urandom | tr -d ' ')" > "$SRC/note.txt"
cb "$PRIMARY" snapshot --dir "$SRC" --recipient "$PRIMARY/recipient.txt" --out "$TMP/v3.age"
CIPHER_BRAIN_FILE_DIR="$STORE" cb "$PRIMARY" push --in "$TMP/v3.age" --backend file \
  --save-locator "$LOCFILE" >/dev/null
[ "$(grep -c . "$LOCFILE")" = "1" ] || { echo "[FAIL] locator file has >1 line (should hold only the latest)"; cat "$LOCFILE"; exit 1; }
echo "[PASS] --save-locator holds only the latest locator (overwrite, not append)"

echo
echo "RECOVERY SELFTEST PASS"
