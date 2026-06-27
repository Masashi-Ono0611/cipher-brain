#!/usr/bin/env bash
# Storage round-trip proof for the FILE backend (issue #2), daemon-free so CI can
# gate push/pull: snapshot -> push -> (delete original) -> pull -> verify -> restore.
# Asserts the locator is content-addressed (not the source path), the stored bytes
# match, the pulled bytes round-trip and decrypt, and an absent locator errors.
# The TON backend's real cross-node transfer is proven separately by an operator
# (scripts/ton-roundtrip.sh) — that needs a running storage-daemon.
set -euo pipefail

BIN="$(cd "$(dirname "$0")/.." && pwd)/bin/cipher-brain.mjs"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
export CIPHER_BRAIN_HOME="$TMP/keys"
export CIPHER_BRAIN_FILE_DIR="$TMP/store"
cb() { node "$BIN" "$@"; }
sha() { shasum -a 256 "$1" | cut -d' ' -f1; }

MARKER="secret-thought-$(od -An -N6 -tx1 /dev/urandom | tr -d ' ')"
SRC="$TMP/brain-src"; mkdir -p "$SRC"
printf '%s\n' "$MARKER" > "$SRC/note.txt"
head -c 524288 /dev/urandom > "$SRC/blob.bin"

echo "== snapshot =="
cb keygen >/dev/null
cb snapshot --dir "$SRC" --out "$TMP/snap.age"
ORIG=$(sha "$TMP/snap.age")

echo "== push (file backend) =="
LOC=$(cb push --in "$TMP/snap.age" --backend file)
[ "$LOC" != "$TMP/snap.age" ] && echo "[PASS] locator != source path" || { echo "[FAIL] locator == source"; exit 1; }
case "$LOC" in "$CIPHER_BRAIN_FILE_DIR"/*) echo "[PASS] object lives in the store";; *) echo "[FAIL] not in store: $LOC"; exit 1;; esac
[ "$(sha "$LOC")" = "$ORIG" ] && echo "[PASS] stored bytes == source" || { echo "[FAIL] store byte mismatch"; exit 1; }

echo "== pull (after deleting the original, so it MUST come from the store) =="
rm -f "$TMP/snap.age"
cb pull --locator "$LOC" --backend file --out "$TMP/got.age"
[ "$(sha "$TMP/got.age")" = "$ORIG" ] && echo "[PASS] pulled bytes == original" || { echo "[FAIL] pulled byte mismatch"; exit 1; }

echo "== verify + decrypt the pulled ciphertext =="
cb verify --in "$TMP/got.age" | grep -q "VERDICT: PASS" && echo "[PASS] verify VERDICT PASS on pulled" || { echo "[FAIL] verify"; exit 1; }
cb restore --in "$TMP/got.age" --out-dir "$TMP/out"
tar -xzf "$TMP/out/brain-src.tar.gz" -C "$TMP/out"
diff -r "$SRC" "$TMP/out/brain-src"
echo "[PASS] decrypt + restore byte-identical to source"

echo "== negative control: an absent locator must fail =="
if cb pull --locator "$CIPHER_BRAIN_FILE_DIR/deadbeef.age" --backend file --out "$TMP/no.age" 2>/dev/null; then
  echo "[FAIL] absent locator returned bytes"; exit 1
fi
echo "[PASS] absent locator errors"

echo "== backend is required (no silent default) =="
if cb push --in "$TMP/got.age" 2>/dev/null; then echo "[FAIL] push ran with no --backend"; exit 1; fi
echo "[PASS] push without --backend is rejected"

echo
echo "STORAGE SELFTEST (file backend) PASS"
