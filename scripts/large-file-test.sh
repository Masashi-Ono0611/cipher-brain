#!/usr/bin/env bash
# Large-file / multi-chunk round-trip (issue #8), operator-run. Confirms the
# streaming snapshot and both backends hold at scale, and that the `ton` backend
# produces a MULTI-PIECE bag the daemon stores intact. Cross-node transfer is still
# blocked on reachability (#6), so the ton part is integrity-only (like #2).
#
# Config: CB_SIZE_MB (default 256). CB_TON=1 to also exercise the ton backend
#   (needs the storage-daemon + the CB_TRIAL_ROOT / ~.homebrew PATH like ton-roundtrip).
set -euo pipefail

SIZE_MB="${CB_SIZE_MB:-256}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/bin/cipher-brain.mjs"
# BIN_DEV_ARGS: literal argv flags to run bin/cipher-brain.mjs against src/*.ts (no
# build step) under plain node — see scripts/dev-node-flags.sh (never an exported
# NODE_OPTIONS string — whitespace-split, breaks under a checkout path with a space).
source "$ROOT/scripts/dev-node-flags.sh"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
export CIPHER_BRAIN_HOME="$TMP/keys"
export CIPHER_BRAIN_FILE_DIR="$TMP/store"
cb() { node "${BIN_DEV_ARGS[@]}" "$BIN" "$@"; }
sha() { shasum -a 256 "$1" | cut -d' ' -f1; }
now() { date +%s; }

echo "== build a ${SIZE_MB} MB synthetic brain (incompressible) =="
SRC="$TMP/brain"; mkdir -p "$SRC"
dd if=/dev/urandom of="$SRC/blob.bin" bs=1048576 count="$SIZE_MB" 2>/dev/null
printf 'large-marker-%s\n' "$(od -An -N6 -tx1 /dev/urandom | tr -d ' ')" > "$SRC/note.txt"
cb keygen >/dev/null

echo "== snapshot (measure time + node peak RSS to prove it streams, not buffers) =="
T0=$(now)
/usr/bin/time -l node "${BIN_DEV_ARGS[@]}" "$BIN" snapshot --dir "$SRC" --out "$TMP/big.age" 2>"$TMP/rss.txt" 1>/dev/null
T1=$(now)
RSS_BYTES=$(grep -i 'maximum resident set size' "$TMP/rss.txt" | grep -oE '[0-9]+' | head -1)
RSS_MB=$(( ${RSS_BYTES:-0} / 1048576 ))
AGE_MB=$(( $(stat -f%z "$TMP/big.age") / 1048576 ))
echo "snapshot: $((T1-T0))s, node peak RSS ~${RSS_MB} MB, ciphertext ${AGE_MB} MB"
# streaming proof = node RSS stays well below the input as the input grows. Only
# meaningful once the input clearly exceeds Node's fixed ~60-70 MB baseline RSS.
if [ "$SIZE_MB" -ge 128 ]; then
  [ "$RSS_MB" -lt "$SIZE_MB" ] && echo "[PASS] node RSS (${RSS_MB} MB) << input (${SIZE_MB} MB) -> streaming (tar|age), not buffered" \
    || { echo "[FAIL] node RSS not < input — possible buffering"; exit 1; }
else
  echo "[SKIP] streaming RSS assert — size < 128 MB is below Node's baseline RSS; run at >=256 MB to prove it"
fi
ORIG=$(sha "$TMP/big.age")
cp "$TMP/big.age" "$TMP/ton.age"   # keep a copy for the ton test before the file backend deletes the original

echo "== file backend: push -> (delete original) -> pull -> decrypt at size =="
T0=$(now); LOC=$(cb push --in "$TMP/big.age" --backend file); T1=$(now)
rm -f "$TMP/big.age"
T2=$(now); cb pull --locator "$LOC" --backend file --out "$TMP/got.age"; T3=$(now)
[ "$(sha "$TMP/got.age")" = "$ORIG" ] && echo "[PASS] file backend round-trip byte-identical (push $((T1-T0))s pull $((T3-T2))s)" \
  || { echo "[FAIL] file backend byte mismatch"; exit 1; }
cb restore --in "$TMP/got.age" --out-dir "$TMP/out" >/dev/null
tar -xzf "$TMP/out/brain.tar.gz" -C "$TMP/out"
diff -r "$SRC" "$TMP/out/brain" >/dev/null && echo "[PASS] decrypt + restore byte-identical at ${SIZE_MB} MB" \
  || { echo "[FAIL] restore mismatch"; exit 1; }

if [ "${CB_TON:-0}" = "1" ]; then
  echo "== ton backend: multi-piece bag stored intact (integrity-only; cross-node blocked, see #6) =="
  ROOT="${CB_TRIAL_ROOT:-$HOME/ton-provider-trial}"; W="$ROOT/work"; CLIBIN="$ROOT/bin/storage-daemon-cli"
  A() { "$CLIBIN" -I 127.0.0.1:15555 -k "$W/db/cli-keys/client" -p "$W/db/cli-keys/server.pub" -c "$1"; }
  export CIPHER_BRAIN_TON_CLI="$CLIBIN" CIPHER_BRAIN_TON_API=127.0.0.1:15555
  export CIPHER_BRAIN_TON_CLIENT="$W/db/cli-keys/client" CIPHER_BRAIN_TON_SERVER="$W/db/cli-keys/server.pub"
  # CB_TON=1 explicitly requested the ton path — if the daemon is unreachable that's
  # BLOCKED, not PASS (don't green-stamp a backend we never exercised).
  A "list" >/dev/null 2>&1 || { echo "[BLOCKED] CB_TON=1 was requested but daemon A (:15555) is unreachable"; exit 2; }
  TON_ORIG=$(sha "$TMP/ton.age")
  BAG=$(cb push --in "$TMP/ton.age" --backend ton)
  TOTAL=$(A "get $BAG --json" 2>/dev/null | grep -oE '"total_size"[^0-9]*[0-9]+' | grep -oE '[0-9]+' | head -1)
  PIECES=$(( ${TOTAL:-0} / 131072 + 1 ))   # default piece size 128 KB
  echo "ton bag $BAG: total_size ${TOTAL} bytes (~${PIECES} pieces of 128 KB)"
  [ "$PIECES" -gt 1 ] && echo "[PASS] multi-piece bag (${PIECES} pieces)" || { echo "[FAIL] not multi-piece"; exit 1; }
  SFILE=$(find "$W/db/torrent/torrent-files/$BAG" -type f 2>/dev/null | head -1)
  [ -n "$SFILE" ] && [ "$(sha "$SFILE")" = "$TON_ORIG" ] && echo "[PASS] daemon stored the exact ${SIZE_MB} MB ciphertext (sha256 match)" \
    || { echo "[FAIL] ton stored bytes mismatch"; exit 1; }
  cb restore --in "$SFILE" --out-dir "$TMP/ton-out" >/dev/null
  tar -xzf "$TMP/ton-out/brain.tar.gz" -C "$TMP/ton-out"
  diff -r "$SRC" "$TMP/ton-out/brain" >/dev/null && echo "[PASS] ton-stored ciphertext decrypts byte-identical" \
    || { echo "[FAIL] ton decrypt mismatch"; exit 1; }
  A "remove $BAG --remove-files" >/dev/null 2>&1 || true   # tidy up the large test bag
fi

echo
echo "LARGE-FILE TEST PASS (${SIZE_MB} MB)"
