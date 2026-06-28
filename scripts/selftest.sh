#!/usr/bin/env bash
# Local round-trip proof for the cipher layer (issue #1): keygen -> snapshot ->
# verify -> restore, asserting the plaintext is recovered AND the ciphertext
# leaks nothing. No Postgres and no network — exercises the crypto + CLI plumbing
# on a synthetic "brain" directory. The real-data (pg_dump) run happens on the
# machine that holds gbrain.
set -euo pipefail

BIN="$(cd "$(dirname "$0")/.." && pwd)/bin/cipher-brain.mjs"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
export CIPHER_BRAIN_HOME="$TMP/keys"
cb() { node "$BIN" "$@"; }

MARKER="secret-thought-$(od -An -N6 -tx1 /dev/urandom | tr -d ' ')"
SRC="$TMP/brain-src"
mkdir -p "$SRC"
printf '%s\n' "$MARKER" > "$SRC/note.txt"
head -c 1048576 /dev/urandom > "$SRC/blob.bin"   # 1 MB binary, to exercise streaming

echo "== keygen =="
cb keygen >/dev/null
test -f "$CIPHER_BRAIN_HOME/identity.age"
test -f "$CIPHER_BRAIN_HOME/recipient.txt"

echo "== snapshot =="
cb snapshot --dir "$SRC" --out "$TMP/snap.age"

echo "== verify =="
cb verify --in "$TMP/snap.age"

echo "== ciphertext must not leak plaintext =="
if LC_ALL=C grep -a -q "$MARKER" "$TMP/snap.age"; then
  echo "FAIL: plaintext marker found in ciphertext"; exit 1
fi
echo "[PASS] marker absent from ciphertext"

echo "== restore + compare =="
cb restore --in "$TMP/snap.age" --out-dir "$TMP/out"
tar -xzf "$TMP/out/brain-src.tar.gz" -C "$TMP/out"
diff -r "$SRC" "$TMP/out/brain-src"
echo "[PASS] restored tree is byte-identical to source"

echo "== wrong key really cannot restore (defense in depth) =="
export CIPHER_BRAIN_HOME="$TMP/keys2"
cb keygen >/dev/null
if cb restore --in "$TMP/snap.age" --out-dir "$TMP/out-wrong" 2>/dev/null; then
  echo "FAIL: restored with a different identity"; exit 1
fi
echo "[PASS] a different identity cannot restore"

echo "== P1 regression: a failed snapshot must not leave staged plaintext =="
# a recipient file with garbage makes `age` exit immediately while `tar` is still
# streaming -> exercises the EPIPE path. The fix must (a) fail cleanly and (b) let
# the finally-block erase the staged plaintext.
export TMPDIR="$TMP/stagedir"; mkdir -p "$TMPDIR"
printf 'not-a-valid-age-recipient\n' > "$TMP/bad-recipient.txt"
if cb snapshot --dir "$SRC" --recipient "$TMP/bad-recipient.txt" --out "$TMP/bad.age" 2>/dev/null; then
  echo "FAIL: snapshot with a bad recipient unexpectedly succeeded"; exit 1
fi
LEFTOVERS=$(find "$TMPDIR" -maxdepth 1 -name 'cipher-brain-*' -type d 2>/dev/null | wc -l | tr -d ' ')
if [ "$LEFTOVERS" != "0" ]; then
  echo "FAIL: $LEFTOVERS staged plaintext dir(s) left behind after a failed snapshot"; exit 1
fi
echo "[PASS] failed snapshot exited cleanly and left no staged plaintext"

echo "== P1 regression: SIGINT mid-snapshot must not leave staged plaintext =="
# A signal tears the process down WITHOUT running the finally-block, so this is the
# gap the EPIPE case above does NOT cover. Use a slow `age` to hold the pipeline open
# while the staged plaintext exists, observe the stage dir appear, then SIGINT and
# assert the signal handler erased it.
SLOWAGE="$TMP/slow-age.sh"
cat > "$SLOWAGE" <<EOF
#!/usr/bin/env bash
sleep 5
exec age "\$@"
EOF
chmod +x "$SLOWAGE"
export TMPDIR="$TMP/stagedir-sig"; mkdir -p "$TMPDIR"
CIPHER_BRAIN_AGE="$SLOWAGE" cb snapshot --dir "$SRC" --out "$TMP/sig.age" >/dev/null 2>&1 &
SNAP_PID=$!
APPEARED=0
for _ in $(seq 1 50); do
  if find "$TMPDIR" -maxdepth 1 -name 'cipher-brain-*' -type d 2>/dev/null | grep -q .; then APPEARED=1; break; fi
  sleep 0.1
done
if [ "$APPEARED" != "1" ]; then
  echo "FAIL: stage dir never appeared (test setup)"; kill "$SNAP_PID" 2>/dev/null || true; exit 1
fi
kill -INT "$SNAP_PID"
wait "$SNAP_PID" 2>/dev/null || true   # signal exit is non-zero — expected
LEFTOVERS=$(find "$TMPDIR" -maxdepth 1 -name 'cipher-brain-*' -type d 2>/dev/null | wc -l | tr -d ' ')
if [ "$LEFTOVERS" != "0" ]; then
  echo "FAIL: $LEFTOVERS staged plaintext dir(s) left behind after SIGINT"; exit 1
fi
echo "[PASS] SIGINT mid-snapshot left no staged plaintext"

echo
echo "SELFTEST PASS"
