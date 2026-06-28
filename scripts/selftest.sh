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

echo "== verify --sha256: correct hash PASSes, wrong hash FAILs =="
SNAPSHA=$(shasum -a 256 "$TMP/snap.age" | cut -d' ' -f1)
cb verify --in "$TMP/snap.age" --sha256 "$SNAPSHA" | grep -q "VERDICT: PASS" \
  && echo "[PASS] verify --sha256 (correct) is PASS" || { echo "FAIL: correct --sha256 not PASS"; exit 1; }
set +e
OUT=$(cb verify --in "$TMP/snap.age" --sha256 "deadbeef" 2>&1); RC=$?
set -e
if [ "$RC" = "0" ]; then echo "FAIL: verify --sha256 (wrong) exited 0"; echo "$OUT"; exit 1; fi
printf '%s' "$OUT" | grep -q "VERDICT: FAIL" || { echo "FAIL: wrong --sha256 not VERDICT FAIL"; echo "$OUT"; exit 1; }
echo "[PASS] verify --sha256 (wrong) is FAIL/non-zero"

echo "== ciphertext must not leak plaintext =="
if LC_ALL=C grep -a -q "$MARKER" "$TMP/snap.age"; then
  echo "FAIL: plaintext marker found in ciphertext"; exit 1
fi
echo "[PASS] marker absent from ciphertext"

echo "== no-clobber: snapshot refuses to overwrite an existing --out =="
set +e
OUT=$(cb snapshot --dir "$SRC" --out "$TMP/snap.age" 2>&1); RC=$?   # snap.age already exists
set -e
if [ "$RC" = "0" ]; then echo "FAIL: snapshot overwrote an existing --out"; exit 1; fi
printf '%s' "$OUT" | grep -q "already exists" || { echo "FAIL: wrong error for existing --out"; echo "$OUT"; exit 1; }
echo "[PASS] snapshot refused to overwrite an existing snapshot"

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
# atomic output: a failed snapshot must leave NEITHER a truncated *.age NOR its (now
# per-run-randomized "<out>.<pid>.<hex>.part") partial — glob, not the old fixed name.
npart() { find "$1" -maxdepth 1 -name "$(basename "$2").*.part" 2>/dev/null | wc -l | tr -d ' '; }
test ! -f "$TMP/bad.age" || { echo "FAIL: failed snapshot left a (truncated) bad.age"; exit 1; }
[ "$(npart "$TMP" "$TMP/bad.age")" = "0" ] || { echo "FAIL: failed snapshot left a bad.age .part"; exit 1; }
echo "[PASS] failed snapshot exited cleanly and left no staged plaintext / no partial *.age"
# a SUCCESSFUL snapshot promotes the .part and leaves none behind
test -f "$TMP/snap.age" && [ "$(npart "$TMP" "$TMP/snap.age")" = "0" ] \
  && echo "[PASS] successful snapshot left no .part (atomic promote)" || { echo "FAIL: snap.age .part lingered"; exit 1; }

echo "== restore of a corrupt artifact fails and removes the tree it created =="
# Drop the LAST bytes of a valid snapshot (snap.age holds a 1 MB blob => multiple age
# STREAM chunks): the leading chunks still decrypt and tar extracts a PARTIAL tree, then
# age fails on the broken final chunk. Use the ORIGINAL keypair ($TMP/keys) so the
# failure is the truncation, not a wrong key (CIPHER_BRAIN_HOME is $TMP/keys2 here).
SNAPSZ=$(wc -c < "$TMP/snap.age" | tr -d ' ')
head -c $((SNAPSZ - 500)) "$TMP/snap.age" > "$TMP/trunc.age"
RDIR="$TMP/restore-corrupt"   # does NOT pre-exist -> restore creates it -> must remove it on failure
set +e
CIPHER_BRAIN_HOME="$TMP/keys" node "$BIN" restore --in "$TMP/trunc.age" --out-dir "$RDIR" >/dev/null 2>&1; RC=$?
set -e
if [ "$RC" = "0" ]; then echo "FAIL: restore of a truncated artifact unexpectedly succeeded"; exit 1; fi
test ! -e "$RDIR" || { echo "FAIL: restore left a partial tree at $RDIR"; exit 1; }
echo "[PASS] restore of a corrupt artifact failed and removed the partial tree"

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
# Invoke `node` DIRECTLY (not the cb() function): backgrounding a shell function makes
# $! the subshell's pid, so `kill -INT $!` would hit the subshell and leave node
# orphaned to run to completion — the signal would never reach the handler under test.
CIPHER_BRAIN_AGE="$SLOWAGE" node "$BIN" snapshot --dir "$SRC" --out "$TMP/sig.age" >/dev/null 2>&1 &
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
# the signal handler also kills the pipeline children, so no partial ciphertext lingers
[ "$(npart "$TMP" "$TMP/sig.age")" = "0" ] || { echo "FAIL: SIGINT left a sig.age .part (child not killed)"; exit 1; }
test ! -f "$TMP/sig.age" || { echo "FAIL: SIGINT left a partial sig.age"; exit 1; }
echo "[PASS] SIGINT mid-snapshot left no staged plaintext / no partial ciphertext"

echo "== race: an --out that appears mid-snapshot is NOT clobbered (link promote is exclusive) =="
# Start a slow snapshot (passes the early exists() check while --out is absent), then
# create --out externally before it promotes. link()+EEXIST must refuse, preserving the
# external file — a plain rename would have clobbered it.
RACE="$TMP/race-out.age"
CIPHER_BRAIN_AGE="$SLOWAGE" node "$BIN" snapshot --dir "$SRC" --out "$RACE" >/dev/null 2>&1 &
RACE_PID=$!
for _ in $(seq 1 50); do find "$TMPDIR" -maxdepth 1 -name 'cipher-brain-*' -type d 2>/dev/null | grep -q . && break; sleep 0.1; done
printf 'PRE-EXISTING-WINNER\n' > "$RACE"   # a "concurrent run" finished first
set +e
wait "$RACE_PID"; RC=$?
set -e
if [ "$RC" = "0" ]; then echo "FAIL: snapshot clobbered an --out that appeared mid-run"; exit 1; fi
[ "$(cat "$RACE")" = "PRE-EXISTING-WINNER" ] || { echo "FAIL: the pre-existing --out was overwritten"; exit 1; }
LEFTPART=$(find "$(dirname "$RACE")" -maxdepth 1 -name "$(basename "$RACE").*.part" 2>/dev/null | wc -l | tr -d ' ')
[ "$LEFTPART" = "0" ] || { echo "FAIL: a .part lingered after the refused promote"; exit 1; }
echo "[PASS] a mid-run --out is not clobbered and no .part lingers"

echo "== verify on a public-key-only box is PARTIAL (exit 2), never a false-green PASS =="
# A box with only recipient.txt (no identity) cannot prove decryptability. verify
# must say PARTIAL and exit 2 so cron/logs don't read it as a full PASS.
PUBONLY="$TMP/pubonly"; mkdir -p "$PUBONLY"
cp "$TMP/keys/recipient.txt" "$PUBONLY/recipient.txt"   # public key only — deliberately NO identity.age
set +e
OUT=$(CIPHER_BRAIN_HOME="$PUBONLY" node "$BIN" verify --in "$TMP/snap.age" 2>&1); RC=$?
set -e
if [ "$RC" != "2" ]; then echo "FAIL: public-key-only verify exited $RC, expected 2"; echo "$OUT"; exit 1; fi
if ! printf '%s' "$OUT" | grep -q "VERDICT: PARTIAL"; then echo "FAIL: expected VERDICT: PARTIAL"; echo "$OUT"; exit 1; fi
if printf '%s' "$OUT" | grep -q "VERDICT: PASS"; then echo "FAIL: public-key-only verify falsely printed PASS"; exit 1; fi
echo "[PASS] public-key-only verify is PARTIAL/exit 2"

echo "== recipient pin: snapshot refuses an out-of-allowlist recipient =="
PINHOME="$TMP/keys"   # the original keypair from the top of this test
MYPUB=$(cat "$PINHOME/recipient.txt")
# (a) matching allowlist -> snapshot succeeds
CIPHER_BRAIN_HOME="$PINHOME" CIPHER_BRAIN_PIN_RECIPIENTS="$MYPUB" \
  node "$BIN" snapshot --dir "$SRC" --out "$TMP/pin-ok.age" >/dev/null
echo "[PASS] snapshot allowed when the recipient is on the allowlist"
# (b) a DIFFERENT key's pin -> snapshot must refuse (the injected-recipient case)
OTHER="$TMP/other-key"; mkdir -p "$OTHER"
CIPHER_BRAIN_HOME="$OTHER" node "$BIN" keygen >/dev/null
OTHERPUB=$(cat "$OTHER/recipient.txt")
set +e
CIPHER_BRAIN_HOME="$PINHOME" CIPHER_BRAIN_PIN_RECIPIENTS="$OTHERPUB" \
  node "$BIN" snapshot --dir "$SRC" --out "$TMP/pin-bad.age" >/dev/null 2>&1; RC=$?
set -e
if [ "$RC" = "0" ]; then echo "FAIL: snapshot encrypted to a non-allowlisted recipient"; exit 1; fi
test ! -f "$TMP/pin-bad.age"
echo "[PASS] snapshot refused a recipient not on the allowlist"
# (c) a recipients FILE that keeps the allowed age key but ALSO adds an ssh recipient
# (age -R accepts ssh-ed25519) must be refused — an age1-only scan would miss it.
SSHMIX="$TMP/recipient-ssh-mix.txt"
printf '%s\nssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIINJECTEDATTACKERKEYxxxxxxxxxxxxxxxxxxxxxx attacker\n' "$MYPUB" > "$SSHMIX"
set +e
CIPHER_BRAIN_HOME="$PINHOME" CIPHER_BRAIN_PIN_RECIPIENTS="$MYPUB" \
  node "$BIN" snapshot --dir "$SRC" --recipient "$SSHMIX" --out "$TMP/pin-ssh.age" >/dev/null 2>&1; RC=$?
set -e
if [ "$RC" = "0" ]; then echo "FAIL: pin let through a file with an injected ssh recipient"; exit 1; fi
test ! -f "$TMP/pin-ssh.age"
echo "[PASS] snapshot refused a recipient file with an injected ssh recipient"
# (d) a FILE allowlist whose path contains "age1" must be read as a file, not parsed
# as an inline key (regression for the includes('age1') path-detection bug).
PINFILE="$TMP/age1-pins.txt"; printf '%s\n' "$MYPUB" > "$PINFILE"
CIPHER_BRAIN_HOME="$PINHOME" CIPHER_BRAIN_PIN_RECIPIENTS="$PINFILE" \
  node "$BIN" snapshot --dir "$SRC" --out "$TMP/pin-file.age" >/dev/null
test -f "$TMP/pin-file.age"
echo "[PASS] snapshot honored a file-based allowlist whose path contains 'age1'"
# (e) a key present only in a COMMENT line of the allowlist file is NOT allowed
# (e.g. a rotated/revoked key left commented out must not silently pass the pin).
PINCOMMENT="$TMP/pins-with-comment.txt"
printf '%s\n# rotated-out: %s\n' "$MYPUB" "$OTHERPUB" > "$PINCOMMENT"
set +e
CIPHER_BRAIN_HOME="$OTHER" CIPHER_BRAIN_PIN_RECIPIENTS="$PINCOMMENT" \
  node "$BIN" snapshot --dir "$SRC" --recipient "$OTHER/recipient.txt" --out "$TMP/pin-comment.age" >/dev/null 2>&1; RC=$?
set -e
if [ "$RC" = "0" ]; then echo "FAIL: pin allowed a key that was only in a comment line"; exit 1; fi
test ! -f "$TMP/pin-comment.age"
echo "[PASS] snapshot refused a recipient whose key was only commented-out in the allowlist"

echo "== push arweave/turbo --yes guard: requires explicit opt-in before a paid permanent store =="
# Without --yes or CIPHER_BRAIN_YES, push to arweave/turbo must fail at the gate
# (before the SDK / wallet is even loaded), so this test needs no external deps.
set +e
OUT_AR=$(node "$BIN" push --in "$TMP/snap.age" --backend arweave 2>&1); RC_AR=$?
OUT_TU=$(node "$BIN" push --in "$TMP/snap.age" --backend turbo  2>&1); RC_TU=$?
set -e
[ "$RC_AR" != "0" ] || { echo "[FAIL] push arweave without --yes exited 0"; exit 1; }
[ "$RC_TU" != "0" ] || { echo "[FAIL] push turbo without --yes exited 0"; exit 1; }
printf '%s' "$OUT_AR" | grep -qi "CIPHER_BRAIN_YES\|--yes" \
  || { echo "[FAIL] push arweave error lacks --yes guidance"; echo "$OUT_AR"; exit 1; }
printf '%s' "$OUT_TU" | grep -qi "CIPHER_BRAIN_YES\|--yes" \
  || { echo "[FAIL] push turbo error lacks --yes guidance"; echo "$OUT_TU"; exit 1; }
echo "[PASS] push arweave/turbo without --yes fails with clear guidance"
# With CIPHER_BRAIN_YES=1 the --yes guard passes; the error moves further in
# (wallet / SDK missing), which proves the guard no longer blocks.
set +e
OUT2=$(CIPHER_BRAIN_YES=1 node "$BIN" push --in "$TMP/snap.age" --backend arweave 2>&1); RC2=$?
set -e
[ "$RC2" != "0" ] || { echo "[FAIL] arweave push should fail (no wallet in test env)"; exit 1; }
printf '%s' "$OUT2" | grep -qi "CIPHER_BRAIN_YES\|--yes" \
  && { echo "[FAIL] CIPHER_BRAIN_YES=1 still hitting the --yes gate"; echo "$OUT2"; exit 1; } || true
echo "[PASS] push arweave with CIPHER_BRAIN_YES=1 passes the --yes guard (fails further in: wallet/SDK)"

echo "== pipe2 timeout: a wedged age in the tar|age pipeline can't hang the CLI (#38) =="
# Replace `age` with a stub that hangs (never consumes stdin / never exits). With a tiny
# CIPHER_BRAIN_PIPE_TIMEOUT the snapshot pipeline must give up, fail non-zero, AND leave
# no staged plaintext or partial ciphertext behind.
AGESTUB="$TMP/age-hang.sh"
printf '#!/bin/sh\nexec sleep 30\n' > "$AGESTUB"; chmod +x "$AGESTUB"
TOUT="$TMP/timeout-snap.age"
START=$(date +%s)
set +e
TERR=$(CIPHER_BRAIN_AGE="$AGESTUB" CIPHER_BRAIN_PIPE_TIMEOUT=600 cb snapshot --dir "$SRC" --out "$TOUT" 2>&1); TRC=$?
set -e
ELAPSED=$(( $(date +%s) - START ))
[ "$TRC" != "0" ] || { echo "[FAIL] wedged-age snapshot exited 0"; exit 1; }
printf '%s' "$TERR" | grep -qi "timed out" || { echo "[FAIL] no timeout error surfaced"; echo "$TERR"; exit 1; }
[ "$ELAPSED" -lt 25 ] || { echo "[FAIL] pipeline took ${ELAPSED}s — timeout did not bound it (< the 30s stub)"; exit 1; }
test ! -f "$TOUT"                                       # no finished output
[ -z "$(find "$TMP" -name '*.part' 2>/dev/null)" ] || { echo "[FAIL] a .part lingered after timeout"; exit 1; }
# the staged plaintext dir must be erased by snapshot's finally on the timeout path
[ -z "$(find "${TMPDIR:-/tmp}" -maxdepth 1 -name 'cipher-brain-*' -newermt "@$START" 2>/dev/null)" ] \
  || { echo "[FAIL] a staged-plaintext cipher-brain-* dir lingered after timeout"; exit 1; }
echo "[PASS] wedged-age pipeline timed out in ${ELAPSED}s, no output / no .part / no staged plaintext left"

echo
echo "SELFTEST PASS"
