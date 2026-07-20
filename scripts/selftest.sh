#!/usr/bin/env bash
# Local round-trip proof for the cipher layer (issue #1): keygen -> snapshot ->
# verify -> restore, asserting the plaintext is recovered AND the ciphertext
# leaks nothing. No Postgres and no network — exercises the crypto + CLI plumbing
# on a synthetic "brain" directory. The real-data (pg_dump) run happens on the
# machine that holds gbrain.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/bin/cipher-brain.mjs"
# BIN_DEV_ARGS: literal argv flags to run bin/cipher-brain.mjs against src/*.ts (no
# build step) under plain node — see scripts/dev-node-flags.sh (never an exported
# NODE_OPTIONS string — whitespace-split, breaks under a checkout path with a space).
source "$ROOT/scripts/dev-node-flags.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
export CIPHER_BRAIN_HOME="$TMP/keys"
cb() { node "${BIN_DEV_ARGS[@]}" "$BIN" "$@"; }

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
# a recipient file with garbage makes the encrypter setup fail (typage rejects the
# line up front, before any plaintext is staged). The run must (a) fail cleanly and
# (b) leave no staged plaintext and no partial output behind.
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

echo "== P1 regression: a recipients file with only comments/blank lines must refuse to snapshot =="
# Such a file flattens to ZERO recipients. typage would happily encrypt to an EMPTY
# stanza list — valid-looking ciphertext NO identity can ever decrypt (the old external
# `age -R` errored here). snapshot must fail fast with a clear stderr error and leave
# no output / .part behind.
printf '# rotated out, keys to follow\n\n# (none yet)\n' > "$TMP/comments-only-recipient.txt"
set +e
ERR=$(cb snapshot --dir "$SRC" --recipient "$TMP/comments-only-recipient.txt" --out "$TMP/norecip.age" 2>&1 >/dev/null); RC=$?
set -e
[ "$RC" != "0" ] || { echo "[FAIL] snapshot with a zero-recipient file exited 0"; exit 1; }
printf '%s' "$ERR" | grep -q "NO identity can ever decrypt" \
  || { echo "[FAIL] empty-recipient refusal lacks a clear stderr error"; echo "$ERR"; exit 1; }
test ! -f "$TMP/norecip.age" || { echo "[FAIL] refused snapshot still created norecip.age"; exit 1; }
[ "$(npart "$TMP" "$TMP/norecip.age")" = "0" ] || { echo "[FAIL] refused snapshot left a norecip.age .part"; exit 1; }
echo "[PASS] snapshot refused a recipients file that resolves to zero entries (nothing written)"

echo "== restore of a corrupt artifact fails and removes the tree it created =="
# Drop the LAST bytes of a valid snapshot (snap.age holds a 1 MB blob => multiple age
# STREAM chunks): the leading chunks still decrypt and tar extracts a PARTIAL tree, then
# age fails on the broken final chunk. Use the ORIGINAL keypair ($TMP/keys) so the
# failure is the truncation, not a wrong key (CIPHER_BRAIN_HOME is $TMP/keys2 here).
SNAPSZ=$(wc -c < "$TMP/snap.age" | tr -d ' ')
head -c $((SNAPSZ - 500)) "$TMP/snap.age" > "$TMP/trunc.age"
RDIR="$TMP/restore-corrupt"   # does NOT pre-exist -> restore creates it -> must remove it on failure
set +e
CIPHER_BRAIN_HOME="$TMP/keys" node "${BIN_DEV_ARGS[@]}" "$BIN" restore --in "$TMP/trunc.age" --out-dir "$RDIR" >/dev/null 2>&1; RC=$?
set -e
if [ "$RC" = "0" ]; then echo "FAIL: restore of a truncated artifact unexpectedly succeeded"; exit 1; fi
test ! -e "$RDIR" || { echo "FAIL: restore left a partial tree at $RDIR"; exit 1; }
echo "[PASS] restore of a corrupt artifact failed and removed the partial tree"

echo "== tar dying mid-stream must fail the snapshot (no valid-looking truncated .age) =="
# With in-process encryption (typage), a tar that dies after emitting some bytes just
# EOFs its stdout — which the encrypter would happily finalize into VALID ciphertext
# of a TRUNCATED archive. encryptToFile gates success on tar's exit code; prove it.
# The stub tar intercepts ONLY the snapshot pipeline invocation (`tar -cf - …`) and
# dispatches on TAR_STUB_MODE; every other tar call passes through to the real tar.
REALTAR="$(command -v tar)"
STUBBIN="$TMP/stubbin"; mkdir -p "$STUBBIN"
cat > "$STUBBIN/tar" <<EOF
#!/usr/bin/env bash
if [ "\$1" = "-cf" ] && [ "\$2" = "-" ]; then
  case "\${TAR_STUB_MODE:-}" in
    slow)  sleep "\${TAR_STUB_SLEEP:-3}" ;;          # hold the pipeline open, then behave
    fail)  printf 'partial-tar-bytes'; exit 1 ;;      # die mid-stream after emitting bytes
    wedge) exec node "$TMP/tar-ignore-term.mjs" ;;    # ignore SIGTERM and hang (timeout test)
  esac
fi
exec "$REALTAR" "\$@"
EOF
chmod +x "$STUBBIN/tar"
set +e
OUT=$(PATH="$STUBBIN:$PATH" TAR_STUB_MODE=fail node "${BIN_DEV_ARGS[@]}" "$BIN" snapshot --dir "$SRC" --out "$TMP/midfail.age" 2>&1); RC=$?
set -e
[ "$RC" != "0" ] || { echo "FAIL: snapshot with a mid-stream tar death exited 0"; exit 1; }
test ! -f "$TMP/midfail.age" || { echo "FAIL: mid-stream tar death left a truncated midfail.age"; exit 1; }
[ "$(npart "$TMP" "$TMP/midfail.age")" = "0" ] || { echo "FAIL: mid-stream tar death left a .part"; exit 1; }
LEFTOVERS=$(find "$TMPDIR" -maxdepth 1 -name 'cipher-brain-*' -type d 2>/dev/null | wc -l | tr -d ' ')
[ "$LEFTOVERS" = "0" ] || { echo "FAIL: mid-stream tar death left staged plaintext"; exit 1; }
echo "[PASS] a tar that dies mid-stream fails the snapshot and leaves nothing behind"

echo "== P1 regression: SIGINT mid-snapshot must not leave staged plaintext =="
# A signal tears the process down WITHOUT running the finally-block, so this is the
# gap the failure cases above do NOT cover. Use a slow pipeline tar to hold the run
# open while the staged plaintext exists, observe the stage dir appear, then SIGINT
# and assert the signal handler erased it.
export TMPDIR="$TMP/stagedir-sig"; mkdir -p "$TMPDIR"
# Invoke `node` DIRECTLY (not the cb() function): backgrounding a shell function makes
# $! the subshell's pid, so `kill -INT $!` would hit the subshell and leave node
# orphaned to run to completion — the signal would never reach the handler under test.
PATH="$STUBBIN:$PATH" TAR_STUB_MODE=slow TAR_STUB_SLEEP=5 node "${BIN_DEV_ARGS[@]}" "$BIN" snapshot --dir "$SRC" --out "$TMP/sig.age" >/dev/null 2>&1 &
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
PATH="$STUBBIN:$PATH" TAR_STUB_MODE=slow TAR_STUB_SLEEP=3 node "${BIN_DEV_ARGS[@]}" "$BIN" snapshot --dir "$SRC" --out "$RACE" >/dev/null 2>&1 &
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
OUT=$(CIPHER_BRAIN_HOME="$PUBONLY" node "${BIN_DEV_ARGS[@]}" "$BIN" verify --in "$TMP/snap.age" 2>&1); RC=$?
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
  node "${BIN_DEV_ARGS[@]}" "$BIN" snapshot --dir "$SRC" --out "$TMP/pin-ok.age" >/dev/null
echo "[PASS] snapshot allowed when the recipient is on the allowlist"
# (b) a DIFFERENT key's pin -> snapshot must refuse (the injected-recipient case)
OTHER="$TMP/other-key"; mkdir -p "$OTHER"
CIPHER_BRAIN_HOME="$OTHER" node "${BIN_DEV_ARGS[@]}" "$BIN" keygen >/dev/null
OTHERPUB=$(cat "$OTHER/recipient.txt")
set +e
CIPHER_BRAIN_HOME="$PINHOME" CIPHER_BRAIN_PIN_RECIPIENTS="$OTHERPUB" \
  node "${BIN_DEV_ARGS[@]}" "$BIN" snapshot --dir "$SRC" --out "$TMP/pin-bad.age" >/dev/null 2>&1; RC=$?
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
  node "${BIN_DEV_ARGS[@]}" "$BIN" snapshot --dir "$SRC" --recipient "$SSHMIX" --out "$TMP/pin-ssh.age" >/dev/null 2>&1; RC=$?
set -e
if [ "$RC" = "0" ]; then echo "FAIL: pin let through a file with an injected ssh recipient"; exit 1; fi
test ! -f "$TMP/pin-ssh.age"
echo "[PASS] snapshot refused a recipient file with an injected ssh recipient"
# (d) a FILE allowlist whose path contains "age1" must be read as a file, not parsed
# as an inline key (regression for the includes('age1') path-detection bug).
PINFILE="$TMP/age1-pins.txt"; printf '%s\n' "$MYPUB" > "$PINFILE"
CIPHER_BRAIN_HOME="$PINHOME" CIPHER_BRAIN_PIN_RECIPIENTS="$PINFILE" \
  node "${BIN_DEV_ARGS[@]}" "$BIN" snapshot --dir "$SRC" --out "$TMP/pin-file.age" >/dev/null
test -f "$TMP/pin-file.age"
echo "[PASS] snapshot honored a file-based allowlist whose path contains 'age1'"
# (e) a key present only in a COMMENT line of the allowlist file is NOT allowed
# (e.g. a rotated/revoked key left commented out must not silently pass the pin).
PINCOMMENT="$TMP/pins-with-comment.txt"
printf '%s\n# rotated-out: %s\n' "$MYPUB" "$OTHERPUB" > "$PINCOMMENT"
set +e
CIPHER_BRAIN_HOME="$OTHER" CIPHER_BRAIN_PIN_RECIPIENTS="$PINCOMMENT" \
  node "${BIN_DEV_ARGS[@]}" "$BIN" snapshot --dir "$SRC" --recipient "$OTHER/recipient.txt" --out "$TMP/pin-comment.age" >/dev/null 2>&1; RC=$?
set -e
if [ "$RC" = "0" ]; then echo "FAIL: pin allowed a key that was only in a comment line"; exit 1; fi
test ! -f "$TMP/pin-comment.age"
echo "[PASS] snapshot refused a recipient whose key was only commented-out in the allowlist"
# (f) #101: an explicitly EMPTY CIPHER_BRAIN_PIN_RECIPIENTS="" (e.g. a broken
# cron/systemd template expansion) must fail CLOSED, not be silently treated the
# same as an unset var (which would disable the allowlist entirely — fail-open).
set +e
CIPHER_BRAIN_HOME="$PINHOME" CIPHER_BRAIN_PIN_RECIPIENTS="" \
  node "${BIN_DEV_ARGS[@]}" "$BIN" snapshot --dir "$SRC" --out "$TMP/pin-empty.age" >"$TMP/pin-empty.log" 2>&1; RC=$?
set -e
if [ "$RC" = "0" ]; then echo "FAIL: snapshot succeeded with CIPHER_BRAIN_PIN_RECIPIENTS=\"\" (fail-open regression)"; cat "$TMP/pin-empty.log"; exit 1; fi
test ! -f "$TMP/pin-empty.age"
grep -q "CIPHER_BRAIN_PIN_RECIPIENTS is set but empty" "$TMP/pin-empty.log" || { echo "FAIL: expected the fail-closed empty-pin error message"; cat "$TMP/pin-empty.log"; exit 1; }
echo "[PASS] snapshot fails closed when CIPHER_BRAIN_PIN_RECIPIENTS is explicitly empty"

echo "== push arweave/turbo --yes guard: requires explicit opt-in before a paid permanent store =="
# Without --yes or CIPHER_BRAIN_YES, push to arweave/turbo must fail at the gate
# (before the SDK / wallet is even loaded), so this test needs no external deps.
set +e
OUT_AR=$(node "${BIN_DEV_ARGS[@]}" "$BIN" push --in "$TMP/snap.age" --backend arweave 2>&1); RC_AR=$?
OUT_TU=$(node "${BIN_DEV_ARGS[@]}" "$BIN" push --in "$TMP/snap.age" --backend turbo  2>&1); RC_TU=$?
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
OUT2=$(CIPHER_BRAIN_YES=1 node "${BIN_DEV_ARGS[@]}" "$BIN" push --in "$TMP/snap.age" --backend arweave 2>&1); RC2=$?
set -e
[ "$RC2" != "0" ] || { echo "[FAIL] arweave push should fail (no wallet in test env)"; exit 1; }
printf '%s' "$OUT2" | grep -qi "CIPHER_BRAIN_YES\|--yes" \
  && { echo "[FAIL] CIPHER_BRAIN_YES=1 still hitting the --yes gate"; echo "$OUT2"; exit 1; } || true
echo "[PASS] push arweave with CIPHER_BRAIN_YES=1 passes the --yes guard (fails further in: wallet/SDK)"

echo "== pipeline timeout: a wedged, SIGTERM-IGNORING tar can't hang the CLI (#38) =="
# TAR_STUB_MODE=wedge swaps the pipeline tar for a node stub that IGNORES SIGTERM and
# stays alive 30s (exec'd — no grandchild, so SIGKILL on it leaks nothing). This
# exercises the hard path: the pipeline must (a) time out, (b) escalate SIGTERM→SIGKILL
# so the child actually dies, and (c) only THEN reject — so cleanup runs after the child
# is dead, leaving no output / .part / staged plaintext. If escalation failed, the run
# would block on the stub's full 30s.
printf 'process.on("SIGTERM",()=>{});\nsetTimeout(()=>process.exit(0),30000);\nprocess.stdout.write("wedged");\n' > "$TMP/tar-ignore-term.mjs"
TOUT="$TMP/timeout-snap.age"
START=$(date +%s)
set +e
TERR=$(PATH="$STUBBIN:$PATH" TAR_STUB_MODE=wedge CIPHER_BRAIN_PIPE_TIMEOUT=600 node "${BIN_DEV_ARGS[@]}" "$BIN" snapshot --dir "$SRC" --out "$TOUT" 2>&1); TRC=$?
set -e
ELAPSED=$(( $(date +%s) - START ))
[ "$TRC" != "0" ] || { echo "[FAIL] wedged-tar snapshot exited 0"; exit 1; }
printf '%s' "$TERR" | grep -qi "timed out" || { echo "[FAIL] no timeout error surfaced"; echo "$TERR"; exit 1; }
# < 15s proves the SIGKILL escalation fired (timeout 0.6s + 2s SIGKILL + overhead),
# NOT that we waited out the stub's 30s sleep.
[ "$ELAPSED" -lt 15 ] || { echo "[FAIL] pipeline took ${ELAPSED}s — SIGKILL escalation did not bound it (< the 30s stub)"; exit 1; }
test ! -f "$TOUT"                                       # no finished output
[ -z "$(find "$TMP" -name '*.part' 2>/dev/null)" ] || { echo "[FAIL] a .part lingered after timeout"; exit 1; }
# the staged plaintext dir must be erased by snapshot's finally on the timeout path
[ -z "$(find "${TMPDIR:-/tmp}" -maxdepth 1 -name 'cipher-brain-*' -newermt "@$START" 2>/dev/null)" ] \
  || { echo "[FAIL] a staged-plaintext cipher-brain-* dir lingered after timeout"; exit 1; }
echo "[PASS] SIGTERM-ignoring tar killed via SIGKILL escalation in ${ELAPSED}s; no output / .part / staged plaintext"

echo "== single-key warning counts DISTINCT keys, not --recipient args (#43) =="
# one --recipient file holding TWO keys must NOT warn (recovery exists); a duplicate
# (two args, same key) MUST warn.
keygen2() { CIPHER_BRAIN_HOME="$1" node "${BIN_DEV_ARGS[@]}" "$BIN" keygen >/dev/null 2>&1; }
keygen2 "$TMP/k-a"; keygen2 "$TMP/k-b"
MULTIREC="$TMP/multi-recipient.txt"
cat "$TMP/k-a/recipient.txt" "$TMP/k-b/recipient.txt" > "$MULTIREC"
W1=$(cb snapshot --dir "$SRC" --recipient "$MULTIREC" --out "$TMP/mk.age" 2>&1 | grep -ic "SINGLE recipient" || true)
[ "$W1" = "0" ] || { echo "[FAIL] warned on a 2-key recipient FILE"; exit 1; }
W2=$(cb snapshot --dir "$SRC" --recipient "$TMP/k-a/recipient.txt" --recipient "$TMP/k-a/recipient.txt" --out "$TMP/dup.age" 2>&1 | grep -ic "SINGLE recipient" || true)
[ "$W2" != "0" ] || { echo "[FAIL] did NOT warn on two args naming the SAME key"; exit 1; }
echo "[PASS] single-key warning is by distinct key, not arg count (2-key file silent; dup-arg warns)"

echo "== #119 regression: keygenAt() fails closed when chmod(home, 0700) cannot succeed =="
# chflags uchg (macOS "user immutable") makes even the OWNER's own chmod() fail EPERM,
# without needing root — the only portable, non-root way found to force a chmod
# failure deterministically. No Linux equivalent exists (chattr +i needs
# CAP_LINUX_IMMUTABLE, i.e. root, on ext4/most filesystems), so this is macOS-only;
# on Linux CI it SKIPs rather than fabricate a pass (rules/shell-ops.md: BLOCKED != PASS).
if [ "$(uname -s)" = "Darwin" ]; then
  CHMOD_FAIL_HOME="$TMP/chmod-fail-home"; mkdir -p "$CHMOD_FAIL_HOME"
  chmod 755 "$CHMOD_FAIL_HOME"    # pre-existing, LOOSER than the 0700 keygenAt() must enforce
  chflags uchg "$CHMOD_FAIL_HOME" # immutable: keygenAt()'s own chmod(home, 0700) will now EPERM
  set +e
  OUT=$(CIPHER_BRAIN_HOME="$CHMOD_FAIL_HOME" node "${BIN_DEV_ARGS[@]}" "$BIN" keygen 2>&1); RC=$?
  set -e
  chflags nouchg "$CHMOD_FAIL_HOME" # clear FIRST — every check below may exit 1, and the
                                     # trap's rm -rf "$TMP" cannot remove an immutable dir
  if [ "$RC" = "0" ]; then echo "FAIL: keygen succeeded despite chmod(home, 0700) failing — the #119 regression (a swallowed chmod error)"; echo "$OUT"; exit 1; fi
  printf '%s' "$OUT" | grep -qi "operation not permitted\|EPERM" || { echo "FAIL: keygen's failure was not the expected chmod EPERM"; echo "$OUT"; exit 1; }
  test ! -f "$CHMOD_FAIL_HOME/identity.age" || { echo "FAIL: an identity.age was written into a directory whose permissions could not be verified/corrected"; exit 1; }
  [ "$(stat -f '%Lp' "$CHMOD_FAIL_HOME")" = "755" ] || { echo "FAIL: the directory's mode changed despite the chmod call failing"; exit 1; }
  echo "[PASS] keygen fails closed (writes nothing) when chmod(home, 0700) cannot succeed, instead of silently proceeding"
else
  echo "[SKIP] #119 chmod-fail-closed repro needs chflags (macOS-only — see comment above)"
fi

echo "== #120 regression: --recipient FILE whose path contains 'age1' is read as a file, not mistaken for an inline literal =="
REC_AGE1_HOME="$TMP/rec-age1-home"
CIPHER_BRAIN_HOME="$REC_AGE1_HOME" node "${BIN_DEV_ARGS[@]}" "$BIN" keygen >/dev/null
REC_AGE1_FILE="$TMP/age1-manual-recipients.txt"   # the filename itself starts with "age1"
printf '%s\n' "$(cat "$REC_AGE1_HOME/recipient.txt")" > "$REC_AGE1_FILE"
cb snapshot --dir "$SRC" --recipient "$REC_AGE1_FILE" --out "$TMP/age1-file-recipient.age" >/dev/null
test -f "$TMP/age1-file-recipient.age" || { echo "FAIL: snapshot did not honor a recipients FILE whose path starts with 'age1'"; exit 1; }
CIPHER_BRAIN_HOME="$REC_AGE1_HOME" node "${BIN_DEV_ARGS[@]}" "$BIN" verify --in "$TMP/age1-file-recipient.age" 2>&1 | grep -q 'VERDICT: PASS' \
  || { echo "FAIL: the age1-named-file recipient did not actually decrypt (recipientEntries misread the filename as the literal key)"; exit 1; }
echo "[PASS] --recipient honored a file-based recipient whose path contains 'age1' (recipientEntries checks existence before the age1 prefix, #120)"

echo "== #121 regression: keygen refuses to silently re-key a stray recipient.txt that has no matching identity.age =="
STRAY_HOME="$TMP/stray-recipient-home"
CIPHER_BRAIN_HOME="$STRAY_HOME" node "${BIN_DEV_ARGS[@]}" "$BIN" keygen >/dev/null
STRAY_RECIPIENT_ORIG="$(cat "$STRAY_HOME/recipient.txt")"
rm -f "$STRAY_HOME/identity.age"   # simulate: identity moved offline (cold storage), recipient.txt left behind
set +e
OUT=$(CIPHER_BRAIN_HOME="$STRAY_HOME" node "${BIN_DEV_ARGS[@]}" "$BIN" keygen 2>&1); RC=$?
set -e
if [ "$RC" = "0" ]; then echo "FAIL: keygen silently re-keyed a stray recipient.txt with no matching identity — the #121 regression"; echo "$OUT"; exit 1; fi
printf '%s' "$OUT" | grep -qi "recipient already exists" || { echo "FAIL: wrong error for a stray pre-existing recipient.txt"; echo "$OUT"; exit 1; }
[ "$(cat "$STRAY_HOME/recipient.txt")" = "$STRAY_RECIPIENT_ORIG" ] || { echo "FAIL: the stray recipient.txt was modified despite the refusal"; exit 1; }
test ! -f "$STRAY_HOME/identity.age" || { echo "FAIL: an identity.age was written despite the recipientPath refusal"; exit 1; }
echo "[PASS] keygen refuses to re-key a stray pre-existing recipient.txt without --force, leaving it byte-identical"

echo "== #122 regression: a failed 'keygen --force' (new payload never finishes) must not lose the OLD identity =="
FORCE_HOME="$TMP/force-atomic-home"
CIPHER_BRAIN_HOME="$FORCE_HOME" node "${BIN_DEV_ARGS[@]}" "$BIN" keygen >/dev/null
ORIG_IDENTITY_SHA="$(shasum -a 256 "$FORCE_HOME/identity.age" | cut -d' ' -f1)"
ORIG_RECIPIENT="$(cat "$FORCE_HOME/recipient.txt")"
# --passphrase with no CIPHER_BRAIN_PASSPHRASE and no TTY (< /dev/null): askNewPassphrase()
# throws deterministically ("stdin is not a TTY") AFTER the new keypair is generated but
# BEFORE keygenAt() ever touches identityPath/recipientPath on disk (see keys.ts) — the
# same "prepare fully, THEN replace" ordering the #122 fix requires.
set +e
OUT=$(CIPHER_BRAIN_HOME="$FORCE_HOME" node "${BIN_DEV_ARGS[@]}" "$BIN" keygen --force --passphrase < /dev/null 2>&1); RC=$?
set -e
if [ "$RC" = "0" ]; then echo "FAIL: keygen --force --passphrase succeeded despite no TTY / no CIPHER_BRAIN_PASSPHRASE"; echo "$OUT"; exit 1; fi
printf '%s' "$OUT" | grep -qi "not a TTY" || { echo "FAIL: expected the passphrase-requires-a-TTY error"; echo "$OUT"; exit 1; }
[ "$(shasum -a 256 "$FORCE_HOME/identity.age" | cut -d' ' -f1)" = "$ORIG_IDENTITY_SHA" ] || { echo "FAIL: the ORIGINAL identity was lost/modified by a failed --force keygen — the #122 regression (delete-before-ready)"; exit 1; }
[ "$(cat "$FORCE_HOME/recipient.txt")" = "$ORIG_RECIPIENT" ] || { echo "FAIL: the ORIGINAL recipient was lost/modified by a failed --force keygen"; exit 1; }
TMP_LEFTOVER="$(find "$FORCE_HOME" -maxdepth 1 -name '*.tmp' 2>/dev/null | head -n1)"
[ -z "$TMP_LEFTOVER" ] || { echo "FAIL: a .tmp sibling survived a failed --force keygen: $TMP_LEFTOVER"; exit 1; }
echo "[PASS] a failed --force keygen (passphrase step throwing) leaves the ORIGINAL identity/recipient completely intact — nothing is deleted before the replacement is ready"

echo "== #122: a SUCCESSFUL 'keygen --force' actually replaces identity+recipient, atomically, with no leftover temp file =="
CIPHER_BRAIN_HOME="$FORCE_HOME" node "${BIN_DEV_ARGS[@]}" "$BIN" keygen --force >/dev/null
[ "$(shasum -a 256 "$FORCE_HOME/identity.age" | cut -d' ' -f1)" != "$ORIG_IDENTITY_SHA" ] || { echo "FAIL: --force did not actually replace the identity"; exit 1; }
[ "$(cat "$FORCE_HOME/recipient.txt")" != "$ORIG_RECIPIENT" ] || { echo "FAIL: --force did not actually replace the recipient"; exit 1; }
[ "$(stat -c '%a' "$FORCE_HOME/identity.age" 2>/dev/null || stat -f '%Lp' "$FORCE_HOME/identity.age")" = "600" ] || { echo "FAIL: the replaced identity is not mode 600"; exit 1; }
TMP_LEFTOVER2="$(find "$FORCE_HOME" -maxdepth 1 -name '*.tmp' 2>/dev/null | head -n1)"
[ -z "$TMP_LEFTOVER2" ] || { echo "FAIL: a .tmp sibling survived a successful --force keygen: $TMP_LEFTOVER2"; exit 1; }
echo "[PASS] keygen --force replaces both identity and recipient with a fresh keypair (mode 600 preserved), no .tmp sibling left behind"

echo
echo "SELFTEST PASS"
