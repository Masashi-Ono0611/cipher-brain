#!/usr/bin/env bash
# verify --level quick|remote|drill (issue #209): restic/kopia-style staged verification.
# quick was already the whole of `verify` before #209 and stays covered by
# scripts/selftest.sh / selftest-storage.sh / selftest-minisign.sh — this script covers
# the two NEW levels against the FILE backend (daemon-free, same reason
# selftest-storage.sh uses it): remote actually re-fetches by locator and re-runs the
# quick checks against the fetched bytes; drill additionally decrypts + extracts into a
# scratch directory and cleans it up.
set -euo pipefail

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

MARKER="verify-levels-$(od -An -N6 -tx1 /dev/urandom | tr -d ' ')"
SRC="$TMP/brain-src"; mkdir -p "$SRC"
printf '%s\n' "$MARKER" > "$SRC/note.txt"

echo "== setup: keygen, snapshot, push (file backend) =="
cb keygen >/dev/null
cb snapshot --dir "$SRC" --out "$TMP/snap.age"
ORIG=$(sha "$TMP/snap.age")
LOC=$(cb push --in "$TMP/snap.age" --backend file --save-locator "$TMP/loc.tsv")
echo "[PASS] setup: pushed to file backend, locator=$LOC"

echo "== --level quick (default, unchanged): still works with no --level flag =="
cb verify --in "$TMP/snap.age" | grep -q 'VERDICT: PASS' \
  && echo "[PASS] verify (no --level) still defaults to quick" \
  || { echo "[FAIL] plain verify regressed"; exit 1; }
cb verify --level quick --in "$TMP/snap.age" | grep -q 'VERDICT: PASS' \
  && echo "[PASS] verify --level quick explicit PASS" \
  || { echo "[FAIL] --level quick explicit did not PASS"; exit 1; }

echo "== --level quick refuses --locator/--backend/--from-locator-file (those FETCH; quick never does) =="
set +e
Q_ERR=$(cb verify --level quick --in "$TMP/snap.age" --locator "$LOC" --backend file 2>&1); Q_RC=$?
set -e
[ "$Q_RC" != "0" ] || { echo "[FAIL] --level quick accepted --locator"; exit 1; }
printf '%s' "$Q_ERR" | grep -q 'quick' || { echo "[FAIL] refusal message unclear: $Q_ERR"; exit 1; }
echo "[PASS] --level quick refuses --locator/--backend"

echo "== --level remote/drill refuse --in (they fetch instead) =="
set +e
R_ERR=$(cb verify --level remote --in "$TMP/snap.age" --locator "$LOC" --backend file 2>&1); R_RC=$?
set -e
[ "$R_RC" != "0" ] || { echo "[FAIL] --level remote accepted --in"; exit 1; }
echo "[PASS] --level remote refuses --in"

echo "== --level remote/drill require --locator+--backend or --from-locator-file =="
set +e
NL_ERR=$(cb verify --level remote 2>&1); NL_RC=$?
set -e
[ "$NL_RC" != "0" ] || { echo "[FAIL] --level remote with no locator/backend accepted"; exit 1; }
echo "[PASS] --level remote refuses with no --locator/--backend/--from-locator-file"

echo "== --level remote: actually re-fetches from the store (delete local copy first) =="
rm -f "$TMP/snap.age"
cb verify --level remote --locator "$LOC" --backend file --sha256 "$ORIG" > "$TMP/remote.out" 2>&1
grep -q 'VERDICT: PASS' "$TMP/remote.out" \
  && echo "[PASS] --level remote VERDICT PASS after re-fetch from store" \
  || { echo "[FAIL] --level remote did not PASS"; cat "$TMP/remote.out"; exit 1; }
grep -q 'remote retrievability confirmed' "$TMP/remote.out" \
  && echo "[PASS] --level remote reports the fetch step" \
  || { echo "[FAIL] --level remote missing fetch-confirmation line"; cat "$TMP/remote.out"; exit 1; }

echo "== --level remote --from-locator-file: same recovery-path input pull/restore already use =="
cb verify --level remote --from-locator-file "$TMP/loc.tsv" | grep -q 'VERDICT: PASS' \
  && echo "[PASS] --level remote --from-locator-file PASS" \
  || { echo "[FAIL] --level remote --from-locator-file did not PASS"; exit 1; }

echo "== --level remote --json: exactly one JSON line, includes pulled{} =="
RJ=$(cb verify --level remote --locator "$LOC" --backend file --json); RRC=$?
[ "$RRC" = "0" ] || { echo "[FAIL] --level remote --json exited $RRC"; echo "$RJ"; exit 1; }
RLINES=$(printf '%s\n' "$RJ" | wc -l | tr -d ' ')
[ "$RLINES" = "1" ] || { echo "[FAIL] --level remote --json printed $RLINES stdout line(s), expected 1"; echo "$RJ"; exit 1; }
printf '%s' "$RJ" | grep -q '"pulled":{"backend":"file"' \
  && echo "[PASS] --level remote --json: one line, includes pulled{backend:file,...}" \
  || { echo "[FAIL] --level remote --json missing pulled{} block"; echo "$RJ"; exit 1; }
printf '%s' "$RJ" | grep -q '"verdict":"PASS"' \
  || { echo "[FAIL] --level remote --json verdict is not PASS"; echo "$RJ"; exit 1; }

echo "== --level remote: a locator that does not exist in the store FAILs (not a crash) =="
set +e
BAD_ERR=$(cb verify --level remote --locator "0000000000000000000000000000000000000000000000000000000000000000.age" --backend file 2>&1); BAD_RC=$?
set -e
[ "$BAD_RC" = "1" ] || { echo "[FAIL] --level remote on a missing locator exited $BAD_RC, expected 1"; echo "$BAD_ERR"; exit 1; }
printf '%s' "$BAD_ERR" | grep -q 'VERDICT: FAIL' \
  && echo "[PASS] --level remote on a missing store object reports VERDICT: FAIL, exit 1 (not a raw crash)" \
  || { echo "[FAIL] missing-object remote check did not report VERDICT: FAIL"; echo "$BAD_ERR"; exit 1; }

echo "== --level drill: pull -> decrypt -> extract into a scratch dir, byte-identical to source =="
cb verify --level drill --locator "$LOC" --backend file --sha256 "$ORIG" > "$TMP/drill.out" 2>&1
grep -q 'VERDICT: PASS' "$TMP/drill.out" \
  && echo "[PASS] --level drill VERDICT PASS" \
  || { echo "[FAIL] --level drill did not PASS"; cat "$TMP/drill.out"; exit 1; }
grep -q 'full restore' "$TMP/drill.out" \
  && echo "[PASS] --level drill reports the full-restore step" \
  || { echo "[FAIL] --level drill missing full-restore line"; cat "$TMP/drill.out"; exit 1; }

echo "== --level drill: the scratch pull/restore directory is not left behind =="
BEFORE=$(find "${TMPDIR:-/tmp}" -maxdepth 1 -name 'cipher-brain-verify-*' 2>/dev/null | wc -l | tr -d ' ')
cb verify --level drill --locator "$LOC" --backend file --sha256 "$ORIG" >/dev/null 2>&1
AFTER=$(find "${TMPDIR:-/tmp}" -maxdepth 1 -name 'cipher-brain-verify-*' 2>/dev/null | wc -l | tr -d ' ')
[ "$BEFORE" = "$AFTER" ] \
  && echo "[PASS] --level drill leaves no cipher-brain-verify-* scratch dir behind" \
  || { echo "[FAIL] --level drill leaked a scratch dir (before=$BEFORE after=$AFTER)"; exit 1; }

echo "== --level drill --json: exactly one JSON line, includes full_restore:true =="
DJ=$(cb verify --level drill --locator "$LOC" --backend file --json); DRC=$?
[ "$DRC" = "0" ] || { echo "[FAIL] --level drill --json exited $DRC"; echo "$DJ"; exit 1; }
DLINES=$(printf '%s\n' "$DJ" | wc -l | tr -d ' ')
[ "$DLINES" = "1" ] || { echo "[FAIL] --level drill --json printed $DLINES stdout line(s), expected 1"; echo "$DJ"; exit 1; }
printf '%s' "$DJ" | grep -q '"full_restore":true' \
  && echo "[PASS] --level drill --json: one line, includes full_restore:true" \
  || { echo "[FAIL] --level drill --json missing full_restore:true"; echo "$DJ"; exit 1; }

echo "== --level drill refuses --pg (a drill must never touch a live database) =="
set +e
PG_ERR=$(cb verify --level drill --locator "$LOC" --backend file --pg "postgres://x/y" 2>&1); PG_RC=$?
set -e
[ "$PG_RC" != "0" ] || { echo "[FAIL] --level drill accepted --pg"; exit 1; }
printf '%s' "$PG_ERR" | grep -qi 'pg_restore' \
  && echo "[PASS] --level drill refuses --pg before doing any work" \
  || { echo "[FAIL] --level drill --pg refusal message unclear: $PG_ERR"; exit 1; }

echo "== --level drill: a sha256 mismatch FAILs closed (no plaintext extracted) =="
set +e
MISMATCH_ERR=$(cb verify --level drill --locator "$LOC" --backend file --sha256 "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef" 2>&1); MISMATCH_RC=$?
set -e
[ "$MISMATCH_RC" = "1" ] || { echo "[FAIL] --level drill sha256 mismatch exited $MISMATCH_RC, expected 1"; echo "$MISMATCH_ERR"; exit 1; }
printf '%s' "$MISMATCH_ERR" | grep -q 'VERDICT: FAIL' \
  && echo "[PASS] --level drill with a wrong --sha256 pin reports VERDICT: FAIL" \
  || { echo "[FAIL] mismatched-pin drill did not report VERDICT: FAIL"; echo "$MISMATCH_ERR"; exit 1; }

echo "== --level bogus is refused =="
set +e
LVL_ERR=$(cb verify --level bogus --in "$TMP/snap.age" 2>&1); LVL_RC=$?
set -e
[ "$LVL_RC" != "0" ] || { echo "[FAIL] --level bogus accepted"; exit 1; }
printf '%s' "$LVL_ERR" | grep -q 'quick, remote or drill' \
  && echo "[PASS] --level bogus refused with a clear message" \
  || { echo "[FAIL] --level bogus refusal message unclear: $LVL_ERR"; exit 1; }

echo "== --level drill on a public-key-only box is PARTIAL (skips the restore step, no identity to decrypt with) =="
PUBONLY="$TMP/pubonly"; mkdir -p "$PUBONLY"
cp "$TMP/keys/recipient.txt" "$PUBONLY/recipient.txt"
set +e
PART_OUT=$(CIPHER_BRAIN_HOME="$PUBONLY" node "${BIN_DEV_ARGS[@]}" "$BIN" verify --level drill --locator "$LOC" --backend file --sha256 "$ORIG" 2>&1); PART_RC=$?
set -e
[ "$PART_RC" = "2" ] || { echo "[FAIL] public-key-only --level drill exited $PART_RC, expected 2"; echo "$PART_OUT"; exit 1; }
printf '%s' "$PART_OUT" | grep -q 'no private identity on this box' \
  && echo "[PASS] public-key-only --level drill SKIPs the restore step and reports PARTIAL (exit 2)" \
  || { echo "[FAIL] public-key-only --level drill did not explain the skip"; echo "$PART_OUT"; exit 1; }

echo "[PASS] verify --level quick/remote/drill (issue #209) all behave as documented"
