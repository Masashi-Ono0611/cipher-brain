#!/usr/bin/env bash
# Selftest for `cipher-brain schedule` (issue #69): the generated nightly runner +
# platform trigger, the paid-backend spend-cap refusal, two REAL back-to-back
# end-to-end runs of the generated runner against the file backend (retry-safety:
# a same-day re-run must not collide with the prior run's snapshot name), status
# reporting, and idempotent uninstall. Never touches the real LaunchAgents/crontab:
# CIPHER_BRAIN_SCHEDULE_DIR + CIPHER_BRAIN_LAUNCHD_DIR point into a temp dir and
# every install/uninstall passes --no-load (artifacts only, no launchctl/crontab
# registration).
set -euo pipefail

BIN="$(cd "$(dirname "$0")/.." && pwd)/bin/cipher-brain.mjs"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
export CIPHER_BRAIN_HOME="$TMP/home"
export CIPHER_BRAIN_SCHEDULE_DIR="$TMP/sched"
export CIPHER_BRAIN_LAUNCHD_DIR="$TMP/launchagents"
export CIPHER_BRAIN_FILE_DIR="$TMP/store"
cb() { node "$BIN" "$@"; }

RUNNER="$CIPHER_BRAIN_SCHEDULE_DIR/nightly.sh"
CONFIG="$CIPHER_BRAIN_SCHEDULE_DIR/schedule.json"
PLIST="$CIPHER_BRAIN_LAUNCHD_DIR/dev.cipher-brain.nightly.plist"
CRON_ENTRY="$CIPHER_BRAIN_SCHEDULE_DIR/cron.entry"
OS="$(uname -s)"

SRC="$TMP/brain-src"; mkdir -p "$SRC"
echo "a-thought" > "$SRC/note.txt"
cb keygen > /dev/null 2>&1

echo "== (a) install --backend file --no-load: runner + trigger artifact, 03:30 default =="
cb schedule install --backend file --dir "$SRC" --no-load > "$TMP/install-a.log" 2>&1 \
  || { echo "[FAIL] install (file) exited non-zero"; cat "$TMP/install-a.log"; exit 1; }
[ -x "$RUNNER" ] || { echo "[FAIL] runner missing or not executable: $RUNNER"; exit 1; }
[ -f "$CONFIG" ] || { echo "[FAIL] schedule.json not written"; exit 1; }
grep -q '^set -euo pipefail$' "$RUNNER" || { echo "[FAIL] runner lacks set -euo pipefail"; exit 1; }
grep -q -- "snapshot --dir '$SRC' --out" "$RUNNER" || { echo "[FAIL] runner lacks the composed snapshot flags"; exit 1; }
grep -q -- "push --in \"\$OUT\" --backend 'file' --save-locator" "$RUNNER" || { echo "[FAIL] runner lacks the composed push flags (--backend/--save-locator)"; exit 1; }
grep -q 'STAMP="\$(date +%Y%m%dT%H%M%S)"' "$RUNNER" || { echo "[FAIL] runner lacks the dated+timed output stamp"; exit 1; }
grep -q 'while \[ -e "\$OUT" \]' "$RUNNER" || { echo "[FAIL] runner lacks the retry-safe disambiguation loop"; exit 1; }
grep -q -- "index.tsv" "$RUNNER" || { echo "[FAIL] runner lacks the index.tsv append"; exit 1; }
grep -q 'FAILED rc=' "$RUNNER" || { echo "[FAIL] runner lacks the trailing FAILED rc trap"; exit 1; }
if grep -q 'CIPHER_BRAIN_YES' "$RUNNER"; then echo "[FAIL] free backend runner must NOT set CIPHER_BRAIN_YES"; exit 1; fi
if grep -q 'CIPHER_BRAIN_MAX_SPEND' "$RUNNER"; then echo "[FAIL] free backend runner must NOT set CIPHER_BRAIN_MAX_SPEND"; exit 1; fi
grep -q '03:30' "$TMP/install-a.log" || { echo "[FAIL] install did not report the 03:30 default"; exit 1; }
grep -q 'settled state' "$TMP/install-a.log" || { echo "[FAIL] install did not print the write-window rationale"; exit 1; }
if [ "$OS" = "Darwin" ]; then
  [ -f "$PLIST" ] || { echo "[FAIL] launchd plist not written: $PLIST"; exit 1; }
  grep -q '<key>Hour</key><integer>3</integer>' "$PLIST" || { echo "[FAIL] plist hour != 3"; exit 1; }
  grep -q '<key>Minute</key><integer>30</integer>' "$PLIST" || { echo "[FAIL] plist minute != 30"; exit 1; }
  grep -q "$RUNNER" "$PLIST" || { echo "[FAIL] plist does not point at the runner"; exit 1; }
else
  [ -f "$CRON_ENTRY" ] || { echo "[FAIL] cron entry artifact not written: $CRON_ENTRY"; exit 1; }
  grep -q '^30 3 \* \* \* /bin/bash ' "$CRON_ENTRY" || { echo "[FAIL] cron entry is not 03:30 daily"; exit 1; }
  grep -q '# cipher-brain-nightly' "$CRON_ENTRY" || { echo "[FAIL] cron entry lacks the uninstall marker"; exit 1; }
fi
echo "[PASS] install (file): runner + trigger artifact with the expected pipeline, 03:30 default, no spend lines"

echo "== (b) paid backend: refused without --max-spend, spend lines written with it =="
if cb schedule install --backend turbo --dir "$SRC" --no-load > "$TMP/turbo-refuse.log" 2>&1; then
  echo "[FAIL] install --backend turbo WITHOUT --max-spend was accepted"; exit 1
fi
grep -q -- '--max-spend' "$TMP/turbo-refuse.log" || { echo "[FAIL] refusal does not name --max-spend"; cat "$TMP/turbo-refuse.log"; exit 1; }
cb schedule install --backend turbo --dir "$SRC" --max-spend 500000 --no-load > "$TMP/install-turbo.log" 2>&1 \
  || { echo "[FAIL] install (turbo, --max-spend) exited non-zero"; cat "$TMP/install-turbo.log"; exit 1; }
grep -q '^export CIPHER_BRAIN_YES=1$' "$RUNNER" || { echo "[FAIL] paid runner lacks CIPHER_BRAIN_YES=1"; exit 1; }
grep -q '^export CIPHER_BRAIN_MAX_SPEND=500000$' "$RUNNER" || { echo "[FAIL] paid runner lacks CIPHER_BRAIN_MAX_SPEND=500000"; exit 1; }
grep -q 'CIPHER_BRAIN_MAX_SPEND=500000' "$TMP/install-turbo.log" || { echo "[FAIL] install did not tell the user to review the cap"; exit 1; }
echo "[PASS] paid backend: uncapped install refused; capped install writes both env lines"

echo "== (c) the generated runner RUNS end-to-end, TWICE in immediate succession (retry-safe, file backend, temp env) =="
cb schedule install --backend file --dir "$SRC" --no-load > /dev/null 2>&1 \
  || { echo "[FAIL] reinstall (file) exited non-zero"; exit 1; }
TODAY="$(date +%F)"
TODAY_COMPACT="$(date +%Y%m%d)" # matches the STAMP="$(date +%Y%m%dT%H%M%S)" the runner names snapshots with
LOG="$CIPHER_BRAIN_SCHEDULE_DIR/logs/nightly-$TODAY.log"
LOCFILE="$CIPHER_BRAIN_HOME/latest-locator.tsv"
IDX="$CIPHER_BRAIN_SCHEDULE_DIR/index.tsv"
SNAP_DIR="$CIPHER_BRAIN_SCHEDULE_DIR/snapshots"

bash "$RUNNER" || { echo "[FAIL] first runner invocation exited non-zero"; cat "$LOG" 2>/dev/null; exit 1; }
# Same-day immediate re-run (manual test-on-install-day / retry-after-failure): must
# NOT collide with run 1's snapshot name (this is the exact issue #69 regression).
bash "$RUNNER" || { echo "[FAIL] second runner invocation (same day, immediate retry) exited non-zero — retry-unsafe"; cat "$LOG" 2>/dev/null; exit 1; }

[ -f "$LOG" ] || { echo "[FAIL] dated log not produced: $LOG"; exit 1; }
tail -n 1 "$LOG" | grep -q '^OK rc=0$' || { echo "[FAIL] log does not end with OK rc=0 after the second run"; tail -n 3 "$LOG"; exit 1; }
SNAP_COUNT="$(find "$SNAP_DIR" -maxdepth 1 -name "brain-$TODAY_COMPACT*.age" | wc -l | tr -d ' ')"
[ "$SNAP_COUNT" = "2" ] || { echo "[FAIL] expected 2 distinct dated snapshots after 2 same-day runs, got $SNAP_COUNT"; find "$SNAP_DIR" -maxdepth 1 -name "brain-$TODAY_COMPACT*.age"; exit 1; }
[ -f "$LOCFILE" ] || { echo "[FAIL] --save-locator file not written: $LOCFILE"; exit 1; }
[ "$(awk -F'\t' '{print NF; exit}' "$LOCFILE")" = "3" ] || { echo "[FAIL] locator file is not 3 tab-separated fields"; exit 1; }
[ "$(awk -F'\t' '{print $2; exit}' "$LOCFILE")" = "file" ] || { echo "[FAIL] locator file backend != file"; exit 1; }
[ "$(wc -l < "$IDX" | tr -d ' ')" = "2" ] || { echo "[FAIL] index.tsv does not have exactly 2 appended lines after 2 runs"; exit 1; }
[ "$(awk -F'\t' '{print NF; exit}' "$IDX")" = "3" ] || { echo "[FAIL] index.tsv line is not timestamp/locator/sha256"; exit 1; }
SNAP="$(find "$SNAP_DIR" -maxdepth 1 -name "brain-$TODAY_COMPACT*.age" | sort | tail -n 1)"
cb pull --from-locator-file "$LOCFILE" --out "$TMP/got.age" > /dev/null 2>&1 || { echo "[FAIL] pull via the saved locator failed"; exit 1; }
cb verify --in "$TMP/got.age" > "$TMP/verify.log" 2>&1 || { echo "[FAIL] verify on the pulled snapshot failed"; cat "$TMP/verify.log"; exit 1; }
grep -q 'VERDICT: PASS' "$TMP/verify.log" || { echo "[FAIL] verify verdict is not PASS"; exit 1; }
echo "[PASS] runner end-to-end, twice same day: 2 distinct dated snapshots + index.tsv +2 lines + trailing OK rc=0 + pull-back verify PASS"

echo "== (d) status reports time, backend, last log rc, next run =="
cb schedule status > "$TMP/status.log" 2>&1 || { echo "[FAIL] status exited non-zero"; cat "$TMP/status.log"; exit 1; }
grep -q 'daily at 03:30' "$TMP/status.log" || { echo "[FAIL] status lacks the configured time"; exit 1; }
grep -q 'backend file' "$TMP/status.log" || { echo "[FAIL] status lacks the backend"; exit 1; }
grep -q "nightly-$TODAY.log — OK rc=0" "$TMP/status.log" || { echo "[FAIL] status lacks the last log + rc line"; cat "$TMP/status.log"; exit 1; }
grep -q 'next run: ' "$TMP/status.log" || { echo "[FAIL] status lacks the next scheduled run"; exit 1; }
echo "[PASS] status: configured time + backend + last rc + next run"

echo "== (c2) a failing run leaves a trailing FAILED rc=N line (heartbeat contract) =="
CIPHER_BRAIN_SCHEDULE_DIR="$TMP/sched-fail" cb schedule install --backend file --dir "$TMP/does-not-exist" --no-load > /dev/null 2>&1 \
  || { echo "[FAIL] install (failure fixture) exited non-zero"; exit 1; }
if bash "$TMP/sched-fail/nightly.sh"; then echo "[FAIL] runner with a missing --dir succeeded"; exit 1; fi
tail -n 1 "$TMP/sched-fail/logs/nightly-$TODAY.log" | grep -q '^FAILED rc=[0-9][0-9]*$' \
  || { echo "[FAIL] failing run did not end the log with FAILED rc=N"; tail -n 3 "$TMP/sched-fail/logs/nightly-$TODAY.log"; exit 1; }
echo "[PASS] failing run: non-zero exit + trailing FAILED rc=N in the dated log"

echo "== (e) uninstall removes trigger + runner; second uninstall is a clean no-op =="
cb schedule uninstall --no-load > "$TMP/uninstall1.log" 2>&1 || { echo "[FAIL] uninstall exited non-zero"; cat "$TMP/uninstall1.log"; exit 1; }
[ ! -f "$RUNNER" ] || { echo "[FAIL] runner still present after uninstall"; exit 1; }
[ ! -f "$CONFIG" ] || { echo "[FAIL] schedule.json still present after uninstall"; exit 1; }
if [ "$OS" = "Darwin" ]; then
  [ ! -f "$PLIST" ] || { echo "[FAIL] plist still present after uninstall"; exit 1; }
else
  [ ! -f "$CRON_ENTRY" ] || { echo "[FAIL] cron entry artifact still present after uninstall"; exit 1; }
fi
grep -q 'removed: ' "$TMP/uninstall1.log" || { echo "[FAIL] uninstall did not report what it removed"; exit 1; }
[ -f "$LOG" ] || { echo "[FAIL] uninstall must KEEP the logs"; exit 1; }
[ -f "$SNAP" ] || { echo "[FAIL] uninstall must KEEP the snapshots"; exit 1; }
[ -f "$IDX" ] || { echo "[FAIL] uninstall must KEEP index.tsv"; exit 1; }
cb schedule uninstall --no-load > "$TMP/uninstall2.log" 2>&1 || { echo "[FAIL] second uninstall exited non-zero (must be idempotent)"; exit 1; }
grep -q 'nothing to remove' "$TMP/uninstall2.log" || { echo "[FAIL] second uninstall did not report a no-op"; exit 1; }
if cb schedule status > /dev/null 2>&1; then echo "[FAIL] status after uninstall must fail (not installed)"; exit 1; fi
echo "[PASS] uninstall: trigger + runner removed, data kept, idempotent; status reports not installed"

echo
echo "SCHEDULE SELFTEST PASS"
