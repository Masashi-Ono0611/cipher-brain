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

echo "== (a2) non-default backend env vars (not just the FILE_DIR/PG_BIN/AR_WALLET/PIN_RECIPIENTS 4) are baked into the runner =="
# launchd/cron start with a BARE env — anything read from process.env by config.mjs that
# was set at install time and silently dropped makes a scheduled run of a non-default
# backend (ton/turbo/a custom arweave gateway) fail or fall back to the wrong default
# vs. what the operator actually tested interactively (Codex review, #69 P2).
CIPHER_BRAIN_TON_CLIENT="$TMP/ton-client.key" CIPHER_BRAIN_TON_SERVER="$TMP/ton-server.pub" CIPHER_BRAIN_AR_PAID_BY="1234567890abcdef1234567890ABCDEF12345678" \
  cb schedule install --backend file --dir "$SRC" --no-load > "$TMP/install-a2.log" 2>&1 \
  || { echo "[FAIL] install (env-capture) exited non-zero"; cat "$TMP/install-a2.log"; exit 1; }
grep -q "export CIPHER_BRAIN_TON_CLIENT='$TMP/ton-client.key'" "$RUNNER" || { echo "[FAIL] runner did not bake CIPHER_BRAIN_TON_CLIENT"; cat "$RUNNER"; exit 1; }
grep -q "export CIPHER_BRAIN_TON_SERVER='$TMP/ton-server.pub'" "$RUNNER" || { echo "[FAIL] runner did not bake CIPHER_BRAIN_TON_SERVER"; cat "$RUNNER"; exit 1; }
grep -q "export CIPHER_BRAIN_AR_PAID_BY='1234567890abcdef1234567890ABCDEF12345678'" "$RUNNER" || { echo "[FAIL] runner did not bake CIPHER_BRAIN_AR_PAID_BY"; cat "$RUNNER"; exit 1; }
echo "[PASS] env-capture: non-default TON/turbo env vars set at install time are baked into the runner"

echo "== (a3) relative --vault/--zip/--recipient file paths resolve to ABSOLUTE in the runner (launchd/cron runs from a DIFFERENT cwd than install); an inline age1... --recipient is left UNCHANGED =="
# This is the exact issue #69 P2 regression: a relative path baked in verbatim resolves
# correctly at install time (whatever cwd the operator happened to be in) but not
# necessarily at scheduled-run time (launchd/cron invoke the runner from a different,
# unrelated cwd). Run install FROM a subdirectory so cwd truly differs from $TMP.
mkdir -p "$TMP/subdir/vaultdir"
touch "$TMP/subdir/exportdata.zip"
printf '# a recipients file\nage1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqcexskr\n' > "$TMP/subdir/recipients.txt"
INLINE_KEY="age1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqcexskr"
# Canonical form of $TMP/subdir — matches what node:path's resolve()/process.cwd() bakes
# in (macOS mktemp dirs live under a symlinked /var/folders -> /private/var/folders, so a
# naive string comparison against the raw $TMP/subdir would false-fail here).
REALSUB="$(cd "$TMP/subdir" && pwd -P)"
(cd "$TMP/subdir" && cb schedule install --backend file --dir "$SRC" --vault vaultdir --zip exportdata.zip --recipient recipients.txt --recipient "$INLINE_KEY" --no-load) \
  > "$TMP/install-a3.log" 2>&1 || { echo "[FAIL] install (relative paths, invoked from a different cwd) exited non-zero"; cat "$TMP/install-a3.log"; exit 1; }
grep -qF -- "--vault '$REALSUB/vaultdir'" "$RUNNER" || { echo "[FAIL] runner does not bake the ABSOLUTE resolved --vault path"; cat "$RUNNER"; exit 1; }
grep -qF -- "--zip '$REALSUB/exportdata.zip'" "$RUNNER" || { echo "[FAIL] runner does not bake the ABSOLUTE resolved --zip path"; cat "$RUNNER"; exit 1; }
grep -qF -- "--recipient '$REALSUB/recipients.txt'" "$RUNNER" || { echo "[FAIL] runner does not bake the ABSOLUTE resolved --recipient FILE path"; cat "$RUNNER"; exit 1; }
grep -qF -- "--recipient '$INLINE_KEY'" "$RUNNER" || { echo "[FAIL] runner does not bake the inline age1... --recipient value UNCHANGED"; cat "$RUNNER"; exit 1; }
if grep -qF -- "--vault 'vaultdir'" "$RUNNER"; then echo "[FAIL] runner still contains the RELATIVE --vault string"; exit 1; fi
if grep -qF -- "--zip 'exportdata.zip'" "$RUNNER"; then echo "[FAIL] runner still contains the RELATIVE --zip string"; exit 1; fi
if grep -qF -- "--recipient 'recipients.txt'" "$RUNNER"; then echo "[FAIL] runner still contains the RELATIVE --recipient FILE string"; exit 1; fi
echo "[PASS] relative --vault/--zip/--recipient(file) resolved to absolute in the runner; inline age1... --recipient left unchanged"

echo "== (a4) --pg without CIPHER_BRAIN_PG_BIN resolves pg_dump on PATH at install time and bakes its DIRECTORY as CIPHER_BRAIN_PG_BIN (config.mjs's PG_BIN is a dir joined with the tool name via pgTool(), not the pg_dump binary path itself — baking the binary path verbatim would break both pg_dump AND pg_restore); install fails clearly when pg_dump cannot be resolved =="
FAKE_PGBIN="$TMP/fake-pgbin"; mkdir -p "$FAKE_PGBIN"
cat > "$FAKE_PGBIN/pg_dump" <<'SHIM'
#!/usr/bin/env bash
echo "fake pg_dump shim: $*" >&2
exit 0
SHIM
chmod +x "$FAKE_PGBIN/pg_dump"
# NOTE: unlike --vault/--zip/--recipient (resolved via node:path's resolve() against
# process.cwd(), which macOS reports already symlink-resolved), pg_dump's path here comes
# straight from `command -v` reading PATH — resolve() only normalizes it (it does NOT
# follow symlinks), so the baked value is the literal $FAKE_PGBIN, not its realpath.
REAL_FAKE_PGBIN="$FAKE_PGBIN"
PATH="$FAKE_PGBIN:$PATH" cb schedule install --backend file --pg "postgres://x/y" --no-load > "$TMP/install-pg.log" 2>&1 \
  || { echo "[FAIL] install (--pg, shimmed pg_dump prepended to PATH) exited non-zero"; cat "$TMP/install-pg.log"; exit 1; }
grep -qF "export CIPHER_BRAIN_PG_BIN='$REAL_FAKE_PGBIN'" "$RUNNER" || { echo "[FAIL] runner did not bake the resolved pg_dump DIRECTORY as CIPHER_BRAIN_PG_BIN"; cat "$RUNNER"; exit 1; }
if grep -qF "CIPHER_BRAIN_PG_BIN='$REAL_FAKE_PGBIN/pg_dump'" "$RUNNER"; then echo "[FAIL] runner baked the pg_dump BINARY path, not its directory — pgTool('pg_dump')/pgTool('pg_restore') would break"; exit 1; fi
grep -qF "resolved pg_dump -> $REAL_FAKE_PGBIN/pg_dump" "$TMP/install-pg.log" || { echo "[FAIL] install did not report the resolved pg_dump path"; cat "$TMP/install-pg.log"; exit 1; }
echo "[PASS] --pg without CIPHER_BRAIN_PG_BIN resolves pg_dump on PATH and bakes its containing directory into the runner"

NODE_BIN="$(command -v node)"
if PATH="/usr/bin:/bin" "$NODE_BIN" "$BIN" schedule install --backend file --pg "postgres://x/y" --no-load > "$TMP/install-pg-missing.log" 2>&1; then
  echo "[FAIL] install (--pg, minimal PATH with no pg_dump) was accepted"; exit 1
fi
grep -qi 'pg_dump' "$TMP/install-pg-missing.log" || { echo "[FAIL] install failure does not name the missing pg_dump binary"; cat "$TMP/install-pg-missing.log"; exit 1; }
echo "[PASS] install refuses clearly (naming pg_dump) when it cannot be resolved on PATH"

EXPLICIT_PGBIN="$TMP/explicit-pgbin"; mkdir -p "$EXPLICIT_PGBIN"
CIPHER_BRAIN_PG_BIN="$EXPLICIT_PGBIN" cb schedule install --backend file --pg "postgres://x/y" --no-load > "$TMP/install-pg-explicit.log" 2>&1 \
  || { echo "[FAIL] install (--pg, explicit CIPHER_BRAIN_PG_BIN set) exited non-zero"; cat "$TMP/install-pg-explicit.log"; exit 1; }
grep -qF "export CIPHER_BRAIN_PG_BIN='$EXPLICIT_PGBIN'" "$RUNNER" || { echo "[FAIL] runner did not preserve an explicit CIPHER_BRAIN_PG_BIN unchanged"; cat "$RUNNER"; exit 1; }
echo "[PASS] an explicit CIPHER_BRAIN_PG_BIN is respected as-is, no auto-resolution overrides it"

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

echo "== (c3) a CIPHER_BRAIN_HOME containing an XML metacharacter ('&') still produces a VALID, well-formed launchd plist (macOS only) =="
if [ "$OS" = "Darwin" ]; then
  AMP_HOME="$TMP/home & co" # plausible in a real $HOME/username; must not corrupt the plist
  mkdir -p "$AMP_HOME"
  AMP_LAUNCHD_DIR="$TMP/launchagents-amp"
  AMP_PLIST="$AMP_LAUNCHD_DIR/dev.cipher-brain.nightly.plist"
  # CIPHER_BRAIN_SCHEDULE_DIR is exported globally at top of this script (pointing at
  # $TMP/sched, no '&'), so it must be overridden here too — otherwise it would win over
  # CIPHER_BRAIN_HOME and the runner path baked into the plist would never see the '&'.
  CIPHER_BRAIN_HOME="$AMP_HOME" CIPHER_BRAIN_SCHEDULE_DIR="$AMP_HOME/sched" CIPHER_BRAIN_LAUNCHD_DIR="$AMP_LAUNCHD_DIR" \
    cb schedule install --backend file --dir "$SRC" --no-load > "$TMP/install-amp.log" 2>&1 \
    || { echo "[FAIL] install with an '&' in CIPHER_BRAIN_HOME exited non-zero"; cat "$TMP/install-amp.log"; exit 1; }
  [ -f "$AMP_PLIST" ] || { echo "[FAIL] plist not written for the '&'-containing home: $AMP_PLIST"; exit 1; }
  plutil -lint "$AMP_PLIST" > "$TMP/plutil.log" 2>&1 || { echo "[FAIL] plutil -lint rejects the generated plist (invalid XML)"; cat "$TMP/plutil.log"; cat "$AMP_PLIST"; exit 1; }
  grep -q '&amp;' "$AMP_PLIST" || { echo "[FAIL] plist does not contain the escaped '&amp;' for the runner path"; cat "$AMP_PLIST"; exit 1; }
  if grep -qF ' & co' "$AMP_PLIST"; then echo "[FAIL] plist contains a raw un-escaped '&' — invalid XML"; exit 1; fi
  # Round-trip: plutil -p decodes entities back to plain text — the '&'-containing home
  # dir must reappear verbatim, proving the escape is reversible (not just well-formed).
  plutil -p "$AMP_PLIST" | grep -qF "$AMP_HOME" || { echo "[FAIL] plutil -p does not decode the plist back to the original '&'-containing path"; plutil -p "$AMP_PLIST"; exit 1; }
  echo "[PASS] plist with an '&' in CIPHER_BRAIN_HOME is valid, well-formed XML (plutil -lint) and round-trips to the original path (plutil -p)"
else
  echo "[SKIP] plist XML-escape check (macOS only — this platform registers a crontab entry, not a plist)"
fi

echo "== (c4) --index-file under a NOT-YET-EXISTING nested directory: the runner creates it before appending (a successful, possibly-paid push must never turn into a FAILED run just because the index dir does not exist yet — a naive retry after a false FAILED could re-upload and pay again) =="
IDX_NESTED_DIR="$TMP/idx-parent/does-not-exist-yet/deeper"
[ ! -d "$IDX_NESTED_DIR" ] || { echo "[FAIL] test setup invalid: $IDX_NESTED_DIR already exists"; exit 1; }
cb schedule install --backend file --dir "$SRC" --index-file "$IDX_NESTED_DIR/index.tsv" --no-load > "$TMP/install-idxnest.log" 2>&1 \
  || { echo "[FAIL] install (--index-file under a nested nonexistent dir) exited non-zero"; cat "$TMP/install-idxnest.log"; exit 1; }
[ ! -d "$IDX_NESTED_DIR" ] || { echo "[FAIL] install must not itself create the index-file directory (only the runner does, at run time)"; exit 1; }
bash "$RUNNER" || { echo "[FAIL] runner with a not-yet-existing --index-file directory exited non-zero"; tail -n 20 "$LOG" 2>/dev/null; exit 1; }
[ -f "$IDX_NESTED_DIR/index.tsv" ] || { echo "[FAIL] index file was not created under the nested directory"; exit 1; }
[ "$(wc -l < "$IDX_NESTED_DIR/index.tsv" | tr -d ' ')" = "1" ] || { echo "[FAIL] index file does not have exactly 1 appended line"; cat "$IDX_NESTED_DIR/index.tsv"; exit 1; }
[ "$(awk -F'\t' '{print NF; exit}' "$IDX_NESTED_DIR/index.tsv")" = "3" ] || { echo "[FAIL] index line is not timestamp/locator/sha256"; exit 1; }
tail -n 1 "$LOG" | grep -q '^OK rc=0$' || { echo "[FAIL] log does not end with OK rc=0 after the nested-index-dir run"; tail -n 3 "$LOG"; exit 1; }
echo "[PASS] runner mkdir -p's the --index-file's parent directory before appending, on a not-yet-existing nested path"

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
