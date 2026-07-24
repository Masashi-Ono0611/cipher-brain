#!/usr/bin/env bash
# Selftest for `cipher-brain schedule` (issue #69): the generated nightly runner +
# platform trigger, the paid-backend spend-cap refusal, two REAL back-to-back
# end-to-end runs of the generated runner against the file backend (retry-safety:
# a same-day re-run must not collide with the prior run's snapshot name), status
# reporting, idempotent uninstall, the --no-load uninstall consistency contract
# (#113) and CIPHER_BRAIN_HOME-scoped LABEL/CRON_MARKER (#114). Every `install`
# call uses --no-load (artifacts only) EXCEPT where a test specifically needs to
# prove real (un)registration behavior — those calls use a LABEL/CRON_MARKER that
# is hash-derived from a throwaway $TMP-based CIPHER_BRAIN_HOME (see home_hash()),
# which can never collide with a real, machine-wide schedule, and are always
# uninstalled again (trap-guarded) before this script exits. The one identifier
# this script deliberately never mutates for real is the LEGACY (pre-#114,
# unscoped) LABEL/CRON_MARKER — it is machine-wide, not test-scoped, and could
# name a real production schedule on whatever machine runs this script; the
# legacy-migration coverage below therefore only exercises detection (status) and
# the --no-load report path (uninstall), never the real bootout/crontab-edit call.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/bin/cipher-brain.mjs"
# BIN_DEV_ARGS: literal argv flags to run bin/cipher-brain.mjs against src/*.ts (no
# build step) under plain node — see scripts/dev-node-flags.sh (never an exported
# NODE_OPTIONS string — whitespace-split, breaks under a checkout path with a space).
source "$ROOT/scripts/dev-node-flags.sh"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
export CIPHER_BRAIN_HOME="$TMP/home"
export CIPHER_BRAIN_SCHEDULE_DIR="$TMP/sched"
export CIPHER_BRAIN_LAUNCHD_DIR="$TMP/launchagents"
export CIPHER_BRAIN_FILE_DIR="$TMP/store"
cb() { node "${BIN_DEV_ARGS[@]}" "$BIN" "$@"; }

# First 8 hex chars of sha256(CIPHER_BRAIN_HOME) — must match src/lib/schedule.ts's
# HOME_LABEL_HASH exactly (same input, same algorithm, same truncation) so this script can
# predict the LABEL/CRON_MARKER/plist filename `schedule install` will actually use.
home_hash() {
  if command -v sha256sum > /dev/null 2>&1; then
    printf '%s' "$1" | sha256sum | cut -c1-8
  else
    printf '%s' "$1" | shasum -a 256 | cut -c1-8
  fi
}

RUNNER="$CIPHER_BRAIN_SCHEDULE_DIR/nightly.sh"
CONFIG="$CIPHER_BRAIN_SCHEDULE_DIR/schedule.json"
PLIST="$CIPHER_BRAIN_LAUNCHD_DIR/dev.cipher-brain.nightly.$(home_hash "$CIPHER_BRAIN_HOME").plist"
CRON_ENTRY="$CIPHER_BRAIN_SCHEDULE_DIR/cron.entry"
OS="$(uname -s)"
HAS_CRONTAB=1
if [ "$OS" != "Darwin" ] && ! command -v crontab > /dev/null 2>&1; then HAS_CRONTAB=0; fi

SRC="$TMP/brain-src"; mkdir -p "$SRC"
echo "a-thought" > "$SRC/note.txt"
cb keygen > /dev/null 2>&1

echo "== (a0) --help documents the CIPHER_BRAIN_LAUNCHD_DIR escape hatch (#182: it existed in code but was undocumented) =="
cb --help > "$TMP/help.txt" 2>&1 || { echo "[FAIL] --help exited non-zero"; cat "$TMP/help.txt"; exit 1; }
grep -q 'CIPHER_BRAIN_LAUNCHD_DIR' "$TMP/help.txt" || { echo "[FAIL] --help Env: block does not mention CIPHER_BRAIN_LAUNCHD_DIR (#182)"; exit 1; }
echo "[PASS] --help documents CIPHER_BRAIN_LAUNCHD_DIR"

echo "== (a) install --backend file --no-load: runner + trigger artifact, 03:30 default =="
cb schedule install --backend file --dir "$SRC" --no-load > "$TMP/install-a.log" 2>&1 \
  || { echo "[FAIL] install (file) exited non-zero"; cat "$TMP/install-a.log"; exit 1; }
[ -x "$RUNNER" ] || { echo "[FAIL] runner missing or not executable: $RUNNER"; exit 1; }
[ -f "$CONFIG" ] || { echo "[FAIL] schedule.json not written"; exit 1; }
grep -q '^set -euo pipefail$' "$RUNNER" || { echo "[FAIL] runner lacks set -euo pipefail"; exit 1; }
grep -q -- "snapshot --dir '$SRC' --out" "$RUNNER" || { echo "[FAIL] runner lacks the composed snapshot flags"; exit 1; }
grep -q -- "push --in \"\$OUT\" --backend 'file' --skip-unchanged --save-locator" "$RUNNER" || { echo "[FAIL] runner lacks the composed push flags (--backend/--skip-unchanged/--save-locator, #100)"; exit 1; }
grep -q -- 'SHA=$(cut -f3 ' "$RUNNER" || { echo "[FAIL] runner does not read the index SHA256 back from the save-locator file's 3rd field (#100 — re-hashing \$OUT would break the index on a skip)"; exit 1; }
if grep -q 'sha256_of' "$RUNNER"; then echo "[FAIL] runner still contains the retired sha256_of \$OUT helper (#100)"; exit 1; fi
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
  grep -q -- "$PLIST is a REAL, PERSISTENT file" "$TMP/install-a.log" || { echo "[FAIL] install --no-load did not warn that the plist is a real, persistent file written outside CIPHER_BRAIN_HOME (#182)"; cat "$TMP/install-a.log"; exit 1; }
  grep -q 'CIPHER_BRAIN_LAUNCHD_DIR' "$TMP/install-a.log" || { echo "[FAIL] install --no-load warning did not mention the CIPHER_BRAIN_LAUNCHD_DIR override (#182)"; exit 1; }
else
  [ -f "$CRON_ENTRY" ] || { echo "[FAIL] cron entry artifact not written: $CRON_ENTRY"; exit 1; }
  grep -q '^30 3 \* \* \* /bin/bash ' "$CRON_ENTRY" || { echo "[FAIL] cron entry is not 03:30 daily"; exit 1; }
  grep -q '# cipher-brain-nightly' "$CRON_ENTRY" || { echo "[FAIL] cron entry lacks the uninstall marker"; exit 1; }
  grep -q -- '--no-load: cron entry written' "$TMP/install-a.log" || { echo "[FAIL] install --no-load did not report the cron entry write"; exit 1; }
fi
echo "[PASS] install (file): runner + trigger artifact with the expected pipeline, 03:30 default, no spend lines"

echo "== (a2) non-default backend env vars (not just the FILE_DIR/PG_BIN/AR_WALLET/PIN_RECIPIENTS 4) are baked into the runner =="
# launchd/cron start with a BARE env — anything read from process.env by config.mjs that
# was set at install time and silently dropped makes a scheduled run of a non-default
# backend (turbo/a custom arweave gateway) fail or fall back to the wrong default
# vs. what the operator actually tested interactively (Codex review, #69 P2).
CIPHER_BRAIN_AR_PAID_BY="1234567890abcdef1234567890ABCDEF12345678" \
  cb schedule install --backend file --dir "$SRC" --no-load > "$TMP/install-a2.log" 2>&1 \
  || { echo "[FAIL] install (env-capture) exited non-zero"; cat "$TMP/install-a2.log"; exit 1; }
grep -q "export CIPHER_BRAIN_AR_PAID_BY='1234567890abcdef1234567890ABCDEF12345678'" "$RUNNER" || { echo "[FAIL] runner did not bake CIPHER_BRAIN_AR_PAID_BY"; cat "$RUNNER"; exit 1; }
echo "[PASS] env-capture: a non-default env var (CIPHER_BRAIN_AR_PAID_BY) set at install time is baked into the runner"

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

echo "== (a3b) relative CIPHER_BRAIN_AR_WALLET / CIPHER_BRAIN_PIN_RECIPIENTS set before install (from a subdirectory) resolve to ABSOLUTE in the runner (same launchd/cron-different-cwd hazard as --vault/--zip/--recipient — Codex review round 4, #69 P2) =="
mkdir -p "$TMP/subdir2"
touch "$TMP/subdir2/wallet.json"
printf '# a pin-recipients file\nage1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqcexskr\n' > "$TMP/subdir2/pins.txt"
REALSUB2="$(cd "$TMP/subdir2" && pwd -P)"
(cd "$TMP/subdir2" && CIPHER_BRAIN_AR_WALLET="wallet.json" CIPHER_BRAIN_PIN_RECIPIENTS="pins.txt" cb schedule install --backend file --dir "$SRC" --no-load) \
  > "$TMP/install-a3b.log" 2>&1 || { echo "[FAIL] install (relative AR_WALLET/PIN_RECIPIENTS, invoked from a different cwd) exited non-zero"; cat "$TMP/install-a3b.log"; exit 1; }
grep -qF "export CIPHER_BRAIN_AR_WALLET='$REALSUB2/wallet.json'" "$RUNNER" || { echo "[FAIL] runner does not bake the ABSOLUTE resolved CIPHER_BRAIN_AR_WALLET"; cat "$RUNNER"; exit 1; }
grep -qF "export CIPHER_BRAIN_PIN_RECIPIENTS='$REALSUB2/pins.txt'" "$RUNNER" || { echo "[FAIL] runner does not bake the ABSOLUTE resolved CIPHER_BRAIN_PIN_RECIPIENTS"; cat "$RUNNER"; exit 1; }
if grep -qF "CIPHER_BRAIN_AR_WALLET='wallet.json'" "$RUNNER"; then echo "[FAIL] runner still contains the RELATIVE CIPHER_BRAIN_AR_WALLET string"; exit 1; fi
if grep -qF "CIPHER_BRAIN_PIN_RECIPIENTS='pins.txt'" "$RUNNER"; then echo "[FAIL] runner still contains the RELATIVE CIPHER_BRAIN_PIN_RECIPIENTS string"; exit 1; fi
echo "[PASS] relative CIPHER_BRAIN_AR_WALLET/CIPHER_BRAIN_PIN_RECIPIENTS resolved to absolute in the runner"

echo "== (a3c) TMPDIR set at install time (relative, from a subdirectory) is baked into the runner as an ABSOLUTE export (snapshot()'s mkdtempSync stages plaintext there; launchd/cron start with a bare env and would silently fall back to the system temp dir otherwise) =="
mkdir -p "$TMP/bigdisk"
# Canonical form of $TMP/bigdisk — matches what node:path's resolve()/process.cwd() bakes
# in (macOS mktemp dirs live under a symlinked /var/folders -> /private/var/folders, so a
# naive string comparison against the raw $TMP/bigdisk would false-fail here — see a3's
# REALSUB for the same reasoning).
REALBIGDISK="$(cd "$TMP/bigdisk" && pwd -P)"
(cd "$TMP/subdir2" && TMPDIR=../bigdisk cb schedule install --backend file --dir "$SRC" --no-load) \
  > "$TMP/install-a3c.log" 2>&1 || { echo "[FAIL] install (relative TMPDIR, invoked from a different cwd) exited non-zero"; cat "$TMP/install-a3c.log"; exit 1; }
grep -qF "export TMPDIR='$REALBIGDISK'" "$RUNNER" || { echo "[FAIL] runner does not bake the ABSOLUTE resolved TMPDIR"; cat "$RUNNER"; exit 1; }
echo "[PASS] TMPDIR baked into the runner as an absolute export"

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
# Do NOT strip PATH down to /usr/bin:/bin and assume pg_dump is absent there — hosts
# (including plausible CI images) that ship the PostgreSQL client tools system-wide under
# /usr/bin make that assertion host-dependent and wrongly FAIL a working feature (Codex
# review round 4, #69 P2). Build an ISOLATED PATH dir containing ONLY the one binary
# schedule install's --pg auto-detect itself shells out to — a POSIX shell, to run
# `command -v pg_dump` (see resolvePgDumpDir() in src/lib/schedule.ts) — so pg_dump is
# guaranteed unresolvable no matter what the real host has installed. node is invoked
# directly via its absolute path ($NODE_BIN), so it needs no entry on PATH itself
# (BIN_DEV_ARGS is passed as literal argv, not via PATH or an env var).
ISOLATED_PATH_DIR="$TMP/isolated-path"; mkdir -p "$ISOLATED_PATH_DIR"
ln -s "$(command -v sh)" "$ISOLATED_PATH_DIR/sh"
if PATH="$ISOLATED_PATH_DIR" "$NODE_BIN" "${BIN_DEV_ARGS[@]}" "$BIN" schedule install --backend file --pg "postgres://x/y" --no-load > "$TMP/install-pg-missing.log" 2>&1; then
  echo "[FAIL] install (--pg, isolated PATH with no pg_dump) was accepted"; exit 1
fi
grep -qi 'pg_dump' "$TMP/install-pg-missing.log" || { echo "[FAIL] install failure does not name the missing pg_dump binary"; cat "$TMP/install-pg-missing.log"; exit 1; }
echo "[PASS] install refuses clearly (naming pg_dump) when it cannot be resolved, regardless of the real host's PATH contents"

EXPLICIT_PGBIN="$TMP/explicit-pgbin"; mkdir -p "$EXPLICIT_PGBIN"
CIPHER_BRAIN_PG_BIN="$EXPLICIT_PGBIN" cb schedule install --backend file --pg "postgres://x/y" --no-load > "$TMP/install-pg-explicit.log" 2>&1 \
  || { echo "[FAIL] install (--pg, explicit CIPHER_BRAIN_PG_BIN set) exited non-zero"; cat "$TMP/install-pg-explicit.log"; exit 1; }
grep -qF "export CIPHER_BRAIN_PG_BIN='$EXPLICIT_PGBIN'" "$RUNNER" || { echo "[FAIL] runner did not preserve an explicit CIPHER_BRAIN_PG_BIN unchanged"; cat "$RUNNER"; exit 1; }
echo "[PASS] an explicit CIPHER_BRAIN_PG_BIN is respected as-is, no auto-resolution overrides it"

echo "== (a5) --ping-url: dead man's switch pings baked into the runner + real end-to-end curl hits (issue #202) =="
# A local-only, OS-assigned-port HTTP request logger (scripts/ping-echo-server.mjs) plays
# the role of a healthchecks.io-style monitor — no real network request ever leaves this
# machine. Started here (before any of the sub-checks below) so (a5.4)'s real runner
# invocations have somewhere to curl.
PING_LOG="$TMP/ping-hits.log"; : > "$PING_LOG"
PING_SERVER_OUT="$TMP/ping-server.out"
node "$ROOT/scripts/ping-echo-server.mjs" "$PING_LOG" > "$PING_SERVER_OUT" 2>&1 &
PING_SERVER_PID=$!
PING_PORT=""
for _ in $(seq 1 50); do
  if [ -s "$PING_SERVER_OUT" ]; then
    PING_PORT="$(sed -n 's/^READY:\([0-9]*\)$/\1/p' "$PING_SERVER_OUT" | head -n1)"
    [ -n "$PING_PORT" ] && break
  fi
  sleep 0.1
done
[ -n "$PING_PORT" ] || { echo "[FAIL] local ping-echo-server.mjs never reported READY"; cat "$PING_SERVER_OUT"; kill "$PING_SERVER_PID" 2>/dev/null; exit 1; }
cleanup_ping_server() { kill "$PING_SERVER_PID" 2>/dev/null || true; }
trap 'cleanup_ping_server; rm -rf "$TMP"' EXIT
PING_BASE="http://127.0.0.1:$PING_PORT/hc/abc123"

echo "-- (a5.0) --ping-url-fail without --ping-url is refused --"
if cb schedule install --backend file --dir "$SRC" --ping-url-fail "$PING_BASE/custom-fail" --no-load > "$TMP/ping-fail-only.log" 2>&1; then
  echo "[FAIL] install --ping-url-fail without --ping-url was accepted"; exit 1
fi
grep -q -- '--ping-url-fail requires --ping-url' "$TMP/ping-fail-only.log" || { echo "[FAIL] refusal does not explain --ping-url-fail requires --ping-url"; cat "$TMP/ping-fail-only.log"; exit 1; }
echo "[PASS] --ping-url-fail without --ping-url refused with a clear message"

echo "-- (a5.1) --ping-url alone: runner bakes PING_URL + default \${url}/fail, the trap curl's both, install + status report it --"
cb schedule install --backend file --dir "$SRC" --ping-url "$PING_BASE" --no-load > "$TMP/ping-install.log" 2>&1 \
  || { echo "[FAIL] install (--ping-url) exited non-zero"; cat "$TMP/ping-install.log"; exit 1; }
grep -qF "PING_URL='$PING_BASE'" "$RUNNER" || { echo "[FAIL] runner does not bake PING_URL"; cat "$RUNNER"; exit 1; }
grep -qF "PING_URL_FAIL='$PING_BASE/fail'" "$RUNNER" || { echo "[FAIL] runner does not default PING_URL_FAIL to \${ping_url}/fail"; cat "$RUNNER"; exit 1; }
grep -qF 'curl -fsS -m 10 "$PING_URL" >/dev/null 2>&1 || true' "$RUNNER" || { echo "[FAIL] runner trap lacks the success ping curl"; cat "$RUNNER"; exit 1; }
grep -qF 'curl -fsS -m 10 "$PING_URL_FAIL" >/dev/null 2>&1 || true' "$RUNNER" || { echo "[FAIL] runner trap lacks the failure ping curl"; cat "$RUNNER"; exit 1; }
grep -qF "dead man's switch enabled: success -> $PING_BASE, failure -> $PING_BASE/fail" "$TMP/ping-install.log" || { echo "[FAIL] install did not report the ping config"; cat "$TMP/ping-install.log"; exit 1; }
cb schedule status > "$TMP/ping-status.log" 2>&1 || { echo "[FAIL] status exited non-zero"; cat "$TMP/ping-status.log"; exit 1; }
grep -qF "ping: $PING_BASE (fail: $PING_BASE/fail)" "$TMP/ping-status.log" || { echo "[FAIL] status does not report the configured ping url"; cat "$TMP/ping-status.log"; exit 1; }
echo "[PASS] --ping-url alone: PING_URL/PING_URL_FAIL baked in with the default /fail suffix, curl calls present in the trap, install + status report it"

echo "-- (a5.2) --ping-url-fail overrides the default \${url}/fail suffix --"
cb schedule install --backend file --dir "$SRC" --ping-url "$PING_BASE" --ping-url-fail "http://127.0.0.1:$PING_PORT/hc/custom-fail" --no-load > "$TMP/ping-override.log" 2>&1 \
  || { echo "[FAIL] install (--ping-url + --ping-url-fail override) exited non-zero"; cat "$TMP/ping-override.log"; exit 1; }
grep -qF "PING_URL_FAIL='http://127.0.0.1:$PING_PORT/hc/custom-fail'" "$RUNNER" || { echo "[FAIL] runner did not use the explicit --ping-url-fail override"; cat "$RUNNER"; exit 1; }
if grep -qF "PING_URL_FAIL='$PING_BASE/fail'" "$RUNNER"; then echo "[FAIL] runner still carries the default /fail suffix even though --ping-url-fail was given"; exit 1; fi
echo "[PASS] --ping-url-fail overrides the default /fail suffix"

echo "-- (a5.3) a schedule installed WITHOUT --ping-url never references PING_URL/curl (no regression) --"
cb schedule install --backend file --dir "$SRC" --no-load > /dev/null 2>&1 || { echo "[FAIL] install (no ping) exited non-zero"; exit 1; }
if grep -q 'PING_URL' "$RUNNER"; then echo "[FAIL] runner without --ping-url still references PING_URL"; cat "$RUNNER"; exit 1; fi
if grep -q 'curl' "$RUNNER"; then echo "[FAIL] runner without --ping-url still calls curl"; cat "$RUNNER"; exit 1; fi
echo "[PASS] omitting --ping-url leaves the runner untouched (no PING_URL/curl)"

echo "-- (a5.4) end-to-end: a REAL successful run curls the success URL exactly once; a REAL failing run curls \${url}/fail exactly once --"
# Fully isolated schedule dir + file-backend store + save-locator (distinct from the
# shared ones the rest of this script uses) so these real runs never perturb the
# skip-unchanged / index.tsv / snapshot-count assertions later sections make against
# the shared fixtures.
PING_SCHED_OK="$TMP/sched-ping-ok"
CIPHER_BRAIN_SCHEDULE_DIR="$PING_SCHED_OK" CIPHER_BRAIN_FILE_DIR="$TMP/ping-store" \
  cb schedule install --backend file --dir "$SRC" --ping-url "$PING_BASE" --save-locator "$TMP/ping-locator.tsv" --no-load > "$TMP/ping-e2e-ok-install.log" 2>&1 \
  || { echo "[FAIL] install (ping e2e, success fixture) exited non-zero"; cat "$TMP/ping-e2e-ok-install.log"; exit 1; }
TODAY_PING="$(date +%F)"
: > "$PING_LOG"
bash "$PING_SCHED_OK/nightly.sh" || { echo "[FAIL] successful run (ping e2e) exited non-zero"; cat "$PING_SCHED_OK/logs/nightly-$TODAY_PING.log" 2>/dev/null; exit 1; }
for _ in $(seq 1 30); do grep -qx "GET /hc/abc123" "$PING_LOG" 2>/dev/null && break; sleep 0.1; done
grep -qx "GET /hc/abc123" "$PING_LOG" || { echo "[FAIL] successful run did not curl the success ping URL"; cat "$PING_LOG"; exit 1; }
if grep -qx "GET /hc/abc123/fail" "$PING_LOG"; then echo "[FAIL] successful run also (wrongly) curled the failure ping URL"; exit 1; fi
[ "$(wc -l < "$PING_LOG" | tr -d ' ')" = "1" ] || { echo "[FAIL] expected exactly 1 ping hit after the successful run"; cat "$PING_LOG"; exit 1; }

PING_SCHED_FAIL="$TMP/sched-ping-fail"
CIPHER_BRAIN_SCHEDULE_DIR="$PING_SCHED_FAIL" CIPHER_BRAIN_FILE_DIR="$TMP/ping-store-2" \
  cb schedule install --backend file --dir "$TMP/does-not-exist-ping" --ping-url "$PING_BASE" --save-locator "$TMP/ping-locator-2.tsv" --no-load > "$TMP/ping-e2e-fail-install.log" 2>&1 \
  || { echo "[FAIL] install (ping e2e, failure fixture) exited non-zero"; cat "$TMP/ping-e2e-fail-install.log"; exit 1; }
: > "$PING_LOG"
if bash "$PING_SCHED_FAIL/nightly.sh"; then echo "[FAIL] runner with a missing --dir (ping e2e) unexpectedly succeeded"; exit 1; fi
for _ in $(seq 1 30); do grep -qx "GET /hc/abc123/fail" "$PING_LOG" 2>/dev/null && break; sleep 0.1; done
grep -qx "GET /hc/abc123/fail" "$PING_LOG" || { echo "[FAIL] failing run did not curl the failure ping URL"; cat "$PING_LOG"; exit 1; }
if grep -qx "GET /hc/abc123" "$PING_LOG"; then echo "[FAIL] failing run also (wrongly) curled the success ping URL"; exit 1; fi
[ "$(wc -l < "$PING_LOG" | tr -d ' ')" = "1" ] || { echo "[FAIL] expected exactly 1 ping hit after the failing run"; cat "$PING_LOG"; exit 1; }
echo "[PASS] end-to-end: a successful run curls only the success URL, a failing run curls only \${url}/fail, both exactly once — the ping never changes the run's own OK/FAILED outcome"

cleanup_ping_server
trap 'rm -rf "$TMP"' EXIT

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
STORE_COUNT_1="$(find "$CIPHER_BRAIN_FILE_DIR" -maxdepth 1 -name '*.age' 2>/dev/null | wc -l | tr -d ' ')"
# Same-day immediate re-run (manual test-on-install-day / retry-after-failure): must
# NOT collide with run 1's snapshot name (this is the exact issue #69 regression). $SRC
# is byte-identical to run 1 (nothing wrote to it in between), so this second run is
# ALSO the #100 regression test: the runner's push line must carry --skip-unchanged and
# actually skip the re-upload rather than silently re-paying/re-storing every night.
bash "$RUNNER" || { echo "[FAIL] second runner invocation (same day, immediate retry) exited non-zero — retry-unsafe"; cat "$LOG" 2>/dev/null; exit 1; }
STORE_COUNT_2="$(find "$CIPHER_BRAIN_FILE_DIR" -maxdepth 1 -name '*.age' 2>/dev/null | wc -l | tr -d ' ')"

[ -f "$LOG" ] || { echo "[FAIL] dated log not produced: $LOG"; exit 1; }
tail -n 1 "$LOG" | grep -q '^OK rc=0$' || { echo "[FAIL] log does not end with OK rc=0 after the second run"; tail -n 3 "$LOG"; exit 1; }
grep -q 'SKIPPED: content, recipients and signing unchanged' "$LOG" || { echo "[FAIL] #100: second same-day run (identical \$SRC content) did not SKIP the re-upload — the runner's --skip-unchanged is not wired in / not working"; tail -n 20 "$LOG"; exit 1; }
[ "$STORE_COUNT_2" = "$STORE_COUNT_1" ] || { echo "[FAIL] #100: the file backend store gained a new object on the second (unchanged-content) run — expected $STORE_COUNT_1, got $STORE_COUNT_2 (skip-unchanged did not prevent the re-upload)"; exit 1; }
SNAP_COUNT="$(find "$SNAP_DIR" -maxdepth 1 -name "brain-$TODAY_COMPACT*.age" | wc -l | tr -d ' ')"
[ "$SNAP_COUNT" = "2" ] || { echo "[FAIL] expected 2 distinct dated snapshots after 2 same-day runs, got $SNAP_COUNT"; find "$SNAP_DIR" -maxdepth 1 -name "brain-$TODAY_COMPACT*.age"; exit 1; }
[ -f "$LOCFILE" ] || { echo "[FAIL] --save-locator file not written: $LOCFILE"; exit 1; }
[ "$(awk -F'\t' '{print NF; exit}' "$LOCFILE")" = "5" ] || { echo "[FAIL] locator file is not 5 tab-separated fields (locator/backend/sha256/content_digest/recipients_fingerprint — snapshot always writes both sidecars, #70)"; exit 1; }
[ "$(awk -F'\t' '{print $2; exit}' "$LOCFILE")" = "file" ] || { echo "[FAIL] locator file backend != file"; exit 1; }
[ "$(wc -l < "$IDX" | tr -d ' ')" = "2" ] || { echo "[FAIL] index.tsv does not have exactly 2 appended lines after 2 runs"; exit 1; }
[ "$(awk -F'\t' '{print NF; exit}' "$IDX")" = "3" ] || { echo "[FAIL] index.tsv line is not timestamp/locator/sha256"; exit 1; }
# The skipped 2nd run must have re-used run 1's locator+sha (read back from the
# save-locator file's 3rd field, #100) — both index.tsv lines should therefore carry the
# SAME locator+sha, only the leading timestamp differs.
[ "$(awk -F'\t' '{print $2"\t"$3}' "$IDX" | sort -u | wc -l | tr -d ' ')" = "1" ] || { echo "[FAIL] #100: index.tsv locator/sha256 differ between the two runs even though the 2nd run skipped (expected the same locator+sha reused from the save-locator file)"; cat "$IDX"; exit 1; }
SNAP="$(find "$SNAP_DIR" -maxdepth 1 -name "brain-$TODAY_COMPACT*.age" | sort | tail -n 1)"
cb pull --from-locator-file "$LOCFILE" --out "$TMP/got.age" > /dev/null 2>&1 || { echo "[FAIL] pull via the saved locator failed"; exit 1; }
cb verify --in "$TMP/got.age" > "$TMP/verify.log" 2>&1 || { echo "[FAIL] verify on the pulled snapshot failed"; cat "$TMP/verify.log"; exit 1; }
grep -q 'VERDICT: PASS' "$TMP/verify.log" || { echo "[FAIL] verify verdict is not PASS"; exit 1; }
echo "[PASS] runner end-to-end, twice same day: 2 distinct dated snapshots, 2nd push SKIPPED (#100, no new store object, index.tsv reuses the locator+sha) + trailing OK rc=0 + pull-back verify PASS"

echo "== (c1b) genuinely CHANGED \$SRC content on a same-day 3rd run: a real re-upload happens, not a false SKIP (#100 coverage: --skip-unchanged must never suppress an actual content change) =="
LOG_LINES_BEFORE_RUN3="$(wc -l < "$LOG" | tr -d ' ')"
echo "a-different-thought" >> "$SRC/note.txt"
bash "$RUNNER" || { echo "[FAIL] third runner invocation (changed \$SRC content) exited non-zero"; cat "$LOG" 2>/dev/null; exit 1; }
STORE_COUNT_3="$(find "$CIPHER_BRAIN_FILE_DIR" -maxdepth 1 -name '*.age' 2>/dev/null | wc -l | tr -d ' ')"
[ "$STORE_COUNT_3" = "$((STORE_COUNT_2 + 1))" ] || { echo "[FAIL] #100: changed \$SRC content did not add exactly 1 new object to the file backend store (expected $((STORE_COUNT_2 + 1)), got $STORE_COUNT_3) — skip-unchanged must never suppress a real content change"; exit 1; }
RUN3_LOG="$(tail -n "+$((LOG_LINES_BEFORE_RUN3 + 1))" "$LOG")"
if echo "$RUN3_LOG" | grep -q 'SKIPPED:'; then echo "[FAIL] #100: the 3rd run (changed content) was wrongly SKIPPED"; echo "$RUN3_LOG"; exit 1; fi
echo "$RUN3_LOG" | grep -q '^pushed -> file:' || { echo "[FAIL] 3rd run log lacks the pushed confirmation line"; echo "$RUN3_LOG"; exit 1; }
tail -n 1 "$LOG" | grep -q '^OK rc=0$' || { echo "[FAIL] log does not end with OK rc=0 after the 3rd (changed-content) run"; tail -n 3 "$LOG"; exit 1; }
[ "$(wc -l < "$IDX" | tr -d ' ')" = "3" ] || { echo "[FAIL] index.tsv does not have exactly 3 appended lines after 3 runs (2 unchanged + 1 changed)"; cat "$IDX"; exit 1; }
[ "$(awk -F'\t' '{print $2"\t"$3}' "$IDX" | sort -u | wc -l | tr -d ' ')" = "2" ] || { echo "[FAIL] #100: index.tsv should now have exactly 2 DISTINCT locator+sha pairs (the 2 unchanged runs sharing one, the changed run with a new one)"; cat "$IDX"; exit 1; }
echo "[PASS] a genuinely changed \$SRC on a same-day 3rd run triggers a REAL re-upload (new store object, new locator+sha in index.tsv, no false SKIPPED) — --skip-unchanged never suppresses an actual content change"

echo "== (d) status reports time, backend, last log rc, next run =="
cb schedule status > "$TMP/status.log" 2>&1 || { echo "[FAIL] status exited non-zero"; cat "$TMP/status.log"; exit 1; }
grep -q 'daily at 03:30' "$TMP/status.log" || { echo "[FAIL] status lacks the configured time"; exit 1; }
grep -q 'backend file' "$TMP/status.log" || { echo "[FAIL] status lacks the backend"; exit 1; }
grep -q "nightly-$TODAY.log — OK rc=0" "$TMP/status.log" || { echo "[FAIL] status lacks the last log + rc line"; cat "$TMP/status.log"; exit 1; }
grep -q 'next run: ' "$TMP/status.log" || { echo "[FAIL] status lacks the next scheduled run"; exit 1; }
echo "[PASS] status: configured time + backend + last rc + next run"

echo "== issue #211: status --json prints the SAME state as one JSON line, human output unchanged =="
SJOUT=$(cb schedule status --json)
LINES=$(printf '%s\n' "$SJOUT" | wc -l | tr -d ' ')
[ "$LINES" = "1" ] || { echo "FAIL: schedule status --json printed $LINES stdout line(s), expected exactly 1"; echo "$SJOUT"; exit 1; }
node -e "
const j = JSON.parse(process.argv[1]);
if (j.configured.at !== '03:30') throw new Error('expected configured.at 03:30, got ' + j.configured.at);
if (j.configured.backend !== 'file') throw new Error('expected configured.backend file, got ' + j.configured.backend);
if (typeof j.runner !== 'string' || j.runner.length === 0) throw new Error('expected a non-empty runner path');
if (!j.last_run || !/^nightly-.*\.log$/.test(j.last_run.log)) throw new Error('expected last_run.log to name a nightly log, got ' + JSON.stringify(j.last_run));
if (j.last_run.rc_line !== 'OK rc=0') throw new Error('expected last_run.rc_line OK rc=0, got ' + j.last_run.rc_line);
if (typeof j.next_run !== 'string' || j.next_run.length === 0) throw new Error('expected a non-empty next_run');
if (!j.trigger || typeof j.trigger.loaded !== 'string') throw new Error('expected trigger.loaded to be a string');
if (j.trigger.legacy !== false) throw new Error('expected trigger.legacy false for a freshly-installed schedule');
" "$SJOUT"
echo "[PASS] status --json: one JSON line; configured/runner/last_run/next_run/trigger all correct"

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
  AMP_PLIST="$AMP_LAUNCHD_DIR/dev.cipher-brain.nightly.$(home_hash "$AMP_HOME").plist"
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

echo "== (e0) uninstall --no-load is a pure status report: never orphans a live trigger by deleting only the files (#113) =="
# Symmetric with install's --no-load ("write artifacts, don't touch launchd/crontab"):
# uninstall's --no-load must not touch launchd/crontab EITHER — and, unlike install,
# that means it must also leave the runner/config/plist(or cron entry) alone, since
# deleting them while the trigger is still registered would orphan a live launchd/cron
# job pointing at a script that no longer exists (the exact #113 regression). This is a
# pure file-existence check — no launchd/crontab call happens on this path at all.
[ -f "$RUNNER" ] || { echo "[FAIL] test setup: runner missing before (e0)"; exit 1; }
[ -f "$CONFIG" ] || { echo "[FAIL] test setup: config missing before (e0)"; exit 1; }
cb schedule uninstall --no-load > "$TMP/uninstall-noload.log" 2>&1 || { echo "[FAIL] uninstall --no-load exited non-zero"; cat "$TMP/uninstall-noload.log"; exit 1; }
[ -f "$RUNNER" ] || { echo "[FAIL] #113: uninstall --no-load deleted the runner — would orphan a still-registered trigger"; exit 1; }
[ -f "$CONFIG" ] || { echo "[FAIL] #113: uninstall --no-load deleted schedule.json — would orphan a still-registered trigger"; exit 1; }
if [ "$OS" = "Darwin" ]; then
  [ -f "$PLIST" ] || { echo "[FAIL] #113: uninstall --no-load deleted the plist"; exit 1; }
else
  [ -f "$CRON_ENTRY" ] || { echo "[FAIL] #113: uninstall --no-load deleted the cron entry file"; exit 1; }
fi
grep -q -- '--no-load: nothing removed' "$TMP/uninstall-noload.log" || { echo "[FAIL] uninstall --no-load did not report that nothing was removed"; cat "$TMP/uninstall-noload.log"; exit 1; }
grep -q 'still live' "$TMP/uninstall-noload.log" || { echo "[FAIL] uninstall --no-load did not explain the trigger registration is still live"; cat "$TMP/uninstall-noload.log"; exit 1; }
echo "[PASS] uninstall --no-load: pure status report — no files removed, launchd/crontab untouched, explains why"

echo "== (e) uninstall (no --no-load) removes trigger + runner; second uninstall is a clean no-op =="
if [ "$OS" != "Darwin" ] && [ "$HAS_CRONTAB" = "0" ]; then
  echo "[SKIP] uninstall (real removal) — this host has no crontab binary (Linux, non-Darwin CI image gap, not a cipher-brain issue)"
else
  # No --no-load this time: every install above used --no-load, so nothing was ever REALLY
  # registered — the launchctl bootout / crontab edit below hit the HOME-scoped (#114)
  # LABEL/CRON_MARKER, which is unique to this test's throwaway CIPHER_BRAIN_HOME and can
  # never match a real, machine-wide schedule, so this is safe to run for real.
  cb schedule uninstall > "$TMP/uninstall1.log" 2>&1 || { echo "[FAIL] uninstall exited non-zero"; cat "$TMP/uninstall1.log"; exit 1; }
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
  cb schedule uninstall > "$TMP/uninstall2.log" 2>&1 || { echo "[FAIL] second uninstall exited non-zero (must be idempotent)"; exit 1; }
  grep -q 'nothing to remove' "$TMP/uninstall2.log" || { echo "[FAIL] second uninstall did not report a no-op"; exit 1; }
  if cb schedule status > /dev/null 2>&1; then echo "[FAIL] status after uninstall must fail (not installed)"; exit 1; fi
  echo "[PASS] uninstall: trigger + runner removed, data kept, idempotent; status reports not installed"
fi

echo "== (f) two different CIPHER_BRAIN_HOME schedules never collide: distinct LABEL/CRON_MARKER, installing/uninstalling one never touches the other's REAL registration (#114) =="
if [ "$OS" != "Darwin" ] && [ "$HAS_CRONTAB" = "0" ]; then
  echo "[SKIP] multi-home collision check — this host has no crontab binary"
else
  MHOME1="$TMP/multi-home1"; MHOME2="$TMP/multi-home2"
  MSRC1="$MHOME1/src"; MSRC2="$MHOME2/src"; mkdir -p "$MSRC1" "$MSRC2"
  echo one > "$MSRC1/f.txt"; echo two > "$MSRC2/f.txt"
  MSCHED1="$TMP/multi-sched1"; MSCHED2="$TMP/multi-sched2"
  MLAUNCHD="$TMP/multi-launchagents" # a SHARED dir, like the real ~/Library/LaunchAgents
  mkdir -p "$MLAUNCHD"
  MH1="$(home_hash "$MHOME1")"; MH2="$(home_hash "$MHOME2")"
  [ "$MH1" != "$MH2" ] || { echo "[FAIL] two different CIPHER_BRAIN_HOME produced the SAME label/marker hash"; exit 1; }

  # These two installs are NOT --no-load — real launchctl/crontab registration — but that
  # is safe: LABEL/CRON_MARKER are hash-derived from CIPHER_BRAIN_HOME (#114), so MH1/MH2
  # are guaranteed unique to this run and can never match a real, machine-wide schedule.
  # Guard with a trap so a failure partway through this block still unregisters both real
  # jobs before the script exits (a leaked real trigger pointing at a $TMP dir that is
  # about to be deleted is exactly the #113 orphan bug this whole file guards against).
  cleanup_multi_home() {
    CIPHER_BRAIN_HOME="$MHOME1" CIPHER_BRAIN_SCHEDULE_DIR="$MSCHED1" CIPHER_BRAIN_LAUNCHD_DIR="$MLAUNCHD" cb schedule uninstall > /dev/null 2>&1 || true
    CIPHER_BRAIN_HOME="$MHOME2" CIPHER_BRAIN_SCHEDULE_DIR="$MSCHED2" CIPHER_BRAIN_LAUNCHD_DIR="$MLAUNCHD" cb schedule uninstall > /dev/null 2>&1 || true
  }
  trap 'cleanup_multi_home; rm -rf "$TMP"' EXIT

  CIPHER_BRAIN_HOME="$MHOME1" CIPHER_BRAIN_SCHEDULE_DIR="$MSCHED1" CIPHER_BRAIN_LAUNCHD_DIR="$MLAUNCHD" \
    cb schedule install --backend file --dir "$MSRC1" > "$TMP/multi-install1.log" 2>&1 \
    || { echo "[FAIL] multi-home install 1 exited non-zero"; cat "$TMP/multi-install1.log"; exit 1; }
  CIPHER_BRAIN_HOME="$MHOME2" CIPHER_BRAIN_SCHEDULE_DIR="$MSCHED2" CIPHER_BRAIN_LAUNCHD_DIR="$MLAUNCHD" \
    cb schedule install --backend file --dir "$MSRC2" > "$TMP/multi-install2.log" 2>&1 \
    || { echo "[FAIL] multi-home install 2 exited non-zero"; cat "$TMP/multi-install2.log"; exit 1; }

  if [ "$OS" = "Darwin" ]; then
    MP1="$MLAUNCHD/dev.cipher-brain.nightly.$MH1.plist"; MP2="$MLAUNCHD/dev.cipher-brain.nightly.$MH2.plist"
    [ -f "$MP1" ] || { echo "[FAIL] home1 plist missing after both installs: $MP1"; exit 1; }
    [ -f "$MP2" ] || { echo "[FAIL] home2 plist missing after both installs (#114: did it overwrite home1's file instead of writing a distinct one?)"; exit 1; }
    launchctl print "gui/$(id -u)/dev.cipher-brain.nightly.$MH1" > /dev/null 2>&1 \
      || { echo "[FAIL] #114: home1's launchd job is not loaded after home2 was installed — home2 clobbered it"; exit 1; }
    launchctl print "gui/$(id -u)/dev.cipher-brain.nightly.$MH2" > /dev/null 2>&1 \
      || { echo "[FAIL] home2's launchd job is not loaded"; exit 1; }
    CIPHER_BRAIN_HOME="$MHOME2" CIPHER_BRAIN_SCHEDULE_DIR="$MSCHED2" CIPHER_BRAIN_LAUNCHD_DIR="$MLAUNCHD" \
      cb schedule uninstall > "$TMP/multi-uninstall2.log" 2>&1 || { echo "[FAIL] home2 uninstall exited non-zero"; cat "$TMP/multi-uninstall2.log"; exit 1; }
    [ -f "$MP1" ] || { echo "[FAIL] #114: uninstalling home2 removed home1's plist"; exit 1; }
    launchctl print "gui/$(id -u)/dev.cipher-brain.nightly.$MH1" > /dev/null 2>&1 \
      || { echo "[FAIL] #114: uninstalling home2 unregistered home1's launchd job"; exit 1; }
  else
    crontab -l 2>/dev/null | grep -q "# cipher-brain-nightly:$MH1" \
      || { echo "[FAIL] home1's crontab entry missing after both installs"; exit 1; }
    crontab -l 2>/dev/null | grep -q "# cipher-brain-nightly:$MH2" \
      || { echo "[FAIL] #114: home2's crontab entry missing after both installs (did it overwrite home1's line?)"; exit 1; }
    CIPHER_BRAIN_HOME="$MHOME2" CIPHER_BRAIN_SCHEDULE_DIR="$MSCHED2" CIPHER_BRAIN_LAUNCHD_DIR="$MLAUNCHD" \
      cb schedule uninstall > "$TMP/multi-uninstall2.log" 2>&1 || { echo "[FAIL] home2 uninstall exited non-zero"; cat "$TMP/multi-uninstall2.log"; exit 1; }
    crontab -l 2>/dev/null | grep -q "# cipher-brain-nightly:$MH1" \
      || { echo "[FAIL] #114: uninstalling home2 removed home1's crontab entry"; exit 1; }
  fi
  cleanup_multi_home
  trap 'rm -rf "$TMP"' EXIT
  echo "[PASS] two different CIPHER_BRAIN_HOME schedules use distinct LABEL/CRON_MARKER; installing/uninstalling one never touches the other's real registration"
fi

echo "== (g) backward compat: a legacy (pre-#114, unscoped LABEL/CRON_MARKER) schedule is recognized by status and reported by uninstall --no-load (#114) =="
# Hand-craft what a pre-#114 `install` would have left behind for THIS home: a
# schedule.json whose trigger literally names the OLD unscoped plist/crontab-marker
# (exactly the shape install() used to write before this fix), plus a plist/cron.entry
# file at that legacy (unscoped, machine-wide) name. Detection-only coverage: this test
# deliberately never invokes a REAL launchctl/crontab mutation against the legacy
# identifier (see the file header) — it only exercises status's read-only launchctl
# print / crontab -l and uninstall --no-load's pure (mutation-free) report path.
LEGACY_HOME="$TMP/legacy-home"; LEGACY_SCHED="$TMP/legacy-sched"; LEGACY_LAUNCHD="$TMP/legacy-launchagents"
LEGACY_SRC="$LEGACY_HOME/src"; mkdir -p "$LEGACY_SRC" "$LEGACY_LAUNCHD"
echo legacy > "$LEGACY_SRC/f.txt"
CIPHER_BRAIN_HOME="$LEGACY_HOME" CIPHER_BRAIN_SCHEDULE_DIR="$LEGACY_SCHED" CIPHER_BRAIN_LAUNCHD_DIR="$LEGACY_LAUNCHD" \
  cb schedule install --backend file --dir "$LEGACY_SRC" --no-load > "$TMP/legacy-install.log" 2>&1 \
  || { echo "[FAIL] legacy-fixture install exited non-zero"; cat "$TMP/legacy-install.log"; exit 1; }
if [ "$OS" = "Darwin" ]; then
  LEGACY_PLIST_PATH="$LEGACY_LAUNCHD/dev.cipher-brain.nightly.plist"
  NEW_PLIST_PATH="$(node -e "console.log(JSON.parse(require('fs').readFileSync('$LEGACY_SCHED/schedule.json','utf8')).trigger.path)")"
  mv "$NEW_PLIST_PATH" "$LEGACY_PLIST_PATH"
  node -e "
    const fs = require('fs');
    const p = '$LEGACY_SCHED/schedule.json';
    const cfg = JSON.parse(fs.readFileSync(p, 'utf8'));
    cfg.trigger.path = '$LEGACY_PLIST_PATH';
    fs.writeFileSync(p, JSON.stringify(cfg, null, 2) + '\n');
  "
  CIPHER_BRAIN_HOME="$LEGACY_HOME" CIPHER_BRAIN_SCHEDULE_DIR="$LEGACY_SCHED" CIPHER_BRAIN_LAUNCHD_DIR="$LEGACY_LAUNCHD" \
    cb schedule status > "$TMP/legacy-status.log" 2>&1 || { echo "[FAIL] status on a legacy-format schedule exited non-zero"; cat "$TMP/legacy-status.log"; exit 1; }
  grep -qi 'legacy' "$TMP/legacy-status.log" || { echo "[FAIL] status did not flag the legacy unscoped launchd label"; cat "$TMP/legacy-status.log"; exit 1; }
  CIPHER_BRAIN_HOME="$LEGACY_HOME" CIPHER_BRAIN_SCHEDULE_DIR="$LEGACY_SCHED" CIPHER_BRAIN_LAUNCHD_DIR="$LEGACY_LAUNCHD" \
    cb schedule uninstall --no-load > "$TMP/legacy-uninstall-noload.log" 2>&1 || { echo "[FAIL] uninstall --no-load on a legacy-format schedule exited non-zero"; cat "$TMP/legacy-uninstall-noload.log"; exit 1; }
  grep -q "legacy launchd plist" "$TMP/legacy-uninstall-noload.log" || { echo "[FAIL] uninstall --no-load did not report the legacy plist as present"; cat "$TMP/legacy-uninstall-noload.log"; exit 1; }
  [ -f "$LEGACY_PLIST_PATH" ] || { echo "[FAIL] uninstall --no-load must not delete the legacy plist either"; exit 1; }
  echo "[PASS] legacy-format schedule.json: status flags it, uninstall --no-load reports (but never deletes) the legacy plist"
else
  if [ "$HAS_CRONTAB" = "0" ]; then
    echo "[SKIP] legacy backward-compat check — this host has no crontab binary"
  else
    printf '30 3 * * * /bin/bash "%s" # cipher-brain-nightly\n' "$LEGACY_SCHED/nightly.sh" > "$LEGACY_SCHED/cron.entry"
    CIPHER_BRAIN_HOME="$LEGACY_HOME" CIPHER_BRAIN_SCHEDULE_DIR="$LEGACY_SCHED" CIPHER_BRAIN_LAUNCHD_DIR="$LEGACY_LAUNCHD" \
      cb schedule status > "$TMP/legacy-status.log" 2>&1 || { echo "[FAIL] status on a legacy-format schedule exited non-zero"; cat "$TMP/legacy-status.log"; exit 1; }
    grep -qi 'legacy' "$TMP/legacy-status.log" || { echo "[FAIL] status did not flag the legacy unscoped crontab marker"; cat "$TMP/legacy-status.log"; exit 1; }
    echo "[PASS] legacy-format cron.entry: status flags the unscoped crontab marker"
  fi
fi

echo
echo "SCHEDULE SELFTEST PASS"
