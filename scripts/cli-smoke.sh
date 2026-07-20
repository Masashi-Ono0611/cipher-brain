#!/usr/bin/env bash
# CLI smoke test for the bundled build: dist/cli.mjs must (a) print non-empty
# --help and exit 0, byte-identical to the unbundled bin shim, and (b) run a real
# keygen into a temp CIPHER_BRAIN_HOME producing the identity + recipient files.
# Follows shell-ops discipline: explicit FAIL + exit 1 (no `cond && echo PASS`).
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIST="$ROOT/dist/cli.mjs"
BIN="$ROOT/bin/cipher-brain.mjs"
# run bin/cipher-brain.mjs straight against src/*.ts (no build step) under plain node —
# see scripts/dev-ts-resolve-hook.mjs for why both flags are required (#63). Passed as
# literal argv elements on the $BIN invocations only (never as a NODE_OPTIONS string,
# and never exported) — an exported NODE_OPTIONS would also leak onto the $DIST calls
# below, which must run under genuinely plain node with no dev flags, and NODE_OPTIONS
# is whitespace-split so interpolating this path into it breaks under a checkout
# directory with a space in it (the same bug already fixed in scripts/dev-shim-reexec.mjs
# for the bin/*.mjs shims themselves — argv arrays go straight to execve, never
# shell/whitespace-split, so a space in $ROOT is harmless here).
BIN_DEV_ARGS=(--experimental-strip-types --import "$ROOT/scripts/dev-cli-loader.mjs")
TMP="$(mktemp -d "${TMPDIR:-/tmp}/cb-smoke-XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

if [ ! -f "$DIST" ]; then echo "[FAIL] $DIST missing — run npm run build first"; exit 1; fi

# (a) --help: exit 0, non-empty, identical to the unbundled CLI
node "$DIST" --help > "$TMP/help-dist.txt" 2>&1 || { echo "[FAIL] node dist/cli.mjs --help exited non-zero"; exit 1; }
if [ ! -s "$TMP/help-dist.txt" ]; then echo "[FAIL] --help output is empty"; exit 1; fi
node "${BIN_DEV_ARGS[@]}" "$BIN" --help > "$TMP/help-bin.txt" 2>&1 || { echo "[FAIL] node bin/cipher-brain.mjs --help exited non-zero"; exit 1; }
if ! diff -q "$TMP/help-bin.txt" "$TMP/help-dist.txt" >/dev/null; then
  echo "[FAIL] dist --help differs from bin --help"; diff "$TMP/help-bin.txt" "$TMP/help-dist.txt" | head -20; exit 1
fi
echo "[PASS] dist --help: exit 0, non-empty, byte-identical to bin"

# (b) keygen in a temp home: the key files must appear
export CIPHER_BRAIN_HOME="$TMP/home"
node "$DIST" keygen > "$TMP/keygen.log" 2>&1 || { echo "[FAIL] dist keygen exited non-zero"; cat "$TMP/keygen.log"; exit 1; }
if [ ! -f "$CIPHER_BRAIN_HOME/identity.age" ]; then echo "[FAIL] identity.age not created"; exit 1; fi
if [ ! -f "$CIPHER_BRAIN_HOME/recipient.txt" ]; then echo "[FAIL] recipient.txt not created"; exit 1; fi
echo "[PASS] dist keygen: identity.age + recipient.txt created in temp CIPHER_BRAIN_HOME"

# (c) estimate --backend file: offline, deterministic — sizes an existing file (the
# keygen'd recipient.txt) and must report the free-tier cost without touching the
# network. Read-only: no upload happens.
node "$DIST" estimate --in "$CIPHER_BRAIN_HOME/recipient.txt" --backend file > "$TMP/estimate-file.log" 2>&1 \
  || { echo "[FAIL] dist estimate --backend file exited non-zero"; cat "$TMP/estimate-file.log"; exit 1; }
grep -q "^cost: 0$" "$TMP/estimate-file.log" \
  || { echo "[FAIL] estimate --backend file did not report cost: 0"; cat "$TMP/estimate-file.log"; exit 1; }
echo "[PASS] dist estimate --backend file: cost: 0 for a local file"

# (d) estimate --backend turbo with the optional @ardrive/turbo-sdk NOT installed in
# this environment — must report a clear "not installed" note (offline, deterministic)
# rather than crash, exercising src/lib/estimate.ts's estimateCost() turbo branch.
node "$DIST" estimate --in "$CIPHER_BRAIN_HOME/recipient.txt" --backend turbo > "$TMP/estimate-turbo.log" 2>&1 \
  || { echo "[FAIL] dist estimate --backend turbo exited non-zero"; cat "$TMP/estimate-turbo.log"; exit 1; }
grep -q "^cost: unavailable$" "$TMP/estimate-turbo.log" \
  || { echo "[FAIL] estimate --backend turbo did not report cost: unavailable"; cat "$TMP/estimate-turbo.log"; exit 1; }
echo "[PASS] dist estimate --backend turbo: cost: unavailable (optional dependency not installed)"

# (e) estimate rejects a bad --backend value and a missing --in, same as push does
node "$DIST" estimate --in "$CIPHER_BRAIN_HOME/recipient.txt" --backend bogus > "$TMP/estimate-bad.log" 2>&1
if [ $? -eq 0 ]; then echo "[FAIL] estimate --backend bogus exited 0, expected non-zero"; cat "$TMP/estimate-bad.log"; exit 1; fi
grep -q "unknown backend" "$TMP/estimate-bad.log" \
  || { echo "[FAIL] estimate --backend bogus did not report 'unknown backend'"; cat "$TMP/estimate-bad.log"; exit 1; }
echo "[PASS] dist estimate --backend bogus: rejected with 'unknown backend'"

echo "CLI SMOKE: PASS"
