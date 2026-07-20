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

# (c) wallet (#158): create at the default path (0600), address derives the SAME
# address create printed, no-clobber refuses a second create, --force replaces it with
# a genuinely fresh keypair (a different address).
WALLET_DEFAULT="$CIPHER_BRAIN_HOME/wallet.json"
node "$DIST" wallet create > "$TMP/wallet-create.log" 2>&1 || { echo "[FAIL] dist wallet create exited non-zero"; cat "$TMP/wallet-create.log"; exit 1; }
if [ ! -f "$WALLET_DEFAULT" ]; then echo "[FAIL] wallet.json not created at default path"; exit 1; fi
WALLET_MODE="$(stat -c '%a' "$WALLET_DEFAULT" 2>/dev/null || stat -f '%Lp' "$WALLET_DEFAULT")"
if [ "$WALLET_MODE" != "600" ]; then echo "[FAIL] wallet.json mode is $WALLET_MODE, expected 600"; exit 1; fi
ADDR1="$(node "$DIST" wallet address --wallet "$WALLET_DEFAULT")" || { echo "[FAIL] dist wallet address exited non-zero"; exit 1; }
if [ -z "$ADDR1" ]; then echo "[FAIL] wallet address printed nothing"; exit 1; fi
if ! grep -qF "$ADDR1" "$TMP/wallet-create.log"; then
  echo "[FAIL] wallet create's printed address does not match wallet address's own derivation"; cat "$TMP/wallet-create.log"; exit 1
fi
echo "[PASS] dist wallet create: wallet.json (mode 600) at default path; wallet address derives the SAME address create printed"

node "$DIST" wallet create > /dev/null 2>"$TMP/wallet-noclobber.log"
if [ $? -eq 0 ]; then echo "[FAIL] wallet create without --force overwrote an existing wallet"; exit 1; fi
if ! grep -q "already exists" "$TMP/wallet-noclobber.log"; then
  echo "[FAIL] wallet create's no-clobber refusal message missing"; cat "$TMP/wallet-noclobber.log"; exit 1
fi
echo "[PASS] dist wallet create: refuses to clobber an existing wallet without --force"

node "$DIST" wallet create --force > "$TMP/wallet-force.log" 2>&1 || { echo "[FAIL] dist wallet create --force exited non-zero"; cat "$TMP/wallet-force.log"; exit 1; }
ADDR2="$(node "$DIST" wallet address --wallet "$WALLET_DEFAULT")" || { echo "[FAIL] dist wallet address (post-force) exited non-zero"; exit 1; }
if [ "$ADDR2" = "$ADDR1" ]; then echo "[FAIL] wallet create --force did not generate a fresh keypair (address unchanged)"; exit 1; fi
echo "[PASS] dist wallet create --force: replaces the wallet with a fresh keypair (new address)"

echo "CLI SMOKE: PASS"
