#!/usr/bin/env bash
# CLI smoke test for the bundled build: dist/cli.mjs must (a) print non-empty
# --help and exit 0, byte-identical to the unbundled bin shim, (b) run a real
# keygen into a temp CIPHER_BRAIN_HOME producing the identity + recipient files,
# and (c)-(g) exercise the `estimate` command (#159) — the free/paid-backend
# happy paths and its input validation (missing --in, bad --backend, a
# directory --in).
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
if ! grep -qF -- "$ADDR1" "$TMP/wallet-create.log"; then
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

# (c2) #164: `wallet address` with NEITHER --wallet NOR CIPHER_BRAIN_AR_WALLET set must
# fall back to the same default path `wallet create` just wrote to, not error out.
unset CIPHER_BRAIN_AR_WALLET
ADDR3="$(node "$DIST" wallet address)" || { echo "[FAIL] dist wallet address (no --wallet, no CIPHER_BRAIN_AR_WALLET) exited non-zero"; exit 1; }
if [ "$ADDR3" != "$ADDR2" ]; then
  echo "[FAIL] wallet address without --wallet did not fall back to the default wallet.json path (got '$ADDR3', expected '$ADDR2')"; exit 1
fi
echo "[PASS] dist wallet address: falls back to \$CIPHER_BRAIN_HOME/wallet.json when --wallet and CIPHER_BRAIN_AR_WALLET are both unset"

# (d) estimate --backend file: offline, deterministic — sizes an existing file (the
# keygen'd recipient.txt) and must report the free-tier cost without touching the
# network. Read-only: no upload happens.
node "$DIST" estimate --in "$CIPHER_BRAIN_HOME/recipient.txt" --backend file > "$TMP/estimate-file.log" 2>&1 \
  || { echo "[FAIL] dist estimate --backend file exited non-zero"; cat "$TMP/estimate-file.log"; exit 1; }
grep -q "^cost: 0$" "$TMP/estimate-file.log" \
  || { echo "[FAIL] estimate --backend file did not report cost: 0"; cat "$TMP/estimate-file.log"; exit 1; }
echo "[PASS] dist estimate --backend file: cost: 0 for a local file"

# (e) estimate --backend turbo — deterministic/offline either way, but the expected
# note depends on whether the OPTIONAL @ardrive/turbo-sdk happens to be installed in
# this environment (it is not a devDependency, only an optional peerDependency — see
# package.json — so `bun install --frozen-lockfile` normally leaves it absent, but a
# future lockfile change could add it): branch on its actual presence instead of
# assuming absence, so this test can't silently start failing on a healthy install.
node "$DIST" estimate --in "$CIPHER_BRAIN_HOME/recipient.txt" --backend turbo > "$TMP/estimate-turbo.log" 2>&1 \
  || { echo "[FAIL] dist estimate --backend turbo exited non-zero"; cat "$TMP/estimate-turbo.log"; exit 1; }
if [ -d "$ROOT/node_modules/@ardrive/turbo-sdk" ]; then
  grep -q "^backend: turbo$" "$TMP/estimate-turbo.log" \
    || { echo "[FAIL] estimate --backend turbo (sdk installed) did not report backend: turbo"; cat "$TMP/estimate-turbo.log"; exit 1; }
  echo "[PASS] dist estimate --backend turbo: SDK installed, ran without crashing"
else
  grep -q "^cost: unavailable$" "$TMP/estimate-turbo.log" \
    || { echo "[FAIL] estimate --backend turbo did not report cost: unavailable"; cat "$TMP/estimate-turbo.log"; exit 1; }
  echo "[PASS] dist estimate --backend turbo: cost: unavailable (optional dependency not installed)"
fi

# (f) estimate rejects a missing --in
node "$DIST" estimate --backend file > "$TMP/estimate-noin.log" 2>&1
if [ $? -eq 0 ]; then echo "[FAIL] estimate with no --in exited 0, expected non-zero"; cat "$TMP/estimate-noin.log"; exit 1; fi
grep -q -- "--in <file.age> required" "$TMP/estimate-noin.log" \
  || { echo "[FAIL] estimate with no --in did not report the expected error"; cat "$TMP/estimate-noin.log"; exit 1; }
echo "[PASS] dist estimate (no --in): rejected with '--in <file.age> required'"

# (g) estimate rejects a bad --backend value, same as it rejects a missing --in above
node "$DIST" estimate --in "$CIPHER_BRAIN_HOME/recipient.txt" --backend bogus > "$TMP/estimate-bad.log" 2>&1
if [ $? -eq 0 ]; then echo "[FAIL] estimate --backend bogus exited 0, expected non-zero"; cat "$TMP/estimate-bad.log"; exit 1; fi
grep -q "unknown backend" "$TMP/estimate-bad.log" \
  || { echo "[FAIL] estimate --backend bogus did not report 'unknown backend'"; cat "$TMP/estimate-bad.log"; exit 1; }
echo "[PASS] dist estimate --backend bogus: rejected with 'unknown backend'"

# (h) estimate rejects a directory --in (stat().size on a dir would otherwise produce
# a nonsensical-but-silent "estimate" instead of a clear error)
node "$DIST" estimate --in "$ROOT" --backend file > "$TMP/estimate-dir.log" 2>&1
if [ $? -eq 0 ]; then echo "[FAIL] estimate --in <dir> exited 0, expected non-zero"; cat "$TMP/estimate-dir.log"; exit 1; fi
grep -q "not a regular file" "$TMP/estimate-dir.log" \
  || { echo "[FAIL] estimate --in <dir> did not report 'not a regular file'"; cat "$TMP/estimate-dir.log"; exit 1; }
echo "[PASS] dist estimate --in <dir>: rejected with 'not a regular file'"

# (i) #253: an unrecognized/mistyped --flag must be a hard error, not silently
# stored and ignored. Covers both a typo of a value flag (--recipiant, for
# --recipient) and a typo of a repeatable array flag (--dirs, plural, for
# --dir) landing in the generic branch.
node "$DIST" estimate --in "$CIPHER_BRAIN_HOME/recipient.txt" --backend file --recipiant foo > "$TMP/unknown-flag.log" 2>&1
if [ $? -eq 0 ]; then echo "[FAIL] estimate with unknown --recipiant exited 0, expected non-zero"; cat "$TMP/unknown-flag.log"; exit 1; fi
grep -q "unknown flag: --recipiant" "$TMP/unknown-flag.log" \
  || { echo "[FAIL] unknown --recipiant did not report 'unknown flag: --recipiant'"; cat "$TMP/unknown-flag.log"; exit 1; }
echo "[PASS] dist estimate --recipiant (typo): rejected with 'unknown flag: --recipiant'"

node "$DIST" snapshot --out "$TMP/unknown-bool.age" --dirs "$CIPHER_BRAIN_HOME" > "$TMP/unknown-bool-flag.log" 2>&1
if [ $? -eq 0 ]; then echo "[FAIL] snapshot with unknown --dirs exited 0, expected non-zero"; cat "$TMP/unknown-bool-flag.log"; exit 1; fi
grep -q "unknown flag: --dirs" "$TMP/unknown-bool-flag.log" \
  || { echo "[FAIL] unknown --dirs did not report 'unknown flag: --dirs'"; cat "$TMP/unknown-bool-flag.log"; exit 1; }
if [ -f "$TMP/unknown-bool.age" ]; then echo "[FAIL] snapshot with an unknown flag still wrote --out"; exit 1; fi
echo "[PASS] dist snapshot --dirs (typo for --dir, plural): rejected with 'unknown flag: --dirs', no --out written"

# a legitimate, fully-recognized flag set must still pass through untouched
node "$DIST" estimate --in "$CIPHER_BRAIN_HOME/recipient.txt" --backend file > "$TMP/known-flags.log" 2>&1 \
  || { echo "[FAIL] estimate with only recognized flags exited non-zero"; cat "$TMP/known-flags.log"; exit 1; }
echo "[PASS] dist estimate with only recognized flags: still exits 0 (no false-positive rejection)"

# (h) --version (#261): the BARE version on stdout, nothing else (so it can be
# captured straight into a variable), exit 0, and the SAME string from the
# bundled dist and the unbundled bin shim — the version is read out of
# package.json at runtime via a relative URL that has to resolve correctly from
# both layouts, so a regression there would silently split the two apart.
node "$DIST" --version > "$TMP/version-dist.txt" 2> "$TMP/version-dist.err" \
  || { echo "[FAIL] dist --version exited non-zero"; cat "$TMP/version-dist.err"; exit 1; }
# the path goes through argv, not string interpolation into the -p script, so a
# checkout directory containing a quote or a space cannot break the expression
PKG_VERSION="$(node -p "require(process.argv[1]).version" "$ROOT/package.json")"
if [ "$(cat "$TMP/version-dist.txt")" != "$PKG_VERSION" ]; then
  echo "[FAIL] dist --version printed '$(cat "$TMP/version-dist.txt")', expected the bare '$PKG_VERSION'"; exit 1
fi
node "${BIN_DEV_ARGS[@]}" "$BIN" --version > "$TMP/version-bin.txt" 2>&1 \
  || { echo "[FAIL] bin --version exited non-zero"; cat "$TMP/version-bin.txt"; exit 1; }
if ! diff -q "$TMP/version-bin.txt" "$TMP/version-dist.txt" >/dev/null; then
  echo "[FAIL] bin --version differs from dist --version"; diff "$TMP/version-bin.txt" "$TMP/version-dist.txt"; exit 1
fi
node "$DIST" -V > "$TMP/version-short.txt" 2>&1 \
  || { echo "[FAIL] dist -V exited non-zero"; cat "$TMP/version-short.txt"; exit 1; }
if ! diff -q "$TMP/version-short.txt" "$TMP/version-dist.txt" >/dev/null; then
  echo "[FAIL] -V differs from --version"; diff "$TMP/version-short.txt" "$TMP/version-dist.txt"; exit 1
fi
echo "[PASS] dist --version / -V: bare '$PKG_VERSION' on stdout, exit 0, identical from bin and dist"

# (i) <command> --help (#262): only that command's section, and the full
# reference is still what plain --help prints.
node "$DIST" verify --help > "$TMP/help-verify.txt" 2>/dev/null \
  || { echo "[FAIL] dist verify --help exited non-zero"; exit 1; }
grep -q "cipher-brain verify --in" "$TMP/help-verify.txt" \
  || { echo "[FAIL] 'verify --help' does not contain the verify section"; cat "$TMP/help-verify.txt"; exit 1; }
if grep -q "cipher-brain snapshot --out" "$TMP/help-verify.txt"; then
  echo "[FAIL] 'verify --help' still contains other commands' sections (whole help dumped)"; exit 1
fi
grep -q "^Env: CIPHER_BRAIN_HOME" "$TMP/help-verify.txt" \
  || { echo "[FAIL] 'verify --help' dropped the command-agnostic Env/Storage/Spend block"; exit 1; }
# an unknown command with --help falls back to the full reference rather than
# nothing. The baseline is re-captured HERE rather than reusing help-dist.txt
# from (a): HELP interpolates ${IDENTITY}, which (b) changed by exporting
# CIPHER_BRAIN_HOME, so the two would differ on that line alone.
node "$DIST" --help > "$TMP/help-full-now.txt" 2>&1 \
  || { echo "[FAIL] dist --help exited non-zero"; exit 1; }
node "$DIST" nosuchcommand --help > "$TMP/help-unknown.txt" 2>&1 \
  || { echo "[FAIL] dist nosuchcommand --help exited non-zero"; exit 1; }
if ! diff -q "$TMP/help-unknown.txt" "$TMP/help-full-now.txt" >/dev/null; then
  echo "[FAIL] unknown command + --help did not fall back to the full help"; exit 1
fi
echo "[PASS] dist <command> --help: scoped to that command, keeps the Env block, unknown command falls back to full help"

echo "CLI SMOKE: PASS"
