#!/usr/bin/env bash
# Round-trip proof for .cipherbrainignore (issue #216): a gitignore-compatible file at
# the root of a --dir (or a --profile-resolved directory) filters what tar actually
# archives from that directory — node_modules/, caches, .git/ etc no longer need to be
# staged, encrypted, or (on a paid backend) permanently stored. Matching is delegated to
# the `ignore` npm package. No .cipherbrainignore present must behave EXACTLY as before
# (every path archived) — the whole point of an additive, backward-compatible filter.
# Also exercises `snapshot --dry-run`, which previews the same filtering without
# staging/encrypting/writing anything. Synthetic fixtures only — no real user data, no
# Postgres, no network.
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

echo "== keygen =="
cb keygen >/dev/null

echo "== control: a --dir with NO .cipherbrainignore archives everything, exactly as before =="
PLAIN="$TMP/plain"
mkdir -p "$PLAIN/x"
printf 'hi\n' > "$PLAIN/x/f.txt"
cb snapshot --dir "$PLAIN" --out "$TMP/plain.age" >/dev/null 2>&1
cb restore --in "$TMP/plain.age" --out-dir "$TMP/plain-out" --no-expand-components >/dev/null
tar -tzf "$TMP/plain-out/plain.tar.gz" | sort > "$TMP/plain-list.txt"
grep -qx 'plain/' "$TMP/plain-list.txt" || { echo "[FAIL] control archive missing top dir entry"; cat "$TMP/plain-list.txt"; exit 1; }
grep -qx 'plain/x/f.txt' "$TMP/plain-list.txt" || { echo "[FAIL] control archive missing nested file"; cat "$TMP/plain-list.txt"; exit 1; }
grep -q '"cipherbrainignore"' "$TMP/plain-out/manifest.json" && { echo "[FAIL] manifest records cipherbrainignore when no ignore file was present"; exit 1; }
echo "[PASS] no .cipherbrainignore -> unchanged archive contents, no manifest field"

echo "== .cipherbrainignore excludes node_modules/ and .git/, keeps everything else =="
SRC="$TMP/brain"
mkdir -p "$SRC/a/b" "$SRC/node_modules/pkg" "$SRC/.git"
printf 'keep1\n' > "$SRC/a/keep.txt"
printf 'keep2\n' > "$SRC/a/b/keep2.txt"
head -c 4096 /dev/urandom > "$SRC/node_modules/pkg/file.bin"
printf 'gitstuff\n' > "$SRC/.git/HEAD"
cat > "$SRC/.cipherbrainignore" <<'EOF'
node_modules/
.git/
EOF
cb snapshot --dir "$SRC" --out "$TMP/snap.age" >/dev/null 2>&1
cb restore --in "$TMP/snap.age" --out-dir "$TMP/out" --no-expand-components >/dev/null
tar -tzf "$TMP/out/brain.tar.gz" | sort > "$TMP/list.txt"
grep -q 'node_modules' "$TMP/list.txt" && { echo "[FAIL] node_modules leaked into the archive"; cat "$TMP/list.txt"; exit 1; }
grep -q '\.git' "$TMP/list.txt" && { echo "[FAIL] .git leaked into the archive"; cat "$TMP/list.txt"; exit 1; }
grep -qx 'brain/a/keep.txt' "$TMP/list.txt" || { echo "[FAIL] included file a/keep.txt missing"; cat "$TMP/list.txt"; exit 1; }
grep -qx 'brain/a/b/keep2.txt' "$TMP/list.txt" || { echo "[FAIL] included file a/b/keep2.txt missing"; cat "$TMP/list.txt"; exit 1; }
grep -qx 'brain/.cipherbrainignore' "$TMP/list.txt" || { echo "[FAIL] .cipherbrainignore itself missing from archive"; cat "$TMP/list.txt"; exit 1; }
echo "[PASS] node_modules/ and .git/ excluded; every other file still archived"

echo "== manifest records cipherbrainignore: true and the right excluded_count =="
grep -q '"cipherbrainignore": true' "$TMP/out/manifest.json" || { echo "[FAIL] manifest missing cipherbrainignore: true"; cat "$TMP/out/manifest.json"; exit 1; }
grep -q '"excluded_count": 2' "$TMP/out/manifest.json" || { echo "[FAIL] manifest excluded_count is not 2 (node_modules/ + .git/)"; cat "$TMP/out/manifest.json"; exit 1; }
echo "[PASS] manifest carries cipherbrainignore provenance (applied + excluded_count)"

echo "== plaintext leak check: excluded content never appears in the ciphertext =="
if LC_ALL=C grep -a -q "gitstuff" "$TMP/snap.age"; then
  echo "[FAIL] excluded .git content leaked into ciphertext"; exit 1
fi
echo "[PASS] excluded content absent from ciphertext"

echo "== negation (!pattern) re-includes a file under an otherwise-matched glob =="
NEG="$TMP/negation"
mkdir -p "$NEG/logs"
printf 'noisy\n' > "$NEG/logs/app.log"
printf 'keep-this\n' > "$NEG/logs/important.log"
cat > "$NEG/.cipherbrainignore" <<'EOF'
logs/*
!logs/important.log
EOF
cb snapshot --dir "$NEG" --out "$TMP/neg.age" >/dev/null 2>&1
cb restore --in "$TMP/neg.age" --out-dir "$TMP/neg-out" --no-expand-components >/dev/null
tar -tzf "$TMP/neg-out/negation.tar.gz" | sort > "$TMP/neg-list.txt"
grep -qx 'negation/logs/important.log' "$TMP/neg-list.txt" || { echo "[FAIL] negated file important.log was excluded"; cat "$TMP/neg-list.txt"; exit 1; }
grep -q 'negation/logs/app.log' "$TMP/neg-list.txt" && { echo "[FAIL] app.log should have been excluded by logs/*"; cat "$TMP/neg-list.txt"; exit 1; }
echo "[PASS] !negation pattern re-includes a specific file excluded by a broader glob"

echo "== --dry-run: previews include/exclude without --out, staging, or writing anything =="
set +e
OUT=$(cb snapshot --dir "$SRC" --dry-run 2>&1); RC=$?
set -e
[ "$RC" = "0" ] || { echo "[FAIL] --dry-run exited non-zero"; echo "$OUT"; exit 1; }
printf '%s' "$OUT" | grep -q "DRY RUN" || { echo "[FAIL] --dry-run output missing DRY RUN banner"; echo "$OUT"; exit 1; }
printf '%s' "$OUT" | grep -q "3 file(s) included" || { echo "[FAIL] --dry-run did not report 3 included files"; echo "$OUT"; exit 1; }
printf '%s' "$OUT" | grep -q "2 path(s) excluded" || { echo "[FAIL] --dry-run did not report 2 excluded paths"; echo "$OUT"; exit 1; }
printf '%s' "$OUT" | grep -q "node_modules/" || { echo "[FAIL] --dry-run exclude list missing node_modules/"; echo "$OUT"; exit 1; }
printf '%s' "$OUT" | grep -q '\.git/' || { echo "[FAIL] --dry-run exclude list missing .git/"; echo "$OUT"; exit 1; }
test ! -f "$TMP/dry-run-should-not-exist.age"
echo "[PASS] --dry-run reports accurate include/exclude counts, no --out required"

echo "== --dry-run never stages, encrypts, or contacts pg_dump (an unreachable --pg is fine) =="
set +e
OUT=$(cb snapshot --pg "postgres://nouser:nopass@127.0.0.1:1/does-not-exist" --dir "$PLAIN" --dry-run 2>&1); RC=$?
set -e
[ "$RC" = "0" ] || { echo "[FAIL] --dry-run with an unreachable --pg still failed (pg_dump must not run in --dry-run)"; echo "$OUT"; exit 1; }
printf '%s' "$OUT" | grep -q "not dumped in --dry-run" || { echo "[FAIL] --dry-run pg note missing"; echo "$OUT"; exit 1; }
printf '%s' "$OUT" | grep -q "nopass" && { echo "[FAIL] --dry-run leaked the pg password into its own output"; exit 1; }
echo "[PASS] --dry-run never touches pg_dump and redacts the connection string it prints"

echo "== --dry-run on a single-file --dir source: not filterable, no crash =="
SINGLE="$TMP/single.txt"; printf 'hello\n' > "$SINGLE"
OUT=$(cb snapshot --dir "$SINGLE" --dry-run 2>&1)
printf '%s' "$OUT" | grep -q "not filterable by .cipherbrainignore" || { echo "[FAIL] single-file --dry-run missing not-filterable note"; echo "$OUT"; exit 1; }
echo "[PASS] --dry-run handles a single-file --dir source without error"

echo "== --dry-run on a symlink --dir source: archived as-is, no crash =="
REALDIR="$TMP/realdir"; mkdir -p "$REALDIR"; printf 'x\n' > "$REALDIR/a.txt"
LINKDIR="$TMP/linkdir"; ln -s "$REALDIR" "$LINKDIR"
OUT=$(cb snapshot --dir "$LINKDIR" --dry-run 2>&1)
printf '%s' "$OUT" | grep -q "symlink source" || { echo "[FAIL] symlink --dry-run missing symlink note"; echo "$OUT"; exit 1; }
echo "[PASS] --dry-run handles a symlink --dir source without error"

echo ""
echo "CIPHERBRAINIGNORE SELFTEST PASS"
