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

# #368 (WITH an ignore file present): the breakdown is added detail alongside the
# existing include/exclude report, not a replacement for it — the assertions above
# already proved the include/exclude report is unchanged; this proves the breakdown of
# what SURVIVED filtering is now there too, and its byte totals reconcile with the
# per-source total (#368 acceptance: "Byte totals in the breakdown reconcile with the
# existing per-source total"). $SRC's 3 included files are exact byte counts on purpose
# (a/keep.txt=6B, a/b/keep2.txt=6B, .cipherbrainignore=20B) so the shares below are
# clean percentages, not rounding artifacts.
echo "== --dry-run (#368): with .cipherbrainignore present, still reports the largest contributors =="
printf '%s' "$OUT" | grep -q "largest contributors" || { echo "[FAIL] with-ignore-file --dry-run missing the largest-contributors breakdown"; echo "$OUT"; exit 1; }
printf '%s' "$OUT" | grep -qE '\.cipherbrainignore +20 B \(62\.5% of this source\)' || { echo "[FAIL] .cipherbrainignore contributor line missing or wrong share"; echo "$OUT"; exit 1; }
printf '%s' "$OUT" | grep -qE '^    a/ +12 B \(37\.5% of this source\)' || { echo "[FAIL] aggregated a/ contributor line missing or wrong share"; echo "$OUT"; exit 1; }
echo "[PASS] --dry-run with an ignore file present still reports the largest contributors of what survived filtering"

# #368 acceptance: "snapshot --dry-run against a source with no .cipherbrainignore lists
# the largest contributors with their byte shares" — the branch this issue exists for. A
# --dir with no .cipherbrainignore used to print exactly ONE aggregate line and nothing
# else; this is the state nobody has audited yet, so it is the one that most needs the
# breakdown. Sizes below are exact byte counts (bigdir/a.bin=700B, bigdir/b.bin=200B,
# root.txt=100B) so the shares are clean percentages the assertions can pin exactly, and
# the reconciliation check below can sum contributor bytes back to the reported total
# without any KB/MB rounding ambiguity.
echo "== --dry-run (#368): NO .cipherbrainignore lists the largest contributors, dominant subtree first =="
CONTRIB="$TMP/contrib"
mkdir -p "$CONTRIB/bigdir"
head -c 700 /dev/urandom > "$CONTRIB/bigdir/a.bin"
head -c 200 /dev/urandom > "$CONTRIB/bigdir/b.bin"
head -c 100 /dev/urandom > "$CONTRIB/root.bin"
set +e
CONTRIB_OUT=$(cb snapshot --dir "$CONTRIB" --dry-run 2>&1); CONTRIB_RC=$?
set -e
[ "$CONTRIB_RC" = "0" ] || { echo "[FAIL] --dry-run (no ignore file, #368) exited non-zero"; echo "$CONTRIB_OUT"; exit 1; }
printf '%s' "$CONTRIB_OUT" | grep -q "no .cipherbrainignore — all 3 file(s) included (1000 B)" || { echo "[FAIL] unexpected no-ignore-file summary line"; echo "$CONTRIB_OUT"; exit 1; }
printf '%s' "$CONTRIB_OUT" | grep -q "largest contributors" || { echo "[FAIL] no-ignore-file --dry-run missing the largest-contributors breakdown"; echo "$CONTRIB_OUT"; exit 1; }
printf '%s' "$CONTRIB_OUT" | grep -qE '^    bigdir/ +900 B \(90\.0% of this source\)' || { echo "[FAIL] the dominant bigdir/ subtree is not reported first with the right share"; echo "$CONTRIB_OUT"; exit 1; }
printf '%s' "$CONTRIB_OUT" | grep -qE '^    root\.bin +100 B \(10\.0% of this source\)' || { echo "[FAIL] the small root.bin contributor is not reported with the right share"; echo "$CONTRIB_OUT"; exit 1; }
# reconciliation: the two contributor byte counts printed above must sum to EXACTLY the
# per-source total already reported in the (unchanged) summary line, not just look right.
BIGDIR_BYTES=$(printf '%s' "$CONTRIB_OUT" | grep -oE '^    bigdir/ +[0-9]+ B' | grep -oE '[0-9]+')
ROOT_BYTES=$(printf '%s' "$CONTRIB_OUT" | grep -oE '^    root\.bin +[0-9]+ B' | grep -oE '[0-9]+')
[ "$((BIGDIR_BYTES + ROOT_BYTES))" = "1000" ] || { echo "[FAIL] contributor bytes ($BIGDIR_BYTES + $ROOT_BYTES) do not reconcile with the reported 1000 B per-source total"; echo "$CONTRIB_OUT"; exit 1; }
echo "[PASS] no .cipherbrainignore --dry-run breaks down the largest contributors, dominant subtree first, bytes reconcile"

# #368 acceptance: "A source whose contents are one flat set of small files produces a
# sane, short report (no pathological output when there is no dominant path)" — every
# file sits directly at the root (no subdirectory to aggregate under), so each is its own
# bucket; the check is that the breakdown stays exactly as long as the file list (3 lines
# here, well under the top-10 cap) rather than ballooning or crashing.
echo "== --dry-run (#368): a flat set of small files produces a short, sane breakdown =="
FLAT="$TMP/flat368"
mkdir -p "$FLAT"
for i in 1 2 3; do printf 'x\n' > "$FLAT/file$i.txt"; done
set +e
FLAT_OUT=$(cb snapshot --dir "$FLAT" --dry-run 2>&1); FLAT_RC=$?
set -e
[ "$FLAT_RC" = "0" ] || { echo "[FAIL] --dry-run (flat small files, #368) exited non-zero"; echo "$FLAT_OUT"; exit 1; }
FLAT_LINES=$(printf '%s' "$FLAT_OUT" | grep -cE '^    file[0-9]\.txt  ')
[ "$FLAT_LINES" = "3" ] || { echo "[FAIL] flat-file breakdown printed $FLAT_LINES contributor line(s), expected exactly 3"; echo "$FLAT_OUT"; exit 1; }
echo "[PASS] a flat set of small files produces a short breakdown with no dominant path"

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

echo "== security: a --dir whose OWN basename looks like a tar option (e.g. '-C') cannot hijack the tar -T list =="
# Multi-model review (Codex) finding: the tar -T list file MUST be NUL-separated
# (--null), or its FIRST line (the bare --dir basename — every OTHER line is
# prefixed "<base>/<rel>" and so can never itself start with "-") is honored by
# tar as an option rather than a literal directory name. Verified by hand: with
# a --dir literally named "-C", the newline-only (pre-fix) list made tar consume
# the well-formed 2nd/3rd list lines as a "-C <dir>" directive's argument and
# then a path relative to THAT dir, producing "Cannot stat ...: No such file or
# directory" (rc=1) instead of a correct archive — a concrete, reproducible
# corruption/DoS from this exact injection class, not just a theoretical one.
# This exercises the real code path (a --dir WITH a .cipherbrainignore, so
# scanDir's -T/--null branch runs) with a --dir directory literally named "-C".
INJ="$TMP/-C"
mkdir -p "$INJ/sub"
printf 'keep\n' > "$INJ/sub/f.txt"
printf 'irrelevant\n' > "$INJ/.cipherbrainignore"     # any ignore file triggers the -T/--null branch
set +e
INJOUT=$(cb snapshot --dir "$INJ" --out "$TMP/inj.age" 2>&1); INJRC=$?
set -e
[ "$INJRC" = "0" ] || { echo "[FAIL][SECURITY] snapshot of a --dir named '-C' failed (tar -T option-injection via the bare basename line)"; echo "$INJOUT"; exit 1; }
cb restore --in "$TMP/inj.age" --out-dir "$TMP/inj-out" --no-expand-components >/dev/null
tar -tzf "$TMP/inj-out/-C.tar.gz" | sort > "$TMP/inj-list.txt"
grep -qx -- '-C/sub/f.txt' "$TMP/inj-list.txt" || { echo "[FAIL][SECURITY] a --dir literally named '-C' did not archive correctly (tar -T list injection via the bare basename line)"; cat "$TMP/inj-list.txt"; exit 1; }
tar -xzf "$TMP/inj-out/-C.tar.gz" -C "$TMP/inj-out"
[ "$(cat "$TMP/inj-out/-C/sub/f.txt")" = "keep" ] || { echo "[FAIL] content corrupted for a --dir named '-C'"; exit 1; }
echo "[PASS] a --dir literally named '-C' archives correctly — no tar -T option-injection via the bare basename line"

echo ""
echo "CIPHERBRAINIGNORE SELFTEST PASS"
