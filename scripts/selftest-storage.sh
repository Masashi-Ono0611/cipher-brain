#!/usr/bin/env bash
# Storage round-trip proof for the FILE backend (issue #2), daemon-free so CI can
# gate push/pull: snapshot -> push -> (delete original) -> pull -> verify -> restore.
# Asserts the locator is content-addressed (not the source path), the stored bytes
# match, the pulled bytes round-trip and decrypt, and an absent locator errors.
# The TON backend's real cross-node transfer is proven separately by an operator
# (scripts/ton-roundtrip.sh) — that needs a running storage-daemon.
set -euo pipefail

BIN="$(cd "$(dirname "$0")/.." && pwd)/bin/cipher-brain.mjs"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
export CIPHER_BRAIN_HOME="$TMP/keys"
export CIPHER_BRAIN_FILE_DIR="$TMP/store"
cb() { node "$BIN" "$@"; }
sha() { shasum -a 256 "$1" | cut -d' ' -f1; }

MARKER="secret-thought-$(od -An -N6 -tx1 /dev/urandom | tr -d ' ')"
SRC="$TMP/brain-src"; mkdir -p "$SRC"
printf '%s\n' "$MARKER" > "$SRC/note.txt"
head -c 524288 /dev/urandom > "$SRC/blob.bin"

echo "== snapshot =="
cb keygen >/dev/null
cb snapshot --dir "$SRC" --out "$TMP/snap.age"
ORIG=$(sha "$TMP/snap.age")

echo "== push (file backend) =="
LOC=$(cb push --in "$TMP/snap.age" --backend file)
[ "$LOC" != "$TMP/snap.age" ] && echo "[PASS] locator != source path" || { echo "[FAIL] locator == source"; exit 1; }
case "$LOC" in "$CIPHER_BRAIN_FILE_DIR"/*) echo "[PASS] object lives in the store";; *) echo "[FAIL] not in store: $LOC"; exit 1;; esac
[ "$(sha "$LOC")" = "$ORIG" ] && echo "[PASS] stored bytes == source" || { echo "[FAIL] store byte mismatch"; exit 1; }

echo "== pull (after deleting the original, so it MUST come from the store) =="
rm -f "$TMP/snap.age"
cb pull --locator "$LOC" --backend file --out "$TMP/got.age"
[ "$(sha "$TMP/got.age")" = "$ORIG" ] && echo "[PASS] pulled bytes == original" || { echo "[FAIL] pulled byte mismatch"; exit 1; }

echo "== verify + decrypt the pulled ciphertext =="
cb verify --in "$TMP/got.age" | grep -q "VERDICT: PASS" && echo "[PASS] verify VERDICT PASS on pulled" || { echo "[FAIL] verify"; exit 1; }
cb restore --in "$TMP/got.age" --out-dir "$TMP/out"
tar -xzf "$TMP/out/brain-src.tar.gz" -C "$TMP/out"
diff -r "$SRC" "$TMP/out/brain-src"
echo "[PASS] decrypt + restore byte-identical to source"

echo "== pull --sha256: correct hash passes, wrong hash fail-closes (deletes --out) =="
cb pull --locator "$LOC" --backend file --out "$TMP/got-ok.age" --sha256 "$ORIG"
[ "$(sha "$TMP/got-ok.age")" = "$ORIG" ] && echo "[PASS] pull --sha256 (correct) kept the bytes" || { echo "[FAIL] correct --sha256 rejected"; exit 1; }
WRONG="0000000000000000000000000000000000000000000000000000000000000000"
if cb pull --locator "$LOC" --backend file --out "$TMP/got-bad.age" --sha256 "$WRONG" 2>/dev/null; then
  echo "[FAIL] pull --sha256 accepted a mismatching hash"; exit 1
fi
test ! -f "$TMP/got-bad.age"   # fail-closed: the bad artifact must not be left at --out
echo "[PASS] pull --sha256 (wrong) errored and deleted --out"

echo "== negative control: an absent locator must fail =="
if cb pull --locator "$CIPHER_BRAIN_FILE_DIR/deadbeef.age" --backend file --out "$TMP/no.age" 2>/dev/null; then
  echo "[FAIL] absent locator returned bytes"; exit 1
fi
echo "[PASS] absent locator errors"

echo "== backend is required (no silent default) =="
if cb push --in "$TMP/got.age" 2>/dev/null; then echo "[FAIL] push ran with no --backend"; exit 1; fi
echo "[PASS] push without --backend is rejected"

# ── same-hash skip (#70): the skip signal is the PLAINTEXT content digest sidecar ──
# (age ciphertext hashes differ every run — ephemeral file key — so only the
# plaintext-side digest can say "unchanged").

echo "== digest sidecar: mtime-independent, content-sensitive =="
SRC2="$TMP/skip-src"; mkdir -p "$SRC2"
printf 'alpha\n' > "$SRC2/a.txt"
printf 'beta\n'  > "$SRC2/b.txt"
cb snapshot --dir "$SRC2" --out "$TMP/s1.age"
[ -f "$TMP/s1.age.digest" ] || { echo "[FAIL] no digest sidecar next to s1.age"; exit 1; }
D1=$(cat "$TMP/s1.age.digest")
# unchanged content, but every mtime moved — the digest must not move with it
touch -t 202001010101 "$SRC2/a.txt" "$SRC2/b.txt" "$SRC2"
cb snapshot --dir "$SRC2" --out "$TMP/s2.age"
D2=$(cat "$TMP/s2.age.digest")
[ "$D1" = "$D2" ] || { echo "[FAIL] digest changed on an mtime-only change: $D1 vs $D2"; exit 1; }
echo "[PASS] unchanged content (mtimes touched) -> identical digest"
printf 'Alpha\n' > "$SRC2/a.txt"   # one changed byte
cb snapshot --dir "$SRC2" --out "$TMP/s3.age"
D3=$(cat "$TMP/s3.age.digest")
[ "$D1" != "$D3" ] || { echo "[FAIL] digest identical after a one-byte content change"; exit 1; }
echo "[PASS] one changed byte -> different digest"

echo "== #70 review fix 1: content_digest reflects the ARCHIVED bytes, not a stale independent pre-tar read =="
# Race-style repro: mutate the source WHILE snapshot is (possibly) still tar/gzip-ing
# it. Big + incompressible so the archive step takes measurable wall-clock time,
# widening the window. The assertion below must hold no matter which content wins
# the race -- it directly checks the invariant fix 1 provides: the digest can never
# describe content other than what actually got archived (previously the digest was
# a SEPARATE, independent walk of the live source taken BEFORE tar read it).
SRC4="$TMP/race-src"; mkdir -p "$SRC4"
head -c 8000000 /dev/urandom > "$SRC4/big.bin"
cb snapshot --dir "$SRC4" --out "$TMP/race.age" &
SNAP_PID=$!
sleep 0.05
head -c 8000000 /dev/urandom > "$SRC4/big.bin"   # mutate mid-flight
wait "$SNAP_PID"
[ -f "$TMP/race.age.digest" ] || { echo "[FAIL] no digest sidecar for the race snapshot"; exit 1; }
cb restore --in "$TMP/race.age" --out-dir "$TMP/race-restored" >/dev/null
tar -xzf "$TMP/race-restored/race-src.tar.gz" -C "$TMP/race-restored"
# the per-COMPONENT content_digest (manifest.json, what fix 1 computes) must match a
# recomputation from what was ACTUALLY archived (the restored/extracted bytes) --
# exactly, regardless of which content won the race.
COMPONENT_DIGEST=$(node -e "console.log(JSON.parse(require('node:fs').readFileSync('$TMP/race-restored/manifest.json','utf8')).components[0].content_digest)")
BIG_SHA=$(sha "$TMP/race-restored/race-src/big.bin")
BIG_SIZE=$(wc -c < "$TMP/race-restored/race-src/big.bin" | tr -d ' ')
EXPECTED=$(printf 'big.bin\tf\t%s\t%s\n' "$BIG_SHA" "$BIG_SIZE" | shasum -a 256 | cut -d' ' -f1)
[ "$COMPONENT_DIGEST" = "$EXPECTED" ] || { echo "[FAIL] component digest does not match a recomputation from the archived bytes: $COMPONENT_DIGEST vs $EXPECTED"; exit 1; }
echo "[PASS] component digest matches the archived bytes exactly, even with a source mutation racing the tar read"

echo "== #70 review fix 2: a top-level symlinked --dir source hashes the LINK's identity, not its target's content =="
# tar archives an explicit symlink argument AS the link (not dereferenced) -- same
# class of bug profiles.mjs's realpath-dereference comment fixes for --vault/--zip.
# Swapping the target to a DIFFERENT path, even one with byte-identical content,
# must change the digest: the archived representation (a symlink recording that
# target) changed, even though a naive content-follow would see no difference.
mkdir -p "$TMP/symtargetA" "$TMP/symtargetB"
printf 'identical content\n' > "$TMP/symtargetA/f.txt"
printf 'identical content\n' > "$TMP/symtargetB/f.txt"
ln -s "$TMP/symtargetA" "$TMP/symlinked-dir"
cb snapshot --dir "$TMP/symlinked-dir" --out "$TMP/sym1.age"
[ -f "$TMP/sym1.age.digest" ] || { echo "[FAIL] no digest sidecar for the symlinked --dir snapshot"; exit 1; }
SYM_D1=$(cat "$TMP/sym1.age.digest")
rm -f "$TMP/symlinked-dir"
ln -s "$TMP/symtargetB" "$TMP/symlinked-dir"   # same link name, byte-identical target content, DIFFERENT target path
cb snapshot --dir "$TMP/symlinked-dir" --out "$TMP/sym2.age"
SYM_D2=$(cat "$TMP/sym2.age.digest")
[ "$SYM_D1" != "$SYM_D2" ] || { echo "[FAIL] digest unchanged after swapping the symlink's target (byte-identical content masked a real archived-representation change)"; exit 1; }
echo "[PASS] swapping a top-level symlink's target changes the digest, even though the pointed-to content is byte-identical"

echo "== #70 review fix 3: identical bytes under a DIFFERENT declared --dir path/name change the combined digest =="
# Renaming/moving a --dir source with byte-identical content must not look
# "unchanged": the restored manifest/archive still labels things under the OLD
# name/path, so --skip-unchanged returning the old locator would be a correctness
# violation, not an optimization.
mkdir -p "$TMP/named-a" "$TMP/named-b"
printf 'identical bytes\n' > "$TMP/named-a/f.txt"
printf 'identical bytes\n' > "$TMP/named-b/f.txt"
cb snapshot --dir "$TMP/named-a" --out "$TMP/id1.age"
D_ID1=$(cat "$TMP/id1.age.digest")
cb snapshot --dir "$TMP/named-b" --out "$TMP/id2.age"
D_ID2=$(cat "$TMP/id2.age.digest")
[ "$D_ID1" != "$D_ID2" ] || { echo "[FAIL] identically-byted components under different declared names produced the SAME digest"; exit 1; }
echo "[PASS] same bytes, different declared --dir name -> different digest"
IDLOCFILE="$TMP/identity-locator.tsv"
cb push --in "$TMP/id1.age" --backend file --save-locator "$IDLOCFILE" >/dev/null
cb push --in "$TMP/id2.age" --backend file --save-locator "$IDLOCFILE" --skip-unchanged 2>"$TMP/id.err" >/dev/null
if grep -q "SKIPPED" "$TMP/id.err"; then echo "[FAIL] --skip-unchanged skipped a differently-named/sourced component with identical bytes"; exit 1; fi
echo "[PASS] --skip-unchanged does not skip when the declared source/name differs (even with identical bytes)"

echo "== push --save-locator writes the 4-field line (locator/backend/sha256/content_digest) =="
LOCFILE="$TMP/latest-locator.tsv"
LOC1=$(cb push --in "$TMP/s1.age" --backend file --save-locator "$LOCFILE")
NF=$(awk -F'\t' 'NR==1{print NF}' "$LOCFILE")
[ "$NF" = "4" ] || { echo "[FAIL] save-locator line has $NF fields, want 4"; exit 1; }
[ "$(cut -f4 "$LOCFILE")" = "$D1" ] || { echo "[FAIL] 4th field != sidecar digest"; exit 1; }
echo "[PASS] save-locator line has 4 fields; 4th == the content digest"

echo "== push #2 (unchanged content) --skip-unchanged: SKIPs, previous locator, exit 0, no new object =="
COUNT_BEFORE=$(ls "$CIPHER_BRAIN_FILE_DIR" | wc -l | tr -d ' ')
OUT2=$(cb push --in "$TMP/s2.age" --backend file --save-locator "$LOCFILE" --skip-unchanged 2>"$TMP/skip.err")
grep -q "SKIPPED" "$TMP/skip.err" || { echo "[FAIL] no SKIPPED line on stderr"; cat "$TMP/skip.err"; exit 1; }
[ "$OUT2" = "$LOC1" ] || { echo "[FAIL] skip did not print the previous locator: $OUT2"; exit 1; }
COUNT_AFTER=$(ls "$CIPHER_BRAIN_FILE_DIR" | wc -l | tr -d ' ')
[ "$COUNT_BEFORE" = "$COUNT_AFTER" ] || { echo "[FAIL] the store gained an object on a skipped push"; exit 1; }
echo "[PASS] unchanged push skipped: SKIPPED line, previous locator on stdout, store untouched"

echo "== --force pushes anyway =="
LOC_F=$(cb push --in "$TMP/s2.age" --backend file --save-locator "$LOCFILE" --skip-unchanged --force)
[ "$LOC_F" != "$LOC1" ] || { echo "[FAIL] --force returned the old locator"; exit 1; }
COUNT_FORCE=$(ls "$CIPHER_BRAIN_FILE_DIR" | wc -l | tr -d ' ')
[ "$COUNT_FORCE" = "$((COUNT_AFTER + 1))" ] || { echo "[FAIL] --force did not add a store object"; exit 1; }
echo "[PASS] --force uploaded despite an identical content digest"

echo "== legacy 3-field save-locator: pull still works AND --skip-unchanged does not skip =="
LEGACY="$TMP/legacy-locator.tsv"
printf '%s\t%s\t%s\n' "$LOC1" file "$(sha "$TMP/s1.age")" > "$LEGACY"
cb pull --from-locator-file "$LEGACY" --out "$TMP/legacy-got.age"
[ "$(sha "$TMP/legacy-got.age")" = "$(sha "$TMP/s1.age")" ] || { echo "[FAIL] legacy 3-field pull bytes mismatch"; exit 1; }
echo "[PASS] pull --from-locator-file accepts a legacy 3-field line (recovery unbroken)"
cb push --in "$TMP/s2.age" --backend file --save-locator "$LEGACY" --skip-unchanged >"$TMP/legacy.out" 2>"$TMP/legacy.err"
if grep -q "SKIPPED" "$TMP/legacy.err"; then echo "[FAIL] skipped off a legacy 3-field line (no digest to compare)"; exit 1; fi
NF_LEGACY=$(awk -F'\t' 'NR==1{print NF}' "$LEGACY")
[ "$NF_LEGACY" = "4" ] || { echo "[FAIL] proceeding push did not upgrade the legacy file to 4 fields"; exit 1; }
echo "[PASS] legacy 3-field line: push proceeded (no skip) and rewrote a 4-field line"

echo "== changed content with --skip-unchanged: proceeds and rewrites the 4-field line =="
COUNT_E=$(ls "$CIPHER_BRAIN_FILE_DIR" | wc -l | tr -d ' ')
cb push --in "$TMP/s3.age" --backend file --save-locator "$LOCFILE" --skip-unchanged >"$TMP/e.out" 2>"$TMP/e.err"
if grep -q "SKIPPED" "$TMP/e.err"; then echo "[FAIL] changed content was skipped"; exit 1; fi
COUNT_E2=$(ls "$CIPHER_BRAIN_FILE_DIR" | wc -l | tr -d ' ')
[ "$COUNT_E2" = "$((COUNT_E + 1))" ] || { echo "[FAIL] changed-content push added no store object"; exit 1; }
[ "$(cut -f4 "$LOCFILE")" = "$D3" ] || { echo "[FAIL] save-locator 4th field was not rewritten to the new digest"; exit 1; }
echo "[PASS] changed content pushed; save-locator now carries the new digest"

echo "== --skip-unchanged without a sidecar: proceeds (skip is an optimization, never a gate) =="
cp "$TMP/s2.age" "$TMP/nosidecar.age"   # same content digest as LOC1's, but NO sidecar next to it
cb push --in "$TMP/nosidecar.age" --backend file --save-locator "$LOCFILE" --skip-unchanged >"$TMP/ns.out" 2>"$TMP/ns.err"
if grep -q "SKIPPED" "$TMP/ns.err"; then echo "[FAIL] skipped without any digest source"; exit 1; fi
echo "[PASS] no sidecar and no --digest -> pushed normally"

echo "== --skip-unchanged requires --save-locator =="
if cb push --in "$TMP/s2.age" --backend file --skip-unchanged 2>/dev/null; then
  echo "[FAIL] --skip-unchanged ran without --save-locator"; exit 1
fi
echo "[PASS] --skip-unchanged without --save-locator is rejected"

echo
echo "STORAGE SELFTEST (file backend) PASS"
