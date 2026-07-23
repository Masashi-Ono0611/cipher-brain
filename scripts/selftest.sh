#!/usr/bin/env bash
# Local round-trip proof for the cipher layer (issue #1): keygen -> snapshot ->
# verify -> restore, asserting the plaintext is recovered AND the ciphertext
# leaks nothing. No Postgres and no network — exercises the crypto + CLI plumbing
# on a synthetic "brain" directory. The real-data (pg_dump) run happens on the
# machine that holds gbrain.
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

MARKER="secret-thought-$(od -An -N6 -tx1 /dev/urandom | tr -d ' ')"
SRC="$TMP/brain-src"
mkdir -p "$SRC"
printf '%s\n' "$MARKER" > "$SRC/note.txt"
head -c 1048576 /dev/urandom > "$SRC/blob.bin"   # 1 MB binary, to exercise streaming

echo "== keygen =="
cb keygen >/dev/null
test -f "$CIPHER_BRAIN_HOME/identity.age"
test -f "$CIPHER_BRAIN_HOME/recipient.txt"

echo "== snapshot =="
cb snapshot --dir "$SRC" --out "$TMP/snap.age"

echo "== verify =="
cb verify --in "$TMP/snap.age"

echo "== verify --sha256: correct hash PASSes, wrong hash FAILs =="
SNAPSHA=$(shasum -a 256 "$TMP/snap.age" | cut -d' ' -f1)
cb verify --in "$TMP/snap.age" --sha256 "$SNAPSHA" | grep -q "VERDICT: PASS" \
  && echo "[PASS] verify --sha256 (correct) is PASS" || { echo "FAIL: correct --sha256 not PASS"; exit 1; }
set +e
OUT=$(cb verify --in "$TMP/snap.age" --sha256 "deadbeef" 2>&1); RC=$?
set -e
if [ "$RC" = "0" ]; then echo "FAIL: verify --sha256 (wrong) exited 0"; echo "$OUT"; exit 1; fi
printf '%s' "$OUT" | grep -q "VERDICT: FAIL" || { echo "FAIL: wrong --sha256 not VERDICT FAIL"; echo "$OUT"; exit 1; }
echo "[PASS] verify --sha256 (wrong) is FAIL/non-zero"

echo "== ciphertext must not leak plaintext =="
if LC_ALL=C grep -a -q "$MARKER" "$TMP/snap.age"; then
  echo "FAIL: plaintext marker found in ciphertext"; exit 1
fi
echo "[PASS] marker absent from ciphertext"

echo "== no-clobber: snapshot refuses to overwrite an existing --out =="
set +e
OUT=$(cb snapshot --dir "$SRC" --out "$TMP/snap.age" 2>&1); RC=$?   # snap.age already exists
set -e
if [ "$RC" = "0" ]; then echo "FAIL: snapshot overwrote an existing --out"; exit 1; fi
printf '%s' "$OUT" | grep -q "already exists" || { echo "FAIL: wrong error for existing --out"; echo "$OUT"; exit 1; }
echo "[PASS] snapshot refused to overwrite an existing snapshot"

echo "== issue #109: snapshot auto-creates a missing --out parent directory =="
NESTED_OUT="$TMP/nested/does/not/exist/yet/new.age"
cb snapshot --dir "$SRC" --out "$NESTED_OUT"
test -f "$NESTED_OUT" || { echo "FAIL: snapshot did not write to the auto-created nested --out path"; exit 1; }
cb verify --in "$NESTED_OUT" | grep -q "VERDICT: PASS" || { echo "FAIL: snapshot at an auto-created nested --out did not verify"; exit 1; }
echo "[PASS] snapshot auto-created the missing --out parent directory chain"

echo "== issue #109: a bad --out parent path (an ancestor component is a FILE, not a dir) is rejected, nothing written =="
BADPARENT="$TMP/blocking-file"; printf 'not a directory\n' > "$BADPARENT"
BADOUT="$BADPARENT/sub/out.age"
if cb snapshot --dir "$SRC" --out "$BADOUT" 2>/dev/null; then
  echo "FAIL: snapshot succeeded despite a bad --out parent path (an ancestor is a plain file)"; exit 1
fi
test ! -e "$BADOUT"   # nothing was ever written under the bad path
echo "[PASS] a bad --out parent path (ancestor is a file) is rejected, nothing written"

echo "== restore + compare =="
cb restore --in "$TMP/snap.age" --out-dir "$TMP/out"
tar -xzf "$TMP/out/brain-src.tar.gz" -C "$TMP/out"
diff -r "$SRC" "$TMP/out/brain-src"
echo "[PASS] restored tree is byte-identical to source"

echo "== #181: restore auto-expands the component into out-dir/expanded/, keyed to its source path =="
# tar archives a --dir source as "-C $(dirname abs) -- $(basename abs)", so the expanded
# dir contains a basename(abs)-named subdirectory holding the actual tree (same shape as
# the manual `tar -xzf brain-src.tar.gz -C "$TMP/out"` two lines above, which is why THAT
# diff compares against "$TMP/out/brain-src", not "$TMP/out" itself).
EXPANDED_SRC_DIR="$TMP/out/expanded/001-$(printf '%s' "$SRC" | sed -E -e 's#^/+##' -e 's#[^A-Za-z0-9._-]+#_#g')"
diff -r "$SRC" "$EXPANDED_SRC_DIR/$(basename "$SRC")" || { echo "FAIL: expanded/ tree differs from source"; ls -la "$TMP/out/expanded"; exit 1; }
test -f "$TMP/out/expanded/README.txt" || { echo "FAIL: expanded/README.txt was not written"; exit 1; }
grep -q "$SRC" "$TMP/out/expanded/README.txt" || { echo "FAIL: expanded/README.txt does not reference the source path"; cat "$TMP/out/expanded/README.txt"; exit 1; }
echo "[PASS] restore auto-expanded the single component under expanded/<001-source>/, with a README mapping it back to the source path"

echo "== #181 regression: colliding-basename --dir sources expand into SEPARATE, correctly-keyed directories =="
# The motivating repro from issue #181: multiple --dir sources sharing a basename (e.g.
# many claude-code project memory/ dirs) restore to opaque names (memory.tar.gz,
# memory-1.tar.gz, ...) that alone don't say which project is which. Two directories
# literally both named "memory" (different parents) reproduce this exactly.
COLLIDE_A="$TMP/collide-project-a/memory"; mkdir -p "$COLLIDE_A"
COLLIDE_B="$TMP/collide-project-b/memory"; mkdir -p "$COLLIDE_B"
printf 'alpha project memory content\n' > "$COLLIDE_A/note.txt"
printf 'beta project memory content\n' > "$COLLIDE_B/note.txt"
cb snapshot --dir "$COLLIDE_A" --dir "$COLLIDE_B" --out "$TMP/collide.age" >/dev/null
EXP_OUT="$TMP/collide-restore"
cb restore --in "$TMP/collide.age" --out-dir "$EXP_OUT" > "$TMP/collide-restore.log"
test -f "$EXP_OUT/memory.tar.gz" || { echo "FAIL: expected raw memory.tar.gz in --out-dir"; ls "$EXP_OUT"; exit 1; }
test -f "$EXP_OUT/memory-1.tar.gz" || { echo "FAIL: expected raw memory-1.tar.gz (colliding basename) in --out-dir"; ls "$EXP_OUT"; exit 1; }
test -f "$EXP_OUT/expanded/README.txt" || { echo "FAIL: expected expanded/README.txt"; exit 1; }
EXPANDED_DIR_COUNT=$(find "$EXP_OUT/expanded" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')
[ "$EXPANDED_DIR_COUNT" = "2" ] || { echo "FAIL: expected 2 expanded component dirs, got $EXPANDED_DIR_COUNT"; ls "$EXP_OUT/expanded"; exit 1; }
grep -rq 'alpha project memory content' "$EXP_OUT/expanded" || { echo "FAIL: alpha content missing from expanded/"; exit 1; }
grep -rq 'beta project memory content' "$EXP_OUT/expanded" || { echo "FAIL: beta content missing from expanded/"; exit 1; }
ALPHA_DIR=$(dirname "$(grep -rl 'alpha project memory content' "$EXP_OUT/expanded" | head -1)")
BETA_DIR=$(dirname "$(grep -rl 'beta project memory content' "$EXP_OUT/expanded" | head -1)")
[ "$ALPHA_DIR" != "$BETA_DIR" ] || { echo "FAIL: alpha and beta content ended up in the SAME expanded dir"; exit 1; }
grep -q "collide-project-a" "$EXP_OUT/expanded/README.txt" || { echo "FAIL: README.txt does not reference collide-project-a's source path"; cat "$EXP_OUT/expanded/README.txt"; exit 1; }
grep -q "collide-project-b" "$EXP_OUT/expanded/README.txt" || { echo "FAIL: README.txt does not reference collide-project-b's source path"; cat "$EXP_OUT/expanded/README.txt"; exit 1; }
grep -q "expanded" "$TMP/collide-restore.log" || { echo "FAIL: restore's own stdout did not summarize the expand step"; cat "$TMP/collide-restore.log"; exit 1; }
echo "[PASS] two colliding-basename --dir sources restore into separate expanded/<NNN>-<source>/ dirs with the right content in each"

echo "== #181: --no-expand-components opts out, leaving only the raw *.tar.gz files =="
cb restore --in "$TMP/collide.age" --out-dir "$TMP/collide-noexpand" --no-expand-components >/dev/null
test ! -d "$TMP/collide-noexpand/expanded" || { echo "FAIL: --no-expand-components still created expanded/"; exit 1; }
test -f "$TMP/collide-noexpand/memory.tar.gz" && test -f "$TMP/collide-noexpand/memory-1.tar.gz" \
  || { echo "FAIL: --no-expand-components should still leave the raw component tarballs"; exit 1; }
echo "[PASS] --no-expand-components opts out of auto-expansion, leaving only the raw component tarballs"

echo "== #181: re-running restore into an out-dir with an existing expansion does not clobber it =="
SENTINEL_EXP="ALREADY-EXPANDED-DO-NOT-CLOBBER-$(od -An -N4 -tx1 /dev/urandom | tr -d ' ')"
printf '%s\n' "$SENTINEL_EXP" > "$ALPHA_DIR/note.txt"
cb restore --in "$TMP/collide.age" --out-dir "$EXP_OUT" >/dev/null
[ "$(cat "$ALPHA_DIR/note.txt")" = "$SENTINEL_EXP" ] || { echo "FAIL: re-running restore into the same --out-dir clobbered a previously-expanded file"; exit 1; }
echo "[PASS] re-running restore into an out-dir with an existing expansion does not clobber it"

echo "== #181 hardening: a forged manifest component 'name' containing a path separator is refused, not followed (path-traversal guard) =="
# age is public-key encryption -- anyone holding a recipient's PUBLIC key can construct
# ciphertext encrypted to it, so a crafted manifest.json inside otherwise-valid
# ciphertext is something restore must defend against. Simulate that by hand-building a
# forged plaintext bundle (manifest.json with a malicious component name, alongside one
# LEGITIMATE component) and encrypting it with the real `age` binary to this test's own
# recipient -- restore must refuse only the malicious component, warn about it clearly,
# still expand the legitimate sibling, and exit 0 (best-effort, not a hard failure).
if ! command -v age >/dev/null 2>&1; then
  echo "[SKIP] path-traversal hardening test: no \`age\` binary on PATH (CI installs it; install age locally to exercise this)"
else
  FORGE_STAGE="$TMP/forge-stage"; mkdir -p "$FORGE_STAGE"
  FORGE_LEGIT_SRC="$TMP/forge-legit-src"; mkdir -p "$FORGE_LEGIT_SRC"
  printf 'legit sibling component content\n' > "$FORGE_LEGIT_SRC/ok.txt"
  tar -czf "$FORGE_STAGE/legit.tar.gz" -C "$TMP" "forge-legit-src"
  cat > "$FORGE_STAGE/manifest.json" <<MANIFEST
{
  "tool": "cipher-brain",
  "schema": 1,
  "host": "forged-test-fixture",
  "created_at": "2026-01-01T00:00:00.000Z",
  "content_digest": "0",
  "recipients_fingerprint": "0",
  "components": [
    { "name": "legit.tar.gz", "kind": "dir", "source": "$FORGE_LEGIT_SRC", "content_digest": "0", "captured_at": "2026-01-01T00:00:00.000Z" },
    { "name": "../forge-traversal-marker.tar.gz", "kind": "dir", "source": "/does/not/matter", "content_digest": "0", "captured_at": "2026-01-01T00:00:00.000Z" }
  ]
}
MANIFEST
  ( cd "$FORGE_STAGE" && tar -cf - manifest.json legit.tar.gz ) | age -r "$(cat "$TMP/keys/recipient.txt")" -o "$TMP/forge.age"
  FORGE_OUT="$TMP/forge-restored"
  set +e
  FORGE_ERR=$(cb restore --in "$TMP/forge.age" --out-dir "$FORGE_OUT" 2>&1); FORGE_RC=$?
  set -e
  [ "$FORGE_RC" = "0" ] || { echo "FAIL: restore of the forged-but-otherwise-valid manifest exited non-zero (expected best-effort: skip only the malicious component)"; echo "$FORGE_ERR"; exit 1; }
  printf '%s' "$FORGE_ERR" | grep -qi "unsafe manifest name" || { echo "FAIL: no warning about the unsafe manifest component name"; echo "$FORGE_ERR"; exit 1; }
  test ! -e "$TMP/forge-traversal-marker.tar.gz" || { echo "FAIL: the forged component name resolved outside --out-dir and something was created there"; exit 1; }
  grep -rq 'legit sibling component content' "$FORGE_OUT/expanded" || { echo "FAIL: the legitimate sibling component in the same forged manifest did not still expand"; find "$FORGE_OUT"; exit 1; }
  echo "[PASS] a forged component name containing a path separator is refused (warned + skipped) without crashing restore, and a legitimate sibling component in the SAME manifest still expands"
fi

echo "== #181 hardening: a pre-existing SYMLINK at the expanded component directory path is refused, never followed =="
# mkdirSync({recursive:true}) FOLLOWS an existing symlink rather than refusing it -- if
# an attacker (or a prior run) planted one at the predictable expanded/<NNN>-<source>
# path before expandComponents() ever runs, extracting into it would land OUTSIDE
# --out-dir entirely. Pre-plant that symlink by hand and prove restore refuses to
# follow it: warns, leaves the symlink untouched, and writes nothing through it.
SYM_SRC="$TMP/symlink-guard-src"; mkdir -p "$SYM_SRC"
printf 'symlink guard test content\n' > "$SYM_SRC/note.txt"
cb snapshot --dir "$SYM_SRC" --out "$TMP/symguard.age" >/dev/null
SYM_OUT="$TMP/symguard-out"; mkdir -p "$SYM_OUT/expanded"
SYM_ESCAPE_TARGET="$TMP/symlink-escape-target"; mkdir -p "$SYM_ESCAPE_TARGET"
SYM_DIRNAME="001-$(printf '%s' "$SYM_SRC" | sed -E -e 's#^/+##' -e 's#[^A-Za-z0-9._-]+#_#g')"
ln -s "$SYM_ESCAPE_TARGET" "$SYM_OUT/expanded/$SYM_DIRNAME"
set +e
SYM_ERR=$(cb restore --in "$TMP/symguard.age" --out-dir "$SYM_OUT" 2>&1); SYM_RC=$?
set -e
[ "$SYM_RC" = "0" ] || { echo "FAIL: restore into an out-dir with a pre-planted expanded-dir symlink exited non-zero"; echo "$SYM_ERR"; exit 1; }
printf '%s' "$SYM_ERR" | grep -qi "is a symlink" || { echo "FAIL: no symlink-refusal warning was printed"; echo "$SYM_ERR"; exit 1; }
printf '%s' "$SYM_ERR" | grep -qi "expanded component directory" || { echo "FAIL: the symlink warning does not identify the expanded component directory"; echo "$SYM_ERR"; exit 1; }
[ "$(readlink "$SYM_OUT/expanded/$SYM_DIRNAME")" = "$SYM_ESCAPE_TARGET" ] || { echo "FAIL: the pre-existing symlink was replaced or removed instead of being left alone"; exit 1; }
[ "$(find "$SYM_ESCAPE_TARGET" -mindepth 1 | wc -l | tr -d ' ')" = "0" ] || { echo "FAIL: something was written through the symlink into $SYM_ESCAPE_TARGET"; find "$SYM_ESCAPE_TARGET"; exit 1; }
echo "[PASS] a pre-existing symlink at the expanded component directory path is refused (warned + skipped), left untouched, with nothing written through it"

echo "== #181 hardening: a pre-existing SYMLINK at expanded/README.txt is refused; component expansion still happens =="
README_OUT="$TMP/symguard-readme-out"; mkdir -p "$README_OUT/expanded"
README_ESCAPE_TARGET="$TMP/symlink-escape-readme-target.txt"
printf 'DO-NOT-OVERWRITE\n' > "$README_ESCAPE_TARGET"
ln -s "$README_ESCAPE_TARGET" "$README_OUT/expanded/README.txt"
set +e
README_ERR=$(cb restore --in "$TMP/symguard.age" --out-dir "$README_OUT" 2>&1); README_RC=$?
set -e
[ "$README_RC" = "0" ] || { echo "FAIL: restore into an out-dir with a pre-planted README.txt symlink exited non-zero"; echo "$README_ERR"; exit 1; }
printf '%s' "$README_ERR" | grep -qi "is a symlink" || { echo "FAIL: no symlink-refusal warning was printed for README.txt"; echo "$README_ERR"; exit 1; }
printf '%s' "$README_ERR" | grep -qi "README.txt" || { echo "FAIL: the symlink warning does not mention README.txt"; echo "$README_ERR"; exit 1; }
[ "$(cat "$README_ESCAPE_TARGET")" = "DO-NOT-OVERWRITE" ] || { echo "FAIL: the external file the README.txt symlink pointed to was overwritten"; exit 1; }
grep -rq 'symlink guard test content' "$README_OUT/expanded" || { echo "FAIL: the component itself did not still expand despite the README.txt write being refused"; find "$README_OUT"; exit 1; }
echo "[PASS] a pre-existing symlink at expanded/README.txt is refused (write skipped, external target untouched), while the component itself still expands"

echo "== wrong key really cannot restore (defense in depth) =="
export CIPHER_BRAIN_HOME="$TMP/keys2"
cb keygen >/dev/null
if cb restore --in "$TMP/snap.age" --out-dir "$TMP/out-wrong" 2>/dev/null; then
  echo "FAIL: restored with a different identity"; exit 1
fi
echo "[PASS] a different identity cannot restore"

echo "== P1 regression: a failed snapshot must not leave staged plaintext =="
# a recipient file with garbage makes the encrypter setup fail (typage rejects the
# line up front, before any plaintext is staged). The run must (a) fail cleanly and
# (b) leave no staged plaintext and no partial output behind.
export TMPDIR="$TMP/stagedir"; mkdir -p "$TMPDIR"
printf 'not-a-valid-age-recipient\n' > "$TMP/bad-recipient.txt"
if cb snapshot --dir "$SRC" --recipient "$TMP/bad-recipient.txt" --out "$TMP/bad.age" 2>/dev/null; then
  echo "FAIL: snapshot with a bad recipient unexpectedly succeeded"; exit 1
fi
LEFTOVERS=$(find "$TMPDIR" -maxdepth 1 -name 'cipher-brain-*' -type d 2>/dev/null | wc -l | tr -d ' ')
if [ "$LEFTOVERS" != "0" ]; then
  echo "FAIL: $LEFTOVERS staged plaintext dir(s) left behind after a failed snapshot"; exit 1
fi
# atomic output: a failed snapshot must leave NEITHER a truncated *.age NOR its (now
# per-run-randomized "<out>.<pid>.<hex>.part") partial — glob, not the old fixed name.
npart() { find "$1" -maxdepth 1 -name "$(basename "$2").*.part" 2>/dev/null | wc -l | tr -d ' '; }
test ! -f "$TMP/bad.age" || { echo "FAIL: failed snapshot left a (truncated) bad.age"; exit 1; }
[ "$(npart "$TMP" "$TMP/bad.age")" = "0" ] || { echo "FAIL: failed snapshot left a bad.age .part"; exit 1; }
echo "[PASS] failed snapshot exited cleanly and left no staged plaintext / no partial *.age"
# a SUCCESSFUL snapshot promotes the .part and leaves none behind
test -f "$TMP/snap.age" && [ "$(npart "$TMP" "$TMP/snap.age")" = "0" ] \
  && echo "[PASS] successful snapshot left no .part (atomic promote)" || { echo "FAIL: snap.age .part lingered"; exit 1; }

echo "== P1 regression: a recipients file with only comments/blank lines must refuse to snapshot =="
# Such a file flattens to ZERO recipients. typage would happily encrypt to an EMPTY
# stanza list — valid-looking ciphertext NO identity can ever decrypt (the old external
# `age -R` errored here). snapshot must fail fast with a clear stderr error and leave
# no output / .part behind.
printf '# rotated out, keys to follow\n\n# (none yet)\n' > "$TMP/comments-only-recipient.txt"
set +e
ERR=$(cb snapshot --dir "$SRC" --recipient "$TMP/comments-only-recipient.txt" --out "$TMP/norecip.age" 2>&1 >/dev/null); RC=$?
set -e
[ "$RC" != "0" ] || { echo "[FAIL] snapshot with a zero-recipient file exited 0"; exit 1; }
printf '%s' "$ERR" | grep -q "NO identity can ever decrypt" \
  || { echo "[FAIL] empty-recipient refusal lacks a clear stderr error"; echo "$ERR"; exit 1; }
test ! -f "$TMP/norecip.age" || { echo "[FAIL] refused snapshot still created norecip.age"; exit 1; }
[ "$(npart "$TMP" "$TMP/norecip.age")" = "0" ] || { echo "[FAIL] refused snapshot left a norecip.age .part"; exit 1; }
echo "[PASS] snapshot refused a recipients file that resolves to zero entries (nothing written)"

echo "== restore of a corrupt artifact fails and removes the tree it created =="
# Drop the LAST bytes of a valid snapshot (snap.age holds a 1 MB blob => multiple age
# STREAM chunks): the leading chunks still decrypt and tar extracts a PARTIAL tree, then
# age fails on the broken final chunk. Use the ORIGINAL keypair ($TMP/keys) so the
# failure is the truncation, not a wrong key (CIPHER_BRAIN_HOME is $TMP/keys2 here).
SNAPSZ=$(wc -c < "$TMP/snap.age" | tr -d ' ')
head -c $((SNAPSZ - 500)) "$TMP/snap.age" > "$TMP/trunc.age"
RDIR="$TMP/restore-corrupt"   # does NOT pre-exist -> restore creates it -> must remove it on failure
set +e
CIPHER_BRAIN_HOME="$TMP/keys" node "${BIN_DEV_ARGS[@]}" "$BIN" restore --in "$TMP/trunc.age" --out-dir "$RDIR" >/dev/null 2>&1; RC=$?
set -e
if [ "$RC" = "0" ]; then echo "FAIL: restore of a truncated artifact unexpectedly succeeded"; exit 1; fi
test ! -e "$RDIR" || { echo "FAIL: restore left a partial tree at $RDIR"; exit 1; }
echo "[PASS] restore of a corrupt artifact failed and removed the partial tree"

echo "== tar dying mid-stream must fail the snapshot (no valid-looking truncated .age) =="
# With in-process encryption (typage), a tar that dies after emitting some bytes just
# EOFs its stdout — which the encrypter would happily finalize into VALID ciphertext
# of a TRUNCATED archive. encryptToFile gates success on tar's exit code; prove it.
# The stub tar intercepts ONLY the snapshot pipeline invocation (`tar -cf - …`) and
# dispatches on TAR_STUB_MODE; every other tar call passes through to the real tar.
REALTAR="$(command -v tar)"
STUBBIN="$TMP/stubbin"; mkdir -p "$STUBBIN"
cat > "$STUBBIN/tar" <<EOF
#!/usr/bin/env bash
if [ "\$1" = "-cf" ] && [ "\$2" = "-" ]; then
  case "\${TAR_STUB_MODE:-}" in
    slow)  sleep "\${TAR_STUB_SLEEP:-3}" ;;          # hold the pipeline open, then behave
    fail)  printf 'partial-tar-bytes'; exit 1 ;;      # die mid-stream after emitting bytes
    wedge) exec node "$TMP/tar-ignore-term.mjs" ;;    # ignore SIGTERM and hang (timeout test)
  esac
fi
exec "$REALTAR" "\$@"
EOF
chmod +x "$STUBBIN/tar"
set +e
OUT=$(PATH="$STUBBIN:$PATH" TAR_STUB_MODE=fail node "${BIN_DEV_ARGS[@]}" "$BIN" snapshot --dir "$SRC" --out "$TMP/midfail.age" 2>&1); RC=$?
set -e
[ "$RC" != "0" ] || { echo "FAIL: snapshot with a mid-stream tar death exited 0"; exit 1; }
test ! -f "$TMP/midfail.age" || { echo "FAIL: mid-stream tar death left a truncated midfail.age"; exit 1; }
[ "$(npart "$TMP" "$TMP/midfail.age")" = "0" ] || { echo "FAIL: mid-stream tar death left a .part"; exit 1; }
LEFTOVERS=$(find "$TMPDIR" -maxdepth 1 -name 'cipher-brain-*' -type d 2>/dev/null | wc -l | tr -d ' ')
[ "$LEFTOVERS" = "0" ] || { echo "FAIL: mid-stream tar death left staged plaintext"; exit 1; }
echo "[PASS] a tar that dies mid-stream fails the snapshot and leaves nothing behind"

echo "== P1 regression: SIGINT mid-snapshot must not leave staged plaintext =="
# A signal tears the process down WITHOUT running the finally-block, so this is the
# gap the failure cases above do NOT cover. Use a slow pipeline tar to hold the run
# open while the staged plaintext exists, observe the stage dir appear, then SIGINT
# and assert the signal handler erased it.
export TMPDIR="$TMP/stagedir-sig"; mkdir -p "$TMPDIR"
# Invoke `node` DIRECTLY (not the cb() function): backgrounding a shell function makes
# $! the subshell's pid, so `kill -INT $!` would hit the subshell and leave node
# orphaned to run to completion — the signal would never reach the handler under test.
PATH="$STUBBIN:$PATH" TAR_STUB_MODE=slow TAR_STUB_SLEEP=5 node "${BIN_DEV_ARGS[@]}" "$BIN" snapshot --dir "$SRC" --out "$TMP/sig.age" >/dev/null 2>&1 &
SNAP_PID=$!
APPEARED=0
for _ in $(seq 1 50); do
  if find "$TMPDIR" -maxdepth 1 -name 'cipher-brain-*' -type d 2>/dev/null | grep -q .; then APPEARED=1; break; fi
  sleep 0.1
done
if [ "$APPEARED" != "1" ]; then
  echo "FAIL: stage dir never appeared (test setup)"; kill "$SNAP_PID" 2>/dev/null || true; exit 1
fi
kill -INT "$SNAP_PID"
wait "$SNAP_PID" 2>/dev/null || true   # signal exit is non-zero — expected
LEFTOVERS=$(find "$TMPDIR" -maxdepth 1 -name 'cipher-brain-*' -type d 2>/dev/null | wc -l | tr -d ' ')
if [ "$LEFTOVERS" != "0" ]; then
  echo "FAIL: $LEFTOVERS staged plaintext dir(s) left behind after SIGINT"; exit 1
fi
# the signal handler also kills the pipeline children, so no partial ciphertext lingers
[ "$(npart "$TMP" "$TMP/sig.age")" = "0" ] || { echo "FAIL: SIGINT left a sig.age .part (child not killed)"; exit 1; }
test ! -f "$TMP/sig.age" || { echo "FAIL: SIGINT left a partial sig.age"; exit 1; }
echo "[PASS] SIGINT mid-snapshot left no staged plaintext / no partial ciphertext"

echo "== race: an --out that appears mid-snapshot is NOT clobbered (link promote is exclusive) =="
# Start a slow snapshot (passes the early exists() check while --out is absent), then
# create --out externally before it promotes. link()+EEXIST must refuse, preserving the
# external file — a plain rename would have clobbered it.
RACE="$TMP/race-out.age"
PATH="$STUBBIN:$PATH" TAR_STUB_MODE=slow TAR_STUB_SLEEP=3 node "${BIN_DEV_ARGS[@]}" "$BIN" snapshot --dir "$SRC" --out "$RACE" >/dev/null 2>&1 &
RACE_PID=$!
for _ in $(seq 1 50); do find "$TMPDIR" -maxdepth 1 -name 'cipher-brain-*' -type d 2>/dev/null | grep -q . && break; sleep 0.1; done
printf 'PRE-EXISTING-WINNER\n' > "$RACE"   # a "concurrent run" finished first
set +e
wait "$RACE_PID"; RC=$?
set -e
if [ "$RC" = "0" ]; then echo "FAIL: snapshot clobbered an --out that appeared mid-run"; exit 1; fi
[ "$(cat "$RACE")" = "PRE-EXISTING-WINNER" ] || { echo "FAIL: the pre-existing --out was overwritten"; exit 1; }
LEFTPART=$(find "$(dirname "$RACE")" -maxdepth 1 -name "$(basename "$RACE").*.part" 2>/dev/null | wc -l | tr -d ' ')
[ "$LEFTPART" = "0" ] || { echo "FAIL: a .part lingered after the refused promote"; exit 1; }
echo "[PASS] a mid-run --out is not clobbered and no .part lingers"

echo "== verify on a public-key-only box is PARTIAL (exit 2), never a false-green PASS =="
# A box with only recipient.txt (no identity) cannot prove decryptability. verify
# must say PARTIAL and exit 2 so cron/logs don't read it as a full PASS.
PUBONLY="$TMP/pubonly"; mkdir -p "$PUBONLY"
cp "$TMP/keys/recipient.txt" "$PUBONLY/recipient.txt"   # public key only — deliberately NO identity.age
set +e
OUT=$(CIPHER_BRAIN_HOME="$PUBONLY" node "${BIN_DEV_ARGS[@]}" "$BIN" verify --in "$TMP/snap.age" 2>&1); RC=$?
set -e
if [ "$RC" != "2" ]; then echo "FAIL: public-key-only verify exited $RC, expected 2"; echo "$OUT"; exit 1; fi
if ! printf '%s' "$OUT" | grep -q "VERDICT: PARTIAL"; then echo "FAIL: expected VERDICT: PARTIAL"; echo "$OUT"; exit 1; fi
if printf '%s' "$OUT" | grep -q "VERDICT: PASS"; then echo "FAIL: public-key-only verify falsely printed PASS"; exit 1; fi
echo "[PASS] public-key-only verify is PARTIAL/exit 2"

echo "== recipient pin: snapshot refuses an out-of-allowlist recipient =="
PINHOME="$TMP/keys"   # the original keypair from the top of this test
MYPUB=$(cat "$PINHOME/recipient.txt")
# (a) matching allowlist -> snapshot succeeds
CIPHER_BRAIN_HOME="$PINHOME" CIPHER_BRAIN_PIN_RECIPIENTS="$MYPUB" \
  node "${BIN_DEV_ARGS[@]}" "$BIN" snapshot --dir "$SRC" --out "$TMP/pin-ok.age" >/dev/null
echo "[PASS] snapshot allowed when the recipient is on the allowlist"
# (b) a DIFFERENT key's pin -> snapshot must refuse (the injected-recipient case)
OTHER="$TMP/other-key"; mkdir -p "$OTHER"
CIPHER_BRAIN_HOME="$OTHER" node "${BIN_DEV_ARGS[@]}" "$BIN" keygen >/dev/null
OTHERPUB=$(cat "$OTHER/recipient.txt")
set +e
CIPHER_BRAIN_HOME="$PINHOME" CIPHER_BRAIN_PIN_RECIPIENTS="$OTHERPUB" \
  node "${BIN_DEV_ARGS[@]}" "$BIN" snapshot --dir "$SRC" --out "$TMP/pin-bad.age" >/dev/null 2>&1; RC=$?
set -e
if [ "$RC" = "0" ]; then echo "FAIL: snapshot encrypted to a non-allowlisted recipient"; exit 1; fi
test ! -f "$TMP/pin-bad.age"
echo "[PASS] snapshot refused a recipient not on the allowlist"
# (c) a recipients FILE that keeps the allowed age key but ALSO adds an ssh recipient
# (age -R accepts ssh-ed25519) must be refused — an age1-only scan would miss it.
SSHMIX="$TMP/recipient-ssh-mix.txt"
printf '%s\nssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIINJECTEDATTACKERKEYxxxxxxxxxxxxxxxxxxxxxx attacker\n' "$MYPUB" > "$SSHMIX"
set +e
CIPHER_BRAIN_HOME="$PINHOME" CIPHER_BRAIN_PIN_RECIPIENTS="$MYPUB" \
  node "${BIN_DEV_ARGS[@]}" "$BIN" snapshot --dir "$SRC" --recipient "$SSHMIX" --out "$TMP/pin-ssh.age" >/dev/null 2>&1; RC=$?
set -e
if [ "$RC" = "0" ]; then echo "FAIL: pin let through a file with an injected ssh recipient"; exit 1; fi
test ! -f "$TMP/pin-ssh.age"
echo "[PASS] snapshot refused a recipient file with an injected ssh recipient"
# (d) a FILE allowlist whose path contains "age1" must be read as a file, not parsed
# as an inline key (regression for the includes('age1') path-detection bug).
PINFILE="$TMP/age1-pins.txt"; printf '%s\n' "$MYPUB" > "$PINFILE"
CIPHER_BRAIN_HOME="$PINHOME" CIPHER_BRAIN_PIN_RECIPIENTS="$PINFILE" \
  node "${BIN_DEV_ARGS[@]}" "$BIN" snapshot --dir "$SRC" --out "$TMP/pin-file.age" >/dev/null
test -f "$TMP/pin-file.age"
echo "[PASS] snapshot honored a file-based allowlist whose path contains 'age1'"
# (e) a key present only in a COMMENT line of the allowlist file is NOT allowed
# (e.g. a rotated/revoked key left commented out must not silently pass the pin).
PINCOMMENT="$TMP/pins-with-comment.txt"
printf '%s\n# rotated-out: %s\n' "$MYPUB" "$OTHERPUB" > "$PINCOMMENT"
set +e
CIPHER_BRAIN_HOME="$OTHER" CIPHER_BRAIN_PIN_RECIPIENTS="$PINCOMMENT" \
  node "${BIN_DEV_ARGS[@]}" "$BIN" snapshot --dir "$SRC" --recipient "$OTHER/recipient.txt" --out "$TMP/pin-comment.age" >/dev/null 2>&1; RC=$?
set -e
if [ "$RC" = "0" ]; then echo "FAIL: pin allowed a key that was only in a comment line"; exit 1; fi
test ! -f "$TMP/pin-comment.age"
echo "[PASS] snapshot refused a recipient whose key was only commented-out in the allowlist"
# (f) #101: an explicitly EMPTY CIPHER_BRAIN_PIN_RECIPIENTS="" (e.g. a broken
# cron/systemd template expansion) must fail CLOSED, not be silently treated the
# same as an unset var (which would disable the allowlist entirely — fail-open).
set +e
CIPHER_BRAIN_HOME="$PINHOME" CIPHER_BRAIN_PIN_RECIPIENTS="" \
  node "${BIN_DEV_ARGS[@]}" "$BIN" snapshot --dir "$SRC" --out "$TMP/pin-empty.age" >"$TMP/pin-empty.log" 2>&1; RC=$?
set -e
if [ "$RC" = "0" ]; then echo "FAIL: snapshot succeeded with CIPHER_BRAIN_PIN_RECIPIENTS=\"\" (fail-open regression)"; cat "$TMP/pin-empty.log"; exit 1; fi
test ! -f "$TMP/pin-empty.age"
grep -q "CIPHER_BRAIN_PIN_RECIPIENTS is set but empty" "$TMP/pin-empty.log" || { echo "FAIL: expected the fail-closed empty-pin error message"; cat "$TMP/pin-empty.log"; exit 1; }
echo "[PASS] snapshot fails closed when CIPHER_BRAIN_PIN_RECIPIENTS is explicitly empty"

echo "== push arweave/turbo --yes guard: requires explicit opt-in before a paid permanent store =="
# #160: push now computes + prints the cost estimate BEFORE the --yes/CIPHER_BRAIN_YES
# gate (previously the gate fired first, and the estimate only ran INSIDE backend.put(),
# i.e. only after consent was already given). That estimate is a real, unauthenticated
# price query (arweave: GET <gateway>/price/<bytes>; turbo: the SDK's pricing call) —
# no longer "no external deps" for the arweave case, so point it at a closed local port
# (connection refused, near-instant) rather than the real network. arweave's redirect
# below (AR_OFFLINE) makes ITS query fully offline/deterministic; turbo has no such
# override (the SDK's pricing endpoint isn't configurable) — its query only fires at all
# when `@ardrive/turbo-sdk` happens to be installed (an optional peerDependency, absent
# in this repo's own devDependencies), same conditional-network precedent cli-smoke.sh's
# `estimate --backend turbo` test already relies on (its "(sdk installed)" vs
# "(dependency not installed)" branches). Either way, the wallet/SDK signing path is
# still never reached without --yes (put() is never called), so the gate itself remains
# a no-signing, no-spend check.
AR_OFFLINE=(CIPHER_BRAIN_AR_HOST=127.0.0.1 CIPHER_BRAIN_AR_PORT=1 CIPHER_BRAIN_AR_PROTOCOL=http)
set +e
OUT_AR=$(env "${AR_OFFLINE[@]}" node "${BIN_DEV_ARGS[@]}" "$BIN" push --in "$TMP/snap.age" --backend arweave 2>&1); RC_AR=$?
OUT_TU=$(env "${AR_OFFLINE[@]}" node "${BIN_DEV_ARGS[@]}" "$BIN" push --in "$TMP/snap.age" --backend turbo  2>&1); RC_TU=$?
set -e
[ "$RC_AR" != "0" ] || { echo "[FAIL] push arweave without --yes exited 0"; exit 1; }
[ "$RC_TU" != "0" ] || { echo "[FAIL] push turbo without --yes exited 0"; exit 1; }
printf '%s' "$OUT_AR" | grep -qi "CIPHER_BRAIN_YES\|--yes" \
  || { echo "[FAIL] push arweave error lacks --yes guidance"; echo "$OUT_AR"; exit 1; }
printf '%s' "$OUT_TU" | grep -qi "CIPHER_BRAIN_YES\|--yes" \
  || { echo "[FAIL] push turbo error lacks --yes guidance"; echo "$OUT_TU"; exit 1; }
echo "[PASS] push arweave/turbo without --yes fails with clear guidance"
# #160 regression: the cost estimate must appear BEFORE the --yes consent-gate error in
# the SAME output — not just present somewhere, but ahead of it (line-order check).
EST_LINE_AR=$(printf '%s\n' "$OUT_AR" | grep -n -i "cost estimate" | head -1 | cut -d: -f1)
YES_LINE_AR=$(printf '%s\n' "$OUT_AR" | grep -n -i "re-run push with --yes" | head -1 | cut -d: -f1)
[ -n "$EST_LINE_AR" ] || { echo "[FAIL] push arweave (no --yes) printed no cost estimate"; echo "$OUT_AR"; exit 1; }
[ -n "$YES_LINE_AR" ] || { echo "[FAIL] push arweave (no --yes) printed no --yes consent error"; echo "$OUT_AR"; exit 1; }
[ "$EST_LINE_AR" -lt "$YES_LINE_AR" ] \
  || { echo "[FAIL] push arweave printed the --yes consent gate before the cost estimate (#160 regression)"; echo "$OUT_AR"; exit 1; }
EST_LINE_TU=$(printf '%s\n' "$OUT_TU" | grep -n -i "cost estimate" | head -1 | cut -d: -f1)
YES_LINE_TU=$(printf '%s\n' "$OUT_TU" | grep -n -i "re-run push with --yes" | head -1 | cut -d: -f1)
[ -n "$EST_LINE_TU" ] || { echo "[FAIL] push turbo (no --yes) printed no cost estimate"; echo "$OUT_TU"; exit 1; }
[ -n "$YES_LINE_TU" ] || { echo "[FAIL] push turbo (no --yes) printed no --yes consent error"; echo "$OUT_TU"; exit 1; }
[ "$EST_LINE_TU" -lt "$YES_LINE_TU" ] \
  || { echo "[FAIL] push turbo printed the --yes consent gate before the cost estimate (#160 regression)"; echo "$OUT_TU"; exit 1; }
echo "[PASS] push arweave/turbo prints the cost estimate BEFORE asking for --yes consent (#160)"
# With CIPHER_BRAIN_YES=1 the --yes guard passes; the error moves further in
# (wallet / SDK missing), which proves the guard no longer blocks.
set +e
OUT2=$(env "${AR_OFFLINE[@]}" CIPHER_BRAIN_YES=1 node "${BIN_DEV_ARGS[@]}" "$BIN" push --in "$TMP/snap.age" --backend arweave 2>&1); RC2=$?
set -e
[ "$RC2" != "0" ] || { echo "[FAIL] arweave push should fail (no wallet in test env)"; exit 1; }
printf '%s' "$OUT2" | grep -qi "CIPHER_BRAIN_YES\|--yes" \
  && { echo "[FAIL] CIPHER_BRAIN_YES=1 still hitting the --yes gate"; echo "$OUT2"; exit 1; } || true
echo "[PASS] push arweave with CIPHER_BRAIN_YES=1 passes the --yes guard (fails further in: wallet/SDK)"

echo "== pipeline timeout: a wedged, SIGTERM-IGNORING tar can't hang the CLI (#38) =="
# TAR_STUB_MODE=wedge swaps the pipeline tar for a node stub that IGNORES SIGTERM and
# stays alive 30s (exec'd — no grandchild, so SIGKILL on it leaks nothing). This
# exercises the hard path: the pipeline must (a) time out, (b) escalate SIGTERM→SIGKILL
# so the child actually dies, and (c) only THEN reject — so cleanup runs after the child
# is dead, leaving no output / .part / staged plaintext. If escalation failed, the run
# would block on the stub's full 30s.
printf 'process.on("SIGTERM",()=>{});\nsetTimeout(()=>process.exit(0),30000);\nprocess.stdout.write("wedged");\n' > "$TMP/tar-ignore-term.mjs"
TOUT="$TMP/timeout-snap.age"
START=$(date +%s)
set +e
TERR=$(PATH="$STUBBIN:$PATH" TAR_STUB_MODE=wedge CIPHER_BRAIN_PIPE_TIMEOUT=600 node "${BIN_DEV_ARGS[@]}" "$BIN" snapshot --dir "$SRC" --out "$TOUT" 2>&1); TRC=$?
set -e
ELAPSED=$(( $(date +%s) - START ))
[ "$TRC" != "0" ] || { echo "[FAIL] wedged-tar snapshot exited 0"; exit 1; }
printf '%s' "$TERR" | grep -qi "timed out" || { echo "[FAIL] no timeout error surfaced"; echo "$TERR"; exit 1; }
# < 15s proves the SIGKILL escalation fired (timeout 0.6s + 2s SIGKILL + overhead),
# NOT that we waited out the stub's 30s sleep.
[ "$ELAPSED" -lt 15 ] || { echo "[FAIL] pipeline took ${ELAPSED}s — SIGKILL escalation did not bound it (< the 30s stub)"; exit 1; }
test ! -f "$TOUT"                                       # no finished output
[ -z "$(find "$TMP" -name '*.part' 2>/dev/null)" ] || { echo "[FAIL] a .part lingered after timeout"; exit 1; }
# the staged plaintext dir must be erased by snapshot's finally on the timeout path
[ -z "$(find "${TMPDIR:-/tmp}" -maxdepth 1 -name 'cipher-brain-*' -newermt "@$START" 2>/dev/null)" ] \
  || { echo "[FAIL] a staged-plaintext cipher-brain-* dir lingered after timeout"; exit 1; }
echo "[PASS] SIGTERM-ignoring tar killed via SIGKILL escalation in ${ELAPSED}s; no output / .part / staged plaintext"

echo "== single-key warning counts DISTINCT keys, not --recipient args (#43) =="
# one --recipient file holding TWO keys must NOT warn (recovery exists); a duplicate
# (two args, same key) MUST warn.
keygen2() { CIPHER_BRAIN_HOME="$1" node "${BIN_DEV_ARGS[@]}" "$BIN" keygen >/dev/null 2>&1; }
keygen2 "$TMP/k-a"; keygen2 "$TMP/k-b"
MULTIREC="$TMP/multi-recipient.txt"
cat "$TMP/k-a/recipient.txt" "$TMP/k-b/recipient.txt" > "$MULTIREC"
W1=$(cb snapshot --dir "$SRC" --recipient "$MULTIREC" --out "$TMP/mk.age" 2>&1 | grep -ic "SINGLE recipient" || true)
[ "$W1" = "0" ] || { echo "[FAIL] warned on a 2-key recipient FILE"; exit 1; }
W2=$(cb snapshot --dir "$SRC" --recipient "$TMP/k-a/recipient.txt" --recipient "$TMP/k-a/recipient.txt" --out "$TMP/dup.age" 2>&1 | grep -ic "SINGLE recipient" || true)
[ "$W2" != "0" ] || { echo "[FAIL] did NOT warn on two args naming the SAME key"; exit 1; }
echo "[PASS] single-key warning is by distinct key, not arg count (2-key file silent; dup-arg warns)"

echo "== #119 regression: keygenAt() fails closed when chmod(home, 0700) cannot succeed =="
# chflags uchg (macOS "user immutable") makes even the OWNER's own chmod() fail EPERM,
# without needing root — the only portable, non-root way found to force a chmod
# failure deterministically. No Linux equivalent exists (chattr +i needs
# CAP_LINUX_IMMUTABLE, i.e. root, on ext4/most filesystems), so this is macOS-only;
# on Linux CI it SKIPs rather than fabricate a pass (rules/shell-ops.md: BLOCKED != PASS).
if [ "$(uname -s)" = "Darwin" ]; then
  CHMOD_FAIL_HOME="$TMP/chmod-fail-home"; mkdir -p "$CHMOD_FAIL_HOME"
  chmod 755 "$CHMOD_FAIL_HOME"    # pre-existing, LOOSER than the 0700 keygenAt() must enforce
  set +e
  chflags uchg "$CHMOD_FAIL_HOME" # immutable: keygenAt()'s own chmod(home, 0700) will now EPERM
  CHFLAGS_RC=$?
  set -e
  if [ "$CHFLAGS_RC" != "0" ]; then
    echo "[SKIP] #119 chmod-fail-closed repro: chflags uchg is unsupported on this filesystem (e.g. a virtualized TMPDIR)"
  else
    set +e
    OUT=$(CIPHER_BRAIN_HOME="$CHMOD_FAIL_HOME" node "${BIN_DEV_ARGS[@]}" "$BIN" keygen 2>&1); RC=$?
    set -e
    chflags nouchg "$CHMOD_FAIL_HOME" # clear FIRST — every check below may exit 1, and the
                                       # trap's rm -rf "$TMP" cannot remove an immutable dir
    if [ "$RC" = "0" ]; then echo "FAIL: keygen succeeded despite chmod(home, 0700) failing — the #119 regression (a swallowed chmod error)"; echo "$OUT"; exit 1; fi
    printf '%s' "$OUT" | grep -qi "operation not permitted\|EPERM" || { echo "FAIL: keygen's failure was not the expected chmod EPERM"; echo "$OUT"; exit 1; }
    test ! -f "$CHMOD_FAIL_HOME/identity.age" || { echo "FAIL: an identity.age was written into a directory whose permissions could not be verified/corrected"; exit 1; }
    [ "$(stat -f '%Lp' "$CHMOD_FAIL_HOME")" = "755" ] || { echo "FAIL: the directory's mode changed despite the chmod call failing"; exit 1; }
    echo "[PASS] keygen fails closed (writes nothing) when chmod(home, 0700) cannot succeed, instead of silently proceeding"
  fi
else
  echo "[SKIP] #119 chmod-fail-closed repro needs chflags (macOS-only — see comment above)"
fi

echo "== #120 regression: --recipient FILE whose path contains 'age1' is read as a file, not mistaken for an inline literal =="
REC_AGE1_HOME="$TMP/rec-age1-home"
CIPHER_BRAIN_HOME="$REC_AGE1_HOME" node "${BIN_DEV_ARGS[@]}" "$BIN" keygen >/dev/null
REC_AGE1_FILE="$TMP/age1-manual-recipients.txt"   # the filename itself starts with "age1"
printf '%s\n' "$(cat "$REC_AGE1_HOME/recipient.txt")" > "$REC_AGE1_FILE"
cb snapshot --dir "$SRC" --recipient "$REC_AGE1_FILE" --out "$TMP/age1-file-recipient.age" >/dev/null
test -f "$TMP/age1-file-recipient.age" || { echo "FAIL: snapshot did not honor a recipients FILE whose path starts with 'age1'"; exit 1; }
CIPHER_BRAIN_HOME="$REC_AGE1_HOME" node "${BIN_DEV_ARGS[@]}" "$BIN" verify --in "$TMP/age1-file-recipient.age" 2>&1 | grep -q 'VERDICT: PASS' \
  || { echo "FAIL: the age1-named-file recipient did not actually decrypt (recipientEntries misread the filename as the literal key)"; exit 1; }
echo "[PASS] --recipient honored a file-based recipient whose path contains 'age1' (recipientEntries checks existence before the age1 prefix, #120)"

echo "== #121 regression: keygen refuses to silently re-key a stray recipient.txt that has no matching identity.age =="
STRAY_HOME="$TMP/stray-recipient-home"
CIPHER_BRAIN_HOME="$STRAY_HOME" node "${BIN_DEV_ARGS[@]}" "$BIN" keygen >/dev/null
STRAY_RECIPIENT_ORIG="$(cat "$STRAY_HOME/recipient.txt")"
rm -f "$STRAY_HOME/identity.age"   # simulate: identity moved offline (cold storage), recipient.txt left behind
set +e
OUT=$(CIPHER_BRAIN_HOME="$STRAY_HOME" node "${BIN_DEV_ARGS[@]}" "$BIN" keygen 2>&1); RC=$?
set -e
if [ "$RC" = "0" ]; then echo "FAIL: keygen silently re-keyed a stray recipient.txt with no matching identity — the #121 regression"; echo "$OUT"; exit 1; fi
printf '%s' "$OUT" | grep -qi "recipient already exists" || { echo "FAIL: wrong error for a stray pre-existing recipient.txt"; echo "$OUT"; exit 1; }
[ "$(cat "$STRAY_HOME/recipient.txt")" = "$STRAY_RECIPIENT_ORIG" ] || { echo "FAIL: the stray recipient.txt was modified despite the refusal"; exit 1; }
test ! -f "$STRAY_HOME/identity.age" || { echo "FAIL: an identity.age was written despite the recipientPath refusal"; exit 1; }
echo "[PASS] keygen refuses to re-key a stray pre-existing recipient.txt without --force, leaving it byte-identical"

echo "== #122 regression: a failed 'keygen --force' (new payload never finishes) must not lose the OLD identity =="
FORCE_HOME="$TMP/force-atomic-home"
CIPHER_BRAIN_HOME="$FORCE_HOME" node "${BIN_DEV_ARGS[@]}" "$BIN" keygen >/dev/null
ORIG_IDENTITY_SHA="$(shasum -a 256 "$FORCE_HOME/identity.age" | cut -d' ' -f1)"
ORIG_RECIPIENT="$(cat "$FORCE_HOME/recipient.txt")"
# --passphrase with no CIPHER_BRAIN_PASSPHRASE and no TTY (< /dev/null): askNewPassphrase()
# throws deterministically ("stdin is not a TTY") AFTER the new keypair is generated but
# BEFORE keygenAt() ever touches identityPath/recipientPath on disk (see keys.ts) — the
# same "prepare fully, THEN replace" ordering the #122 fix requires.
set +e
OUT=$(CIPHER_BRAIN_HOME="$FORCE_HOME" node "${BIN_DEV_ARGS[@]}" "$BIN" keygen --force --passphrase < /dev/null 2>&1); RC=$?
set -e
if [ "$RC" = "0" ]; then echo "FAIL: keygen --force --passphrase succeeded despite no TTY / no CIPHER_BRAIN_PASSPHRASE"; echo "$OUT"; exit 1; fi
printf '%s' "$OUT" | grep -qi "not a TTY" || { echo "FAIL: expected the passphrase-requires-a-TTY error"; echo "$OUT"; exit 1; }
[ "$(shasum -a 256 "$FORCE_HOME/identity.age" | cut -d' ' -f1)" = "$ORIG_IDENTITY_SHA" ] || { echo "FAIL: the ORIGINAL identity was lost/modified by a failed --force keygen — the #122 regression (delete-before-ready)"; exit 1; }
[ "$(cat "$FORCE_HOME/recipient.txt")" = "$ORIG_RECIPIENT" ] || { echo "FAIL: the ORIGINAL recipient was lost/modified by a failed --force keygen"; exit 1; }
TMP_LEFTOVER="$(find "$FORCE_HOME" -maxdepth 1 -name '*.tmp' 2>/dev/null | head -n1)"
[ -z "$TMP_LEFTOVER" ] || { echo "FAIL: a .tmp sibling survived a failed --force keygen: $TMP_LEFTOVER"; exit 1; }
echo "[PASS] a failed --force keygen (passphrase step throwing) leaves the ORIGINAL identity/recipient completely intact — nothing is deleted before the replacement is ready"

echo "== #122: a SUCCESSFUL 'keygen --force' actually replaces identity+recipient, atomically, with no leftover temp file =="
CIPHER_BRAIN_HOME="$FORCE_HOME" node "${BIN_DEV_ARGS[@]}" "$BIN" keygen --force >/dev/null
[ "$(shasum -a 256 "$FORCE_HOME/identity.age" | cut -d' ' -f1)" != "$ORIG_IDENTITY_SHA" ] || { echo "FAIL: --force did not actually replace the identity"; exit 1; }
[ "$(cat "$FORCE_HOME/recipient.txt")" != "$ORIG_RECIPIENT" ] || { echo "FAIL: --force did not actually replace the recipient"; exit 1; }
[ "$(stat -c '%a' "$FORCE_HOME/identity.age" 2>/dev/null || stat -f '%Lp' "$FORCE_HOME/identity.age")" = "600" ] || { echo "FAIL: the replaced identity is not mode 600"; exit 1; }
TMP_LEFTOVER2="$(find "$FORCE_HOME" -maxdepth 1 -name '*.tmp' 2>/dev/null | head -n1)"
[ -z "$TMP_LEFTOVER2" ] || { echo "FAIL: a .tmp sibling survived a successful --force keygen: $TMP_LEFTOVER2"; exit 1; }
echo "[PASS] keygen --force replaces both identity and recipient with a fresh keypair (mode 600 preserved), no .tmp sibling left behind"

echo "== #110: 'keygen --wrap-in-place' passphrase-protects an EXISTING identity WITHOUT replacing it =="
WRAP_HOME="$TMP/wrap-home"
CIPHER_BRAIN_HOME="$WRAP_HOME" node "${BIN_DEV_ARGS[@]}" "$BIN" keygen >/dev/null
WRAP_RECIPIENT_ORIG="$(cat "$WRAP_HOME/recipient.txt")"
# Prove non-destructiveness end-to-end, not just "the recipient string didn't change":
# encrypt a snapshot to this identity BEFORE wrapping it, then decrypt that SAME
# snapshot AFTER wrapping — if --wrap-in-place secretly generated a brand-new keypair
# (the exact #110 bug `keygen --passphrase --force` has), this pre-wrap snapshot would
# no longer decrypt with the now-wrapped identity.
CIPHER_BRAIN_HOME="$WRAP_HOME" node "${BIN_DEV_ARGS[@]}" "$BIN" snapshot --dir "$SRC" --out "$TMP/wrap-presnap.age" >/dev/null

CIPHER_BRAIN_HOME="$WRAP_HOME" CIPHER_BRAIN_PASSPHRASE="wrap-in-place-test-pass" \
  node "${BIN_DEV_ARGS[@]}" "$BIN" keygen --wrap-in-place >/dev/null

grep -qa '^-> scrypt ' "$WRAP_HOME/identity.age" || { echo "FAIL: keygen --wrap-in-place did not actually scrypt-wrap the identity"; exit 1; }
[ "$(cat "$WRAP_HOME/recipient.txt")" = "$WRAP_RECIPIENT_ORIG" ] || { echo "FAIL: keygen --wrap-in-place changed the recipient — it generated a NEW keypair instead of wrapping the existing one (the #110 bug)"; exit 1; }

CIPHER_BRAIN_HOME="$WRAP_HOME" CIPHER_BRAIN_PASSPHRASE="wrap-in-place-test-pass" \
  node "${BIN_DEV_ARGS[@]}" "$BIN" verify --in "$TMP/wrap-presnap.age" 2>&1 | grep -q 'VERDICT: PASS' \
  || { echo "FAIL: a snapshot encrypted BEFORE the wrap no longer decrypts with the wrapped identity — wrap-in-place did not preserve the original keypair"; exit 1; }
echo "[PASS] keygen --wrap-in-place scrypt-wraps the identity in place, keeps the SAME recipient, and a snapshot made BEFORE the wrap still decrypts with it afterward"

echo "== keygen --wrap-in-place refuses a no-op re-wrap and a missing identity =="
set +e
OUT=$(CIPHER_BRAIN_HOME="$WRAP_HOME" CIPHER_BRAIN_PASSPHRASE="wrap-in-place-test-pass" node "${BIN_DEV_ARGS[@]}" "$BIN" keygen --wrap-in-place 2>&1); RC=$?
set -e
if [ "$RC" = "0" ]; then echo "FAIL: re-wrapping an already-wrapped identity should refuse, not succeed"; echo "$OUT"; exit 1; fi
printf '%s' "$OUT" | grep -qi "already passphrase-wrapped" || { echo "FAIL: wrong error for re-wrapping an already-wrapped identity"; echo "$OUT"; exit 1; }

NOKEY_HOME="$TMP/wrap-no-identity-home"; mkdir -p "$NOKEY_HOME"
set +e
OUT=$(CIPHER_BRAIN_HOME="$NOKEY_HOME" node "${BIN_DEV_ARGS[@]}" "$BIN" keygen --wrap-in-place 2>&1); RC=$?
set -e
if [ "$RC" = "0" ]; then echo "FAIL: --wrap-in-place should refuse when no identity exists yet"; echo "$OUT"; exit 1; fi
printf '%s' "$OUT" | grep -qi "no identity found" || { echo "FAIL: wrong error for a missing identity"; echo "$OUT"; exit 1; }
echo "[PASS] keygen --wrap-in-place refuses to re-wrap an already-wrapped identity, and refuses cleanly when no identity exists yet"

echo "== keygen --wrap-in-place also refuses an ASCII-ARMORED already-wrapped identity, without corrupting it (#87-style edge case) =="
# loadIdentities() (crypt.ts) treats a wrapped identity as EITHER raw age ciphertext OR
# that same ciphertext ASCII-armored (`age -p -a`, or one re-typed from a printed
# recovery note — #87's own motivating case) — wrap-in-place's "already wrapped" check
# must recognize both shapes too, or it would silently double-wrap/corrupt an armored
# one instead of refusing.
ARMOR_HOME="$TMP/wrap-armor-home"
CIPHER_BRAIN_HOME="$ARMOR_HOME" node "${BIN_DEV_ARGS[@]}" "$BIN" keygen >/dev/null
CIPHER_BRAIN_HOME="$ARMOR_HOME" CIPHER_BRAIN_PASSPHRASE="wrap-in-place-test-pass" \
  node "${BIN_DEV_ARGS[@]}" "$BIN" keygen --wrap-in-place >/dev/null
node -e "
const fs = require('fs');
const { armor } = require('age-encryption');
const raw = fs.readFileSync(process.argv[1]);
fs.writeFileSync(process.argv[1], armor.encode(new Uint8Array(raw)));
" "$ARMOR_HOME/identity.age"
grep -q -- '-----BEGIN AGE ENCRYPTED FILE-----' "$ARMOR_HOME/identity.age" || { echo "FAIL: test setup: identity.age was not actually armored"; exit 1; }
ARMORED_SHA="$(shasum -a 256 "$ARMOR_HOME/identity.age" | cut -d' ' -f1)"
set +e
OUT=$(CIPHER_BRAIN_HOME="$ARMOR_HOME" node "${BIN_DEV_ARGS[@]}" "$BIN" keygen --wrap-in-place 2>&1); RC=$?
set -e
if [ "$RC" = "0" ]; then echo "FAIL: re-wrapping an ASCII-armored already-wrapped identity should refuse, not succeed"; echo "$OUT"; exit 1; fi
printf '%s' "$OUT" | grep -qi "already passphrase-wrapped" || { echo "FAIL: wrong error for re-wrapping an armored already-wrapped identity"; echo "$OUT"; exit 1; }
[ "$(shasum -a 256 "$ARMOR_HOME/identity.age" | cut -d' ' -f1)" = "$ARMORED_SHA" ] || { echo "FAIL: the armored identity was modified despite the refusal — double-wrap corruption"; exit 1; }
echo "[PASS] keygen --wrap-in-place recognizes an ASCII-armored identity as already-wrapped too, refuses, and leaves it byte-identical (no double-wrap corruption)"

echo "== #111 regression: restore --pg requires --yes/CIPHER_BRAIN_YES before pg_restore --clean --if-exists =="
# pg_restore --clean --if-exists DROPs/replaces objects in the target DB — an
# irreversible operation, so it needs the same explicit-opt-in gate as push's
# paid-backend guard above. The gate fires before any decrypt/extract work, so
# this needs no real Postgres and no valid identity for the negative case.
set +e
OUT=$(node "${BIN_DEV_ARGS[@]}" "$BIN" restore --in "$TMP/snap.age" --out-dir "$TMP/pg-noyes-out" --pg "postgres://x/y" 2>&1); RC=$?
set -e
[ "$RC" != "0" ] || { echo "[FAIL] restore --pg without --yes exited 0"; exit 1; }
printf '%s' "$OUT" | grep -qi "CIPHER_BRAIN_YES\|--yes" \
  || { echo "[FAIL] restore --pg without --yes error lacks --yes guidance"; echo "$OUT"; exit 1; }
test ! -e "$TMP/pg-noyes-out" || { echo "[FAIL] the consent gate ran AFTER out-dir was created"; exit 1; }
echo "[PASS] restore --pg without --yes fails with clear guidance, before touching --out-dir"
# --yes (or CIPHER_BRAIN_YES=1) passes the gate — the error moves further in (this
# snapshot has no db.dump, so it now fails on THAT check instead), proving the gate
# no longer blocks. Needs the correct identity ($TMP/keys, snap.age's recipient).
set +e
OUT2=$(CIPHER_BRAIN_HOME="$TMP/keys" node "${BIN_DEV_ARGS[@]}" "$BIN" restore --in "$TMP/snap.age" --out-dir "$TMP/pg-yes-out" --pg "postgres://x/y" --yes 2>&1); RC2=$?
set -e
[ "$RC2" != "0" ] || { echo "[FAIL] restore --pg --yes against a snapshot with no db.dump exited 0"; exit 1; }
printf '%s' "$OUT2" | grep -qi "no db.dump in snapshot" \
  || { echo "[FAIL] --yes did not pass the consent gate (expected to fail further in, on the missing db.dump)"; echo "$OUT2"; exit 1; }
set +e
OUT3=$(CIPHER_BRAIN_HOME="$TMP/keys" CIPHER_BRAIN_YES=1 node "${BIN_DEV_ARGS[@]}" "$BIN" restore --in "$TMP/snap.age" --out-dir "$TMP/pg-envyes-out" --pg "postgres://x/y" 2>&1); RC3=$?
set -e
[ "$RC3" != "0" ] || { echo "[FAIL] restore --pg with CIPHER_BRAIN_YES=1 against a snapshot with no db.dump exited 0"; exit 1; }
printf '%s' "$OUT3" | grep -qi "no db.dump in snapshot" \
  || { echo "[FAIL] CIPHER_BRAIN_YES=1 did not pass the consent gate"; echo "$OUT3"; exit 1; }
echo "[PASS] --yes and CIPHER_BRAIN_YES=1 both pass the consent gate (fail further in: missing db.dump)"

echo "== #112 regression: restore --keep-old-files does not clobber a pre-existing file in --out-dir =="
KOF_OUT="$TMP/keep-old-out"
mkdir -p "$KOF_OUT"
SENTINEL="PRE-EXISTING-DO-NOT-OVERWRITE-$(od -An -N4 -tx1 /dev/urandom | tr -d ' ')"
printf '%s\n' "$SENTINEL" > "$KOF_OUT/manifest.json"   # same top-level name a real restore would extract
CIPHER_BRAIN_HOME="$TMP/keys" node "${BIN_DEV_ARGS[@]}" "$BIN" restore --in "$TMP/snap.age" --out-dir "$KOF_OUT" >/dev/null
[ "$(cat "$KOF_OUT/manifest.json")" = "$SENTINEL" ] || { echo "[FAIL] restore overwrote a pre-existing file in --out-dir (missing --keep-old-files)"; exit 1; }
test -f "$KOF_OUT/brain-src.tar.gz" || { echo "[FAIL] restore did not extract the non-colliding component alongside the kept file"; exit 1; }
echo "[PASS] restore --keep-old-files preserves a pre-existing file in --out-dir while extracting the rest of the archive around it"

echo "== #106 regression: pg_restore is bounded by a timeout (a wedged pg_restore can't hang the CLI) =="
# A fake pg_dump/pg_restore pair: pg_dump behaves normally (so the snapshot really
# gets a db.dump component); pg_restore just sleeps, simulating a wedged/hung
# process. run()'s timeout SIGKILLs on expiry (proc.ts) — no SIGTERM-ignoring
# trick needed, unlike the pipeline-tar wedge test above.
FAKE_PGBIN_R="$TMP/fake-pgbin-restore-timeout"; mkdir -p "$FAKE_PGBIN_R"
cat > "$FAKE_PGBIN_R/pg_dump" <<'SHIM'
#!/usr/bin/env bash
out=""; prev=""
for a in "$@"; do
  if [ "$prev" = "-f" ]; then out="$a"; fi
  prev="$a"
done
printf 'fake-pg-dump-content\n' > "$out"
exit 0
SHIM
chmod +x "$FAKE_PGBIN_R/pg_dump"
cat > "$FAKE_PGBIN_R/pg_restore" <<'SHIM'
#!/usr/bin/env bash
exec sleep 30
SHIM
chmod +x "$FAKE_PGBIN_R/pg_restore"
PGTO_SNAP="$TMP/pg-timeout-snap.age"
CIPHER_BRAIN_HOME="$TMP/keys" CIPHER_BRAIN_PG_BIN="$FAKE_PGBIN_R" \
  node "${BIN_DEV_ARGS[@]}" "$BIN" snapshot --dir "$SRC" --pg "postgres://fake/conn" --out "$PGTO_SNAP" >/dev/null
PGTO_OUT="$TMP/pg-timeout-out"
START=$(date +%s)
set +e
TERR=$(CIPHER_BRAIN_HOME="$TMP/keys" CIPHER_BRAIN_PG_BIN="$FAKE_PGBIN_R" CIPHER_BRAIN_PIPE_TIMEOUT=600 \
  node "${BIN_DEV_ARGS[@]}" "$BIN" restore --in "$PGTO_SNAP" --out-dir "$PGTO_OUT" --pg "postgres://fake/scratch" --yes 2>&1); TRC=$?
set -e
ELAPSED=$(( $(date +%s) - START ))
[ "$TRC" != "0" ] || { echo "[FAIL] restore with a wedged pg_restore exited 0"; exit 1; }
printf '%s' "$TERR" | grep -qi "timed out" || { echo "[FAIL] no timeout error surfaced for a wedged pg_restore"; echo "$TERR"; exit 1; }
[ "$ELAPSED" -lt 15 ] || { echo "[FAIL] pg_restore took ${ELAPSED}s — timeoutMs did not bound it (< the 30s stub sleep)"; exit 1; }
echo "[PASS] a wedged pg_restore is killed by the timeout in ${ELAPSED}s instead of hanging the CLI"

echo "== #215: --scan-secrets warn|deny (gitleaks) =="
# This whole section is deliberately explicit about CIPHER_BRAIN_HOME="$TMP/keys" on
# EVERY invocation (snapshot AND restore) rather than relying on the ambient exported
# default — the export was repointed to "$TMP/keys2" earlier in this script (line ~216),
# so a bare `cb` call and an explicit "$TMP/keys" override would silently use TWO
# DIFFERENT identities/recipients (a snapshot's ciphertext would then not decrypt with
# the identity a paired restore call explicitly names).
echo "== #215: --scan-secrets is validated up front (bad value refused before any work) =="
set +e
BADMODE_ERR=$(CIPHER_BRAIN_HOME="$TMP/keys" cb snapshot --dir "$SRC" --out "$TMP/badmode.age" --scan-secrets bogus 2>&1); BADMODE_RC=$?
set -e
[ "$BADMODE_RC" != "0" ] || { echo "[FAIL] --scan-secrets bogus was accepted"; exit 1; }
printf '%s' "$BADMODE_ERR" | grep -q 'must be "warn" or "deny"' || { echo "[FAIL] wrong error for --scan-secrets bogus"; echo "$BADMODE_ERR"; exit 1; }
test ! -e "$TMP/badmode.age" || { echo "[FAIL] --scan-secrets bogus still produced an output file"; exit 1; }
echo "[PASS] --scan-secrets rejects anything other than warn/deny, before any --out is created"

if ! command -v gitleaks >/dev/null 2>&1; then
  echo "[SKIP] --scan-secrets warn/deny tests: no \`gitleaks\` binary on PATH (install it — https://github.com/gitleaks/gitleaks — to exercise this; CI installs it via the .github/workflows/ci.yml step, see #215)"
else
  # A DUMMY, obviously-fake AWS-access-key-SHAPED string (sequential alphabet, never a
  # real credential) — just enough to match gitleaks' default aws-access-token rule so
  # this proves the wiring, not gitleaks' own detection accuracy.
  SECRETS_SRC="$TMP/secrets-src"; mkdir -p "$SECRETS_SRC"
  printf 'AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP\n' > "$SECRETS_SRC/config.env"
  CLEAN_SRC="$TMP/clean-secrets-src"; mkdir -p "$CLEAN_SRC"
  printf 'nothing secret here\n' > "$CLEAN_SRC/note.txt"

  echo "== #215: default (no --scan-secrets) is unchanged — a snapshot with a secret still succeeds silently =="
  CIPHER_BRAIN_HOME="$TMP/keys" cb snapshot --dir "$SECRETS_SRC" --out "$TMP/nosca.age" >/dev/null
  test -f "$TMP/nosca.age" || { echo "[FAIL] default (no --scan-secrets) snapshot did not produce an output file"; exit 1; }
  echo "[PASS] omitting --scan-secrets leaves existing behavior unchanged (no scan, no refusal)"

  echo "== #215: --scan-secrets warn proceeds despite a finding, and records rule ID + count (never the secret) in the manifest =="
  WARN_SNAP="$TMP/warn.age"
  WARN_ERR=$(CIPHER_BRAIN_HOME="$TMP/keys" cb snapshot --dir "$SECRETS_SRC" --out "$WARN_SNAP" --scan-secrets warn 2>&1)
  test -f "$WARN_SNAP" || { echo "[FAIL] --scan-secrets warn refused to produce a snapshot despite being warn-mode"; echo "$WARN_ERR"; exit 1; }
  printf '%s' "$WARN_ERR" | grep -qi "gitleaks found" || { echo "[FAIL] --scan-secrets warn did not report the finding"; echo "$WARN_ERR"; exit 1; }
  printf '%s' "$WARN_ERR" | grep -q "AKIAABCDEFGHIJKLMNOP" && { echo "[FAIL] the actual dummy secret value leaked into --scan-secrets warn output"; echo "$WARN_ERR"; exit 1; }
  WARN_OUT="$TMP/warn-restored"
  CIPHER_BRAIN_HOME="$TMP/keys" node "${BIN_DEV_ARGS[@]}" "$BIN" restore --in "$WARN_SNAP" --out-dir "$WARN_OUT" >/dev/null
  WARN_MANIFEST="$WARN_OUT/manifest.json"
  test -f "$WARN_MANIFEST" || { echo "[FAIL] restore did not extract manifest.json"; exit 1; }
  node -e "
    const m = JSON.parse(require('node:fs').readFileSync('$WARN_MANIFEST', 'utf8'));
    if (m.scan_secrets_mode !== 'warn') { console.error('manifest scan_secrets_mode = ' + JSON.stringify(m.scan_secrets_mode) + ', expected \"warn\"'); process.exit(1); }
    const c = m.components.find((x) => /^secrets-src/.test(x.name));
    if (!c) { console.error('no secrets-src component in manifest'); process.exit(1); }
    if (!Array.isArray(c.secrets_scan) || c.secrets_scan.length === 0) { console.error('component.secrets_scan missing/empty: ' + JSON.stringify(c.secrets_scan)); process.exit(1); }
    const f = c.secrets_scan.find((x) => x.rule_id === 'aws-access-token');
    if (!f || f.count < 1) { console.error('expected an aws-access-token finding with count >= 1, got: ' + JSON.stringify(c.secrets_scan)); process.exit(1); }
    const raw = JSON.stringify(m);
    if (raw.includes('AKIAABCDEFGHIJKLMNOP')) { console.error('the dummy secret VALUE leaked into manifest.json'); process.exit(1); }
  " || { echo "[FAIL] manifest.json did not record rule ID + count for the --scan-secrets warn finding (or leaked the secret value)"; cat "$WARN_MANIFEST"; exit 1; }
  echo "[PASS] --scan-secrets warn proceeds, logs the finding, and records only rule ID + count in the manifest — never the secret value"

  echo "== #215: --scan-secrets deny refuses the whole snapshot when a finding exists (no --out produced) =="
  DENY_SNAP="$TMP/deny.age"
  set +e
  DENY_ERR=$(CIPHER_BRAIN_HOME="$TMP/keys" cb snapshot --dir "$SECRETS_SRC" --out "$DENY_SNAP" --scan-secrets deny 2>&1); DENY_RC=$?
  set -e
  [ "$DENY_RC" != "0" ] || { echo "[FAIL] --scan-secrets deny exited 0 despite a finding"; exit 1; }
  printf '%s' "$DENY_ERR" | grep -qi "refusing to snapshot" || { echo "[FAIL] --scan-secrets deny did not explain the refusal"; echo "$DENY_ERR"; exit 1; }
  printf '%s' "$DENY_ERR" | grep -q "AKIAABCDEFGHIJKLMNOP" && { echo "[FAIL] the actual dummy secret value leaked into --scan-secrets deny output"; echo "$DENY_ERR"; exit 1; }
  test ! -e "$DENY_SNAP" || { echo "[FAIL] --scan-secrets deny still produced an output file"; exit 1; }
  test ! -e "$DENY_SNAP.part" || { echo "[FAIL] --scan-secrets deny left a .part file behind"; exit 1; }
  echo "[PASS] --scan-secrets deny aborts the snapshot before any ciphertext is written, without leaking the secret value"

  echo "== #215: --scan-secrets deny still succeeds on a source with no findings =="
  CIPHER_BRAIN_HOME="$TMP/keys" cb snapshot --dir "$CLEAN_SRC" --out "$TMP/deny-clean.age" --scan-secrets deny >/dev/null
  test -f "$TMP/deny-clean.age" || { echo "[FAIL] --scan-secrets deny refused a clean source"; exit 1; }
  echo "[PASS] --scan-secrets deny only refuses when gitleaks actually finds something"

  echo "== #215: --scan-secrets refuses clearly (naming gitleaks) when the binary can't be resolved, regardless of the real host's PATH =="
  # Same isolated-PATH technique selftest-schedule.sh uses for pg_dump: build a PATH
  # containing ONLY the one binary this check itself shells out to (a POSIX shell, to run
  # `command -v gitleaks` — see gitleaksAvailable() in src/lib/secrets-scan.ts), so
  # gitleaks is guaranteed unresolvable no matter what the real host has installed. node
  # is invoked via its absolute path so it needs no PATH entry of its own.
  NODE_BIN_215="$(command -v node)"
  ISOLATED_PATH_215="$TMP/isolated-path-215"; mkdir -p "$ISOLATED_PATH_215"
  ln -s "$(command -v sh)" "$ISOLATED_PATH_215/sh"
  set +e
  MISS_ERR=$(CIPHER_BRAIN_HOME="$TMP/keys" PATH="$ISOLATED_PATH_215" "$NODE_BIN_215" "${BIN_DEV_ARGS[@]}" "$BIN" snapshot --dir "$CLEAN_SRC" --out "$TMP/miss.age" --scan-secrets warn 2>&1); MISS_RC=$?
  set -e
  [ "$MISS_RC" != "0" ] || { echo "[FAIL] --scan-secrets warn (isolated PATH, no gitleaks) was accepted"; exit 1; }
  printf '%s' "$MISS_ERR" | grep -qi "gitleaks" || { echo "[FAIL] the missing-gitleaks error does not name gitleaks"; echo "$MISS_ERR"; exit 1; }
  printf '%s' "$MISS_ERR" | grep -qi "brew install gitleaks" || { echo "[FAIL] the missing-gitleaks error does not suggest an install command"; echo "$MISS_ERR"; exit 1; }
  test ! -e "$TMP/miss.age" || { echo "[FAIL] a snapshot was produced despite gitleaks being unresolvable"; exit 1; }
  echo "[PASS] --scan-secrets fails fast (before any pg_dump/tar work) with an actionable error when gitleaks cannot be resolved"
fi

echo
echo "SELFTEST PASS"
