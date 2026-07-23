#!/usr/bin/env bash
# Storage round-trip proof for the RCLONE backend (issue #204): cipher-brain never
# implements a cloud storage API itself — it shells out to `rclone copyto`, the same
# "delegate to rclone" pattern restic/kopia use, and the locator IS the "<remote>:
# <path>" string itself. Exercised here against rclone's built-in, config-less
# `:local:` on-the-fly remote (a real rclone backend, just pointed at a local temp
# dir) — proving the actual `rclone` binary is invoked end-to-end, with NO real
# cloud storage or rclone.conf entry involved.
#
# Auto-SKIPs (exit 0) when the `rclone` binary is absent — same posture as
# selftest-interop.sh's `age`-binary check: the point of this backend is that
# operators bring their own rclone, so CI (which does not install it) skips the
# live round-trip and only the environment doesn't have it can't otherwise prove.
set -euo pipefail

if ! command -v rclone >/dev/null 2>&1; then
  echo "[SKIP] rclone selftest: no \`rclone\` binary on PATH — install rclone (https://rclone.org/downloads/) to exercise the rclone backend round-trip"
  exit 0
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/bin/cipher-brain.mjs"
# BIN_DEV_ARGS: literal argv flags to run bin/cipher-brain.mjs against src/*.ts (no
# build step) under plain node — see scripts/dev-node-flags.sh (never an exported
# NODE_OPTIONS string — whitespace-split, breaks under a checkout path with a space).
source "$ROOT/scripts/dev-node-flags.sh"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
export CIPHER_BRAIN_HOME="$TMP/keys"
cb() { node "${BIN_DEV_ARGS[@]}" "$BIN" "$@"; }
sha() { shasum -a 256 "$1" | cut -d' ' -f1; }

# rclone's built-in `:local:` connection-string syntax addresses the local
# filesystem AS a real rclone remote/backend — no rclone.conf entry needed — so this
# proof never touches actual cloud storage while still driving the real `rclone`
# binary through its normal remote-resolution path (not a cipher-brain-side stub).
STORE="$TMP/rclone-store"; mkdir -p "$STORE"
REMOTE=":local:$STORE/snap.age"

MARKER="rclone-marker-$(od -An -N6 -tx1 /dev/urandom | tr -d ' ')"
SRC="$TMP/brain-src"; mkdir -p "$SRC"
printf '%s\n' "$MARKER" > "$SRC/note.txt"

echo "== snapshot =="
cb keygen >/dev/null
cb snapshot --dir "$SRC" --out "$TMP/snap.age"
ORIG=$(sha "$TMP/snap.age")

echo "== push --backend rclone --remote (locator IS the --remote string) =="
LOC=$(cb push --in "$TMP/snap.age" --backend rclone --remote "$REMOTE")
[ "$LOC" = "$REMOTE" ] || { echo "[FAIL] locator != --remote: $LOC"; exit 1; }
echo "[PASS] locator == --remote string"
[ -f "$STORE/snap.age" ] || { echo "[FAIL] rclone copyto did not land the object at $STORE/snap.age"; exit 1; }
[ "$(sha "$STORE/snap.age")" = "$ORIG" ] && echo "[PASS] object at the rclone remote == source bytes" || { echo "[FAIL] remote byte mismatch"; exit 1; }

echo "== pull --backend rclone --remote (after deleting the original, so it MUST come from the remote) =="
rm -f "$TMP/snap.age"
cb pull --backend rclone --remote "$REMOTE" --out "$TMP/got.age"
[ "$(sha "$TMP/got.age")" = "$ORIG" ] && echo "[PASS] pulled bytes == original (via --remote)" || { echo "[FAIL] pulled byte mismatch"; exit 1; }

echo "== pull --backend rclone --locator (the SAME string also works via the generic --locator flag) =="
cb pull --backend rclone --locator "$REMOTE" --out "$TMP/got-via-locator.age"
[ "$(sha "$TMP/got-via-locator.age")" = "$ORIG" ] && echo "[PASS] pulled bytes == original (via --locator)" || { echo "[FAIL] pulled byte mismatch via --locator"; exit 1; }

echo "== verify + decrypt the pulled ciphertext =="
cb verify --in "$TMP/got.age" | grep -q "VERDICT: PASS" && echo "[PASS] verify VERDICT PASS on pulled" || { echo "[FAIL] verify"; exit 1; }
cb restore --in "$TMP/got.age" --out-dir "$TMP/out"
tar -xzf "$TMP/out/brain-src.tar.gz" -C "$TMP/out"
diff -r "$SRC" "$TMP/out/brain-src"
echo "[PASS] decrypt + restore byte-identical to source"

echo "== push --save-locator + pull --from-locator-file (recovery path) =="
LOCFILE="$TMP/rclone-locator.tsv"
# Re-push the already-pulled artifact (still on disk as $TMP/got.age, byte-identical
# to the original) with --save-locator so --from-locator-file has a real file to
# recover from below.
cb push --in "$TMP/got.age" --backend rclone --remote "$REMOTE" --save-locator "$LOCFILE" >/dev/null
cb pull --from-locator-file "$LOCFILE" --out "$TMP/recovered.age"
[ "$(sha "$TMP/recovered.age")" = "$ORIG" ] && echo "[PASS] --from-locator-file recovery round-trips (backend read back from the saved locator file)" || { echo "[FAIL] recovery byte mismatch"; exit 1; }
grep -q "^${REMOTE//./\\.}"$'\t'"rclone"$'\t' "$LOCFILE" || { echo "[FAIL] save-locator file did not record backend=rclone"; cat "$LOCFILE"; exit 1; }
echo "[PASS] save-locator file records backend=rclone"

echo "== pull refuses to overwrite an existing --out by default (no-clobber, same as every backend) =="
printf 'pre-existing bytes, must survive the refusal\n' > "$TMP/collide.age"
COLLIDE_BEFORE=$(sha "$TMP/collide.age")
if cb pull --backend rclone --remote "$REMOTE" --out "$TMP/collide.age" 2>"$TMP/collide.err"; then
  echo "[FAIL] pull overwrote an existing --out without --force"; exit 1
fi
grep -q "already exists" "$TMP/collide.err" || { echo "[FAIL] no-clobber error message missing 'already exists'"; cat "$TMP/collide.err"; exit 1; }
[ "$(sha "$TMP/collide.age")" = "$COLLIDE_BEFORE" ] || { echo "[FAIL] the pre-existing --out was modified despite the no-clobber refusal"; exit 1; }
echo "[PASS] pull refuses to overwrite an existing --out, which survives byte-identical"

echo "== push --backend rclone without --remote is rejected with an actionable message =="
if cb push --in "$TMP/got.age" --backend rclone 2>"$TMP/noremote.err"; then
  echo "[FAIL] push ran with no --remote"; exit 1
fi
grep -q -- "--remote" "$TMP/noremote.err" || { echo "[FAIL] missing-remote error does not mention --remote"; cat "$TMP/noremote.err"; exit 1; }
echo "[PASS] push --backend rclone without --remote is rejected"

echo "== a missing rclone binary produces an actionable error (not a bare ENOENT) =="
if CIPHER_BRAIN_RCLONE_BIN="$TMP/no-such-rclone-binary" cb push --in "$TMP/got.age" --backend rclone --remote "$REMOTE" 2>"$TMP/missingbin.err"; then
  echo "[FAIL] push succeeded with a nonexistent rclone binary"; exit 1
fi
grep -qi "not found on PATH" "$TMP/missingbin.err" || { echo "[FAIL] missing-binary error is not actionable"; cat "$TMP/missingbin.err"; exit 1; }
echo "[PASS] a missing rclone binary (CIPHER_BRAIN_RCLONE_BIN override) produces an actionable error"

echo "== --remote containing a tab is rejected (would corrupt the tab-delimited save-locator file) =="
BAD_REMOTE="$(printf ':local:%s\tevil' "$STORE")"
if cb push --in "$TMP/got.age" --backend rclone --remote "$BAD_REMOTE" 2>"$TMP/badremote.err"; then
  echo "[FAIL] push accepted a --remote containing a tab"; exit 1
fi
grep -qi "tab or newline" "$TMP/badremote.err" || { echo "[FAIL] tab-in-remote error does not mention 'tab or newline'"; cat "$TMP/badremote.err"; exit 1; }
echo "[PASS] a --remote containing a tab is rejected with an actionable error"

echo "== estimate --backend rclone: free (cost: 0), notes the transfer cost is the operator's own remote/contract =="
EST_OUT=$(cb estimate --in "$TMP/got.age" --backend rclone)
echo "$EST_OUT" | grep -q "^cost: 0$" || { echo "[FAIL] estimate --backend rclone did not report cost: 0"; echo "$EST_OUT"; exit 1; }
echo "[PASS] estimate --backend rclone reports cost: 0"

echo
echo "STORAGE SELFTEST (rclone backend) PASS"
