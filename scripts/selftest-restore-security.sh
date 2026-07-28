#!/usr/bin/env bash
# Restore security proof (#218): a forged/malicious tar archive — not merely a forged
# manifest.json field, which PR #198 already covers — must be REJECTED before restore
# writes a single byte, and a legitimate archive (including the symlink/hardlink shapes
# snapshot() itself deliberately produces) must still restore correctly.
#
# Threat model reminder (see the comment above inspectRestoreArchive() in
# src/lib/restore.ts): age is public-key encryption, so anyone holding a recipient's
# PUBLIC key can construct ciphertext encrypted to it and hand it over claiming to be
# "your backup" — a forged/malicious TAR PAYLOAD inside such ciphertext is something
# restore must defend against, the same way #198 already made it defend against a forged
# manifest.json.
#
# Each malicious case below is built as a real tar with Python's stdlib `tarfile` module
# (scripts/restore-security-fixtures.py — precise control over path-traversal/absolute-
# path/symlink/hardlink/FIFO/device entries that the `tar` CLI itself will not construct
# on request), wrapped into age ciphertext with the REAL age binary
# (`age -r <recipient> -o out.age in.tar`, the same technique scripts/selftest-interop.sh
# already uses to prove typage<->binary interop) addressed to a keypair this script
# controls, and then handed to `cipher-brain restore`.
#
# Auto-SKIPs (exit 0) when the `age` binary is absent — same posture as
# selftest-interop.sh, which needs it for the identical reason (constructing ciphertext
# outside the CLI's own snapshot() path).
set -euo pipefail

if ! command -v age >/dev/null 2>&1; then
  echo "[SKIP] restore-security selftest: no \`age\` binary on PATH — install age (brew/apt) to exercise this"
  exit 0
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "[SKIP] restore-security selftest: no \`python3\` on PATH — needed to craft malicious tar entries"
  exit 0
fi

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

cb keygen >/dev/null
RECIPIENT="$(cat "$CIPHER_BRAIN_HOME/recipient.txt")"

# Build a raw tar of shape $2 (a CB_TAR_SHAPE the python helper switches on) at $1, then
# wrap it into age ciphertext at $3.
make_age() {
  out_tar="$1"; shape="$2"; out_age="$3"
  CB_TAR_OUT="$out_tar" CB_TAR_SHAPE="$shape" python3 "$ROOT/scripts/restore-security-fixtures.py"
  age -r "$RECIPIENT" -o "$out_age" "$out_tar"
}

# Assert `cb restore` REJECTS $1 (an age file) with an error mentioning $4, and that
# nothing was left behind: no --out-dir at $2, and no scratch directory sibling to it
# either (proves the isolated-scratch + atomic-promote design in restoreImpl never let a
# rejected archive touch disk). Prints its own [PASS]/[FAIL] and exits 1 on failure —
# deliberately NOT meant to be called inside a `$(...)` capture (a caller that did would
# swallow this function's own diagnostic output instead of letting it reach the console).
assert_restore_rejected() {
  in_age="$1"; out_dir="$2"; label="$3"; expect_substr="$4"
  set +e
  ERR=$(cb restore --in "$in_age" --out-dir "$out_dir" 2>&1); RC=$?
  set -e
  if [ "$RC" = "0" ]; then
    echo "[FAIL] $label: restore succeeded, expected rejection"
    exit 1
  fi
  if [ -e "$out_dir" ]; then
    echo "[FAIL] $label: --out-dir was created despite rejection ($out_dir)"
    exit 1
  fi
  # shellcheck disable=SC2086 # deliberate glob, not a single path
  if compgen -G "${out_dir}.restore-*" >/dev/null; then
    echo "[FAIL] $label: a restore scratch directory was left behind (not cleaned up on rejection)"
    exit 1
  fi
  if ! printf '%s' "$ERR" | grep -qi -- "$expect_substr"; then
    echo "[FAIL] $label: error message did not contain the expected text ('$expect_substr')"
    echo "$ERR"
    exit 1
  fi
  echo "[PASS] $label: rejected with the expected message, no --out-dir, no scratch dir left behind"
}

echo "== malicious archives are rejected before anything is written =="

make_age "$TMP/m-traversal.tar" traversal "$TMP/m-traversal.age"
assert_restore_rejected "$TMP/m-traversal.age" "$TMP/out-traversal" "path traversal (..)" 'path traversal'

make_age "$TMP/m-absolute.tar" absolute "$TMP/m-absolute.age"
assert_restore_rejected "$TMP/m-absolute.age" "$TMP/out-absolute" "absolute path entry" 'absolute path'

make_age "$TMP/m-fifo.tar" fifo "$TMP/m-fifo.age"
assert_restore_rejected "$TMP/m-fifo.age" "$TMP/out-fifo" "FIFO entry" 'fifo entry'

make_age "$TMP/m-device.tar" device "$TMP/m-device.age"
assert_restore_rejected "$TMP/m-device.age" "$TMP/out-device" "device entry" 'device entry'

make_age "$TMP/m-hardlink.tar" hardlink-escape "$TMP/m-hardlink.age"
assert_restore_rejected "$TMP/m-hardlink.age" "$TMP/out-hardlink" "hardlink target escapes the tree" 'hardlink target escapes'

# The classic tar path-traversal-through-symlink attack (OWASP's page, #218's own
# citation): a symlink entry named "link" pointing outside the tree, followed by a LATER
# entry "link/pwned.txt" nested under it. If this ever slipped through, the payload would
# land at $TMP/escape-target/pwned.txt (the symlink's target) — assert that file is never
# created, not merely that the command exits non-zero.
mkdir -p "$TMP/escape-target"
CB_SYMLINK_TARGET="$TMP/escape-target" make_age "$TMP/m-symtraverse.tar" symlink-traverse "$TMP/m-symtraverse.age"
assert_restore_rejected "$TMP/m-symtraverse.age" "$TMP/out-symtraverse" "path-traversal-through-symlink" 'path-traversal-through-symlink'
[ ! -e "$TMP/escape-target/pwned.txt" ] || { echo "[FAIL] path-traversal-through-symlink actually wrote outside --out-dir"; exit 1; }
echo "[PASS] path-traversal-through-symlink did not write through the symlink's target"

echo
echo "== legitimate archives snapshot() itself deliberately produces still restore =="

# A plain file tree restores exactly as before (no false positive from the new inspection
# phase on ordinary content).
make_age "$TMP/c-plain.tar" plain "$TMP/c-plain.age"
cb restore --in "$TMP/c-plain.age" --out-dir "$TMP/out-plain" >/dev/null
[ "$(cat "$TMP/out-plain/note.txt")" = "plain-ok" ] || { echo "[FAIL] plain archive restore content mismatch"; exit 1; }
echo "[PASS] a plain file tree restores unchanged"

# snapshot.ts deliberately archives a dangling/absolute-target symlink AS-IS when a --dir
# source is itself a symlink (see restore.ts's own comment above validateRestoreEntries) —
# this must NOT be rejected just because its target is absolute; only a LATER entry
# nested under it is the attack.
make_age "$TMP/c-symlink.tar" symlink-standalone "$TMP/c-symlink.age"
cb restore --in "$TMP/c-symlink.age" --out-dir "$TMP/out-symlink" >/dev/null
[ -L "$TMP/out-symlink/dangling-link" ] || { echo "[FAIL] legitimate standalone symlink entry was not restored"; exit 1; }
echo "[PASS] a legitimate dangling absolute-target symlink entry restores unchanged"

# An in-tree hardlink to a sibling regular file (both same archive, relative names) is
# ordinary tar content with no traversal potential — must restore, not be rejected.
make_age "$TMP/c-hardlink.tar" hardlink-safe "$TMP/c-hardlink.age"
cb restore --in "$TMP/c-hardlink.age" --out-dir "$TMP/out-hardlink-safe" >/dev/null
[ "$(cat "$TMP/out-hardlink-safe/link.txt")" = "hardlink-ok" ] || { echo "[FAIL] legitimate in-tree hardlink did not restore"; exit 1; }
echo "[PASS] a legitimate in-tree hardlink restores unchanged"

echo
echo "RESTORE-SECURITY SELFTEST PASS"
