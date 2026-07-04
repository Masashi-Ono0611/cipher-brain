#!/usr/bin/env bash
# Round-trip proof for --profile source presets (issue #67). The three product
# entry points (claude-code / obsidian / chatgpt-export) must resolve to the
# right paths, compose with extra --dir flags, record the profile name in the
# manifest, and fail loudly (non-zero + a clear error) when their inputs are
# missing. Everything runs on synthetic fixtures under a fake $HOME — no real
# user data is read, no Postgres, no network.
set -euo pipefail

BIN="$(cd "$(dirname "$0")/.." && pwd)/bin/cipher-brain.mjs"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
export CIPHER_BRAIN_HOME="$TMP/keys"
cb() { node "$BIN" "$@"; }

echo "== keygen =="
cb keygen >/dev/null

# synthetic Claude Code home: two projects WITH memory/, one without, + CLAUDE.md
FAKEHOME="$TMP/home"
mkdir -p "$FAKEHOME/.claude/projects/proj-a/memory" \
         "$FAKEHOME/.claude/projects/proj-b/memory" \
         "$FAKEHOME/.claude/projects/no-memory-proj"
printf 'alpha memory\n' > "$FAKEHOME/.claude/projects/proj-a/memory/MEMORY.md"
printf 'beta memory\n'  > "$FAKEHOME/.claude/projects/proj-b/memory/notes.md"
printf 'global instructions\n' > "$FAKEHOME/.claude/CLAUDE.md"

echo "== profile claude-code: picks up 2 memory dirs + CLAUDE.md and round-trips =="
# homedir() honors \$HOME, so the profile reads the synthetic home, not the real one
HOME="$FAKEHOME" cb snapshot --profile claude-code --out "$TMP/cc.age" > "$TMP/cc.log" 2>&1 \
  || { echo "[FAIL] claude-code snapshot failed"; cat "$TMP/cc.log"; exit 1; }
cb restore --in "$TMP/cc.age" --out-dir "$TMP/cc-out" >/dev/null
grep -q '"profile": "claude-code"' "$TMP/cc-out/manifest.json" \
  || { echo "[FAIL] manifest lacks profile claude-code"; cat "$TMP/cc-out/manifest.json"; exit 1; }
N=0
for t in "$TMP/cc-out"/*.tar.gz; do
  X="$TMP/cc-x/$N"; mkdir -p "$X"; tar -xzf "$t" -C "$X"; N=$((N+1))
done
[ "$N" = "3" ] || { echo "[FAIL] expected 3 components (memory x2 + CLAUDE.md), got $N"; exit 1; }
grep -rq 'alpha memory' "$TMP/cc-x"        || { echo "[FAIL] proj-a memory missing from restore"; exit 1; }
grep -rq 'beta memory' "$TMP/cc-x"         || { echo "[FAIL] proj-b memory missing from restore"; exit 1; }
grep -rq 'global instructions' "$TMP/cc-x" || { echo "[FAIL] CLAUDE.md missing from restore"; exit 1; }
echo "[PASS] claude-code profile round-trips 2 project memory dirs + CLAUDE.md (3 components)"

echo "== profile claude-code composes with --dir (extra dirs appended after) =="
EXTRA="$TMP/extra"; mkdir -p "$EXTRA"; printf 'extra stuff\n' > "$EXTRA/e.txt"
HOME="$FAKEHOME" cb snapshot --profile claude-code --dir "$EXTRA" --out "$TMP/mix.age" >/dev/null 2>&1
cb restore --in "$TMP/mix.age" --out-dir "$TMP/mix-out" >/dev/null
MIXN=$(ls "$TMP/mix-out"/*.tar.gz | wc -l | tr -d ' ')
[ "$MIXN" = "4" ] || { echo "[FAIL] profile + --dir expected 4 components, got $MIXN"; exit 1; }
# --dir paths are appended AFTER the profile's paths: the LAST component is the extra dir
LASTNAME=$(grep '"name"' "$TMP/mix-out/manifest.json" | tail -1)
printf '%s' "$LASTNAME" | grep -q 'extra.tar.gz' \
  || { echo "[FAIL] extra --dir is not the last component"; cat "$TMP/mix-out/manifest.json"; exit 1; }
echo "[PASS] --profile + --dir compose (profile paths first, extra dir appended)"

echo "== profile claude-code with an empty home fails with a clear error =="
EMPTYHOME="$TMP/emptyhome"; mkdir -p "$EMPTYHOME"
set +e
ERR=$(HOME="$EMPTYHOME" cb snapshot --profile claude-code --out "$TMP/cc-empty.age" 2>&1); RC=$?
set -e
[ "$RC" != "0" ] || { echo "[FAIL] empty-home claude-code snapshot exited 0"; exit 1; }
printf '%s' "$ERR" | grep -q "found nothing to snapshot" \
  || { echo "[FAIL] empty-profile error is unclear"; echo "$ERR"; exit 1; }
printf '%s' "$ERR" | grep -q "CLAUDE.md" \
  || { echo "[FAIL] empty-profile error does not list what it looked for"; echo "$ERR"; exit 1; }
test ! -f "$TMP/cc-empty.age" || { echo "[FAIL] refused profile snapshot still wrote output"; exit 1; }
echo "[PASS] empty claude-code profile fails non-zero, listing what it looked for"

echo "== profile obsidian: vault (with .obsidian/) round-trips byte-identical =="
VAULT="$TMP/vault"
mkdir -p "$VAULT/.obsidian" "$VAULT/daily"
printf '{}\n' > "$VAULT/.obsidian/app.json"
printf 'vault note\n' > "$VAULT/daily/note.md"
cb snapshot --profile obsidian --vault "$VAULT" --out "$TMP/ob.age" >/dev/null 2>&1
cb restore --in "$TMP/ob.age" --out-dir "$TMP/ob-out" >/dev/null
grep -q '"profile": "obsidian"' "$TMP/ob-out/manifest.json" \
  || { echo "[FAIL] manifest lacks profile obsidian"; exit 1; }
tar -xzf "$TMP/ob-out/vault.tar.gz" -C "$TMP/ob-out"
diff -r "$VAULT" "$TMP/ob-out/vault" || { echo "[FAIL] restored vault differs from source"; exit 1; }
echo "[PASS] obsidian vault round-trips byte-identical (manifest records the profile)"

echo "== profile obsidian: a dir without .obsidian/ is refused unless --force-vault =="
NOTVAULT="$TMP/notavault"; mkdir -p "$NOTVAULT"; printf 'x\n' > "$NOTVAULT/note.md"
set +e
ERR=$(cb snapshot --profile obsidian --vault "$NOTVAULT" --out "$TMP/nv.age" 2>&1); RC=$?
set -e
[ "$RC" != "0" ] || { echo "[FAIL] non-vault dir was accepted without --force-vault"; exit 1; }
printf '%s' "$ERR" | grep -q "does not look like an Obsidian vault" \
  || { echo "[FAIL] non-vault refusal lacks a clear error"; echo "$ERR"; exit 1; }
printf '%s' "$ERR" | grep -q -- "--force-vault" \
  || { echo "[FAIL] non-vault refusal does not mention --force-vault"; echo "$ERR"; exit 1; }
test ! -f "$TMP/nv.age" || { echo "[FAIL] refused vault snapshot still wrote output"; exit 1; }
cb snapshot --profile obsidian --vault "$NOTVAULT" --force-vault --out "$TMP/fv.age" >/dev/null 2>&1 \
  || { echo "[FAIL] --force-vault did not override the vault check"; exit 1; }
test -f "$TMP/fv.age" || { echo "[FAIL] --force-vault snapshot produced no output"; exit 1; }
echo "[PASS] vault check refuses a non-vault dir; --force-vault overrides"

echo "== profile chatgpt-export: the zip round-trips byte-identical (never extracted) =="
ZIP="$TMP/chatgpt-export.zip"
head -c 65536 /dev/urandom > "$ZIP"   # content is opaque to the profile — taken as-is
ZSHA=$(shasum -a 256 "$ZIP" | cut -d' ' -f1)
cb snapshot --profile chatgpt-export --zip "$ZIP" --out "$TMP/gpt.age" >/dev/null 2>&1
cb restore --in "$TMP/gpt.age" --out-dir "$TMP/gpt-out" >/dev/null
grep -q '"profile": "chatgpt-export"' "$TMP/gpt-out/manifest.json" \
  || { echo "[FAIL] manifest lacks profile chatgpt-export"; exit 1; }
grep -q '"kind": "file"' "$TMP/gpt-out/manifest.json" \
  || { echo "[FAIL] zip component is not recorded as kind file"; cat "$TMP/gpt-out/manifest.json"; exit 1; }
tar -xzf "$TMP/gpt-out/chatgpt-export.zip.tar.gz" -C "$TMP/gpt-out"
GSHA=$(shasum -a 256 "$TMP/gpt-out/chatgpt-export.zip" | cut -d' ' -f1)
[ "$ZSHA" = "$GSHA" ] || { echo "[FAIL] restored zip is not byte-identical (expected $ZSHA, got $GSHA)"; exit 1; }
echo "[PASS] chatgpt-export zip round-trips byte-identical as a single file component"

echo "== profile chatgpt-export: a missing / non-.zip path is refused =="
set +e
ERR=$(cb snapshot --profile chatgpt-export --zip "$TMP/does-not-exist.zip" --out "$TMP/gz1.age" 2>&1); RC1=$?
printf 'not a zip\n' > "$TMP/export.tar"
ERR2=$(cb snapshot --profile chatgpt-export --zip "$TMP/export.tar" --out "$TMP/gz2.age" 2>&1); RC2=$?
set -e
[ "$RC1" != "0" ] || { echo "[FAIL] missing zip was accepted"; exit 1; }
printf '%s' "$ERR" | grep -q "no export zip" || { echo "[FAIL] missing-zip error unclear"; echo "$ERR"; exit 1; }
[ "$RC2" != "0" ] || { echo "[FAIL] non-.zip path was accepted"; exit 1; }
printf '%s' "$ERR2" | grep -q "does not end in .zip" || { echo "[FAIL] non-zip error unclear"; echo "$ERR2"; exit 1; }
echo "[PASS] chatgpt-export refuses a missing or non-.zip input"

echo "== unknown profile lists the valid ones =="
set +e
ERR=$(cb snapshot --profile nope --out "$TMP/nope.age" 2>&1); RC=$?
set -e
[ "$RC" != "0" ] || { echo "[FAIL] unknown profile exited 0"; exit 1; }
printf '%s' "$ERR" | grep -q "claude-code, obsidian, chatgpt-export" \
  || { echo "[FAIL] unknown-profile error does not list valid profiles"; echo "$ERR"; exit 1; }
echo "[PASS] unknown profile fails, listing the valid names"

echo
echo "PROFILES SELFTEST PASS"
