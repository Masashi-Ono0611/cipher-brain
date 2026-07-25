#!/usr/bin/env bash
# selftest: $CIPHER_BRAIN_HOME/config.env (#286).
#
# Every assertion here was written to FAIL before the feature existed. The ones that
# matter most are not "a value from the file is used" but the three that decide whether
# the design holds:
#
#   (c) an explicit environment variable still WINS over the file — the precedence comes
#       from Node's own loader, and a regression there would silently override what an
#       operator typed on the command line;
#   (f) an unknown CIPHER_BRAIN_* key is REFUSED through the normal error path, on BOTH
#       entry points — a module-body throw would escape cli.ts's main().catch and print a
#       raw stack trace, and an unchecked mcp.ts would serve as if nothing were wrong;
#   (g) `schedule install` still bakes file-derived values into the runner — the property
#       that lets the file exist without changing what an unattended run does.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLI="$ROOT/dist/cli.mjs"
MCP="$ROOT/dist/mcp.mjs"
[ -f "$CLI" ] || { echo "[FAIL] $CLI missing — run npm run build first"; exit 1; }

TMP="$(mktemp -d)"
trap 'chmod -R u+rwX "$TMP" 2>/dev/null || true; rm -rf "$TMP"' EXIT

SRC="$TMP/src"; mkdir -p "$SRC"; printf 'hello\n' > "$SRC/a.md"

# Each case gets its own CIPHER_BRAIN_HOME so a bad config in one cannot leak into another.
new_home() { local h="$TMP/$1"; mkdir -p "$h"; printf '%s' "$h"; }
write_cfg() { printf '%s\n' "${@:2}" > "$1/config.env"; chmod 600 "$1/config.env"; }

echo "== (a) no config file at all is the normal case, not an error =="
H="$(new_home none)"
CIPHER_BRAIN_HOME="$H" node "$CLI" --version >/dev/null 2>&1 \
  || { echo "[FAIL] a missing config file broke the CLI"; exit 1; }
echo "[PASS] a missing config.env is not an error"

echo "== (b) a value in the file is applied =="
H="$(new_home applied)"; STORE="$TMP/store-from-file"
write_cfg "$H" "CIPHER_BRAIN_FILE_DIR=$STORE"
export CIPHER_BRAIN_HOME="$H"
node "$CLI" keygen >/dev/null 2>&1
node "$CLI" snapshot --dir "$SRC" --out "$TMP/s.age" >/dev/null 2>&1
LOC="$(node "$CLI" push --in "$TMP/s.age" --backend file 2>/dev/null | grep '\.age$')"
case "$LOC" in
  "$STORE"/*) echo "[PASS] the file's CIPHER_BRAIN_FILE_DIR was used ($LOC)" ;;
  *) echo "[FAIL] the file's CIPHER_BRAIN_FILE_DIR was ignored — locator=$LOC, expected under $STORE"; exit 1 ;;
esac

echo "== (c) an explicit environment variable WINS over the file =="
ENVSTORE="$TMP/store-from-env"
LOC="$(CIPHER_BRAIN_FILE_DIR="$ENVSTORE" node "$CLI" push --in "$TMP/s.age" --backend file --force 2>/dev/null | grep '\.age$')"
case "$LOC" in
  "$ENVSTORE"/*) echo "[PASS] env beat the file ($LOC)" ;;
  *) echo "[FAIL] the file overrode an explicit env var — locator=$LOC, expected under $ENVSTORE"; exit 1 ;;
esac

echo "== (d) CIPHER_BRAIN_HOME in the file is ignored, and says so =="
H="$(new_home selfhome)"
write_cfg "$H" "CIPHER_BRAIN_HOME=/somewhere/else"
OUT="$(CIPHER_BRAIN_HOME="$H" node "$CLI" --version 2>&1 >/dev/null)"
printf '%s' "$OUT" | grep -q 'sets CIPHER_BRAIN_HOME, which is ignored' \
  || { echo "[FAIL] no warning for CIPHER_BRAIN_HOME in the file: $OUT"; exit 1; }
CIPHER_BRAIN_HOME="$H" node "$CLI" --version >/dev/null 2>&1 \
  || { echo "[FAIL] CIPHER_BRAIN_HOME in the file was fatal; it should warn and continue"; exit 1; }
echo "[PASS] CIPHER_BRAIN_HOME in the file warns and is ignored"

echo "== (e) a group-readable config file warns but still works =="
H="$(new_home loose)"
write_cfg "$H" "CIPHER_BRAIN_AR_HOST=example.invalid"
chmod 644 "$H/config.env"
OUT="$(CIPHER_BRAIN_HOME="$H" node "$CLI" --version 2>&1 >/dev/null)"
printf '%s' "$OUT" | grep -q 'group/other-accessible' \
  || { echo "[FAIL] no loose-permission warning for the config file: $OUT"; exit 1; }
CIPHER_BRAIN_HOME="$H" node "$CLI" --version >/dev/null 2>&1 \
  || { echo "[FAIL] a group-readable config file was fatal; it should warn and continue"; exit 1; }
echo "[PASS] a group-readable config file warns without refusing"

echo "== (f) an unknown CIPHER_BRAIN_* key is refused, through the NORMAL error path =="
H="$(new_home unknown)"
write_cfg "$H" "CIPHER_BRAIN_MAXSPEND=1"
if CIPHER_BRAIN_HOME="$H" node "$CLI" --version >/dev/null 2>&1; then
  echo "[FAIL] an unknown CIPHER_BRAIN_* key was accepted"; exit 1
fi
OUT="$(CIPHER_BRAIN_HOME="$H" node "$CLI" --version 2>&1 >/dev/null || true)"
printf '%s' "$OUT" | grep -q '^error: config file .*unknown setting' \
  || { echo "[FAIL] the refusal did not use the CLI's 'error: …' form (a module-body throw would print a stack trace): $OUT"; exit 1; }
printf '%s' "$OUT" | grep -q 'CIPHER_BRAIN_MAXSPEND' \
  || { echo "[FAIL] the refusal did not name the offending key: $OUT"; exit 1; }
printf '%s' "$OUT" | grep -qi 'at loadConfigFile\|^\s*at ' \
  && { echo "[FAIL] the refusal printed a stack trace instead of a clean error: $OUT"; exit 1; }
# ...and --json still yields a parseable error object (#270), not a crash
JSON="$(CIPHER_BRAIN_HOME="$H" node "$CLI" estimate --in "$TMP/s.age" --backend file --json 2>/dev/null || true)"
printf '%s' "$JSON" | node -e '
  let s=""; process.stdin.on("data",d=>s+=d).on("end",()=>{
    const o=JSON.parse(s); if(typeof o.error!=="string"||o.exit_code!==1) throw new Error("bad error object: "+s);
  });' || { echo "[FAIL] --json did not produce a well-formed error object for a bad config file"; exit 1; }
# ...and the MCP server refuses to serve rather than starting up as if unconfigured
MOUT="$(printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}' \
  | CIPHER_BRAIN_HOME="$H" timeout 20 node "$MCP" 2>&1 >/dev/null || true)"
printf '%s' "$MOUT" | grep -q 'unknown setting' \
  || { echo "[FAIL] the MCP server started despite a config file it could not accept: $MOUT"; exit 1; }
echo "[PASS] an unknown key is refused on the CLI (error: + --json) and by the MCP server"

echo "== (f2) a key outside the CIPHER_BRAIN_ namespace is left alone =="
H="$(new_home foreign)"
write_cfg "$H" "EDITOR=vim" "CIPHER_BRAIN_AR_HOST=example.invalid"
CIPHER_BRAIN_HOME="$H" node "$CLI" --version >/dev/null 2>&1 \
  || { echo "[FAIL] a non-CIPHER_BRAIN_ key in the file was rejected; the file is not ours to police"; exit 1; }
echo "[PASS] a foreign key is neither rejected nor our business"

echo "== (g) schedule install BAKES a file-derived value into the runner =="
H="$(new_home baked)"; BAKESTORE="$TMP/store-baked"
write_cfg "$H" "CIPHER_BRAIN_FILE_DIR=$BAKESTORE" "CIPHER_BRAIN_SCHEDULE_DIR=$H/sched" "CIPHER_BRAIN_LAUNCHD_DIR=$H/agents"
mkdir -p "$H/agents"
export CIPHER_BRAIN_HOME="$H"
node "$CLI" keygen >/dev/null 2>&1
node "$CLI" schedule install --dir "$SRC" --backend file --no-load >/dev/null 2>&1 \
  || { echo "[FAIL] schedule install failed with a config file present"; exit 1; }
grep -q "export CIPHER_BRAIN_FILE_DIR='$BAKESTORE'" "$H/sched/nightly.sh" \
  || { echo "[FAIL] the runner did not bake the file-derived CIPHER_BRAIN_FILE_DIR"; sed -n '1,40p' "$H/sched/nightly.sh"; exit 1; }
echo "[PASS] a value that came from the config file is baked into the runner like any other"

echo "== (h) schedule status names the file it loaded =="
node "$CLI" schedule status 2>/dev/null | grep -q "config file: $H/config.env" \
  || { echo "[FAIL] schedule status did not report the loaded config file"; exit 1; }
node "$CLI" schedule status --json 2>/dev/null | node -e '
  let s=""; process.stdin.on("data",d=>s+=d).on("end",()=>{
    const o=JSON.parse(s);
    if(!o.config_file || !o.config_file.path) throw new Error("no config_file in --json: "+s);
    if(!Array.isArray(o.config_file.variables) || !o.config_file.variables.includes("CIPHER_BRAIN_FILE_DIR"))
      throw new Error("config_file.variables did not list the settings: "+s);
  });' || { echo "[FAIL] schedule status --json did not report the config file"; exit 1; }
echo "[PASS] schedule status reports the config file, human-readable and in --json"

echo "CONFIG FILE SELFTEST: PASS"
