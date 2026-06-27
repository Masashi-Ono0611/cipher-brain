#!/usr/bin/env bash
# Operator round-trip for the TON backend (issue #2). Run on the machine that hosts
# the storage-daemon. Two daemons on one host:
#   A = the existing seeder (control :15555), B = a fresh leech we start (:15556, db2).
# It attempts a GENUINE content-addressed cross-node fetch — `get-peers` must show A
# as the source, which a same-daemon local read can never satisfy — then decrypts the
# pulled ciphertext and compares. If the two daemons do not peer within the budget
# (the seeder is home-NAT'd and testnet DHT discovery may not rendezvous), it falls
# back to proving integrity + decrypt against the real bag the daemon stored, and
# reports PARTIAL (integrity only) — never a full PASS.
#
# Config (env, with Mac-mini trial defaults):
#   CB_TRIAL_ROOT  default ~/ton-provider-trial   (has bin/ + work/)
#   CB_BIN         default ~/cipher-brain-cli/bin/cipher-brain.mjs
#   CB_LAN_IP      default 192.168.128.156         (this host's LAN IP for daemon B ADNL)
#   CB_PEER_BUDGET default 60  (×3s poll = 3 min)  CIPHER_BRAIN_TON_TIMEOUT bounds the pull
set -uo pipefail

ROOT="${CB_TRIAL_ROOT:-$HOME/ton-provider-trial}"
WORK="$ROOT/work"
DAEMON="$ROOT/bin/storage-daemon"
CLIBIN="$ROOT/bin/storage-daemon-cli"
LANIP="${CB_LAN_IP:-192.168.128.156}"
CB="${CB_BIN:-$HOME/cipher-brain-cli/bin/cipher-brain.mjs}"
PEER_BUDGET="${CB_PEER_BUDGET:-60}"
export PATH="$HOME/.homebrew/bin:$HOME/.homebrew/opt/postgresql@17/bin:$PATH"
export CIPHER_BRAIN_TON_TIMEOUT="${CIPHER_BRAIN_TON_TIMEOUT:-180}"

# portable hard timeout (macOS has no `timeout`): run a command, kill it after N s.
with_timeout() { # with_timeout SECS cmd [args...]
  local secs=$1; shift
  "$@" & local cpid=$!
  ( sleep "$secs"; kill -9 "$cpid" 2>/dev/null ) >/dev/null 2>&1 & local wpid=$!
  wait "$cpid" 2>/dev/null; local rc=$?
  kill -9 "$wpid" 2>/dev/null; wait "$wpid" 2>/dev/null
  return $rc
}
sha() { shasum -a 256 "$1" | cut -d' ' -f1; }
# every control call is bounded so a stuck daemon can never hang the script
A() { with_timeout 20 "$CLIBIN" -I 127.0.0.1:15555 -k "$WORK/db/cli-keys/client"  -p "$WORK/db/cli-keys/server.pub"  -c "$1"; }
B() { with_timeout 20 "$CLIBIN" -I 127.0.0.1:15556 -k "$WORK/db2/cli-keys/client" -p "$WORK/db2/cli-keys/server.pub" -c "$1"; }
FAILED=0; BLOCKED=0
pass(){ echo "[PASS] $1"; }; fail(){ echo "[FAIL] $1"; FAILED=1; }; blk(){ echo "[BLOCKED] $1"; BLOCKED=1; }

# A0 prereq — never fake a result
A "list" >/dev/null 2>&1 || { echo "[BLOCKED] daemon A (:15555) unreachable"; exit 2; }

# A1 build a fresh ciphertext with a known plaintext marker (fresh each run -> no duplicate-bag)
export CIPHER_BRAIN_HOME="$WORK/cb-keys"
MARKER="cipher-marker-$(od -An -N6 -tx1 /dev/urandom | tr -d ' ')"
SRC="$WORK/rt-src"; rm -rf "$SRC"; mkdir -p "$SRC"; printf '%s\n' "$MARKER" > "$SRC/note.txt"
[ -f "$CIPHER_BRAIN_HOME/identity.age" ] || node "$CB" keygen >/dev/null
node "$CB" snapshot --dir "$SRC" --out "$WORK/snap.age"
ORIG=$(sha "$WORK/snap.age")

# A2 push to daemon A (seeder)
export CIPHER_BRAIN_TON_CLI="$CLIBIN" CIPHER_BRAIN_TON_API=127.0.0.1:15555
export CIPHER_BRAIN_TON_CLIENT="$WORK/db/cli-keys/client" CIPHER_BRAIN_TON_SERVER="$WORK/db/cli-keys/server.pub"
BAG=$(node "$CB" push --in "$WORK/snap.age" --backend ton)
[[ "$BAG" =~ ^[0-9A-Fa-f]{64}$ ]] && pass "push -> BagID $BAG (content-addressed)" || { fail "no BagID ($BAG)"; exit 1; }

# A3 start daemon B: fresh db2, distinct control + ADNL ports, NO -P (pure leech)
rm -rf "$WORK/db2"; mkdir -p "$WORK/db2"
nohup "$DAEMON" -v 3 -C "$WORK/testnet-global.config.json" -I "$LANIP:13334" -p 15556 -D "$WORK/db2" -l "$WORK/daemon2.log" >/dev/null 2>&1 &
DPID=$!
trap 'kill $DPID 2>/dev/null' EXIT
for i in $(seq 1 30); do B "list" >/dev/null 2>&1 && break; sleep 1; done
B "list" >/dev/null 2>&1 || { echo "[BLOCKED] daemon B CLI not reachable (db2/cli-keys not auto-provisioned?). See $WORK/daemon2.log"; exit 2; }
pass "daemon B up on :15556 (fresh db2)"

# A4 the bag must be ABSENT on B before the fetch (else a later 'success' is a local read)
B "list --hashes" 2>/dev/null | grep -qi "$BAG" && fail "bag already on B before fetch" || pass "bag absent on B pre-fetch"

# A5 pull on B (downloads over ADNL from A)
export CIPHER_BRAIN_TON_API=127.0.0.1:15556
export CIPHER_BRAIN_TON_CLIENT="$WORK/db2/cli-keys/client" CIPHER_BRAIN_TON_SERVER="$WORK/db2/cli-keys/server.pub"
node "$CB" pull --locator "$BAG" --backend ton --out "$WORK/pulled.age" &
PULLPID=$!

# A6 PEER assert — the network-transfer discriminator (a local read can never satisfy this)
PEERED=0
for i in $(seq 1 "$PEER_BUDGET"); do
  if B "get-peers $BAG" 2>/dev/null | grep -qi "$LANIP"; then PEERED=1; break; fi
  kill -0 "$PULLPID" 2>/dev/null || break
  sleep 3
done
wait "$PULLPID"; PULLRC=$?

if [ "$PEERED" = 1 ]; then
  # --- FULL PATH: cross-node ADNL transfer happened. Prove integrity + decrypt on the PULLED bytes. ---
  pass "get-peers shows daemon A — real ADNL transfer, not a local read"
  if [ "$PULLRC" = 0 ] && [ -f "$WORK/pulled.age" ]; then
    [ "$(sha "$WORK/pulled.age")" = "$ORIG" ] && pass "sha256(pulled) == sha256(original)" || fail "pulled byte mismatch"
    node "$CB" verify --in "$WORK/pulled.age" | grep -q "VERDICT: PASS" && pass "verify VERDICT PASS on pulled" || fail "verify on pulled"
    export CIPHER_BRAIN_HOME="$WORK/cb-keys"
    node "$CB" restore --in "$WORK/pulled.age" --out-dir "$WORK/b-out"
    tar -xzf "$WORK/b-out/rt-src.tar.gz" -C "$WORK/b-out" 2>/dev/null
    { grep -rq "$MARKER" "$WORK/b-out/rt-src" && diff -r "$SRC" "$WORK/b-out/rt-src" >/dev/null; } \
      && pass "decrypt(pulled) == original plaintext (marker present, trees equal)" || fail "decrypt/compare"
  else
    fail "peered but pull produced no ciphertext (rc=$PULLRC)"
  fi
else
  # --- FALLBACK: cross-node transfer BLOCKED on reachability (NAT/DHT). Prove what we still can
  # via the REAL TON bag the daemon stored: it holds the EXACT ciphertext and it still decrypts.
  # This does NOT exercise network transfer (see the filed reachability issue). ---
  blk "get-peers never showed the seeder within budget -> NAT/DHT discovery failed (cross-node transfer not exercised)"
  STORED="$WORK/db/torrent/torrent-files/$BAG"
  SFILE=$(find "$STORED" -type f 2>/dev/null | head -1)
  if [ -n "$SFILE" ] && [ "$(sha "$SFILE")" = "$ORIG" ]; then
    pass "daemon stored the EXACT ciphertext (sha256 of bag file == original)"
  else fail "stored bag bytes mismatch (sfile=$SFILE)"; fi
  export CIPHER_BRAIN_HOME="$WORK/cb-keys"
  node "$CB" restore --in "$SFILE" --out-dir "$WORK/fb-out"
  tar -xzf "$WORK/fb-out/rt-src.tar.gz" -C "$WORK/fb-out" 2>/dev/null
  { grep -rq "$MARKER" "$WORK/fb-out/rt-src" && diff -r "$SRC" "$WORK/fb-out/rt-src" >/dev/null; } \
    && pass "stored ciphertext decrypts to the original plaintext" || fail "decrypt/compare (fallback)"
fi

# A10 storage saw ONLY ciphertext (no plaintext marker at rest under either db)
grep -rqa "$MARKER" "$WORK/db" "$WORK/db2" 2>/dev/null && fail "plaintext marker found under a daemon dir!" \
  || pass "no plaintext marker under daemon storage dirs"

# A11 negative control: a flipped BagID must NOT return bytes
last="${BAG: -1}"; if [ "$last" = "A" ]; then rep=B; else rep=A; fi
BADBAG="${BAG%?}$rep"
export CIPHER_BRAIN_TON_TIMEOUT=15 CIPHER_BRAIN_TON_API=127.0.0.1:15556
if node "$CB" pull --locator "$BADBAG" --backend ton --out "$WORK/bad.age" 2>/dev/null && [ -s "$WORK/bad.age" ]; then
  fail "flipped BagID returned bytes"
else
  pass "negative control: flipped BagID returns nothing (times out)"
fi

echo
if [ "$FAILED" = 1 ]; then echo "TON ROUND-TRIP: FAIL"; exit 1
elif [ "$BLOCKED" = 1 ]; then echo "TON ROUND-TRIP: PARTIAL (integrity proven; cross-node ADNL transfer NOT exercised — necessary-not-sufficient)"; exit 0
else echo "TON ROUND-TRIP: PASS (cross-node ADNL transfer + decrypt verified)"; fi
