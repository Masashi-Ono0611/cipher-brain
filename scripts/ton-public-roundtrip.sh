#!/usr/bin/env bash
# Leech-side proof of a GENUINE cross-node TON Storage fetch (issue #6). Run on a host on a
# DIFFERENT network from the seeder. Given a BagID already pushed to a PUBLIC-IP seeder (see
# docs/ton-public-seeder.md), it starts a throwaway downloader daemon, fetches the bag by
# BagID over the internet, and asserts get-peers shows the seeder (a transfer a local read
# cannot fake), the bytes match (if CB_ORIG_SHA given), and they decrypt (if an identity is
# present). Reports PASS / PARTIAL / FAIL — it never green-stamps a fetch that did not peer.
#
# Required: CB_CONFIG (TON global config json), CB_BAG (BagID), CB_LAN_IP (the downloader IP).
# Optional: CB_SEEDER_IP (assert this exact peer appears), CB_ORIG_SHA (assert byte match),
#   CIPHER_BRAIN_HOME (identity to decrypt), CB_BIN, CB_DAEMON, CB_CLI, CB_PEER_BUDGET.
set -uo pipefail
: "${CB_CONFIG:?set CB_CONFIG to the TON global config json}"
: "${CB_BAG:?set CB_BAG to the BagID to fetch}"
: "${CB_LAN_IP:?set CB_LAN_IP to the downloader host IP}"

ROOT="${CB_TRIAL_ROOT:-$HOME/ton-provider-trial}"
DAEMON="${CB_DAEMON:-$ROOT/bin/storage-daemon}"
CLIBIN="${CB_CLI:-$ROOT/bin/storage-daemon-cli}"
CB="${CB_BIN:-$HOME/cipher-brain-cli/bin/cipher-brain.mjs}"
WORK="$(mktemp -d)"
PEER_BUDGET="${CB_PEER_BUDGET:-100}"   # ×3s poll
export PATH="$HOME/.homebrew/bin:$HOME/.homebrew/opt/postgresql@17/bin:$PATH"
export CIPHER_BRAIN_TON_TIMEOUT="${CIPHER_BRAIN_TON_TIMEOUT:-300}"
DPID=""
trap 'kill $DPID 2>/dev/null; rm -rf "$WORK"' EXIT

sha(){ shasum -a 256 "$1" | head -c 64; }
with_timeout(){ local s=$1; shift; "$@" & local c=$!; ( sleep "$s"; kill -9 "$c" 2>/dev/null ) >/dev/null 2>&1 & local w=$!; wait "$c" 2>/dev/null; local rc=$?; kill -9 "$w" 2>/dev/null; wait "$w" 2>/dev/null; return $rc; }
L(){ with_timeout 20 "$CLIBIN" -I 127.0.0.1:15557 -k "$WORK/db/cli-keys/client" -p "$WORK/db/cli-keys/server.pub" -c "$1"; }
FAILED=0; BLOCKED=0; VERIFIED=0
pass(){ echo "[PASS] $1"; }; fail(){ echo "[FAIL] $1"; FAILED=1; }; blk(){ echo "[BLOCKED] $1"; BLOCKED=1; }

# throwaway downloader daemon: own db, distinct ports, NOT a provider (no -P)
nohup "$DAEMON" -v 3 -C "$CB_CONFIG" -I "$CB_LAN_IP:13335" -p 15557 -D "$WORK/db" -l "$WORK/d.log" >/dev/null 2>&1 &
DPID=$!
for i in $(seq 1 30); do L "list" >/dev/null 2>&1 && break; sleep 1; done
L "list" >/dev/null 2>&1 || { cp "$WORK/d.log" /tmp/ton-public-d.log 2>/dev/null; echo "[BLOCKED] downloader daemon CLI not reachable; see /tmp/ton-public-d.log"; exit 2; }
pass "downloader daemon up (throwaway db)"
L "list --hashes" 2>/dev/null | grep -qi "$CB_BAG" && fail "bag already present before fetch" || pass "bag absent pre-fetch"

# pull by BagID over the internet
export CIPHER_BRAIN_TON_CLI="$CLIBIN" CIPHER_BRAIN_TON_API=127.0.0.1:15557
export CIPHER_BRAIN_TON_CLIENT="$WORK/db/cli-keys/client" CIPHER_BRAIN_TON_SERVER="$WORK/db/cli-keys/server.pub"
node "$CB" pull --locator "$CB_BAG" --backend ton --out "$WORK/pulled.age" & PULLPID=$!

# peer assert: get-peers must show the (remote) seeder — the cross-node discriminator
PEERED=0
for i in $(seq 1 "$PEER_BUDGET"); do
  peers=$(L "get-peers $CB_BAG" 2>/dev/null)
  if [ -n "${CB_SEEDER_IP:-}" ]; then
    echo "$peers" | grep -qF "$CB_SEEDER_IP" && { PEERED=1; break; }
  else
    echo "$peers" | grep -oE "[0-9]{1,3}(\.[0-9]{1,3}){3}" | grep -qv "^${CB_LAN_IP}$" && { PEERED=1; break; }
  fi
  kill -0 "$PULLPID" 2>/dev/null || break
  sleep 3
done
wait "$PULLPID"; PULLRC=$?
[ "$PEERED" = 1 ] && pass "get-peers shows the seeder — real cross-node ADNL transfer" \
                  || blk "no remote peer within budget — UDP/reachability still not open end-to-end"

if [ "$PULLRC" = 0 ] && [ -f "$WORK/pulled.age" ]; then
  if [ -n "${CB_ORIG_SHA:-}" ]; then
    if [ "$(sha "$WORK/pulled.age")" = "$CB_ORIG_SHA" ]; then pass "pulled bytes == original (sha match)"; VERIFIED=1; else fail "pulled byte mismatch"; fi
  fi
  if [ -n "${CIPHER_BRAIN_HOME:-}" ] && [ -f "$CIPHER_BRAIN_HOME/identity.age" ]; then
    node "$CB" verify --in "$WORK/pulled.age" | grep -q "VERDICT: PASS" && pass "verify PASS on pulled" || fail "verify on pulled"
    if node "$CB" restore --in "$WORK/pulled.age" --out-dir "$WORK/out" >/dev/null 2>&1; then pass "pulled ciphertext decrypts"; VERIFIED=1; else fail "decrypt"; fi
  fi
  # peered + downloaded is necessary but NOT sufficient — full PASS needs the content proven
  [ "$VERIFIED" = 0 ] && blk "transfer peered + downloaded, but content NOT verified — set CB_ORIG_SHA and/or a decrypting CIPHER_BRAIN_HOME identity"
elif [ "$PEERED" = 1 ]; then
  fail "peered but pull produced no ciphertext (rc=$PULLRC)"
fi

echo
if [ "$FAILED" = 1 ]; then echo "TON PUBLIC ROUND-TRIP: FAIL"; exit 1
elif [ "$PEERED" != 1 ] || [ "$VERIFIED" != 1 ]; then echo "TON PUBLIC ROUND-TRIP: PARTIAL (cross-node transfer and/or content not fully proven — see [BLOCKED] lines)"; exit 0
else echo "TON PUBLIC ROUND-TRIP: PASS (cross-node ADNL transfer + content verified)"; fi
