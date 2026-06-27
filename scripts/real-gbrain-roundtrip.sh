#!/usr/bin/env bash
# Real-data round-trip proof for the cipher layer (issue #1), operator-run on the
# machine that holds gbrain. Dumps ONE live table, encrypts -> verifies ->
# decrypts -> restores into a throwaway scratch DB, then asserts the row count and
# a content checksum match the source exactly. The scratch DB is dropped at the
# end. Reads/writes only the table and scratch DB you point it at.
#
# Config (env):
#   CB_PG_URL      source gbrain connection (required), e.g. postgres://you@localhost:5432/gbrain
#   CB_TABLE       table to round-trip (default: dream_verdicts) — pick a small, FK-free one
#   CB_SCRATCH_DB  scratch db name (default: gbrain_cipher_test)
#   CIPHER_BRAIN_PG_BIN / CIPHER_BRAIN_AGE   if pg tools / age aren't on PATH
set -euo pipefail

: "${CB_PG_URL:?set CB_PG_URL to your gbrain connection string}"
TBL="${CB_TABLE:-dream_verdicts}"
SCRATCH_DB="${CB_SCRATCH_DB:-gbrain_cipher_test}"
PG_BIN="${CIPHER_BRAIN_PG_BIN:-}"
PSQL="${PG_BIN:+$PG_BIN/}psql"
psql() { command "$PSQL" "$@"; }   # `command` bypasses this function -> runs the real binary

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CLI="$ROOT/bin/cipher-brain.mjs"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
export CIPHER_BRAIN_HOME="$WORK/keys"
SCRATCH_URL="${CB_PG_URL%/*}/$SCRATCH_DB"

echo "== keygen =="
node "$CLI" keygen >/dev/null

echo "== baseline (live table: $TBL) =="
SRC_COUNT=$(psql "$CB_PG_URL" -At -c "select count(*) from $TBL;")
SRC_SUM=$(psql "$CB_PG_URL" -At -c "select md5(coalesce(string_agg(t::text, '' order by t::text),'')) from $TBL t;")
echo "source: count=$SRC_COUNT checksum=$SRC_SUM"

echo "== snapshot -> verify =="
node "$CLI" snapshot --pg "$CB_PG_URL" --pg-table "$TBL" --out "$WORK/snap.age"
node "$CLI" verify --in "$WORK/snap.age"

echo "== scratch db =="
psql "$CB_PG_URL" -c "drop database if exists $SCRATCH_DB;" >/dev/null
psql "$CB_PG_URL" -c "create database $SCRATCH_DB;" >/dev/null
psql "$SCRATCH_URL" -c "create extension if not exists vector;"  >/dev/null 2>&1 || true
psql "$SCRATCH_URL" -c "create extension if not exists pg_trgm;" >/dev/null 2>&1 || true

echo "== restore -> compare =="
node "$CLI" restore --in "$WORK/snap.age" --out-dir "$WORK/out" --pg "$SCRATCH_URL" >/dev/null
DST_COUNT=$(psql "$SCRATCH_URL" -At -c "select count(*) from $TBL;")
DST_SUM=$(psql "$SCRATCH_URL" -At -c "select md5(coalesce(string_agg(t::text, '' order by t::text),'')) from $TBL t;")
echo "restored: count=$DST_COUNT checksum=$DST_SUM"
psql "$CB_PG_URL" -c "drop database if exists $SCRATCH_DB;" >/dev/null

PASS=1
[ "$SRC_COUNT" = "$DST_COUNT" ] && echo "[PASS] row count ($SRC_COUNT)" || { echo "[FAIL] count $SRC_COUNT != $DST_COUNT"; PASS=0; }
[ "$SRC_SUM" = "$DST_SUM" ]     && echo "[PASS] content checksum identical" || { echo "[FAIL] checksum mismatch"; PASS=0; }
[ "$PASS" = 1 ] && { echo; echo "REAL-DATA ROUND-TRIP PASS"; } || { echo; echo "REAL-DATA ROUND-TRIP FAIL"; exit 1; }
