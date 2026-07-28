#!/usr/bin/env bash
# Selftest for `cipher-brain doctor` (#201): the read-only environment health check.
#
# Covers, in order:
#   (a) a not-yet-set-up CIPHER_BRAIN_HOME: every check SKIPs, health_score 100, PASS.
#   (b) a freshly keygen'd home: home-dir-perms / identity-perms / identity-recipient-
#       pairing all PASS.
#   (c) a loose (group/other-accessible) identity.age is a NEW FAIL with a `chmod 600`
#       remediation, and the process exit code is 1.
#   (d) running doctor AGAIN with the SAME unfixed problem marks it "known" (carryover),
#       not 🆕 new — and health_score for the carryover run is HIGHER than the first
#       run's (the known-issue discount), while VERDICT stays FAIL and health_score
#       stays below 100 (the discount must never look like a full pass — the specific
#       regression this test exists to catch: an earlier draft of the scoring excluded
#       carryover issues ENTIRELY, so a single unfixed FAIL still read 100/100 next to
#       VERDICT: FAIL).
#   (e) fixing the permission is reported as [RESOLVED] on the next run, back to PASS.
#   (f) CIPHER_BRAIN_PIN_RECIPIENTS="" is a FAIL (matches snapshot()'s own #101
#       fail-closed behavior) with a remediation naming the variable.
#   (g) an identity/recipient pairing mismatch (recipient.txt replaced independently) is
#       a FAIL naming both paths.
#   (h) --json prints exactly one JSON document with the documented shape, and it agrees
#       with the human-readable report's verdict.
#   (i) doctor never CREATES $CIPHER_BRAIN_HOME (no side effect on a machine with
#       nothing set up yet — the read-only posture the CLI help promises).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/bin/cipher-brain.mjs"
source "$ROOT/scripts/dev-node-flags.sh"
TMP="$(mktemp -d)"
trap 'chmod -R u+rwX "$TMP" 2>/dev/null || true; rm -rf "$TMP"' EXIT

# Start from a clean CIPHER_BRAIN_* environment (same reasoning as selftest-schedule.sh:
# a PIN_RECIPIENTS/AR_WALLET/etc. left over in whoever-runs-this's own shell would leak
# into every case below).
for _leaked in $(env | sed -n 's/^\(CIPHER_BRAIN_[A-Za-z0-9_]*\)=.*/\1/p'); do unset "$_leaked"; done
unset _leaked

cb() { node "${BIN_DEV_ARGS[@]}" "$BIN" "$@"; }

echo "== (a) a not-yet-set-up home: every check SKIPs, health_score 100, PASS, exit 0 =="
export CIPHER_BRAIN_HOME="$TMP/fresh-home"
[ ! -e "$CIPHER_BRAIN_HOME" ] || { echo "[FAIL] test setup: $CIPHER_BRAIN_HOME already exists"; exit 1; }
RC=0
cb doctor > "$TMP/a.log" 2>&1 || RC=$?
[ "$RC" = "0" ] || { echo "[FAIL] doctor on a not-yet-set-up home exited $RC, expected 0"; cat "$TMP/a.log"; exit 1; }
grep -q '^health_score: 100/100 (no issues found)$' "$TMP/a.log" \
  || { echo "[FAIL] expected health_score 100/100 (no issues found)"; cat "$TMP/a.log"; exit 1; }
grep -q '^VERDICT: PASS$' "$TMP/a.log" || { echo "[FAIL] expected VERDICT: PASS"; cat "$TMP/a.log"; exit 1; }
[ ! -e "$CIPHER_BRAIN_HOME" ] \
  || { echo "[FAIL] doctor CREATED $CIPHER_BRAIN_HOME — it must stay read-only when nothing is set up yet"; exit 1; }
echo "[PASS] not-yet-set-up home: all SKIP, health_score 100/100, VERDICT PASS, no side effect"

echo "== (b) after keygen: home-dir-perms / identity-perms / identity-recipient-pairing all PASS =="
export CIPHER_BRAIN_HOME="$TMP/home"
cb keygen > "$TMP/keygen.log" 2>&1 || { echo "[FAIL] keygen exited non-zero"; cat "$TMP/keygen.log"; exit 1; }
cb doctor --json > "$TMP/b.json" 2>&1 || { echo "[FAIL] doctor --json exited non-zero after keygen"; cat "$TMP/b.json"; exit 1; }
node -e "
const j = JSON.parse(require('node:fs').readFileSync(process.argv[1], 'utf8'));
const byId = Object.fromEntries(j.checks.map((c) => [c.id, c]));
for (const id of ['home-dir-perms', 'identity-perms', 'identity-recipient-pairing']) {
  if (!byId[id] || byId[id].status !== 'pass') {
    throw new Error(id + ' expected status pass, got ' + JSON.stringify(byId[id]));
  }
}
if (j.verdict !== 'PASS') throw new Error('expected verdict PASS, got ' + j.verdict);
if (j.health_score !== 100) throw new Error('expected health_score 100, got ' + j.health_score);
" "$TMP/b.json"
echo "[PASS] freshly keygen'd home: home-dir-perms/identity-perms/identity-recipient-pairing PASS"

echo "== (c) a loose identity.age is a NEW FAIL with a chmod 600 remediation, exit 1 =="
chmod 644 "$CIPHER_BRAIN_HOME/identity.age"
RC=0
cb doctor > "$TMP/c.log" 2>&1 || RC=$?
[ "$RC" = "1" ] || { echo "[FAIL] doctor with a loose identity.age exited $RC, expected 1"; cat "$TMP/c.log"; exit 1; }
grep -E '^\[FAIL\] .+ new .*identity \(private key\) at .*identity\.age is group/other-accessible \(mode 644\)' "$TMP/c.log" \
  || { echo "[FAIL] expected a NEW FAIL line for the loose identity.age"; cat "$TMP/c.log"; exit 1; }
grep -qF "remediation: chmod 600 $CIPHER_BRAIN_HOME/identity.age" "$TMP/c.log" \
  || { echo "[FAIL] expected the exact chmod 600 remediation command"; cat "$TMP/c.log"; exit 1; }
FIRST_SCORE="$(sed -n 's/^health_score: \([0-9]*\)\/100.*/\1/p' "$TMP/c.log")"
[ "$FIRST_SCORE" -lt 100 ] || { echo "[FAIL] health_score did not drop below 100 for a new FAIL (got $FIRST_SCORE)"; exit 1; }
echo "[PASS] loose identity.age: NEW FAIL, exact chmod remediation, exit 1, health_score $FIRST_SCORE/100"

echo "== (d) the SAME unfixed problem on the next run is 'known' (carryover), not new; VERDICT stays FAIL and health_score stays below 100 =="
RC=0
cb doctor > "$TMP/d.log" 2>&1 || RC=$?
[ "$RC" = "1" ] || { echo "[FAIL] second doctor run (still unfixed) exited $RC, expected 1"; cat "$TMP/d.log"; exit 1; }
grep -E '^\[FAIL\] \(known since [0-9]{4}-[0-9]{2}-[0-9]{2}\) .*identity \(private key\)' "$TMP/d.log" \
  || { echo "[FAIL] expected the SAME unfixed FAIL to be marked '(known since ...)', not 🆕 new"; cat "$TMP/d.log"; exit 1; }
if grep -qF 'new age identity' "$TMP/d.log"; then
  echo "[FAIL] the already-seen identity.age FAIL was marked new again — carryover tracking is not working"; cat "$TMP/d.log"; exit 1
fi
SECOND_SCORE="$(sed -n 's/^health_score: \([0-9]*\)\/100.*/\1/p' "$TMP/d.log")"
grep -q '^VERDICT: FAIL$' "$TMP/d.log" || { echo "[FAIL] expected VERDICT: FAIL to persist while the problem is unfixed"; cat "$TMP/d.log"; exit 1; }
[ "$SECOND_SCORE" -lt 100 ] \
  || { echo "[FAIL] a lingering, known FAIL must still pull health_score below 100 (regression: a full score/verdict mismatch), got $SECOND_SCORE/100"; exit 1; }
[ "$SECOND_SCORE" -gt "$FIRST_SCORE" ] \
  || { echo "[FAIL] a known/carryover FAIL should cost LESS than a brand-new one (first=$FIRST_SCORE, second=$SECOND_SCORE)"; exit 1; }
echo "[PASS] carryover: marked known (not new), VERDICT FAIL persists, health_score $SECOND_SCORE/100 (discounted, still < 100)"

echo "== (e) fixing the permission is reported [RESOLVED] on the next run, back to PASS =="
chmod 600 "$CIPHER_BRAIN_HOME/identity.age"
RC=0
cb doctor > "$TMP/e.log" 2>&1 || RC=$?
[ "$RC" = "0" ] || { echo "[FAIL] doctor after fixing the permission exited $RC, expected 0"; cat "$TMP/e.log"; exit 1; }
grep -qF '[RESOLVED] identity-perms:' "$TMP/e.log" \
  || { echo "[FAIL] expected identity-perms to be reported [RESOLVED]"; cat "$TMP/e.log"; exit 1; }
grep -q '^VERDICT: PASS$' "$TMP/e.log" || { echo "[FAIL] expected VERDICT: PASS once the permission is fixed"; cat "$TMP/e.log"; exit 1; }
echo "[PASS] fixed permission: [RESOLVED] reported, back to VERDICT PASS"

echo "== (f) CIPHER_BRAIN_PIN_RECIPIENTS=\"\" is a FAIL naming the fix (#101 fail-closed behavior) =="
RC=0
CIPHER_BRAIN_PIN_RECIPIENTS="" cb doctor > "$TMP/f.log" 2>&1 || RC=$?
[ "$RC" = "1" ] || { echo "[FAIL] doctor with an empty PIN_RECIPIENTS exited $RC, expected 1"; cat "$TMP/f.log"; exit 1; }
grep -qF 'CIPHER_BRAIN_PIN_RECIPIENTS is set but EMPTY' "$TMP/f.log" \
  || { echo "[FAIL] expected the empty-pin FAIL message"; cat "$TMP/f.log"; exit 1; }
grep -qF 'remediation: unset CIPHER_BRAIN_PIN_RECIPIENTS' "$TMP/f.log" \
  || { echo "[FAIL] expected a remediation naming CIPHER_BRAIN_PIN_RECIPIENTS"; cat "$TMP/f.log"; exit 1; }
echo "[PASS] empty CIPHER_BRAIN_PIN_RECIPIENTS: FAIL with the unset remediation"

echo "== (g) an identity/recipient pairing mismatch is a FAIL naming both files =="
cp "$CIPHER_BRAIN_HOME/recipient.txt" "$TMP/recipient.txt.bak"
# A syntactically valid but UNRELATED age1 recipient (68 bech32 chars after 'age1',
# matching AGE_PUBKEY_RE) — recipientEntries()/identityToRecipient() only care about
# shape, not that it maps to a real keypair, since this check never encrypts anything.
printf 'age1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpq5s0kwc\n' > "$CIPHER_BRAIN_HOME/recipient.txt"
RC=0
cb doctor > "$TMP/g.log" 2>&1 || RC=$?
[ "$RC" = "1" ] || { echo "[FAIL] doctor with a mismatched recipient.txt exited $RC, expected 1"; cat "$TMP/g.log"; exit 1; }
grep -E "does not match $CIPHER_BRAIN_HOME/recipient\.txt" "$TMP/g.log" \
  || { echo "[FAIL] expected the identity/recipient pairing mismatch FAIL"; cat "$TMP/g.log"; exit 1; }
cp "$TMP/recipient.txt.bak" "$CIPHER_BRAIN_HOME/recipient.txt"
echo "[PASS] identity/recipient mismatch: FAIL naming both paths"

echo "== (h) --json: exactly one JSON document, shape matches the human-readable report =="
JOUT="$(cb doctor --json)"
LINES=$(printf '%s\n' "$JOUT" | wc -l | tr -d ' ')
[ "$LINES" = "1" ] || { echo "[FAIL] doctor --json printed $LINES stdout line(s), expected exactly 1"; echo "$JOUT"; exit 1; }
node -e "
const j = JSON.parse(process.argv[1]);
for (const key of ['checks', 'resolved', 'health_score', 'new_count', 'carryover_count', 'verdict', 'state_path', 'state_saved']) {
  if (!(key in j)) throw new Error('missing top-level key: ' + key);
}
if (!Array.isArray(j.checks) || j.checks.length === 0) throw new Error('expected a non-empty checks array');
for (const c of j.checks) {
  for (const key of ['id', 'status', 'message', 'marker']) {
    if (!(key in c)) throw new Error('check ' + JSON.stringify(c) + ' missing key: ' + key);
  }
  if (!['pass', 'warn', 'fail', 'skip'].includes(c.status)) throw new Error('unexpected status: ' + c.status);
  if (![null, 'new', 'carryover'].includes(c.marker)) throw new Error('unexpected marker: ' + c.marker);
}
if (!['PASS', 'FAIL', 'PARTIAL'].includes(j.verdict)) throw new Error('unexpected verdict: ' + j.verdict);
if (j.verdict !== 'PASS' && j.health_score >= 100) throw new Error('verdict ' + j.verdict + ' but health_score is ' + j.health_score + ' — score/verdict must not disagree');
if (typeof j.state_saved !== 'boolean') throw new Error('expected state_saved to be a boolean');
" "$JOUT"
echo "[PASS] --json: exactly one document, documented shape, score/verdict agree"

echo "== (i) the bookkeeping file itself never holds key material =="
STATE="$CIPHER_BRAIN_HOME/doctor-state.json"
[ -f "$STATE" ] || { echo "[FAIL] expected $STATE to have been written by now"; exit 1; }
if grep -qE 'AGE-SECRET-KEY|age1' "$STATE"; then
  echo "[FAIL] doctor-state.json contains what looks like key material — it must hold only check ids/timestamps"; cat "$STATE"; exit 1
fi
echo "[PASS] doctor-state.json holds no key material"

echo
echo "all cipher-brain doctor selftests passed"
