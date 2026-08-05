#!/usr/bin/env node
// Proof for #341: what `push` reports about credits before an irreversible paid upload.
//
// The bug being pinned is not cosmetic. On a real 459 MB monthly push, this line said
//
//   turbo: Turbo Credit balance: 0 winc (~0.00000000 AR)
//
// and the upload then spent ~4.7T winc from a Credit Share Approval and succeeded. The
// signer's OWN balance is structurally 0 in the funding flow docs/arweave-upload-runbook.md
// documents (credits bought on a browser wallet that cannot sign here, then shared to the
// JWK), so the one number the operator sees at the moment of spending was guaranteed to be
// the alarming, useless one — "did my top-up not land?" — every single time.
//
// Like selftest-progress.mjs (#283), the surface itself cannot be tested honestly: a real
// turbo upload needs a funded wallet and actual, irreversible spend. So the reporting
// logic is separated from the upload and exercised directly here, against the ACTUAL wire
// shape the payment service returns — the fixtures below are the real bodies observed
// during that push and the top-up that preceded it, with the amounts kept verbatim.
import { summarizeBalance, balanceLines, reachableCredit } from '../src/lib/balance.ts';

let failed = 0;
const check = (name, cond, detail) => {
  if (cond) console.log(`[PASS] ${name}`);
  else {
    failed++;
    console.log(`[FAIL] ${name}${detail ? ` — ${detail}` : ''}`);
  }
};

const PAYER = '0x1b2c2Fda8d1fA0c734E9F0EadEaddEaa7C14c865';
const SIGNER = 'h1h8Z2iwzUAjydHhYaJAD3KgS2K1qshFIZmXtPIK830';

// Verbatim from the live service immediately after the 2026-08 push: the signer holds
// nothing, yet 626476237410 winc remain reachable through the payer's approval.
const REAL_BODY = {
  winc: '0',
  balance: '0',
  controlledWinc: '0',
  effectiveBalance: '626476237410',
  givenApprovals: [],
  receivedApprovals: [
    {
      approvalDataItemId: 'JNFdO_pG3-R7DQG4ETG8iK-l1uoQo2dpWhUPxRuNlrM',
      approvedAddress: SIGNER,
      approvedWincAmount: '5344300000000',
      creationDate: '2026-08-04T14:05:07.463Z',
      payingAddress: PAYER,
      usedWincAmount: '4717823762590',
      expirationDate: '2026-08-11T14:05:07.465Z',
    },
  ],
};

// --- the regression itself -------------------------------------------------------
{
  const bal = summarizeBalance(REAL_BODY);
  check("summarize: the signer's own balance still reads 0 (unchanged)", bal.own === '0', bal.own);
  check(
    'summarize: the effective figure is the approval-backed one, NOT the signer own balance (#341)',
    bal.effective === '626476237410',
    bal.effective,
  );

  const lines = balanceLines(bal, PAYER).join('\n');
  check(
    'report: the reachable line is present and carries the amount THIS upload can draw',
    lines.includes('reachable for this upload') && lines.includes('626476237410 winc'),
    lines,
  );
  check(
    'report: the drawn-on approval is named, with what is left and when it lapses',
    lines.includes(`via approval from ${PAYER}: 626476237410 winc left`) &&
      lines.includes('expires 2026-08-11T14:05:07.465Z'),
    lines,
  );
  // The exact shape of the pre-fix failure: a report whose ONLY balance figure is 0 while
  // an approval is about to fund the upload.
  const only0 = lines.split('\n').filter((l) => /balance|reachable/.test(l));
  check(
    'report: the operator is never shown 0 as the only balance figure while credit is reachable',
    !(only0.length === 1 && /: 0 winc/.test(only0[0])),
    lines,
  );
}

// --- negative control: a self-funded wallet must NOT gain a redundant second line ----
{
  const bal = summarizeBalance({ winc: '5000000000000', effectiveBalance: '5000000000000' });
  const lines = balanceLines(bal, '');
  check(
    'report: own == reachable prints ONE line, not the same number twice',
    lines.length === 1 && lines[0].includes('5000000000000 winc'),
    JSON.stringify(lines),
  );
}

// --- reachable ≠ effective: only PAID_BY's approvals count (Codex review) ----------
{
  const bal = summarizeBalance(REAL_BODY);
  // With PAID_BY unset, the approval exists but the upload cannot draw on it: reachable
  // must be the own balance (0), and the effective figure must be explained as stranded —
  // NOT presented as spendable. This is the overstatement the round-1 implementation had.
  const { winc } = reachableCredit(bal, '');
  check('reachable: with PAID_BY unset, an approval adds NOTHING to what this upload can spend', winc === 0n, winc);
  const lines = balanceLines(bal, '').join('\n');
  check(
    'report: with PAID_BY unset, the effective figure is explained as unreachable, not shown as spendable',
    lines.includes('cannot draw on') && !lines.includes('reachable for this upload'),
    lines,
  );
  check(
    'report: a PAID_BY naming a different payer claims no approval either',
    !balanceLines(bal, SIGNER).some((l) => l.includes('via approval')),
    JSON.stringify(balanceLines(bal, SIGNER)),
  );
  check(
    'report: an ETH payer in the other case still resolves to the same approval',
    balanceLines(bal, PAYER.toLowerCase()).some((l) => l.includes('via approval')),
    JSON.stringify(balanceLines(bal, PAYER.toLowerCase())),
  );
}

// --- one payer, several approvals: ALL of them are drawable and must be summed -----
{
  const second = {
    ...REAL_BODY.receivedApprovals[0],
    approvalDataItemId: 'second',
    approvedWincAmount: '1000000000010',
    usedWincAmount: '10',
    expirationDate: '2030-01-01T00:00:00.000Z',
  };
  const bal = summarizeBalance({
    ...REAL_BODY,
    effectiveBalance: '1626476237410',
    receivedApprovals: [REAL_BODY.receivedApprovals[0], second],
  });
  const { winc, approvals } = reachableCredit(bal, PAYER);
  check(
    'reachable: several approvals from the SAME payer are summed, not first-match-wins',
    winc === 626476237410n + 1000000000000n && approvals.length === 2,
    `${winc} across ${approvals.length}`,
  );
  const lines = balanceLines(bal, PAYER).join('\n');
  check(
    'report: each drawn-on approval gets its own line',
    lines.includes('626476237410 winc left') && lines.includes('1000000000000 winc left'),
    lines,
  );
}

// --- an expiry we could not read must not be printed as though it were a date ------
// It also must not COUNT: an approval whose deadline cannot be evaluated is excluded
// from reachable credit, same rule as wallet balance.
{
  const body = {
    ...REAL_BODY,
    receivedApprovals: [{ ...REAL_BODY.receivedApprovals[0], expirationDate: '2026-02-30T00:00:00.000Z' }],
  };
  const bal = summarizeBalance(body);
  check(
    'reachable: an unevaluatable expiry excludes the approval from what can be drawn',
    reachableCredit(bal, PAYER).winc === 0n,
    reachableCredit(bal, PAYER).winc,
  );
  const lines = balanceLines(bal, PAYER).join('\n');
  check('report: a rolled-over calendar date is never printed as a deadline', !lines.includes('expires'), lines);
}

// --- a body the summarizer cannot trust must THROW, so push reports why ------------
// push catches this and prints "could not read the credit balance (...)" rather than
// silently dropping the line, which is what made a missing balance indistinguishable
// from a zero one before.
{
  let threw = false;
  try {
    summarizeBalance({ winc: 12345 });
  } catch {
    threw = true;
  }
  check('summarize: a malformed winc throws rather than reporting a guessed balance', threw);
}

console.log(failed ? 'PUSH BALANCE REPORT SELFTEST: FAIL' : 'PUSH BALANCE REPORT SELFTEST: PASS');
process.exit(failed ? 1 : 0);
