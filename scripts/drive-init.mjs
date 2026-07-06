#!/usr/bin/env node
// drive-init.mjs — a tiny, purpose-built driver for scripts/selftest-init.sh: spawns
// an interactive child process (`cipher-brain init`) and feeds it a SCRIPTED sequence
// of answers, each one sent only once the child's own combined stdout+stderr contains
// the corresponding expected prompt substring.
//
// Why not just pipe a static file of answers (like `printf 'y\n\nn\n...' | cb init`)?
// Node's readline (non-TTY/piped mode) does not queue 'line' events for later — if
// several answer lines are already sitting in the input pipe's kernel buffer when
// more than one arrives before the awaiting code has re-attached its NEXT
// `question()` listener (there is real async work — keygen, disk writes — between
// this wizard's prompts), the extra 'line' events fire with no listener attached and
// are silently DROPPED, wedging the wizard on its next `question()` forever
// (confirmed empirically while building this test). Pacing each answer to the
// prompt it actually answers — one at a time, only once that prompt has genuinely
// been printed — avoids ever having more than one answer in flight.
import { spawn } from 'node:child_process';
import { writeFileSync, readFileSync } from 'node:fs';

function usage() {
  console.error('usage: drive-init.mjs --qa <qa.json> --out <transcript.log> -- <cmd> [args...]');
  process.exit(2);
}

const args = process.argv.slice(2);
const qaIdx = args.indexOf('--qa');
const outIdx = args.indexOf('--out');
const sepIdx = args.indexOf('--');
if (qaIdx === -1 || outIdx === -1 || sepIdx === -1 || sepIdx + 1 >= args.length) usage();

const qa = JSON.parse(readFileSync(args[qaIdx + 1], 'utf8')); // [[waitForSubstring, answerToSend], ...]
const outPath = args[outIdx + 1];
const [cmd, ...cmdArgs] = args.slice(sepIdx + 1);

const child = spawn(cmd, cmdArgs, { stdio: ['pipe', 'pipe', 'pipe'] });
let transcript = '';
let qaIndex = 0;

function tryAdvance() {
  while (qaIndex < qa.length) {
    const [waitFor, send] = qa[qaIndex];
    if (!transcript.includes(waitFor)) return;
    child.stdin.write(`${send}\n`);
    qaIndex++;
  }
}

child.stdout.on('data', (d) => { transcript += d.toString('utf8'); tryAdvance(); });
child.stderr.on('data', (d) => { transcript += d.toString('utf8'); tryAdvance(); });

const exitCode = await new Promise((resolve) => {
  child.on('close', (code, signal) => resolve(code ?? (signal ? 1 : 1)));
  child.on('error', () => resolve(1));
});

writeFileSync(outPath, transcript);
if (qaIndex < qa.length) {
  const unused = qa.slice(qaIndex).map(([waitFor]) => waitFor);
  console.error(
    `drive-init.mjs: FAIL — only ${qaIndex}/${qa.length} scripted prompts were seen before the child exited (rc=${exitCode}); ` +
    `${unused.length} scripted answer(s) were never consumed — see ${outPath}\n` +
    `unused prompts (waitFor):\n${unused.map((s) => `  - ${JSON.stringify(s)}`).join('\n')}`
  );
  process.exit(1);
}
process.exit(exitCode);
