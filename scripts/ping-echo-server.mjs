// Minimal local-only HTTP request logger used ONLY by
// scripts/selftest-schedule.sh's --ping-url dead man's switch coverage (issue #202).
// Binds an OS-assigned port (no hardcoded-port flake — same convention as
// arlocal-server.mjs / arweave-roundtrip.mjs's inline listeners: `listen(0, ...)`),
// appends one line per request ("<METHOD> <path>") to a log file, and always
// responds 200 — the selftest greps that log file to prove the generated nightly
// runner's curl actually fired against the expected URL, without any real network
// request ever leaving the machine.
// Usage: node scripts/ping-echo-server.mjs <hits-log-file>
import { createServer } from 'node:http';
import { appendFileSync } from 'node:fs';

const hitsFile = process.argv[2];
if (!hitsFile) {
  console.error('usage: node ping-echo-server.mjs <hits-log-file>');
  process.exit(1);
}

const server = createServer((req, res) => {
  appendFileSync(hitsFile, `${req.method} ${req.url}\n`);
  res.writeHead(200);
  res.end('ok');
});

server.listen(0, '127.0.0.1', () => {
  // The selftest polls stdout for this exact line to learn the assigned port.
  console.log(`READY:${server.address().port}`);
});

const stop = () => {
  server.close(() => process.exit(0));
};
process.on('SIGTERM', stop);
process.on('SIGINT', stop);
