// Standalone arlocal launcher. Run in a SEPARATE process from the round-trip test:
// the test spawns the cipher-brain CLI (which itself spawns tar/age), and if arlocal
// ran in that same process its listening socket would be inherited by those children
// and deadlock the synchronous spawn. Keeping arlocal out-of-process avoids that.
// Usage: node scripts/arlocal-server.mjs <port>
import ArLocalPkg from 'arlocal';
const ArLocal = ArLocalPkg.default ?? ArLocalPkg;
const port = Number(process.argv[2] || 1984);
const arlocal = new ArLocal(port, false);
await arlocal.start();
console.error(`arlocal listening on ${port}`);
const stop = async () => { try { await arlocal.stop(); } finally { process.exit(0); } };
process.on('SIGTERM', stop);
process.on('SIGINT', stop);
