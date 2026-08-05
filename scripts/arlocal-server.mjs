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
// start() resolves BEFORE the bind completes — ArLocal calls app.listen() fire-and-
// forget, so on a taken port it "starts" fine and the process then dies of an
// unhandled EADDRINUSE ~300ms later (measured, #351). The parent treats the line
// below as proof that OUR server owns the port, so it must only ever be printed once
// the socket's own 'listening' event says so; a bind failure exits BEFORE announcing,
// which is what lets the parent tell "our server is up" from "an orphaned previous
// run's server answers this port".
const server = arlocal.getServer();
try {
  await new Promise((resolve, reject) => {
    if (server?.listening) return resolve(undefined);
    if (!server) return reject(new Error('arlocal.getServer() returned nothing — bind state unknowable'));
    // Each outcome detaches the other's listener: the loser would otherwise stay
    // installed for the life of the server (Codex review).
    const onListening = () => {
      server.removeListener('error', onError);
      resolve(undefined);
    };
    const onError = (e) => {
      server.removeListener('listening', onListening);
      reject(e);
    };
    server.once('listening', onListening);
    server.once('error', onError);
  });
} catch (e) {
  console.error(`arlocal failed to bind :${port}: ${e?.message ?? e}`);
  process.exit(1);
}
console.error(`arlocal listening on ${port}`);
// A post-announce socket error (rare) must still be a visible, clean death — the
// parent watches our exit and reports it — not an unhandled-event crash dump.
server.on('error', (e) => {
  console.error(`arlocal server error after listening: ${e?.message ?? e}`);
  process.exit(1);
});
const stop = async () => {
  try {
    await arlocal.stop();
  } finally {
    process.exit(0);
  }
};
process.on('SIGTERM', stop);
process.on('SIGINT', stop);
