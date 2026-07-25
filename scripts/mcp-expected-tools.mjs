// The MCP server's public tool surface, as one list, because it is asserted from two
// places that run in different situations:
//
//   - scripts/mcp-smoke.mjs   — part of `npm run verify`, so every PR runs it
//   - scripts/tarball-smoke.mjs — only in publish.yml's final gate, on a v* tag push
//
// They used to each carry their own inline copy. The release-only one went stale at
// four tools while the server grew to ten. Because publish.yml runs on tags alone, and
// no tag has ever been pushed (the registry release is still #144), no run of this
// gate had happened since — the mismatch was found by reproducing it locally (#290),
// not by a failed release. One list, imported by both, removes the drift rather than
// asking anyone to remember two files.
//
// NOT derived from src/mcp.ts on purpose. A source-derived list would still catch some
// packed-vs-source divergence, so that is not the argument; the argument is that this
// list independently states the INTENDED public tool surface. Deriving it would let the
// expectation move whenever the source moves, which is exactly what a gate must not do —
// when a tool is added or removed on purpose, editing this file is the deliberate step
// that says so.
//
// Sorted, because both callers compare against a sorted tools/list response.
export const EXPECTED_MCP_TOOLS = [
  'estimate_cost',
  'keygen',
  'last_snapshot_status',
  'restore_now',
  'schedule_install',
  'schedule_status',
  'snapshot_now',
  'verify_restore',
  'wallet_address',
  'wallet_create',
];
