// The MCP server's public tool surface, as one list, because it is asserted from two
// places that run in different situations:
//
//   - scripts/mcp-smoke.mjs   — part of `npm run verify`, so every PR runs it
//   - scripts/tarball-smoke.mjs — only in publish.yml's final gate, on a v* tag push
//
// They used to each carry their own inline copy. The release-only one went stale at
// four tools while the server grew to ten, and because publish.yml runs on tags alone
// — and no tag has been pushed (npm publish is still #144) — nothing could catch it
// until a release failed (#290). One list, imported by both, removes the drift rather
// than asking anyone to remember two files.
//
// NOT derived from src/mcp.ts on purpose: tarball-smoke's whole value is driving the
// PACKED, INSTALLED artifact, and checking that against the source it was built from
// would assert nothing about packaging. This is an independently maintained
// expectation, which is what makes it a real gate — when a tool is added or removed
// on purpose, updating this file is the deliberate step that says so.
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
