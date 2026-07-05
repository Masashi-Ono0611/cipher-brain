#!/usr/bin/env node
// Thin shim so the MCP server runs straight from the repo with no build step
// (same pattern as bin/cipher-brain.mjs). The server lives in src/mcp.ts; the
// bundled single-file build lands at dist/mcp.mjs (`npm run build`). See
// bin/cipher-brain.mjs for the NODE_OPTIONS this shim needs to resolve
// src/mcp.ts's internal `.js`-specifier imports under plain node.
import '../src/mcp.js';
