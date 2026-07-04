#!/usr/bin/env node
// Thin shim so the MCP server runs straight from the repo with no build step
// (same pattern as bin/cipher-brain.mjs). The server lives in src/mcp.mjs; the
// bundled single-file build lands at dist/mcp.mjs (`npm run build`).
import '../src/mcp.mjs';
