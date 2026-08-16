#!/usr/bin/env node
// Pre-rename entry point, kept so an MCP client config that still points here keeps
// working after the cipher-brain -> cypher-brain rename. Everything lives in
// bin/cypher-brain-mcp.mjs.
await import('./cypher-brain-mcp.mjs');
