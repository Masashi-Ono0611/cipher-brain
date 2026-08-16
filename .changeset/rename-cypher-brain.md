---
"cypher-brain": minor
---

The project is now **cypher-brain** (the cypherpunk spelling). Everything the old name
was wired into keeps working, so an existing install upgrades without an edit:

- Every `CIPHER_BRAIN_*` environment variable and `config.env` key is still read; the
  `CYPHER_BRAIN_*` spelling wins when both are set. A file naming the same setting under
  both spellings is refused as ambiguous.
- The default home stays an existing `~/.cipher-brain` until a `~/.cypher-brain` exists.
- A `.cipherbrainignore` is still honoured when no `.cypherbrainignore` sits beside it.
- The `cipher-brain` / `cipher-brain-mcp` commands remain as aliases of
  `cypher-brain` / `cypher-brain-mcp`, and `bin/cipher-brain.mjs` /
  `bin/cipher-brain-mcp.mjs` still exist as forwarders for a source checkout.
- `schedule install|status|uninstall` recognise a registration made under the old
  `dev.cipher-brain.nightly.<hash>` label / `# cipher-brain-nightly:<hash>` marker (this
  home's own, read from `schedule.json` / `cron.entry`) and migrate it on the next
  install, exactly as the pre-#114 unscoped one is handled — never a machine-wide sweep.

Forward-only (no compatibility needed): the MCP server name and its
`cypher-brain://` resource URI scheme, the `App-Name` tag on new Arweave/Turbo uploads,
the gateway `user-agent`, the temp-directory / sentinel-file prefixes, and the
write-only `manifest.json` provenance field (`cypherbrainignore`; nothing reads it back,
archives made before the rename keep the old key).
