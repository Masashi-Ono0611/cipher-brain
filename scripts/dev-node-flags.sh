# Shared dev-mode Node flags for running bin/cipher-brain.mjs straight against
# src/*.ts (no build step) under plain node — see scripts/dev-ts-resolve-hook.mjs
# for why both flags are required (#63).
#
# Callers must set ROOT (absolute repo root, no trailing slash) before sourcing
# this file. It defines BIN_DEV_ARGS, a bash array of literal argv elements —
# pass it as "${BIN_DEV_ARGS[@]}" immediately before "$BIN" on every node
# invocation that runs the dev-source (unbundled) CLI, e.g.:
#   node "${BIN_DEV_ARGS[@]}" "$BIN" "$@"
#
# NEVER redo this via an exported NODE_OPTIONS string: NODE_OPTIONS is
# whitespace-split by node, so interpolating an absolute path into it breaks
# under a checkout directory with a space in it. Argv arrays go straight to
# execve and are never shell/whitespace-split, so a space in $ROOT is harmless
# here (the same fix shape as scripts/dev-shim-reexec.mjs and the smoke test's
# BIN_DEV_ARGS, scripts/cli-smoke.sh).
BIN_DEV_ARGS=(--experimental-strip-types --import "$ROOT/scripts/dev-cli-loader.mjs")
