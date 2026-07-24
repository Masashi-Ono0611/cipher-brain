// Shared shapes that don't belong to any single module: the parsed CLI/MCP options
// bag every command function takes, and the storage-backend contract every
// src/lib/backends/*.ts implements. Kept in one place so cli.ts, mcp.ts and every
// lib/*.ts consumer import the SAME type instead of each hand-rolling its own.

// The flags every "cipher-brain <cmd>" (and its schedule-runner-generating twin)
// can see. `parseArgs` (src/cli.ts) turns `--foo-bar val` into `foo_bar: val` for
// any flag not in BOOL_FLAGS (which get `true`) — genuinely dynamic (any command
// only reads the handful of fields it cares about), so every field beyond the
// three always-initialized arrays is optional rather than a big union of exact
// per-command shapes the parser can't actually guarantee.
export interface CliOptions {
  _?: string; // the schedule/wallet subcommand (install|status|uninstall|create|address) or the top-level positional arg
  dirs: string[];
  tables: string[];
  recipients: string[];
  pg_exclude_table_data?: string[]; // repeatable --pg-exclude-table-data <table>: passed through verbatim to pg_dump

  // boolean flags (BOOL_FLAGS in cli.ts) — absent when not passed
  force?: boolean;
  passphrase?: boolean;
  wrap_in_place?: boolean;
  pq?: boolean; // keygen --pq: post-quantum HYBRID keypair (ML-KEM-768 + X25519, #205)
  yes?: boolean;
  force_vault?: boolean;
  skip_unchanged?: boolean;
  no_load?: boolean;
  no_expand_components?: boolean;
  dry_run?: boolean; // snapshot --dry-run: preview .cipherbrainignore include/exclude without writing anything (#216)
  json?: boolean; // verify/estimate/schedule status: machine-readable JSON on stdout instead of the human-readable report (issue #211)
  sign?: boolean; // keygen --sign: generate a minisign-compatible Ed25519 signing keypair instead of an age identity (#214)
  no_sign?: boolean; // snapshot --no-sign: skip writing a <out>.minisig sidecar even when a signing identity is present (#214)

  // value flags — always a string when passed (argv is untyped text)
  out?: string;
  out_dir?: string;
  profile?: string;
  vault?: string;
  zip?: string;
  pg?: string;
  pg_filter?: string; // --pg-filter <file>: passed through verbatim as pg_dump's --filter <file> (issue #235)
  in?: string;
  identity?: string;
  sha256?: string;
  backend?: string;
  remote?: string; // rclone backend: "<rclone-remote-name>:<path>" (also usable as pull's --locator, since that IS the rclone backend's locator)
  digest?: string;
  save_locator?: string;
  locator?: string;
  scan_secrets?: string; // snapshot --scan-secrets warn|deny (gitleaks, #215) — validated in snapshot.ts, not here (parseArgs can't know the enum)
  from_locator_file?: string;
  sign_identity?: string; // keygen/snapshot: signing PRIVATE key path override (default $CIPHER_BRAIN_HOME/sign-identity.key, #214)
  sign_recipient?: string; // snapshot/restore/verify: signing PUBLIC key path override (default $CIPHER_BRAIN_HOME/sign-recipient.pub, #214)
  sig_locator?: string; // pull: explicit locator for the <out>.minisig sidecar (mirrors --locator; usually read from --from-locator-file's 6th field instead, #214)
  wait?: string;
  at?: string;
  max_spend?: string;
  index_file?: string;
  wallet?: string; // wallet address --wallet <path> (defaults to CIPHER_BRAIN_AR_WALLET)
  ping_url?: string; // schedule install: dead man's switch success ping (healthchecks.io-style)
  ping_url_fail?: string; // schedule install: failure ping override (defaults to `${ping_url}/fail`)
}

// A StorageBackend is { put(file) -> locator, get(locator, outFile) }. Storage
// only ever sees the *.age ciphertext. The locator is whatever the backend
// assigns: a content hash for file (known before upload), or a tx id for
// arweave (assigned AFTER upload) — the interface assumes neither.
export interface PutOpts {
  yes?: boolean;
  remote?: string; // rclone backend only: the "<remote>:<path>" destination (put() throws without it)
}

export interface StorageBackend {
  put(file: string, opts?: PutOpts): Promise<string>;
  get(locator: string, out: string): Promise<void>;
}
