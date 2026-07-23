// Stable, ngrok-style ("CB-E###") error codes for cipher-brain's own most-common
// failure messages (issue #212). ngrok's own docs (https://ngrok.com/docs/errors) are
// the model: a short stable code + a doc link next to the human-readable message, so a
// person mid-incident (or an AI agent wrapping the CLI/MCP tools) can look up cause +
// next action in one place instead of parsing prose.
//
// Design constraint (issue #212): additive only, NEVER touches an existing throw site's
// message text. Every entry below is matched AFTER the fact, against the already-
// formatted error text, at the two places every error funnels through before a human/
// agent sees it — cli.ts's top-level `main().catch` and mcp.ts's `structuredErr()`. That
// keeps every one of the ~100 existing `throw new Error(...)` call sites across
// src/lib/** completely untouched; only those two display boundaries changed.
//
// Coverage is deliberately partial (issue #212 asks for "10-15 representative patterns",
// not exhaustive). An error that matches nothing here is displayed exactly as before,
// with no code appended — that is the intended, safe default, not a bug. Add a new
// entry (+ a matching row in MANAGEMENT.md's "## Error codes" table) whenever a new
// failure pattern turns out to be common enough to deserve one; nothing else needs to
// change.

export interface ErrorCodeEntry {
  /** Stable, never-reused identifier — this repo's equivalent of ERR_NGROK_xxx. */
  readonly code: string;
  /** One-line human title, used only in MANAGEMENT.md's table — never printed at runtime. */
  readonly title: string;
  /** Matched against the fully-formatted error message (errMsg(e)); first match wins. */
  readonly pattern: RegExp;
}

// The doc anchor every annotated message points readers at. Keep in sync with the
// "## Error codes" heading in MANAGEMENT.md (GitHub renders that heading's anchor as
// exactly this slug).
export const ERROR_DOC_REF = 'MANAGEMENT.md#error-codes';

// Order is not currently significant (no two patterns below can both match the same
// message), but new entries should stay specific enough to keep it that way — prefer a
// longer, more literal substring over a broad one that could shadow a future entry.
export const ERROR_CODES: readonly ErrorCodeEntry[] = [
  {
    code: 'CB-E001',
    title: 'integrity pin mismatch — fetched bytes do not match --sha256',
    pattern: /sha256 mismatch: fetched/,
  },
  {
    code: 'CB-E002',
    title: 'age decrypt failed (wrong identity, or corrupt/truncated ciphertext)',
    pattern: /age decrypt failed:/,
  },
  {
    code: 'CB-E003',
    title: 'cannot unwrap a passphrase-protected identity (wrong passphrase?)',
    pattern: /\(wrong passphrase\?\)/,
  },
  {
    code: 'CB-E004',
    title: 'storage object not yet retrievable (upload not yet propagated)',
    pattern: /not mined \/ not found \/ not yet seeded/,
  },
  {
    code: 'CB-E005',
    title: 'recipient rejected by the CIPHER_BRAIN_PIN_RECIPIENTS allowlist',
    pattern: /is NOT in CIPHER_BRAIN_PIN_RECIPIENTS/,
  },
  {
    code: 'CB-E006',
    title: 'spend cap exceeded, or wallet balance insufficient (paid backend)',
    pattern: /exceeds CIPHER_BRAIN_MAX_SPEND|insufficient (?:balance|funds)/i,
  },
  {
    code: 'CB-E007',
    title: 'paid backend upload needs explicit spend consent (--yes)',
    pattern: /spends real funds/,
  },
  {
    code: 'CB-E008',
    title: 'refusing to push non-ciphertext to storage',
    pattern: /not age ciphertext \(header mismatch\)/,
  },
  {
    code: 'CB-E009',
    title: 'refusing to overwrite an existing output (no-clobber)',
    pattern: /already exists — refusing to overwrite/,
  },
  {
    code: 'CB-E010',
    title: 'locator rejected — outside the store, or the wrong shape (possible path traversal)',
    pattern: /locator is outside FILE_DIR|does not match the expected <sha256>\.age shape/,
  },
  {
    code: 'CB-E011',
    title: 'Arweave JWK wallet missing or unreadable',
    pattern: /needs CIPHER_BRAIN_AR_WALLET|cannot read JWK wallet at/,
  },
  {
    code: 'CB-E012',
    title: 'optional storage SDK dependency not installed',
    pattern: /run: npm install (?:@ardrive\/turbo-sdk|arweave)\b/,
  },
  {
    code: 'CB-E013',
    title: 'unknown --backend name',
    pattern: /unknown backend:/,
  },
  {
    code: 'CB-E014',
    title: 'schedule automation not installed, or crontab write failed',
    pattern: /schedule not installed \(no |crontab write failed/,
  },
  {
    code: 'CB-E015',
    title: 'identity file not found (cannot decrypt)',
    pattern: /cannot decrypt without the private key/,
  },
];

/** The first registry entry whose pattern matches `message`, if any. */
export function matchErrorCode(message: string): ErrorCodeEntry | undefined {
  return ERROR_CODES.find((e) => e.pattern.test(message));
}

// Append "[CB-E0xx] see MANAGEMENT.md#error-codes" to an already-formatted error message
// when (and only when) it matches a known pattern; an unmatched message is returned
// byte-for-byte unchanged (issue #212's "additive only" constraint). Call this ONLY at a
// display boundary (cli.ts's top-level catch, mcp.ts's structuredErr) — never at an
// individual throw site, so every existing message body stays exactly as it was.
export function annotateErrorMessage(message: string): string {
  const entry = matchErrorCode(message);
  return entry ? `${message} [${entry.code}] see ${ERROR_DOC_REF}` : message;
}
