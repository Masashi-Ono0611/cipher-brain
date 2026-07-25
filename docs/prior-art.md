# Prior art

Most of this project's feature ideas come from reading what comparable tools
already do well. This file names them.

It serves two purposes at once, and the first is the more important:

1. **Credit.** These projects did the thinking. Ideas are not copyrightable and
   nothing here uses their code — but taking a design without saying where it
   came from is bad manners in a commons this project also depends on. Every row
   below says which project an idea came from and what was taken.
2. **Not repeating ourselves.** Without a record, the next person to go looking
   re-reads the same projects, re-derives the same idea, and files a duplicate
   of an issue that is already open.

Projects whose *code* cipher-brain actually runs are credited in
[`README.md`](../README.md#acknowledgements) instead. The rule for borrowing —
what needs a citation, what needs a license check — is in
[`CONTRIBUTING.md`](../CONTRIBUTING.md#credit-what-you-borrowed).

## How to use it

**Before** proposing a feature borrowed from another project, search for the
project name — then compare **what you want to take** against the "Taken away"
column, not just the name.

A project appearing here does **not** mean every idea it could inspire is
already filed. restic is listed for chunking and staged verification; a restic
idea about something else is a new idea, and should be filed as one. What is
already covered is the *takeaway*, not the project. So:

- Same takeaway as a row → read that issue and comment there. Do not open a
  second one.
- Same project, different takeaway → file it, and say in the issue how it
  differs from the existing row so the next reader is not confused by two
  entries citing one project.

**When** you file an issue whose reasoning is "project X does this", add a row.
One line, in the same sitting: a ledger nobody updates is worse than none,
because it reads as authoritative while being stale. The feature issue form asks
for this, but nothing can enforce it — a row added a week later is a row that
never gets added.

Not everything belongs here — this is for *external projects consulted as a
model*, not for every dependency. `age`/typage, Turbo/ArDrive, `rclone` and
`gitleaks` are integrations cipher-brain builds on, credited in
[`README.md`](../README.md#acknowledgements).

## Surveyed

Two separate things are tracked, because they answer different questions.
**Issue state** is just the linked issue's open/closed state. **Outcome** is
whether the borrowed idea was taken up at all — an open issue means the idea was
accepted as worth doing and has not been built yet, which is not the same as an
idea that was considered and declined.

| Project | Consulted for | Taken away | Issue | Issue state | Outcome |
|---|---|---|---|---|---|
| [restic](https://restic.net) / [Kopia](https://kopia.io) / [BorgBackup](https://borgbackup.org) / [Duplicacy](https://duplicacy.com) | Snapshot-oriented backup CLIs | Content-defined chunking to cut upload cost; staged `verify` levels; a `doctor` health command | [#208](https://github.com/Masashi-Ono0611/cipher-brain/issues/208), [#209](https://github.com/Masashi-Ono0611/cipher-brain/issues/209), [#201](https://github.com/Masashi-Ono0611/cipher-brain/issues/201) | Open | Accepted, not built |
| [Cryptomator](https://cryptomator.org) | Encrypted-vault format design | Separate key material from format version / KDF parameters | [#225](https://github.com/Masashi-Ono0611/cipher-brain/issues/225) | Open | Accepted, not built |
| [zfec](https://github.com/tahoe-lafs/zfec) / [Tahoe-LAFS](https://www.tahoe-lafs.org) | Erasure coding, distributed durability | Redundant fragmented placement for large snapshots | [#224](https://github.com/Masashi-Ono0611/cipher-brain/issues/224) | Open | Accepted, not built |
| [Magic Wormhole](https://magic-wormhole.readthedocs.io) | Short-lived authenticated key exchange | One-time code to authenticate an offline backup recipient at registration | [#223](https://github.com/Masashi-Ono0611/cipher-brain/issues/223) | Open | Accepted, not built |
| Shamir's Secret Sharing | Threshold key recovery | Optional threshold recovery of the identity | [#207](https://github.com/Masashi-Ono0611/cipher-brain/issues/207) | Open | Accepted, not built |
| [age-plugin-yubikey](https://github.com/str4d/age-plugin-yubikey) / FIDO2 | Hardware-backed identities | Protect the identity with a hardware key | [#203](https://github.com/Masashi-Ono0611/cipher-brain/issues/203) | Open | Accepted, not built |
| [libarchive](https://github.com/libarchive/libarchive) | Secure extraction | Two-stage restore: inspect tar entries before extracting, then extract isolated | [#218](https://github.com/Masashi-Ono0611/cipher-brain/issues/218) | Open | Accepted, not built |
| [BagIt](https://datatracker.ietf.org/doc/html/rfc8493) / [RO-Crate](https://www.researchobject.org/ro-crate/) | Long-term archival packaging | Move the decrypted payload toward an interoperable standard layout | [#217](https://github.com/Masashi-Ono0611/cipher-brain/issues/217) | Open | Accepted, not built |
| [AR.IO Wayfinder](https://ar.io) | Verified gateway reads | Replace the plain gateway fetch in `arweave get()` with a verifying one | [#210](https://github.com/Masashi-Ono0611/cipher-brain/issues/210) | Open | Accepted, not built |
| [Socket.dev](https://socket.dev) | Behaviour-based dependency review | Supply-chain scanning that does not depend on a CVE existing | [#213](https://github.com/Masashi-Ono0611/cipher-brain/issues/213) | Open | Accepted, not built |
| [Presidio](https://microsoft.github.io/presidio/) | PII detection | Redact PII before snapshot, so a key compromise leaks less | [#234](https://github.com/Masashi-Ono0611/cipher-brain/issues/234) | Open | Accepted, not built |
| [OpenDP](https://opendp.org) | Differential privacy | A DP aggregate artifact — explicitly *not* a replacement for the raw backup | [#236](https://github.com/Masashi-Ono0611/cipher-brain/issues/236) | Open | Accepted, not built |
| [FOCUS](https://focus.finops.org) / [OpenMeter](https://openmeter.io) | FinOps cost reporting | Persist provider receipts into a cumulative spend ledger | [#232](https://github.com/Masashi-Ono0611/cipher-brain/issues/232) | Open | Accepted, not built |
| [Terraform](https://developer.hashicorp.com/terraform) | `plan` / `apply` consent split | A spend plan that binds the estimate the user consented to, to the push that spends it | [#231](https://github.com/Masashi-Ono0611/cipher-brain/issues/231) | Open | Accepted, not built |
| [@clack/prompts](https://github.com/bombshell-dev/clack) | Interactive CLI prompts | Rework the `init` wizard; handle `NO_COLOR` and screen readers | [#230](https://github.com/Masashi-Ono0611/cipher-brain/issues/230) | Open | Accepted, not built |
| [fast-check](https://fast-check.dev) | Property-based testing | Property tests, the official age test vectors, bounded mutation testing | [#228](https://github.com/Masashi-Ono0611/cipher-brain/issues/228) | Open | Accepted, not built |
| [pino](https://getpino.io) / [OpenTelemetry](https://opentelemetry.io) | Structured logging, tracing | Structured logs, a hash-chained audit trail, opt-in OTel-lite | [#226](https://github.com/Masashi-Ono0611/cipher-brain/issues/226) | Open | Accepted, not built |
| [Changesets](https://github.com/changesets/changesets) / [commitlint](https://commitlint.js.org) | Release automation | Changesets for versioning + Conventional Commits enforced on the PR title | [#227](https://github.com/Masashi-Ono0611/cipher-brain/issues/227) | Closed | **Shipped** ([#274](https://github.com/Masashi-Ono0611/cipher-brain/pull/274)) |
| semantic-release | Release automation | Nothing — evaluated in [#227](https://github.com/Masashi-Ono0611/cipher-brain/issues/227) and **declined** as overlapping Changesets | [#227](https://github.com/Masashi-Ono0611/cipher-brain/issues/227) | Closed | **Declined** |
| [OpenSSF Best Practices](https://www.bestpractices.dev) / [contributing-template](https://github.com/nayafia/contributing-template) | Project health baseline | SECURITY.md, private vulnerability reporting, branch protection, CONTRIBUTING.md | [#229](https://github.com/Masashi-Ono0611/cipher-brain/issues/229) | Closed | Shipped except the bestpractices.dev registration itself |
| Healthcheck ping services | Dead-man's-switch monitoring | `schedule` pings a URL on success/failure so a silent nightly failure surfaces | [#202](https://github.com/Masashi-Ono0611/cipher-brain/issues/202) | Closed | **Shipped** |
| [Open Second Brain](https://github.com/itechmeat/open-second-brain) | A comparable second-brain project | A `--profile o2b` that ingests its bank-export bundle | [#206](https://github.com/Masashi-Ono0611/cipher-brain/issues/206) | Open | Accepted, not built |
| [x402](https://www.x402.org) | Agentic payment rails | Let an agent hold its own means of payment for a paid push | [#187](https://github.com/Masashi-Ono0611/cipher-brain/issues/187) | Open | Under discussion |
| [Sigstore](https://www.sigstore.dev) | Keyless signing, transparency logs | Considered for release signing alongside npm OIDC provenance | [#186](https://github.com/Masashi-Ono0611/cipher-brain/issues/186), [#66](https://github.com/Masashi-Ono0611/cipher-brain/issues/66) | Closed | Partly shipped (npm OIDC provenance; no Rekor entry) |
| [rclone](https://rclone.org/flags/) / [restic](https://restic.net) / [Turbo SDK](https://github.com/ardriveapp/turbo-sdk) | Transfer progress reporting | Report upload progress on `push`. The finding was that we need to *build* almost none of it: the Turbo SDK has emitted `onProgress`/`onUploadProgress` since v1.26.0 and we require `^1.42.0`, and rclone has `-P`/`--stats` we can pass through. Only the arweave L1 path has no upstream answer. **The SDK documents no resume API** — resumption is deliberately excluded | [#283](https://github.com/Masashi-Ono0611/cipher-brain/issues/283) | Open | Accepted, not built |

## Angles already swept

These directions have been mined once. Reading another tool in one of these
categories will *mostly* re-derive a row above — but "mostly" is not "always",
and this list is a prompt to check, never a reason to drop an idea. If yours is
genuinely different, file it and say what is new relative to the linked row.

Snapshot/backup CLIs · encrypted vault formats · erasure coding · authenticated
key exchange · threshold recovery · hardware-backed keys · archive extraction
safety · archival packaging standards · verified gateway reads · supply-chain
scanning · PII/privacy tooling · FinOps cost reporting · plan-then-apply consent
· interactive prompt libraries · property-based testing · structured
logging/tracing · release automation · project-health baselines · transfer
progress reporting.

## Angles not yet swept

Recorded so a survey has somewhere to start. These are directions, not
proposals — each still needs the usual "does this fit the project's scope?"
judgement against [`README.md`](../README.md)'s "What cipher-brain isn't".

- **Recovery-kit and emergency-access design.** `init` ends in a printed
  recovery kit. Password managers have iterated hard on exactly this artifact
  (1Password's Emergency Kit, Bitwarden's time-delayed Emergency Access). Nobody
  has compared the two.
- **Retention and forgetting on permanent storage.** restic/Kopia pruning was
  consulted for *cost* ([#208](https://github.com/Masashi-Ono0611/cipher-brain/issues/208)),
  never for the harder question this project's permanence creates: what does
  "delete this snapshot" even mean when the ciphertext is public forever, and
  what should the CLI promise about it?
- **The MCP surface as a surface.** cipher-brain exposes 10 MCP *tools* and
  nothing else — no resources, no prompts. Whether the other primitives fit here
  has not been examined.
- **Configuration files.** Everything is environment variables — 25 distinct
  `CIPHER_BRAIN_*` names, two of them deprecated no-ops — and
  [#276](https://github.com/Masashi-Ono0611/cipher-brain/issues/276) was a bug
  caused precisely by that list having to be re-enumerated by hand in two
  places. `rclone.conf`, restic profiles and `git config` are the obvious models.
- **Deterministic/reproducible archives.** Checked once and found *not* to be a
  correctness problem — `--skip-unchanged` hashes a sorted, normalized plaintext
  tree listing, not the tar bytes, so tar non-determinism cannot affect it.
  Recorded here so the next person does not spend the same hour on it.
