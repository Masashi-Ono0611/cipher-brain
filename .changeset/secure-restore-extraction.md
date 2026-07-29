---
"cipher-brain": patch
---

`restore` now inspects every tar entry in an artifact before extracting anything, and
extracts into an isolated scratch directory that is only promoted into `--out-dir` once
extraction of the already-vetted archive fully succeeds (issue #218). An entry with an
absolute path, a `..` path component, a FIFO/device/socket, a hardlink whose target
escapes the archive tree, or a symlink another entry is nested under (the classic tar
path-traversal-through-symlink attack) is now rejected outright, before extraction starts
— this is defense-in-depth on top of protections `tar` itself already has, not a fix for
a known exploited vulnerability: age's confidentiality/tamper-detection means an artifact
must already come from someone holding a recipient's public key, and PR #198 already
closed the equivalent gap for manifest.json's `name`/`source` fields. A legitimate
snapshot's dangling/absolute-target symlinks (produced when a `--dir` source is itself a
symlink) and in-tree hardlinks still restore exactly as before. No CLI flag changes.
