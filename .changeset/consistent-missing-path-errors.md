---
"cipher-brain": patch
---

A missing `--in` / `--dir` path is now reported the same way by every command:
`no such file: <path>`. `restore` used to reach the decryption path first and
fail with `CB-E002` (not a valid age file), which pointed at the file's contents
when the real problem was that the file did not exist.
