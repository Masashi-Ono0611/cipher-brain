---
"cypher-brain": minor
---

Added `cipher-brain --version`, and `cipher-brain <command> --help` now prints
only that command's section instead of the full help text. Previously there was
no way to ask which version you were running, and every `--help` returned the
whole reference regardless of which command you asked about.
