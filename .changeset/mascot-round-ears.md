---
"cipher-brain": patch
---

Mascot redesign: a deliberate deforme of the repo's own `mascot.svg` (the
cypherpunk hooded dog in sunglasses) down to a 4-line terminal face — floppy
ear peaks and the connected sunglasses bar (`[10]==[01]`), everything else
dropped. Replaces the "deep visor" look from the previous redesign, which
read as cool but no longer matched the SVG. The mouth is a single smile/frown
character (`-` neutral, `v` happy, `x` sad, `~` partial) instead
of the prior 2-char check-mark motif, and happy/sad get a small flanking
accent (`+` shine / `!`) that neutral and partial stay without, so the accent
reads as signal rather than decoration on every render. Lens bracket
semantics (square = proven, round = slipping) and `moodForVerdict` are
unchanged. README banner updated to match. Decoration-only change — no
machine-readable output touched.
