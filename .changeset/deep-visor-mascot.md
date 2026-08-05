---
"cipher-brain": patch
---

Mascot redesign: "deep visor". The ASCII mascot trades the round-cheeked hood
peak for a flat-topped hood with a solid brim sitting directly on a connected
visor (`[10]==[01]`) and an angular jaw — cooler, less cute, same verification
semantics. The mouth widens to 2 chars and now draws the verdict literally:
`__` neutral, `,/` a check mark for PASS, `\.` its fallen mirror for FAIL,
`~/` a half-drawn check for PARTIAL. Lens brackets (square = proven, round =
slipping) and `moodForVerdict` are unchanged; the README banner is updated to
match. Decoration-only change — no machine-readable output touched.
