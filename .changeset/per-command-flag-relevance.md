---
'cipher-brain': minor
---

A flag another command accepts is now refused by the command that never reads it.

#253 made an unrecognized `--flag` an error instead of storing it where nothing would read
it. That validation is global, so the same bug class survived one scope down:
`restore --out ./x` is a real flag with a real value, stored and then never read, because
restore's destination is `--out-dir`. Thirteen flags across six commands were verified against what each command's implementation
actually does with them, rather than inferred from the flag's name:

```console
$ cipher-brain restore --in b.age --out ./restored
error: restore does not read --out: --out (restore extracts into a directory —
did you mean --out-dir?). Refused rather than ignored: …

$ cipher-brain snapshot --dir ./d --out s.age --backend file
error: snapshot does not read --backend: … the CLI snapshot does not push —
run `push --in <file.age> --backend <name>` after it
```

The shape is the one #308 took for the MCP surface: each command declares which flags it
will **not** read, an empty declaration is a real answer, and a command with no declaration
refuses to run — so `scripts/cli-smoke.sh`, walking the same derived command list the
unknown-command reply prints, turns a forgotten entry into a failing build rather than a
rule everyone has to remember.

Deliberately a deny-list, not an allow-list. #277 explains why an allow-list cannot be
derived from `--help` (the usage lines are abbreviated), and a hand-written one fails in the
direction that matters most: a flag missing from it would start refusing a valid
invocation. A missing deny-list entry only preserves today's behaviour, so the table can
grow safely instead of having to be complete at once.

`restore --out`'s "did you mean --out-dir?" hint (#279) is preserved — it now comes from the
refusal itself, one step earlier, so the reply did not get worse when the check moved.

The guard is a STATIC comparison of the dispatch switch's case labels against the
declaration table, both read out of `src/cli.ts`. A runtime probe cannot do it: the check
stays quiet for a name it does not recognise, so that a typo still gets the friendly
"unknown command" reply — which makes an undocumented `switch` case indistinguishable from
a typo at run time. `help` is a real case that `--help` does not document, and it is why
that gap was worth closing rather than assuming.
