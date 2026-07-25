---
"cipher-brain": patch
---

An unknown command now goes to stderr with the list of valid commands and exit
code 2, leaving stdout empty. It used to be printed on stdout, so a script
piping `cipher-brain` output into a parser was handed an error message where it
expected data.
