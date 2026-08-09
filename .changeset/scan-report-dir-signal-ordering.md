---
'cipher-brain': patch
---

Closed two narrow timing windows in which interrupting a snapshot could still leave the
secret scan's `cipher-brain-gitleaks-*` report directory behind: one between creating that
directory and registering it with the signal handler, and one between clearing the
registration and the removal actually finishing. Both are now ordered the way the snapshot
staging directory already was — created and registered in a single step, removed before
being deregistered.
