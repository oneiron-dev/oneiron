"""The rack harness of pass 34 row K1: canaries and readbacks for sections 13 and 15.

`workflow_check.py HOST PHASE CHECK` is the one entry. It answers in the
contract of the rack audit's approved workflow checks: exactly
`PASS HOST PHASE CHECK` on stdout and exit 0 only when the named check
passed, and a nonzero exit with one line on stderr otherwise. See README.md.
"""
