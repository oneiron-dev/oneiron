# Resident runs that settle their own TASK

The resident pump does not issue another implicit TASK result when the current
run has already settled that same bound TASK through a native successful
decline or a fresh terminal `tasks.update` report.

Terminal report recognition uses the effective verb after any door rewrite and
the native returned `TaskUpdateReceipt`. The receipt must name the bound TASK,
carry a report for that same TASK handle, and say `Reported` with a terminal
phase. It must not be an idempotent replay. Its native lifecycle must record a
`report` call with body `done` or `failed`. An acknowledgement can expose an
already terminal phase without settling anything; it does not count. Reader
reports, waits, denied/failed calls, nonterminal reports and other TASKs do not
count either.

The completion caller counts declines and terminal reports with the same helper
for both the completed replay record and a continuation's inherited source
prefix. Only an increase for the current bound TASK makes the run self-settled.
No predecessor attempt or current TASK row is read to manufacture that proof.
No lifecycle receipt-retention setting is used as an extra settlement gate.

The existing native result, attribution, confession, completion and child-spend
settlement paths remain unchanged. This classification does not change TASK
reporting, authority, hooks, lifecycle rules or the continuation's admitted
prefix. It adds no compatibility reader or new policy/default.
