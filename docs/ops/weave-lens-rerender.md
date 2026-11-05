# Saved Weave lens rerender after erasure

A hard erasure may rewrite only the affected rows in a saved Weave period.
The saved report keeps its publication time, receipt and scheduled Owner basis.
It gets a fresh internal report revision. The old lens and its old refusal are
removed because they described the report before the erasure.

The erasure transaction also stores an empty `weave:digest_rerender:v1:` intent
key naming that period. On the next existing home digest pass, the intent is
moved to the native Dreamer lens queue and retired in the same transaction.
This adds no timer or retry interval. The existing timer checks again on its
normal cadence, including on hosts that do not run a Dreamer; execution still
needs the normal Dreamer model and funding. A stopped schedule does not delete
its saved periods, so a rewritten saved period can still get its replacement
lens. No new due notification or cadence advance is produced by the rerender.

The attempt input and dedupe key include the exact report revision. A pending
attempt over an older revision cannot suppress the new one. Execution still
rereads the current authorized report, including the scheduled Owner basis and
live-owner census. Admin reads remain foreground-only. Both the successful
lens writer and the refusal writer compare the same report revision inside
their write transaction. An older in-flight answer cannot land on a rewritten
period, even when the publication time has not changed.

Whole-period erasure removes its rerender intent. Reader erasure uses the same
period teardown. Intent rows contain no report or lens bytes. Their checkpoint
payload class is Structure and restore class is CONTENT. The existing newest
live-lens family `weave:live:v1:` now has a typed Raw declaration and CONTENT
restore classification; its stored JSON bytes are unchanged.

These source paths do not establish a runtime timing bound or a whole-engine
erasure proof. The normal current-policy saved-read checks remain in force.
