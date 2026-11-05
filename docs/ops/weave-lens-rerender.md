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

A claim-bound Gate decision's canonical redaction also clears copied reason codes
from saved loop rows whose original publication did not name the claim. Those
periods are discovered by the saved-period prefix, not the source index that the
reader's refused claim never entered. The private required `claim_was_named` flag
survives later ref erasure, so rows that originally named their claim keep the
existing named-ref history behavior. It is not a read grant or a public field.

The live-redaction callback runs only after the native ledger writes its
redacted decision, in the same transaction. Checkpoint restore also invokes the
same exact-decision scrub when it drops a singular-claim decision whose key
generation was retired after the image was taken. The restored saved periods
have already landed in that writer; policy-partition rows keep their existing
skip. Thus dropping the retired decision before the native claim-scrub rerun
does not leave its copied reason bytes behind. A stale mark alone does not
trigger either callback. Held decisions
wait for the existing native owed-scrub settlement; claim-free bundles are not
part of this singular-claim copy scrub. Only reason-code bytes change in the
saved row; its decision identity, saved outcome, refs and other history remain.
Changed periods use the same fresh revision and rerender intent described above.
No source index repair is needed because this scrub changes no indexed ref.
