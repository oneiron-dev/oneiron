# Contribution-fork erasure

Contribution replay keeps a matched pair under its experiment digest while
its subjects are live. Each stored row carries the actual actor, credited
skill and both ends of a used edge as typed erase subjects. This is erase
ownership, not a grant or model-call admission policy.

Fork receipt identifiers and response paths are opaque ULIDs from the start.
They do not derive from a target, the request or the pair digest. The response
body, its actual receipt and its erase ownership commit in one writer, so an
erase cannot miss a published response between publication and registration.
The normal custody admission, result marks, body spill and run ownership remain
unchanged.

Erasing a subject moves all rows of each affected pair to a fresh opaque key
and reissues each fork receipt. The same transaction updates only exact
matching receipt references in measured and unmatched CHECK pairs. Scores,
measurement IDs, reasons and answer bodies remain. The erased subject leaves
the provenance list; the other subjects remain discoverable for later erases.
The capsule actor eraser still releases the actor's answer bodies and marks.

Provider and scorer work can finish after an erase. Their original subjects
are checked in the publishing writer. Scoring also requires the exact receipt
to still exist at the original pair key; it never inserts a missing row. A
previously erased capsule cannot recreate its old unavailable-reason row.

This is the current stored format only. There is no legacy reader or migration.
The public receipt fields and scoring protocol are unchanged. This repair does
not claim full erasure of every artifact that might mention a contribution.
