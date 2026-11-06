# Contribution-fork erasure

Contribution replay keeps a matched pair under its experiment digest while
its subjects are live. Each stored row carries the actual actor, credited
skill and both ends of a used edge as typed erase subjects. This is erase
ownership, not a grant or model-call admission policy.

Fork receipt identifiers and response paths use independent opaque ULIDs from the start.
They do not derive from each other, a target, the request or the pair digest. The response
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

Outcome receipt references remain opaque caller-supplied strings, not authority
or verified entity references. Their full entity-id hex spellings are captured
as erase metadata using the same case-insensitive spelling match as CHECK.
No delimiter or receipt grammar is invented, and ordinary receipt strings stay
accepted. If an erase names one of those spellings, the pair moves as above
and only the matched scoring reference becomes a fresh opaque `erased:`
reference. Both forks with the same original reference reuse its replacement.
Scores, anchor digests, scoring identity, answer bodies and their owner joins
stay unchanged. The captured spellings also reach the existing same-writer
late-publication fence; a provider or scorer finishing after that erase cannot
restore the original reference. This adds no new format, limit or setting.

Provider and scorer work can finish after an erase. Their original subjects
are checked in the publishing writer. Scoring also requires the exact receipt
to still exist at the original pair key; it never inserts a missing row. A
previously erased capsule cannot recreate its old unavailable-reason row.
Capsule selection (or its unavailable reason) and its actor provenance come
from one captured snapshot. Preparation uses that selected capsule or reason;
it does not reopen a snapshot and change which capture the reason describes.
When no captured step exposed a used edge, the reason still records the actual
actors of the attempt's latest captured generation. Erasing those actors moves
the reason too, and their erased capsules fence a later reason write. Older
erased generations do not hide a newer live generation.

Two scorers racing on the same unchanged fork reuse the first committed score,
even if their judgments differ. A losing scorer does not turn a valid scored
pair into a permanent unavailable reason.

This is the current stored format only. There is no legacy reader or migration.
The public receipt fields and scoring protocol are unchanged. This repair does
not claim full erasure of every artifact that might mention a contribution.
