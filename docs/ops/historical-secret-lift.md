# Historical secret-lift accounting

The historical lift sweep runs when the owner enables masking or asks for a run.
Its native writer doors, retry rules, busy-stream waits and page cursor are unchanged.

## Stored and served counts

`secret_lift:contribution:v1:` stores the canonical count contributions for each run.
Each row groups one family and one actual source entity, or explicitly unmapped sources.
It counts every census read, including clean rows, and the committed masked, proposal
and failed outcomes. A run stores its cursor and retry membership, not another copy of
these totals. A completed run stores completion metadata. The public progress and
receipt totals are projections of the same contribution rows.

Contribution rows use the same LIVE restore class as the run and receipt metadata.
There is no old-format reader or migration.

## Destination projection

On-device status includes all contributions. Off-device status uses the existing
source-entity destination filter. The source is established only for ordinary entity
records, typed-body documents, typed-body forks, codebase snapshots and note proposals whose
producer keys name the actual source entity. A codebase snapshot's source is the
CODE_ARTIFACT entity id that its native writer validates and uses as the table key.
A typed-body fork's source is the first entity id in its native `(entity, fork)` key:
its writer validates that entity's live typed-body head before storing the fork
snapshot. Both key ids must decode; the fork nonce is not treated as a source.
A note proposal's source is the first entity id in its native `hex32(note):hex32(head)`
ASCII key: its writer validates that NOTE's live core before storing the proposal
document. Both key ids must decode; the fork head is not treated as a source.
The same verified mapping projects pending retry counts and newly booked
contribution rows. Existing unmapped contributions are not reattributed. Other attempt, side-row and carrier
sources remain unmapped and pass unchanged; this is not a complete source
attribution claim for every carrier format.

The proposal list and its open/closed totals use these same known source mappings.
The status reader collects and projects one content snapshot, so a later committed
row cannot enter the result without its known source being included in the judgment.
No source ids are added to the public status or receipt shape. These are diagnostic
projections, not a change to admission, masking, erasure authority or recovery rights.
