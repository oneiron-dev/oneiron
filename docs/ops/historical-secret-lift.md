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
records and typed-body documents whose producer keys name the actual source entity.
The same verified mapping projects pending retry counts. Other attempt, side-row and
carrier sources remain unmapped and pass unchanged; this is not a complete source
attribution claim for every carrier format.

The proposal list and its open/closed totals keep their existing source rules.
The status reader collects and projects one content snapshot, so a later committed
row cannot enter the result without its known source being included in the judgment.
No source ids are added to the public status or receipt shape. These are diagnostic
projections, not a change to admission, masking, erasure authority or recovery rights.
