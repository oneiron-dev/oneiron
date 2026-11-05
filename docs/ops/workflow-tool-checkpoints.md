# Workflow tool checkpoint body history

A retained workflow tool checkpoint belongs to one native attempt. Its live
row holds the admitted transcript pointer, tool cursor and settled meter. It
is not a read grant: the workflow still uses its native lease, actor, scope
and retained-hook checks.

## Retained terminal answers

A retained terminal answer keeps the response and the model binding of the
completed call. Resume reads it under the same claimed attempt's checkpoint
checks. It does not call the model again, resample the response, replay tools,
or admit a second model budget.

Model-role authorization binds a new request to its configured route and host.
The policy budget guard meters new spend. Neither is a read grant for retained
answer bytes or their sources.

## Claim status is not recording origin

`ClaimReadStatus::Recorded` is the record-verb status mode. It includes
proposed, closed and stale claims. `Surfaceable` keeps the retrieval status
filter. Session origin is a separate property of the native read lane.
Do not change this status flag to classify checkpoint inputs or route their
bodies.

## Historical body sources

A successful checkpoint publication records the actual actor, every known
source and the room against the dedicated body owner's published digests.
Only real vault body-key instances, current or remembered, become source
facts. Missing facts never establish a complete source set.

`PROVENANCE_BODY_SOURCE` is exterior custody history, not live author data.
Its raw key is `source16 | body_owner16 | digest32 | instance16` (80 bytes),
with an empty value. It is classified `LIVE` for restore. The publication
writer journals new facts once before committing. The existing `BodyHistory`
fold unions them into same-lineage restores and prunes a fact when its real
instance retires. No invented entity-tree owner or attachment occurrence is
used for this metadata.

Actor scrubbing clears the live checkpoint association but keeps these
historical erase obligations. The BODY and BODY_DIGEST capture dependencies
include their actual historical sources even after that live row is cleared.
These facts never authorize reading or resuming the transcript. They are not
an off-record routing mechanism.

## Delete and erase

The existing typed payload disposition controls retirement. `Retain` and
reasonless actor scrubbing do not become `Erase`. The native GDPR tombstone
reason supplies `Erase`; an ordinary hard delete does not imply it.

On typed erase, current and historical matches are joined by their exact
body owner. The writer releases that owner's current occurrence before
calling the native body-history cutter once per owner. Another owner's
identical bytes keep their existing shared-holder protection. Native erase
pending state carries any retirement still owed until the final holder
releases it; this checkpoint mechanism adds no second debt ledger.

After that handoff succeeds, the same writer removes only the erased source's
live fact keys. Exterior history still carries non-retired instances and
uses its existing retirement pruning. The writer does not commit or run an
external key finisher here, so later native deletion guards can still roll
back its row changes.
