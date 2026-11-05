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

## Current readers and off-record bodies

Before opening a retained transcript, the claimed workflow rechecks positively
typed content sources on all of its current member/binder read lanes, including
private-thread and own-entry selection. Metadata and untyped erase dependencies
do not create a new read grant or refusal. An eligible leaf whose content is no
longer readable uses the existing Cancel intervention; it never restarts the
paid call as a fresh request.

A room workflow derives the actual join subject from its queue lineage, binds
a live native stretch and captures that instance's route before the model call.
When several unrecorded stretches exist, the first in native registry-key order
is selected once. Each publication rechecks the live route and participant. A
room that goes off record during a call routes the new checkpoint into its live
session before any canonical body sink is used.

Session checkpoints use the native overlay, BODY rows, session spill directory,
body keys and close cleanup. They publish no canonical owned-body descriptor or
body-source history. Once the host has a response or tool result to save, its
first publication reserves the existing content-free fence before staging any
bytes. A failed first save therefore cannot restart paid work as Fresh; provider
failures before any save keep the ordinary retry path. Their queue hold and content-free fence share the native
base writer. The session segment publishes immediately after that base commit,
before the write door's notifications or debt payments can reacquire a writer.
Readers wait for a prior writer's segment publication before treating a missing
session row as unavailable. The fence carries the current
claim generation while session metadata keeps its last saved generation. A
session close or lost ephemeral payload is unavailable, never a fresh call or
a fallback to the earlier canonical transcript. A flip to on-record does not
promote previously off-record bytes. Anonymous sessions keep their native
`OffRecordTalkOnly` refusal for retained-content operations.

The terminal queue transition ends checkpoint access. Existing native session
close owns its overlay rows and spill lifetime; terminal clearing does not write
actor, room, source or body-digest session facts into canonical metadata. The
ordinary final workflow-output publisher is separate from this checkpoint
mechanism; this repair does not claim to route every workflow output off record.

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
