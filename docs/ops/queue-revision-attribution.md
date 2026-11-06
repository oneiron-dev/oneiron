# Queue revision attribution

A tested queue revision records a derivation witness for each distinct leased
run that authored one of its applied proposals. The queue's aggregation session,
checker, export author and current driver are not substitute authoring runs.

The finalizer reads each proposal in its own write transaction. Its id, applied
status, operation sequence, source session and provenance must match the sealed
source. The proposal's run stamp was captured from the authenticated host lease
before submission and revalidated in that submission's writer. Reusing it for
attribution grants no authority and does not rebuild a host binding.

The witness uses the revision's actual stored `DerivedFrom` edge. Repeated sources
from one attempt and lease generation contribute that pair once. A live run gains
the edge in its bound attribution. A completed run keeps its frozen receipt and
reconciles late credit. The exact-record retry uses the same deduplication.

Missing or mismatched proposals, proposals with an erased actor, proposals with
no run stamp, and retired attempts add no witness. An older lease generation is
still eligible while its attempt remains stored. The baseline has no source run.
Witness capture runs in a savepoint: an error drops that capture with a warning
and never rejects or rolls back the queue seal.

No run token or lease-owner field is added to the seal, aggregate provenance,
Git metadata, public output or storage schema. Existing witness erasure and
checkpoint handling remain in use. There is no attribution backfill.

Received candidate intake is unchanged. Its publisher identity does not prove a
leased authoring run, and the original Git author is not authenticated run
metadata. Such received proposals retain their existing absent run stamp; the
intake fork and a later seal do not invent a run for them.
