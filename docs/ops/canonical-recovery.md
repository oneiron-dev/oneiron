# Canonical window recovery

Canonical window recovery takes turns on the vault's existing task-work line.

Before reconstruction, artifact validation returns its turn between the existing
ordered groups: manifest and ordering, window rows, asset body references, NOTE
documents, entity documents, row births, and withdrawn cutoffs. The artifact is
rewritten for actors erased here once, then stays immutable across those turns.
Every group must pass before encoding, reconstruction, quarantine or a durable
write. A validation error clears the group cursor; a retry applies current local
erasures again. Synchronous validation drives the same groups to completion.

During verification, recovery recaptures the rebuilt window in four structural stages:

| Stage | Work |
| --- | --- |
| Raw | Check document roots and collect their carriers. |
| Joins | Mark deleted carriers, then read entity, tombstone, receipt and edge joins. |
| Documents | Capture NOTE and other entity documents, then document pins. |
| Finish | Capture remaining metadata, sort and validate the snapshot. |

Verification returns its turn after each stage. It does not advance the
recapture check until all stages finish and the snapshot comparison succeeds.
The rebuilt `PreparedRecovery.window` stays the same throughout.

The joins open one owned store read transaction after the deletion-marker
writer. Documents and remaining metadata use that same read view, rather than
opening a new transaction for each stage. Completion releases the view before
pad normalization, subsequent entity and edge checks, and carrying window pads.
An error discards the capture state and releases its read view. A later attempt
starts a fresh capture, not a continuation of failed scratch data.

The public `capture_canonical_window_within` function drives this same state to
completion synchronously. The stages do not introduce a worker thread or move
a read transaction between threads. Existing NOTE and sync capture helpers,
and the writer that couples NOTE cleanup with publication, are unchanged.

These are structural yields, not row-level or time-bounded pages. A capture
stage or validation group can still enumerate a whole map or run a whole nested
document scan. Actor erasure, encoding and hashing, transactional preflight, the
NOTE workflow plan and the final snapshot comparison remain whole operations.
No new setting, limit or deadline is introduced.
