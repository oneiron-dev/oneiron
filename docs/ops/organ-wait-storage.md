# Retained organ calls

When no node can run an organ call, the router retains the call beside its
artifact. A redrive uses the same run ref. Failed calls keep their payload until
release. Successful landing releases the hold. Artifact deletion purges it.

## Storage

`edit_settle:organ_wait:v1:` holds the call metadata, its encoded length and its
BLAKE3 digest. `edit_settle:organ_wait_body:v1:` holds the exact opaque call bytes
under the same artifact/run-ref key. Both writes, releases and artifact purges
share one transaction. The call bytes do not pass through a Named byte-array
encoding. There is no old-format reader or migration.

Listings and the redrive census read metadata. Each redrive borrows one payload,
checks its exact length and digest, and admits the organ protocol's shape bound
and the capacity walk's depth-first iterator frames before decoding. The memory-floor wait ends its read transaction first.
Conversion allocations grow the same lease. Actual owned capacities replace
pending reservations. The lease survives dispatch and landing. A fresh preflight
checks that the held call and artifact are still current after admission waits.
Owner-versus-masked input sight and submitting-principal landing remain unchanged.

## Supplied floors

The router uses its existing machine memory floor for encoding and decoding.
These offline admission waits have no new execution deadline: the mesh stop
interrupts them. The saved call's deadline remains its per-execution duration.
A router without a supplied memory floor keeps its existing behavior.

A server lends `StorageDiskFloor` on the filesystem holding the vault. It shares
its upload/spool disk ledger when that filesystem matches; otherwise it creates
one bound floor at server construction, not one per call. The configured disk
reserve does not change. An embedded host may lend no disk floor.

The disk claim admits the exact encoded metadata and raw payload lengths after
the transaction's consume-once and deletion preflights, before either put. It
stays held through the grouped commit. Only a successful durable return marks it
landed; errors release the pending claim. A measured floor reports `StorageFull`
with its measured values. A measurement error remains its original I/O error.

This disk budget covers encoded values, not LMDB keys, pages, splits, freelists
or copy-on-write amplification. It is not a total native-disk or native-heap
measurement. LMDB's configured map limit and actual filesystem I/O errors remain
in force. Overlay read copies, save-serializer scratch, traversal scratch and
native transaction allocations still need their own admission; this document
does not claim complete resource coverage or runtime proof.
