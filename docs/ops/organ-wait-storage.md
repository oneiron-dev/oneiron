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

Listings and the redrive census read metadata. Each redrive borrows one payload
from the base pages or the accessor's immutable single-valued overlay snapshot,
without copying the payload before admission. It checks the exact length and
digest and admits the organ protocol's shape bound
and the capacity walk's depth-first iterator frames before decoding. The memory-floor wait ends its read transaction first.
Conversion allocations grow the same lease. Actual owned capacities replace
pending reservations. The lease survives dispatch and landing. A fresh preflight
checks that the held call and artifact are still current after admission waits.
Owner-versus-masked input sight and submitting-principal landing remain unchanged.

## Supplied floors

The router uses its existing machine memory floor for encoding and decoding.
Encoding starts one empty lease before counting the saved call. Both the count
and write pass admit the Value encoder's depth-first iterator stack before it
grows. A replacement books the new stack capacity beside the old allocation;
the old capacity is released only after replacement. The input IDs use the same
32-character lowercase hex on the stack. The encoded output reserves before
allocation and records its actual capacity before write-pass scratch grows.
The same lease survives routing and the held-row write; its bytes drop first.
This covers the known borrowed held-call shape, not arbitrary serializers.

These offline admission waits have no new execution deadline: the mesh stop
interrupts them. The saved call's deadline remains its per-execution duration.
A router without a supplied memory floor keeps its existing behavior.

A server lends `StorageDiskFloor` on the filesystem holding the vault. It shares
its upload/spool disk ledger when that filesystem matches; otherwise it creates
one bound floor at server construction, not one per call. The configured disk
reserve does not change. An embedded host may lend no disk floor.

The disk claim admits the exact encoded metadata and raw payload lengths after
the transaction's consume-once and deletion preflights, before either put. It
stays held through the grouped commit. The attempt's durable own-commit witness
marks it landed even if a later postcommit action reports an error. Uncommitted
errors release the pending claim. A measured floor reports `StorageFull`
with its measured values. A measurement error remains its original I/O error.

This disk budget covers encoded values, not LMDB keys, pages, splits, freelists
or copy-on-write amplification. It is not a total native-disk or native-heap
measurement. LMDB's configured map limit and actual filesystem I/O errors remain
in force. Other row and overlay metadata copies and native transaction
allocations still need their own admission; this document
does not claim complete resource coverage or runtime proof.

## Shared native allocation account

`FloorLease::into_shared` transfers an existing job lease without creating a
second machine-memory line. The server adapter uses `SharedMemoryLease` on the
original line's mutex. Admission waits release that mutex, so a native buffer
freed by another writer can return memory while the job waits.

An in-flight malloc assigns part of the existing pending reservation before it
allocates. Successful malloc moves that part to actual memory; failed malloc
cancels only its assignment. Physical free can restore pending credit for a
replay without dropping the cumulative admission. A cached buffer has not
physically freed and keeps its actual charge.

After the job's growth waits and writer have returned, `finish` releases unused
pending credit. No new growth starts afterward. Later physical frees release
actual charges instead of keeping retry credit until the environment closes.
Caller buffers release allocated bytes separately, without consuming native
pending reservations. All of these transitions use the original machine line.

## Native held-write attempts

A hosted held write uses the encoder's same shared lease for native dirty-page
heap buffers. Its opaque write takes its ordinary place on the group queue.
Detached writes ahead of it commit before the account attaches to a fresh root;
the leader retains their Vault handles until its final handoff. The child write
inherits the account, and the root's commit retains it too. Existing unaccounted
callers keep their original group behavior.

Native callbacks assign only already admitted pending room. A denied allocation
returns through the entire write door before the caller waits for more room on
the same lease. Each new attempt repeats the original consume-once, live-artifact
and positive-deletion checks. Only a real native admission denial, an error and
no successful own root commit permit a replay. A native malloc failure without
an admission denial is its ordinary error. The commit witness is set immediately
after the root commits, before callbacks or fallible postcommit work, so a later
error never replays already durable rows.

The real mesh stop interrupts these untimed admission waits. The native scope
finishes only after its writer and growth waits return. The encoded Vec frees
before its allocated charge is released; cached native buffers keep their own
charge until their physical free callback.

This covers the native dirty-page malloc request, including its actual heap-only
prefix. It does not cover IDL/control allocations, encryption stash, mmap, read
pages, every metadata/overlay copy or native physical-disk/CoW costs. The disk
claim above still covers encoded values only. This is not complete FIX8125,
whole-heap coverage or runtime proof.
