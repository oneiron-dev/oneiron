# Native memory admission

`oneiron::host_memory::MachineMemory::process()` returns the same physical-memory
admission line used by every `SyncServer` in the process. Native bindings must
keep the lease alive while their admitted DTOs and copies live. Starting another
server does not create another memory allowance.

Acquire a lease before the first native allocation. Use `lease_until` when the
actual caller supplies a deadline, or `lease_untimed` when it supplies none. The
stop callback must come from a real caller or host lifecycle signal; absence is
not a synthetic timeout. These calls block, so asynchronous callers wait on a
blocking worker.

Grow reservations with `grow_pending` or `grow_pending_untimed` before allocating
more. Both keep earlier unallocated reservations charged. After allocation,
`materialized(reserved, actual)` replaces that pending reservation with the bytes
actually held. `shrink` returns unused room; dropping the lease returns its charge
and wakes the same FIFO line. Admission requires actual allocation sizes, not a
measuring-only limit check or an allocator capacity check.

The existing floor remains the larger of 256 MiB and one sixteenth of measured
machine memory. If the platform gives no total, the existing 2 GiB fallback
applies. Waiters still remeasure every 200 ms and when room is returned. The
existing live-memory and whole-memory fallback accounting is unchanged.

This provider alone does not complete the N-API codebase-snapshot boundary.
That caller must separately ask and serve the manifest-file limit, obtain its
required concurrency admission, reserve before marshaling, and retain/grow the
same lease through all DTO, path, content and core-vector allocations.

## Pending document-update replay

The document loader keeps its original order: it imports the stored snapshot
and validates birth first. It then collects every pending-update row and its
storage errors before importing any of those updates.

Base update bytes borrow the same transaction. A staged Single-row update
retains the exact immutable overlay view that supplied it, rather than copying
its encoded payload into the merge plan. Reading that value performs an
exact-key lookup in the retained view, not a new prefix scan or a fresh view.
The owned read APIs and their callers are unchanged.

A retained update can keep the whole captured snapshot and its existing read
lease alive through update imports. Closing, zeroization and the native held
state's charge can therefore last longer than the old collect-time iterator.
This is data ownership, not a new row grant or a separate memory ledger.

This removes an encoded-payload copy; it does not admit the whole replay heap.
Keys, plan metadata, outer vectors, iterator metadata, Loro state, decoded data
and caches still need their own accounting. It is not a runtime, no-hang or
whole-heap certificate.
