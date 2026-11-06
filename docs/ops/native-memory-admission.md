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
