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

## Native e-sign preparation

A hosted sealer without a selected first-party prepare organ uses the trusted
native renderer with its host's optional machine floor. A host without a floor
keeps the existing native fallback, and ordinary offline preparation APIs stay
unadmitted. Third-party prepared bytes are never substituted for trusted bytes;
the first-party organ path and its work limits are unchanged.

This native path has no actual call deadline or stop handle. It uses the
existing `MachineFloor::lease_untimed` and the pending-preserving
`FloorLease::grow_pending_untimed` bridge, not the
configured timeout of an organ call that never ran. The server's `OrganFloor`
forwards these to the same process memory line. The adapter retains the first
floor/deadline refusal separately from PDF errors and reports it as a retryable
preparation failure; it never labels that refusal a malformed input.

The shared preparation body admits preflight parsing and source stream decodes.
Cached page streams retain their admission through the cache's lifetime and
still decode once. Form/pattern buffers, Type 3 glyph aggregates and page-content
concatenations reserve before growth, including a new allocation while the old
one lives. Temporary stages release only after their buffers drop. Reservations
remain pending: this inspection interface supplies no materialization notice.
This is not whole-heap accounting: input bytes, content-operation parsing, output
objects, field rendering, audit strings and encoded output are not covered by
this boundary. The existing per-stream codec bound and PDF format bounds remain.
