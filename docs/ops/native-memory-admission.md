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
existing `MachineFloor::lease_untimed`, not the configured timeout of an organ
call that never ran. The server's `OrganFloor` forwards this to the same process
memory line.

Each parse attempt draws only from its already-reserved complete pool. A
shortfall cancels that attempt internally and unwinds its buffers and stages;
its pool lease is dropped too, before any new memory wait. The next attempt
books a fresh pool of exactly the observed required size on the same FIFO line.
No parsed buffer, decoded cache or previous pool reservation is held across
that wait. There is no speculative growth, synthetic deadline or claim of
materialization.

Before booking, the existing native `check_irreducible_peak` predicate checks
the caller's `pinned_buffer_bytes` plus the required complete pool. The seal
producer supplies actual allocated capacities of every original PDF buffer,
every distinct raster RGBA buffer, and prior sealed output buffers still held
by that operation. The current original is included once, not added again as a
slice length. The required Rust field has no invented fallback footprint.
State/event/container/allocator and other private heap remain outside this
witness; it is not whole-heap accounting or a global no-hang certificate. The
predicate neither reserves nor creates a new limit. Real floor/deadline refusals return the existing retryable preparation
failure, never a malformed input. Each attempt uses the already-replayed audit;
it does not replay that audit or send an organ call again.

The shared preparation body admits preflight parsing and source stream decodes.
Within one attempt, cached page streams retain their admission through the
cache's lifetime and each distinct stream decodes once. An unwound attempt's
cache is discarded; a retry repeats the pure parse and source decoding. Form/pattern buffers, Type 3 glyph aggregates and page-content
concatenations reserve before growth, including a new allocation while the old
one lives. Temporary stages release only after their buffers drop, returning room to
that attempt's pool; the machine lease lasts through the attempt. Reservations
remain pending: this inspection interface supplies no materialization notice.
This is not whole-heap accounting: input bytes, content-operation parsing, output
objects, field rendering, audit strings and encoded output are not covered by
this boundary. The existing per-stream codec bound and PDF format bounds remain.
