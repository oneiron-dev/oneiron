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

The native path cannot wait for capacity while its caller holds source
inputs: concurrent preparations could otherwise keep each other's required
room pinned. `MachineFloor::try_lease` forwards through `OrganFloor` to the
same native process line. It uses the existing floor, live-memory/fallback fit
and FIFO rules; the decision and charge share the line's lock. A queued waiter
is never bypassed. If a booking would wait, no reservation or ticket is made.
The existing retryable preparation status uses the new diagnostic code
`memory_unavailable`, letting the caller unwind its inputs before retrying. Busy memory is not a fabricated deadline or
a permanent physical-floor refusal. Other organ/frame wait paths are unchanged.

Each parse attempt draws only from its already-reserved complete pool. A
shortfall cancels that attempt internally and unwinds its buffers and stages;
its pool lease is dropped too, before the next nonblocking booking. The next
attempt requests a fresh pool of exactly the observed required size. No parsed
buffer, decoded cache or previous pool reservation is held across that booking.
There is no speculative growth, synthetic deadline or claim of materialization.

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
