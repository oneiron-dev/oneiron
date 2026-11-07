# Deferred federation payload memory

Deferred federation work keeps its original payload under a process-memory
lease. Creating or loading work borrows the input bytes, reserves memory before
copying them, and records the resulting vector capacity. The original bytes
and their lease share an immutable owner. Cloning work shares that owner rather
than copying the payload. The bytes drop before their lease is released.

The deferred queue encodes one borrowed view of the stored fields. It measures
the exact postcard output, reserves memory before allocating that output, and
keeps its separate lease through the queue write. The payload field has the
same ordered length-plus-bytes representation. Batch hashes and queue keys are
unchanged.

Memory admission uses the existing process floor and an immediate deadline.
A floor refusal is an out-of-memory I/O error. Temporary pressure is a
would-block I/O error. Neither acknowledges, imports, settles or deletes work.
Existing grant, expiry, erase and review rules still apply.

Retaining or scrubbing a review measures its named MessagePack output with
that same serializer before allocation. Its separate output lease covers the
actual vector capacity and stays held through the queue write. The review
record, its payload bytes, and its selected erase entries are unchanged.

Isolated payload copies reserve memory before allocation. Stored deferred
parts borrow their window names and bytes during encode and decode; owned
copies are admitted only after the existing record validation. Moving or
cloning these payloads into a native review result preserves their byte owner
and lease. Review payloads still serialize as the same byte arrays.

Before decoding retained review payloads, the native loader counts each byte
array without allocating its bytes and reserves each payload separately. The
owned decoder uses MessagePack's exact array length for one allocation, records
actual capacity, and attaches each lease before returning. Resource pressure
stays an I/O error; genuine malformed records retain their corruption error.

A generic wire decode can arrive without admission. The native retained-review
loader performs that admission before allocation and use. Generated SDK mirror
copies and other receivers have their own allocation lifetimes; they are not
claimed covered by the native review owner.

This does not close all federation memory accounting. Selector, container,
shared-owner metadata and downstream SDK copies remain separate work. Existing
logical payload checks remain in place. There is no new numeric limit, timer,
configuration or stored format.
