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

This does not close all federation memory accounting. Isolation copies,
review input decoding and public review-result ownership remain separate
work. Selector, container and shared-owner metadata allocations are not covered
by the original-payload lease. The existing logical payload checks remain in
place. There is no new numeric limit, timer, configuration or stored format.
