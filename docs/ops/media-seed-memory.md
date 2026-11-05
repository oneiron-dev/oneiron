# Returned media-seed memory

The context-pack, core-query and MCP memory doors record the backing storage
of the `Vec<MediaSeed>` returned by their shared embedding call. Each charge
uses the vector's actual capacity and `size_of::<MediaSeed>()` on the same
machine-memory line supplied by that server.

The context-pack and core-query handlers keep the buffer and charge through
their existing reads and waits. The buffer drops before the charge on normal
completion, errors, unwinding and cancellation of those futures. The reader
choice `none` still skips embedding and produces an empty vector.

The context-pack and core-query consumers' initial charges also include the
retained capacity of each seed's owned space string and kind-filter vector.
Each charge counts those capacities once beside the existing outer buffer,
using the concrete `InputKind` size. The native pipeline's copies of the
borrowed fields are outside these charges. The returned seeds and their guards
keep the same drop order.

All three consumers' initial charges also include the returned embedding-vector
backing, using each vector's actual capacity and `size_of::<f32>()`, once on the
same lease as the other retained seed storage.

The MCP door keeps its original fallback and error handling. It drains the
returned seeds into the existing `EmbeddedMediaSeed` result vector, keeping the
source buffer until the emptied vector drops before its charge. The charge
covers the original buffer, not the converted result vector.

The MCP consumer separately records the returned `Vec<EmbeddedMediaSeed>`
backing, using its actual capacity and element size. Its local charge stays
through native reads and the existing observation wait. That buffer drops before
its charge, including errors, unwinding and cancellation of the consumer future.
The same consumer charge also counts each seed's owned space-string capacity,
embedding-vector capacity and kind-filter-vector capacity, once. The vector
backings use their actual capacities and `size_of::<f32>()` or
`size_of::<InputKind>()`, respectively. Explicit media decoding clones these
fields; the text-slot space is decoded into an owned string. These allocations
move into the consumed seeds without adding another charge for their headers.
This is adoption at the consumer; construction and return-time storage are not
covered by this separate charge.

Core query also records its separate borrowed-media view vector while the
native seeded search borrows it. That charge counts only the view's slots,
using actual capacity and the concrete tuple type. It does not charge the
strings, embeddings or kind filters those slots borrow. The existing server
memory line is passed to that internal query helper; no global substitute or
new configuration field is introduced.

This is post-allocation accounting, not admission before allocation. It adds
no memory-admission wait, refusal, configured limit, timeout or sparse fallback.
Provider internals, native pipeline copies, construction and return gaps,
other query storage and a full working-set bound remain outside these charges.
This does not prove queue fairness, pre-growth admission, runtime performance
or a machine-derived embedding-width floor. The shared embedding producer, paid-call
policy, authority, results and receipts are unchanged.
