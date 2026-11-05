# Returned media-seed memory

The context-pack, core-query and MCP memory doors record the backing storage
of the `Vec<MediaSeed>` returned by their shared embedding call. Each charge
uses the vector's actual capacity and `size_of::<MediaSeed>()` on the same
machine-memory line supplied by that server.

The context-pack and core-query handlers keep the buffer and charge through
their existing reads and waits. The buffer drops before the charge on normal
completion, errors, unwinding and cancellation of those futures. The reader
choice `none` still skips embedding and produces an empty vector.

The MCP door keeps its original fallback and error handling. It drains the
returned seeds into the existing `EmbeddedMediaSeed` result vector, keeping the
source buffer until the emptied vector drops before its charge. The charge
covers the original buffer, not the converted result vector.

Core query also records its separate borrowed-media view vector while the
native seeded search borrows it. That charge counts only the view's slots,
using actual capacity and the concrete tuple type. It does not charge the
strings, embeddings or kind filters those slots borrow. The existing server
memory line is passed to that internal query helper; no global substitute or
new configuration field is introduced.

This is post-allocation accounting, not admission before allocation. It adds
no memory-admission wait, refusal, configured limit, timeout or sparse fallback. Provider
internals, the seeds' inner allocations, the MCP converted vector, other query
storage and a full working-set bound remain outside these charges. This does
not prove queue fairness, pre-growth admission, runtime performance or a
machine-derived embedding-width floor. The shared embedding producer, paid-call
policy, authority, results and receipts are unchanged.
