# Recall query-vector and input memory

Server recalls record the backing storage of returned query vectors on the same
machine-memory line used by the server's other work. The charge uses actual
capacities, not configured embedding width or an estimate of model memory:

- The text-index `Vec<f32>` backing allocation.
- The declared-space/media tuple vector's backing allocation.
- Each retained space string, embedding vector and stored-input-kind vector.

Both seeded server entry points retain the charge through their native recall
call. The async door keeps it inside the blocking work, so answering at a deadline
does not release the charge while that work still reads the vectors. Room turns,
prepasses and reranked recalls use that same call scope. The owned vectors drop
inside the native recall before the enclosing charge drops, including errors
and unwinding. A media-embedding error also drops the initial vectors first.

The callback records its initial returned storage once. After the existing media
extension, it adds only the increase in retained capacity. Previously retained
outer backing and inner allocations are not charged again.

This is post-allocation accounting. It does not reserve output space before a
provider runs, wait for memory, change embedding admission or create a new sparse
fallback. Light recalls and existing provider failures behave as before.

The text-slot embedding call also records its original query-byte buffer. Its
local lease starts before the copy, records the actual `Vec<u8>` capacity before
embedding, and stays through the blocking runtime call. The bytes become the
embedding part's text string without copying its backing allocation. That
original buffer drops inside the call, including width retries, errors and
unwinding. The provider receives deep copies; those are separate allocations,
not part of this input charge. The input buffer and returned vectors have separate leases.

Decoded media also carries a private owner for its original decoded byte vector
and MIME string. It records their actual capacities after validation, before
embedding consumes them. The async door moves the entire owner into its blocking
work, so answering at a deadline cannot release that work's input charge. Unused
media drops before its lease. Space and stored-kind fields move into returned
vectors, so the input charge excludes them; the existing output charge records
them.

Other input copies, temporary seed vectors, the borrowed `media_seeds` view vector,
model weights, GPU memory, provider scratch, other recall allocations and a full
working-set bound remain outside this slice.
It does not establish queue fairness, pre-growth admission, cancellation, runtime
performance or a machine-derived embedding-width floor. The separate semantic
search request/probe owners are unchanged.
