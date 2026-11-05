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

The synchronous run host also records its decoded request's original query
string capacity through the native recall call, including early errors. The hook
boundary deep-copies its arguments before decoding, so this allocation is
separate from the outer arguments.

The async recall door also records its decoded request's original query string.
A private owner holds the request before its lease and travels whole into the
blocking work. Once the work starts, the request moves into the native recall
while the lease remains in that work's scope. Unstarted work drops the request
before its lease. A deadline return does not release the original string's
charge while the detached work still owns it. The actual facade and agent paths
deep-copy hook arguments before decoding; the OpenAI-compatible proxy passes a
fresh query clone. These allocations are separate from their outer arguments.

The async home step separately records the capacity of the query string cloned
into `HomeRecallAsk`. Its outer future retains that string and its lease while
local work runs and while the home search borrows it. The string drops before
the lease on normal completion, early errors, deadline returns and cancellation.
The blocking local recall never receives this clone. Per-page RPC values and
serialized copies are distinct allocations outside this charge.

Other input copies, temporary seed vectors, the borrowed `media_seeds` view vector,
model weights, GPU memory, provider scratch, other recall allocations and a full
working-set bound remain outside this slice.
It does not establish queue fairness, pre-growth admission, provider cancellation, runtime
performance or a machine-derived embedding-width floor. The separate semantic
search request/probe owners are unchanged.
