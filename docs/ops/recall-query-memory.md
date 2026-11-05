# Recall query-vector memory

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

This slice covers retained returned storage only. Input copies, temporary seed
vectors, the borrowed `media_seeds` view vector, model weights, GPU memory,
provider scratch, other recall allocations and a full working-set bound remain
outside it. It does not establish queue fairness, pre-growth admission,
cancellation, runtime performance or a machine-derived embedding-width floor.
The separate semantic search request/probe owners are unchanged.
