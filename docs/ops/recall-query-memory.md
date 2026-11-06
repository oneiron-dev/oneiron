# Recall query-vector memory

Server recalls record the backing capacity of a returned text-index query vector
on the same machine-memory line used by the server's other work. The charge uses
the actual `Vec<f32>::capacity()` and `size_of::<f32>()`, not the configured
embedding width or an estimate of model memory.

Both seeded server entry points retain the charge through their native recall
call. The async door keeps it inside the blocking work, so answering at a deadline
does not release the charge while that work still reads the vector. Room turns,
prepasses and reranked recalls use that same call scope. The owned vector drops
inside the native recall before the enclosing charge drops, including errors
and unwinding. A media-embedding error also drops the text vector first.

This is post-allocation accounting. It does not reserve output space before a
provider runs, wait for memory, change embedding admission or create a new sparse
fallback. Light recalls and existing provider failures behave as before.

This slice covers only the returned text-index vector's backing allocation. It
does not cover declared-space or media vectors, input copies, model weights, GPU
memory, provider scratch, other recall allocations or a full working-set bound.
It does not establish queue fairness, pre-growth admission, cancellation, runtime
performance or a machine-derived embedding-width floor. The separate semantic
search request/probe owners are unchanged.
