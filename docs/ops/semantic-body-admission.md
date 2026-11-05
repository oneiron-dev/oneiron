# Semantic search request body custody

`POST /api/search/semantic` admits the caller before reading its JSON body.
It spools the complete wire body into an anonymous vault-staged file, under the
listener's existing body policy. Content-Length is only a spool hint. The
spool's actual file length determines the raw-buffer allocation.

On the existing transfer worker, one lease from the process-wide MachineMemory
line admits that entire raw buffer before a fallible exact reserve. This is not
an incremental grow while holding part of the request. The vector's actual
capacity is named materialized after its storage is filled, so the live memory
reading does not count the pending reservation twice. The raw vector is dropped
before its lease, on parsing success and on errors.

The waiting request owns a cancellation flag. Dropping the request sets it even
when the body feed already finished. A worker waiting for the whole-buffer lease
checks that flag on the native line's existing repoll; there is no new timeout.
The JSON MIME check, path-aware parser and trailing-input check remain Axum's
native codec. Malformed or incomplete JSON remains a 400; native physical-memory,
allocation, complete-spool read and disk-full failures use the existing 500
response. The shared spool's generic Failed ending still includes non-disk-full
spool I/O and transport failure under the existing incomplete-body 400 shape.

The configured semantic_query_bytes row still asks and serves the whole query.
No body cap, fixed concurrency, queue deadline or truncation is added here.
The endpoint-only route change and post-read question hook in PR5296 are separate
changes; this collector does not copy their unmerged source.

This is custody of the complete raw input vector only. The transport's frame and
spool-piece buffers, disk pre-admission, serde scratch, decoded query String and
later copies, embedding concurrency and runtime behavior remain unproved. The
returned decoded query does not retain the raw-buffer lease. This is not a claim
of whole-request heap coverage, a runtime no-hang result or a speed improvement.
