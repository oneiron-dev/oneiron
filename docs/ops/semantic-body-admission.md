# Semantic search request body custody

`POST /api/search/semantic` admits the caller before reading its JSON body.
It spools the complete wire body into an anonymous vault-staged file, under the
listener's existing body policy. Content-Length is only a spool hint. The
spool's actual file length determines the raw-buffer allocation.

On the existing transfer worker, one lease from the process-wide MachineMemory
line admits that entire raw buffer before a fallible exact reserve. This is not
an incremental grow while holding part of the request. The vector's actual
capacity is named materialized after its storage is filled, so the live memory
reading does not count the pending reservation twice. After a successful parse
the same lease adopts the genuinely allocated decoded text with
materialized(0, actual); this is not a second lease, grow, wait or refusal.
The raw vector is dropped before its lease, on parsing success and on errors;
on success the decoded text is adopted before the raw drop, then the raw drop
happens first and the lease shrinks by the raw actual capacity.

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
The endpoint-only route change and post-read question hook landed separately in
PR5296 and remain unchanged here.

This is custody of the complete raw input vector plus the adopted original
decoded text, with no decoded preadmission and no raw-multiplier guard. The
transport's frame and spool-piece buffers, disk pre-admission, serde scratch,
path-key and error-payload temporaries, question, provider and probe copies,
embedding concurrency and runtime behavior remain not owned and unproved. The
returned decoded body retains its own raw lease as the holder of the adopted
text: params is declared first so the query String frees before the guard on
every drop path, and the handler binds the guard before the owned params so
reverse-local order holds. This is not a claim of whole-request heap coverage,
a runtime no-hang result or a speed improvement.
