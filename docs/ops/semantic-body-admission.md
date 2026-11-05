# Semantic search request body custody

`POST /api/search/semantic` admits the caller before reading its JSON body.
It spools the complete wire body into an anonymous vault-staged file, under the
listener's existing body policy. Content-Length is only a spool hint. The
spool's actual file length determines the raw-buffer allocation. The semantic
reader copies directly from that file into its admitted raw vector; it does not
allocate or hold a separate buffered reader while waiting for the vector's room.

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
Other typed shared-spool endings use the spool's native error mapping rather
than being relabeled as invalid JSON or disk capacity.

The configured semantic_query_bytes row still asks and serves the whole query.
No body cap, fixed concurrency, queue deadline or truncation is added here.
The endpoint-only route change and post-read question hook landed separately in
PR5296 and remain unchanged here.

This is custody of the complete raw input vector plus the adopted original
decoded text, with no decoded preadmission and no raw-multiplier guard. The
transport's frame and spool-piece buffers, disk pre-admission, serde scratch,
path-key and error-payload temporaries, provider request buffers and any
engine-internal query/probe copies, embedding concurrency and runtime behavior
remain not owned and unproved. The
returned decoded body retains its own raw lease as the holder of the adopted
text: params is declared first so the query String frees before the guard on
every drop path, and the handler binds the guard before the owned params so
reverse-local order holds. This is not a claim of whole-request heap coverage,
a runtime no-hang result or a speed improvement.

## Trimmed question and probe custody

Beyond the decoded body above, the semantic handler owns its trimmed question
`String` and the embedded `Vec<f32>` on one process-memory empty lease. The
trimmed text is adopted after it allocates with `materialized(0, actual)` on
its actual capacity. The known-ready non-deadline native embedding
opportunistically pre-grows its model-shaped logical minimum on that same
lease before the model call, from the SAME snapshotted slot that then runs
the query: the slot's configured `dimensions` times `size_of::<f32>()`, the
physical unit width, not an allocator-capacity bound, tokenizer, tensor, GPU,
input-copy, whole-question, or runtime count. The single attempt carries an
already-due deadline, so the native line grants it only on an immediate fit
and otherwise drops this attempt's own waiter before any Condvar wait; this
adds no new memory-FIFO wait or hold-and-wait cycle while the question text
is retained. A granted pre-growth is reconciled against the actual vector
capacity after the call, while contention (`WaitedOut`) keeps the original
adoption-only path with zero reservation and no retry, queue wait, or new
busy refusal. Full cover before growth and queueing behavior stay open here.
The native floor stays the real dynamic reserve check: physical-memory floor
refusal logs privately and uses the existing generic query-failure response.
Dropping the request is only a pre-call checkpoint here, not a new memory
wait or an already-running native inference cancellation. No new cap,
default, physical-floor constant, queue deadline, or timer is added. Deadline,
space, and media
adoption stays adoption-only via `finish`, with no dims, byte envelope, or
model estimate entering that count. Native accounting still takes a mutex and
may contend.

`Question` holds its text before its lease, and `OwnedProbe` holds its
embedding and question before its lease, so the payloads free before the guard
on every drop path. The handler binds the probe guard before the owned buffers,
so reverse-local order holds; under a deadline the whole question moves into
the static read task, which adopts, guards, and drops its own probe past the
request cut. The non-deadline native task owns its question, stop flag, and
lease, then transfers the owned probe and lease to the actual search consumer. Eliminating the untracked
question clone is a custody simplification, not a speed win. Provider scratch,
tokenizer and frame buffers, fair queueing, preemption, and whole-heap or
runtime behavior remain not owned and unproved here.
