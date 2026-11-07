# Managed widen request bodies

The managed widen accept and reject doors keep the existing v1 action MAC, holder
selection and native owner/credential checks. An action MAC covers the actual byte
count and the exact original body. Spooling does not change the bytes replayed to
the route.

## Body geometry

The existing 2 MiB boundary is a choice between in-memory and file-backed work,
not a request-size refusal. Small bodies keep their existing in-memory route and
hex decoding. Larger bodies use the transfer spool, its configured idle policy and
its shared disk reserve. Actual disk capacity can still stop a spool.

For a large accept body, the `expected_delta` JSON string is unescaped and decoded
as lowercase, even-length hex into an anonymous vault-staged file. It is not one
request-sized `String` or `Vec`. JSON validation finishes before an invalid hex
field is reported. Empty hex remains valid syntax and fails or succeeds only under
the existing native comparison rules.

The `proposal_ref` string is also unescaped into an anonymous file. Property names
are matched as they stream, without copying them or an unknown member's value
into a metadata head. Missing, duplicate, unknown and non-string members still
produce the same invalid-JSON response. Large widen answers do not use the generic
metadata decoder. The existing whole-JSON reader used by other doors is unchanged.

Large reject bodies use the same closed-schema string reader and UTF-8 file sink
for their sole required `proposal_ref` member. They have no delta member. Small
rejects keep the existing in-memory decode and native decline call.

The closed-schema reader matches each property name against a stack array sized
by its declared schema: two members for accepts and one for rejects. Matching
allocates no per-property name vector. These are the existing required fields,
not a new request-size or property-name-length limit.

The raw-body spool already reserves a stored-copy amount equal to its counted
length. The decoded hex file cannot exceed half its own raw member's length;
unescaping the reference cannot expand its raw member. Their combined decoded
length therefore cannot exceed the raw body's length. That same room is retained
through both files' final native read; it is not replaced with a second cumulative
claim. Files are anonymous and are removed when their handles close.

## Spool and decoder I/O memory

The raw-body spool admits one finite payload phase on the shared process memory
line. It covers the existing two queued copies, the producer's unsent copy, the
reader's current copy and the existing 64 KiB read piece. Each copied piece is at
most 64 KiB; these are the existing queue and I/O geometry, not a request-size
limit. Admission runs on the dedicated transfer worker after the anonymous spool
file is created, outside every vault transaction.

The feed starts observing input and the existing idle policy immediately, but
waits for that admission before its first nonempty piece copy. This wait is worker
backpressure, not a new client deadline. The actual copied lengths and read-buffer
capacity are recorded on the same lease. Once a current copy is fully consumed,
its backing is freed and returned to that lease's pending room under the original
memory-line lock. No other waiter can take the freed room between those steps,
and no further admission is needed for the next piece.

The reader, current copy, queue and read piece drop before the worker signals the
end of the raw phase. An explicit owner then destroys the whole producer future,
including any unsent copy, before acknowledging that signal. Cancellation performs
the same destruction before closing the acknowledgment channel; a closed channel
never starts the decoder. Only after acknowledgment does the worker drop the final
raw-phase lease and call the decoder. All raw payloads therefore drop before their
lease on success, error and unwind, and do not overlap a decoder's later reservation.
Channel, future and error metadata, upstream frame backing and allocator RSS are
not included in this payload accounting.

The raw-spool wait has no new deadline and observes the same cancellation flag
as the decoder wait. A physical memory floor uses the existing internal-server-
error shape with a raw-spool allocation message, not `disk_capacity`. A cancelled
wait keeps the body-not-whole response. Custody's disk-specific message and all
existing disk and idle rules stay unchanged.

The same stop flag is set before an observed input failure or existing idle expiry
is queued to the worker. A full feed channel therefore cannot hide that terminal
event from the waiting admission. Successful data and clean EOF do not set it.
Other transfers keep their existing feed helpers and behavior.

Before the large accept or reject decoder constructs its text writer or JSON
reader, its dedicated transfer worker admits both existing 64 KiB I/O buffers
on the process's shared memory line. One lease covers both, and each buffer's
actual capacity is recorded on it. The lease stays live through parsing and
both sinks' flush and close, including errors and unwinding, and is then returned
on that worker before the native answer runs. This does not add a request-size
limit or change the I/O geometry.

The memory wait has no new deadline. If the awaiting spool future leaves, a
local cancellation flag lets the waiting worker leave the same untimed line.
A physical floor uses the existing internal-server-error response with an
allocation message; a cancelled wait uses the existing body-not-whole response.
No error code or field is added. For admitted decodes, JSON, hex, file, holder
and native validation keep their existing order.

## Other spool readers

The whole-JSON owner reader, sealed custody object reader and raw training-checkpoint
reader admit their existing 64 KiB reader buffer on the same process line before
allocation. Each records the actual buffer capacity and retains the lease through
the reader's last use and drop. The raw-spool piece has already released its lease
before any of these readers starts. The large widen string readers retain their
existing paired reader-and-writer lease; they do not take an additional reader lease.

Checkpoint reader admission runs on the transfer worker before it returns the spool.
The later native blocking callback owns both spool and lease, creates the reader
before entering the native writer and never waits for memory under that writer.
The completed transfer's cancellation flag is not reused for a later admission.

A physical memory floor keeps the existing internal-server-error shape with a spool
reader allocation message; cancellation keeps the body-not-whole response. Admitted
reads retain the existing JSON-before-sink and native validation order. This accounts
only for the fixed reader buffer, not generic DTOs, metadata heads or native decoded
rows. The sealed object's additional fixed base64 buffers are covered below.

## Sealed base64 and metadata working buffers

The sealed custody reader admits its source JSON reader, pending base64 text,
decoded output and metadata-head writer together on the original transfer worker,
before any of them allocates. One lease covers two existing 64 KiB I/O windows,
128 KiB of pending base64 text and 96 KiB of initialized output: 352 KiB in this
phase. These capacities derive from the existing window and piece geometry, not
a request-size limit. Each actual capacity is recorded once on the combined lease.

The sink keeps reusable text and initialized output buffers. It decodes the same
text extent with the same standard base64 engine and writes only the decoded
prefix. Chunk boundaries, padding checks, JSON-before-sink errors, file writes
and final field handling keep their existing order.

The other object members stream to a second anonymous vault-staged file instead
of one rebuilt encoded metadata vector. Values and quoted property names retain
their original bytes. Names are unescaped only into the existing stack-array bulk
matcher, never a name vector or normalization string. A non-bulk name is replayed
from its saved extent through the same admitted reader, after any preceding comma;
the reader ends exactly at that name's closing quote. Escaped names keep the same
meaning for the later DTO decode. Omitting the base64 member also removes its name
and punctuation. The head and decoded input bytes therefore fit within the raw
body's stored-copy room; no second
cumulative disk claim is created. Files still close on drop, and real disk
capacity failures keep the custody response.

A head-file write failure stops further writes but does not stop syntax scanning.
After scanning, both sinks close inside the first lease. All four working buffers
and that lease drop before a later admission. Known syntax and head-file failures
are returned before waiting for another reader. Only then does the same original
transfer worker admit a separate 64 KiB head reader and decode the route's DTO.
There is no buffer lease or vault transaction across that wait, and the original
live cancellation flag remains in use. The phases do not overlap. A head-file
read failure keeps body-not-whole rather than being called malformed JSON.
Position, seek and original-name replay failures keep that same response; malformed
name escapes or UTF-8 still produce invalid JSON. A head write failure does not
stop replaying the name's full extent or judging the rest of the document.

A readable head's DTO errors still precede saved input-sink errors. The reader
drops before its lease, including refusal and unwind; the returned request keeps
only its original head, input file and disk room. The transient head file is gone
before the worker returns.

A physical memory floor uses the existing internal-server-error shape with a
custody-decode allocation message. A stopped wait keeps body-not-whole, not disk
capacity. The later serde reader's key scratch space, generic DTOs and native
decoded rows remain unpriced; this is not whole-endpoint heap admission.

## Native answers

Native acceptance checks the holder credential before validating the reference's
existing 64-byte lowercase hex shape. It reads that reference into a fixed 64-byte
buffer and checks EOF, never a request-sized string. Invalid references retain
their existing refusal and do not bypass the holder check.

For a large accept, native work runs on a dedicated transfer worker, not the
runtime's shared blocking pool. It carries the same restriction-clock, run-write
and idempotency context as the old blocking helper. Both decoded files and their
disk room stay owned by that worker through their last use, even if HTTP leaves.
A separate live stop flag lets a queued native memory wait end when HTTP leaves;
it does not reuse the completed spool's flag or revoke the native operation.
A thread that cannot start or ends without an answer keeps the existing
"widen approval failed" internal-server-error response.

Before decoding the first stored canonical byte vector, a short authorized read
measures the stored row's byte length and closes. The process memory line then
reserves a conservative allowance for that vector's payload and growth. The
allowance derives from the pinned JSON Vec decoder and Rust allocator geometry,
not a request-size cap or the observed canonical length. A fresh read rechecks
owner and credential and the required allowance before decoding. A row that grew
replans only after closing the transaction and returning the entire old allowance,
before reading the expected file. No memory wait holds a read or write transaction
or another memory lease.

The actual canonical vector capacity is recorded on the same lease. The vector
stays charged through comparison and the acting writer, and drops before its lease.
A physical floor keeps the existing internal-server-error shape and says the
canonical byte allowance could not be reserved, not that an allocation was observed
to fail. A stopped wait keeps body-not-whole; native refusals keep their old mapping.
The admitted read keeps its decoded proposal row with that vector. In the acting
writer, owner and holder liveness are checked first. A streaming JSON writer then
compares the entire retained row's serialized bytes with the actual stored bytes,
without making another encoded row vector. Only exact whole-row equality reuses the
retained row and its already charged canonical payload. Validation, current-owner,
expiry, unresolved-state and full canonical-byte checks still precede grant minting.
The row, including its payload, drops before the same lease on every return path.

Any stored-byte difference, including a metadata-only change or a different JSON
spelling, takes the original native row decode, validation and owner checks. An
encoding failure also takes that path. No new refusal, memory wait, file replay or
request-size bound is added. This fallback's second canonical vector remains
unaccounted, as do row metadata, validation trees, typed values, re-encoding,
overlay-owned raw row copies and allocator RSS. The unchanged-row reuse is not a
claim of complete native-answer heap admission.

For an accept, file comparison runs outside every LMDB transaction. It compares
exact bytes to the proposal's stored canonical delta, not just a digest.
The acting writer then checks the current owner, holder credential, unresolved
state, expiry and the same canonical bytes before minting the grant and recording
the acceptance. No file read or await runs inside that writer.

A large reject validates its reference with the same credential-first, fixed-buffer
and EOF rules, then uses the existing checked decline and acting writer. No file
read runs inside that writer. Its reference file and the same disk room move whole
into the blocking worker, so HTTP cancellation cannot return the room early.

The wire requests, error fields and OpenAPI schemas do not change. Reject still
has no `expected_delta`.

## Scope

This removes request-sized `expected_delta`, `proposal_ref`, property-name and
metadata-head allocations on large widen-answer paths. It is not a bound on the
whole endpoint or a claim of complete heap admission. Other doors' generic metadata
decoding, upstream frame backing and channel/future/error metadata, and the
remaining stored proposal allocations stay separate work. The fixed 64 KiB working buffers and 64-byte reference buffer
are internal I/O geometry and the existing reference shape, not new request caps,
defaults or timeouts.
