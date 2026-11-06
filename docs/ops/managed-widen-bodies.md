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
produce the same invalid-JSON response. The generic decoder used by other doors
is unchanged.

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

The raw-body spool uses the same shared process memory line before allocating its
existing 64 KiB read piece. This wait runs on its dedicated transfer worker after
the anonymous spool file is created, outside every vault transaction. The actual
buffer capacity is recorded on the lease. The piece drops before its lease on
success, error and unwind; both are released before the decoder starts, so they
do not overlap the decoder's later reservation.

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
only for the fixed reader buffer, not generic DTOs, metadata heads, base64 text or
native decoded rows.

## Native answers

Native acceptance checks the holder credential before validating the reference's
existing 64-byte lowercase hex shape. It reads that reference into a fixed 64-byte
buffer and checks EOF, never a request-sized string. Invalid references retain
their existing refusal and do not bypass the holder check.

For an accept, file comparison runs on a blocking worker, outside every LMDB
transaction. It
compares exact bytes to the proposal's stored canonical delta, not just a digest.
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
decoding, queued feed/frame-buffer admission and stored proposal allocations
remain separate work. The fixed 64 KiB working buffers and 64-byte reference buffer
are internal I/O geometry and the existing reference shape, not new request caps,
defaults or timeouts.
