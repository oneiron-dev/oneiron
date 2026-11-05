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

The raw-body spool already reserves a stored-copy amount equal to its counted
length. The decoded hex file cannot exceed half its own raw member's length;
unescaping the reference cannot expand its raw member. Their combined decoded
length therefore cannot exceed the raw body's length. That same room is retained
through both files' final native read; it is not replaced with a second cumulative
claim. Files are anonymous and are removed when their handles close.

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
decoding, normal working-buffer admission and stored proposal allocations
remain separate work. The fixed 64 KiB working buffers and 64-byte reference buffer
are internal I/O geometry and the existing reference shape, not new request caps,
defaults or timeouts.
