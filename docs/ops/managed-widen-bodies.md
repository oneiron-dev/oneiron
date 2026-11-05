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

The raw-body spool already reserves a stored-copy amount equal to its counted
length. The decoded hex file cannot exceed half that raw length. That same room
is retained through the final native read; it is not replaced with a second
cumulative claim. Files are anonymous and are removed when their handles close.

## Native acceptance

File comparison runs on a blocking worker, outside every LMDB transaction. It
compares exact bytes to the proposal's stored canonical delta, not just a digest.
The acting writer then checks the current owner, holder credential, unresolved
state, expiry and the same canonical bytes before minting the grant and recording
the acceptance. No file read or await runs inside that writer.

The wire request, error fields and OpenAPI schema do not change. Reject has no
`expected_delta` and keeps its previous path.

## Scope

This removes request-sized `expected_delta` allocations on the large-body path.
It is not a bound on the whole endpoint or a claim of complete heap admission.
Other metadata, `proposal_ref`, unknown JSON members, normal JSON working buffers
and stored proposal allocations remain separate work. The two 64 KiB working
buffers are internal I/O geometry, not new request caps, defaults or timeouts.
