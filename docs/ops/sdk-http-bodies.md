# SDK HTTP request bodies

The Rust SDK backend shared by the JavaScript and Python bindings stages
ordinary synchronous facade requests with one JSON serialization. It keeps
small bodies in memory and spills larger bodies to a temporary file. The
spill threshold is `CODEC_MIN_FRAME_BYTES`, also used by the HTTP codec
(currently 16 KiB). The HTTP transport reads the staged body rather than
building a second whole-body byte vector.

The existing 64 MiB limit still applies to the raw JSON length, before any
request is sent or compressed. This is not an increase in the server's
accepted request size. The server's codec, invocation middleware and JSON
extractor still buffer request bodies.

Requests at or above the codec threshold use zstd only when the encoded
body is smaller. Compression uses the existing codec level. If compression
fails, the SDK sends the original staged body without a content encoding.
Temporary files belong to the request and are closed when their readers are
dropped. Staging I/O failures return a transport error; they do not send a
partially serialized request.

Off-record session handles, verbs in the `off_record` namespace,
`ai.anonymous_chat`, and in-process exchanges keep their original in-memory
request serialization. The sealed custody submission also keeps its existing
path: above the facade limit it goes to the owner route that spools custody
input. Asynchronous model requests, pairing, credential renewal and lens
callbacks are unchanged.

The holder proof, invocation identifier, turn and session headers, response
receipts, timeouts and redirect policy are unchanged. The holder proof signs
the slip's timestamp-and-nonce challenge, not the request body. Invocation
claims separately bind the server's canonical call-body digest.

## Core key-value results

The embedded core `vault.kv.get`, `vault.kv.put`, and `vault.kv.search`
result adapters move each item's JSON payload into the result without
serializing that payload again. All payloads are removed before encoding
the remaining finite record fields with the existing codec. The adapters
then restore the original payloads, including their object and array order.
Absent gets stay JSON null; put receipts and search results keep their
existing fields and ordering. Native storage, input decoding, verb hooks,
and client result types are unchanged. Other core result encoders retain
their existing behavior.

## Core saved-query results

The core `self.saved_query.create`, `self.saved_query.update`, and
`self.saved_query.archive` result adapters move claim operands and judge
rubrics out of the returned record before its existing structural codec
runs. `self.saved_query.read` does the same when its record is present.
The adapters restore each original JSON value at its existing field.
Filter and matcher tags, term order, explicit nulls, lifecycle fields, and
the read result's `found` and `record` fields keep their existing encoding.
Membership results and host-only evaluation are unchanged. These result
adapters do not change storage, query admission, input decoding, or hooks.

## Core claim-review results

The core `vault.claims.review` and `vault.claims.vetting` result adapter
moves the returned claim's JSON value and optional scope out before the
existing record codec runs. It restores both original payloads at their
existing fields without serializing them again. Required null values stay
present; absent and null optional scopes still encode as a present null key.
The review handle, claim metadata, provenance, labels, and finite numeric
fields keep their original encoding. Native reads, owner checks, input
decoding, verb hooks, and public result types are unchanged. This selected
result conversion does not prove end-to-end depth or memory bounds.

## Core scoped, settled, and extracted claims

The core claim list, filtered list, history, filtered read, settlement, and
signal-extraction result adapters use the same owned claim payload transfer.
Every returned claim's value and optional scope are removed before the
existing whole-result codec runs, then restored in their original positions.
Empty claim lists, absent filtered reads and extraction jobs, null values,
and optional scopes keep their original JSON representation. The original
codec still emits the `narrowing` receipt, settlement warnings, job and park
state, citations, prospective hints, provenance, and all finite fields.
Native reads, writes, owner checks, input decoding, verb hooks, and public
result types are unchanged. The host-only core vet call is unchanged.

## Core model-catalog output metadata

The core SDK `vault.models.catalog.refresh` and `vault.models.catalog.get` output
adapters move metadata from both the seed catalog rows and the resulting registry
rows before the original whole-record codec. `vault.models.catalog.diff` does the
same for every present previous and current row. The adapters restore the owned
JSON values in their original positions afterward. Empty metadata maps remain
omitted; present keys with null values remain present. Row order, absent diff
rows, receipts and the remaining native serde fields keep the original codec.
Native producers, owner checks, catalog validation and input handling are
unchanged. This does not change the separate UniFFI model-catalog conversion or
the storage codecs, and does not claim a general depth or memory bound.
