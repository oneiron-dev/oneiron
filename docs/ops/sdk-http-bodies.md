# SDK HTTP request bodies

The Rust SDK backend shared by the JavaScript and Python bindings stages
ordinary synchronous facade requests with one JSON serialization. It keeps
small bodies in memory and spills larger bodies to a temporary file. The
spill threshold is `CODEC_MIN_FRAME_BYTES`, also used by the HTTP codec
(currently 16 KiB). The HTTP transport reads the staged body rather than
building a second whole-body byte vector.

The existing 64 MiB limit still applies to the raw JSON length, before any
request is sent or compressed. This is not an increase in the server's
accepted request size. For ordinary compressed facade requests, the server
stages the encoded body, decodes it into a second temporary file, then streams
that decoded file to the existing receipt and JSON readers. Both the encoded
and decoded lengths keep their existing limits. The decoder finishes before
dispatch, so malformed or over-limit compressed input still reaches no handler.
Unencoded requests and the final JSON extraction still buffer their bodies.

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

The server also keeps its in-memory codec path for every session-header call,
verbs in the `off_record` namespace, `ai.anonymous_chat`, all three custody
input verbs, and `vault.notes.editor.close` (a room-note hold can close without
a session header). Other API routes keep their existing codec path. Staging
files are anonymous temporary files owned by the request or its body reader;
closing the reader drops the file. Staging I/O failures do not dispatch a
partially decoded request. This does not add a vault record or a new disk or
memory admission policy.

The receipt's existing canonical digest is carried to invocation admission,
so it need not read and parse the same body again. A custody arrival keeps its
original combined redaction-and-secret digest, not the receipt's redacted-only
digest. The handler's JSON parsing and its content-type refusals are unchanged.

The holder proof, invocation identifier, turn and session headers, response
receipts, timeouts and redirect policy are unchanged. The holder proof signs
the slip's timestamp-and-nonce challenge, not the request body. Invocation
claims separately bind the server's canonical call-body digest.
