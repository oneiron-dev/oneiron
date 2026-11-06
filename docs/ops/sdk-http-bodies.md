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
For the same ordinary calls, receipt middleware stages the input bytes and
parses its receipt input from a file reader. After capturing the receipt's
inputs and digest, it drops that parsed value before dispatch. It replays the
original bytes to the handler. For these same ordinary calls, the handler
stages those bytes again and parses its final JSON input from a file reader
on a blocking worker. RAM-only calls still use Axum's original JSON extractor.
The content-type check runs before handler staging and accepts the same MIME
types as that extractor. Compressed calls also stage the decoded file again
for the receipt read. These separate passes add disk I/O; this is not a
single-pass, speed, heap-bound or disk-privacy claim.

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
partially decoded request. Receipt staging failures keep the ordinary refusal
receipt path and return an internal error without running the handler. An
input read failure or over-limit ordinary body still reaches that handler
empty, as before. The staged payload adds no vault record beyond the ordinary
call or refusal receipt. This adds no disk or memory admission policy.

The receipt's existing canonical digest is carried to invocation admission,
so it need not read and parse the same body again. A custody arrival keeps its
original combined redaction-and-secret digest, not the receipt's redacted-only
digest. The handler keeps the same accepted JSON, content types and malformed
request error. A physical handler staging or file-read failure returns an
internal error through the existing call and refusal-receipt path.

The holder proof, invocation identifier, turn and session headers, response
receipts, timeouts and redirect policy are unchanged. The holder proof signs
the slip's timestamp-and-nonce challenge, not the request body. Invocation
claims separately bind the server's canonical call-body digest.

## SDK response bodies

The synchronous SDK parses ordinary success replies and error envelopes
from a buffered, capped reader instead of collecting the complete raw body
in a byte vector. Ordinary successes keep the existing 64 MiB read limit and
unchanged truncation, over-limit and JSON-decode error handling.
The existing 64 KiB limit and its one-byte overrun probe still apply. Invalid
JSON is drained only to that same bound, so over-limit and unreadable errors
keep their existing transport-error message. Foreign response bytes still
never appear in that message. All typed refusal fields keep their existing
mapping. A lens callback's already-decoded 202 refusal goes straight from its
JSON value to the same typed envelope, without serializing another byte copy.
Pairing replies use the same bounded reader and keep the original no-slip,
truncation, token and checkpoint-pin checks. Raw asynchronous model responses
keep their existing limits and readers.
