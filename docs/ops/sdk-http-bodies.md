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


### Core connector schema and status outputs

`connector.schema` and `connector.call_status` move the native arbitrary JSON
fields out before the original whole-result codec, then put them back at the
same paths. This covers approved input schemas, delivered content and optional
structured/error data, and each awaiting-input question's requested schema.
The native tags, finite fields, omissions, required nulls and item order stay
unchanged. This does not change connector admission, source stamps, native
producers, hooks or the separate UniFFI result conversions.


### Core conversation write receipts

`vault.conversations.create` and `vault.conversations.turns.create` move the
returned native receipt's stored body around the original whole-result codec.
The required `body` stays present, including null. The native writer still
selects the id, entity type, learned time and stored body, including a TURN's
announcement normalization. Its writes, authorization, input and hooks do not
change. The existing UniFFI receipt codec is separate and unchanged.


### Core shape output documents

The core `vault.shape.read`, `vault.shape.plan`, `vault.shape.apply`,
`vault.shape.groups`, `vault.shape.groups.resolve`, `vault.shape.items.receipt`
and `vault.shape.plan.card` result adapters move each returned manifest row's
JSON around the original whole-result codec. This covers stored and live seed
rows, plan items and undeclared rows, the before/after rows in apply receipts,
and the items in each inbox group.
Present null JSON keeps its field; absent JSON stays omitted. Native tags,
field positions, array order, finite fields and optional results keep their
existing encoding. The plan card's generated UI stays on its original codec.
Native producers, read projections, authority, writes, inputs, hooks and the
separate UniFFI adapters are unchanged. This is not a general depth or memory
bound.


### Core skill-library output documents

The core `vault.skills.get`, `vault.skills.list`, `vault.skills.archive`,
`vault.skills.restore` and `vault.skills.fork` result adapters move the returned
skill's provenance and each present call's argument and return contracts around
the original whole-result codec. This includes each skill in a page and the
skill in a `restored` receipt. The same native JSON values return at the same
fields, including nulls. A missing call stays null. Empty pages, pagination,
lineage, source evidence, files, receipts and the other restore outcomes keep
their original encoding.
Native projection of stored provenance, contract validation, storage, owner
checks, lifecycle and restore admission, inputs, hooks and the separate UniFFI
conversion are unchanged. This selected output conversion is not an end-to-end
depth or memory bound.


### Core Coach inspection proposal output

The core `vault.coach.inspect` result adapter moves the served proposal claim's
value and scope, and each present repair document, around the original
whole-result codec. It restores the native JSON at its original fields.
An absent proposal and an absent repair keep their original null fields;
returned repair values, including a present null, keep their field position.
The outer scoped-read receipt, report, diagnostic and working set retain their
original codec. Native read filtering, claim and repair selection, authority,
inputs, hooks and public types are unchanged. This does not change diagnostic
projection or prove a general depth or memory bound.


### Core pending artifact proposal summaries

The core `vault.artifacts.proposals` and `vault.artifacts.propose_output` result
adapters move each returned proposal's summary around the original whole-result
codec, then restore it at the same field. This includes the native report JSON
already selected by the producer. Required null values and list order remain
unchanged. The other proposal fields retain their original encoding.
Native report parsing and its null fallback, validation, read filtering,
retention, authority, inputs, hooks and the separate UniFFI conversion are
unchanged. This selected output conversion is not an end-to-end depth or memory
bound.


### Core secret-use result output

The core `self.use` result adapter moves the native answer's already-cleared
result around the original whole-result codec, then restores it at the same
field. A present null keeps its field; an absent result remains omitted.
Status, failure text and the use receipt retain their original encoding.
Native provider parsing, custody and send-time secret clearing, admission,
inputs, hooks and the separate UniFFI conversion are unchanged. This selected
output conversion is not an end-to-end depth or memory bound.
