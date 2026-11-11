# Typed signing preview

`vault.esign.signing.preview` returns the page geometry and field layout of one
item under its recipient signing capability. Its typed input is `token` and
`item`; its typed response is `pages` and `fields`. The normal generated SDKs,
facade and OpenAPI schema publish those same types.

The capability authorizes the ceremony. The bound caller still classes its Load
and a narrowed credential's lane still bounds the document. The read uses the
same immutable original version, or the canonical sealed version with its hash
check, as the existing public preview. Preview does not record Viewed; that
remains an explicit ceremony action.

## Resources

The native facade uses the registered document-memory operation, like the native
signature-image door. Actual FILE and plain inline ASSET body lengths reserve
memory before allocation. Record-head reads retain their existing post-read
reservation. The same hold accounts for actual Vec capacity and grows for PDF
inspection. Released parse stages bank spare for later stages, so the hold keeps
the parse's peak rather than its sum. The input bytes drop before their hold.

Reservations use the host's existing fair queue wait. This facade adds no
absolute operation deadline of its own and introduces no new timeout or size
cap. A host without a registered document-memory provider keeps the engine's
existing measuring-port behavior. A floor or wait refusal remains a typed
resource error, not a malformed-document error. This is not a full-heap closure
claim for layout or response allocations.

## Existing public HTTP doors

`POST /sign/preview` still admits its capability header before reading its body,
uses its actual caller/IP/user-agent evidence, and runs its existing leased read
and parse on its blocking worker with its existing 60-second memory-wait bound.
It does not route through the facade or lose its request evidence.

Only the pure layout step is shared. The editor's `POST /sign/layout` keeps its
existing admission and body policy. Both keep the same page lookup, field order,
geometry rules, JSON carrier and refusal response. The public preview's OpenAPI
request remains the headerless `{item}` shape; its response now names the actual
typed layout instead of a generic object.

Deploy matching engine/server and normal generated clients to use the new verb.
No configuration, stored-format migration, protocol bump, organ executable or
worker/VM image change is introduced here. Broader process-organ migration is
separate work; this addition does not claim that it is complete.
