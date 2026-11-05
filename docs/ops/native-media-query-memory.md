# Native copied media-query memory

A native pipeline owns separate copies of a media query's space string,
embedding vector and kind-filter vector. These copies are distinct from the
returned seed storage described in `media-seed-memory.md`.

A host can supply its existing memory line through `media_query_memory` on a
pipeline or context-pack builder. The server context-pack route supplies its
own line before adding media queries. Each push records the actual retained
outer-buffer capacity increase and the new query's owned inner capacities.
The concrete element sizes are used. This is post-allocation accounting, not
admission before allocation.

The private owner keeps its query buffers before its accounting fields, so the
buffers drop before their charge. A deep clone records that clone's actual
capacities on a separate lease on the same supplied line. Context-pack L2 and
neighbor plans and retrieval-loop plans keep their own copied storage charged
until those owners drop. Reads, hashing and trace inputs still borrow the same
query fields.

An unbound native builder remains usable. It gains no global memory line,
refusal, configured limit, wait, floor or timeout. Binding this owner does not
change media embedding, validation, authority, ranking, cuts, results or
receipts.

Core query supplies its existing server memory line to seeded retrieval. The
MCP adapter borrows that same host-supplied line and forwards it through its
fresh actor-bound reader to both seeded query and context-pack construction.
An adapter built without a line keeps its previous unbound behavior. The query
helper lives in the adapter's `media_query` child; its native search and error
handling are unchanged apart from this resource argument.

When bound, the adapter also records the actual capacity of the separate
borrowed tuple-view vector made by its seeded query helper. Only the vector's
backing storage is counted. Its space, embedding and kind-filter references
borrow the seed buffers; those buffers and the pipeline's owned copies stay
with their separate owners. The view drops before its local lease on both
success and error, including unwinding. An unbound adapter remains usable.

Opt-in replay capture also records the actual backing capacities of its
temporary media-list, kind-override, BM25-field and vector-evidence
`Vec<Value>` buffers. Each temporary stays alive through its existing JSON
serialization and drops before its local lease, including the vector-evidence
buffer moved into the existing serialization expression. These charges use the
same supplied line and leave an unbound capture usable. They cover vector slots
only, not the temporary objects' inner storage or the retained replay JSON.

An `AnyOf` corpus replay also records the backing capacities of its temporary
hex-ID vector and each owned hex string. The existing ID expression stays at
its JSON field, so field evaluation order is unchanged. The vector moves into
the serialization temporary while the enclosing arm keeps the lease alive.
The source IDs and copied retained JSON are outside this charge.

Sorted access-factor override and community-session usage replay also record
the actual backing capacities of their temporary vectors and each newly owned
hex-ID string on that line. Their borrowed factor or count values and source
maps are not owned by the temporaries. The existing collections, sorts and JSON
field evaluation stay in place. Each lease survives its returned vector's
serialization temporary, but does not cover the retained replay JSON.

World-authority replay records its two temporary hex-ID vectors and optional
owned default-claim hex string on the same line. Only those new backing
capacities are counted. Source authority sets, source claim IDs and retained
JSON are separate. The existing field order and authority values are unchanged;
the enclosing serialization scope keeps the lease past its ID temporaries.

Replay also records owned temporary strings used for a single corpus ID,
debug-rendered input fields and metadata-hash hex values. Each string is
counted by its actual capacity on that line. A local accounting closure moves
the same string onward; its lease stays outside the closure until the capture
ends. Source IDs, source hash buffers and retained JSON are separate owners.

The shared replay identity also holds the actual backing capacities of its
media-space vector and two copied metadata hash buffers on that line until the
native attempt releases the identity. Each hash copy is recorded immediately
after its existing read, so a later read error also releases its charge after
the buffer drops. Each successfully decoded space declaration's owned ID
string is also recorded once on that lease, separately from the query's own
space ID. Its buffers are declared before the private lease. The space
declarations' sets and maps remain outside that charge. Native declaration
checks, floors, hashes and capture gates stay unchanged.

Other pipeline buffers, remaining trace serialization storage, provider
storage, construction and return gaps, pre-growth admission and a full
working-set bound remain open.
No runtime, compiler or performance result is implied by these source changes.
