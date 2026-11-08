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
debug-rendered input fields, canonical repository references and metadata-hash
hex values. Each string is counted by its actual capacity on that line. A local
accounting closure moves the same string onward; its lease stays outside the
closure until the capture ends. Source IDs, source hash buffers and retained
JSON are separate owners.

The shared replay identity also holds the actual backing capacities of its
media-space vector and two copied metadata hash buffers on that line until the
native attempt releases the identity. Each hash copy is recorded immediately
after its existing read, so a later read error also releases its charge after
the buffer drops. Each successfully decoded space declaration's owned ID
string is also recorded once on that lease, separately from the query's own
space ID. Its buffers are declared before the private lease. The space
declarations' sets and maps remain outside that charge. Native declaration
checks, floors, hashes and capture gates stay unchanged.

Replay capture also records the actual capacities of the two copied query and
corpus-snapshot reference strings. A private per-attempt lease stays after the
payload fields and moves into the pack before its replay-input local. A retry
replaces the old payload before its old lease. The original strings remain
charged through replay metadata patches, record construction and borrowed
writes, until that original payload drops. Public replay types, their deep
clone and serialization behavior stay unchanged. The provisional writer's
detached record clone owns different backing and is not covered by this lease;
neither are serialized row bytes or later decoded rows.

The original captured replay config records its actual owned string capacities,
array slot capacities and recursively owned children, including object-key
strings. These are the retained `Value` buffers, not the distinct transient
serialization inputs. Object-map buckets and number internals remain unpriced.
The private per-attempt accounting owner measures the final config after all
capture joins. Each of the two later policy metadata assignments keeps its
existing evaluation and error behavior, then measures the updated config after
the replaced value drops. It records the new extent before releasing the old
tracked extent, so repeated patches neither release live backing early nor
accumulate stale charges. Reference-string charges stay separate within the
same lease. No config walk or new memory line is added to an unbound capture.
The detached record clone's config remains separate from this original owner.

The canonical provisional writer separately records those same two reference
capacities and the config's known backing on its deep-cloned record, using the
same optional supplied line. Both config owners use the replay-data type's
shared capacity calculation, but each measures its own actual buffers after
construction or cloning. The cloned config's charge does not inherit the
original's capacities or lease. Its private owner keeps the whole cloned
record before that separate lease and moves by value into the detached write.
Staging consumes the whole owner, so neither an unstarted write nor a write
error can release the lease before the cloned payload. The clone's object-map
storage, number internals and other record fields remain outside that charge.
Existing queue behavior is unchanged.

The detached clone also records the actual slot capacities of its signal,
result-ID, score-breakdown and degradation vectors on that same private lease.
Each uses its native element size. Each cloned score-breakdown entry also
records its component vector's actual slot capacity, separately from the outer
score-breakdown vector. Component fields and degradation variants have no
owned inner storage. These are separate buffers created by the record clone,
not the original pipeline's vectors. The slot charge applies even when the
cloned record has no replay inputs, provided the caller supplied the line.
The same clone also records the actual capacities of its optional query-expander
ID and empty-reason strings. These are outer record fields, separate from the
two nested replay references and config strings. Absent fields and strings with
zero capacity add no string backing; no length estimate or extra copy is used.

A present cloned trace records its per-channel vector's actual slot capacity,
each channel's candidate vector and the candidate vectors in its fused,
blended, reranked and final stages. Each candidate vector includes its entries'
component-vector backing, using the same capacity calculation as the cloned
record's top-level score breakdown. These cloned buffers are distinct even
when their entries describe the same results. All extend the same private
lease and single materialized charge. An absent trace adds no trace backing;
an unbound caller performs no added accounting walk. Serialized row bytes and
later decoded records remain separate.

A present cloned policy trace also records its decision vector's actual slot
capacity using the native decision size, on the same private lease and
materialized charge. Each decision's state, action and tier are inline within
those slots; they own no separate backing. The policy identity and envelope,
and the record's state, turn, action, quality and confidence adjustment also
own no separate backing. An absent policy trace adds no decision backing.
This does not price serialized or later decoded copies, config map storage,
number internals or construction peaks.

The canonical detached provisional stage separately records the actual backing
capacities of its encoded retrieval-row key and value after encoding, once on
that same private lease. It uses the existing typed staged-row writer without
re-encoding or copying either buffer. Both encoded buffers stay alive through
the native put and drop before the cloned record and its lease, including write
errors and unwind. An unbound caller keeps the original direct put path without
added accounting. This covers only the encoded key and serialized value on that
bound detached path. Serialization scratch, keys and values of marker, index,
session and other unbound writes, finalized rows and later decoded records are
separate allocations outside it.

Other pipeline buffers, remaining trace serialization storage, provider
storage, construction and return gaps, pre-growth admission and a full
working-set bound remain open.
No runtime, compiler or performance result is implied by these source changes.
