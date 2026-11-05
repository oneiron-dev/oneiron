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

The core-query and MCP adapter thread is not connected in this source bank yet.
Other pipeline buffers, trace serialization, provider storage, construction and
return gaps, pre-growth admission and a full working-set bound remain open.
No runtime, compiler or performance result is implied by these source changes.
