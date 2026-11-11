# Retrieval query byte rows

`[limits].recall_query_bytes` defaults to `8_388_608` UTF-8 bytes. Crossing
this engine row calls the vault's installed `LimitAsk` port and serves the query
whole. An embedded host can set the row through `EngineLimits` and install its
own port; without a port, a crossing asks nobody. The server accepts the same
key in `[limits]` and installs its normal question port.

The row is measured at execution, not in pure SDK input validators:

- `PipelineBuilder::run_for_pack` measures its resolved text query and each
  phonetic query independently, once before expansion or scoring. This covers
  the mapped context-pack, scoped BM25 and hybrid pipeline paths.
- `scoped_session_text` measures the scoped room search after its deny-all
  branch. Room BM25 and the run's room search share this execution path.
- A direct native text search measures in `default_text_search` or the
  alternative profile/room implementation, `search_text_scored`, not both.

Outer binding and recall doors do not add a second measurement. The old shared
8 KiB query refusal and the BM25 character-boundary clip are removed, including
the generated recall/BM25 validators and the legacy N-API and C ABI guards.
The tokenizer reads the full query; an embedder's separately counted model
input window still applies to embedding.

## Other limits remain independent

This row does not change result-count limits, deadlines, authentication,
authority, spaces, dimensions, UTF-8 validation or nonempty-input checks.
It does not replace HTTP/MCP `retrieval_query_bytes`, transport/body limits,
residence budgets or a model's input window. A separate limit can still end or
refuse a request before it reaches an engine search. This change does not
claim end-to-end large-body support through those transports.

## Scope of the current FIX55 slice

The shared refusal/clip removal and the mapped execution measurements are
implemented. FIX55 remains PART pending the complete caller/consumer audit,
including ASR fire/final and retrieval-loop execution links, all guest wire
paths, and any direct low-level index caller outside these measured entries.
No runtime, concurrency or latency result is implied by this source change.
