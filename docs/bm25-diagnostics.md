# BM25 Integrity Diagnostics

ONE-315 decision: BM25 index-corruption observability uses content-free
counters in core `oneiron`, not default per-token or per-term runtime warnings.
The counters belong to the vault, not to the process (2026-09 state-ownership
pass), so two vaults open in one process count separately.

## Surface

`vault.diagnostics().bm25_snapshot()` returns stable counters for:

- `malformed_posting_alignment`
- `missing_scored_document_metadata`
- `deindex_self_healed_missing_posting_row`
- `deindex_self_healed_missing_posting_entity`

The labels intentionally carry no query text, terms, entity ids, payload bytes,
tenant handles, or file paths. They are suitable for low-noise diagnostics and
test assertions without leaking user content.

## Behavior

Search-time integrity failures that would produce incorrect rankings still fail
closed with `Error::CorruptedIndex`. Targeted classes increment a diagnostic
counter immediately before returning the existing error:

- malformed posting bytes, duplicate entity postings, or impossible posting
  cardinality count as `malformed_posting_alignment`
- missing or inconsistent per-document field-length metadata during scoring
  counts as `missing_scored_document_metadata`

Deindexing may self-heal when the forward row still names a term but the posting
row, or this entity's duplicate under that posting row, is already missing. In
that case `deindex_text` removes the remaining per-doc metadata and corpus
stats, increments the matching self-heal counter, and continues. Malformed bytes,
field-length drift, and stats underflow remain fail-closed.

## Noise And Overhead

No log event is emitted by default for these BM25 paths. The common search and
deindex paths do not touch the diagnostic atomics; increments happen only on
rare hard-corruption or self-heal branches and use relaxed atomics. Operators
who need durable repair details should run maintenance/reindex tooling and use
these counters as the low-cardinality signal that such inspection is warranted.
