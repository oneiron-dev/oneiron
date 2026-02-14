# oneiron Implementation Tasks

> Reference: [SCHEMA-DESIGN.md](./SCHEMA-DESIGN.md), [BUILD-PROMPT.md](./BUILD-PROMPT.md), [DEPLOYMENT.md](./DEPLOYMENT.md)

## Workflow

Each task is a **PR** built in its own **git worktree**. This isolates work and triggers auto-review on PR creation.

### Setup (per task)

```bash
git worktree add .worktrees/<task-name> -b feat/<task-name>
# e.g. git worktree add .worktrees/types-store -b feat/types-store
```

Worktree directory: `.worktrees/` (gitignored).
Branch naming: `feat/<task-name>` (e.g. `feat/types-store`, `feat/batch-builder`, `feat/bm25`).

### Phase 1 — Build (Codex)

1. Create worktree + branch
2. Feed task to codex (working in `.worktrees/<task-name>/`)
3. Codex plans → claude (opus) reviews plan
4. Codex implements + writes tests
5. `cargo test` passes → codex commits

### Phase 2 — Review (Opus)

6. Claude (opus) reviews code
7. If changes needed → codex updates, tests again, commits
8. Repeat until opus approves

### Phase 3 — Simplify (code-simplifier)

9. Run `code-simplifier` agent (opus) → clean/simplify code
10. `cargo test` → verify nothing broke
11. Claude (opus) reviews simplifier output
12. Commit cleaned code

### Phase 4 — PR + Merge

13. Push branch, create PR → auto-review triggers
14. Address review feedback if any
15. Merge to `main`, delete worktree: `git worktree remove .worktrees/<task-name>`
16. Confirm ready for next task

### Worktree mapping

| # | Task | Worktree | Branch |
|---|------|----------|--------|
| 1 | Types + LMDB Store | `.worktrees/types-store` | `feat/types-store` |
| 2 | Batch Builder + Indexes | `.worktrees/batch-builder` | `feat/batch-builder` |
| 3 | BM25 Full-Text Search | `.worktrees/bm25` | `feat/bm25` |
| 4 | HNSW Vector Search | `.worktrees/hnsw` | `feat/hnsw` |
| 5 | PPR Graph Traversal | `.worktrees/ppr` | `feat/ppr` |
| 6 | RRF Fusion + Pipeline | `.worktrees/rrf-pipeline` | `feat/rrf-pipeline` |
| 7 | Context Pack + Serialization | `.worktrees/context-pack` | `feat/context-pack` |
| 8 | Index Maintenance | `.worktrees/maintenance` | `feat/maintenance` |
| 9 | Benchmarks | `.worktrees/benchmarks` | `feat/benchmarks` |
| 10 | FFI Layer | `.worktrees/ffi` | `feat/ffi` |

---

## Task 1: Types, Errors, and LMDB Store Foundation

**Files:** `types.rs`, `error.rs`, `store.rs`, `lib.rs`
**Est:** ~400 LOC
**Depends on:** nothing

Implement core types and the LMDB storage layer with all 18 databases.

**Types (`types.rs`):**
- `EntityId` — newtype over `[u8; 16]`, UUID v7 big-endian. Implement `Ord`, `Eq`, `Hash`, `Debug`, `Clone`, `Copy`.
- `EdgeKind` — `#[repr(u8)]` enum with 13 variants (see SCHEMA-DESIGN.md EdgeKind section). Include `default_weight() -> f32` method.
- `TimeRange` — `{ start: u64, end: u64 }`. For point events, `start == end`.
- `VaultConfig` — with `dimensions`, `embedding_model`, `map_size`, `max_readers`, `hnsw: HnswConfig`. Include `device()` and `server()` presets.
- `HnswConfig` — `m_max_0`, `ef_construction`, `ef_search`.
- `ScoredEntity` — `{ id: EntityId, score: f32 }`.
- `Signal` — enum: `Vector`, `Text`, `Phonetic`, `Temporal`, `Ppr`.
- `PackFormat` — enum: `Json`, `Yaml`, `Toon`, `Markdown`, `Plaintext`.
- `FieldProfile` — enum: `Minimal`, `Standard`, `Full`.

**Errors (`error.rs`):**
- `Error` enum via `thiserror`: `Storage(heed::Error)`, `Io(std::io::Error)`, `DimensionMismatch { expected, got }`, `EmbeddingModelChanged { stored, requested }`, `MapFull`, `EntityNotFound`, `InvalidKey`.
- `pub type Result<T> = std::result::Result<T, Error>;`

**Store (`store.rs`):**
- `Store` struct holding `heed::Env` + 18 named `heed::Database` handles.
- `Store::open(path, config) -> Result<Store>` — create env, open all 18 databases by name (use `create_database` / `open_database`).
- Key encoding functions:
  - `encode_edge_key(src, kind, tgt) -> [u8; 33]`
  - `encode_temporal_key(ts, id) -> [u8; 24]`
  - `encode_type_key(entity_type, id) -> [u8; 17]`
- Embedding model verification on open (read `hnsw_meta["model_id"]`, compare with config).

**Vault (`lib.rs`):**
- `Vault` struct wrapping `Store`.
- `Vault::open(path, config) -> Result<Vault>`
- Entity CRUD: `put_entity`, `get`, `delete_entity` (delete from `entities` db only for now, full deindex in later task)
- Vector CRUD: `put_vector`, `get_vector`
- Edge CRUD: `put_edge`, `delete_edge`, `edges_out`, `edges_in` — edge values are 12 bytes (`weight: f32 + created_at: u64`)

**Tests:**
- Open vault in temp directory, put/get/delete entities
- Put/get vectors, verify dimensions
- Put edges with weights, query edges_out/edges_in, delete edges
- Verify embedding model check (mismatch → error)
- Verify all 18 databases are created (check via env stats or similar)

**Key notes from BUILD-PROMPT.md §8 (bugs to avoid):**
- Do NOT use `heed3`, use `heed` (0.20.x)
- Use `EnvOpenOptions` not `EnvBuilder`
- Set `max_dbs(24)` on env open
- Entity IDs are big-endian for correct LMDB lexicographic ordering

---

## Task 2: Batch Builder + Temporal/Type/Phonetic/Short ID Indexing

**Files:** `batch.rs`, `store.rs` (extend), `lib.rs` (extend)
**Est:** ~400 LOC
**Depends on:** Task 1

Implement the `BatchBuilder` for atomic multi-database writes, and all secondary index writes.

**Batch Builder (`batch.rs`):**
- `BatchBuilder<'a>` struct borrowing `&'a Vault`
- Accumulates operations: `put`, `vector`, `edge`, `text` (placeholder — just store for Task 3), `phonetic`, `delete`, `delete_edge`
- `commit()` — opens one LMDB write txn, applies all operations atomically, returns `Result<()>`
- Method chaining (each method returns `Self`)

**Secondary Index Writes (in `commit()`):**
- `type_index`: write `[entity_type(1) | entity_id(16)] → empty` for each `put`
- `temporal_occurred_start`: write `[start_ts(8 BE) | entity_id(16)] → empty`
- `temporal_occurred_end`: write `[end_ts(8 BE) | entity_id(16)] → empty` (skip if start == end, point event)
- `temporal_learned`: write `[learned_ts(8 BE) | entity_id(16)] → empty`
- `phonetic_index`: for each code, append entity_id to the posting list at that code
- `short_ids` + `short_ids_reverse`: assign short ID on first put (per-type counter stored at sentinel key `[0xFF; 16]` under each type byte in `short_ids`), compute content hash (`xxHash32(blob) % 256`)

**Simple API uses batch internally:**
- Refactor `put_entity` to use `BatchBuilder` internally (one-operation batch)
- Same for `put_edge`

**Full Delete (extend `delete_entity`):**
- Read entity to get type byte, timestamps, phonetic codes
- Delete from all secondary indexes: `type_index`, `temporal_*`, `phonetic_index`, `short_ids`, `short_ids_reverse`
- Delete edges (prefix scan `edges_out[E|*]` and `edges_in[E|*]`, delete matching reverse entries)
- Delete entity blob + vector
- All in one write txn

**Review follow-ups from Task 1:**
- Validate `dimensions > 0` and `map_size` to a sane minimum in `Vault::open`
- `delete_entity` should return `Result<bool>` (whether entity existed)

**Tests:**
- Batch builder: put 3 entities + edges in one commit, verify all present
- Type index: query by type prefix scan, verify correct entities returned
- Temporal index: range scan, verify ordering
- Phonetic index: lookup code, verify entity IDs
- Short IDs: verify assignment (`cl1`, `cl2`), verify content hash changes on update
- Full delete: put entity, delete, verify all indexes cleaned up
- Batch atomicity: verify partial failure rolls back (e.g., simulate error mid-batch)

---

## Task 3: BM25 Full-Text Search

**Files:** `bm25.rs`, extend `batch.rs`
**Est:** ~600 LOC
**Depends on:** Task 2

**Tokenizer:**
- Unicode word boundaries + lowercase
- No stemming, no stop words for v1
- Return `Vec<String>` of terms

**Index (in batch commit):**
- For each `text(id, fields)` call in batch:
  - Tokenize all field values
  - Write `text_postings[term] += (entity_id, tf)` for each term
  - Write `text_meta[entity_id] = (doc_len, field_count)`
  - Write `text_forward[entity_id] = [term1\0term2\0...]` (for deindexing)
  - Update collection stats: `text_meta[[0x00;16]]` (total_docs++), `text_meta[[0xFF;16]]` (total_length += doc_len)

**Deindex (in delete_entity):**
- Read `text_forward[entity_id]` → list of terms
- For each term: read `text_postings[term]`, remove entity, write back (delete key if list empty)
- Update collection stats (total_docs--, total_length -= doc_len)
- Delete `text_meta[entity_id]`, `text_forward[entity_id]`

**Search:**
- `search_text(query: &str, limit: usize) -> Result<Vec<ScoredEntity>>`
- Tokenize query → look up posting lists → BM25 scoring → top-k
- BM25 params: `k1 = 1.2`, `b = 0.75` (standard)
- Average doc length from collection stats

**Tests:**
- Index 100 documents with known text, search for terms, verify ranking
- Verify exact match scores highest
- Verify deindex: delete document, search again, should not appear
- Verify multi-term query (AND semantics: score documents containing both terms higher)
- Edge case: empty query, empty document, single-term document

---

## Task 4: HNSW Vector Search

**Files:** `hnsw.rs`, `distance.rs`
**Est:** ~800 LOC
**Depends on:** Task 1

**Distance (`distance.rs`):**
- `cosine_similarity(a: &[f32], b: &[f32]) -> f32` — scalar implementation
- `cosine_distance(a, b) -> f32` — `1.0 - cosine_similarity`
- `#[cfg(target_arch = "x86_64")]` AVX2 variant (use `std::arch::x86_64`)
- `#[cfg(target_arch = "aarch64")]` NEON variant (use `std::arch::aarch64`)
- Auto-select at runtime or compile time

**HNSW (`hnsw.rs`) — Flat NSW (single layer):**
- `hnsw_insert(store, txn, id, vector, config) -> Result<()>`
  - If graph empty: set as entry point in `hnsw_meta`
  - Else: beam search from entry point to find nearest neighbors (ef = `ef_construction`)
  - Select up to `m_max_0` neighbors (simple nearest-first selection)
  - Write `hnsw_neighbors[id] = selected_neighbors`
  - For each selected neighbor: read their neighbor list, append id if not full, write back
  - Update `hnsw_meta["count"]`

- `hnsw_search(store, txn, query_vector, ef, limit) -> Result<Vec<ScoredEntity>>`
  - Beam search from entry point
  - Visited set (HashSet)
  - Return top `limit` by cosine similarity
  - **Skip dead nodes:** for each candidate, check `entities` db — skip if deleted (lazy deletion)

- Entry point management: store in `hnsw_meta["entry_point"]`

**Wire into batch builder:**
- When batch includes `vector(id, vec)`, call `hnsw_insert` in the commit txn

**Tests:**
- Insert 1K random vectors (128-dim for speed), search top-10
- Compute recall@10 vs brute-force cosine — target: >95%
- Test with deletions: delete 100 vectors, search should skip them
- Test empty graph: search returns empty
- Test dimension mismatch: error
- Benchmark: insert + search latency at 1K scale (print, don't assert)

**Review follow-ups from Task 1:**
- Consider zero-copy vector reads (`&[u8]` → `&[f32]` reinterpret) to avoid 16KB alloc per vector during search

**Review follow-ups from Task 2:**
- Validate `weight.is_finite()` in `apply_edge` and vector elements in `apply_vector` (NaN/Inf poisons HNSW distances)

**Key notes from BUILD-PROMPT.md §8:**
- Do NOT pre-allocate huge `Vec`s for neighbor lists. Read/write from LMDB each time.
- Entry point update: only update if new node has more connections (not needed for flat NSW, just set first node)
- Use `f32` not `f64`

---

## Task 5: PPR Graph Traversal

**Files:** `ppr.rs`
**Est:** ~400 LOC
**Depends on:** Task 1, Task 2

**Personalized PageRank:**
- `ppr_compute(store, txn, seeds: &[EntityId], depth: u32, alpha: f32) -> Result<Vec<ScoredEntity>>`
- Bidirectional: walk both `edges_out` and `edges_in`
- Per-edge weights: read `weight` from edge value (f32), use as transition probability
- `alpha` = teleport probability (default 0.15)
- Fixed-depth iteration (not convergence-based for v1)
- `PartOf` edge kind: hop-limited to max 2 hops
- `Opposes` edge kind: weight is 0.0, blocks propagation

**PPR Cache:**
- On compute: write result to `ppr_cache[seed_hash]` with metadata header (computed_at, graph_version, stale=0)
- On query: check cache first, use if not stale and not expired (TTL: 24h for active, 168h for dormant)
- `ppr_cache_deps`: for each entity in seed set, write `[entity_id | seed_hash] → empty`
- On edge write: look up `ppr_cache_deps[entity_id|*]`, mark matching caches as stale
- `graph_version` counter in `hnsw_meta["graph_version"]`, incremented on every edge write

**Tests:**
- Simple graph: A→B→C, PPR from A, verify B scores higher than C
- Weighted edges: A→B (w=0.9), A→C (w=0.1), verify B >> C
- Opposes: A→B (opposes, w=0.0), verify B gets no score
- PartOf hop limit: A→B(part_of)→C(part_of)→D(part_of), verify D not reached (max 2 hops)
- Bidirectional: A→B, C→B, PPR from A, verify C is reachable via B's inbound
- Cache: compute, verify cached, modify edge, verify stale, recompute

---

## Task 6: RRF Fusion + Pipeline Builder

**Files:** `fusion.rs`, `pipeline.rs`
**Est:** ~300 LOC
**Depends on:** Task 3, Task 4, Task 5

**Review follow-ups from Task 2:**
- Add `phonetic_forward` index (entity → codes) to replace O(vocabulary_size) full scan in `delete_from_phonetic_postings`

**RRF Fusion (`fusion.rs`):**
- `rrf_fuse(ranked_lists: &[Vec<ScoredEntity>], k: f32) -> Vec<ScoredEntity>`
- Standard RRF: `score(d) = Σ 1 / (k + rank_i(d))`, default `k = 60`
- Handles missing entries (entity not in all lists)

**Signal Boosts:**
- `boost_recency(scores, half_life_days, store, txn)` — exponential decay from `learned_at`
- `boost_salience(scores, store, txn)` — read from entity blob (if present)
- `boost_confidence(scores, store, txn)` — read from entity blob (if present)

**Pipeline Builder (`pipeline.rs`):**
- `PipelineBuilder<'a>` struct borrowing `&'a Vault`
- Lazy: accumulates search/filter/boost config, executes on `run()`
- `run()` opens one read txn, executes all signals, fuses, applies boosts/filters, returns `Vec<ScoredEntity>`
- Methods: `search_vector`, `search_text`, `search_phonetic`, `search_temporal`, `search` (convenience), `expand_ppr`, `boost_recency`, `boost_salience`, `boost_confidence`, `filter_types`, `filter_since`, `filter_occurred_range`, `filter_learned_range`, `limit`

**Phonetic search (in pipeline):**
- `search_phonetic(codes: &[&str])` — look up each code in `phonetic_index`, score by graduated edit distance
- Score: `1.0 - (levenshtein(query_code, stored_code) / max_len)`
- Multi-code boost: entity matching both primary + alternate → 1.2× boost

**Temporal search (in pipeline):**
- `search_temporal(anchor_start, anchor_end, limit)` — range scan temporal indexes, score by proximity
- `s_occurred = 1 - |midpoint(entity) - midpoint(query)| / (query_range / 2)`
- `s_learned = exp(-λ × (now - learned_at))`
- `s_temporal = α × s_occurred + (1-α) × s_learned`, default `α = 0.7`

**Tests:**
- End-to-end: insert entities with text + vectors + edges + phonetic codes + timestamps
- Query with all 5 signals, verify fusion produces reasonable ranking
- Verify type filter works (only matching types returned)
- Verify temporal filter works (only entities in range)
- Verify recency boost (recent entities score higher)
- Test with only 1 signal (e.g., text-only query), verify still works

---

## Task 7: Context Pack + Serialization

**Files:** `context_pack.rs`, `serialize.rs`
**Est:** ~500 LOC
**Depends on:** Task 6

**Context Pack Builder (`context_pack.rs`):**
- `ContextPackBuilder<'a>` — extends pipeline with hydration options
- All `PipelineBuilder` methods available
- Additional: `hydrate(bool)`, `include_edges(bool)`, `edge_hop(u32)`, `max_neighbors(usize)`, `include_vectors(bool)`, `format(PackFormat)`, `field_profile(FieldProfile)`, `token_budget(usize)`
- `run() -> Result<ContextPack>` — run pipeline, then hydrate results in same read txn
  - For each result: read entity blob, decode short_id + content_hash from `short_ids` db, optionally read edges, optionally read vector
  - If `edge_hop > 0`: walk edges N hops, collect neighbor IDs, hydrate neighbors
  - Return `ContextPack { results, neighbors, stats }`
- `run_serialized() -> Result<Vec<u8>>` — run + serialize to chosen format

**ContextPack types:**
- `ContextPack`, `ContextEntity` (with `short_id`, `content_hash`, `fields` from decoded msgpack), `EdgeInfo`, `SignalHit`, `PackStats`

**Serialization (`serialize.rs`):**
- `serialize_pack(pack: &ContextPack, format: PackFormat, profile: FieldProfile, budget: usize) -> Vec<u8>`
- Decode MessagePack entity blobs → extract fields by name
- Apply field profile (minimal/standard/full) to select which fields to include
- Group entities by type in priority order: CLAIM → TURN → SUMMARY → EVENT → PERSON → SKILL → ASSET_TEXT → PLACE
- Sort within group by score descending
- Format short IDs with content hash: `cl88:f2`

**Format implementations:**
- **JSON**: standard serde_json
- **TOON**: pipe-delimited tables with section headers `[CLAIMS]`, header row, data rows
- **Plaintext**: no headers, pipe-delimited, most compact
- **Markdown**: markdown tables with `## Claims` headers
- **YAML**: abbreviated field names, relative timestamps

**Token budget:**
- Estimate tokens (rough: chars / 4)
- Allocate budget per entity type (claims 50%, turns 30%, summaries 15%, other 5%)
- Truncate sections that exceed budget

**Tests:**
- Context pack with hydration: verify blobs, edges, neighbors returned
- Edge hop: 1-hop neighbors included, 2-hop not (when edge_hop=1)
- run_serialized with TOON format: verify output matches expected TOON structure
- run_serialized with Plaintext: verify compact output
- Short ID + content hash in output: `cl88:f2` format
- Token budget: verify output doesn't exceed budget
- Empty results: verify graceful handling

---

## Task 8: Index Maintenance API

**Files:** `maintain.rs`, `lib.rs` (extend)
**Est:** ~250 LOC
**Depends on:** Task 4, Task 5

Deterministic index maintenance primitives — the dreamer (in `oneiron-internal`) calls these.

**Review follow-ups from Task 2:**
- Add specific error variants for `Error::InvalidKey` (currently overloaded for ~8 different failure modes)
- Reject unknown entity types (>11) in `apply_put` or encode type byte into short ID prefix to prevent `"xx"` collision across types

**MaintenanceBuilder (`maintain.rs`):**
- `MaintenanceBuilder<'a>` borrowing `&'a Vault`
- `rebuild_hnsw()` — re-insert all live vectors (from `vectors` db) into a fresh HNSW graph. Delete old `hnsw_neighbors` entries, rebuild from scratch. Update `hnsw_meta["count"]`, `hnsw_meta["entry_point"]`.
- `cleanup_ppr_cache(max_age_secs)` — scan `ppr_cache`, evict entries where `computed_at + max_age < now` OR `stale == 1`. Clean up corresponding `ppr_cache_deps` entries.
- `compact_postings()` — scan `text_postings`, delete entries with empty posting lists (can accumulate after many deletes).
- `recompute_short_id_hashes()` — scan `short_ids`, for each entity read current blob from `entities`, recompute `xxHash32 % 256`, update if changed.
- `run() -> Result<MaintenanceReport>` — execute selected operations, return stats.

**MaintenanceReport:**
- `hnsw_dead_nodes_removed`, `hnsw_live_nodes`, `ppr_caches_evicted`, `postings_compacted`, `duration_ms`

**Tests:**
- Insert 100 entities + vectors, delete 20, run `rebuild_hnsw`, verify dead nodes removed and search still works
- Create PPR caches, age them, run `cleanup_ppr_cache`, verify evicted
- Create posting lists, delete documents, run `compact_postings`, verify empty lists removed
- Update entity blobs, run `recompute_short_id_hashes`, verify hashes updated

---

## Task 9: Benchmarks

**Files:** `crates/oneiron-bench/src/main.rs`
**Est:** ~400 LOC
**Depends on:** Task 6, Task 8

**Benchmark suite:**
- Scale: 1K, 5K, 10K, 50K entities
- Dimensions: 1024 (device) and 4096 (server) modes
- Test data: random f32 vectors, Zipf-distributed text (generate fake documents)

**Metrics per scale:**
- HNSW: recall@10 vs brute-force, insert latency, search latency (p50/p90/p99)
- BM25: search latency, index throughput
- PPR: compute latency at depth 3
- Full pipeline: end-to-end query latency
- Context pack: serialization latency (TOON format)
- Disk usage: total LMDB file size
- QPS: queries per second (single-threaded)

**Targets (from BUILD-PROMPT.md):**

| Scale | Recall@10 | Search p99 | Insert p99 | Disk |
|-------|-----------|------------|------------|------|
| 10K | >97% | <10ms | <5ms | <500MB |
| 50K | >95% | <50ms | <10ms | <2.5GB |

**Output:** print results as markdown table to stdout.

---

## Task 10: FFI Layer

**Files:** `crates/oneiron-ffi/src/lib.rs`
**Est:** ~300 LOC
**Depends on:** Task 7

C-compatible FFI for mobile (iOS/Android) and TypeScript/Node via NAPI or direct FFI.

- `oneiron_vault_open(path, config_json) -> *mut Vault`
- `oneiron_vault_close(vault: *mut Vault)`
- `oneiron_vault_put(vault, id, type, data, data_len, ...) -> i32`
- `oneiron_vault_query(vault, query_json) -> *mut c_char` (returns serialized context pack)
- `oneiron_vault_context_pack(vault, query_json, format) -> *mut c_char` (returns formatted text)
- `oneiron_vault_maintain(vault, ops_json) -> *mut c_char` (returns maintenance report)
- `oneiron_vault_free_string(s: *mut c_char)`
- Error handling: return error codes, last-error string

**Note:** The first consumer is `oneiron-internal` (TypeScript on Fly machines), calling via FFI. Mobile (iOS/Android) is the second consumer. Both use the same C FFI surface.

---

## Task Summary

| # | Task | Est LOC | Depends | Core deliverable |
|---|------|---------|---------|-----------------|
| 1 | Types + LMDB Store | ~400 | — | 18 databases, CRUD, key encoding |
| 2 | Batch Builder + Secondary Indexes | ~400 | 1 | Atomic writes, type/temporal/phonetic/short ID indexes |
| 3 | BM25 Full-Text Search | ~600 | 2 | Tokenizer, inverted index, forward index, deindexing |
| 4 | HNSW Vector Search | ~800 | 1 | Flat NSW, cosine distance, SIMD, lazy deletion |
| 5 | PPR Graph Traversal | ~400 | 1,2 | Bidirectional PPR, per-edge weights, cache |
| 6 | RRF Fusion + Pipeline | ~300 | 3,4,5 | 5-signal fusion, pipeline builder |
| 7 | Context Pack + Serialization | ~500 | 6 | Hydration, 5 formats, short ID + hash, token budget |
| 8 | Index Maintenance | ~250 | 4,5 | HNSW rebuild, PPR cache cleanup, posting compaction |
| 9 | Benchmarks | ~400 | 6,8 | Scale testing, recall targets, latency targets |
| 10 | FFI Layer | ~300 | 7 | C FFI for mobile + TypeScript |

**Total:** ~4,350 LOC

**Parallelizable:** Tasks 3 and 4 can run in parallel (both depend on 1/2 but not each other). Task 5 can start as soon as Task 2 is done. Task 8 can start after Tasks 4+5. Tasks 9 and 7 can run in parallel.

**Execution order (serial):** 1 → 2 → 3 → 4 → 5 → 6 → 7 → 8 → 9 → 10
**Execution order (parallel where possible):** 1 → 2 → [3, 4] → 5 → 6 → [7, 8] → 9 → 10
