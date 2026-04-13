# oneiron-db Schema Design

> Working document. Captures all schema decisions from design sessions.
> This will be consolidated into an updated BUILD-PROMPT.md before implementation.

---

## Database Layout (v1 — 18 databases)

| # | Database | Key Format | Key Size | Value Format | Value Size | Purpose |
|---|----------|-----------|----------|-------------|-----------|---------|
| 1 | `entities` | `entity_id` (16B, UUID v7 BE) | 16B | MessagePack blob | variable | Document store |
| 2 | `edges_out` | `src_id(16) \| kind(1) \| tgt_id(16)` | 33B | `weight(f32 4B) \| created_at(u64 8B) \| valence(f32 4B) \| arousal(f32 4B) \| dominance(f32 4B)` | 24B | Outbound adjacency |
| 3 | `edges_in` | `tgt_id(16) \| kind(1) \| src_id(16)` | 33B | `weight(f32 4B) \| created_at(u64 8B) \| valence(f32 4B) \| arousal(f32 4B) \| dominance(f32 4B)` | 24B | Inbound adjacency |
| 4 | `vectors` | `entity_id` (16B) | 16B | `[f32; N]` raw little-endian | N×4B | Embeddings |
| 5 | `hnsw_neighbors` | `entity_id` (16B) | 16B | `[entity_id; M]` concatenated | M×16B | HNSW neighbor lists (flat NSW) |
| 6 | `hnsw_meta` | string key (UTF-8) | variable | raw bytes | variable | HNSW metadata |
| 7 | `text_postings` | `term` (UTF-8) | variable | `[(entity_id(16), tf(u32 4B))]` packed | N×20B | BM25 inverted index |
| 8 | `text_meta` | `entity_id` (16B) | 16B | `doc_len(u32 4B) \| field_count(u32 4B)` | 8B | BM25 document metadata |
| 9 | `text_forward` | `entity_id` (16B) | 16B | `[term1\0term2\0...]` packed UTF-8 | variable | BM25 forward index (for deindexing) |
| 10 | `ppr_cache` | `seed_set_hash` (16B, XXH3-128 of sorted seeds + depth + alpha) | 16B | `[meta(17B)] [scores N×20B]` | variable | Cached PPR results |
| 11 | `ppr_cache_deps` | `entity_id(16) \| seed_hash(16)` | 32B | empty | 0B | PPR cache invalidation index |
| 12 | `type_index` | `entity_type(1) \| entity_id(16)` | 17B | empty | 0B | Entity type filtering |
| 13 | `temporal_occurred_start` | `start_ts(u64 8B BE) \| entity_id(16)` | 24B | empty | 0B | Bi-temporal: when it started |
| 14 | `temporal_occurred_end` | `end_ts(u64 8B BE) \| entity_id(16)` | 24B | empty | 0B | Bi-temporal: when it ended |
| 15 | `temporal_learned` | `learned_ts(u64 8B BE) \| entity_id(16)` | 24B | empty | 0B | Bi-temporal: when we recorded it |
| 16 | `phonetic_index` | `phonetic_code` (UTF-8) | variable | `[(entity_id(16))]` packed | N×16B | Phonetic code → entity lookup |
| 17 | `short_ids` | `entity_id` (16B) | 16B | `short_id(var) \| content_hash(1B)` | variable | Short ID + content hash mapping |
| 18 | `short_ids_reverse` | `short_id` (UTF-8, e.g. "cl88") | variable | `entity_id` (16B) | 16B | Short ID → full ID lookup |

```rust
const MAX_DBS: u32 = 24; // 18 core + room for sync, entity_vad, future
```

---

## Changes from Original BUILD-PROMPT.md

| What Changed | Before | After | Why |
|---|---|---|---|
| Edge values | empty (`&[]`, 0B) | `weight(f32) + created_at(u64) + valence(f32) + arousal(f32) + dominance(f32)` = 24B | Per-edge weights for PPR (not hardcoded by EdgeKind). Timestamps for cache invalidation and temporal queries. VAD scores for emotion-aware traversal (ARCH-022/023). |
| PPR cache values | `[(id, score)]` only | 17B metadata header + scores | Header: `computed_at(8) + graph_version(8) + stale(1)`. Enables TTL, lazy invalidation, graph version tracking per ARCH-014. |
| +`ppr_cache_deps` | didn't exist | entity_id\|seed_hash → empty | O(1) PPR cache invalidation when entities/edges change. Without it: full cache scan. |
| +`type_index` | didn't exist | type(1)\|id(16) → empty | Entity type filtering in Rust, not across FFI. Post-filtering 300 blobs in TypeScript is bad. |
| +`temporal_occurred_start/end` | didn't exist | ts(8)\|id(16) → empty | Bi-temporal interval indexing. Temporal is a 5th retrieval signal, not just a filter. Hindsight showed +46.7% on temporal reasoning. |
| +`temporal_learned` | didn't exist | ts(8)\|id(16) → empty | "When did we learn this?" vs "when did it happen?" — different temporal dimensions. |
| +`phonetic_index` | didn't exist | code → [(id)] | Voice-first product needs phonetic matching for ASR misspellings (CROSS-ARCH-013). 5th retrieval signal. |
| +`text_forward` | didn't exist | entity_id → [terms] | Forward index for O(terms) deindexing without requiring original text. |
| +`hnsw_meta` keys | entry_point, count | + model_id, hnsw_config, graph_version, vector_version, temporal schema version | Persist vector-space compatibility + maintenance guard metadata without clearing unrelated keys during rebuild. |
| +`short_ids` | didn't exist | entity_id → short_id + hash | Vault-scoped permanent short IDs (`cl88`) + 1-byte content hash for freshness detection. |
| +`short_ids_reverse` | didn't exist | short_id → entity_id | Reverse lookup for hydration endpoint. |
| Entity blob format | opaque `&[u8]` | MessagePack | Self-describing binary format. ~30% smaller than JSON, enables field extraction in context_pack without schema registration. |
| Database count | 9 | 18 | |
| MAX_DBS | 12 | 24 | |

---

## Entity Blob Format: MessagePack

Entity blobs are stored as MessagePack — a binary serialization format with the same data model as JSON (maps, arrays, strings, numbers) but encoded as compact bytes.

**Why MessagePack over JSON:**

| | JSON | MessagePack |
|---|---|---|
| Avg entity size | ~500 bytes | ~350 bytes (-30%) |
| 50K entities | ~25MB | ~17MB |
| Parse speed | String scanning | Binary tag reading (~3x faster) |
| Self-describing | Yes | Yes (keys stored in blob) |
| Field extraction | Yes (parse and access by key) | Yes (same, but binary) |
| Human-readable | Yes | No (binary) |

**Why self-describing matters:** The `context_pack()` endpoint needs to extract fields from entity blobs to serialize to TOON/JSON/MD formats. With MessagePack, the crate can decode any blob and extract fields by name without a compile-time schema. The crate doesn't need to know what a CLAIM looks like — it just reads the map keys.

**Rust crate:** `rmp-serde` for serialization/deserialization.

```rust
// Write path — caller serializes to MessagePack
let blob = rmp_serde::to_vec(&claim)?;
vault.put_entity(id, CLAIM, occurred, learned_at, &blob, ...)?;

// Read path — context_pack decodes msgpack to extract fields
let fields: HashMap<String, rmpv::Value> = rmp_serde::from_slice(&blob)?;
```

---

## Short IDs + Content Hash

### Short ID Assignment

Each entity gets a permanent vault-scoped short ID on creation: `<2-char prefix><sequential number>`.

| Prefix | Type | Prefix | Type |
|---|---|---|---|
| `cl` | CLAIM | `ev` | EVENT |
| `tn` | TURN | `sk` | SKILL |
| `ss` | SESSION | `sm` | SUMMARY |
| `ms` | MESSAGE | `pl` | PLACE |
| `pr` | PERSON | `tx` | ASSET_TEXT |
| `rl` | RELATIONSHIP | `cv` | CONVERSATION |
| `og` | ORGANIZATION | `fc` | FACET |
| `wd` | WORLD | | |

Properties:
- Vault-scoped (no cross-vault collisions)
- Permanent (never reassigned, even after deletion)
- Incremental per kind: `cl1`, `cl2`, `cl3`...
- Counter stored in `short_ids` db under sentinel key `[0xFF; 16]` per entity type

### Content Hash

Each entity also gets a 1-byte content hash: `xxHash32(msgpack_blob) % 256` → 2-char hex.

Combined format in context output: **`cl88:f2`**

- `cl88` — permanent short ID (which entity)
- `f2` — content hash (which version)

**Purpose:** Freshness detection. The LLM sees `cl88:f2` in its context. If the entity is later updated, the hash changes to `cl88:a7`. When the LLM references `cl88:f2`, the orchestrator detects the stale hash and can re-fetch or warn.

**Storage:** `short_ids` database:
```
Key:   entity_id (16B)
Value: short_id (variable UTF-8, e.g. "cl88") | content_hash (1B, xxHash32 % 256)
```

**Recomputed on every `put_entity`.** The hash is a function of the blob content — any change to the entity automatically updates it.

**Collision rate:** 1/256 (0.4%) chance of hash staying the same after an update. Acceptable for freshness hinting — it's not a cryptographic guarantee, just a cheap signal.

### Hydration

```
short_ids_reverse db:
  Key:   "cl88" (UTF-8)
  Value: entity_id (16B)
```

Hydration endpoint: `/vault/{vaultId}/hydrate/{shortId}` → returns full entity.

---

## Key Encoding

All entity IDs: 16 bytes, UUID v7, big-endian. LMDB lexicographic ordering = temporal ordering.

**Edge keys (33 bytes):**
```
[source_id: 16B] [edge_kind: 1B] [target_id: 16B]
```
Range scan for "all outbound edges of entity X": prefix scan on X (first 16 bytes).

**Temporal keys (24 bytes):**
```
[timestamp: 8B big-endian] [entity_id: 16B]
```
Range scan for "all entities after time T": seek to [T, 0x00...] and iterate forward.

**Type index keys (17 bytes):**
```
[entity_type: 1B] [entity_id: 16B]
```
Prefix scan for "all entities of type X": seek to [X, 0x00...].

---

## Edge Values

```rust
struct EdgeValue {
    weight: f32,       // PPR propagation weight (default from EdgeKind, overridable)
    created_at: u64,   // timestamp of edge creation
    valence: f32,      // emotional valence (-1.0 to 1.0, default 0.0)
    arousal: f32,      // emotional arousal (0.0 to 1.0, default 0.0)
    dominance: f32,    // emotional dominance (0.0 to 1.0, default 0.0)
}
// Serialized: 24 bytes, little-endian
// Layout: [weight 0..4] [created_at 4..12] [valence 12..16] [arousal 16..20] [dominance 20..24]
```

`EdgeKind::default_weight()` remains as the DEFAULT weight when creating edges. The actual per-edge weight is stored in the value and used at query time. VAD scores default to 0.0 (neutral) and are populated by the dreamer for emotion-bearing edges (ARCH-022/023).

---

## PPR Cache Value Format

```
[computed_at: u64 8B] [graph_version: u64 8B] [stale: u8 1B] [scores...]
```

Where scores are `[(entity_id: 16B, score: f32 4B)]` packed = N×20B.

- `computed_at`: timestamp for TTL checks (active=24h, recent=72h, dormant=168h)
- `graph_version`: monotonic counter, incremented once per batch of graph mutations. Used as a write-side guard so PPR does not persist results computed against an older graph snapshot.
- `stale`: set to 1 when entity's edges change (via ppr_cache_deps lookup). Search skips stale entries.

---

## hnsw_meta Keys

| Key | Value | Notes |
|-----|-------|-------|
| `"entry_point"` | entity_id (16B) | Flat NSW, no level needed |
| `"count"` | u64 (8B LE) | Total nodes in graph |
| `"model_id"` | UTF-8 string | e.g., "qwen3-8b-v1" |
| `"hnsw_config"` | `m_max_0(u64 LE) + ef_construction(u64 LE) + ef_search(u64 LE)` | Persisted at open; reopening with a different HNSW config fails fast instead of silently mixing graph semantics |
| `"graph_version"` | u64 (8B LE) | Monotonic counter, incremented once per batch of graph mutations |
| `"vector_version"` | u64 (8B LE) | Monotonic counter, incremented once per batch of vector mutations; rebuild uses it as an OCC guard between read/build and final swap |
| `"temporal_long_intervals_schema_version"` | u8 | Migration marker for the `temporal_long_intervals` key layout |

---

## text_meta Special Keys

| Key | Meaning | Value |
|-----|---------|-------|
| `[0x00; 16]` (all zeros) | total_docs | u32 (4B) |
| `[0xFF; 16]` (all ones) | total_length | u64 (8B) |
| any entity_id | per-doc metadata | doc_len(4) + field_count(4) = 8B |

UUID v7 will never produce all-zeros or all-ones keys (timestamp in high bits), so sentinel keys are safe.

---

## Retrieval Pipeline — 5 Signals

```
1. Vector search (HNSW)         → ranked list (3× limit)
2. BM25 text search             → ranked list (3× limit)
3. Phonetic lookup              → ranked list (graduated scoring)
4. Temporal scoring             → ranked list (proximity to query time)
5. RRF fuse signals 1-4        → merged ranking
6. PPR expand                   → re-rank with graph context
7. Signal boosts                → salience, recency, confidence
8. Hard filters                 → type, time range (optional)
9. Return top K
```

**Temporal scoring (from Hindsight):**
```
s_occurred(Q, f) = 1 - |midpoint(f.occurred) - midpoint(Q.range)| / (Q.range_width / 2)
s_learned(f) = exp(-λ × (now - f.learned_at))
s_temporal = α × s_occurred + (1-α) × s_learned
```
Where α depends on query type ("what happened?" → high α, "catch me up" → low α).

**Phonetic scoring:**
- Graduated edit distance: `1.0 - (levenshtein(query_code, stored_code) / max_len)`
- Multi-code boost: entities matching both primary + alternate codes get 1.2× boost
- Feeds into RRF as ranked list with proper differentiation

---

## API Design

### Simple API (common cases)

```rust
impl Vault {
    pub fn open(path: impl AsRef<Path>, config: VaultConfig) -> Result<Self>;

    // Single-entity write — atomic across all indexes
    pub fn put_entity(
        &self,
        id: EntityId,
        entity_type: u8,
        occurred: TimeRange,         // start..end or instant
        learned_at: u64,
        data: &[u8],
        vector: Option<&[f32]>,
        text_fields: Option<&[(&str, &str)]>,
        phonetic_codes: Option<&[&str]>,
    ) -> Result<()>;

    pub fn put_edge(
        &self,
        src: EntityId,
        kind: EdgeKind,
        tgt: EntityId,
        weight: f32,
    ) -> Result<()>;

    pub fn get(&self, id: EntityId) -> Result<Option<Vec<u8>>>;
    pub fn get_vector(&self, id: EntityId) -> Result<Option<Vec<f32>>>;
    pub fn edges_out(&self, src: EntityId) -> Result<Vec<(EdgeKind, EntityId, f32)>>;
    pub fn edges_in(&self, tgt: EntityId) -> Result<Vec<(EdgeKind, EntityId, f32)>>;

    // Delete — fully deindexes from all databases atomically
    pub fn delete_entity(&self, id: EntityId) -> Result<bool>;
    pub fn delete_edge(&self, src: EntityId, kind: EdgeKind, tgt: EntityId) -> Result<bool>;

    // Query — pipeline builder
    pub fn query(&self) -> PipelineBuilder;

    // Batch — for multi-entity atomic writes
    pub fn batch(&self) -> BatchBuilder;
}
```

### Batch Builder (complex cases, LLM code mode)

```rust
pub struct BatchBuilder<'a> { /* borrows Vault */ }

impl<'a> BatchBuilder<'a> {
    pub fn put(self, id: EntityId, entity_type: u8, occurred: TimeRange, learned_at: u64, data: &[u8]) -> Self;
    pub fn vector(self, id: EntityId, vec: &[f32]) -> Self;
    pub fn edge(self, src: EntityId, kind: EdgeKind, tgt: EntityId, weight: f32) -> Self;
    pub fn text(self, id: EntityId, fields: &[(&str, &str)]) -> Self;
    pub fn phonetic(self, id: EntityId, codes: &[&str]) -> Self;
    pub fn delete(self, id: EntityId) -> Self;
    pub fn delete_edge(self, src: EntityId, kind: EdgeKind, tgt: EntityId) -> Self;
    pub fn commit(self) -> Result<()>;
}
```

The simple API uses BatchBuilder internally. One call → one transaction → all-or-nothing.

### Pipeline Builder (query composition)

```rust
pub struct PipelineBuilder<'a> { /* borrows Vault */ }

impl<'a> PipelineBuilder<'a> {
    // Retrieval signals (each produces a ranked list for RRF)
    pub fn search_vector(self, vector: &[f32], limit: usize) -> Self;
    pub fn search_text(self, query: &str, limit: usize) -> Self;
    pub fn search_phonetic(self, codes: &[&str]) -> Self;
    pub fn search_temporal(self, anchor_start: u64, anchor_end: u64, limit: usize) -> Self;

    // Convenience: vector + text + temporal together
    pub fn search(self, query: &str, vector: &[f32], time: Option<TimeRange>, limit: usize) -> Self;

    // Graph expansion
    pub fn expand_ppr(self, seeds: &[EntityId], depth: u32) -> Self;

    // Signal boosts (applied after RRF)
    pub fn boost_recency(self, half_life_days: f32) -> Self;
    pub fn boost_salience(self) -> Self;
    pub fn boost_confidence(self) -> Self;

    // Hard filters (applied after scoring)
    pub fn filter_types(self, types: &[u8]) -> Self;
    pub fn filter_since(self, timestamp: u64) -> Self;
    pub fn filter_occurred_range(self, start: u64, end: u64) -> Self;
    pub fn filter_learned_range(self, start: u64, end: u64) -> Self;

    pub fn limit(self, n: usize) -> Self;
    pub fn run(self) -> Result<Vec<ScoredEntity>>;
}
```

---

## VaultConfig

```rust
pub struct VaultConfig {
    pub dimensions: usize,              // dynamic — 1024 (device), 4096 (server), any
    pub embedding_model: Option<String>, // e.g., "qwen3-8b-v1". Checked on open.
    pub map_size: usize,                // LMDB map size (virtual memory, not RAM)
    pub max_readers: u32,               // default 126
    pub hnsw: HnswConfig,
}

pub struct HnswConfig {
    pub m: usize,               // 32 (upper layers — unused for flat NSW, kept for future)
    pub m_max_0: usize,         // 64 (neighbors per node, flat NSW)
    pub ef_construction: usize, // 200 (beam width during insert)
    pub ef_search: usize,       // 128 (beam width during search)
}

impl VaultConfig {
    pub fn device() -> Self {
        Self {
            dimensions: 1024,
            embedding_model: None,
            map_size: 1 << 30,  // 1 GB
            max_readers: 126,
            hnsw: HnswConfig::default(),
        }
    }

    pub fn server() -> Self {
        Self {
            dimensions: 4096,
            embedding_model: None,
            map_size: 1 << 33,  // 8 GB
            max_readers: 126,
            hnsw: HnswConfig::default(),
        }
    }
}
```

**Map size explanation:** LMDB memory-maps the database file. The map size is the maximum virtual address space reserved. On 64-bit systems this is free — only pages actually written consume physical RAM or disk. Over-allocating (e.g., 8GB on a device with 4GB RAM) is safe. The file grows as data is written, up to the limit. If you hit the limit, writes fail with `MDB_MAP_FULL` and you need to reopen with a larger size.

**Sizing math:**

| Component | Per Entity | 50K @ 1024-dim | 50K @ 4096-dim |
|-----------|-----------|----------------|----------------|
| Vectors | N × 4B | 200MB | 800MB |
| HNSW neighbors | 64 × 16B | 50MB | 50MB |
| Entity blobs | ~500B avg | 25MB | 25MB |
| Edges (10 avg × 45B) | ~450B | 22MB | 22MB |
| All other indexes | ~300B | 15MB | 15MB |
| **Total** | | **~312MB** | **~912MB** |

---

## Embedding Model Verification

On `Vault::open()`, if `config.embedding_model` is `Some(model)`:
1. Read `hnsw_meta["model_id"]`
2. If it exists and doesn't match → return `Error::EmbeddingModelChanged { stored, requested }`
3. If it doesn't exist (fresh vault) → write `model` to `hnsw_meta["model_id"]`
4. If `config.embedding_model` is `None` → skip check (for tests, migration scripts)

The app decides how to handle model changes (wipe and re-embed, or abort).

---

## HNSW Deletion Strategy

**v1: Lazy deletion.** When an entity is deleted:
- Remove from `entities`, `vectors`, all indexes
- Do NOT touch `hnsw_neighbors` — the node stays in the graph as a ghost
- During search, check each candidate against `entities` db — skip if missing
- Cost: one existence check per HNSW candidate (~128 checks at ef=128, ~0.5ms)

**Later: Dreamer-driven rebuild.** New dreamer job kind `index_maintenance`:
- Nightly: count dead nodes (entries in `hnsw_neighbors` with no matching `entities` entry)
- If dead ratio > 10%: full HNSW rebuild (re-insert all live vectors into fresh graph)
- At 50K scale, rebuild takes seconds

---

## Deindexing Process (Full Delete)

When `delete_entity(E)` is called, one write transaction does:

```
1. TEXT DEINDEX
   read text_forward[E] → terms
   for each term:
     read text_postings[term], remove E, write back
   update text_meta collection stats (total_docs--, total_length -= doc_len)
   delete text_meta[E]
   delete text_forward[E]

2. VECTOR (lazy HNSW delete)
   delete vectors[E]
   hnsw_meta["count"] -= 1
   (hnsw_neighbors untouched — lazy deletion)

3. PHONETIC DEINDEX
   for each code associated with E:
     read phonetic_index[code], remove E, write back

4. EDGES
   prefix scan edges_out[E|*] → delete each, plus matching edges_in entry
   prefix scan edges_in[E|*] → delete each, plus matching edges_out entry
   for each affected entity: check ppr_cache_deps, mark stale
   after batch graph mutations commit: increment `graph_version` once

5. TYPE + TEMPORAL
   delete type_index[type|E]
   delete temporal_occurred_start[start_ts|E]
   delete temporal_occurred_end[end_ts|E] (if exists)
   delete temporal_learned[learned_ts|E]

6. ENTITY
   delete entities[E]

7. COMMIT
```

Note: phonetic deindexing needs the codes. Two options:
- Store codes in entity blob (app deserializes before delete)
- Add `phonetic_forward` database (like text_forward)

For v1: require codes to be in the entity blob. The `delete_entity` implementation reads the blob first, extracts phonetic codes (caller provides a decoder), then deindexes. If the blob is opaque, the simple API's `delete_entity` handles it by also reading `phonetic_index` entries that reference E (reverse scan — phonetic vocabulary is small enough).

---

## Bi-Temporal Model

Three temporal dimensions per entity:

| Dimension | Meaning | Example |
|-----------|---------|---------|
| `occurred_start` | When the thing started happening | Session started 2pm |
| `occurred_end` | When the thing stopped | Session ended 4pm |
| `learned_at` | When we first recorded it | Dreamer processed at 4:30pm |

**Point events:** `occurred_start = occurred_end` (e.g., a single utterance).

**Ongoing entities:** No entry in `temporal_occurred_end` (e.g., active session, valid claim). Treated as end = +∞ in queries.

**Query patterns:**
- "What happened last Tuesday?" → `occurred_start/end` overlaps Tuesday
- "What did we learn this week?" → `learned_at` within this week
- "State of knowledge as of Monday" → `learned_at <= Monday`
- "Sessions active at 3pm" → `occurred_start <= 3pm AND (no end OR occurred_end >= 3pm)`

**Temporal scoring:**
```
s_occurred(Q, f) = 1 - |midpoint(f.occurred) - midpoint(Q.range)| / (Q.range_width / 2)
s_learned(f) = exp(-λ × (now - f.learned_at))
s_temporal = α × s_occurred + (1-α) × s_learned
```
α depends on query type: "what happened?" → high α; "catch me up" → low α.

---

## Future Additions (Not v1)

### Database #17: `entity_vad` (Companion Plugin — Emotional Scoring)

```
Key:   entity_id (16B)
Value: valence(f32 4B) + arousal(f32 4B) + dominance(f32 4B) = 12B
```

Entity-level aggregate emotional metadata. Per ARCH-022/023, edge-level VAD (stored in the 24-byte edge value, bytes 12-24) is the primary mechanism for emotion-aware PPR traversal. This database provides an optional entity-level summary for cases where aggregate emotion per entity is needed (e.g., companion plugin emotional profiling).
Only populated for entities with emotional data (messages, turns, events).
Add when companion plugin is built.

### Databases #18-19: Sync (Device Mode)

```
sync_deltas:  (timestamp_ulid(16) | doc_id(16)) → serialized CRDT delta
sync_meta:    string key → value (cursors, device_id, last_sync)
```

For offline-first device mode. Convex cloud is sync hub.
Add when device sync is implemented.

### HNSW Multi-Index (Multimodal Embeddings — v2)

If we ever embed non-text modalities (audio via CLAP, images via CLIP) that use different embedding spaces/dimensions, we'd need multiple vector indexes per vault:

```
vectors_text:         entity_id → [f32; 4096]
vectors_audio:        entity_id → [f32; 512]
hnsw_neighbors_text:  entity_id → [id; M]
hnsw_neighbors_audio: entity_id → [id; M]
hnsw_meta_text:       string → bytes
hnsw_meta_audio:      string → bytes
```

For v1: all modalities get text representations (transcripts, captions, OCR) and those text representations are embedded. One embedding space per vault. Multimodal embedding indexes are a v2 concern.

### Semantic Date Parsing (Retrieval Enhancement)

Hindsight's biggest win (+46.7% temporal reasoning). Parse natural language temporal expressions ("last Tuesday", "three weeks ago", "in March") into timestamp ranges. Hybrid: rule-based regex + small model fallback (flan-t5-small).

This is a pipeline/query-parsing concern, not a schema concern. The temporal databases support it — the parsing layer just needs to produce `(start_ts, end_ts)` from natural language.

### Extended HNSW Neighbor Heuristic

The BUILD-PROMPT uses simple neighbor selection (take M closest). The HNSW paper's extended heuristic considers edge diversity and can improve recall at scale. Worth evaluating at 50K+ scale if recall targets aren't met. No schema change — just algorithm change in `select_neighbors()`.

### BM25 Enhancements

- Stemming / lemmatization (currently just lowercase + Unicode word boundaries)
- Stop word removal
- Field-weighted BM25 (title fields weighted higher than body)
- BM25F (field-aware variant)

All are algorithm changes within the existing `text_postings` / `text_meta` schema.

### Predicate Index (If App-Layer Filtering Becomes Bottleneck)

```
claim_predicates: predicate_string | entity_id(16) → empty
```

For efficient "find all claims with predicate X" without deserializing blobs. Defer until profiling proves it's needed — type_index + temporal filters should reduce candidate sets enough for app-layer predicate filtering.

### Value-Layer Compression (If Vault Sizes Become an Issue)

LMDB stores raw bytes with no built-in compression. For v1 this is fine — MessagePack is already ~30% smaller than JSON, and f32 vectors are incompressible. But if text-heavy vaults grow large:

- **zstd on `entities` DB values only.** Decompression runs at ~1.5+ GB/s, so per-blob overhead is single-digit microseconds on typical payloads (hundreds of bytes to a few KB). Negligible vs. the LMDB read itself.
- **Don't compress vectors, edges, or index keys.** Floats and small fixed-size values don't compress well and the overhead isn't worth it.
- **Use a pre-trained zstd dictionary.** zstd dictionaries excel on small payloads with shared structure — exactly what MessagePack entity blobs are (repeated map keys like `"type"`, `"content"`, `"source"`).
- **Backward-compatible migration:** prefix compressed values with a 1-byte version tag. Decompress if present, read raw if not. No migration needed.

No schema change — purely a value encoding concern. Add the `zstd` crate dependency when needed.

---

## EdgeKind Enum

```rust
#[repr(u8)]
pub enum EdgeKind {
    BelongsTo = 0,
    ParticipatesIn = 1,
    Attached = 2,
    AuthoredBy = 3,
    Mentions = 4,
    About = 5,
    Supports = 6,
    Opposes = 7,       // default weight 0.0 — blocks PPR propagation
    ClaimOf = 8,
    ScopedTo = 9,
    Supersedes = 10,
    DerivedFrom = 11,
    PartOf = 12,        // hop-limited to max 2 in PPR
    EmployedBy = 13,    // ARCH-022: person → org
    HasFacet = 14,      // ARCH-022: person → facet
    InWorld = 15,       // ARCH-022: person → world
    FacetOf = 16,       // ARCH-023: claim → facet
    SetIn = 17,         // ARCH-023: relationship → world
    // Future (multi-party, CROSS-ARCH-010):
    // AddressedTo = 18,  // default weight 0.4
    // RepliesTo = 19,    // default weight 0.3
}
```

Default weights are used when `put_edge` is called without an explicit weight. The actual per-edge weight is stored in the edge value.

---

## LMDB Configuration

```rust
const MAX_DBS: u32 = 24;           // 16 core + 8 headroom
const DEFAULT_MAX_READERS: u32 = 126;

// Map sizes (virtual memory, not physical RAM)
const MAP_SIZE_DEVICE: usize = 1 << 30;  // 1 GB
const MAP_SIZE_SERVER: usize = 1 << 33;  // 8 GB
const MAP_SIZE_DEV: usize = 1 << 28;     // 256 MB
```

---

## Skills as Entities

Agent Skills (agentskills.io spec) are just entities. No special schema support needed.

```
Skill (entity)
│  blob: { skillId, version, spec (SKILL.md content), approvalStatus,
│          lifecycleStatus, source, confidence, scopeRelationshipId }
│  type_index: SKILL (e.g., 0x0E)
│  vector: embedding of spec text
│  BM25: spec content indexed
│  temporal: learned_at = when dreamer created it
│
│  Edges:
│  ├── --[derived_from]--> Turn_123     (source evidence)
│  ├── --[derived_from]--> Turn_456     (source evidence)
│  ├── --[scoped_to]--> Relationship_X  (if relationship-scoped)
│  ├── --[authored_by]--> Person_Y      (teacher/creator)
│  └── --[supersedes]--> Skill_old      (version chain)
```

**Three creation pathways:**
1. **Authored** — user installs SKILL.md, starts approved
2. **Generated** — dreamer detects patterns, starts as proposed, user approves/rejects
3. **Message-derived** — user selects conversation content, LLM refines into SKILL.md

**Lifecycle:** proposed → approved → active/superseded/archived. Only approved+active skills appear in retrieval results.

**Dreamer writing a skill via batch builder:**
```rust
vault.batch()
    .put(skill_id, SKILL_TYPE, occurred, learned_at, &skill_blob)
    .vector(skill_id, &spec_embedding)
    .text(skill_id, &[("spec", &skill_md_content)])
    .edge(skill_id, EdgeKind::DerivedFrom, source_turn_1, 1.0)
    .edge(skill_id, EdgeKind::DerivedFrom, source_turn_2, 1.0)
    .edge(skill_id, EdgeKind::AuthoredBy, person_id, 0.9)
    .commit()?;
```

---

## Text Forward Index — Explained

### The Problem

BM25 search uses an **inverted index**: for each word, store which documents contain it.

```
INVERTED INDEX (text_postings)
"alice"    → [doc_7, doc_23, doc_891]
"sushi"    → [doc_7, doc_12, doc_445]
"likes"    → [doc_2, doc_7, doc_12, doc_23, doc_445, doc_891]
```

Searching "alice sushi" = look up two posting lists, score overlapping docs. Fast.

**But deleting doc_7 is hard.** We need to remove doc_7 from the posting lists of every
word it was indexed under ("alice", "likes", "sushi"). How do we know which words those are?

### Without Forward Index

Scan every word in the inverted index, checking each posting list for doc_7. If there are
50,000 unique words, that's 50,000 LMDB lookups to delete one document. Terrible.

### With Forward Index

Store a reverse mapping: for each document, which words it was indexed under.

```
FORWARD INDEX (text_forward)
doc_7   → ["alice", "likes", "sushi"]
doc_23  → ["alice", "bob", "likes"]
```

Deleting doc_7: read text_forward[doc_7] → 3 words → 3 targeted posting list updates. Done.

### The Full Picture

```
INDEXING (write path):
  "alice likes sushi" (doc_7)
      ├──► text_postings["alice"]  += doc_7    (inverted: word → docs)
      ├──► text_postings["likes"]  += doc_7
      ├──► text_postings["sushi"]  += doc_7
      ├──► text_meta[doc_7] = {len: 3}
      └──► text_forward[doc_7] = ["alice", "likes", "sushi"]  (forward: doc → words)

DEINDEXING (delete path):
  delete doc_7
      ├──► read text_forward[doc_7] → ["alice", "likes", "sushi"]
      ├──► text_postings["alice"]  -= doc_7    (undo)
      ├──► text_postings["likes"]  -= doc_7
      ├──► text_postings["sushi"]  -= doc_7
      ├──► delete text_meta[doc_7]
      └──► delete text_forward[doc_7]
```

Cost: one extra write per document on index (~200 bytes avg). At 50K entities = 10MB. Negligible.

---

## Index Maintenance API (Dreamer Primitives)

The `oneiron` crate provides deterministic index maintenance operations. These are the low-level primitives that the dreamer (in `oneiron-internal`) calls — the crate does not contain any LLM logic, consolidation intelligence, or ML service calls.

```rust
impl Vault {
    pub fn maintain(&self) -> MaintenanceBuilder;
}

pub struct MaintenanceBuilder<'a> { /* borrows Vault */ }

impl<'a> MaintenanceBuilder<'a> {
    pub fn rebuild_hnsw(self) -> Self;
    pub fn rebuild_hnsw_heal_invalid_vectors(self) -> Self;
    pub fn cleanup_ppr_cache(self, max_age_secs: u64) -> Self;
    pub fn compact_postings(self) -> Self;
    pub fn recompute_short_id_hashes(self) -> Self;
    pub fn run(self) -> Result<MaintenanceReport>;
}

pub struct MaintenanceReport {
    pub hnsw_dead_nodes_removed: u64,
    pub hnsw_live_nodes: u64,
    pub hnsw_invalid_vectors_skipped: u64,
    pub ppr_caches_evicted: u64,
    pub ppr_deps_cleaned: u64,
    pub postings_compacted: u64,
    pub orphan_short_ids_deleted: u64,
    pub short_id_hashes_updated: u64,
}
```

- `hnsw_dead_nodes_removed` counts nodes omitted from the rebuilt graph compared with the previously committed `count`. In heal mode that includes invalid-vector skips; use `hnsw_invalid_vectors_skipped` for the explicit invalid-row breakdown.
- `orphan_short_ids_deleted` counts logical stale/orphan short-id repairs across the forward and reverse short-id indexes.

| Operation | What it does | When to call |
|---|---|---|
| `rebuild_hnsw` | Strict rebuild: validate vectors from a read snapshot, rebuild from that snapshot, then do a single final swap write txn. Fails on invalid stored vectors or if `vector_version` changed before commit. | Dead ratio > 10% |
| `rebuild_hnsw_heal_invalid_vectors` | Repair rebuild: same snapshot/swap flow, but skip invalid stored vectors while preserving the raw vector rows for later inspection | Operator-triggered repair |
| `cleanup_ppr_cache` | Evict stale + expired cache entries from `ppr_cache` + `ppr_cache_deps` | Nightly |
| `compact_postings` | Remove empty posting lists from `text_postings` | After bulk deletes |
| `recompute_short_id_hashes` | Recompute content hashes for all entities in `short_ids` and delete stale/orphaned mappings from both `short_ids` and `short_ids_reverse` | After bulk updates |

**Boundary:** The crate provides `maintain()`. The dreamer (private, in `oneiron-internal`) decides *when* to call it and *what entities to write/update*. The dreamer's intelligence (LLM-driven consolidation, skill extraction, edge weight tuning, ML service orchestration) is proprietary.

---

## Repository Structure

```
github.com/oneiron-ai/oneiron            ← public, Apache 2.0
  Rust retrieval engine: LMDB, HNSW, BM25, PPR, RRF, context packs
  Provides: Vault, BatchBuilder, PipelineBuilder, ContextPackBuilder,
            MaintenanceBuilder, VaultManager

github.com/oneiron-ai/oneiron-internal    ← private, proprietary
  Platform: Convex backend, dreamer agent, API layer, LLM orchestration
  Uses: oneiron crate as embedded storage engine
  Contains: dreamer intelligence, consolidation logic, skill extraction,
            ML service calls (Modal, Salad), scheduling, Fly deployment

github.com/oneiron-ai/eiri-docs           ← private, architecture docs
  ADRs, cross-cutting specs, product architecture
```

The public crate is the storage engine. The private repo is the brain that uses it. Like SQLite (public) vs your app (private).

---

## Multi-Vault Deployment, ML Infrastructure, Platform Decisions

See [DEPLOYMENT.md](./DEPLOYMENT.md) for:
- Multi-vault architecture (1 LMDB env per vault, VaultManager API)
- Deployment platform (Fly.io Machines, not K8s/DO/Azure)
- Vault placement (1 machine per vault, 2 states: running/sleeping)
- Migration mechanics and cold storage format
- ML infrastructure (Modal GPU per region: NER 0.6B + Embedding 8B)
- Inference runtime (Candle CUDA, Luminal exploration)
- Dreamer batch jobs (Salad)
- Progressive disclosure for skills

---

## Context Pack Endpoint

### The Problem

`PipelineBuilder.run()` returns `Vec<ScoredEntity>` (IDs + scores). The app then needs N separate `get()` calls to hydrate blobs + edges. That's N FFI round-trips across N read transactions.

### Solution: Single-Call Retrieval + Hydration

```rust
impl Vault {
    pub fn context_pack(&self) -> ContextPackBuilder;
}

pub struct ContextPackBuilder<'a> { /* borrows Vault */ }

impl<'a> ContextPackBuilder<'a> {
    // All PipelineBuilder methods available here
    pub fn search_vector(self, vector: &[f32], limit: usize) -> Self;
    pub fn search_text(self, query: &str, limit: usize) -> Self;
    pub fn search_phonetic(self, codes: &[&str]) -> Self;
    pub fn search_temporal(self, anchor_start: u64, anchor_end: u64, limit: usize) -> Self;
    pub fn search(self, query: &str, vector: &[f32], time: Option<TimeRange>, limit: usize) -> Self;
    pub fn expand_ppr(self, seeds: &[EntityId], depth: u32) -> Self;
    pub fn boost_recency(self, half_life_days: f32) -> Self;
    pub fn filter_types(self, types: &[u8]) -> Self;
    pub fn filter_since(self, timestamp: u64) -> Self;
    pub fn limit(self, n: usize) -> Self;

    // Context pack specific
    pub fn hydrate(self, yes: bool) -> Self;              // return entity blobs (default: true)
    pub fn include_edges(self, yes: bool) -> Self;        // return edges per entity
    pub fn edge_hop(self, depth: u32) -> Self;            // hydrate N-hop neighbors
    pub fn max_neighbors(self, n: usize) -> Self;         // cap neighbor count
    pub fn include_vectors(self, yes: bool) -> Self;      // return vectors (for re-ranking)

    // Output format (for run_serialized)
    pub fn format(self, fmt: PackFormat) -> Self;
    pub fn field_profile(self, profile: FieldProfile) -> Self;
    pub fn token_budget(self, budget: usize) -> Self;

    // Return options
    pub fn run(self) -> Result<ContextPack>;           // struct (programmatic use)
    pub fn run_serialized(self) -> Result<Vec<u8>>;    // formatted text (LLM injection)
}

pub struct ContextPack {
    pub results: Vec<ContextEntity>,
    pub neighbors: Vec<ContextEntity>,
    pub stats: PackStats,
}

pub struct ContextEntity {
    pub id: EntityId,
    pub short_id: String,                // e.g. "cl88"
    pub content_hash: u8,                // xxHash32 % 256
    pub entity_type: u8,
    pub score: f32,                      // 0.0 for unscored neighbors
    pub data: Option<Vec<u8>>,           // MessagePack blob
    pub fields: Option<HashMap<String, rmpv::Value>>,  // decoded fields (if hydrate)
    pub edges: Option<Vec<EdgeInfo>>,    // outbound edges
    pub vector: Option<Vec<f32>>,        // if include_vectors
}

pub struct EdgeInfo {
    pub kind: EdgeKind,
    pub target: EntityId,
    pub target_short_id: Option<String>,
    pub weight: f32,
    pub created_at: u64,
    pub vad: Vad,
}

pub enum Signal {
    Vector,
    Text,
    Phonetic,
    Temporal,
    Ppr,
}

pub struct PackStats {
    pub candidates_considered: usize,
    pub signals_used: Vec<Signal>,
    pub query_time_us: u64,
    pub entities_hydrated: usize,
    pub neighbors_hydrated: usize,
}
```

### Why This Matters

| | Without context_pack | With context_pack |
|---|---|---|
| FFI calls | 20-50 per query | 1 |
| LMDB transactions | 20-50 read txns | 1 read txn |
| Consistency | Entities could change between calls | Snapshot-consistent (MVCC) |
| Network (if gRPC) | 20-50 round trips | 1 round trip |

### Serialization Formats

Two return modes per [CROSS-DEC-003](../eiri-docs/docs/cross/CROSS-DEC-003-query-serialization-v2.md):

- `run()` → `ContextPack` struct (programmatic use, custom formatting)
- `run_serialized()` → `Vec<u8>` formatted text (direct LLM injection, one FFI call)

`run_serialized()` decodes MessagePack blobs, maps to short IDs with content hashes, applies field profiles, and serializes to the chosen format — all in Rust, one LMDB read txn.

| Format | Content-Type | Token Efficiency | Use Case |
|---|---|---|---|
| **JSON** | `application/json` | Baseline | Programmatic access, debugging |
| **YAML** | `application/yaml` | -12% vs JSON | Human-readable debugging |
| **TOON** | `text/toon` | -50% vs JSON | Token-optimized for LLM (tabular) |
| **Markdown** | `text/markdown` | -42% vs JSON | LLM-friendly prose |
| **Plaintext** | `text/plain` | -63% vs JSON | Ultra-minimal |

**TOON (Token-Optimized Object Notation)** — pipe-delimited tabular with content hashes:
```
[META tokens=1250 vault=test-vault]

[CLAIMS]
| id | pred | val | conf | sal | evid |
| cl88:f2 | goal.learning | "Learn Japanese by June" | 0.9 | 0.8 | tn17:a1,tn23:c4 |

[TURNS]
| id | txt | spkr | at |
| tn17:a1 | "I really want to learn Japanese..." | user | -3d |
```

**Plaintext** — most compact (no headers, no pipes around rows):
```
META tokens=1250

CLAIMS
cl88:f2|goal.learning|Learn Japanese by June|0.9|0.8|tn17:a1,tn23:c4

TURNS
tn17:a1|I really want to learn Japanese...|user|-3d
```

Short IDs include content hash suffix (`:f2`) for freshness detection. See [Short IDs + Content Hash](#short-ids--content-hash) section above.

### Field Profiles

Three presets control which fields are included (reduces token usage):

| Profile | Token Reduction | Fields |
|---|---|---|
| **Minimal** | -58% | id, pred/name, val/txt |
| **Standard** | -25% | + conf, sal, evid, spkr, at |
| **Full** | 0% | All fields |

### Grouping Order

Entities grouped by kind in priority order: CLAIM → TURN → SUMMARY → EVENT → PERSON → SKILL → ASSET_TEXT → PLACE. Within each group, sorted by relevance score descending.

### Token Budget

```rust
pub struct ContextPackFormat {
    pub format: PackFormat,          // json | yaml | toon | md | txt
    pub field_profile: FieldProfile, // minimal | standard | full
    pub token_budget: usize,         // default: 4000
    pub token_allocation: TokenAllocation,
}

pub struct TokenAllocation {
    pub claims: f32,     // default: 0.50
    pub turns: f32,      // default: 0.30
    pub summaries: f32,  // default: 0.15
    pub other: f32,      // default: 0.05
}
```

**Serialization happens in the Rust crate** via `run_serialized()`. The crate decodes MessagePack blobs, resolves short IDs + content hashes from `short_ids` db, applies field profiles, and emits formatted text. The TypeScript layer in `oneiron-internal/open/packages/api/src/component/contextPack/` is the reference implementation for format specs; the Rust crate reimplements the same logic for zero-FFI-overhead context assembly.

`run()` is also available for cases where the app needs programmatic access to the struct (custom formatting, inspection, testing).

---

## Open Questions

1. **Phonetic deindexing:** Add `phonetic_forward` database (#17, bumping entity_vad to #18)? Or rely on phonetic vocabulary being small enough for reverse lookup? Decision: defer, measure first.

2. **Temporal α parameter:** How does the pipeline decide whether "occurred" or "learned" matters more for a given query? Heuristic from query text? Explicit parameter? LLM decides?

3. **PPR graph_version counter:** Stored where? `hnsw_meta["graph_version"]` as u64, incremented once per batch of graph mutations in the same LMDB environment.

4. **Collection stats atomicity:** BM25 total_docs and total_length (sentinel keys in text_meta) are updated on every index/deindex. Under concurrent reads, readers see a consistent snapshot (LMDB MVCC). No issue.

5. **Multi-party EdgeKinds:** `AddressedTo` (18) and `RepliesTo` (19) — add to enum now (reserved) or add when multi-party ships? Recommendation: reserve the values now, don't implement until needed.
