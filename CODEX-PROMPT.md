# Task 6: RRF Fusion + Pipeline Builder

**Files to create:** `crates/oneiron/src/fusion.rs`, `crates/oneiron/src/pipeline.rs`
**Files to modify:** `crates/oneiron/src/lib.rs` (add modules + `Vault::query()` method)
**~300 LOC target**
**Depends on:** Task 3 (BM25), Task 4 (HNSW), Task 5 (PPR) — all merged to main

---

## What to Build

Two new modules that tie together all existing retrieval signals (HNSW vector search, BM25 text search, PPR graph traversal, phonetic lookup, temporal scoring) into a unified query pipeline with RRF score fusion.

---

## 1. RRF Fusion (`fusion.rs`)

### `rrf_fuse`

```rust
pub(crate) fn rrf_fuse(ranked_lists: &[Vec<ScoredEntity>], k: f32) -> Vec<ScoredEntity>
```

- Standard RRF formula: `score(d) = Σ 1 / (k + rank_i(d) + 1)` where rank is 0-indexed
- Default `k = 60.0`
- Handles missing entries — entity not in all lists simply doesn't get that list's contribution
- Returns results sorted by fused score descending, tie-break by entity ID bytes ascending
- Deduplicates entity IDs across lists (same entity in multiple lists → single output entry with summed RRF contributions)

### Signal Boosts

Applied **after** RRF fusion as multiplicative adjustments:

```rust
pub(crate) fn boost_recency(
    scores: &mut [ScoredEntity],
    half_life_days: f32,
    store: &Store,
    rtxn: &RoTxn<'_>,
) -> Result<()>
```

- Reads `temporal_learned` index: for each scored entity, find its `learned_at` timestamp
- To find `learned_at` for an entity: read the entity blob from `entities` db, extract `learned_at` from the metadata header
  - Entity blob format: `[entity_type(1) | occurred_start(8 BE) | occurred_end(8 BE) | learned_at(8 BE) | user_data...]`
  - The metadata header is 25 bytes (defined as `ENTITY_METADATA_HEADER_LEN` in `batch.rs`)
  - `learned_at` is at bytes 17..25, big-endian u64
- Exponential decay: `recency = exp(-ln(2) / (half_life_days * 86400) * (now - learned_at))`
- Multiply: `score *= 1.0 + 0.5 * recency`

```rust
pub(crate) fn boost_salience(
    scores: &mut [ScoredEntity],
    store: &Store,
    rtxn: &RoTxn<'_>,
) -> Result<()>
```

- Read entity blob from `entities` db, decode MessagePack user data (after 25-byte header), look for `"salience"` field (f32, 0.0-1.0)
- If present: `score *= 1.0 + salience`
- If absent or decode fails: no boost (multiply by 1.0)

```rust
pub(crate) fn boost_confidence(
    scores: &mut [ScoredEntity],
    store: &Store,
    rtxn: &RoTxn<'_>,
) -> Result<()>
```

- Same pattern: decode msgpack, look for `"confidence"` field (f32, 0.0-1.0)
- `score *= 0.5 + 0.5 * confidence`
- If absent: no boost

---

## 2. Pipeline Builder (`pipeline.rs`)

### Structure

```rust
pub struct PipelineBuilder<'a> {
    vault: &'a Vault,
    // Accumulated signal configs
    vector_search: Option<(Vec<f32>, usize)>,          // (query_vector, limit)
    text_search: Option<(String, usize)>,               // (query, limit)
    phonetic_search: Option<Vec<String>>,                // codes
    temporal_search: Option<TemporalSearchConfig>,       // see below
    ppr_search: Option<(Vec<EntityId>, u32)>,            // PRE-RRF: (seeds, depth) — 5th signal
    ppr_expand: Option<(Vec<EntityId>, u32)>,            // POST-RRF: (seeds, depth) — graph expansion
    // Boost configs
    recency_half_life: Option<f32>,                      // half_life_days
    apply_salience: bool,
    apply_confidence: bool,
    // Filters
    type_filter: Option<Vec<u8>>,                        // entity type bytes
    since_filter: Option<u64>,                           // timestamp
    occurred_range: Option<(u64, u64)>,
    learned_range: Option<(u64, u64)>,
    // Output
    result_limit: usize,                                 // default: 20
}

struct TemporalSearchConfig {
    anchor_start: u64,
    anchor_end: u64,
    sigma_secs: u64,   // controls decay width — derived from range, granularity, or explicit
    limit: usize,
}
```

### Builder Methods

All methods take `self` and return `Self` (move semantics for chaining):

```rust
impl<'a> PipelineBuilder<'a> {
    pub fn search_vector(self, vector: &[f32], limit: usize) -> Self;
    pub fn search_text(self, query: &str, limit: usize) -> Self;
    pub fn search_phonetic(self, codes: &[&str]) -> Self;

    // Temporal search — three tiers (all set the same internal TemporalSearchConfig):
    // Tier 1: infer sigma from range width
    pub fn search_temporal(self, anchor_start: u64, anchor_end: u64, limit: usize) -> Self;
    // Tier 2: explicit sigma (caller controls decay width in seconds)
    pub fn search_temporal_with_sigma(self, anchor_start: u64, anchor_end: u64, sigma_secs: u64, limit: usize) -> Self;
    // Tier 3: granularity enum (maps to sigma internally)
    pub fn search_temporal_with_granularity(self, anchor_start: u64, anchor_end: u64, granularity: TemporalGranularity, limit: usize) -> Self;

    // Convenience: set vector + text + optional temporal in one call
    pub fn search(self, query: &str, vector: &[f32], time: Option<TimeRange>, limit: usize) -> Self;

    // PPR — two modes, caller can use either or both:
    // Pre-RRF: PPR as a 5th retrieval signal fed into fusion (needs explicit seeds, e.g. from NER)
    pub fn search_ppr(self, seeds: &[EntityId], depth: u32) -> Self;
    // Post-RRF: graph expansion using top RRF results + optional explicit seeds
    pub fn expand_ppr(self, seeds: &[EntityId], depth: u32) -> Self;

    pub fn boost_recency(self, half_life_days: f32) -> Self;
    pub fn boost_salience(self) -> Self;
    pub fn boost_confidence(self) -> Self;

    pub fn filter_types(self, types: &[u8]) -> Self;
    pub fn filter_since(self, timestamp: u64) -> Self;
    pub fn filter_occurred_range(self, start: u64, end: u64) -> Self;
    pub fn filter_learned_range(self, start: u64, end: u64) -> Self;

    pub fn limit(self, n: usize) -> Self;

    pub fn run(self) -> Result<Vec<ScoredEntity>>;
}
```

### `run()` Execution Order

Opens **one** read transaction, then:

1. **Execute retrieval signals** — each configured signal produces a `Vec<ScoredEntity>`:
   - `search_vector` → calls `hnsw::hnsw_search(store, config, &rtxn, query_vector, limit)`
   - `search_text` → calls `bm25::search_text(store, &rtxn, query, limit)`
   - `search_phonetic` → phonetic scoring (see below)
   - `search_temporal` → temporal scoring (see below)
   - `search_ppr` (if configured) → calls `ppr::ppr_query(store, config, &seeds, depth, 0.15)` as a **pre-RRF 5th signal**. Note: `ppr_query` manages its own transactions internally (for caching). Call it outside the read txn scope.

2. **RRF fuse** — call `rrf_fuse(&ranked_lists, 60.0)` on all signal results (up to 5 lists). If no signals were configured (empty ranked_lists), return `Ok(vec![])` immediately — filters and boosts only apply to retrieved candidates.

3. **PPR expand** (if `expand_ppr` configured) — post-fusion graph expansion:
   - Take the top `result_limit` entity IDs from the RRF fused results as implicit seeds
   - Combine with explicit seeds (from `expand_ppr(seeds, depth)`), deduplicating
   - Call `ppr::ppr_query(store, config, &combined_seeds, depth, 0.15)`
   - The PPR results become another ranked list
   - Re-fuse: `rrf_fuse(&[rrf_results, ppr_results], 60.0)`
   - Note: if both `search_ppr` and `expand_ppr` are configured, both run — pre-RRF PPR feeds into the initial fusion, post-RRF PPR expands from the fused results.

4. **Apply boosts** (if configured) — mutate scores in-place:
   - `boost_recency`, `boost_salience`, `boost_confidence`
   - These need a read txn to look up entity data

5. **Apply hard filters** (if configured) — remove non-matching entities:
   - `filter_types`: read entity blob header byte 0 (entity_type), keep only matching types
   - `filter_since`: read `learned_at` from entity header (bytes 17..25), keep only entities with `learned_at >= timestamp`
   - `filter_occurred_range`: read `occurred_start` (bytes 1..9) and `occurred_end` (bytes 9..17) from entity header, keep entities whose occurred range overlaps `[start, end]`
   - `filter_learned_range`: read `learned_at` from entity header, keep entities within `[start, end]`

6. **Re-sort** by score descending, tie-break by entity ID

7. **Truncate** to `result_limit`

### Phonetic Search Implementation

```rust
fn execute_phonetic(
    store: &Store,
    rtxn: &RoTxn<'_>,
    codes: &[String],
) -> Result<Vec<ScoredEntity>>
```

- For each query code, look up `phonetic_index[code]` → posting list of entity IDs (packed `[entity_id(16)]...`)
- Score each entity by graduated edit distance: `1.0 - (levenshtein(query_code, stored_code) / max(query_code.len(), stored_code.len()))`
  - Since we're looking up exact codes, the edit distance is 0 for exact matches → score = 1.0
  - For a simple v1: just do exact matching with score 1.0 per match. The graduated edit distance across all phonetic codes in the index would require scanning every code, which is expensive. Instead:
    - Look up each query code in `phonetic_index` → get matching entity IDs → score = 1.0 per match
    - Multi-code boost: entity matching 2+ query codes gets 1.2× multiplier
- Deduplicate entities, sum/max scores, sort descending

### Temporal Search Implementation

```rust
fn execute_temporal(
    store: &Store,
    rtxn: &RoTxn<'_>,
    anchor_start: u64,
    anchor_end: u64,
    limit: usize,
) -> Result<Vec<ScoredEntity>>
```

**Candidate selection: index-bounded window (not full scan)**

1. Compute window bounds:
   - `range_width = anchor_end - anchor_start` (if 0, treat as `86400` — 1 day — for point queries)
   - `padding = range_width * 2` (but at least `7 * 86400` — 7 days — floor)
   - `window_start = anchor_start.saturating_sub(padding)`
   - `window_end = anchor_end.saturating_add(padding)`
   - `candidate_cap = limit * 4` (hard cap on candidates to bound latency)

2. Range scan `temporal_occurred_start` from `window_start` to `window_end`:
   - Seek to `[window_start_BE, 0x00...0x00]`, iterate while key timestamp <= `window_end`
   - Extract entity IDs from keys (bytes 8..24), deduplicate into a set
   - Stop after `candidate_cap` unique entities

3. Also range scan `temporal_learned` with same window bounds, merge into the same candidate set (up to `candidate_cap`)

4. For each candidate entity:
   - Read entity metadata header from `entities` db to get `occurred_start`, `occurred_end`, `learned_at`
   - Compute `s_occurred` using **sigmoid decay with floor** (Mnemosyne-style, NOT linear clamp-to-zero):
     ```
     distance = |midpoint(entity.occurred) - midpoint(query)|   (in seconds)
     midpoint(r) = r.start / 2 + r.end / 2 + (r.start % 2 + r.end % 2) / 2   (overflow-safe)
     sigma = sigma_secs from TemporalSearchConfig
     floor = 0.05
     s_occurred = (1.0 - floor) / (1.0 + exp((distance - sigma) / (sigma / 4.0))) + floor
     ```
     - `sigma` controls where the steep dropoff happens. Derived from:
       - Tier 1 (`search_temporal`): `sigma = max(range_width, 86400)` where `range_width = anchor_end - anchor_start`
       - Tier 2 (`search_temporal_with_sigma`): caller provides `sigma_secs` directly
       - Tier 3 (`search_temporal_with_granularity`): mapped from `TemporalGranularity` enum (see types section)
     - `floor = 0.05` ensures old memories never score zero (always retrievable)
     - `sigma / 4.0` as steepness gives a smooth but decisive dropoff
     - At `distance = 0`: score ≈ 1.0 (close to anchor = best)
     - At `distance = sigma`: score ≈ 0.525 (midpoint of decay)
     - At `distance >> sigma`: score → 0.05 (floor, never zero)
   - `s_learned = exp(-(now - entity.learned_at) / (28 * 86400))` (28-day half-life, per Mnemosyne)
   - `s_temporal = 0.7 * s_occurred + 0.3 * s_learned`

5. Sort by temporal score descending, take top `limit`

---

## 3. Wire into `lib.rs`

Add to `lib.rs`:

```rust
pub mod pipeline;
pub(crate) mod fusion;

pub use crate::pipeline::PipelineBuilder;
pub use crate::types::TemporalGranularity;
```

Add method to `Vault`:

```rust
impl Vault {
    pub fn query(&self) -> PipelineBuilder<'_> {
        PipelineBuilder::new(self)
    }
}
```

---

## 4. Existing Internal APIs (DO NOT MODIFY)

These are the functions you'll call. They already exist and work:

```rust
// hnsw.rs — vector search (returns scores as cosine similarity, higher = better)
pub(crate) fn hnsw_search(store: &Store, config: &VaultConfig, rtxn: &RoTxn<'_>, query_vector: &[f32], limit: usize) -> Result<Vec<ScoredEntity>>

// bm25.rs — text search (returns BM25 scores, higher = better)
pub(crate) fn search_text(store: &Store, rtxn: &RoTxn<'_>, query: &str, limit: usize) -> Result<Vec<ScoredEntity>>

// ppr.rs — graph traversal with caching (manages its own transactions)
pub(crate) fn ppr_query(store: &Store, config: &VaultConfig, seeds: &[EntityId], depth: u32, alpha: f32) -> Result<Vec<ScoredEntity>>

// ppr.rs — low-level compute (takes a read txn, no caching)
pub(crate) fn ppr_compute(store: &Store, txn: &RoTxn<'_>, seeds: &[EntityId], depth: u32, alpha: f32) -> Result<Vec<ScoredEntity>>
```

### Entity Metadata Header Format (from `batch.rs`)

```rust
pub(crate) const ENTITY_METADATA_HEADER_LEN: usize = 25;
// Layout: [entity_type(1) | occurred_start(8 BE) | occurred_end(8 BE) | learned_at(8 BE)]
```

Reading timestamps from entity blobs:
```rust
let raw = store.entities.get(&rtxn, id.as_bytes())?;
// raw[0] = entity_type
// raw[1..9] = occurred_start (u64 big-endian)
// raw[9..17] = occurred_end (u64 big-endian)
// raw[17..25] = learned_at (u64 big-endian)
// raw[25..] = user data (MessagePack blob)
```

### Store databases available:
- `store.entities` — entity blobs with 25-byte metadata header
- `store.phonetic_index` — `code (UTF-8)` → `[(entity_id(16))]` packed
- `store.temporal_occurred_start` — `[ts(8 BE) | id(16)]` → empty
- `store.temporal_occurred_end` — `[ts(8 BE) | id(16)]` → empty
- `store.temporal_learned` — `[ts(8 BE) | id(16)]` → empty
- `store.type_index` — `[type(1) | id(16)]` → empty
- All other stores (see `store.rs`)

### Key encoding helpers:
```rust
Store::encode_temporal_key(ts: u64, id: &EntityId) -> [u8; 24]
Store::encode_type_key(entity_type: u8, id: &EntityId) -> [u8; 17]
```

### Crate-level helpers:
```rust
pub(crate) fn unix_seconds_now() -> u64;
pub(crate) fn le_bytes_to_f32_vec(bytes: &[u8]) -> Result<Vec<f32>>;
```

### Types (from `types.rs`):
```rust
pub struct ScoredEntity { pub id: EntityId, pub score: f32 }
pub struct TimeRange { pub start: u64, pub end: u64 }
pub enum Signal { Vector, Text, Phonetic, Temporal, Ppr }
```

### New type to add to `types.rs`:
```rust
/// Temporal query precision — controls decay width for temporal scoring.
/// Maps to sigma_secs internally. Wider granularity = more forgiving decay.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TemporalGranularity {
    Exact,   //    3,600s (1 hour)
    Hour,    //   14,400s (4 hours)
    Day,     //   86,400s (1 day)
    Week,    //  604,800s (1 week)
    Month,   // 2,592,000s (30 days)
    Season,  // 7,776,000s (90 days)
    Year,    // 15,552,000s (180 days)
    Vague,   // 31,536,000s (365 days)
}

impl TemporalGranularity {
    pub fn sigma_secs(self) -> u64 {
        match self {
            Self::Exact  => 3_600,
            Self::Hour   => 14_400,
            Self::Day    => 86_400,
            Self::Week   => 604_800,
            Self::Month  => 2_592_000,
            Self::Season => 7_776_000,
            Self::Year   => 15_552_000,
            Self::Vague  => 31_536_000,
        }
    }
}
```

---

## 5. Tests

Write tests in `pipeline.rs` (or `fusion.rs`) under `#[cfg(test)] mod tests`.

### RRF fusion tests:
- **Single list**: fuse with one list → scores should be `1/(k+rank+1)`
- **Two lists, overlapping entities**: entity in both lists gets summed contributions
- **Empty lists**: no results
- **Missing entities**: entity in list A but not B → only gets A's contribution

### Pipeline end-to-end tests:
- **Insert entities with text + vectors + edges**, then query with pipeline
- **Text-only query**: `vault.query().search_text("term", 10).run()`
- **Vector-only query**: `vault.query().search_vector(&vec, 10).run()`
- **Combined query**: text + vector → fused results
- **Type filter**: insert entities of type 0 and type 1, filter to type 0 only
- **Temporal filter**: insert entities at different times, filter with `filter_since`
- **Recency boost**: insert old and new entities, verify new ones score higher with boost
- **PPR expand (post-RRF)**: insert entities with edges, use `expand_ppr` to find graph neighbors
- **PPR search (pre-RRF)**: insert entities with edges, use `search_ppr` with explicit seeds
- **Both PPR modes**: use `search_ppr` + `expand_ppr` together, verify both contribute
- **Single signal still works**: each signal type alone produces valid results
- **Limit**: verify result count respects limit

### Temporal scoring tests:
- **Sigmoid decay shape**: entity at distance 0 scores ~1.0, at distance >> sigma scores ~0.05 (floor), never zero
- **Granularity tiers**: same anchor range with `Day` vs `Year` granularity gives different score distributions
- **Tier equivalence**: `search_temporal(start, end, limit)` produces same results as `search_temporal_with_sigma(start, end, range_width, limit)` when range_width >= 86400
- **Vague queries**: wide granularity (Year/Vague) still surfaces distant entities with floor score

### Test helpers (reuse pattern from existing tests):
```rust
fn test_config() -> VaultConfig {
    VaultConfig {
        map_size: 16 * 1024 * 1024,
        dimensions: 4,
        embedding_model: None,
        max_readers: 16,
        hnsw: HnswConfig { m_max_0: 64, ef_construction: 200, ef_search: 128 },
    }
}
```

---

## 6. Review Follow-ups to Address

From TASKS.md, Task 6 has two follow-up items. Handle them if they naturally fit, otherwise note them as TODO comments:

1. **`phonetic_forward` index** — Currently phonetic deindex is O(vocabulary_size) full scan. Adding a `phonetic_forward` (entity → codes) database would fix this. This is a schema change beyond Task 6 scope — skip, but your phonetic search implementation should work with the current `phonetic_index` (code → entity_ids).

2. **PPR cache key includes depth/alpha** — Currently PPR cache is keyed only by seed set hash. This is safe since `ppr_query` always uses config-level defaults (depth, alpha). Leave as-is; this is tracked for Task 8.

---

## 7. Style & Constraints

- No comments unless the logic is truly non-obvious
- No `pub` visibility on fusion.rs internals — use `pub(crate)`
- `pipeline.rs` types that go in the public API (`PipelineBuilder`) should be `pub`
- Use `rmp-serde` and `rmpv` for MessagePack decoding (already in Cargo.toml dependencies)
- Match existing code style (look at `ppr.rs`, `bm25.rs` for reference)
- All tests use `tempfile::tempdir()` for vault paths
- Run `cargo test` to verify — all 52 existing tests must continue to pass
- Run `cargo clippy` — zero warnings
- Run `cargo fmt --all` before committing
- `#![cfg_attr(not(test), allow(dead_code))]` at top of `fusion.rs` if needed (pipeline may not call every helper in non-test builds initially)
- **Do NOT modify existing files** except `lib.rs` (module declarations, `Vault::query()`, re-export) and `types.rs` (add `TemporalGranularity` enum only)

---

## 8. Working Directory

You are working in the worktree at:
```
/Users/olety/Desktop/code/oneiron/.worktrees/rrf-pipeline/
```

Source files are at:
```
crates/oneiron/src/
```

Run commands from the worktree root:
```bash
cargo test
cargo clippy -- -D warnings
cargo fmt --all
```
