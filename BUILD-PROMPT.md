# oneiron-db: Complete Build Prompt

> Drop this into a fresh session. It contains everything needed to build the oneiron-db Rust crate from scratch — architecture, algorithms, LMDB schema, API surface, known bugs to avoid, and performance targets.

**Working directory:** `/home/ubuntu/projects/oneiron-db/`
**License:** Apache 2.0
**NOT a fork** — clean-room rewrite. Helix code at `/home/ubuntu/projects/oneiron-helixdb/helix/` is AGPL reference only (DO NOT COPY CODE, only reference algorithms).

---

## 1. What This Is

oneiron-db is a ~2-3K line Rust crate — a single embedded retrieval engine that unifies HNSW vector search, BM25 full-text search, PPR graph traversal, and RRF score fusion. One binary, one process, zero network hops between components.

**Deployment targets:**
- Server (Fly.io): x86_64, AVX2, 4096-dim vectors
- iOS: aarch64, NEON, 1024-dim vectors
- Android: aarch64, NEON, 1024-dim vectors
- Desktop (macOS/Linux): native arch, native SIMD

**Key constraints:**
- f32 vectors (not f64 like helix)
- Dimension-agnostic (config parameter, not hardcoded)
- No async runtime (sync-only DB operations)
- No OpenSSL, no core_affinity, no mimalloc (mobile-safe)
- Minimal dependency tree (< 10 transitive deps)

---

## 2. Crate Structure

```
oneiron-db/
├── Cargo.toml              # workspace
├── LICENSE                  # Apache 2.0
├── crates/
│   ├── oneiron/             # core library
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs       # Vault API, re-exports
│   │       ├── types.rs     # EntityId, EdgeKind, VaultConfig, ScoredEntity
│   │       ├── error.rs     # Error enum, Result type
│   │       ├── store.rs     # LMDB environment, database handles, key encoding
│   │       ├── hnsw.rs      # HNSW insert + search (flat NSW)
│   │       ├── distance.rs  # Cosine similarity (NEON / AVX2 / scalar)
│   │       ├── bm25.rs      # BM25 indexing + search
│   │       ├── graph.rs     # Edge storage, traversal helpers
│   │       ├── ppr.rs       # Personalized PageRank
│   │       ├── fusion.rs    # RRF + signal boosts
│   │       └── pipeline.rs  # PipelineBuilder (lazy query composition)
│   ├── oneiron-ffi/         # C FFI for mobile (later)
│   │   ├── Cargo.toml
│   │   └── src/lib.rs
│   └── oneiron-bench/       # Benchmarks
│       ├── Cargo.toml
│       └── src/main.rs
```

---

## 3. Dependencies

```toml
[workspace]
resolver = "2"
members = ["crates/*"]

[workspace.package]
version = "0.1.0"
edition = "2021"
license = "Apache-2.0"

[workspace.dependencies]
heed = "0.20"
uuid = { version = "1", features = ["v7"] }
thiserror = "2"
```

For the `oneiron` crate:
```toml
[dependencies]
heed = { workspace = true }
uuid = { workspace = true }
thiserror = { workspace = true }
```

Add `serde`, `bincode`, `rand` etc. only as modules need them. Start minimal.

**Key: use `heed` (NOT `heed3`).** The crate was published as `heed` on crates.io. Helix used `heed3` which was a dev alias. Check the actual latest version — it may be 0.20.x or 0.21.x.

---

## 4. LMDB Schema

Single LMDB environment per vault. All databases created upfront on first open.

### 4.1 Database Layout

| # | Database | Key Format | Key Size | Value Format | Value Size | Purpose |
|---|----------|-----------|----------|-------------|-----------|---------|
| 1 | `entities` | `entity_id` (16 bytes, big-endian) | 16B | opaque blob (caller-serialized) | variable | Document store |
| 2 | `edges_out` | `source_id(16) \| kind(1) \| target_id(16)` | 33B | empty (`&[]`) | 0B | Outbound adjacency list |
| 3 | `edges_in` | `target_id(16) \| kind(1) \| source_id(16)` | 33B | empty | 0B | Inbound adjacency index |
| 4 | `vectors` | `entity_id` (16 bytes) | 16B | `[f32; N]` raw little-endian bytes | N×4B | Embedding vectors |
| 5 | `hnsw_neighbors` | `entity_id` (16 bytes) | 16B | `[entity_id; M]` concatenated IDs | M×16B | HNSW neighbor lists (flat NSW, single layer) |
| 6 | `hnsw_meta` | string key (e.g., `"entry_point"`, `"count"`) | variable | raw bytes | variable | HNSW metadata (entry point ID, node count) |
| 7 | `text_postings` | `term` (UTF-8 string) | variable | `[(entity_id(16), tf(4))]` packed | N×20B | BM25 inverted index |
| 8 | `text_meta` | `entity_id` (16 bytes) | 16B | `doc_len(4) \| field_count(4)` | 8B | BM25 document metadata |
| 9 | `ppr_cache` | `seed_set_hash` (32 bytes, SHA-256) | 32B | `[(entity_id(16), score(4))]` packed | N×20B | Cached PPR results |

### 4.2 Key Encoding Patterns

All entity IDs are 16 bytes (UUID v7, time-ordered, big-endian). This ensures LMDB's lexicographic key ordering matches temporal ordering.

**Edge keys (33 bytes):**
```
edges_out key: [source_id: 16B] [edge_kind: 1B] [target_id: 16B]
edges_in key:  [target_id: 16B] [edge_kind: 1B] [source_id: 16B]
```

Range scan for "all outbound edges of entity X": seek to `[X, 0x00, 0x00...]`, iterate while prefix matches `X`.

**Helix pattern for reference (DO NOT COPY — different approach):**
Helix uses `node_id(16) | label_hash(4)` = 20B keys with DUP_SORT for multiple edges per key. Value = `edge_id(16) | neighbor_id(16)` = 32B. We simplify: no DUP_SORT, no edge IDs in graph — edge existence is the key itself.

### 4.3 Vector Storage

Vectors stored as raw little-endian f32 bytes. No length prefix (dimension known from config).

```rust
// Write: &[f32] → &[u8] (zero-copy on LE platforms)
fn f32_to_bytes(v: &[f32]) -> &[u8] {
    unsafe { std::slice::from_raw_parts(v.as_ptr() as *const u8, v.len() * 4) }
}

// Read: &[u8] → &[f32] (zero-copy on LE platforms)
fn bytes_to_f32(b: &[u8]) -> &[f32] {
    unsafe { std::slice::from_raw_parts(b.as_ptr() as *const f32, b.len() / 4) }
}
```

Or use safe Vec-based conversion initially and optimize later.

### 4.4 LMDB Configuration

```rust
const MAX_DBS: u32 = 12; // 9 core + room for sync databases
const DEFAULT_MAP_SIZE: usize = 1 << 30; // 1 GB
const DEFAULT_MAX_READERS: u32 = 126;
```

Map size is virtual memory only on 64-bit — doesn't consume physical RAM until pages are written.

### 4.5 Transaction Patterns

- **Reads**: Single `RoTxn` shared across entire pipeline (consistent snapshot)
- **Writes**: Single `RwTxn` per batch (LMDB single-writer). Insert entity + vector + edges + text index in one txn.
- **heed API**:
  ```rust
  let env = unsafe { EnvOpenOptions::new().map_size(size).max_dbs(12).open(path)? };
  let mut wtxn = env.write_txn()?;
  let db: Database<Bytes, Bytes> = env.create_database(&mut wtxn, Some("entities"))?;
  wtxn.commit()?;

  // Read
  let rtxn = env.read_txn()?;
  let val = db.get(&rtxn, key_bytes)?; // Option<&[u8]>

  // Write
  let mut wtxn = env.write_txn()?;
  db.put(&mut wtxn, key_bytes, value_bytes)?;
  wtxn.commit()?;

  // Range scan (for edge prefix iteration)
  let iter = db.range(&rtxn, &(start..end))?;
  // Or prefix_iter if available in your heed version:
  let iter = db.prefix_iter(&rtxn, prefix_bytes)?;
  ```

---

## 5. Public API

### 5.1 Vault (main entry point)

```rust
pub struct Vault { /* Store + config */ }

impl Vault {
    pub fn open(path: impl AsRef<Path>, config: VaultConfig) -> Result<Self>;

    // Document CRUD
    pub fn put(&self, id: EntityId, data: &[u8]) -> Result<()>;
    pub fn get(&self, id: EntityId) -> Result<Option<Vec<u8>>>;
    pub fn delete(&self, id: EntityId) -> Result<bool>;

    // Vector storage
    pub fn put_vector(&self, id: EntityId, vector: &[f32]) -> Result<()>;
    pub fn get_vector(&self, id: EntityId) -> Result<Option<Vec<f32>>>;

    // Edge storage
    pub fn put_edge(&self, src: EntityId, kind: EdgeKind, tgt: EntityId) -> Result<()>;
    pub fn delete_edge(&self, src: EntityId, kind: EdgeKind, tgt: EntityId) -> Result<bool>;
    pub fn edges_out(&self, src: EntityId) -> Result<Vec<(EdgeKind, EntityId)>>;
    pub fn edges_in(&self, tgt: EntityId) -> Result<Vec<(EdgeKind, EntityId)>>;

    // Text indexing (for BM25)
    pub fn index_text(&self, id: EntityId, fields: &[(&str, &str)]) -> Result<()>;
    pub fn deindex_text(&self, id: EntityId) -> Result<()>;

    // Pipeline query
    pub fn query(&self) -> PipelineBuilder;
}
```

### 5.2 VaultConfig

```rust
pub struct VaultConfig {
    pub dimensions: usize,      // 1024 (device) or 4096 (server)
    pub map_size: usize,        // LMDB map size (default 1GB)
    pub max_readers: u32,       // default 126
    pub hnsw: HnswConfig,
}

pub struct HnswConfig {
    pub m: usize,               // 32 (neighbors per node in upper layers)
    pub m_max_0: usize,         // 64 (neighbors per node in layer 0)
    pub ef_construction: usize, // 200 (beam width during insert)
    pub ef_search: usize,       // 128 (beam width during search)
}

impl Default for VaultConfig {
    fn default() -> Self {
        Self {
            dimensions: 1024,
            map_size: 1 << 30,
            max_readers: 126,
            hnsw: HnswConfig {
                m: 32,
                m_max_0: 64,
                ef_construction: 200,
                ef_search: 128,
            },
        }
    }
}
```

### 5.3 PipelineBuilder (lazy query composition)

```rust
pub struct PipelineBuilder<'a> { /* borrows Vault */ }

impl<'a> PipelineBuilder<'a> {
    pub fn search_vector(self, vector: &[f32], limit: usize) -> Self;
    pub fn search_text(self, query: &str, limit: usize) -> Self;
    pub fn search(self, query: &str, vector: &[f32], limit: usize) -> Self; // both

    pub fn filter_types(self, types: &[&str]) -> Self;
    pub fn filter_since(self, timestamp: u64) -> Self;

    pub fn expand_ppr(self, seeds: &[EntityId], depth: u32) -> Self;
    pub fn boost_recency(self, half_life_days: f32) -> Self;

    pub fn limit(self, n: usize) -> Self;
    pub fn run(self) -> Result<Vec<ScoredEntity>>;
}
```

### 5.4 Core Types

```rust
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EntityId([u8; 16]);

impl EntityId {
    pub fn new() -> Self; // UUID v7 (time-ordered)
    pub fn from_bytes(bytes: [u8; 16]) -> Self;
    pub fn as_bytes(&self) -> &[u8; 16];
}

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum EdgeKind {
    BelongsTo = 0,
    ParticipatesIn = 1,
    Attached = 2,
    AuthoredBy = 3,
    Mentions = 4,
    About = 5,
    Supports = 6,
    Opposes = 7,      // weight 0.0 — blocks PPR propagation
    ClaimOf = 8,
    ScopedTo = 9,
    Supersedes = 10,
    DerivedFrom = 11,
    PartOf = 12,       // hop-limited to max 2
}

impl EdgeKind {
    pub fn ppr_weight(self) -> f32;     // see weight table below
    pub fn max_hops(self) -> Option<u32>; // PartOf → Some(2), others → None
    pub fn try_from_u8(v: u8) -> Option<Self>;
}

pub struct ScoredEntity {
    pub id: EntityId,
    pub score: f32,
}
```

---

## 6. Algorithm Details

### 6.1 HNSW (Flat NSW)

**Use flat NSW** (single layer, no hierarchy). At 768+ dimensions, hierarchy provides no recall benefit while doubling search time. This was validated in helix benchmarks.

#### Insert
```
fn insert(id, vector):
    store vector in vectors db
    if graph is empty:
        store as entry point, return

    neighbors = search(vector, ef_construction)
    selected = select_neighbors(neighbors, m_max_0)  // always m_max_0 for flat

    store selected as neighbors of id
    for each neighbor n in selected:
        add id to n's neighbor list
        if n.neighbors.len() > m_max_0:
            prune: keep closest m_max_0 neighbors (by distance to n, NOT to id)
```

**CRITICAL BUG TO AVOID:** Helix pruned using distance to the *query* point instead of distance to the *neighbor being pruned*. This is wrong — when re-pruning a neighbor's connections, distances should be relative to that neighbor, not the newly inserted node.

#### Search
```
fn search(query_vector, k, ef):
    entry = entry_point
    candidates = BinaryHeap::new()  // min-heap by distance
    results = BinaryHeap::new()     // max-heap by distance (for eviction)
    visited = HashSet::new()

    distance = cosine_distance(query_vector, entry.vector)
    candidates.push((distance, entry))
    results.push((distance, entry))
    visited.insert(entry.id)

    while let Some((dist, current)) = candidates.pop_min():
        // Early termination
        if dist > results.peek_max().distance && results.len() >= ef:
            break

        for neighbor_id in current.neighbors:
            if visited.contains(neighbor_id): continue
            visited.insert(neighbor_id)

            neighbor_vec = load_vector(neighbor_id)
            d = cosine_distance(query_vector, neighbor_vec)

            if d < results.peek_max().distance || results.len() < ef:
                candidates.push((d, neighbor_id))
                results.push((d, neighbor_id))
                if results.len() > ef:
                    results.pop_max()  // evict furthest

    return results.into_sorted_vec().take(k)
```

#### Select Neighbors (simple strategy)
```
fn select_neighbors(candidates, m):
    sort candidates by distance ascending
    return candidates[..m]  // take m closest
```

No extended heuristic (from the HNSW paper). Simple selection works well for our use case.

#### Cosine Distance

`distance = 1.0 - cosine_similarity(a, b)`

Where `cosine_similarity = dot(a,b) / (||a|| × ||b||)`

**SIMD implementations needed:**

```rust
// ARM (iOS, Android, Apple Silicon) — NEON, 4×f32 per register
#[cfg(target_arch = "aarch64")]
unsafe fn cosine_similarity_neon(a: &[f32], b: &[f32]) -> f32 {
    // vld1q_f32, vfmaq_f32, vaddvq_f32
    // Process 4 f32 per iteration
}

// x86 (cloud, desktop) — AVX2, 8×f32 per register
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2", enable = "fma")]
unsafe fn cosine_similarity_avx2(a: &[f32], b: &[f32]) -> f32 {
    // _mm256_loadu_ps, _mm256_fmadd_ps
    // Process 8 f32 per iteration
}

// Fallback — scalar with 8-element unrolling
fn cosine_similarity_scalar(a: &[f32], b: &[f32]) -> f32 {
    // Manual loop unrolling (8 elements per iteration)
}
```

Select at compile time via `#[cfg(target_arch)]`.

### 6.2 BM25

Standard BM25 with inverted index in LMDB.

**Parameters:**
- k1 = 1.2
- b = 0.75
- Tokenizer: Unicode word boundaries + lowercase (no stemming, no stop words)

**Scoring:**
```
IDF(t) = ln((N - df(t) + 0.5) / (df(t) + 0.5) + 1.0)
BM25(q, d) = Σ IDF(t) × (tf(t,d) × (k1 + 1)) / (tf(t,d) + k1 × (1 - b + b × dl/avgdl))
```

**Index structure:**
- `text_postings`: term → posting list `[(entity_id, tf)]`
- `text_meta`: entity_id → `(doc_length, field_count)`
- Collection stats stored in `text_meta` under special keys (e.g., key = all-zeros for total_docs, all-ones for total_length)

**Search:**
```
fn bm25_search(query, k):
    tokens = tokenize(query)  // lowercase + split on non-alphanumeric
    N = get_total_docs()
    avgdl = get_total_length() / N

    scores: HashMap<EntityId, f32> = {}
    for token in tokens:
        posting_list = get_postings(token)
        df = posting_list.len()
        idf = ln((N - df + 0.5) / (df + 0.5) + 1.0)
        for (doc_id, tf) in posting_list:
            dl = get_doc_length(doc_id)
            score = idf * (tf * (k1 + 1)) / (tf + k1 * (1 - b + b * dl / avgdl))
            scores[doc_id] += score

    sort by score descending, return top k
```

**Helix BM25 reference:**
- Uses `Database<Bytes, Bytes>` with DUP_SORT for inverted index (multiple docs per term stored as sorted duplicates)
- `Database<U128<BE>, U32<BE>>` for doc_lengths
- `Database<Bytes, U32<BE>>` for term_frequencies (global df per term)
- `Database<Bytes, Bytes>` for metadata (total_docs, total_length)

### 6.3 Personalized PageRank (PPR)

Bidirectional PPR with weighted edge propagation. Two reference implementations:
- TypeScript: `/home/ubuntu/projects/oneiron-internal/open/packages/api/src/component/ppr.ts`
- Rust: `/home/ubuntu/projects/oneiron-helixdb/helix/helix-db/src/helix_engine/graph/ppr.rs`

**Edge weights for PPR propagation:**

| Edge Kind | Weight | Notes |
|-----------|--------|-------|
| belongs_to | 1.0 | |
| participates_in | 1.0 | |
| attached | 0.8 | |
| authored_by | 0.9 | |
| mentions | 0.6 | |
| about | 0.5 | |
| supports | 1.0 | |
| opposes | 0.0 | **Blocks propagation entirely** (contradiction isolation) |
| claim_of | 1.0 | |
| scoped_to | 0.7 | |
| supersedes | 0.3 | |
| derived_from | 0.2 | |
| part_of | 0.8 | **Hop-limited**: max 2 hops to prevent over-expansion |

**Algorithm:**
```
fn ppr(seeds, depth, damping=0.85):
    scores: HashMap<EntityId, f32> = {}
    frontier: HashMap<(EntityId, part_of_hops), f32> = {}

    // Initialize
    for seed in seeds:
        scores[seed] = 1.0 / seeds.len()
        frontier[(seed, 0)] = 1.0 / seeds.len()

    // Iterate
    for _ in 0..depth:
        next_frontier = {}
        total = sum(frontier.values())

        for ((node, hops), score) in frontier:
            if score < 1e-10: continue

            // Propagate through BOTH out AND in edges (bidirectional)
            for (kind, neighbor) in edges_out(node) ∪ edges_in(node):
                weight = kind.ppr_weight()
                if weight == 0.0: continue  // opposes blocks

                new_hops = if kind == PartOf { hops + 1 } else { hops }
                if kind == PartOf && new_hops > 2: continue  // hop limit

                propagated = score * weight * damping
                next_frontier[(neighbor, new_hops)] += propagated

        // Teleport back to seeds
        teleport = total * (1.0 - damping) / seeds.len()
        for seed in seeds:
            next_frontier[(seed, 0)] += teleport

        // Accumulate
        for ((node, _), score) in next_frontier:
            scores[node] += score

        frontier = next_frontier

    return scores sorted by score descending
```

**Key difference from TypeScript version:**
- TypeScript normalizes by total outgoing weight; Rust uses raw weights
- TypeScript has convergence-based termination (delta < 0.0001, max 20 iterations)
- Rust uses fixed depth iterations (typically 2-5)
- Rust tracks `part_of` hops in frontier key for hop limiting

**Caching:**
PPR results cached by hash of seed set. TTL varies by access pattern:
- Active session: 24 hours
- Recent (7 days): 72 hours
- Dormant: 168 hours
Cache invalidated when edges are added/removed from seed entities.

### 6.4 RRF Score Fusion

```
const RRF_K: f32 = 60.0;

fn rrf_fuse(ranked_lists: &[Vec<ScoredEntity>]) -> Vec<ScoredEntity> {
    scores: HashMap<EntityId, f32> = {}
    for list in ranked_lists:
        for (rank, entity) in list.iter().enumerate():
            scores[entity.id] += 1.0 / (RRF_K + rank as f32 + 1.0)
    sort by score descending
}
```

**Signal boosts (applied after RRF):**
```
final_score = rrf_score
    × (1.0 + salience)              // salience: 0-1, activation count / max
    × (1.0 + 0.5 × recency)        // recency: 0-1, exponential decay
    × (0.5 + 0.5 × confidence)     // confidence: 0-1, claim confidence
```

**Oversampling:**
- Vector: fetch 3× limit for fusion
- BM25: fetch 3× limit
- PPR: fetch 2× limit

### 6.5 Retrieval Modes

| Mode | Signals | Target Latency (server) | Target Latency (device) |
|------|---------|------------------------|------------------------|
| fast | Vector + BM25 | < 20ms | < 10ms |
| standard | + PPR (depth 3) | < 50ms | < 30ms |
| deep | + PPR (depth 4-5) + cross-encoder | < 100ms | < 60ms |

---

## 7. Build Order

Implement in this order. Each step should compile and pass tests before moving to the next.

### Step 1: Scaffold + LMDB Document Store (~300 LOC)

**Files:** `lib.rs`, `types.rs`, `error.rs`, `store.rs`

- VaultConfig, EntityId, EdgeKind types
- Error enum (Storage, Io, DimensionMismatch)
- Store struct with all 9 LMDB databases
- Key encoding/decoding functions
- Vault::open, put, get, delete
- Vault::put_vector, get_vector
- Vault::put_edge, delete_edge, edges_out, edges_in
- Basic tests: open vault, CRUD entities, CRUD vectors, CRUD edges

### Step 2: HNSW Vector Search (~800 LOC)

**Files:** `hnsw.rs`, `distance.rs`

- Cosine distance: scalar implementation first, then NEON/AVX2
- HNSW insert (flat NSW, m_max_0=64)
- HNSW search (beam search, ef=128)
- Select neighbors (simple strategy)
- Entry point management
- Tests: insert 1K vectors, search recall@10 vs brute-force

### Step 3: BM25 Full-Text Search (~600 LOC)

**Files:** `bm25.rs`

- Tokenizer (Unicode word boundaries + lowercase)
- Inverted index: insert/delete documents
- BM25 scoring
- Search: top-k by BM25 score
- Tests: index documents, search queries, verify ranking

### Step 4: PPR Graph Traversal (~400 LOC)

**Files:** `ppr.rs`

- Bidirectional PPR with weighted edges
- Part-of hop limiting
- Convergence detection or fixed-depth iteration
- PPR cache (optional, can defer)
- Tests: build graph, compute PPR, verify propagation

### Step 5: RRF Fusion + Pipeline Builder (~200 LOC)

**Files:** `fusion.rs`, `pipeline.rs`

- RRF fusion (combine vector + BM25 + PPR ranked lists)
- Signal boosts (salience, recency, confidence)
- PipelineBuilder: lazy composition, single-txn execution
- Tests: end-to-end pipeline with all signals

### Step 6: Benchmarks (~400 LOC)

**Files:** `crates/oneiron-bench/src/main.rs`

- Scale benchmarks: 1K, 5K, 10K, 50K, 100K
- Metrics: recall@10, p50/p90/p99 latency, QPS, disk usage
- Ground truth: brute-force cosine distance
- Test data: random vectors + Zipf-distributed text
- Compare against baseline targets

### Step 7: FFI Layer (~200 LOC)

**Files:** `crates/oneiron-ffi/src/lib.rs`

- C-compatible FFI for mobile
- JSON serialization at FFI boundary
- `oneiron_vault_open`, `oneiron_vault_search`, `oneiron_vault_close`

---

## 8. Known Bugs to Avoid (from Helix)

These were discovered and fixed in the helix fork. DO NOT introduce them:

1. **m_max_0 for layer 0**: Always use `m_max_0` (64) for layer 0 connections, not `m` (32). Helix used `m` for all layers, causing 26.7pp recall loss at 50K scale.

2. **Conditional re-pruning**: Only prune a neighbor's connections when they exceed `m_max_0`. Helix unconditionally re-pruned ALL neighbors on every insert.

3. **Re-pruning reference point**: When pruning neighbor N's connections, compute distances relative to N (the neighbor being pruned), NOT relative to the newly inserted node. Helix passed the wrong reference point.

4. **Reversed Ord for heaps**: If using a max-heap where pop() should return the *closest* (smallest distance), you need reversed Ord. Helix's `get_max()` used `iter().min()` due to this. **Better approach:** Use std `BinaryHeap` with `Reverse` wrapper or a proper min-heap. Don't invent custom heap ordering.

5. **Entry point persistence**: Store both entry point ID (16 bytes) AND level (8 bytes) = 24 bytes total. Helix initially stored only the ID, losing level information.

6. **AVX2 remainder handling**: When vector length isn't divisible by SIMD width, handle the remainder elements with scalar code.

---

## 9. Helix Benchmark Reference

These are the numbers helix achieved (768-dim f64, M=32, m_max_0=64, ef=128, flat NSW, AVX2):

| Scale | p50 | p90 | Recall@10 | Disk |
|-------|-----|-----|-----------|------|
| 1K | 20ms | 28ms | 100.0% | 14MB |
| 5K | 33ms | 43ms | 98.3% | 91MB |
| 10K | 29ms | 34ms | 95.7% | 185MB |
| 50K | 42ms | 50ms | 72.7% | 879MB |
| 100K | 44ms | 55ms | 55.7% | 1635MB |

oneiron-db should beat these because:
- f32 vectors = half the memory, 2x SIMD throughput
- Fix the re-pruning reference point bug (should improve recall at scale)
- Consider extended neighbor heuristic for better recall

**PPR performance (from helix benchmarks):**
- Deep traversal (depth=5): 1.66ms
- Many seeds (50): 5.37ms
- 1K nodes: 11ms
- 5K edges: 12ms

---

## 10. Convex Baseline (what we're replacing)

Current JS brute-force on Convex (1536-dim, full table scan):

| Scale | Vector p50 | Deployed | Max Scale |
|-------|-----------|----------|-----------|
| 1K | 3.8ms (local) | 1,056ms | 1K (16MB read limit) |
| 5K | 22ms (local) | **IMPOSSIBLE** | — |
| 10K | 40ms (local) | **IMPOSSIBLE** | — |
| 50K | 303ms (local) | **IMPOSSIBLE** | — |

oneiron-db needs to beat 3.8ms local at 1K (easy) and work at 50K+ (impossible on Convex).

---

## 11. Schema-Agnostic Design

oneiron-db does NOT know about Oneiron's entity types (Person, Claim, Event, etc.). It stores:
- **Documents**: opaque byte blobs with an EntityId
- **Vectors**: f32 embeddings associated with an EntityId
- **Text fields**: named string fields for BM25 indexing
- **Edges**: typed connections between EntityIds

The application layer (Eiri, B2B customer) assigns meaning. A Person, a Claim, and a diary entry are all just documents with optional vectors, text, and edges.

Adding a new entity type = inserting documents with that type's text fields and edges. No schema changes to oneiron-db.

---

## 12. Oneiron Data Model (for context — NOT implemented in oneiron-db)

The application layer (oneiron-internal) has these entity types that will be stored as documents:

**Core entities:** Person, Relationship, Conversation, Session, Turn, Message, MessageRevision, Event, Summary, Claim, PredicateDef, Skill, Place, Asset, AssetText

**Edge kinds used:**
- `belongs_to` — ownership/containment (message → conversation)
- `claim_of` — claim → subject entity
- `about` — content references entity
- `mentions` — passing reference
- `supports` — evidential link
- `derived_from` — computation provenance
- `participates_in`, `attached`, `authored_by`, `scoped_to`, `supersedes`, `part_of`, `opposes`

**Claims model:**
- Subject (entity being described) + predicate (e.g., "profile.name") + value (typed union)
- Confidence score (0-1)
- Lifecycle: active → superseded → retracted
- Approval: auto, proposed, approved, rejected
- Claims with `opposes` edges block PPR propagation (contradiction isolation)

---

## 13. Reference Code Locations (READ ONLY — AGPL, DO NOT COPY)

Helix reference for algorithm understanding:
- **HNSW**: `/home/ubuntu/projects/oneiron-helixdb/helix/helix-db/src/helix_engine/vector_core/vector_core.rs` (insert: lines 592-672, search: 523-590, select_neighbors: 289-340)
- **Distance**: `/home/ubuntu/projects/oneiron-helixdb/helix/helix-db/src/helix_engine/vector_core/vector_distance.rs` (158 lines)
- **BM25**: `/home/ubuntu/projects/oneiron-helixdb/helix/helix-db/src/helix_engine/bm25/bm25.rs` (505 lines)
- **PPR**: `/home/ubuntu/projects/oneiron-helixdb/helix/helix-db/src/helix_engine/graph/ppr.rs` (595 lines)
- **PPR Cache**: `/home/ubuntu/projects/oneiron-helixdb/helix/helix-db/src/helix_engine/graph/ppr_cache.rs` (622 lines)
- **Storage**: `/home/ubuntu/projects/oneiron-helixdb/helix/helix-db/src/helix_engine/storage_core/mod.rs` (345 lines)
- **Benchmarks**: `/home/ubuntu/projects/oneiron-helixdb/helix/helix-db/benches/vault_scale_benches.rs`

Oneiron-internal TypeScript reference (OUR CODE, can reference freely):
- **PPR**: `/home/ubuntu/projects/oneiron-internal/open/packages/api/src/component/ppr.ts`
- **Fusion**: `/home/ubuntu/projects/oneiron-internal/open/packages/api/src/component/fusion.ts`
- **Vector**: `/home/ubuntu/projects/oneiron-internal/open/packages/api/src/component/vector.ts`
- **FTS**: `/home/ubuntu/projects/oneiron-internal/open/packages/api/src/component/fts.ts`
- **Schema**: `/home/ubuntu/projects/oneiron-internal/open/packages/api/src/component/schema.ts` (687 lines, 26+ tables)
- **Edges**: `/home/ubuntu/projects/oneiron-internal/open/packages/api/src/component/edges.ts`
- **Types**: `/home/ubuntu/projects/oneiron-internal/open/packages/core/src/types/`

Architecture docs:
- **ONEIRON-ARCH-019**: `/home/ubuntu/projects/eiri-docs/docs/oneiron/architecture/ONEIRON-ARCH-019-oneiron-db-v1.md` (engine architecture)
- **CROSS-RESEARCH-019**: `/home/ubuntu/projects/eiri-docs/docs/cross/research/CROSS-RESEARCH-019-helix-db-internals.md` (helix internals + 10 bug fixes)

---

## 14. Style Guidelines

- **No comments** unless explicitly requested
- **Short, descriptive names**
- **Simple > clever** (KISS)
- **YAGNI** — only implement what's needed now
- Prefer `bun` over `npm` for any JS tooling
- Never sign git commits
- Apache 2.0 license header NOT required in source files (just LICENSE file)
- Use `thiserror` for errors, not custom Display impls
- Use `uuid` v7 for EntityId generation (time-ordered)
- Use `heed` (not `heed3`) for LMDB bindings

---

## 15. Success Criteria

The crate is done when:
1. `cargo test` passes all unit tests
2. `cargo bench` (via oneiron-bench) shows:
   - Vector search recall@10 > 95% at 10K scale
   - Vector search p50 < 20ms at 10K scale (on server hardware)
   - Full pipeline p50 < 50ms at 10K scale
3. The API surface matches section 5 (Vault, PipelineBuilder, types)
4. Cross-compiles to aarch64 (for future iOS/Android)
5. Total LOC < 3K (excluding benchmarks and FFI)
