# Task 7: Context Pack + Serialization — Implementation Guide

## Overview

Build the context pack layer that turns `PipelineBuilder.run()` (which returns `Vec<ScoredEntity>` — IDs + scores) into fully hydrated, formatted output suitable for direct LLM injection or programmatic access. This eliminates N separate `get()` calls and N FFI round-trips.

**New files:**

- `crates/oneiron/src/context_pack.rs` — `ContextPackBuilder`, hydration, edge walking
- `crates/oneiron/src/serialize.rs` — 5 format serializers (JSON, YAML, TOON, Markdown, Plaintext)

**Modified files:**

- `crates/oneiron/src/lib.rs` — add `pub mod context_pack; pub mod serialize;`, add `Vault::context_pack()` method, re-export new public types
- `crates/oneiron/src/types.rs` — add new types (`ContextPack`, `ContextEntity`, `EdgeInfo`, `SignalHit`, `PackStats`)
- `crates/oneiron/Cargo.toml` — add `serde`, `serde_json`, `toon-format` dependencies
- `Cargo.toml` (workspace) — add workspace dependencies (`serde`, `serde_json`, `toon-format`)

**Do NOT modify:** `pipeline.rs`, `fusion.rs`, `store.rs`, `batch.rs`, `ppr.rs`, `hnsw.rs`, `bm25.rs`, `distance.rs`, `error.rs`

The review follow-ups from Task 6 (pipeline optimizations) are tracked in TASKS.md but are **out of scope** for this PR. They require changes to `pipeline.rs` and `ppr.rs` which are separate concerns.

---

## Dependencies

Add to workspace `Cargo.toml`:

```toml
[workspace.dependencies]
serde = { version = "1", features = ["derive"] }
serde_json = "1"
toon-format = { version = "0.4", default-features = false }
```

Add to `crates/oneiron/Cargo.toml`:

```toml
[dependencies]
serde = { workspace = true }
serde_json = { workspace = true }
toon-format = { workspace = true }
```

We use the `toon-format` crate (v0.4.3, without `cli` feature) for TOON output. It handles tabular detection, delimiter management, quoting, and encoding automatically. The crate's non-cli deps are: `serde`, `serde_json`, `indexmap`, `thiserror` — all of which we already have or need.

**Do NOT add:** `serde_yaml` or any other serialization crates. YAML and Markdown/Plaintext are simple enough to emit manually.

---

## Types (add to `types.rs`)

```rust
use std::collections::HashMap;

/// Hydrated entity with decoded fields, edges, and provenance.
#[derive(Debug, Clone)]
pub struct ContextEntity {
    pub id: EntityId,
    pub short_id: String,        // e.g. "cl88"
    pub content_hash: u8,        // xxHash32 % 256
    pub entity_type: u8,
    pub score: f32,              // 0.0 for unscored neighbors
    pub fields: Option<HashMap<String, serde_json::Value>>,  // decoded msgpack fields
    pub edges: Option<Vec<EdgeInfo>>,
    pub vector: Option<Vec<f32>>,
}

/// Edge info for hydrated context entities.
#[derive(Debug, Clone)]
pub struct EdgeInfo {
    pub kind: EdgeKind,
    pub target: EntityId,
    pub target_short_id: Option<String>,  // resolved if target in result set
    pub weight: f32,
    pub created_at: u64,
}

/// Which retrieval signal produced a hit and its raw score.
#[derive(Debug, Clone, Copy)]
pub struct SignalHit {
    pub signal: Signal,
    pub score: f32,
}

/// Stats about the context pack query.
#[derive(Debug, Clone)]
pub struct PackStats {
    pub candidates_considered: usize,
    pub signals_used: Vec<Signal>,
    pub query_time_us: u64,
    pub entities_hydrated: usize,
    pub neighbors_hydrated: usize,
}

/// A fully hydrated context pack ready for serialization or programmatic use.
#[derive(Debug, Clone)]
pub struct ContextPack {
    pub results: Vec<ContextEntity>,
    pub neighbors: Vec<ContextEntity>,
    pub stats: PackStats,
}

/// Token budget allocation across entity types.
#[derive(Debug, Clone, Copy)]
pub struct TokenAllocation {
    pub claims: f32,     // default: 0.50
    pub turns: f32,      // default: 0.30
    pub summaries: f32,  // default: 0.15
    pub other: f32,      // default: 0.05
}

impl Default for TokenAllocation {
    fn default() -> Self {
        Self {
            claims: 0.50,
            turns: 0.30,
            summaries: 0.15,
            other: 0.05,
        }
    }
}
```

Add `Default` impls for `PackFormat` and `FieldProfile`:

```rust
impl Default for PackFormat {
    fn default() -> Self { Self::Json }
}

impl Default for FieldProfile {
    fn default() -> Self { Self::Standard }
}
```

---

## context_pack.rs — ContextPackBuilder

### Architecture

`ContextPackBuilder` wraps `PipelineBuilder` via **composition** (not inheritance). It holds a `PipelineBuilder` internally and delegates all search/filter/boost methods to it. It adds hydration-specific configuration and output formatting.

### Execution flow

```
ContextPackBuilder::run()
  1. Start timer
  2. Run internal PipelineBuilder::run() → Vec<ScoredEntity>
  3. Open single read txn (snapshot-consistent hydration)
  4. For each scored entity:
     a. Read entity blob from `entities` db
     b. Parse EntityMetadataHeader (25 bytes)
     c. Decode msgpack payload → HashMap<String, serde_json::Value>
     d. Read short_id + content_hash from `short_ids` db
     e. If include_edges: read outbound edges via prefix scan on `edges_out`
     f. If include_vectors: read vector from `vectors` db
  5. If edge_hop > 0: walk edges N hops, collect neighbor IDs (dedup), hydrate neighbors
  6. Record stats
  7. Return ContextPack
```

### API

```rust
pub struct ContextPackBuilder<'a> {
    pipeline: PipelineBuilder<'a>,
    vault: &'a Vault,
    hydrate: bool,              // decode msgpack fields (default: true)
    include_edges: bool,        // include outbound edges (default: false)
    edge_hop: u32,              // neighbor hops to hydrate (default: 0)
    max_neighbors: usize,       // cap on hydrated neighbors (default: 50)
    include_vectors: bool,      // include raw vectors (default: false)
    include_stats: bool,        // include stats in output (default: false)
    merge_neighbors: bool,          // merge results+neighbors into one pool (default: true)
    format: PackFormat,         // output format for run_serialized
    field_profile: FieldProfile,
    token_budget: usize,        // default: 4000 (0 = unlimited)
    token_allocation: TokenAllocation,
    max_field_chars: usize,     // truncate any string field beyond this (default: 500, 0 = unlimited)
    signals_used: Vec<Signal>,  // tracked by search_* delegation methods
}

impl<'a> ContextPackBuilder<'a> {
    pub(crate) fn new(vault: &'a Vault) -> Self { ... }

    // --- Delegate all PipelineBuilder methods ---
    // Each method takes self, calls the same method on self.pipeline, returns self.
    // search_* methods also push the corresponding Signal to self.signals_used.
    pub fn search_vector(mut self, vector: &[f32], limit: usize) -> Self;
    pub fn search_text(mut self, query: &str, limit: usize) -> Self;
    pub fn search_phonetic(mut self, codes: &[&str]) -> Self;
    pub fn search_temporal(mut self, anchor_start: u64, anchor_end: u64, limit: usize) -> Self;
    pub fn search_temporal_with_sigma(mut self, ...) -> Self;
    pub fn search_temporal_with_granularity(mut self, ...) -> Self;
    pub fn search_temporal_bitemporal(mut self, ...) -> Self;
    pub fn temporal_adaptive(mut self, enabled: bool) -> Self;  // no signal push, just config
    pub fn search(mut self, query: &str, vector: &[f32], time: Option<TimeRange>, limit: usize) -> Self;  // convenience combo — pushes Vector+Text+(Temporal if time.is_some())
    pub fn search_ppr(mut self, seeds: &[EntityId], depth: u32) -> Self;
    pub fn expand_ppr(mut self, seeds: &[EntityId], depth: u32) -> Self;
    pub fn boost_recency(mut self, half_life_days: f32) -> Self;
    pub fn boost_salience(mut self) -> Self;
    pub fn boost_confidence(mut self) -> Self;
    pub fn boost_contiguity(mut self) -> Self;
    pub fn filter_types(mut self, types: &[u8]) -> Self;
    pub fn filter_since(mut self, timestamp: u64) -> Self;
    pub fn filter_occurred_range(mut self, start: u64, end: u64) -> Self;
    pub fn filter_learned_range(mut self, start: u64, end: u64) -> Self;
    pub fn limit(mut self, n: usize) -> Self;

    // --- Context pack specific ---
    pub fn hydrate(mut self, yes: bool) -> Self;
    pub fn include_edges(mut self, yes: bool) -> Self;
    pub fn edge_hop(mut self, depth: u32) -> Self;
    pub fn max_neighbors(mut self, n: usize) -> Self;
    pub fn include_vectors(mut self, yes: bool) -> Self;
    pub fn include_stats(mut self, yes: bool) -> Self;  // include stats in output (default: false)
    pub fn merge_neighbors(mut self, yes: bool) -> Self;  // merge results+neighbors (default: true)
    pub fn format(mut self, fmt: PackFormat) -> Self;
    pub fn field_profile(mut self, profile: FieldProfile) -> Self;
    pub fn token_budget(mut self, budget: usize) -> Self;
    pub fn token_allocation(mut self, allocation: TokenAllocation) -> Self;
    pub fn max_field_chars(mut self, max: usize) -> Self;  // truncate string fields (default: 500, 0 = unlimited)

    // --- Output ---
    pub fn run(self) -> Result<ContextPack>;
    pub fn run_serialized(self) -> Result<Vec<u8>>;
}
```

### Key implementation details

**Delegating to PipelineBuilder:** The `PipelineBuilder` methods consume `self` and return `Self`. So `ContextPackBuilder` holds a `PipelineBuilder<'a>` and delegates like:

```rust
pub fn search_text(mut self, query: &str, limit: usize) -> Self {
    self.pipeline = self.pipeline.search_text(query, limit);
    self.signals_used.push(Signal::Text);  // track for PackStats
    self
}
```

**Signal tracking:** Each `search_*` delegation method pushes its `Signal` variant to `self.signals_used`. The `search()` convenience method pushes `Signal::Vector`, `Signal::Text`, and optionally `Signal::Temporal`. Non-search methods (boosts, filters, `temporal_adaptive`) don't push signals. The `signals_used` vec is deduped and moved into `PackStats` in `run()`.

**Hydrating entity blobs:** Entity blobs are stored as `[metadata_header(25 bytes) | msgpack_payload]`. The msgpack payload is a MessagePack Map. Decode it using `rmpv::decode::read_value()` on a `Cursor` over the payload bytes (after skipping the 25-byte header), then convert the `rmpv::Value::Map` to `HashMap<String, serde_json::Value>`.

Conversion from `rmpv::Value` → `serde_json::Value`:

```rust
fn rmpv_to_json(value: &rmpv::Value) -> serde_json::Value {
    match value {
        rmpv::Value::Nil => serde_json::Value::Null,
        rmpv::Value::Boolean(b) => serde_json::Value::Bool(*b),
        rmpv::Value::Integer(i) => {
            if let Some(v) = i.as_i64() {
                serde_json::json!(v)
            } else if let Some(v) = i.as_u64() {
                serde_json::json!(v)
            } else {
                serde_json::Value::Null
            }
        }
        rmpv::Value::F32(f) => serde_json::json!(*f),
        rmpv::Value::F64(f) => serde_json::json!(*f),
        rmpv::Value::String(s) => {
            serde_json::Value::String(s.as_str().unwrap_or_default().to_owned())
        }
        rmpv::Value::Binary(_) => serde_json::Value::Null,
        rmpv::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(rmpv_to_json).collect())
        }
        rmpv::Value::Map(entries) => {
            let mut map = serde_json::Map::new();
            for (k, v) in entries {
                if let Some(key) = k.as_str() {
                    map.insert(key.to_owned(), rmpv_to_json(v));
                }
            }
            serde_json::Value::Object(map)
        }
        rmpv::Value::Ext(_, _) => serde_json::Value::Null,
    }
}
```

**Reading short IDs:** The `short_ids` database maps `entity_id(16B) → short_id_string + content_hash(1B)`. Read the value, split last byte as content_hash, rest as UTF-8 short_id string.

**Edge walking for neighbors:**

```rust
fn walk_edges(
    store: &Store,
    rtxn: &RoTxn,
    seed_ids: &[EntityId],
    hops: u32,
    max_neighbors: usize,
    exclude: &HashSet<EntityId>,
) -> Result<Vec<EntityId>> {
    let mut visited = HashSet::new();
    let mut frontier: Vec<EntityId> = seed_ids.to_vec();

    for _ in 0..hops {
        let mut next_frontier = Vec::new();
        for id in &frontier {
            let edges = scan_edges_for_entity(store, rtxn, id)?;
            for edge in edges {
                if !visited.contains(&edge.target)
                    && !exclude.contains(&edge.target)
                    && visited.len() < max_neighbors
                {
                    visited.insert(edge.target);
                    next_frontier.push(edge.target);
                }
            }
        }
        frontier = next_frontier;
        if frontier.is_empty() || visited.len() >= max_neighbors {
            break;
        }
    }

    Ok(visited.into_iter().collect())
}
```

**`run_serialized()`** calls `run()` then builds a `SerializeConfig` from builder fields and passes both to `serialize::serialize_pack()`.

### Vault API addition

In `lib.rs`, add:

```rust
impl Vault {
    /// Creates a context pack builder for retrieval + hydration + serialization.
    pub fn context_pack(&self) -> ContextPackBuilder<'_> {
        ContextPackBuilder::new(self)
    }
}
```

---

## serialize.rs — Format Serializers

### Main entry point

```rust
pub struct SerializeConfig {
    pub format: PackFormat,
    pub profile: FieldProfile,
    pub budget: usize,             // 0 = unlimited
    pub allocation: TokenAllocation,
    pub include_stats: bool,       // default: false
    pub merge_neighbors: bool,     // default: true
    pub max_field_chars: usize,    // default: 500 (0 = unlimited). Truncate with "…" suffix.
}

pub fn serialize_pack(pack: &ContextPack, config: &SerializeConfig) -> Vec<u8> {
    match config.format {
        PackFormat::Json => serialize_json(pack, config),
        PackFormat::Yaml => serialize_llm(pack, config),
        PackFormat::Toon => serialize_llm(pack, config),
        PackFormat::Markdown => serialize_llm(pack, config),
        PackFormat::Plaintext => serialize_llm(pack, config),
    }
}
```

The `serialize_llm` function handles the shared transformation pipeline (grouping, field filtering, timestamps, budget) then dispatches to format-specific writers (toon/yaml/markdown/plaintext).

**`merge_neighbors` defaults to `true`** for all formats. When `true`, results and neighbors are merged into one pool, grouped by entity type, sorted by score descending. When `false`, all formats output results grouped by type first, then a separator, then neighbors grouped by type.

**Split mode separators** (when `merge_neighbors = false`):
- **JSON**: `{"results": {...}, "neighbors": {...}}` (keyed structure, no separator needed)
- **TOON**: `---neighbors` line between result groups and neighbor groups
- **Markdown**: `---` + `### Neighbors` header
- **Plaintext**: `---NEIGHBORS` line
- **YAML**: `# --- neighbors ---` comment line

**`include_stats` defaults** to `false` for all formats. When `true`:
- JSON adds a `"stats"` key
- LLM formats append a compact stats line at the end (e.g. `---\nquery: 2.1ms | 45 candidates | signals: vector,text,temporal`)

**serialize_toon implementation approach:**

1. Merge results + neighbors, group by type, filter fields, replace short IDs, format relative timestamps
2. Build `serde_json::Value` with entity-type keys → arrays of entity objects
3. Call `toon_format::encode_default(&value)` → `String`
4. Convert to `Vec<u8>`

### Entity type grouping

All LLM-oriented formats group entities by type in priority order:

```rust
const GROUP_ORDER: &[u8] = &[
    0,  // CLAIM
    1,  // TURN
    8,  // SUMMARY
    6,  // EVENT
    4,  // PERSON
    7,  // SKILL
    10, // ASSET_TEXT
    9,  // PLACE
];
```

Group name for each type byte (used as section headers):

```rust
fn group_name(entity_type: u8) -> &'static str {
    match entity_type {
        0 => "CLAIMS",
        1 => "TURNS",
        2 => "SESSIONS",
        3 => "MESSAGES",
        4 => "PERSONS",
        5 => "RELATIONSHIPS",
        6 => "EVENTS",
        7 => "SKILLS",
        8 => "SUMMARIES",
        9 => "PLACES",
        10 => "TEXTS",
        11 => "CONVERSATIONS",
        _ => "OTHER",
    }
}
```

Within each group, sort by score descending.

### Field profiles

Field profiles control which msgpack fields to include per entity type.

```rust
fn fields_for_profile(entity_type: u8, profile: FieldProfile) -> &'static [&'static str] {
    match (entity_type, profile) {
        // CLAIM
        (0, FieldProfile::Minimal)  => &["pred", "val"],
        (0, FieldProfile::Standard) => &["pred", "val", "conf", "sal", "evid"],
        (0, FieldProfile::Full)     => &["pred", "val", "conf", "sal", "evid", "from", "to", "src", "world", "subj", "scope"],

        // TURN
        (1, FieldProfile::Minimal)  => &["txt"],
        (1, FieldProfile::Standard) => &["txt", "spkr", "at"],
        (1, FieldProfile::Full)     => &["txt", "spkr", "at", "sess"],

        // SUMMARY
        (8, FieldProfile::Minimal)  => &["txt"],
        (8, FieldProfile::Standard) => &["txt", "lvl", "at"],
        (8, FieldProfile::Full)     => &["txt", "lvl", "at", "src"],

        // EVENT
        (6, FieldProfile::Minimal)  => &["name"],
        (6, FieldProfile::Standard) => &["name", "at", "ppl"],
        (6, FieldProfile::Full)     => &["name", "at", "ppl", "place", "desc"],

        // PERSON
        (4, FieldProfile::Minimal)  => &["name"],
        (4, FieldProfile::Standard) => &["name"],
        (4, FieldProfile::Full)     => &["name", "role", "rel"],

        // SKILL (agentskills.io Agent Skills — blob has skillId, desc, version, approvalStatus, lifecycleStatus, source, confidence, spec)
        // NOTE: `spec` (full SKILL.md) is NEVER included in context pack — use Vault::load_skill() for full content.
        // `desc` is a short 1-2 sentence description set at ingest time by the Dreamer or skill install pipeline.
        (7, FieldProfile::Minimal)  => &["skillId"],
        (7, FieldProfile::Standard) => &["skillId", "desc", "approvalStatus"],
        (7, FieldProfile::Full)     => &["skillId", "desc", "version", "approvalStatus", "lifecycleStatus", "source", "confidence"],

        // All other types: return all fields for any profile
        _ => &[],  // empty means "include all fields from msgpack map"
    }
}
```

When the field list is empty (unknown type), include all fields from the msgpack map.

**Short ID format in output:** `short_id:content_hash_hex` — e.g., `cl88:f2`. The content_hash byte is formatted as lowercase hex (2 chars).

**Field truncation:** During serialization, any string field value exceeding `max_field_chars` (default: 500) is truncated and suffixed with `…` (U+2026 ellipsis). This applies after field profile filtering but before format-specific encoding. The context pack provides entity IDs so callers can look up full content via `vault.get(id)`. When `max_field_chars` is 0, no truncation is applied.

### Format specifications

#### JSON

Use `serde_json::to_vec()` (**minified**, not pretty-printed) on a constructed `serde_json::Value`. Minified saves tokens when injected into LLM context; programmatic callers can always pretty-print client-side.

**Default: merged** (`merge_neighbors = true`):

```json
{"claims":[{"id":"cl88:f2","score":0.42,"pred":"goal.learning","val":"Learn Japanese by June","conf":0.9,"sal":0.8,"evid":["tn17:a1","tn23:c4"]}],"persons":[{"id":"pr05:b3","score":0.0,"name":"Alice"}]}
```

With `merge_neighbors(false)` — results/neighbors keyed structure:

```json
{"results":{"claims":[{"id":"cl88:f2","score":0.42,"pred":"goal.learning","val":"Learn Japanese by June","conf":0.9,"sal":0.8,"evid":["tn17:a1","tn23:c4"]}]},"neighbors":{"persons":[{"id":"pr05:b3","score":0.0,"name":"Alice"}]}}
```

With `include_stats(true)` — adds `"stats"` key (works with either merge mode):

```json
{"claims":[...],"persons":[...],"stats":{"candidates":45,"signals":["vector","text","temporal"],"query_us":2100,"hydrated":15,"neighbors_hydrated":3}}
```

JSON encoding rules:
- **Minified** output (`serde_json::to_vec`, not `to_vec_pretty`)
- Timestamps are raw UNIX seconds (no relative conversion)
- Scores are included per entity
- Entity type groups use lowercase plural keys (claims, turns, persons, etc.)
- Empty groups are omitted
- No token budget enforcement
- `merge_neighbors` default: `true`; override with `merge_neighbors(false)` for results/neighbors split
- `include_stats` default: `false`; override with `include_stats(true)`

#### TOON

Uses the standard TOON v3.0 format via the `toon-format` crate. The crate auto-detects tabular arrays (homogeneous arrays of objects with identical keys) and encodes them as compact `key[N]{fields}:` rows. This is more token-efficient than custom pipe tables.

**How it works:** Build a `serde_json::Value` object with entity-type keys (lowercase plural), where each key maps to an array of entity objects. Then call `toon_format::encode_default(&value)`.

```
claims[2]{id,pred,val,conf,sal,evid}:
  cl88:f2,goal.learning,Learn Japanese by June,0.9,0.8,"tn17:a1,tn23:c4"
  cl92:a1,boundary.topic,Don't discuss ex,0.95,1.0,tn45:b2
turns[2]{id,txt,spkr,at}:
  tn17:a1,I really want to learn Japanese...,user,-3d
  tn23:c4,Set a goal for June...,eiri,-3d
```

TOON encoding rules:
- Build a single `serde_json::Value::Object` with lowercase plural keys (claims, turns, summaries, etc.)
- Each key maps to an array of entity objects (already field-filtered, short-ID-replaced, timestamp-formatted)
- Call `toon_format::encode_default(&value).unwrap()` — the crate handles tabular detection, quoting, delimiters
- The crate auto-quotes values containing commas, colons, or special chars
- Timestamps: relative notation (`-2h`, `-3d`, `-1w`, `-2mo`, `-1y`) — apply BEFORE encoding (they become string values)
- References (entity IDs in evid, src, etc.): comma-separated short IDs with hash — will be auto-quoted by toon-format since they contain commas
- Empty groups: omit the key entirely (don't include empty arrays)
- Entity ordering within groups: by score descending (pre-sort before building the Value)

**Important:** Apply all transformations (field filtering, short ID replacement, header abbreviation, relative timestamps) BEFORE building the `serde_json::Value`. The toon-format crate just serializes whatever `Value` you give it.

#### Markdown

```markdown
## Claims

| id | pred | val | conf | sal | evid |
|----|------|-----|------|-----|------|
| cl88:f2 | goal.learning | Learn Japanese by June | 0.9 | 0.8 | tn17:a1, tn23:c4 |

## Turns

| id | txt | spkr | at |
|----|-----|------|-----|
| tn17:a1 | I really want to learn Japanese... | user | -3d |
```

Markdown encoding rules:
- Section headers: `## Kind` (sentence case)
- Standard markdown table syntax (with separator row `|----|`)
- Same value escaping as TOON
- Same relative timestamps

#### Plaintext

```
CLAIMS
cl88:f2|goal.learning|Learn Japanese by June|0.9|0.8|tn17:a1,tn23:c4
cl92:a1|boundary.topic|Don't discuss ex|0.95|1.0|tn45:b2

TURNS
tn17:a1|I really want to learn Japanese...|user|-3d
tn23:c4|Set a goal for June...|eiri|-3d
```

Plaintext encoding rules:
- Section headers: `KIND` (all caps, no brackets)
- No header row (field order documented per kind)
- Pipe-delimited, NO spaces around pipes
- No quotes — pipes in values replaced with `\|`, newlines with `\n`
- Same relative timestamps

#### YAML

```yaml
claims:
  - id: "cl88:f2"
    pred: goal.learning
    val: "Learn Japanese by June"
    conf: 0.9
    sal: 0.8
    evid: [tn17:a1, tn23:c4]

turns:
  - id: "tn17:a1"
    txt: "I really want to learn Japanese..."
    spkr: user
    at: -3d
```

YAML encoding rules:
- Write YAML manually (no serde_yaml dep — it's trivial for our flat structure)
- Section keys: lowercase plural (claims, turns, summaries, etc.)
- Values that need quoting: strings containing `:`, `#`, `[`, `]`, `{`, `}`, or starting with special YAML chars
- Same relative timestamps
- Same reference format

### Relative timestamp formatting

Convert UNIX seconds to human-relative strings:

```rust
fn format_relative_timestamp(ts: u64, now: u64) -> String {
    if ts == 0 { return String::new(); }
    let diff = now.saturating_sub(ts);
    let minutes = diff / 60;
    let hours = diff / 3600;
    let days = diff / 86400;
    let weeks = days / 7;
    let months = days / 30;
    let years = days / 365;

    if minutes < 1 { "now".to_owned() }
    else if minutes < 60 { format!("-{}m", minutes) }
    else if hours < 24 { format!("-{}h", hours) }
    else if days < 7 { format!("-{}d", days) }
    else if weeks < 5 { format!("-{}w", weeks) }
    else if months < 12 { format!("-{}mo", months) }
    else { format!("-{}y", years) }
}
```

Use relative timestamps for TOON, Markdown, Plaintext, YAML. Use raw UNIX seconds for JSON.

### Token budget enforcement

Token estimation: `chars / 4` (rough approximation, matches industry standard).

```rust
fn enforce_token_budget(
    groups: &mut Vec<(u8, Vec<&ContextEntity>)>,
    profile: FieldProfile,
    budget: usize,
    allocation: &TokenAllocation,
    format: PackFormat,
) {
    if budget == 0 { return; } // 0 = unlimited
    let char_budget = budget * 4;

    for (entity_type, entities) in groups.iter_mut() {
        let type_fraction = match *entity_type {
            0 => allocation.claims,
            1 => allocation.turns,
            8 => allocation.summaries,
            _ => allocation.other,
        };
        let type_char_budget = (char_budget as f32 * type_fraction) as usize;

        // Serialize entities one by one, truncate when budget exceeded
        let mut used = 0;
        let mut keep = 0;
        for entity in entities.iter() {
            let entity_chars = estimate_entity_chars(entity, *entity_type, profile, format);
            if used + entity_chars > type_char_budget && keep > 0 {
                break;
            }
            used += entity_chars;
            keep += 1;
        }
        entities.truncate(keep);
    }
}
```

---

## Reference Material

### TOON format reference

We use the standard TOON v3.0 format via the `toon-format` crate (v0.4.3):
- Spec repo: `/Users/olety/Desktop/code/refs-oneiron/toon` (TypeScript reference implementation)
- Rust crate: `/Users/olety/Desktop/code/refs-oneiron/toon-rust` (Rust implementation)
- Key API: `toon_format::encode_default(&serde_json::Value) -> Result<String>`
- The crate auto-detects homogeneous arrays of objects and encodes them as tabular `key[N]{fields}:` format
- Handles quoting, delimiter escaping, nested objects automatically
- Use `default-features = false` in Cargo.toml to exclude the CLI/TUI dependencies

### Serialization spec

The full serialization format spec is at:
- `/Users/olety/Desktop/code/eiri-docs/docs/cross/CROSS-DEC-003-query-serialization-v2.md`

This is the canonical reference for all 5 formats, field profiles, short ID system, header abbreviations, and cross-reference handling.

### Schema design

- `/Users/olety/Desktop/code/oneiron/SCHEMA-DESIGN.md` — Context Pack Endpoint section (line 806+)

---

## Existing Code Patterns to Follow

### Entity blob layout

```
[type(1) | occurred_start(8 BE) | occurred_end(8 BE) | learned_at(8 BE) | msgpack_payload(...)]
 \_________________ 25 bytes ________________/
```

Parse via `EntityMetadataHeader::parse(raw)` in `batch.rs` (already `pub(crate)`).

### Short ID reading

```rust
// short_ids db: entity_id(16B) → [short_id_string(var) | content_hash(1B)]
fn read_short_id(store: &Store, rtxn: &RoTxn, id: &EntityId) -> Result<Option<(String, u8)>> {
    let Some(value) = store.short_ids.get(rtxn, id.as_bytes())? else {
        return Ok(None);
    };
    if value.len() < 2 {
        return Ok(None);
    }
    let (short_id_bytes, hash) = value.split_at(value.len() - 1);
    let short_id = std::str::from_utf8(short_id_bytes)
        .map_err(|_| Error::InvalidKey)?
        .to_owned();
    Ok(Some((short_id, hash[0])))
}
```

### Edge scanning (reuse pattern from lib.rs)

```rust
fn scan_edges_for_entity(
    store: &Store,
    rtxn: &RoTxn,
    id: &EntityId,
) -> Result<Vec<EdgeInfo>> {
    let mut edges = Vec::new();
    for entry in store.edges_out.prefix_iter(rtxn, id.as_bytes())? {
        let (key, value) = entry?;
        if key.len() != 33 || value.len() != 12 {
            continue;
        }
        let kind = match EdgeKind::try_from_u8(key[16]) {
            Some(k) => k,
            None => continue,
        };
        let target = EntityId::from_bytes(key[17..33].try_into().map_err(|_| Error::InvalidKey)?);
        let weight = f32::from_le_bytes(value[..4].try_into().map_err(|_| Error::InvalidKey)?);
        let created_at = u64::from_le_bytes(value[4..12].try_into().map_err(|_| Error::InvalidKey)?);
        edges.push(EdgeInfo {
            kind,
            target,
            target_short_id: None,  // resolved later
            weight,
            created_at,
        });
    }
    Ok(edges)
}
```

### Msgpack decoding (reuse pattern from fusion.rs)

The `decode_msgpack_float` function in `fusion.rs` shows the pattern: skip the 25-byte header, `rmpv::decode::read_value()` on a `Cursor`, match `Value::Map(entries)`. For context pack, decode the full map instead of extracting a single field.

---

## Tests

All tests go in the respective `#[cfg(test)] mod tests` blocks within each file.

### context_pack.rs tests

1. **Basic hydration**: Insert 3 entities (different types, with msgpack payloads), run context pack query with text search, verify `ContextEntity` fields populated (short_id, content_hash, entity_type, fields decoded)

2. **Edge inclusion**: Insert entity + edges, run with `include_edges(true)`, verify `EdgeInfo` in result

3. **Edge hop neighbors**: Insert A→B→C chain, run with `edge_hop(1)` from query returning A, verify B in neighbors but C not. With `edge_hop(2)`, verify both B and C.

4. **max_neighbors cap**: Insert entity with 100 outbound edges, run with `max_neighbors(10)`, verify at most 10 neighbors

5. **include_vectors**: Insert entity + vector, run with `include_vectors(true)`, verify vector in result. Without flag, verify vector is None.

6. **Empty results**: Run query with no matches, verify empty ContextPack with zero stats

7. **Score preservation**: Insert scored entities, verify context pack scores match pipeline scores

8. **Missing short_id graceful handling**: Insert entity via raw put (no batch), verify hydration doesn't crash (short_id may be empty/missing)

### serialize.rs tests

1. **JSON round-trip**: Serialize to JSON, parse back with serde_json, verify structure

2. **TOON format**: Serialize, verify `claims[` header prefix, tabular `{id,pred,val,...}:` field list, comma-delimited data rows

3. **Markdown format**: Serialize, verify `## Claims` header, markdown table separator row `|----|`

4. **Plaintext format**: Serialize, verify `CLAIMS` header, no header row, no spaces around pipes

5. **YAML format**: Serialize, verify `claims:` key, `- id:` list items

6. **Field profile filtering**: Same data serialized with Minimal vs Full, verify Minimal has fewer fields

7. **Token budget enforcement**: Set budget to 100 tokens, verify output is truncated (fewer entities)

8. **Empty groups omitted**: No claims in result, verify `claims[` not present in TOON output, `## Claims` not in Markdown

9. **Relative timestamps**: Verify timestamp formatting (-3d, -1w, etc.)

10. **Short ID format**: Verify output contains `cl88:f2` style IDs (short_id + colon + hex hash)

11. **Entity type grouping order**: Claims before turns before summaries in output

12. **Pipe escaping**: Entity with pipe char in a field value, verify proper escaping per format

### Integration test (in lib.rs tests)

1. **End-to-end**: Insert entities with text + vectors + edges + timestamps, use `vault.context_pack().search_text("query", 10).format(PackFormat::Toon).run_serialized()`, verify non-empty output

---

## Bugs to Avoid

1. **Do NOT open write transactions** in context_pack.rs — this is read-only. Only `RoTxn`.

2. **Skip missing entities gracefully** — entity blobs can be deleted between pipeline run and hydration. Skip, don't error.

3. **Short IDs may not exist** for entities created via raw `put_entity` without going through batch. Handle `None` from short_ids lookup (use entity ID hex as fallback).

4. **Msgpack payloads may be empty** — entity blob may be just the 25-byte header with no msgpack. Handle gracefully (empty fields map).

5. **Entity type byte range**: valid 0-11 per `short_id_prefix()`. Unknown types (>11) should still work (use "xx" prefix, include all fields).

6. **Edge values are 12 bytes**: `weight(f32 LE, 4B) + created_at(u64 LE, 8B)`. Don't mix up endianness — weights are little-endian f32, timestamps are little-endian u64.

7. **Don't allocate vectors unless requested** — `include_vectors` is false by default. Skip the `vectors` db read entirely when false.

8. **Token budget 0 means unlimited** — if budget is 0 or very large, skip truncation.

9. **`rmpv::decode::read_value` can fail** on corrupt msgpack — wrap in `.ok()` and skip entity rather than propagating error.

10. **Neighbor deduplication**: When walking edges for neighbors, a neighbor may appear in multiple paths. Use `HashSet` to dedup. Also exclude entities already in the main result set from neighbors.

---

## Module visibility and re-exports

In `lib.rs`:

```rust
pub mod context_pack;
pub mod serialize;

// Add to the existing re-export block:
pub use crate::context_pack::ContextPackBuilder;
pub use crate::types::{
    ContextEntity, ContextPack, EdgeInfo, PackStats, SignalHit, TokenAllocation,
};
```

Make both `context_pack` and `serialize` modules public. Users may want to re-serialize a `ContextPack` in a different format after initial retrieval.
