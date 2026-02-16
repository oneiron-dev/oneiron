# Temporal Scoring Specification — Oneiron Crate

**Status:** Revised after external review (v3)
**Scope:** `execute_temporal()` in `pipeline.rs` (Task 6)
**Author:** Design discussion, Feb 2026
**Revision history:**
- v1: Initial formula (linear cutoff, single proximity, fixed α)
- v2: Interval distance, σ-driven discovery, TemporalAnchorMode, dynamic α, bidirectional scan, adaptive widening, temporal contiguity boost
- v3: Normalized noisy-OR (Auto mode), Both anchor mode, spanner interval index, contiguity improvements (axis-aware + clamped + gated), σ clamp fix, future events support, considered alternatives appendix
- v3.1: Floor-preserving Both mode (normalized-space product), noisy-OR defensive clamp, overlap tie-break, abs_diff α for future anchors, true-spanner filter, spanner value stores bounds, adaptive widening skip-when-unchanged, underflow guards, recency double-counting docs

---

## 1. Problem

An entity in Oneiron has two temporal anchors (bitemporal model):

| Field | Meaning | Stored as | Bitemporal analog |
|---|---|---|---|
| `occurred_start` / `occurred_end` | When the real-world event happened (or is scheduled to happen) | u64 BE in entity header bytes 1..17 | **Valid time** |
| `learned_at` | When the entity was recorded into the system | u64 BE in entity header bytes 17..25 | **Transaction time** |

**Relationship between timestamps:** Typically `learned_at >= occurred_start` (events are recorded after they happen). However, for future-scheduled entities (calendar events, plans, commitments, habit experiments), `learned_at < occurred_start` is expected and handled correctly — the scoring functions work symmetrically on unsigned distances. For `anchor_age` calculation, we use `abs_diff(now, anchor_end)` — symmetric distance regardless of past/future direction. Near-future anchors get α ≈ 0.72 (recency mostly active), while far-future anchors (e.g., 2027) gradually suppress recency, matching the behavior for far-past anchors.

A query arrives with an anchor time range `[anchor_start, anchor_end]`. The scoring function must answer: **how temporally relevant is this entity to the query?**

### Why this is non-trivial

| Query | Entity | Naive scoring | Problem |
|---|---|---|---|
| "What happened 5 years ago?" | occurred=5y ago, learned=5y ago | High | Works |
| "What happened 5 years ago?" | occurred=5y ago, learned=yesterday | High | Works |
| "What did I tell you last March?" | occurred=10y ago, learned=last March | **Floor** | Entity told near query time but occurred long ago — missed |
| "Remember that old trip?" (vague) | occurred=8y ago, learned=3y ago | **Floor** if query defaults to "now" | Old memories should still be retrievable |
| "What happened last March?" | occurred=10y ago, learned=last March | **High** (false positive in Auto mode) | Entity was _told_ last March, not _happened_ — needs anchor intent |
| "What did I know in March about 2016?" | occurred=2016, learned=March 2025 | Needs **both axes** to match | Neither single-axis mode captures this; requires constrained bitemporal query |

The third case is the critical gap: the user is asking about **when they told the system**, not when the event occurred. A single-timestamp proximity score cannot serve both intents.

The fifth case shows why **TemporalAnchorMode** matters: without intent disambiguation, Auto mode trades precision for recall.

The sixth case motivates **Both** mode: constrained queries where both temporal axes must match.

---

## 2. Literature Survey

We surveyed 11+ papers for temporal scoring approaches. Key findings:

| Paper | Timestamps | Scoring | Limitation |
|---|---|---|---|
| **MemoTime** (2025) | Event time only | `exp(-\|t_event - t_query\| / σ)` — proximity to query | No recency signal; no learned-time awareness |
| **Hindsight** (2025) | `tau_s/tau_e` (occurred), `tau_m` (mentioned) | `tau_m` used for graph link weights; `tau_s/tau_e` for date-range retrieval (interval overlap) | `tau_m` never scored against query time |
| **Mnemosyne** (2025) | Effective age (access-adjusted) | Sigmoid with floor=0.05: `τ(e_eff) = (1-d)/(1+exp((e_eff-a)/b)) + d` | Decay from now only; no proximity to query time |
| **MemoryBank** (2024) | Time since learning | Ebbinghaus: `R = e^(-t/S)`, S++ on recall | Recency from now only; no query-time awareness |
| **SynapticRAG** (2024) | Temporal association | Sigmoid-normalized temporal score, leaky integrate-and-fire decay | Complex propagation model; not bitemporal |
| TiMem, ENGRAM, EcphoryRAG, A-Mem, AgeMem, EverMemOS, EM-LLM | Timestamps as metadata | No temporal scoring formula | Rely on LLM to interpret timestamps in context |

**Key observations:**
- Only Hindsight stores both occurred and learned timestamps; nobody scores both against the query
- Hindsight uses **interval overlap filtering** then **midpoint proximity scoring** for temporal constraints (Eq. 13/14 in paper)
- Proximity-to-query (MemoTime) and recency-from-now (MemoryBank/Mnemosyne) are treated as separate approaches
- No existing system combines both timestamps into a unified proximity score
- EM-LLM uses **temporal contiguity** as a retrieval primitive (co-occurring memories reinforce each other)
- SynapticRAG demonstrates that sigmoid normalization is a common choice for temporal scores
- The bitemporal data model (valid-time vs transaction-time) is well-established in database literature and maps directly to our occurred/learned split

---

## 3. Proposed Formula

### Interval distance functions

Replaces midpoint-to-midpoint distance. Handles range queries, long events, and future events correctly.

```
interval_distance([a, b], [c, d]) =
    0       if max(a, c) <= min(b, d)    // intervals overlap
    c - b   if b < c                      // [a,b] entirely before [c,d]
    a - d   if d < a                      // [a,b] entirely after [c,d]

point_interval_distance(p, [c, d]) =
    0       if c <= p && p <= d           // point inside interval
    c - p   if p < c                      // point before interval
    p - d   if p > d                      // point after interval
```

Both return unsigned distances in seconds. O(1) per entity.

**Why not midpoint distance:** An event spanning Feb 1-28 queried with "mid February" (Feb 10-20) has midpoint distance ~0, which is correct. But an event spanning Jan 1 - Mar 31 queried with "late March" has a midpoint (mid-Feb) far from the query, even though the event **overlaps** the query range. Interval distance returns 0 for overlap — correct.

### Overlap tie-break

When `interval_distance = 0` (overlap), many entities can share the same sigmoid score (~0.983). For month/year queries this can produce hundreds of tied candidates, making temporal ordering feel arbitrary. To provide stable, meaningful ranking within the overlap bucket:

```
tie_break_distance = |midpoint(entity_occurred) - midpoint(anchor)|
```

Midpoint distance is safe as a **secondary sort key** (not the primary metric). Entities closest to the anchor center rank higher among the tied-at-zero set. This is applied during the final sort of temporal candidates (step 5 in execute_temporal), not during the sigmoid scoring itself.

### Sigmoid function

```
sigmoid(distance, σ, floor) = (1.0 - floor) / (1.0 + exp((distance - σ) / (σ / 4.0))) + floor
```

Where:
- `distance` = interval distance in seconds (from functions above)
- `σ` = decay midpoint in seconds (controls where steep dropoff happens)
- `σ / 4.0` = steepness (scales with σ for consistent shape across granularities)
- `floor` = 0.05

Behavior:
- At `distance = 0`: score ≈ **0.983** (`(1-0.05)/(1+exp(-4)) + 0.05 = 0.95/1.018 + 0.05`)
- At `distance = σ`: score ≈ 0.525 (midpoint of sigmoid)
- At `distance = 2σ`: score ≈ 0.068
- At `distance = 3σ`: score ≈ 0.050 (effectively floor)
- At `distance >> σ`: score → floor (0.05)

### Three components

```
d_occ = interval_distance([occurred_start, occurred_end], [anchor_start, anchor_end])
d_lrn = point_interval_distance(learned_at, [anchor_start, anchor_end])

s_occ_prox = sigmoid(d_occ, σ, 0.05)
s_lrn_prox = sigmoid(d_lrn, σ, 0.05)
```

For **Both** mode, `d_lrn` uses a separate learned anchor range:
```
d_lrn = point_interval_distance(learned_at, [learned_anchor_start, learned_anchor_end])
```

### Anchor mode gating

```
match anchor_mode {
    Occurred => s_proximity = s_occ_prox,
    Learned  => s_proximity = s_lrn_prox,
    Both     => {
        // Floor-preserving product: soft AND in normalized space
        let s_occ_net = ((s_occ_prox - floor) / (1.0 - floor)).clamp(0.0, 1.0)
        let s_lrn_net = ((s_lrn_prox - floor) / (1.0 - floor)).clamp(0.0, 1.0)
        let s_prox_net = s_occ_net × s_lrn_net
        s_proximity = s_prox_net × (1.0 - floor) + floor
    }
    Auto     => {
        // Normalized noisy-OR: P(at least one axis matches)
        let s_occ_net = ((s_occ_prox - floor) / (1.0 - floor)).clamp(0.0, 1.0)
        let s_lrn_net = ((s_lrn_prox - floor) / (1.0 - floor)).clamp(0.0, 1.0)
        let s_prox_net = 1.0 - (1.0 - s_occ_net) × (1.0 - s_lrn_net)
        s_proximity = s_prox_net × (1.0 - floor) + floor
    }
}
```

**Defensive clamp:** The `.clamp(0.0, 1.0)` on net values prevents float drift from producing values outside [0,1] after normalization. Without this, tiny floating-point errors could violate noisy-OR/product assumptions.

### Recency with dynamic α

```
s_recency = exp(-(now - learned_at) / λ)

// Dynamic α: historical/far-future queries suppress recency, near-now queries keep it
anchor_age = abs_diff(now, anchor_end)   // symmetric: past and future treated equally
α = 0.7 + 0.3 × (1.0 - exp(-(anchor_age as f64) / (90.0 × 86400.0)))

s_temporal = α × s_proximity + (1.0 - α) × s_recency
```

Where `abs_diff(a, b) = if a >= b { a - b } else { b - a }` (safe unsigned subtraction).

Dynamic α behavior:
- Query is "now" (`anchor_age = 0`): **α = 0.70** — recency gets 30% weight
- Query is 1 month ago (or 1 month in future): **α ≈ 0.80** — recency fading
- Query is 3 months ago (or 3 months ahead): **α ≈ 0.89** — recency mostly irrelevant
- Query is 1+ year ago (or 1+ year ahead): **α ≈ 1.00** — pure proximity, recency completely suppressed

**Why abs_diff, not saturating_sub:** With `saturating_sub`, ALL future anchors yield `anchor_age = 0` → α = 0.70, meaning "meeting in 2027" gets the same recency treatment as "meeting next week." With `abs_diff`, far-future anchors suppress recency just like far-past anchors — only proximity to the anchor matters. Near-future (next week) still gets α ≈ 0.72 — recency active, appropriate for "what's coming up?"

**Rationale:** Fixed α=0.7 penalizes historical queries. "What happened 5 years ago?" shouldn't care about recency. Dynamic α, gated by `abs_diff(now, anchor_end)`, naturally suppresses recency for explicitly past-anchored OR far-future-anchored queries while keeping it active for near-now queries. The 90-day transition timescale means queries within ~3 months of now get meaningful recency weight; beyond that, proximity dominates.

For **Both** mode, `anchor_age` uses the occurred anchor (`abs_diff(now, anchor_end)`) since that represents the "when did it happen?" dimension.

**Recency auto-skip:** The pipeline also offers a post-RRF `boost_recency` (exponential decay by half-life). If any temporal search is configured on the pipeline, `boost_recency` is a **silent no-op** — temporal search already includes recency via `s_recency` weighted by dynamic α. The `boost_recency()` builder method still accepts the call (for API ergonomics) but skips execution when temporal search is present.

### TemporalAnchorMode

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum TemporalAnchorMode {
    /// Query refers to when events happened: "what happened last March?"
    Occurred,
    /// Query refers to when information was recorded: "what did I tell you last March?"
    Learned,
    /// Constrained bitemporal: both axes must match.
    /// "What did I know in March 2025 about events from 2016?"
    Both,
    /// Ambiguous — score both axes via noisy-OR, never penalizes divergence
    #[default]
    Auto,
}
```

**Precision/recall contract per mode:**
- **Occurred** = precision for "happened" queries. Only scores occurred axis. Rejects entities that merely match on learned time.
- **Learned** = precision for "told/mentioned" queries. Only scores learned axis. Rejects entities that merely match on occurred time.
- **Both** = precision for constrained bitemporal queries. Floor-preserving product (soft AND in normalized space): both axes must match for a high score. If either axis is at floor, output is floor. Range: [floor, ~1.0].
- **Auto** = recall-maximizing. Accepts false positives from either axis in exchange for never missing matches on either axis.

**With upstream intent signal:** Caller passes `Occurred`, `Learned`, or `Both` from NER/classifier/heuristic. Scoring uses only the relevant axis/axes. Precision is tight — the false positive case (row 5 in Problem table) is eliminated.

**Without intent signal:** Default `Auto`. Both axes scored via noisy-OR. Accepts the false positive tradeoff in exchange for never missing the learned-proximity case.

The crate provides the knobs. Upstream decides how to set them (NER, regex heuristic, user toggle — not our business).

### Constants

| Symbol | Value | Rationale |
|---|---|---|
| `floor` | 0.05 | Old memories never score zero (Mnemosyne principle) |
| `λ` | 28 × 86400 s (28 days) | Exponential time constant: `exp(-t/λ)` gives 1/e ≈ 0.368 at 28 days. Note: Mnemosyne uses a ~4-week parameter as a sigmoid midpoint in its decay curve, and also frames ~28 days as a "memory half-life" in its recency component. We adopt the 28-day timescale but as an exponential time constant (1/e at 28d), not a half-life (0.5 at 28d). This gives slightly faster decay than a half-life interpretation, appropriate since s_recency is modulated by dynamic α. |
| `α` | 0.7 base, dynamic up to 1.0 | Proximity dominates; recency fades for historical queries |
| `90 × 86400` | α transition timescale | ~3 months: queries within ~3 months of now get meaningful recency; beyond that, proximity dominates |

---

## 4. Why Normalized Noisy-OR (Auto Mode)

### The design problem

In Auto mode, we don't know which temporal axis the user cares about. We need a fusion formula that:
1. Never penalizes divergence (old event told recently should score high on the matching axis)
2. Rewards agreement (both axes matching is stronger evidence of temporal relevance)
3. Stays in [floor, ~1.0] — clean probability interpretation
4. Has no arbitrary tuning constants

### Chosen: Normalized noisy-OR

```
s_occ_net = (s_occ_prox - floor) / (1.0 - floor)    // normalize to [0, 1]
s_lrn_net = (s_lrn_prox - floor) / (1.0 - floor)
s_prox_net = 1.0 - (1.0 - s_occ_net) × (1.0 - s_lrn_net)  // noisy-OR
s_proximity = s_prox_net × (1.0 - floor) + floor     // re-add floor
```

**Interpretation:** "Probability that at least one temporal axis is a good match." The normalization step removes the floor before applying noisy-OR (preventing floor-lifting), then re-adds it after.

**Behavior:**

| Scenario | s_occ | s_lrn | s_proximity | Interpretation |
|---|---|---|---|---|
| Both at floor | 0.05 | 0.05 | **0.050** | No temporal match — floor preserved exactly |
| Divergent (high/floor) | 0.983 | 0.05 | **0.983** | One axis matches — same as single-axis |
| Moderate agreement | 0.50 | 0.50 | **0.737** | Both axes moderately match — boosted |
| Strong agreement | 0.983 | 0.983 | **0.999** | Both axes agree — near-maximum |

Range: `[floor, ~1.0]` — valid probability, never exceeds 1.0.

### Considered alternatives

| Approach | Formula | Range | Divergent (0.983, 0.05) | Aligned (0.983, 0.983) | Issue |
|---|---|---|---|---|---|
| **Single proximity (v1)** | `sigmoid(d_occ)` | [floor, 0.983] | **Misses learned-axis** | N/A | "What did I tell you?" returns floor |
| **Weighted sum** | `w₁·s_occ + w₂·s_lrn` | [floor, 0.983] | 0.37 (penalized) | 0.983 | Penalty largest in the divergent case — the case we need to fix |
| **Pure max** | `max(s_occ, s_lrn)` | [floor, 0.983] | 0.983 (correct) | 0.983 (no tiebreak) | Loses agreement signal — identical max can't be distinguished |
| **max + bonus** | `max + 0.1·min` | [0.055, 1.08] | 0.988 | 1.081 | Exceeds 1.0; arbitrary 0.1 constant; lifts floor-floor to 0.055 |
| **max + bonus (floor-adjusted)** | `max + 0.1·(min-floor)` | [floor, 1.076] | 0.983 | 1.076 | Still exceeds 1.0; still has 0.1 constant |
| **Raw noisy-OR** | `1-(1-a)(1-b)` | [0.098, 1.0] | 0.984 | 1.0 | Lifts floor-floor to 0.098 |
| **Normalized noisy-OR** ✓ | See above | [floor, ~1.0] | 0.983 | 0.999 | **Chosen**: clean range, no floor lift, no constants, probabilistic |
| **Lexicographic sort** | `sort by (max, min)` | N/A | N/A | N/A | Doesn't produce scalar for α blending |

**Why not max + bonus (v2 approach):** The v2 spec used `max + 0.1 × min`. This works but (a) exceeds 1.0, (b) has an arbitrary constant (0.1 — why not 0.05 or 0.2?), and (c) slightly lifts floor-floor pairs. Normalized noisy-OR eliminates all three issues while preserving the core properties: no divergence penalty, agreement rewarded.

**Why not raw noisy-OR:** Without normalization, `1 - (1-0.05)(1-0.05) = 0.098` — the floor-floor case lifts to nearly 2× floor. The normalization step prevents this.

**A note on tiebreaking behavior:** Noisy-OR and max+bonus differ in one subtle case — "balanced moderate" (both at 0.5) vs "strong one-axis" (one at 0.7, other at floor). Noisy-OR ranks balanced higher (0.737 > 0.700); max+bonus ranks strong-axis higher (0.55 < 0.705). In Auto mode (ambiguous intent), the balanced entity IS arguably a better temporal match — it's reasonably close on both possible interpretations. When we DO know the intent (Occurred/Learned modes), we only use one axis, so this doesn't apply.

---

## 5. Candidate Discovery

### σ-driven window

```
range_width  = anchor_end - anchor_start           (fallback: 86400 if zero)
sigma        = if sigma_secs == 0 { 86400 } else { sigma_secs }
radius       = max(2 × range_width, 3 × sigma, 7 × 86400)
window_start = anchor_start.saturating_sub(radius)
window_end   = anchor_end.saturating_add(radius)
per_scan_cap = limit × 4
```

**σ clamping:** Only zero is special-cased (defaults to 1 day). Non-zero σ values are used as-is, including sub-day values like `Exact` (3600s) and `Hour` (14400s). The `7 × 86400` floor in radius already guarantees a minimum scan window regardless of σ.

**Why `3σ`:** At distance = 3σ, the sigmoid is deep in the floor (`exp((3σ-σ)/(σ/4)) = exp(8)`, denominator ≈ 2981, score ≈ floor). Anything beyond 3σ scores ≈ floor regardless, so not discovering it is acceptable.

**Critical:** σ must drive the radius, not just range_width. A point anchor (`anchor_start == anchor_end`) with `TemporalGranularity::Year` (σ=180d) would produce radius=7d without σ-awareness — completely wrong. With σ-awareness: radius = max(2×1d, 3×180d, 7d) = 540d. Correct.

### Three index scans with per-scan caps

Each scan gets its own `per_scan_cap` to prevent index starvation:

1. **`temporal_occurred_start`** — entities whose `occurred_start` falls in `[window_start, window_end]`
2. **`temporal_occurred_end`** — entities whose `occurred_end` falls in `[window_start, window_end]`. Catches long events that started before the window but end inside it.
3. **`temporal_learned`** — entities whose `learned_at` falls in `[window_start, window_end]`

After all scans, merge into a single deduplicated candidate set.

**Anchor mode optimization:**
- `Occurred` mode: scan only indexes 1 + 2 (skip learned)
- `Learned` mode: scan only index 3 (skip occurred)
- `Auto` mode: scan all three
- `Both` mode: scan all three. Occurred indexes use the occurred window; learned index uses a separate window computed from `[learned_anchor_start, learned_anchor_end]` ± radius.

### Bidirectional scan from anchor

For each index, instead of scanning forward from `window_start` (which biases toward earliest timestamps under the cap):

1. Compute `anchor_mid = midpoint(anchor_start, anchor_end)` using overflow-safe formula
2. Seek to `encode_temporal_key(anchor_mid, [0x00; 16])`
3. Open two iterators: one forward (ascending), one backward (descending)
4. Alternate: take one from forward, one from backward
5. Stop when both iterators exit `[window_start, window_end]` or `per_scan_cap` reached

This ensures **closest-to-anchor** candidates are collected first. Under `per_scan_cap` with large windows (Year/Vague granularity), forward-only scan would fill the cap with timestamps far from the anchor, missing the good candidates near it.

### Spanner interval discovery (long-interval side index)

**Problem:** Entities whose occurred interval fully contains the query window are invisible to start/end scans — neither `occurred_start` nor `occurred_end` falls within the scan window. Example: an entity `occurred=[2010, 2030]` queried at `[2025-03, 2025-03]` has interval distance 0 (overlap) but is missed by all three index scans.

**Affected entity types:** CLAIMs with long `validFrom/validTo` (e.g., "user is a software engineer"), RELATIONSHIPs (ongoing), SKILLs (persistent), long EVENTs (multi-month projects).

**Solution:**

```
LONG_INTERVAL_THRESHOLD = 14 × 86400   // 14 days

New database: temporal_long_intervals
    Key: entity_id (16 bytes)
    Value: [occurred_start(8 BE) | occurred_end(8 BE)]  (16 bytes)
```

**Write path:** On entity put, if `occurred_end.saturating_sub(occurred_start) > LONG_INTERVAL_THRESHOLD`, insert entity_id with `[occurred_start(8 BE) | occurred_end(8 BE)]` value into `temporal_long_intervals`. On entity delete, always remove (harmless if absent). Note: `saturating_sub` guards against malformed entities where `start > end` — these produce 0, safely excluded from the index.

**Input validation at ingest:** `put_entity` should enforce `occurred_start <= occurred_end`. If `start > end`, swap them before storing. This is defense-in-depth — the temporal indexes and scoring functions use `saturating_sub` throughout, but preventing malformed data at the source is cleaner.

**Read path:** After the three bidirectional scans and deduplication, scan `temporal_long_intervals`. For each entry, read the `[occurred_start, occurred_end]` directly from the value (no entity header fetch needed). Apply **true-spanner filter**: only add entities where `occurred_start < window_start AND occurred_end > window_end` — these are the entities invisible to start/end scans because neither timestamp falls within the window. Dedup with existing candidates.

**Anchor mode gating:** Skip the spanner scan entirely in `Learned` mode — the spanner index is occurred-axis only and adds nothing when scoring only against learned timestamps.

**Why true-spanner filter (not any-overlap):** Start/end scans already catch entities with start or end inside the window. The spanner index exists specifically for entities invisible to those scans. Filtering to true spanners (`start < window_start && end > window_end`) avoids redundant candidates and prevents long-lived states from flooding event-like queries under `per_scan_cap`.

**Why 14 days:** The minimum scan radius is 7 days (from the `7 × 86400` floor). A spanner must span more than `2 × radius + range_width` to be invisible. The smallest possible `2 × radius` is 14 days. Setting the threshold at 14 days catches all spanners for all queries.

**Cost:** Personal vault: ~50-500 long-interval entities, scanning values ≈ ~16KB, <1ms. B2B vault with 100K entities: maybe 5-10K long intervals, <5ms. Acceptable. Storing bounds in the value avoids entity header reads during scan — the overlap check uses the value directly. If the set ever grows too large (>50K), the approach can be replaced with a bucketed overlap index (one key per month-bucket per interval) — see Considered Alternatives (§12).

### Adaptive σ widening

If total unique candidates after all scans (including long-interval scan) < `limit`:

1. `sigma *= 2`
2. Recompute `new_radius = max(2 × range_width, 3 × sigma, 7 × 86400)`
3. **Skip rescan if radius unchanged:** If `new_radius == old_radius` (the 7-day floor dominates), skip the rescan — the same window would produce the same candidates. Still proceed to the next doubling round (σ affects scoring shape even if the window doesn't expand).
4. If radius changed: re-scan with new window bounds (bidirectional from anchor), merge new candidates into existing set (deduplicated)
5. Repeat up to **2 more times** (max 3 rounds total, σ grows to 8× original)

**Why skip unchanged radius:** For small σ (Exact=3600s, Hour=14400s), the radius is dominated by the 7-day floor. Doubling σ from 3600→7200→14400→28800 doesn't change radius at all, making rescans pure waste. The skip check makes widening O(1) for these cases instead of O(3 × scan_cost).

**Controlled by `adaptive` flag (default: `true`):**
- `adaptive = true`: widen on insufficient candidates
- `adaptive = false`: exact mode, no widening. Useful when the caller wants precise temporal filtering and would rather get few results than expand the window.

---

## 6. Sigma Source: Three API Tiers + Bitemporal

### Tier 1: Inferred from range width

```rust
pub fn search_temporal(self, anchor_start: u64, anchor_end: u64, limit: usize) -> Self
```

`σ = max(anchor_end - anchor_start, 86400)`, `anchor_mode = Auto`, `adaptive = true`

### Tier 2: Explicit sigma + anchor mode

```rust
pub fn search_temporal_with_sigma(
    self,
    anchor_start: u64,
    anchor_end: u64,
    sigma_secs: u64,
    anchor_mode: TemporalAnchorMode,
    limit: usize,
) -> Self
```

### Tier 3: Granularity enum + anchor mode

```rust
pub fn search_temporal_with_granularity(
    self,
    anchor_start: u64,
    anchor_end: u64,
    granularity: TemporalGranularity,
    anchor_mode: TemporalAnchorMode,
    limit: usize,
) -> Self
```

`TemporalGranularity` maps to fixed sigma values:

| Variant | Example expression | σ (seconds) |
|---|---|---|
| `Exact` | "at 3:15pm" | 3,600 (1h) |
| `Hour` | "that afternoon" | 14,400 (4h) |
| `Day` | "last Tuesday" | 86,400 (1d) |
| `Week` | "last week" | 604,800 (1w) |
| `Month` | "in March" | 2,592,000 (30d) |
| `Season` | "last summer" | 7,776,000 (90d) |
| `Year` | "5 years ago" | 15,552,000 (180d) |
| `Vague` | "a while back" | 31,536,000 (365d) |

### Tier 4: Bitemporal (Both mode)

```rust
pub fn search_temporal_bitemporal(
    self,
    occurred_start: u64,
    occurred_end: u64,
    learned_start: u64,
    learned_end: u64,
    sigma_secs: u64,
    limit: usize,
) -> Self
```

Sets `anchor_mode = Both`, uses the occurred range as the primary anchor and the learned range as the secondary anchor. Both ranges use the same σ for radius calculation. `adaptive = true` by default.

### Adaptive control

```rust
pub fn temporal_adaptive(self, enabled: bool) -> Self
```

Default: `true`. Set to `false` for exact temporal filtering.

---

## 7. Temporal Contiguity Boost

Post-RRF boost, same pattern as recency/salience/confidence.

### Rationale

Memories that occurred close together in time are often part of the same episode. "Trip to Japan" + "met Yuki" + "ate ramen" all in the same week should mutually reinforce when any one is recalled. EM-LLM uses temporal contiguity as a retrieval primitive; we apply it as a post-fusion boost.

### Gating

Contiguity boost only applies if a temporal search signal was configured in the pipeline. If the query is purely vector+BM25 with no temporal anchor, contiguity has no semantic basis and is skipped.

### Window clamping

The contiguity neighborhood window is capped to prevent overly broad "episodes":

```
σ_contig = min(σ_from_temporal_config, 14 × 86400)  // cap at 2 weeks
```

Without capping, a `Year` query (σ=180d) would treat entities 6 months apart as "contiguous" — not a meaningful episode.

If temporal config is present but sigma is 0 (unset), default σ_contig = 86400 (1 day). If no temporal config exists at all, the boost is skipped entirely (see Gating above).

### Axis-awareness

The contiguity axis matches the anchor mode:

```
match anchor_mode {
    Occurred | Auto | Both => contiguity uses interval_distance on occurred ranges
    Learned                => contiguity uses |learned_a - learned_b| distance
}
```

Auto uses occurred because when intent is ambiguous, co-occurring events are the safer "episode" signal. Learned-mode contiguity captures "conversation bursts" (multiple things told in one session).

### Formula

For each entity `e` in the result set:

```text
neighbors(e) = count of other entities in results where
               distance(e, other) < σ_contig    // axis-aware distance
contiguity   = neighbors / max(result_count - 1, 1)        // 0.0 to 1.0
score       *= 1.0 + 0.2 × contiguity
```

### Algorithm — O(n log n) via sorted-endpoint binary search

The naive O(n²) pairwise comparison is replaced by a sorted-endpoint technique. The key insight is that for interval distance:

```text
interval_distance([s_i, e_i], [s_j, e_j]) < σ
  ⟺  s_j < e_i + σ  AND  e_j > s_i - σ
```

The negation — "j is NOT a neighbor of i" — splits into two **disjoint** cases (disjoint because for valid intervals `s ≤ e`, an interval cannot simultaneously end before `s_i - σ` and start after `e_i + σ`):

```text
too_far_left:   e_j ≤ s_i - σ      (j ends before i's window)
too_far_right:  s_j ≥ e_i + σ      (j starts after i's window)
```

Therefore: `neighbors(i) = (n - 1) - too_left - too_right`

**Algorithm:**

1. Extract timestamps per axis mode:
   - Occurred/Auto/Both: `(s, e) = (occurred_start, occurred_end)` per entity
   - Learned: `(s, e) = (learned_at, learned_at)` — point intervals
2. Sort two arrays: `sorted_starts` (all `s` values, ascending) and `sorted_ends` (all `e` values, ascending) — **O(n log n)**
3. For each entity i, compute neighbor count via two binary searches — **O(log n)** each:

```rust
// Use checked arithmetic to handle u64 boundaries correctly.
// If s_i < σ, s_i - σ is negative → no interval can be "too far left" → 0.
// If e_i + σ overflows u64 → no interval can be "too far right" → 0.
let too_left = match s_i.checked_sub(sigma_contig) {
    Some(threshold) => sorted_ends.partition_point(|&ej| ej <= threshold),
    None => 0,
};
let too_right = match e_i.checked_add(sigma_contig) {
    Some(threshold) => n - sorted_starts.partition_point(|&sj| sj < threshold),
    None => 0,
};

let neighbors = (n - 1).saturating_sub(too_left + too_right);
```

**Why `checked_*` not `saturating_*`:** `saturating_sub` gives 0 when the true result is negative, which would wrongly classify intervals ending at timestamp 0 as "too far left." `checked_sub` returns `None` on underflow, letting us correctly set `too_left = 0` (nothing is too far left). Symmetric reasoning for `checked_add` at the u64::MAX boundary.

**Self-exclusion correctness:** Entity i always has `e_i > s_i - σ` and `s_i < e_i + σ` (when σ > 0), so self is never counted in too_left or too_right. The `n - 1` subtracts self from the total.

**Total complexity:** O(n log n) for sorts + O(n log n) for 2n binary searches = **O(n log n)**.

For Learned mode, `s = e = learned_at` simplifies to point-distance binary search but uses the same code path.

### API

```rust
pub fn boost_contiguity(self) -> Self;
```

### Examples

- 5 entities from the same week, σ_contig=86400: each has ~4 neighbors → contiguity ≈ 1.0 → score ×1.2
- 1 isolated entity among 20 results: neighbors=0 → contiguity=0 → no boost
- Mixed: 3 entities from trip week + 17 others scattered → trip entities get ~0.1-0.15 contiguity → score ×1.02-1.03
- Learned mode: 5 entities all told in one conversation session → learned-axis contiguity ≈ 1.0 → score ×1.2

**Tuning note:** The 0.2 multiplier is a starting point. Task 9 benchmarks will evaluate this against real data.

### Considered alternatives for contiguity

- **Additive** (`score += β·contiguity`): avoids disproportionate boost for already-strong items. Rejected because we specifically want "already good + temporally clustered = even better" — proportional boosting is the right semantic.
- **No contiguity**: simpler. Rejected because episode-coherent retrieval is a real product need (trip memories, conversation bursts). EM-LLM validates the concept.
- **Ungated** (apply always): risk of biasing non-temporal queries toward time clusters. Rejected in favor of gating behind temporal search configuration.

---

## 8. Worked Examples

### Example 1: Recent event, recorded at the time (Auto mode)

```
Query:   [2026-02-10 12:00, 2026-02-10 12:00] (point query)
Entity:  occurred=[2026-02-10 14:00, 2026-02-10 15:00], learned_at=2026-02-10 14:30
Now:     2026-02-16
σ = 86400 (1 day, Tier 1 inferred from point → fallback)

d_occ = interval_distance([14:00, 15:00], [12:00, 12:00])
      = 14:00 - 12:00 = 7200s  (entity starts 2h after query point, no overlap)

d_lrn = point_interval_distance(14:30, [12:00, 12:00])
      = 14:30 - 12:00 = 9000s  (2.5h after)

s_occ_prox = 0.95 / (1 + exp((7200 - 86400) / 21600)) + 0.05 ≈ 0.976
s_lrn_prox = 0.95 / (1 + exp((9000 - 86400) / 21600)) + 0.05 ≈ 0.974

Auto (noisy-OR):
  s_occ_net = (0.976 - 0.05) / 0.95 = 0.975
  s_lrn_net = (0.974 - 0.05) / 0.95 = 0.973
  s_prox_net = 1 - (1 - 0.975)(1 - 0.973) = 1 - 0.025 × 0.027 = 0.999
  s_proximity = 0.999 × 0.95 + 0.05 = 0.999

anchor_age = 2026-02-16 - 2026-02-10 = 6d = 518400s
α = 0.7 + 0.3 × (1 - exp(-518400 / 7776000)) = 0.7 + 0.019 = 0.719

s_recency = exp(-(6 × 86400) / (28 × 86400)) = exp(-0.214) ≈ 0.807

s_temporal = 0.719 × 0.999 + 0.281 × 0.807 = 0.718 + 0.227 = 0.945
```

High score. Both timestamps agree, noisy-OR pushes proximity to 0.999. α near 0.7 because query is recent.

### Example 2: "What happened 5 years ago?" (Auto mode, Year granularity)

```
Query:   [2021-02-16, 2021-02-16] (point, Tier 3: Year → σ = 15,552,000s)
Entity:  occurred=[2021-02-18, 2021-02-22] (trip week), learned_at=2026-02-15 (told yesterday)
Now:     2026-02-16

d_occ = interval_distance([2021-02-18, 2021-02-22], [2021-02-16, 2021-02-16])
      = 2021-02-18 - 2021-02-16 = 172800s (2 days, no overlap)

d_lrn = point_interval_distance(2026-02-15, [2021-02-16, 2021-02-16])
      = 2026-02-15 - 2021-02-16 ≈ 157,680,000s (5 years)

s_occ_prox = 0.95 / (1 + exp((172800 - 15552000) / 3888000)) + 0.05 ≈ 0.982
s_lrn_prox ≈ 0.05 (floor — 5 years away with σ = 180 days)

Auto (noisy-OR):
  s_occ_net = (0.982 - 0.05) / 0.95 = 0.981
  s_lrn_net = 0.0  (at floor → net = 0)
  s_prox_net = 1 - (1 - 0.981)(1 - 0.0) = 0.981
  s_proximity = 0.981 × 0.95 + 0.05 = 0.982

anchor_age ≈ 5 years ≈ 157,680,000s
α = 0.7 + 0.3 × (1 - exp(-157680000 / 7776000)) ≈ 1.000

s_recency = exp(-(1 × 86400) / (28 × 86400)) ≈ 0.965

s_temporal = 1.0 × 0.982 + 0.0 × 0.965 = 0.982
```

Dynamic α pushed to 1.0 — query is 5 years in the past, recency is irrelevant. Noisy-OR with one axis at floor degrades gracefully to the max value. Correct behavior.

### Example 3: "What did I tell you last March?" (Auto vs Learned mode)

```
Query:   [2025-03-01, 2025-03-31] (month range), σ = Month = 2,592,000s
Entity:  occurred=[2016-06-01, 2016-06-15] (old trip), learned_at = 2025-03-20
Now:     2026-02-16

d_occ = interval_distance([2016-06-01, 2016-06-15], [2025-03-01, 2025-03-31])
      = 2025-03-01 - 2016-06-15 ≈ 276,048,000s (no overlap, huge gap)

d_lrn = point_interval_distance(2025-03-20, [2025-03-01, 2025-03-31])
      = 0  ← learned_at falls WITHIN query range!

s_occ_prox ≈ 0.05 (floor)
s_lrn_prox = sigmoid(0, 2592000, 0.05) ≈ 0.983

Auto (noisy-OR):
  s_occ_net = 0.0
  s_lrn_net = (0.983 - 0.05) / 0.95 = 0.982
  s_prox_net = 1 - (1 - 0.0)(1 - 0.982) = 0.982
  s_proximity = 0.982 × 0.95 + 0.05 = 0.983

Learned: s_proximity = 0.983

anchor_age = 2026-02-16 - 2025-03-31 ≈ 322 days ≈ 27,820,800s
α = 0.7 + 0.3 × (1 - exp(-27820800 / 7776000)) = 0.7 + 0.292 = 0.992

s_recency = exp(-(322 × 86400) / (28 × 86400)) = exp(-11.5) ≈ 0.00001

Auto:    s_temporal = 0.992 × 0.983 + 0.008 × 0.00001 ≈ 0.975
Learned: s_temporal = 0.992 × 0.983 + 0.008 × 0.00001 ≈ 0.975
```

**Key improvements from v1 spec:**
- `d_lrn = 0` because learned_at falls within query range (interval distance). v1 used midpoint distance → 432,000s.
- `α ≈ 0.99` because query is ~11 months ago → recency irrelevant. v1 used fixed α=0.7.
- **Final score ≈ 0.975** vs v1's **0.680**. Massive improvement.

**Without s_lrn_prox** (original single-proximity): s_temporal = 0.992 × 0.05 ≈ **0.050** — dead.

### Example 4: False positive case — anchor mode matters

```
Query:   "What happened last March?"
         [2025-03-01, 2025-03-31], σ = Month, anchor_mode varies
Entity:  occurred=[2016-06-01, 2016-06-15], learned_at=2025-03-20
         (User told the bot about their 2016 trip in March 2025)

This entity did NOT happen last March. It was TOLD last March.

Auto mode:     s_temporal ≈ 0.975  ← FALSE POSITIVE for "what happened"
Occurred mode: s_proximity = s_occ_prox = 0.05 → s_temporal ≈ 0.050  ← correctly rejected
Learned mode:  s_proximity = s_lrn_prox = 0.983 → s_temporal ≈ 0.975  ← correctly high
Both mode:     occ_net=0.0, lrn_net=0.981 → prox_net=0.0 → s_proximity = 0.050  ← correctly rejected (floor-preserved)
```

This demonstrates why TemporalAnchorMode matters:
- **Auto** accepts this false positive for recall (better than missing "what did I tell you" queries)
- **Occurred** rejects it for precision (when upstream knows the intent)
- **Learned** correctly ranks it high (when upstream knows the intent)
- **Both** rejects it (entity doesn't match on occurred axis)

### Example 5: Constrained bitemporal — Both mode

```
Query occurred:  [2016-01-01, 2016-12-31] ("events from 2016")
Query learned:   [2025-03-01, 2025-03-31] ("that I told you in March 2025")
σ = Month = 2,592,000s
Now: 2026-02-16

Entity A: occurred=[2016-06-01, 2016-06-15], learned_at=2025-03-20
  d_occ = 0 (occurred within query occurred range — overlap)
  d_lrn = 0 (learned_at within query learned range)
  s_occ_prox ≈ 0.983, s_lrn_prox ≈ 0.983
  Both (normalized-space product):
    occ_net = (0.983 - 0.05) / 0.95 = 0.981
    lrn_net = (0.983 - 0.05) / 0.95 = 0.981
    prox_net = 0.981 × 0.981 = 0.962
    s_proximity = 0.962 × 0.95 + 0.05 = 0.964
  α ≈ 1.0 (occurred anchor is 9+ years ago)
  s_temporal = 1.0 × 0.964 = 0.964  ← strong match on both axes

Entity B: occurred=[2016-06-01, 2016-06-15], learned_at=2026-02-10
  d_occ = 0 (same as A)
  d_lrn = point_interval_distance(2026-02-10, [2025-03-01, 2025-03-31])
        = 2026-02-10 - 2025-03-31 ≈ 316 days ≈ 27,302,400s
  s_occ_prox ≈ 0.983, s_lrn_prox ≈ 0.05 (floor — far from learned anchor)
  Both (normalized-space product):
    occ_net = 0.981, lrn_net = 0.0
    prox_net = 0.981 × 0.0 = 0.0
    s_proximity = 0.0 × 0.95 + 0.05 = 0.050  (exactly floor)
  s_temporal ≈ 0.050  ← correctly rejected (wrong learned time, floor-preserved)
```

Both mode correctly finds Entity A (matched on both axes) and rejects Entity B (only matched on occurred). This enables queries like "tell me about what you learned in March 2025 regarding 2016 events."

### Example 6: Future event (calendar event)

```
Query:   "What's coming up next week?"
         [2026-02-23, 2026-03-01], σ = Week = 604,800s
Entity:  occurred=[2026-02-25, 2026-02-25] (dentist appointment), learned_at=2026-02-10
Now:     2026-02-16

d_occ = interval_distance([2026-02-25, 2026-02-25], [2026-02-23, 2026-03-01])
      = 0  (entity falls within query range — overlap)

d_lrn = point_interval_distance(2026-02-10, [2026-02-23, 2026-03-01])
      = 2026-02-23 - 2026-02-10 = 13 days = 1,123,200s

s_occ_prox ≈ 0.983
s_lrn_prox = 0.95 / (1 + exp((1123200 - 604800) / 151200)) + 0.05
           = 0.95 / (1 + exp(3.43)) + 0.05 ≈ 0.081

Auto (noisy-OR):
  s_occ_net = 0.981, s_lrn_net = 0.033
  s_prox_net = 1 - (0.019)(0.967) = 0.982
  s_proximity = 0.982 × 0.95 + 0.05 = 0.983

anchor_age = abs_diff(2026-02-16, 2026-03-01) = 13 days = 1,123,200s
α = 0.7 + 0.3 × (1 - exp(-1123200 / 7776000)) = 0.7 + 0.3 × 0.134 = 0.740

s_recency = exp(-(6 × 86400) / (28 × 86400)) = exp(-0.214) ≈ 0.807

s_temporal = 0.740 × 0.983 + 0.260 × 0.807 = 0.727 + 0.210 = 0.937
```

Future event scored correctly. `learned_at < occurred_start` is handled naturally. α = 0.740 (near-future anchor, 13 days out — recency still gets ~26% weight). With abs_diff, a far-future anchor (e.g., 2027) would get α → 1.0, suppressing recency — correct for "what's planned for next year?" where proximity to the target date matters more than when the plan was recorded.

---

## 9. Error Handling

- **Missing entity blob** (deleted between scan and scoring): skip candidate, no error
- **Malformed header** (blob < 25 bytes): skip candidate, no error
- **Zero sigma**: treated as 86400 (1 day floor)
- **anchor_start > anchor_end**: swap them
- **Overflow in midpoint**: use `start/2 + end/2 + (start%2 + end%2)/2`
- **Overflow in interval_distance**: use `u64::saturating_sub` for all subtractions
- **Empty candidate set after adaptive widening**: return empty vec, no error
- **Single entity in result set for contiguity boost**: `max(result_count - 1, 1)` prevents division by zero
- **Future occurred_start** (calendar events): scoring works symmetrically on unsigned distances, no special handling needed
- **Empty long-interval index**: iteration returns immediately, zero cost
- **Both mode with None learned anchors**: if `anchor_mode = Both` but no learned anchor range is set (i.e., `learned_start`/`learned_end` are None), return an error. Silent fallback to Auto would hide caller bugs and produce incorrect recall-heavy results. Use `search_temporal_bitemporal()` or set learned anchors explicitly when using Both mode.
- **Inverted occurred range** (`occurred_start > occurred_end`): swap at ingest in `put_entity`. All internal arithmetic uses `saturating_sub` as defense-in-depth.

---

## 10. Test Criteria

### Sigmoid shape
1. Entity at distance=0 scores ≈ **0.983** (not 1.0 — sigmoid shape)
2. Entity at distance >> σ scores ≈ 0.05 (floor), never zero
3. Floor guarantee: no entity ever scores below 0.05 on any proximity component

### Interval distance
4. Overlapping occurred interval and query range → `d_occ = 0`
5. Long event (3 months) with query near end → distance is gap to nearest edge, not midpoint distance
6. Point event with range query → `interval_distance` degenerates correctly

### Anchor mode
7. Same entity scores differently under Occurred vs Learned vs Auto vs Both
8. False positive case (Example 4): Occurred mode rejects, Learned mode accepts, Both mode rejects
9. In Occurred mode, only occurred indexes are scanned (verify with entity that only matches via learned index — should not appear)
10. Both mode: entity matching both axes scores ~0.966; entity matching only one axis scores ~0.049

### Proximity (Auto mode — noisy-OR)
11. Learned proximity wins when appropriate: entity occurred 10y ago but learned near query time scores high via s_lrn_prox
12. Occurred proximity wins when appropriate: entity occurred near query time but learned long ago scores high via s_occ_prox
13. Agreement bonus: two entities with same max but different min — entity where both axes match scores higher (noisy-OR agreement effect)
14. Floor preservation: two entities both at floor → s_proximity exactly equals floor (0.05), not lifted
15. Range: s_proximity never exceeds 1.0 in any mode

### Dynamic α
16. Near-now query (anchor_age ≈ 0): α ≈ 0.70, recency has 30% weight
17. Historical query (anchor_age >> 90d): α ≈ 1.0, recency suppressed
18. Same entity with same proximity but different anchor_age → different s_temporal due to α shift
19. Near-future anchor (next week): anchor_age ≈ 7d (abs_diff), α ≈ 0.708
19b. Far-future anchor (1 year ahead): anchor_age ≈ 1y (abs_diff), α ≈ 1.00 (recency suppressed)

### Candidate discovery
20. σ-driven padding: point anchor + Year granularity → radius includes 3σ = 540d (not just 7d)
21. Bidirectional scan: closest-to-anchor entities are in candidate set even when per_scan_cap is tight
22. Three indexes: entity with occurred_start outside window but occurred_end inside → discovered via occurred_end scan
23. Per-scan independence: learned scan produces candidates even when occurred scans are saturated
24. σ not clamped to 86400: Exact (σ=3600) and Hour (σ=14400) produce different scoring than Day (σ=86400)

### Spanner intervals
25. Long-interval entity (occurred spanning years) whose start AND end are outside scan window → still discovered via temporal_long_intervals index
26. Short-interval entity (< 14 days) → NOT in temporal_long_intervals (not needed)
27. Long-interval entity with no overlap to query → discovered by long-interval scan but filtered out (distance > 0)

### Adaptive widening
28. Narrow σ with few entities → widens and finds more candidates
29. `temporal_adaptive(false)` → no widening, returns fewer results
30. Max 3 rounds: σ doesn't grow beyond 8× original

### Temporal contiguity
31. Temporally clustered entities (same week) score higher than isolated entities after boost
32. Single entity → contiguity=0, no boost
33. boost_contiguity without temporal search configured → skipped (no boost applied)
34. Contiguity window capped: Year query with σ=180d → σ_contig = 14d, not 180d
35. Learned mode: contiguity computed on learned_at distance, not occurred distance

### Both mode
36. Entity matching both axes: floor-preserving product score ≈ 0.964 (not raw 0.966)
37. Entity matching only occurred: floor-preserving product → exactly floor (0.050), not sub-floor
38. Both mode uses separate learned anchor range for d_lrn computation
39. Both mode scans all three indexes (spanner scan included for occurred axis)
40b. Both mode with no learned anchors: returns error (not silent Auto fallback)

### API tiers
40. Tier equivalence: `search_temporal(s, e, lim)` gives same results as `search_temporal_with_sigma(s, e, max(e-s, 86400), Auto, lim)` when range_width >= 86400
41. Granularity effect: Day σ vs Year σ produces different score distributions for same entity set

### Future events
42. Entity with occurred_start in future, learned_at = now → scored correctly
43. Future anchor query → α = 0.70 (saturating_sub gives 0)

### Overlap tie-break
44b. Two entities both overlapping query (d=0): entity closer to anchor midpoint ranks higher
44c. Entity exactly at anchor midpoint vs entity at edge of query range: midpoint entity wins tie-break

### Adaptive widening — skip unchanged
45b. Exact σ (3600s): widening σ to 7200/14400/28800 doesn't change 7d radius → no rescan wasted
45c. Week σ (604800s): widening to 1209600 DOES change radius → rescan happens

### Spanner scan specifics
45d. True-spanner filter: entity with start inside window but end outside → NOT added by spanner scan (already found by start scan)
45e. Spanner scan skipped in Learned mode
45f. Spanner value contains correct occurred_start/occurred_end (read from value, not header)

### Underflow guards
45g. Entity with occurred_start > occurred_end at put_entity → swapped before storing
45h. All threshold checks use saturating_sub — no panic on malformed data

### Recency double-counting
45i. Pipeline with temporal search + boost_recency: boost_recency is a silent no-op (scores unchanged)

### Error cases
46. Skip missing entities: deleted entity in candidate set doesn't cause error
47. Recency component: recently-learned entity gets higher s_temporal than old-learned entity (all else equal, near-now query)
48. Both mode error: anchor_mode=Both without learned anchors → error returned

---

## 11. Open Questions

### Resolved from v1

1. **Bonus weight (0.1)** — Eliminated. Replaced with normalized noisy-OR which has no tuning constant (v3).

2. **s_proximity can exceed 1.0** — Eliminated. Noisy-OR stays in [floor, ~1.0] (v3).

3. **Access-based strengthening** — Deferred. MemoryBank's `S++ on recall` pattern requires `last_access_at` tracking, which is a schema change beyond Task 6 scope. Future task.

4. **Learned scan window** — Resolved: same window for all scans (except Both mode which has separate learned window), derived from σ. The dynamic α handles the "recently told me" case by suppressing recency for historical queries rather than using a separate scan window.

### Resolved from v2

5. **Contiguity multiplier (0.2)** — Kept as starting point but now gated behind temporal queries, axis-aware, and window-clamped. Task 9 benchmarks will tune the multiplier.

6. **Adaptive widening round count** — Kept at 3 rounds (8×). The σ is no longer clamped to 86400, so Exact (3600) can widen to 3600→7200→14400→28800. per_scan_cap bounds latency regardless.

7. **Bidirectional scan implementation** — heed provides `rev_range` and `range` iterators. LMDB allows multiple cursors in one read transaction on the same thread. Forward and reverse iterators use separate cursors, so the approach is safe. Fallback (forward scan + distance sort) should be implemented as safe-mode behind a flag.

### New from v3

8. **Long-interval threshold (14 days)** — Conservative choice that catches all spanners. If write amplification becomes a concern (many entities just over 14 days), the threshold could be raised. Monitor temporal_long_intervals cardinality.

9. **Both mode sigma sharing** — Both mode uses one σ for both axes. Should each axis have its own σ? (e.g., "events from 2016" → Year σ, "told in March" → Month σ). Adds API complexity. Defer unless benchmarks show a need. The API extension would be `sigma_occurred_secs` + `sigma_learned_secs` as separate fields.

10. **Duration penalty for overlap=0 in Occurred mode** — Long-lived entities (year-spanning CLAIMs, relationships) get `d=0` for any query inside their validity span. Correct for "what was true?" but potentially wrong for "what happened?" An entity-type-aware or duration-aware penalty like `min(1, query_len / entity_len)` could help. This is a product-level decision about EVENT vs STATE semantics in temporal scoring.

11. **Explainability / debug metadata** — Return `(anchor_mode, axis_winner, s_occ_prox, s_lrn_prox, s_proximity, α, s_recency)` as optional debug fields in `ScoredEntity`. Useful for QA tooling when Auto mode misfires. Low implementation cost — just add an optional debug struct.

---

## 12. Considered Alternatives

This section preserves the design alternatives evaluated during v1-v3 development.

### Sigmoid alternatives (§3)

| Approach | Formula | Properties | Why rejected/chosen |
|---|---|---|---|
| **Linear clamp (v1)** | `1 - d/range` | Drops to zero at boundary | Rejected: too harsh. "5 years + 2 weeks ago" scores zero for "5 years ago" |
| **Pure exponential (Hindsight)** | `exp(-d/σ)` | Asymptotic, never reaches zero | Rejected: no floor. Very old memories effectively vanish |
| **Gaussian** | `exp(-d²/2σ²)` | Steeper near σ, gentler far | Not necessarily better than sigmoid; less standard in memory literature |
| **Sigmoid with floor (Mnemosyne)** ✓ | `(1-floor)/(1+exp((d-σ)/(σ/4))) + floor` | Floor guarantee, sigmoid shape | **Chosen**: matches Mnemosyne/SynapticRAG practice, configurable steepness |

### Recency alternatives (§3)

| Approach | Formula | Properties | Why rejected/chosen |
|---|---|---|---|
| **Fixed α** | `0.7 × proximity + 0.3 × recency` | Simple | Rejected: penalizes historical queries |
| **Dynamic α (anchor_age)** ✓ | `α(age) × proximity + (1-α(age)) × recency` | Adapts to query intent | **Chosen**: historical queries suppress recency naturally |
| **Upstream intent boolean** | Caller passes "recency matters" flag | Explicit | Not adopted at crate level — TemporalAnchorMode + dynamic α cover common cases |
| **α keyed off anchor_mid** | Distance from anchor center to now | Slightly more correct for straddling intervals | Marginal benefit, added complexity. Noted for future. |

### Spanner interval alternatives (§5)

| Approach | Properties | Why rejected/chosen |
|---|---|---|
| **Ignore (document limitation)** | Zero cost | Rejected: CLAIMs and relationships are real long-interval entities |
| **Bucketed overlap index** | One key per month-bucket per interval. Correct. O(interval_months) write | Good for very large vaults. Overkill for personal vaults (<50K long intervals) |
| **Interval tree (in-memory)** | O(log n) query | Not LMDB-friendly, requires rebuild on open |
| **Reverse start scan** | Scan occurred_start backward from window_start | Unbounded depth, can't guarantee finding spanners |
| **Long-interval side index** ✓ | O(1) write, bounded read | **Chosen**: simple, correct, scales to ~50K. Upgradable to bucket index later |

### Dynamic α transition timescale alternatives (§3)

| Timescale | Behavior | Why rejected/chosen |
|---|---|---|
| 30 days | α reaches ~0.93 at 3 months — aggressive suppression | Too aggressive for near-term queries |
| **90 days** ✓ | α reaches ~0.89 at 3 months, ~1.0 at 1 year | **Chosen**: balanced transition |
| 180 days | α only reaches ~0.80 at 3 months — too much recency for clearly past queries | Too slow to suppress recency |
| Scaled with σ | Transition adapts to query granularity | Adds complexity. Dynamic α already captures the key signal (anchor age) |

### Contiguity formula alternatives (§7)

| Approach | Formula | Properties | Why rejected/chosen |
|---|---|---|---|
| **Multiplicative** ✓ | `score *= 1 + 0.2 × contiguity` | Proportional: strong + clustered = stronger | **Chosen**: right semantic for episode coherence |
| **Additive** | `score += β × contiguity` | Flat bonus regardless of base score | Rejected: can artificially promote weak items |
| **No contiguity** | N/A | Simpler | Rejected: episode coherence is a real product need |
| **Min-neighbors guard** | Only boost if ≥2 neighbors | Prevents single near-pair from skewing | Not needed: ×1.2 max multiplier is already mild enough. Revisit if multiplier increases. |

### Both mode fusion alternatives (§3)

| Approach | Formula | Range | Properties | Why rejected/chosen |
|---|---|---|---|---|
| **Raw multiplication** | `s_occ × s_lrn` | [0.0025, ~1.0] | Breaks floor contract | Rejected: floor-floor → 0.0025, violates "never below 0.05" for downstream consumers |
| **Floor-preserving product** ✓ | Normalize → multiply → denormalize | [floor, ~1.0] | Preserves floor, soft AND | **Chosen**: if either axis is floor, output is exactly floor. Same normalized-space pattern as noisy-OR. |
| **min(s_occ, s_lrn)** | min | [floor, ~1.0] | Preserves floor but weaker AND | Rejected: doesn't punish "one barely above floor" as much. Less selective than product. |
| **Geometric mean** | `sqrt(s_occ × s_lrn)` | [0.05, ~1.0] | Between product and min | Rejected: breaks floor contract (floor-floor → 0.05, ok, but 0.05 × 0.2 → 0.1 not intuitive). Product in normalized space is cleaner. |

### α anchor_age computation alternatives (§3)

| Approach | Formula | Future behavior | Why rejected/chosen |
|---|---|---|---|
| **saturating_sub** | `now.saturating_sub(anchor_end)` | All future → age=0, α=0.70 | Rejected: "meeting in 2027" gets same recency as "meeting next week" |
| **abs_diff** ✓ | `abs_diff(now, anchor_end)` | Near-future ≈ near-now; far-future → α→1.0 | **Chosen**: symmetric, far-future suppresses recency like far-past |
| **Piecewise** | Different formula for past vs future | Full control | Over-engineered; abs_diff captures the key insight simply |

### σ sentinel alternatives (§6)

| Approach | Properties | Why rejected/chosen |
|---|---|---|
| **σ=0 as sentinel** ✓ | Simple, documented | **Chosen**: σ=0 means "unset → default 86400". Acceptable for internally-consumed Rust API. |
| **Option\<u64\>** | Type-safe, no ambiguity | Rejected: adds API complexity for no practical benefit. σ=0 is a natural "not set" value. |
| **Validation error on σ=0** | Catches bugs | Too strict for Tier 1 callers who don't know σ. |

### α scaling with σ alternatives (§3)

| Approach | Formula | Properties | Why rejected/chosen |
|---|---|---|---|
| **Fixed 90d** ✓ | `exp(-age / 90d)` | Simple, reasonable default | **Chosen**: captures the key signal (anchor age) without σ coupling |
| **max(90d, σ)** | `exp(-age / max(90d, σ))` | Slower transition for vague queries | Rejected: one review suggested this, another suggested `max(90d, 3σ)` — disagreement signals it's a tuning knob, not a design flaw. Task 9 benchmarks will settle it. |
| **max(90d, 3σ)** | `exp(-age / max(90d, 3σ))` | Even slower transition | Same as above — deferred to benchmarks. |

### Dismissed review findings (v3.1)

These findings from external reviews were evaluated and intentionally not adopted:

| Finding | Source | Why dismissed |
|---|---|---|
| **Belief revision mode** (two tx-time anchors) | R2 | Out of scope for temporal scoring. Claim supersession chains + validity intervals handle "what did we believe at time T" queries. |
| **Recurrence/periodicity** ("every Tuesday") | R3 | Upstream NER/pattern-matching concern, not temporal scoring. The crate provides building blocks; periodicity detection belongs in Dreamer agent or extraction pipeline. |
| **Builder API ergonomics for Tier 4** | R3 | Style preference. Current separate `search_temporal_bitemporal()` is explicit and consistent with tier pattern. |
| **Widen radius independently of σ** | R3 | Skip-rescan-when-unchanged (adopted) is simpler and sufficient. |
| **SynapticRAG arXiv citation** | R1 | Only in REVIEW-PROMPT.md (review guide), not in the spec. Low priority. |
