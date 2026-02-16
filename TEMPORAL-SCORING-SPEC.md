# Temporal Scoring Specification — Oneiron Crate

**Status:** Revised after external review (v2)
**Scope:** `execute_temporal()` in `pipeline.rs` (Task 6)
**Author:** Design discussion, Feb 2026
**Revision:** Incorporated external review feedback — interval distance, σ-driven discovery, TemporalAnchorMode, dynamic α, bidirectional scan, adaptive widening, temporal contiguity boost

---

## 1. Problem

An entity in Oneiron has two temporal anchors (bitemporal model):

| Field | Meaning | Stored as | Bitemporal analog |
|---|---|---|---|
| `occurred_start` / `occurred_end` | When the real-world event happened | u64 BE in entity header bytes 1..17 | **Valid time** |
| `learned_at` | When the entity was recorded into the system | u64 BE in entity header bytes 17..25 | **Transaction time** |

**Invariant:** `learned_at >= occurred_start` (you cannot record something before it happens; exception: fictional/roleplay scenarios, handled separately).

A query arrives with an anchor time range `[anchor_start, anchor_end]`. The scoring function must answer: **how temporally relevant is this entity to the query?**

### Why this is non-trivial

| Query | Entity | Naive scoring | Problem |
|---|---|---|---|
| "What happened 5 years ago?" | occurred=5y ago, learned=5y ago | High | Works |
| "What happened 5 years ago?" | occurred=5y ago, learned=yesterday | High | Works |
| "What did I tell you last March?" | occurred=10y ago, learned=last March | **Floor** | Entity told near query time but occurred long ago — missed |
| "Remember that old trip?" (vague) | occurred=8y ago, learned=3y ago | **Floor** if query defaults to "now" | Old memories should still be retrievable |
| "What happened last March?" | occurred=10y ago, learned=last March | **High** (false positive in Auto mode) | Entity was _told_ last March, not _happened_ — needs anchor intent |

The third case is the critical gap: the user is asking about **when they told the system**, not when the event occurred. A single-timestamp proximity score cannot serve both intents.

The fifth case shows why **TemporalAnchorMode** matters: without intent disambiguation, Auto mode trades precision for recall.

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
- Hindsight uses **interval overlap** for temporal constraints, not midpoint distance
- Proximity-to-query (MemoTime) and recency-from-now (MemoryBank/Mnemosyne) are treated as separate approaches
- No existing system combines both timestamps into a unified proximity score
- EM-LLM uses **temporal contiguity** as a retrieval primitive (co-occurring memories reinforce each other)
- SynapticRAG demonstrates that sigmoid normalization is a common choice for temporal scores
- The bitemporal data model (valid-time vs transaction-time) is well-established in database literature and maps directly to our occurred/learned split

---

## 3. Proposed Formula

### Interval distance functions

Replaces midpoint-to-midpoint distance. Handles range queries and long events correctly.

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

### Anchor mode gating

```
match anchor_mode {
    Occurred => s_proximity = s_occ_prox,
    Learned  => s_proximity = s_lrn_prox,
    Auto     => s_proximity = max(s_occ_prox, s_lrn_prox) + 0.1 × min(s_occ_prox, s_lrn_prox),
}
```

### Recency with dynamic α

```
s_recency = exp(-(now - learned_at) / λ)

// Dynamic α: historical queries suppress recency, near-now queries keep it
anchor_age = now.saturating_sub(anchor_end)
α = 0.7 + 0.3 × (1.0 - exp(-(anchor_age as f64) / (90.0 × 86400.0)))

s_temporal = α × s_proximity + (1.0 - α) × s_recency
```

Dynamic α behavior:
- Query is "now" (`anchor_age = 0`): **α = 0.70** — recency gets 30% weight
- Query is 1 month ago: **α ≈ 0.80** — recency fading
- Query is 3 months ago: **α ≈ 0.89** — recency mostly irrelevant
- Query is 1+ year ago: **α ≈ 1.00** — pure proximity, recency completely suppressed

**Rationale:** Fixed α=0.7 penalizes historical queries. "What happened 5 years ago?" shouldn't care about recency. Dynamic α, gated by `|now - anchor_end|`, naturally suppresses recency for explicitly past-anchored queries while keeping it active for near-now queries. The 90-day transition timescale means queries within ~3 months of now get meaningful recency weight; beyond that, proximity dominates.

### TemporalAnchorMode

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum TemporalAnchorMode {
    /// Query refers to when events happened: "what happened last March?"
    Occurred,
    /// Query refers to when information was recorded: "what did I tell you last March?"
    Learned,
    /// Ambiguous — score both axes, take best match
    #[default]
    Auto,
}
```

**With upstream intent signal:** Caller passes `Occurred` or `Learned` from NER/classifier/heuristic. Scoring uses only the relevant axis. Precision is tight — the false positive case (row 5 in Problem table) is eliminated.

**Without intent signal:** Default `Auto`. Both axes scored, max+bonus. Accepts the false positive tradeoff in exchange for never missing the learned-proximity case.

The crate provides the knobs. Upstream decides how to set them (NER, regex heuristic, user toggle — not our business).

### Constants

| Symbol | Value | Rationale |
|---|---|---|
| `floor` | 0.05 | Old memories never score zero (Mnemosyne principle) |
| `λ` | 28 × 86400 s (28 days) | Exponential time constant: `exp(-t/λ)` gives 1/e ≈ 0.368 at 28 days. Note: Mnemosyne uses 28d as a sigmoid midpoint, not an exponential time constant — we adopt the timescale, not the exact parameterization. |
| `α` | 0.7 base, dynamic up to 1.0 | Proximity dominates; recency fades for historical queries |
| `0.1` | Bonus weight for min-signal (Auto mode only) | Small reward when both timestamps agree; doesn't penalize divergence |
| `90 × 86400` | α transition timescale | ~3 months: queries within ~3 months of now get meaningful recency; beyond that, proximity dominates |

---

## 4. Why `max + 0.1 × min` (Auto mode)

### Option A: Single proximity (occurred only) — original SCHEMA-DESIGN.md

```
s_proximity = sigmoid(d_occ)
```

**Rejected.** "What did I tell you last March?" returns floor score for entities that occurred years before March but were recorded in March.

### Option B: Weighted sum

```
s_proximity = w₁ × s_occ_prox + w₂ × s_lrn_prox
```

**Rejected.** When timestamps diverge (old event told recently), the irrelevant signal drags the score down:

```
Entity: occurred=10y ago, learned=last March
Query: "last March"

  s_occ_prox = 0.05, s_lrn_prox = 0.85

  weighted (0.6/0.4): 0.6×0.05 + 0.4×0.85 = 0.37   ← heavily penalized
  max + bonus:        0.85 + 0.1×0.05      = 0.855   ← correct
```

The penalty from weighting is largest exactly in the divergent-timestamp case, which is the scenario this spec exists to fix.

### Option C: Pure max

```
s_proximity = max(s_occ_prox, s_lrn_prox)
```

**Almost chosen.** Handles divergence perfectly. But loses information when both timestamps agree — two entities with identical best-match scores can't be distinguished by how well their other timestamp matches.

### Option D: max + bonus (chosen for Auto mode)

```
s_proximity = max(s_occ_prox, s_lrn_prox) + 0.1 × min(s_occ_prox, s_lrn_prox)
```

- Divergent case: bonus ≈ 0.1 × floor = 0.005 (negligible — no penalty)
- Aligned case: bonus ≈ 0.1 × 0.9 = 0.09 (small tiebreaker for entities where both timestamps agree)
- Can exceed 1.0 in the aligned case (~1.08 max). This is fine — scores are used for relative ordering, not as probabilities. RRF operates on ranks, not raw scores.

**Note:** In `Occurred` and `Learned` modes, this formula doesn't apply — only the relevant axis is scored, so s_proximity is always in [floor, ~0.983].

---

## 5. Candidate Discovery

### σ-driven window

```
range_width  = anchor_end - anchor_start           (fallback: 86400 if zero)
sigma        = max(sigma_secs, 86400)              (from TemporalSearchConfig)
radius       = max(2 × range_width, 3 × sigma, 7 × 86400)
window_start = anchor_start.saturating_sub(radius)
window_end   = anchor_end.saturating_add(radius)
per_scan_cap = limit × 4
```

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

### Bidirectional scan from anchor

For each index, instead of scanning forward from `window_start` (which biases toward earliest timestamps under the cap):

1. Compute `anchor_mid = midpoint(anchor_start, anchor_end)` using overflow-safe formula
2. Seek to `encode_temporal_key(anchor_mid, [0x00; 16])`
3. Open two iterators: one forward (ascending), one backward (descending)
4. Alternate: take one from forward, one from backward
5. Stop when both iterators exit `[window_start, window_end]` or `per_scan_cap` reached

This ensures **closest-to-anchor** candidates are collected first. Under `per_scan_cap` with large windows (Year/Vague granularity), forward-only scan would fill the cap with timestamps far from the anchor, missing the good candidates near it.

### Adaptive σ widening

If total unique candidates after all scans < `limit`:

1. `sigma *= 2`
2. Recompute `radius = max(2 × range_width, 3 × sigma, 7 × 86400)`
3. Re-scan with new window bounds (bidirectional from anchor)
4. Merge new candidates into existing set (deduplicated)
5. Repeat up to **2 more times** (max 3 rounds total, σ grows to 8× original)

**Controlled by `adaptive` flag (default: `true`):**
- `adaptive = true`: widen on insufficient candidates
- `adaptive = false`: exact mode, no widening. Useful when the caller wants precise temporal filtering and would rather get few results than expand the window.

---

## 6. Sigma Source: Three API Tiers

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

### Formula

For each entity `e` in the result set:
```
neighbors(e) = count of other entities in results where
               interval_distance(e.occurred, other.occurred) < σ
contiguity   = neighbors / max(result_count - 1, 1)        // 0.0 to 1.0
score       *= 1.0 + 0.2 × contiguity
```

Where `σ` comes from the temporal search config if configured, or defaults to 86400 (1 day) if no temporal search was set.

O(n²) where n = result_limit (typically 20). Negligible cost.

### API

```rust
pub fn boost_contiguity(self) -> Self;
```

### Examples

- 5 entities from the same week, σ=86400: each has ~4 neighbors → contiguity ≈ 1.0 → score ×1.2
- 1 isolated entity among 20 results: neighbors=0 → contiguity=0 → no boost
- Mixed: 3 entities from trip week + 17 others scattered → trip entities get ~0.1-0.15 contiguity → score ×1.02-1.03

**Tuning note:** The 0.2 multiplier is a starting point. Task 9 benchmarks will evaluate this against real data.

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

s_occ_prox = 0.95 / (1 + exp((7200 - 86400) / 21600)) + 0.05
           = 0.95 / (1 + exp(-3.667)) + 0.05 ≈ 0.976

s_lrn_prox = 0.95 / (1 + exp((9000 - 86400) / 21600)) + 0.05 ≈ 0.974

Auto: s_proximity = max(0.976, 0.974) + 0.1 × min(0.976, 0.974)
                  = 0.976 + 0.097 = 1.073

anchor_age = 2026-02-16 - 2026-02-10 = 6d = 518400s
α = 0.7 + 0.3 × (1 - exp(-518400 / 7776000)) = 0.7 + 0.3 × 0.065 = 0.719

s_recency = exp(-(6 × 86400) / (28 × 86400)) = exp(-0.214) ≈ 0.807

s_temporal = 0.719 × 1.073 + 0.281 × 0.807 = 0.771 + 0.227 = 0.998
```

High score. Both timestamps agree, bonus kicks in. α near 0.7 because query is recent.

### Example 2: "What happened 5 years ago?" (Auto mode, Year granularity)

```
Query:   [2021-02-16, 2021-02-16] (point, Tier 3: Year → σ = 15,552,000s)
Entity:  occurred=[2021-02-18, 2021-02-22] (trip week), learned_at=2026-02-15 (told yesterday)
Now:     2026-02-16

d_occ = interval_distance([2021-02-18, 2021-02-22], [2021-02-16, 2021-02-16])
      = 2021-02-18 - 2021-02-16 = 172800s (2 days, no overlap)

d_lrn = point_interval_distance(2026-02-15, [2021-02-16, 2021-02-16])
      = 2026-02-15 - 2021-02-16 ≈ 157,680,000s (5 years)

s_occ_prox = 0.95 / (1 + exp((172800 - 15552000) / 3888000)) + 0.05
           = 0.95 / (1 + exp(-3.956)) + 0.05 ≈ 0.982

s_lrn_prox ≈ 0.05 (floor — 5 years away with σ = 180 days)

Auto: s_proximity = max(0.982, 0.05) + 0.1 × 0.05 = 0.987

anchor_age ≈ 5 years ≈ 157,680,000s
α = 0.7 + 0.3 × (1 - exp(-157680000 / 7776000)) = 0.7 + 0.3 × ~1.0 ≈ 1.000

s_recency = exp(-(1 × 86400) / (28 × 86400)) ≈ 0.965

s_temporal = 1.0 × 0.987 + 0.0 × 0.965 = 0.987
```

Dynamic α pushed to 1.0 — query is 5 years in the past, recency is irrelevant. Correct behavior.

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

Auto:    s_proximity = max(0.05, 0.983) + 0.1 × 0.05 = 0.988
Learned: s_proximity = 0.983

anchor_age = 2026-02-16 - 2025-03-31 ≈ 322 days ≈ 27,820,800s
α = 0.7 + 0.3 × (1 - exp(-27820800 / 7776000)) = 0.7 + 0.3 × 0.972 = 0.992

s_recency = exp(-(322 × 86400) / (28 × 86400)) = exp(-11.5) ≈ 0.00001

Auto:    s_temporal = 0.992 × 0.988 + 0.008 × 0.00001 ≈ 0.980
Learned: s_temporal = 0.992 × 0.983 + 0.008 × 0.00001 ≈ 0.975
```

**Key improvements from v1 spec:**
- `d_lrn = 0` because learned_at falls within query range (interval distance). v1 used midpoint distance → 432,000s (5 days).
- `α ≈ 0.99` because query is ~11 months ago → recency irrelevant. v1 used fixed α=0.7 → s_temporal=0.680.
- **Final score ≈ 0.98** vs v1's **0.680**. Massive improvement.

**Without s_lrn_prox** (original single-proximity): s_temporal = 0.992 × 0.05 ≈ **0.050** — dead.

### Example 4: False positive case — anchor mode matters

```
Query:   "What happened last March?"
         [2025-03-01, 2025-03-31], σ = Month, anchor_mode varies
Entity:  occurred=[2016-06-01, 2016-06-15], learned_at=2025-03-20
         (User told the bot about their 2016 trip in March 2025)

This entity did NOT happen last March. It was TOLD last March.

Auto mode:     s_temporal ≈ 0.980  ← FALSE POSITIVE for "what happened"
Occurred mode: s_proximity = s_occ_prox = 0.05 → s_temporal ≈ 0.050  ← correctly rejected
Learned mode:  s_proximity = s_lrn_prox = 0.983 → s_temporal ≈ 0.975  ← correctly high
```

This demonstrates why TemporalAnchorMode matters:
- **Auto** accepts this false positive for recall (better than missing "what did I tell you" queries)
- **Occurred** rejects it for precision (when upstream knows the intent)
- **Learned** correctly ranks it high (when upstream knows the intent)

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
7. Same entity scores differently under Occurred vs Learned vs Auto
8. False positive case (Example 4): Occurred mode rejects, Learned mode accepts
9. In Occurred mode, only occurred indexes are scanned (verify with entity that only matches via learned index — should not appear)

### Proximity (Auto mode)
10. Learned proximity wins when appropriate: entity occurred 10y ago but learned near query time scores high via s_lrn_prox
11. Occurred proximity wins when appropriate: entity occurred near query time but learned long ago scores high via s_occ_prox
12. Bonus effect: two entities with same max but different min — entity with higher min scores slightly higher

### Dynamic α
13. Near-now query (anchor_age ≈ 0): α ≈ 0.70, recency has 30% weight
14. Historical query (anchor_age >> 90d): α ≈ 1.0, recency suppressed
15. Same entity with same proximity but different anchor_age → different s_temporal due to α shift

### Candidate discovery
16. σ-driven padding: point anchor + Year granularity → radius includes 3σ = 540d (not just 7d)
17. Bidirectional scan: closest-to-anchor entities are in candidate set even when per_scan_cap is tight
18. Three indexes: entity with occurred_start outside window but occurred_end inside → discovered via occurred_end scan
19. Per-scan independence: learned scan produces candidates even when occurred scans are saturated

### Adaptive widening
20. Narrow σ with few entities → widens and finds more candidates
21. `temporal_adaptive(false)` → no widening, returns fewer results
22. Max 3 rounds: σ doesn't grow beyond 8× original

### Temporal contiguity
23. Temporally clustered entities (same week) score higher than isolated entities after boost
24. Single entity → contiguity=0, no boost
25. boost_contiguity without temporal search → uses 86400 default window

### API tiers
26. Tier equivalence: `search_temporal(s, e, lim)` gives same results as `search_temporal_with_sigma(s, e, max(e-s, 86400), Auto, lim)` when range_width >= 86400
27. Granularity effect: Day σ vs Year σ produces different score distributions for same entity set

### Error cases
28. Skip missing entities: deleted entity in candidate set doesn't cause error
29. Recency component: recently-learned entity gets higher s_temporal than old-learned entity (all else equal, near-now query)

---

## 11. Open Questions

### Resolved from v1

1. **Bonus weight (0.1)** — Kept as-is. It adds ~0.098 in the aligned case, which is meaningful but not dominant. Task 9 benchmarks will evaluate sensitivity.

2. **s_proximity can exceed 1.0** — Accepted. Scores are used for relative ordering within the temporal signal. RRF operates on ranks, not raw scores, so >1.0 doesn't propagate downstream. If this ever changes, clamp at the RRF boundary.

3. **Access-based strengthening** — Deferred. MemoryBank's `S++ on recall` pattern requires `last_access_at` tracking, which is a schema change beyond Task 6 scope. Future task.

4. **Learned scan window** — Resolved: same window for all scans, derived from σ. The dynamic α handles the "recently told me" case by suppressing recency for historical queries rather than using a separate scan window.

### New from v2

5. **Contiguity multiplier (0.2)** — Is this too strong? Could it over-promote temporal clusters at the expense of isolated but highly relevant entities? Task 9.

6. **Adaptive widening round count** — 3 rounds (8× σ) may be too aggressive for Exact/Hour granularity. Should max rounds scale with initial σ? Or is the "still < limit" condition sufficient to stop early?

7. **Bidirectional scan implementation** — heed (LMDB wrapper) provides `rev_range` and `range` iterators. Need to verify that alternating between two iterators on the same database within one read txn is safe. If not, fallback: scan forward from window_start, then sort candidates by distance-to-anchor and truncate to per_scan_cap.
