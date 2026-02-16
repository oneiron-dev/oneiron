# Temporal Scoring Specification — Oneiron Crate

**Status:** Proposed, pending review
**Scope:** `execute_temporal()` in `pipeline.rs` (Task 6)
**Author:** Design discussion, Feb 2026
**Reviewers:** [pending]

---

## 1. Problem

An entity in Oneiron has two temporal anchors:

| Field | Meaning | Stored as |
|---|---|---|
| `occurred_start` / `occurred_end` | When the real-world event happened | u64 BE in entity header bytes 1..17 |
| `learned_at` | When the entity was recorded into the system | u64 BE in entity header bytes 17..25 |

**Invariant:** `learned_at >= occurred_start` (you cannot record something before it happens; exception: fictional/roleplay scenarios, handled separately).

A query arrives with an anchor time range `[anchor_start, anchor_end]`. The scoring function must answer: **how temporally relevant is this entity to the query?**

### Why this is non-trivial

A linear or naive scoring function fails on common queries:

| Query | Entity | Naive "occurred proximity only" | Problem |
|---|---|---|---|
| "What happened 5 years ago?" | occurred=5y ago, learned=5y ago | High score | Works fine |
| "What happened 5 years ago?" | occurred=5y ago, learned=yesterday | High score | Works fine |
| "What did I tell you last March?" | occurred=10y ago, learned=last March | **Floor score** | Entity was told near query time but occurred long ago — missed |
| "Remember that old trip?" (vague) | occurred=8y ago, learned=3y ago | **Floor score** if query defaults to "now" | Old memories should still be retrievable |

The third case is the critical gap: the user is asking about **when they told the system**, not when the event occurred. A single-timestamp proximity score cannot serve both intents.

---

## 2. Literature Survey

We surveyed 11 papers for temporal scoring approaches. Key findings:

| Paper | Timestamps | Scoring | Limitation |
|---|---|---|---|
| **MemoTime** (2025) | Event time only | `exp(-\|t_event - t_query\| / σ)` — proximity to query | No recency signal; no learned-time awareness |
| **Hindsight** (2025) | `tau_s/tau_e` (occurred), `tau_m` (mentioned) | `tau_m` used for graph link weights; `tau_s/tau_e` for date-range retrieval | `tau_m` never used in scoring against query time |
| **Mnemosyne** (2025) | Effective age (access-adjusted) | Sigmoid with floor=0.05: `τ(e_eff) = (1-d)/(1+exp((e_eff-a)/b)) + d` | Decay from now only; no proximity to query time |
| **MemoryBank** (2024) | Time since learning | Ebbinghaus: `R = e^(-t/S)`, S++ on recall | Recency from now only; no query-time awareness |
| TiMem, ENGRAM, EcphoryRAG, A-Mem, AgeMem, EverMemOS, EM-LLM | Timestamps as metadata | No temporal scoring formula | Rely on LLM to interpret timestamps in context |

**Key observations:**
- Only Hindsight stores both occurred and learned timestamps; nobody scores both against the query
- Proximity-to-query (MemoTime) and recency-from-now (MemoryBank/Mnemosyne) are treated as separate approaches
- No existing system combines both timestamps into a unified proximity score

---

## 3. Proposed Formula

### Three components

```
s_occ_prox  = sigmoid(|occurred_mid - query_mid|, σ, floor)
s_lrn_prox  = sigmoid(|learned_at   - query_mid|, σ, floor)

s_proximity = max(s_occ_prox, s_lrn_prox) + 0.1 × min(s_occ_prox, s_lrn_prox)

s_recency   = exp(-(now - learned_at) / λ)

s_temporal  = α × s_proximity + (1 - α) × s_recency
```

### Constants

| Symbol | Value | Rationale |
|---|---|---|
| `floor` | 0.05 | Old memories never score zero (Mnemosyne principle) |
| `λ` | 28 × 86400 s (28 days) | Mnemosyne default; 1/e decay at 28 days |
| `α` | 0.7 | Proximity dominates; recency is a mild tiebreaker |
| `0.1` | Bonus weight for min-signal | Small reward when both timestamps agree; doesn't penalize divergence |

### Sigmoid function

```
sigmoid(distance, σ, floor) = (1.0 - floor) / (1.0 + exp((distance - σ) / (σ / 4.0))) + floor
```

Where:
- `distance` = absolute difference in seconds between entity timestamp and query midpoint
- `σ` = decay midpoint in seconds (controls where steep dropoff happens)
- `σ / 4.0` = steepness (scales with σ for consistent shape across granularities)

Behavior:
- At `distance = 0`: score ≈ 1.0
- At `distance = σ`: score ≈ 0.525 (midpoint of sigmoid)
- At `distance >> σ`: score → floor (0.05)

### Midpoint calculation (overflow-safe)

```
midpoint(start, end) = start/2 + end/2 + (start%2 + end%2)/2
```

For `learned_at` (a single timestamp), `midpoint = learned_at`.

---

## 4. Why `max + 0.1 × min` instead of alternatives

### Option A: Single proximity (occurred only) — current SCHEMA-DESIGN.md

```
s_proximity = sigmoid(|occurred_mid - query_mid|)
```

**Rejected.** "What did I tell you last March?" returns floor score for entities that occurred years before March but were recorded in March.

### Option B: Weighted sum

```
s_proximity = w₁ × s_occ_prox + w₂ × s_lrn_prox
```

**Rejected.** When timestamps diverge (old event told recently, or recent event about old topic), the irrelevant signal drags the score down:

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

### Option D: max + bonus (chosen)

```
s_proximity = max(s_occ_prox, s_lrn_prox) + 0.1 × min(s_occ_prox, s_lrn_prox)
```

- Divergent case: bonus ≈ 0.1 × floor = 0.005 (negligible — no penalty)
- Aligned case: bonus ≈ 0.1 × 0.9 = 0.09 (small tiebreaker for entities where both timestamps agree)
- No new hyperparameter to tune (0.1 is fixed; not sensitive)

---

## 5. Candidate Discovery

### Index-bounded window scan

Before scoring, we need a candidate set. Full table scan is O(n) and unacceptable.

```
range_width  = anchor_end - anchor_start       (fallback: 86400 if zero)
padding      = max(range_width × 2, 7 × 86400) (at least 7 days)
window_start = anchor_start.saturating_sub(padding)
window_end   = anchor_end.saturating_add(padding)
candidate_cap = limit × 4
```

### Two index scans (same window)

1. **`temporal_occurred_start`** — keys: `[timestamp_BE(8) | entity_id(16)]`
   - Finds entities that **occurred** near the query time
   - Primary discovery path

2. **`temporal_learned`** — keys: `[timestamp_BE(8) | entity_id(16)]`
   - Finds entities that were **recorded** near the query time
   - Catches the "what did I tell you last March?" case

Both scans use the same `[window_start, window_end]` bounds. Entity IDs are deduplicated into a single candidate set, capped at `candidate_cap`.

### Why scan learned with occurred-derived bounds?

The query anchor could refer to either timestamp. Scanning both indexes with the same window catches:
- Events that happened near the query time (via occurred scan)
- Events that were told near the query time (via learned scan)

The scoring function then determines which interpretation produces higher relevance.

---

## 6. Sigma Source: Three API Tiers

The `σ` parameter controls the sigmoid's decay width. Three ways to provide it:

### Tier 1: Inferred from range width

```rust
pub fn search_temporal(self, anchor_start: u64, anchor_end: u64, limit: usize) -> Self
```

`σ = max(anchor_end - anchor_start, 86400)` — at least 1 day.

### Tier 2: Explicit sigma

```rust
pub fn search_temporal_with_sigma(self, anchor_start: u64, anchor_end: u64, sigma_secs: u64, limit: usize) -> Self
```

Caller provides `sigma_secs` directly.

### Tier 3: Granularity enum

```rust
pub fn search_temporal_with_granularity(self, anchor_start: u64, anchor_end: u64, granularity: TemporalGranularity, limit: usize) -> Self
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

Intended for use with NER/SFT output that includes granularity classification (oneiron-internal scope).

---

## 7. Worked Examples

All examples use `σ = 86400` (1 day), `floor = 0.05`, `λ = 28 × 86400`, `α = 0.7`.

### Example 1: Recent event, recorded at the time

```
Query:   anchor_mid = 2026-02-10 12:00
Entity:  occurred_mid = 2026-02-10 14:00,  learned_at = 2026-02-10 14:30
Now:     2026-02-16

distance_occ = 7200s (2h),  distance_lrn = 9000s (2.5h)

s_occ_prox = (0.95) / (1 + exp((7200 - 86400) / 21600)) + 0.05
           ≈ 0.95 / (1 + exp(-3.667)) + 0.05
           ≈ 0.95 / 1.026 + 0.05
           ≈ 0.976

s_lrn_prox ≈ 0.974  (similar, slightly further)

s_proximity = max(0.976, 0.974) + 0.1 × min(0.976, 0.974)
            = 0.976 + 0.097 = 1.073  (clamped to 1.0 in practice, or left as-is for ranking)

s_recency = exp(-(6 × 86400) / (28 × 86400)) = exp(-0.214) ≈ 0.807

s_temporal = 0.7 × 1.0 + 0.3 × 0.807 = 0.942
```

Both timestamps agree, bonus kicks in.

### Example 2: Old memory recalled recently

```
Query:   anchor_mid = 2021-02-16 (5 years ago)
Entity:  occurred_mid = 2021-02-20,  learned_at = 2026-02-15 (told yesterday)

distance_occ = 4 × 86400 = 345600s
distance_lrn = |2026-02-15 - 2021-02-16| ≈ 5y ≈ 157,680,000s

s_occ_prox = 0.95 / (1 + exp((345600 - 86400) / 21600)) + 0.05
           = 0.95 / (1 + exp(12.0)) + 0.05
           ≈ 0.95 / 162755 + 0.05
           ≈ 0.05  (floor)

Wait — distance_occ = 4 days with σ = 1 day. That's 4σ away.
s_occ_prox = 0.95 / (1 + exp((345600 - 86400) / 21600)) + 0.05
           = 0.95 / (1 + exp(12.0)) + 0.05 ≈ 0.05

Hmm, with σ = 86400 (1 day), 4 days away gives floor. Let's use σ = Year = 15,552,000s for a "5 years ago" query:

distance_occ = 345600s (4 days off from 5y ago)
s_occ_prox = 0.95 / (1 + exp((345600 - 15552000) / 3888000)) + 0.05
           = 0.95 / (1 + exp(-3.91)) + 0.05
           ≈ 0.95 / 1.020 + 0.05
           ≈ 0.981

distance_lrn ≈ 157,680,000s (5 years)
s_lrn_prox = 0.95 / (1 + exp((157680000 - 15552000) / 3888000)) + 0.05
           = 0.95 / (1 + exp(36.5)) + 0.05
           ≈ 0.05 (floor)

s_proximity = max(0.981, 0.05) + 0.1 × min(0.981, 0.05)
            = 0.981 + 0.005 = 0.986

s_recency = exp(-(1 × 86400) / (28 × 86400)) = exp(-0.036) ≈ 0.965

s_temporal = 0.7 × 0.986 + 0.3 × 0.965 = 0.980
```

High score. occurred_mid is close to query, learned yesterday (high recency). Bonus from min is negligible (0.005).

### Example 3: "What did I tell you last March?" — the key case

```
Query:   anchor_mid = 2025-03-15 (last March), σ = Month = 2,592,000s
Entity:  occurred_mid = 2016-06-01 (10 years ago),  learned_at = 2025-03-20

distance_occ = |2016-06-01 - 2025-03-15| ≈ 276,480,000s (way beyond σ)
distance_lrn = |2025-03-20 - 2025-03-15| = 432,000s (5 days)

s_occ_prox ≈ 0.05 (floor — 10 years from March)

s_lrn_prox = 0.95 / (1 + exp((432000 - 2592000) / 648000)) + 0.05
           = 0.95 / (1 + exp(-3.33)) + 0.05
           ≈ 0.95 / 1.036 + 0.05
           ≈ 0.967

s_proximity = max(0.05, 0.967) + 0.1 × min(0.05, 0.967)
            = 0.967 + 0.005 = 0.972

s_recency = exp(-(11 × 30 × 86400) / (28 × 86400)) = exp(-11.8) ≈ 0.000007

s_temporal = 0.7 × 0.972 + 0.3 × 0.000007 ≈ 0.680
```

Without s_lrn_prox: `s_temporal = 0.7 × 0.05 + 0.3 × 0.000007 = 0.035` — **lost**.
With s_lrn_prox: `s_temporal = 0.680` — **found**.

---

## 8. Error Handling

- **Missing entity blob** (deleted between scan and scoring): skip candidate, no error
- **Malformed header** (blob < 25 bytes): skip candidate, no error
- **Zero sigma**: treated as 86400 (1 day floor)
- **anchor_start > anchor_end**: swap them
- **Overflow in midpoint**: handled by `start/2 + end/2 + (start%2 + end%2)/2`
- **Overflow in abs_diff**: use `u64::abs_diff()` (wrapping-safe)

---

## 9. Test Criteria

1. **Sigmoid shape**: entity at distance=0 scores ≈1.0, at distance >> σ scores ≈0.05, never zero
2. **Floor guarantee**: no entity ever scores below 0.05 on any proximity component
3. **Learned proximity wins when appropriate**: entity occurred 10y ago but learned near query time scores high via s_lrn_prox
4. **Occurred proximity wins when appropriate**: entity occurred near query time but learned long ago scores high via s_occ_prox
5. **Bonus effect**: two entities with same max but different min — entity with higher min scores slightly higher
6. **Tier equivalence**: `search_temporal(s, e, lim)` gives same results as `search_temporal_with_sigma(s, e, max(e-s, 86400), lim)`
7. **Granularity effect**: Day σ vs Year σ produces different score distributions for same entity set
8. **Skip missing entities**: deleted entity in candidate set doesn't cause error
9. **Recency component**: recently-learned entity gets higher s_temporal than old-learned entity (all else equal)

---

## 10. Open Questions for Reviewer

1. **Bonus weight (0.1)**: Is this too small to matter? Too large? Should it be benchmarked?
2. **s_proximity can exceed 1.0**: When both timestamps agree, `max + 0.1×min` can reach ~1.1. Should we clamp to 1.0, or let it act as a natural tiebreaker in ranking? (Currently: no clamp, since scores are only used for relative ordering.)
3. **Access-based strengthening**: Mnemosyne and MemoryBank both boost frequently-accessed memories. We don't (yet). Should s_recency evolve into an access-aware signal? (Tracked as future work, not Task 6 scope.)
4. **Learned scan window**: We scan `temporal_learned` with occurred-derived bounds. Should the learned scan instead use a separate recent window (e.g., `[now - 28d, now]`) to catch recently-recorded entities regardless of query time? Current design is simpler and validated by the scoring function.
