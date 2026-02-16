# Task 6 Design Notes — Temporal Scoring & PPR Placement

> **Note:** These notes capture the initial design discussion (v1). The authoritative spec is **TEMPORAL-SCORING-SPEC.md (v3.1)**, which supersedes the formulas below. Key changes in v2/v3/v3.1: interval distance (not midpoint), dynamic α with abs_diff (not fixed 0.7, not saturating_sub), normalized noisy-OR with defensive clamp (not max+bonus), floor-preserving Both mode (not raw product), spanner interval index with true-spanner filter and stored bounds, overlap tie-break for d=0, contiguity improvements, future event support, σ clamp fix, underflow guards.

Captures design decisions from the Task 6 discussion. Reference for future tasks (especially Task 9 benchmarks, oneiron-internal query layer).

---

## 1. PPR Placement: Pre-RRF, Post-RRF, or Both

### Problem

SCHEMA-DESIGN.md lists PPR as step 6 (post-RRF expansion), but BUILD-PROMPT.md lists PPR alongside vector/BM25 as an input to RRF fusion. Which is correct?

### Two valid architectures

**Pre-RRF (PPR as 5th signal):**
- Query → NER → extract entities → PPR from those seeds → ranked list → RRF with other 4 signals
- Pros: PPR can surface entities with zero text/vector overlap but strong graph connections. Runs in parallel with other signals.
- Cons: **Requires NER on every query** to produce seeds. NER is an LLM call (expensive).

**Post-RRF (PPR as graph expansion):**
- 4 signals → RRF fuse → take top-K as seeds → PPR expand → re-fuse
- Pros: **No NER required** — seeds come automatically from top results. Works out of the box.
- Cons: Can only expand what was already found. Circular — PPR re-ranks existing results rather than discovering truly new entities.

### Decision

**Support both.** Two separate pipeline methods:
- `expand_ppr(seeds, depth)` — post-RRF expansion using RRF top results + optional explicit seeds
- `search_ppr(seeds, depth)` — pre-RRF signal, PPR as a 5th ranked list into fusion

The caller picks which (or both). Task 9 benchmarks will compare recall/latency across: pre-only, post-only, both.

**Key insight:** Post-RRF avoids mandatory NER on every query. Pre-RRF is better when NER output is available (richer seeds from query entities). The crate supports both; oneiron-internal decides based on context.

---

## 2. Temporal Scoring: From Linear Cutoff to Sigmoid Decay

### Problem with linear formula (from SCHEMA-DESIGN.md)

```text
s_occurred = 1.0 - |midpoint(entity) - midpoint(query)| / (query_range / 2)
```

This linearly drops to **zero** at the range boundary. For "what happened 5 years ago?":
- If range is narrow (1 day), anything outside that day scores 0.0
- An entity from 5 years + 2 weeks ago? Dead zero. Wrong.

### Alternatives considered

**Hindsight (pure exponential):**

```text
w = exp(-delta_t / sigma_t)
```

- Never reaches zero (asymptotic). Better than linear.
- No floor — very old memories effectively vanish.

**Mnemosyne (reverse sigmoid with floor):**

```text
τ(e_eff) = (1 - d) / (1 + exp((e_eff - a) / b)) + d
```

Where:
- `a` = midpoint (default: 4 weeks) — where steep dropoff happens
- `b` = steepness (lower = steeper)
- `d` = floor (default: 0.05) — old memories never fully forgotten
- Models Ebbinghaus forgetting curve

### Decision

**Use Mnemosyne-style sigmoid with floor for `s_occurred`:**

```text
s_occurred = (1 - floor) / (1 + exp((|distance| - midpoint) / steepness)) + floor
```

Where:
- `floor = 0.05` (5% — old memories always retrievable)
- `midpoint` derives from query range width or explicit sigma
- `steepness` scales with midpoint

**Keep exponential decay for `s_learned`** (recency of when we recorded it):

```text
s_learned = exp(-(now - learned_at) / λ)    // λ = 28 days (Mnemosyne default)
```

**Combined:**

```text
s_temporal = α × s_occurred + (1-α) × s_learned    // α = 0.7 default
```

---

## 3. Temporal Granularity & NER SFT

### Problem

The crate receives `anchor_start` and `anchor_end` as raw u64 timestamps. But temporal scoring needs to know **how uncertain** the query is. "Last Tuesday" is precise; "5 years ago" is vague. The scoring decay shape must adapt.

### Solution: three API tiers

```rust
// Tier 1: Infer from range width (simplest, no extra params)
pub fn search_temporal(self, start: u64, end: u64, limit: usize) -> Self;

// Tier 2: Explicit sigma (caller controls decay width in seconds)
pub fn search_temporal_with_sigma(self, start: u64, end: u64, sigma_secs: u64, limit: usize) -> Self;

// Tier 3: Granularity enum (maps to sigma internally)
pub fn search_temporal_with_granularity(self, start: u64, end: u64, granularity: TemporalGranularity, limit: usize) -> Self;
```

Tier 1 derives sigma from `end - start`. Tier 2/3 let the caller be explicit.

### NER SFT for temporal extraction (oneiron-internal scope)

**Key insight:** If we're already fine-tuning a NER model for entity extraction, we can extend the training data to include temporal expressions with granularity labels. The model outputs:

```json
{
  "entities": [
    {"text": "Alice", "type": "PERSON", "id": "pr42"}
  ],
  "temporal": {
    "expression": "5 years ago",
    "range": [1613347200, 1644883200],
    "granularity": "year"
  }
}
```

The `granularity` field maps directly to `TemporalGranularity` in the crate:

| Granularity | Example | Sigma (seconds) |
|------------|---------|-----------------|
| `Exact` | "at 3:15pm" | 3,600 (1h) |
| `Hour` | "that afternoon" | 14,400 (4h) |
| `Day` | "last Tuesday" | 86,400 (1d) |
| `Week` | "last week" | 604,800 (1w) |
| `Month` | "in March" | 2,592,000 (30d) |
| `Season` | "last summer" | 7,776,000 (90d) |
| `Year` | "5 years ago" | 15,552,000 (180d) |
| `Vague` | "a while back" | 31,536,000 (365d) |

**Training data sources for SFT:**
- Existing NER datasets with DATE/TIME tags (CoNLL, OntoNotes)
- Temporal expression datasets (TempEval, TimeBank)
- Custom labeled examples from Eiri conversations
- Granularity labels derived from expression type (rule-based annotation, then SFT)

**This is oneiron-internal scope** — the crate provides the `TemporalGranularity` enum and the three API tiers. The NER model, SFT pipeline, and temporal expression parsing live in oneiron-internal.

---

## 4. References

- **Hindsight paper:** `/Users/olety/Desktop/code/eiri-papers/markdown/Hindsight.md` — TEMPR temporal retrieval, `exp(-delta_t / sigma_t)` decay
- **Mnemosyne paper:** `/Users/olety/Desktop/code/eiri-papers/markdown/Mnemosyne.md` — reverse sigmoid with floor, `τ(e_eff) = (1-d)/(1+exp((e_eff-a)/b)) + d`, Ebbinghaus forgetting curve
- **SCHEMA-DESIGN.md:** Original temporal scoring formula (`s_occurred`, `s_learned`, `s_temporal`)
- **BUILD-PROMPT.md §6.4:** RRF oversampling ratios (vector 3×, BM25 3×, PPR 2×)
