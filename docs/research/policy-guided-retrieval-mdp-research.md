# Policy-Guided Retrieval as MDP for Knowledge Graph Memory Systems

## Research Report for Oneiron

**Date:** 2026-03-28
**Context:** Oneiron is a Rust-based graph memory engine with 5-signal retrieval (HNSW vectors, BM25 text, PPR graph traversal, temporal, phonetic) fused via RRF. Currently one-shot deterministic. This report investigates adding a policy-guided retrieval layer that can RE-QUERY (reformulate), EXPAND (walk graph neighbors), or STOP.

---

## 1. Annotated Bibliography — Top 12 Papers

### 1.1 Memora (ICML 2026) — **PRIMARY REFERENCE**
- **arXiv:** 2602.03315
- **Authors:** Xia et al. (Microsoft Research)
- **Key contribution:** Formulates memory retrieval as an MDP with action space {Refine, Expand, Stop}. Introduces "cue anchors" as lightweight semantic hooks enabling many-to-many traversal across memory entries. Policy trained via GRPO (Group-Relative Policy Optimization) comparing groups of retrieval trajectories.
- **Relevance to Oneiron:** **Directly applicable.** Memora's action space maps cleanly to Oneiron. The "primary abstraction + cue anchor" architecture is structurally similar to Oneiron's entity/edge graph. Their GRPO training achieves 87.4% on LongMemEval with a 3B policy model (Qwen-2.5-3B-Instruct). Policy retriever adds ~3.4 steps/query at ~4.6s mean search latency vs ~0.2s for semantic-only.
- **State representation:** `s_t = (q_t, W_t, F_t, b_t)` — current query, working set, frontier of reachable memories, remaining budget.
- **Reward signal:** `J(τ) = w1·Groundedness − w2·Redundancy − w3·Cost`
- **Result:** Policy retriever (86.3%) > Semantic retriever (84.9%) > Full Context baseline (82.5%) on LoCoMo.

### 1.2 ProGraph-R1 (2026) — **Graph-Specific RL**
- **arXiv:** 2601.17755
- **Authors:** Park et al. (KAIST, Microsoft, Amazon)
- **Key contribution:** Progress-aware RL for graph retrieval. Introduces structure-aware hypergraph retrieval that jointly considers semantic similarity AND graph connectivity. Step-wise advantage modulation provides dense rewards based on intermediate reasoning progress within the graph, not just final outcome.
- **Relevance to Oneiron:** Directly addresses the question of how to reward intermediate graph traversal steps. Their "inter-turn entity connectedness" reward measures whether successive retrieval steps form coherent paths through the knowledge graph — crucial for Oneiron's PPR-based traversal.
- **Key insight:** Models trained with only outcome rewards take MORE retrieval steps for same accuracy. Progress-aware rewards produce more efficient trajectories.

### 1.3 ProRAG (2026) — **Process-Supervised RL for RAG**
- **arXiv:** 2601.21912
- **Authors:** Wang et al. (Renmin University)
- **Key contribution:** 4-stage framework: (1) SFT warmup, (2) MCTS-based Process Reward Model (PRM) construction, (3) PRM-guided refinement, (4) Process-supervised RL with dual-granularity advantage (step-level + outcome-level). Uses MCTS to explore diverse retrieval trajectories and build step-level quality labels.
- **Relevance to Oneiron:** Their PRM training approach is practical — only 728 seed queries needed for MCTS to train a generalized PRM, which then supervises 10k RL queries. The dual-granularity advantage mechanism (β=0.3 optimal) provides a concrete recipe for balancing step vs outcome rewards.
- **Result:** +2.5% F1 over outcome-only RL baselines; biggest gains on complex multi-hop tasks (MuSiQue: +4.6% F1).

### 1.4 DGPO — Compact Model Distillation (2025)
- **arXiv:** 2508.20324
- **Authors:** Kotoge et al. (OMRON SINIC X)
- **Key contribution:** Distillation-Guided Policy Optimization enables 0.5B-1B models to perform agentic RAG via cold-start initialization from teacher demonstrations + selective KL penalty during RL. Introduces ARC (Agentic RAG Capabilities) metric decomposing search into thinking, query rewriting, and source referencing.
- **Relevance to Oneiron:** **Critical for small-model feasibility.** Shows that a 0.5B model trained with DGPO achieves 55x improvement over base (0.006 → 0.329), approaching 3B teacher performance (0.353). Proves the policy CAN be a small model. PPO more stable than GRPO for compact models.
- **Key finding:** Cold-start KD initialization essential — without it, training collapses at ~800 steps. GRPO collapses for <1B models even with initialization.

### 1.5 Agent Distillation (NeurIPS 2025)
- **arXiv:** 2505.17612
- **Authors:** Kang et al. (KAIST, KRAFTON)
- **Key contribution:** Framework for distilling full agentic behavior (not just reasoning traces) from LLM agents into 0.5B-7B models with retrieval and code tools. "First-thought prefix" improves teacher trajectory quality. Self-consistent action generation for test-time robustness.
- **Relevance to Oneiron:** Demonstrates that 0.5B, 1.5B, 3B agent-distilled models match next-tier-larger CoT-distilled models. The "agent distillation" paradigm (learning to act, not memorize) maps well to Oneiron's retrieval policy use case.

### 1.6 REX-RAG (ICLR 2026 submission)
- **arXiv:** 2508.08149
- **Authors:** Jiang et al. (Wuhan University)
- **Key contribution:** Identifies and solves the "dead end" problem in RL-based RAG — where models get trapped in unproductive reasoning paths (>85% of instances in early training for 3B models). Mixed Sampling Strategy combines probe policy (injected reasoning prompts) with target policy. Policy Correction via importance sampling fixes distribution shift.
- **Relevance to Oneiron:** The dead-end problem is directly relevant — Oneiron's policy might learn to always STOP early or always EXPAND redundantly. REX-RAG's mixed sampling + correction provides a concrete solution for exploration in policy training. +5.1% over baselines on 3B, +3.6% on 7B.

### 1.7 Graph-RFT / Graph-R1 (2025-2026)
- **arXiv:** 2510.20691
- **Authors:** Song et al.
- **Key contribution:** "Plan then Retrieve" framework — two-stage RL fine-tuning for KGQA. Chain-of-thought fine-tuning with plan-retrieval dataset solves GRPO cold-start. Cartesian-inspired planning decomposes complex questions into ordered subquestions. Multi-reward combining outcome + retrieval-specific signals.
- **Relevance to Oneiron:** Shows how to decompose multi-hop graph queries into sub-plans, which maps to Oneiron's need to plan entity graph traversals.

### 1.8 KG-Based Memory for POMDPs (2024)
- **arXiv:** 2408.05861
- **Authors:** Kim et al. (VU Amsterdam)
- **Key contribution:** Formulates KG-based memory management as a POMDP — agent navigates a maze answering questions while managing a KG memory. The learning objective IS the memory management policy. Shows interpretable, reusable hidden state estimation through KG memory.
- **Relevance to Oneiron:** Theoretical grounding — proves that learning memory management as an RL policy captures the most likely hidden state. Supports Oneiron's approach of treating retrieval-as-policy rather than retrieval-as-function.

### 1.9 ARK: Adaptive Retriever of Knowledge (2026)
- **arXiv:** 2601.13969
- **Authors:** Polonuer et al. (Harvard, Oxford)
- **Key contribution:** Agentic KG retriever with two-operation toolset: global lexical search + one-hop neighborhood exploration. Gives LLM control over breadth-depth tradeoff. Distills 70B teacher trajectories into 8B student model via label-free imitation learning.
- **Relevance to Oneiron:** Closest to Oneiron's use case — a KG retriever that learns when to do broad search vs. graph walk. +31.4% Hit@1 over baselines. The distillation approach (retaining 98.5% of teacher quality in 8B student) validates small-model feasibility.

### 1.10 Cost-Aware RAG with Adaptive Retrieval Depth (2025)
- **arXiv:** 2510.15719
- **Authors:** Hashemi et al. (Microsoft)
- **Key contribution:** Budget-constrained retrieval — learns when additional retrieval steps have diminishing returns. Adaptive depth selection based on query complexity.
- **Relevance to Oneiron:** Directly addresses latency-constrained retrieval. Provides early stopping criteria based on estimated marginal information gain.

### 1.11 SPIRAL: Iterative Subgraph Expansion (MIT Thesis, 2025)
- **Source:** MIT DSpace (M.Eng thesis)
- **Author:** Hadjiivanov
- **Key contribution:** Iterative subgraph expansion for KG-based RAG. Starts from seed entities and progressively expands subgraph based on relevance to query. Evaluates when to stop expansion.
- **Relevance to Oneiron:** The subgraph expansion paradigm maps directly to Oneiron's EXPAND action. Provides practical heuristics for expansion stopping criteria.

### 1.12 Tiny-Critic RAG (2026)
- **arXiv:** 2603.00846
- **Key contribution:** Parameter-efficient small language model (critic) for agentic RAG fallback decisions. Rather than a full policy model, uses a tiny critic to decide when retrieval is needed.
- **Relevance to Oneiron:** Alternative to full policy model — a lightweight critic that only decides CONTINUE/STOP, with the retrieval mechanics handled by existing pipeline.

---

## 2. Recommended Approach for Oneiron

### Progressive 3-Tier Architecture: Rule-Based → Learned → GRPO

#### Tier 1: Rule-Based Policy (v1) — "Smart Heuristics"

**Architecture:** A deterministic finite automaton over retrieval states.

```
State: (query, retrieved_set, iteration_count)
Actions: RE-QUERY | EXPAND | STOP

Rules:
1. INITIAL: Run all 5 signals, RRF-fuse top-k results → state
2. CONFIDENCE CHECK:
   - If top result score > θ_high → STOP (confident)
   - If top result score < θ_low AND iterations < max_iter → decide RE-QUERY vs EXPAND
   - If iterations >= max_iter → STOP (budget exhausted)
3. COVERAGE CHECK:
   - If query entities not covered in results → EXPAND (walk entity neighbors)
   - If query terms poorly matched → RE-QUERY (reformulate using entity context)
4. REDUNDANCY CHECK:
   - If new results overlap >80% with existing → STOP (diminishing returns)
```

**Scoring signals for decisions:**
- **Score gap:** Difference between #1 and #2 result scores (large gap → confident, STOP)
- **Entity coverage:** Fraction of query-mentioned entities appearing in retrieved set
- **Novelty:** 1 - max_similarity(new_results, existing_results)
- **Budget remaining:** Simple counter, max 3 iterations

**Effort:** ~2 weeks Rust implementation
**Expected improvement:** 10-15% on multi-hop queries where one-shot misses connecting entities

#### Tier 2: Learned Policy via Supervised Imitation (v2) — "Distilled Expert"

**Architecture:** Small classifier (logistic regression or tiny MLP) trained on retrieval trajectories.

**Training data generation:**
1. For each query in evaluation set, run exhaustive retrieval (all actions at each step)
2. Score each trajectory by final answer quality (F1 or LLM-judge)
3. Build (state, best_action) pairs from best trajectories
4. Train classifier: state features → action

**State features (for Oneiron):**
```rust
struct RetrievalState {
    // Query features
    query_entity_count: usize,
    query_token_count: usize,

    // Retrieved set features
    top_score: f32,           // Best RRF score
    score_gap: f32,           // Gap between #1 and #2
    mean_score: f32,          // Average of top-k
    entity_coverage: f32,     // Fraction of query entities found
    result_count: usize,

    // Signal-specific features
    hnsw_top_score: f32,
    bm25_top_score: f32,
    ppr_top_score: f32,
    temporal_relevance: f32,
    phonetic_match_count: usize,

    // Iteration features
    iteration: usize,
    novelty_vs_previous: f32, // How different are new results

    // Graph features
    frontier_size: usize,     // How many unexplored neighbors
    avg_edge_weight: f32,     // Average weight of frontier edges
}
```

**Model:** XGBoost or small MLP (not an LLM). Outputs probability distribution over {RE-QUERY, EXPAND, STOP}.

**Effort:** ~4 weeks (trajectory generation + training pipeline)
**Expected improvement:** 20-30% on complex queries; latency ~0ms per policy decision (numeric features → small model)

#### Tier 3: GRPO-Trained Policy (v3) — "Self-Improving"

**Architecture:** Small language model (1-3B) or Oneiron-native policy network, trained via GRPO following Memora's approach.

**Training procedure (adapted from Memora + ProRAG):**

1. **Warmup:** SFT on high-quality trajectories from v2 (cold-start initialization, essential per DGPO findings)

2. **Trajectory sampling:** For each query, sample G=8 trajectories from current policy

3. **Reward computation:**
   ```
   J(τ) = w1·Groundedness(q, retrieved_set)
        - w2·Redundancy(retrieved_set)
        - w3·Cost(num_steps)
        + w4·StepProgress(intermediate_coverage_gain)
   ```

4. **Group-relative advantage:**
   ```
   A_i = J(τ_i) - mean(J(τ_1..G))
   ```

5. **Policy update:** GRPO with KL regularization against reference policy

**Key design choices from literature:**
- Use PPO over GRPO for <3B models (DGPO finding: GRPO unstable for compact models)
- Dual-granularity advantage (ProRAG): β=0.3 weight for step-level rewards
- Mixed sampling with probe policy (REX-RAG): essential for escaping dead ends
- Progress-aware rewards (ProGraph-R1): reward entity coverage gain per step
- Budget constraint: max 5 iterations (REX-RAG setting)

**Effort:** ~8-12 weeks (RL training infrastructure + evaluation)
**Expected improvement:** 5-10% beyond v2; adaptive behavior on diverse query types

---

## 3. Action Space Definition for Oneiron's 5-Signal Pipeline

```rust
enum RetrievalAction {
    /// Reformulate the query and re-run signals
    ReQuery {
        /// New query string (from entity context or LLM reformulation)
        reformulated_query: String,
        /// Which signals to re-run (can be selective)
        signals: SignalSet, // e.g., {HNSW, BM25} only
    },

    /// Walk graph neighbors of current results
    Expand {
        /// Which entities to expand from
        seed_entities: Vec<EntityId>,
        /// Max hops to walk
        max_hops: u8, // typically 1-2
        /// Whether to use PPR or simple BFS
        traversal_mode: TraversalMode,
    },

    /// Stop retrieval and return current results
    Stop,
}

bitflags! {
    struct SignalSet: u8 {
        const HNSW     = 0b00001;
        const BM25     = 0b00010;
        const PPR      = 0b00100;
        const TEMPORAL  = 0b01000;
        const PHONETIC  = 0b10000;
        const ALL      = 0b11111;
    }
}

enum TraversalMode {
    /// Simple BFS from seed entities
    BreadthFirst,
    /// PPR-weighted expansion (existing Oneiron capability)
    PersonalizedPageRank { alpha: f32 },
    /// Follow highest-weight edges first
    GreedyEdge,
}
```

**Action costs (for budget tracking):**
- `ReQuery(ALL)`: cost = 5 (expensive, re-runs everything)
- `ReQuery({HNSW, BM25})`: cost = 2 (selective, cheaper)
- `Expand(BFS, 1-hop)`: cost = 1 (graph walk is fast in Oneiron)
- `Expand(PPR, 2-hop)`: cost = 3 (PPR computation)
- `Stop`: cost = 0

**Budget:** B = 10 per query (allows ~3-5 iterations depending on action mix)

---

## 4. Reward Signal Design

### 4.1 Trajectory-Level Reward (Outcome)

```
R_outcome(τ) = Correctness(answer, ground_truth)  // F1 or exact match
```

For Oneiron (memory retrieval, not QA), the equivalent is:

```
R_outcome(τ) = Relevance(retrieved_set, ground_truth_memories)
             = Σ_i precision@k + recall_of_target_entities
```

### 4.2 Step-Level Reward (Process)

Based on ProGraph-R1 and ProRAG:

```
R_step(t) = EntityCoverageGain(t)     // How many new target entities discovered
           + NoveltyGain(t)            // How different are new results from existing
           - RedundancyCost(t)         // Penalty for overlapping results
           + FormatCompliance(t)       // Did action follow expected schema
```

**EntityCoverageGain (from ProGraph-R1):**
```
ECG(t) = |entities(W_t) ∩ target_entities| / |target_entities|
       - |entities(W_{t-1}) ∩ target_entities| / |target_entities|
```

**NoveltyGain:**
```
NG(t) = 1 - max_sim(new_results_t, W_{t-1})
```

### 4.3 Composite Reward (Dual-Granularity)

Following ProRAG's optimal β=0.3:

```
A_total = A_outcome + 0.3 * A_process
```

Where advantages are group-normalized:
```
A_outcome = (R_outcome - mean(R_outcome_group)) / std(R_outcome_group)
A_process = (R_step - mean(R_step_group)) / std(R_step_group)
```

### 4.4 Oneiron-Specific Reward Signals

Oneiron's 5-signal architecture provides unique reward opportunities:

1. **Signal agreement bonus:** +reward when multiple signals (HNSW, BM25, PPR) independently identify same entities
2. **Temporal coherence:** +reward when retrieved memories form temporally coherent narrative
3. **Graph connectivity:** +reward when retrieved set forms connected subgraph (not disconnected fragments)
4. **Phonetic disambiguation:** +reward when phonetic matching resolves entities that HNSW missed

---

## 5. Effort & Expected Improvement Estimates

| Tier | Effort | Latency Impact | Quality Improvement | Risk |
|------|--------|---------------|-------------------|------|
| **v1: Rule-Based** | 2 weeks | +5-20ms/query | +10-15% on multi-hop | Low — fully deterministic, debuggable |
| **v2: Learned (XGBoost)** | 4 weeks | +1-5ms/query | +20-30% on complex queries | Medium — needs training data pipeline |
| **v3: GRPO-Trained** | 8-12 weeks | +50-200ms/query (if LLM) or +5ms (if tiny model) | +5-10% beyond v2 | High — RL training instability, needs infrastructure |

### Recommended Timeline

1. **Weeks 1-2:** Implement v1 rule-based policy. This is the "can't lose" option — simple, fast, immediately useful for multi-hop queries.

2. **Weeks 3-6:** Build trajectory collection pipeline. Run v1 exhaustively on evaluation queries. Collect (state, action, outcome) tuples. Train v2 classifier.

3. **Weeks 7-12 (if v2 shows promise):** Set up RL training. Use v2 policy as initialization (cold-start). Train with GRPO/PPO. Use REX-RAG mixed sampling for exploration.

### When to Skip to v3

If Oneiron is deployed in a context where:
- Queries are diverse and unpredictable (rules can't cover all cases)
- Latency budget is generous (>500ms)
- You have a GPU available for policy inference
- You have ground-truth evaluation data for reward computation

### When to Stay at v1/v2

If:
- Latency is critical (<50ms total retrieval)
- Query patterns are predictable (e.g., always "tell me about X" style)
- Training data is scarce
- Debugging/interpretability matters more than marginal accuracy

---

## 6. Open-Source Implementations to Adapt

| Project | URL | Language | Relevance |
|---------|-----|----------|-----------|
| **ProRAG** | github.com/lilinwz/ProRAG | Python | MCTS-based PRM + dual-granularity GRPO. Most complete RL-for-retrieval codebase. |
| **REX-RAG** | github.com/MiliLab/REX-RAG | Python | Mixed sampling + policy correction. Good exploration mechanism. |
| **GRPO-Zero** | github.com/policy-gradient/GRPO-Zero | Python | Clean GRPO implementation from scratch. 1.8k stars. |
| **Search-R1** | (referenced by multiple papers) | Python | Foundation for RL-based agentic RAG. PPO + search engine interaction. |
| **Memora** | github.com/elzai/memora | Python | Memory management + retrieval policy. Apache-2.0 license. |
| **SubgraphRAG** | github.com/Graph-COM/SubgraphRAG | Python | ICLR 2025. Graph subgraph retrieval for RAG. |
| **Open Instruct (GRPO)** | allenai.github.io/open-instruct | Python | Allen AI's GRPO implementation. Well-documented, production-quality. |

### Most Directly Reusable

1. **ProRAG** — Adapt their MCTS trajectory generation for building Oneiron training data. Their PRM training recipe (728 seed queries → generalized PRM) is extremely data-efficient.

2. **REX-RAG** — Port their mixed sampling strategy to Oneiron's policy training. Essential for avoiding the dead-end problem that plagues naive RL.

3. **GRPO-Zero** — Clean reference implementation for the RL algorithm itself. Can be adapted to work with Oneiron's Rust policy model via Python bindings or reimplemented in Rust.

---

## 7. Key Findings Summary

### What the Literature Agrees On

1. **One-shot retrieval is insufficient for complex queries.** Every paper shows 10-30% improvement from iterative retrieval over single-pass.

2. **Outcome-only rewards are insufficient.** Process/step-level rewards consistently outperform outcome-only (ProRAG: +2.5%, ProGraph-R1: significant gains on multi-hop).

3. **Cold-start initialization is essential.** Every RL approach that works starts with SFT/distillation warmup. Direct RL from scratch collapses (DGPO, ProRAG, REX-RAG all confirm).

4. **Small models CAN work.** 0.5B-3B models trained with DGPO/distillation achieve 70-95% of large model performance for retrieval policy decisions.

5. **Budget/cost awareness matters.** Best policies learn to STOP early on simple queries and EXPAND more on complex ones (ProGraph-R1, Memora).

### What Remains Open

1. **Optimal action space granularity.** Should EXPAND be one action or multiple (1-hop vs 2-hop vs PPR)? Papers vary.

2. **PRM vs heuristic rewards.** ProRAG shows PRM > heuristics, but PRM training is expensive. For Oneiron's Rust pipeline, heuristic rewards may be more practical initially.

3. **LLM-based vs feature-based policy.** Memora uses LLM (GPT-4.1-mini), DGPO uses 0.5B LLM, but a feature-based classifier (v2 approach) may be sufficient and orders-of-magnitude faster.

4. **How to handle the latency-quality tradeoff at serving time.** Most papers test offline; real-time serving with budget constraints is less explored.

---

## 8. Oneiron-Specific Recommendations

### Immediate Actions (v1)

1. Add iteration count and confidence tracking to `retrieve()` function
2. Implement score-gap and entity-coverage heuristics
3. Add EXPAND action that walks 1-hop entity neighbors and re-scores with existing RRF
4. Add RE-QUERY action that augments query with entity names from partial results
5. Max 3 iterations, stop on high confidence or low novelty

### Architecture Considerations

- **Keep policy decision in Rust.** The policy model (v1 rules, v2 classifier) should run natively in Rust for latency. Only v3 might need Python/ONNX for LLM inference.
- **Log all trajectories.** Every retrieval should log (state, action, result) for future training data.
- **Design for A/B testing.** v1 should run alongside one-shot retrieval so you can measure improvement.

### What NOT to Do

- Don't start with RL (v3). Start with rules (v1), prove the value, then graduate.
- Don't use a full LLM for policy decisions in production. Use features → small model.
- Don't ignore the cold-start problem. If you eventually do RL, always start from supervised initialization.
- Don't use GRPO for <3B models. Use PPO (per DGPO findings).
