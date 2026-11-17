# The knobs

Every retrieval knob, checked against engine commit `0fdfe222c`. Paths are under `crates/oneiron/src/` unless they say otherwise.

How to read the columns:

- **default** is what the code ships.
- **in code** is the range the engine accepts. Outside it, the engine refuses.
- **try** is a range one proposal may explore, one step at a time. It is a prior from the sources in [sources.md](sources.md). The vault's held-out runs decide.
- **who**:
  - *bandit*: learned per run inside the envelope. Never set its live value.
  - *learner*: learned by the blend tuner. Never set its live value; you may re-seed the tuner's settings.
  - *skill*: a retrieval-skill parameter by design. Today most are compiled, so a change is engine work plus a proposal.
  - *caller*: set per request by whoever calls retrieval.
  - *host*: a vault or host setting. Recommend it; never set it.
  - *wall*: never changes through tuning.

## Effort and the envelope

The caller picks the level. The bandit, once built, picks inside it. You propose the edges.

| knob | code | default | in code | try | who |
|---|---|---|---|---|---|
| graph depth per level | `memory/recall/mod.rs:93-101` | light 0, medium 1, high 2, xhigh 4, max 10 | PPR depth at most 10 (`ppr/cache_store.rs:37-52`) | move one level by one hop; keep the levels in order | skill |
| rerank top n | `memory/recall/mod.rs:103-108` | 30; 50 at xhigh and max | above 0 | 20 to 100, never below the result limit | skill |
| lease and reranker required | `memory/recall/mod.rs:89-91` | high, xhigh, max | the door refuses without them | — | wall |
| recall PPR seeds | `memory/recall/mod.rs:40` | 8 | at most 256 seeds | 4 to 16 | skill |
| depth-search lane | `retrieval_depth.rs:55-69` | 4 subqueries; 8 seeds; at most 2 rounds of 4 queries | — | — | skill |

At light, retrieval makes no model call and takes no lease. High and up add `expand_ppr` and the rerank. Max also searches both time axes (`pipeline/builder_effort.rs:23-55`).

## Lexical (BM25F)

| knob | code | default | in code | try | who |
|---|---|---|---|---|---|
| k1 | `bm25/config.rs:151` | 1.2 | pinned; no override | — | engine (ONE-BM25-ADPT is parked) |
| Surface weight, b | `bm25/config.rs:128-132` | 1.00, 0.75 | weight finite and ≥ 0; b in [0, 1] (`config.rs:479-530`) | keep weight 1.00 as the anchor; b 0.3 to 0.9 | skill; today caller |
| Stem weight, b | `bm25/config.rs:133-137` | 0.35, 0.65 | same | weight 0.1 to 0.6; b 0.3 to 0.9 | skill; today caller |
| NormalizedOverlay weight, b | `bm25/config.rs:138-142` | 0.55, 0 (no length norm) | same | weight 0.3 to 0.8; b stays 0 | skill; today caller |
| CjkNgram weight, b | `bm25/config.rs:143-147` | 0.45, 0.30 | same | weight 0.3 to 0.8; b 0.1 to 0.5 | skill; today caller |
| formula | `bm25/config.rs:56` | Okapi; BM25+ with delta 1.0 on request | delta finite and > 0 | Okapi | skill; today caller |
| per-language dictionaries | `config.rs:338` | none, so portable n-grams | — | install Sudachi for Japanese | host |
| detection window | `crates/oneiron-retrieval/src/analyzer/detect.rs:19` | 512 bytes | — | — | engine |
| phonetic score | `ports/lmdb_phonetic.rs:51-53` | +1 per matched code; ×1.2 at 2 or more | codes come from the caller | — | caller |

The weights and b are scoring-only: a `Bm25RankProfile` per query changes them with no reindex (`config.rs:427`). A dictionary changes the index itself. Flipping a language between portable and morphological mode on a non-empty index fails closed. The host then runs `clear_text_index`, which clears the old postings and rewrites the analyzer manifest, and reruns its indexing pipeline to rebuild the index (`maintain/builder.rs:178-185`).

## Vectors (HNSW)

| knob | code | default | in code | try | who |
|---|---|---|---|---|---|
| ef_search | `config.rs:250` | 128 | the beam is max(ef_search, limit) (`hnsw/search.rs:108`) | 64 to 512 | host; skill by design |
| m_max_0, ef_construction | `config.rs:248-249` | 64, 200 | persisted; a different value fails the open (`store/open_gates/hnsw_model_gates.rs:114-131`) | leave them | host |
| fast_dims | `config.rs:303` | unset | 1 ≤ fast_dims < dimensions; a change on a populated vault fails the open | leave it until a bake-off picks one | host |
| dimensions | `config.rs:283` | 1024 device, 4096 server | pinned with the model | — | host |
| query embedding | `retrieval_depth/controls.rs:47-53` | none unless the host passes one | — | pass one whenever the vault has an embedder | host |

Distance is cosine (`crates/oneiron-retrieval/src/distance.rs:18-26`). The defaults already sit at the high-recall end. Exact search is the recall oracle. One Lucene study saw negligible speed differences below 100K documents ([sources.md](sources.md)); measure the crossover on this vault's dimensions, filters and hardware. `oneiron-bench vector` checks recall@10 on a synthetic vault with fixed settings, so it cannot compare a candidate setting (NOTES.md).

## Fusion and blend

| knob | code | default | in code | try | who |
|---|---|---|---|---|---|
| channel fusion | `crates/oneiron-retrieval/src/fusion.rs:70-113` | each channel's list is z-scored; a candidate missing from a list gets that list's lowest z; the sum is relevance | a list with one hit or no variance contributes zeros (`fusion.rs:309-328`) | — | skill (formula, Tier 2) |
| relevance log weight | `crates/oneiron-retrieval/src/fusion.rs:38` | 1.0 | fixed | — | skill |
| blend weights | `crates/oneiron-contracts/src/retrieval_telemetry.rs:60-76` | recency 0.35, salience 0.30, confidence 0.20, gravity 0.15 | each finite and ≥ 0; positive sum; normalized to sum to one on read (`store/retrieval_telemetry/blend_tuning.rs:212-220`) | — | learner |
| tuner settings | `store/retrieval_telemetry/types.rs:127-141` | 1024 runs, learning rate 0.05, 1 reward minimum | positive values | learning rate 0.01 to 0.1; reward minimum 30 or more | host today; skill by design |
| recency half-life by entity type | `pipeline/types.rs:69-99` | claim, turn, session and message 28 days; person 365; relationship, place, org 180; event 30; skill and summary 90; notification 7 | unknown types fall back to 28 | ×0.5 to ×2 for one type per proposal | skill; compiled |
| claim access decay by class | `claim/decay.rs:26-35` | durable 365 days, standard 90, ephemeral 14; floor 0.05; superseded, retracted or expired claims 0 | caller overrides in [0, 1] for live claims only | — | skill; compiled |
| contiguity boost | `pipeline/blend.rs:344` | 1 + 0.2 × contiguity, when the caller turns it on | — | — | skill |
| ghost-vector threshold | `pipeline/types.rs:121` | 0.3 cosine | — | re-derive per embedder | skill |

The blend works in log space. It z-scores the summed channel relevance again across the candidate pool, adds it at weight 1.0 to each blend weight times its z-scored signal, then applies exp (`crates/oneiron-retrieval/src/fusion.rs:145-172, 259-265`). The read-side access factor multiplies after that. The trace's `fused` stage shows a reciprocal-rank order with k = 60 for display only (`pipeline/types.rs:56`).

## Graph (PPR)

| knob | code | default | in code | try | who |
|---|---|---|---|---|---|
| damping (teleport) | `pipeline/types.rs:117` | 0.15 | also a literal 0.15 at `ppr_community/bridge.rs:33` | 0.10 to 0.30 | skill; compiled |
| λ budget per edge kind, legacy priors | `ppr/policy.rs:84-118` | belongs_to, claim_of, supports, participates_in 1.0; authored_by 0.9; part_of, attached 0.8; scoped_to 0.7; mentions 0.6; about 0.5; supersedes, merged_into, split_into 0.3; derived_from 0.2 | — | ×0.5 to ×1.5 for one kind per proposal | skill; compiled, and pinned to the docs contract table |
| λ budget, world-model kinds | `ppr/policy.rs:79-83, 110-114` | employed_by 0.10; has_facet, facet_of, in_world, set_in 0.05 | pinned by ARCH-0039 | — | wall; only an owner proposal to the contract changes them |
| opposes λ; untraversed kinds | `ppr/policy.rs:84-130` | opposes 0; child_of, assigned_to, blocked_by, same_as and others not traversed | — | — | wall |
| part_of hop cap | `ppr/walk.rs:531-540` | 2 | — | — | skill |
| seed weights | `ppr/policy.rs:36-46` | search_ppr: 1/ln(1 + max(mentions, 1)); expand_ppr: uniform | — | — | skill |
| VAD alpha | `config.rs:273-275` | 0 | finite, 0 to 0.4 (`config.rs:27-35`); nothing checks a BEAM result at run time | — | host; a nonzero value needs the pinned BEAM recall and latency gate first |
| community prior | `ppr_community/types.rs:13-23` | beta 0 (experiment 0.2); gamma 1.0; multiplier cap 1.5 | bounds cannot be relaxed | — | host |
| cache TTL | `ppr/cache_store.rs:29-36, 53-69` | 24 h when the newest seed's `learned_at` is under 7 days old; 72 h at 7 to 30 days; 168 h after; 24 h when no seed has a usable timestamp | — | — | engine |

The cache key holds the damping, VAD alpha and formula version. A change to any of them makes every cached walk miss once. Warm the cache before you measure latency.

## Temporal

| knob | code | default | try | who |
|---|---|---|---|---|
| sigma | `pipeline/types.rs:36` | 1 day | 0.5 to 7 days, for time-bearing queries | skill; caller may pass one |
| minimum window radius | `pipeline/types.rs:37` | 7 days | — | skill |
| score floor | `pipeline/types.rs:38` | 0.05 | — | skill |
| widening rounds | `pipeline/types.rs:118` | 3, doubling sigma each round | 2 to 5 | skill |
| alpha base, range, tau | `pipeline/types.rs:114-116` | 0.7, 0.3, 90 days | — | skill |
| scan cap | `pipeline/types.rs:119-120` | 4 × limit per axis; 8192 seek buffer | — | engine |

A window the host passes turns off the separate recency blend. The effort's own anchor at now keeps it (`pipeline/builder/mod.rs:379-388`).

## Budgets

| knob | code | default | who |
|---|---|---|---|
| result limit | `pipeline/types.rs:35` | 20 | caller |
| recall token budget | `memory/recall/mod.rs:45` | 4000 | skill; ARCH-0004 wants a share of the caller's window instead |
| context-pack token window | `context_pack/types.rs:22` | 4000 | caller |
| token split | `context_pack/types.rs:216-225` | claims 0.45, turns 0.10, summaries 0.25, other 0.20 | skill |
| capabilities per kind | `pipeline/capabilities.rs:15-18` | 5 | skill |
| deadline | `retrieval_depth/controls.rs:8-37` | none; a stage that started finishes | caller |

## Abstention (RET-01, context packs only)

| rule | code | default | who |
|---|---|---|---|
| anomalous query text | `pipeline/budget.rs:227-255` | a control character other than newline, carriage return or tab; or one non-whitespace character repeated 32 times in a row | wall |
| dual-weak | `pipeline/budget.rs:216-224` | a text and a vector query were both sent, no keyword hit survived, and every vector score is under 0.3 | floor |
| poor gap | `pipeline/budget.rs:260-277` | two or more vector scores, top under 0.5, and (top1 − top2) / top1 under 0.1 | floor |

An abstaining pack returns `BelowThreshold` (`pipeline/execution/channels/mod.rs:755-771`). Other empty reasons are `FilterMatchedNone`, `NoData` and `AllActivated` (`context_pack/empty_pack.rs:16-20`). A HyDE retry skips this check for the retry. All three cosine numbers belong to one embedder. Re-derive them from labelled answerable and unanswerable queries at a target false-abstention rate under 5%.

## HyDE and rerank

| knob | code | default | who |
|---|---|---|---|
| HyDE subqueries | `query_expansion.rs:7` | 3 | host |
| HyDE retry limit | `query_expansion.rs:8-9, 55-60` | max(limit, min(2 × limit, 200)), once | host and caller |
| reranker | `rerank.rs:35` | none; the host injects one | host |

## Interactions

1. Every cosine threshold (abstention, ghost vector) belongs to one embedder. A model swap invalidates them all.
2. Depth adds latency and hops, and the reward subtracts both. A deeper walk has to buy more gated hits than it costs.
3. Fusion fills a candidate's missing channels with that channel's lowest z. A channel with many weak hits shifts everyone's relevance; a channel with one hit adds nothing.
4. The blend reorders only the fused pool. Channel limits bound the pool. The result limit cuts after the post-blend scope filters.
5. Two age systems apply: the blend's recency half-life by entity type, and the read-side access decay by claim class. Shorten one without checking the other and age counts twice.
6. `expand_ppr` takes extra seeds from a preliminary full blend. Recency, salience, confidence and gravity shape that ranking; only the read-side access decay waits (`pipeline/execution/channels/mod.rs:407-456`). Fusion and blend changes both move graph expansion.
7. A HyDE retry widens channel limits to max(limit, min(2 × limit, 200)) and skips abstention for that retry. Count retries before reading latency.
8. Changing damping or VAD alpha empties the PPR cache's usefulness once. Measure latency warm.
