# Reading the retrieval receipts

Checked against engine commit `0fdfe222c`. ARCH-0037 owns these records. Their shapes are a wall: read them, never change them. Paths are in the engine repository, under `crates/oneiron/src/` unless the path says otherwise.

## Where they live

Eight side tables in `vault_meta` (`side_table/decls/vault_meta_m_r.rs:349-380`). ARCH-0037 still describes three LMDB databases; read the code's shape.

| table | key | value |
|---|---|---|
| `retr_run:v0:` | run id | the run row |
| `retr_run_prov:v0:` | run id | marker for a run not yet published; readers skip it |
| `retr_out:v0:` | run id, `:`, key | an outcome row |
| `retr_turn:v1:` | turn id, start time, run id | turn index |
| `retr_trace_fork:v0:` | fork hash, run id | trace index |
| `retr_age:v0:` and `retr_age_run:v0:` | capture time and run id | retention bookkeeping |
| `retr_blend_weights:v0:active` | one key | the active blend table |

Capture is off by default (`VaultConfig.retrieval_telemetry_capture`, `config.rs:281`). Retention keeps 7 days or 1024 runs unless the gate manifest says otherwise (`gate/retrieval_retention.rs:7-8`). One telemetry write failure turns later telemetry writes off (`store/retrieval_telemetry/run_store.rs:249-270`).

## How to read them

| door | returns |
|---|---|
| `Vault::retrieval_runs(limit)` (`vault/search_retrieval.rs:316`) | published runs, newest first |
| `Vault::retrieval_runs_by_turn(turn_id)` (`store/retrieval_telemetry/turn_index.rs:66`) | the run ids of one turn |
| `Vault::retrieval_outcomes(run_id)` (`vault/search_retrieval.rs:358`) | outcome rows, sorted by key |
| `Vault::retrieval_trace_by_fork_hash(hash)` (`vault/search_retrieval.rs:326`) | the latest trace for a fork hash |
| `Vault::retrieval_latency_baseline(limit)` (`store/retrieval_telemetry/turn_index.rs:71`) | p50 and p95 of `elapsed_us` over one-shot runs |
| `Store::retrieval_blend_weight_table()` (`store/retrieval_telemetry/blend_tuning.rs:52`) | the active blend table |

Bench commands (`crates/oneiron-bench`):

- `oneiron-bench eval outcome-ingest`: writes gated end outcomes from a file. Each row names its evaluator and source.
- `oneiron-bench eval tune`: one explicit tuner step on the blend table.
- `oneiron-bench beam corpus-export` and `corpus-replay`: export one turn's runs, states, packs and traces, and print them back. This does not rerun retrieval.
- `oneiron-bench beam trace-export`: traces as JSONL.
- `oneiron-bench vector`: vector recall@10 against brute force.
- `oneiron-bench analyzer`: analyzer throughput and a small retrieval smoke test.

## The run row

`RetrievalRunRecord` (`store/retrieval_telemetry/types.rs:230-258`). It holds no query text and no query hash.

| field | what it tells you |
|---|---|
| `run_id` | a time-ordered id (UUIDv7) |
| `action` | the call site: pipeline, context_pack, vault_search, graph_fs_coreutils or speculative. It is not a policy verb. |
| `started_at`, `elapsed_us` | when the run started and how long it took |
| `state` | the `RetrievalState` (below) |
| `replay_inputs` | `query_ref`, the resolved config snapshot, `corpus_snapshot_ref`; present only when the caller captured them |
| `turn` | `turn_id`, `episode_id`, `turn_idx`; needed to link a gated outcome |
| `signals` | the channels that ran: Vector, Text, Phonetic, Temporal, Ppr, Hyde |
| `result_ids` | the surfaced ids, in rank order |
| `score_breakdown` | per surfaced id: final rank, final score, each signal's component, and the read-side decay factor |
| `total_in_scope`, `claims_suppressed` | how much the scope offered and how much the filters removed |
| `empty_reason` | why the pack came back empty |
| `trace` | the opt-in per-stage trace |
| `quality`, `degradation`, `confidence_adjustment` | the run's own quality report |

`RetrievalState` has the sixteen ARCH-0037 fields (`store/retrieval_telemetry/state.rs:10-27`). A one-shot run fills six of them: `top_score_norm` (the top final score s as s/(1+s)), `score_gap_ratio`, `mean_score_norm`, `result_count`, `novelty_vs_prior` (0 or 1) and `signal_agreement` (`state.rs:32-79`). The other ten stay 0 unless the caller passed a full state. A zero there is not a measurement. Nothing writes `last_action` or `intent_class` yet.

## The outcome row

`RetrievalOutcomeRecord` (`store/retrieval_telemetry/types.rs:417-427`). There are two kinds.

- **Raw.** `record_retrieval_outcome` stores an optional reward with no evidence. It is telemetry, not a label.
- **Gated.** `record_retrieval_end_outcome` takes a `RetrievalEndOutcome`: turn id, activated memory id, `gate_score` in (0, 1], `confirmed_fact_hit`, `latency_scale_us` and `cost_weight`. The engine checks that the run belongs to that turn and surfaced that memory. Then it stores the evidence and the shaped reward (`types.rs:387-413`):

```
reward = gate_score × hit − cost_weight × (elapsed_us / latency_scale_us + hops)
```

A raw outcome can never replace a gated one. Keys are 1 to 128 characters: ASCII letters, digits, `.`, `_`, `-` and `:`. A gated outcome credits only the run it names. Splitting one turn's credit across its runs is not built. The door cannot label an empty run or a memory the run missed.

## The trace

`RetrievalTrace` (`store/retrieval_telemetry/types.rs:217-227`). It is captured per run on request, and only with capture on.

- Stages: `per_channel`, `fused`, `blended`, `reranked`, `final`. Finalizing trims every stage to the surfaced ids.
- The `fused` stage is shown in reciprocal-rank order with k = 60. That order is for display. The ranking itself sums per-channel z-scores.
- `fork_hash` keys the run's inputs: the config, the BM25 profile, the half-life table, the blend weights, the scoring constants and the candidate set. It does not include the engine commit. Pair it with the commit.

## The blend table

`RetrievalBlendWeightTableEntry` (`store/retrieval_telemetry/types.rs:98-124`): the four weights, `tuned_at`, the provenance (source, algorithm, `max_runs`, `learning_rate`, previous `tuned_at`) and the data window (runs, outcomes, candidates, and the time spans they cover). A `tuned_at` of 0 and the algorithm `ret010b.bootstrap.v1` mean the tuner never ran.

## Readings

| reading | how | watch for |
|---|---|---|
| capture health | runs per day; the share with `replay_inputs`; the share with a trace | no rows: capture is off, no retrieval ran, or a write failure turned writes off |
| empty rate | runs with `empty_reason` or no `result_ids`, over all runs; group by `empty_reason` | a jump after an embedder swap |
| channel coverage | the share of runs with each signal in `signals` | Vector near 0% means no query embedding |
| latency | p50 and p95 of `elapsed_us`, by `action` and by effort; read the effort from `replay_inputs.config` (PPR steps, rerank top n) | compare on one machine only |
| reward coverage | the share of runs with a gated outcome; gated outcomes per slice | below the seeds on the main page, do not tune |
| reward | mean shaped reward per slice; the spread of `gate_score`; the hit rate | one evaluator in the metadata is one judge |
| rank of hits | the rank of the activated memory among `result_ids`, for gated hits | a gated outcome always names a surfaced memory, so this shows ordering only; a memory the run never surfaced needs a label for that query and scope |
| possible false abstention | an empty run in a turn where another run's gated outcome confirmed a fact | triage only: the runs may ask different things; confirm with a label for the same query and scope |
| learner health | the blend table's data window and the age of `tuned_at` | `tuned_at` 0 means the tuner never ran |
| slices by language or intent | runs are query-free. Join the turn's message text through `turn` or `replay_inputs.query_ref`, only where the Grant allows, and detect the script there. Never copy that text into a proposal. | `intent_class` is 0 today |
