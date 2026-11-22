# Engine work this skill needs

Hub rule: a folder that needs a missing engine mechanism names it here and does not fake it. Checked against oneiron `origin/main` at `0fdfe222c` on 2026-10-08. Paths are under `crates/oneiron/src/` unless they say otherwise. RESEARCH-0651 is the fuller plan; its Tier 0 (the ruler) comes first.

## Blocking: the slow loop cannot tune retrieval yet

1. **Retrieval is not a skill row.** The engine seeds four skills only (`skill_hub/bootstrap.rs:38`). No seeded retrieval skill and no transition-table script exist; OF-092's FSM is unfinished. Work: seed the retrieval skill, with its parameters as data.
2. **No parameter object.** About 25 scoring numbers are compiled in (`pipeline/types.rs:35-129`, `crates/oneiron-retrieval/src/fusion.rs:38`, `pipeline/blend.rs:344`, `ppr/policy.rs:70-126`, `memory/recall/mod.rs:40,93-108`). Some inputs already take per-query values: BM25F weights, b and formula (`config.rs:427-452`), temporal sigma (`pipeline/builder/mod.rs:305-325`), rerank options (`rerank.rs:57-65`) and per-entity access factors (`pipeline/builder/mod.rs:237-249`). There is no single parameter object. Work: a `RetrievalParams` with shipped values, validation, a digest and a knob schema (path, range, whether it needs a rebuild), passed per call and never stored as a policy row.
3. **The loop edits text only, and reads no skill files.** `skill_optimize` drafts a new `desc` of at most 4096 bytes (`skill_optimize/job.rs:396-508`, `skill/record.rs:40`). Its brief carries the target's `desc` and dev-split evidence, not package files (`skill_optimize/brief.rs:48-87`). Nothing can hand it this skill. Work: let a loop over a target load a linked knowledge skill, as an attempt loads a skill pack (`skill/pack_load.rs:70`); and add a parameter-edit draft (knob path, from, to) beside the text edit.
4. **No retrieval replay.** Runs can capture query-free replay metadata when trace and telemetry capture are both on (`pipeline/builder_capture.rs:17-19`). The query packet and corpus snapshot are host-owned references and optional today (`store/retrieval_telemetry/state.rs:110-119`). Finalized runs keep z-scored components for surfaced ids only, so a half-life change cannot be re-scored from them (`store/retrieval_telemetry/run_store.rs:569-584`). `oneiron-bench beam corpus-replay` prints stored packs and does not rerun retrieval (`crates/oneiron-bench/src/retrieval_turn_corpus.rs`). The held-out scorer judges skill text (`skill_optimize/gate/basis.rs:288`). Work: rerun a stored run under candidate parameters with a pinned clock and corpus snapshot, and key each experiment by engine commit, parameter digest and pack digest. The fork hash has no engine commit (`pipeline/trace/trace_fork_hash.rs:31`).
5. **No gated outcomes in production.** The end-outcome door checks a supplied `gate_score` (`store/retrieval_telemetry/end_outcome.rs:21`, `types.rs:362-413`). Only tests and `oneiron-bench eval outcome-ingest` supply one. No Dreamer job computes the gate. Work: the attribution gate as a Dreamer job, and a rule for turns with several runs; today credit goes only to the run named (`types.rs:388-389`).
6. **No ruler.** No retrieval pack, no scorecard and no acceptance rule exist. `MetricAxis` has no tolerance, so latency jitter escalates everything (`autoreason_campaign/general.rs:37`). Work: RESEARCH-0651 Tier 0.

## The fast loop is not built yet

7. **No retrieval bandit.** No arms, no effort-envelope eligibility, no shipped prior, no stored posterior and no update at sleep. The shared `Posterior` serves skills and critics only (`crates/oneiron-contracts/src/posterior.rs:17`). Work: OF-092.
8. **The blend tuner is the only learner, and it has no guard.** One gradient step per explicit call; it overwrites the active row with no hold-out and no candidate slot (`store/retrieval_telemetry/blend_tuning.rs:57-191`). Nothing schedules it. Work: write candidates beside the active row and promote by held-out check.
9. **`RetrievalState` is mostly empty.** A one-shot run fills 6 of 16 fields (`store/retrieval_telemetry/state.rs:32-79`). Nothing writes `last_action` or `intent_class`, and no intent router exists.
10. **No policy verbs are logged.** `RetrievalAction` is a call-site tag (`store/retrieval_telemetry/types.rs:63-72`). So ARCH-0037's Expand firing-rate check (10 to 30%) cannot be measured.

## Smaller gaps the playbook runs into

11. **The plain recall door sends no query embedding.** `Memory::recall` passes an empty `RecallExecution` (`memory/recall/mod.rs:285-300`; `retrieval_depth/controls.rs:47-53`), and the server facade recall calls it (`crates/oneiron-server/src/api/facade/agent_verbs.rs:136-142`). Through these doors the vector and phonetic channels never run. Work: embed the query when the vault has an embedder, or say so in the response.
12. **Half-lives are compiled.** ONE-1186-D3 tunes weights and half-lives; only weights tune (`pipeline/types.rs:69-99`).
13. **A dead knob.** `boost_recency(half_life_days)` reads its argument only as on or off (`pipeline/builder/mod.rs:484-490`).
14. **PPR damping is written twice.** `PPR_DAMPING` (`pipeline/types.rs:117`) and a literal 0.15 (`ppr_community/bridge.rs:33`). A tuned value would diverge.
15. **No event-level diversity or MMR.** Many records of one event can fill a pack. A default-off community selection exists (`ppr_community/scoring.rs:167`), but it does not de-duplicate events. MMR sits on the OF-091 backlog.
16. **The vector bench cannot compare candidate settings.** `oneiron-bench vector` builds a synthetic vault with fixed HNSW settings (`crates/oneiron-bench/src/vector/vector_run.rs:190-199`). Work: run incumbent and candidate settings on one corpus and query set against brute force.
17. **No citation or fetch feedback.** `RetrievalFeedback` (ARCH-0037) does not exist, so explicit citations cannot feed the reward.
18. **The recall budget is a fixed 4000 tokens** (`memory/recall/mod.rs:45`). ARCH-0004 sets the budget as a share of the caller's context window; no such share exists in the engine.
19. **No fold thresholds.** The engine has no fold-threshold knob to tune.
