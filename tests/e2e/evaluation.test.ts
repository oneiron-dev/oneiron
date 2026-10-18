import { afterAll, test } from "bun:test";
import { defineFile } from "./support/run.ts";

const profile = process.env.E2E_PROFILE === "real-small-model"
  ? "real-small-model" : "deterministic";
const suite = defineFile(import.meta, { profile, slots: 1 });
afterAll(suite.flush);

/**
 * Evaluation contracts, in plan order. G01: a missing typed door stays BLOCKED.
 *
 * Binding read: origin/main 264aa549dad4d3a59cb8a7cd92ddc4540c7d2742.
 * Inspected server CLI, api/mod.rs + openapi_registry.rs, generated HTTP facade
 * inputs/results, TypeScript SDK, and the shipped oneiron-bench CLI dispatch.
 * Runtime OpenAPI still must be captured by EngineFixture when these activate.
 *
 * There IS a bench binary. `beam run` and `beam measure` open/seed their own
 * in-process Vault; neither binds an authenticated EngineFixture server.
 * `beam judge`/`score-nuggets` alone exercise a scorer, not a server E2E flow.
 * Do not replace these cases with those commands, a copied benchmark runner,
 * caller-supplied result rows, execute_code, or a cast to an unshipped verb.
 * No endpoint name is invented below. The request/result notes are canon
 * requirements, not declarations that a generated method already exists.
 *
 * Fixtures: evaluation-contracts plus the shared owner-authored observatory
 * note. Synthetic usage/edit/byte cases test contracts, not model quality.
 * No missing human-labelled extraction/update gold is manufactured here.
 */

// EVALUATION-01 — Benchmark manifest and arm admission should work.
// Sources: ARCH-0042 #three-arm-scaffold, #pinned-configs; OF-254/255/261/264/268.
// Fixture: evaluation-contracts.admission; same corpus/questions for every run.
// Request requirements:
//   dataset/corpus sha256, arm/config hash, resolved model_id@revision, params
//   hash, CallPurpose, Durable|BestEffort class and background_tier_enabled.
//   Validate a pinned deterministic plan, then run its tiny supported case.
//   Negative variants omit a revision, mismatch a digest, admit a background
//   purpose with background_tier_enabled=false, or request an unavailable arm.
// Result requirements:
//   validation refusal precedes answer/judge calls and result/card fabrication;
//   accepted card discloses dataset, arm, model, config, prompt and producer pins;
//   unsupported arms have no score; 500K/1M are explicitly unrun and the 10M
//   cell remains `not-yet-run (10M-gated)`. Tiny fixtures prove no tier quality.
// Current gap: the server CLI has no bench command; standalone `beam run`
// RunManifest uses a local dataset and in-process ingest. Do not add a local
// remote-bench adapter in the test or silently treat a missing arm as success.
suite.todo(test, "EVALUATION-01", "waits on authenticated server-backed benchmark manifest validation and arm admission CLI");

// EVALUATION-02 — Independent answer and judge scoring should work.
// Sources: ARCH-0042 #three-arm-scaffold, #comparability-and-scorer; OF-251/253.
// Fixture: evaluation-contracts.scoring; truth is the curated accessWord, not
// an answerer response. Distinct scripted answerer/judge origins and pins.
// Request requirements:
//   an answerer sees only question + untouched pack, not gold/arm/ability;
//   the judge gets fixed gold and three scripted votes, including disagreement.
//   Run TWO prompt-pinned passes: real question for beam-fixed; the literal
//   <question> placeholder for beam-replicate@3e12035. Never reuse fixed-pass
//   judgments and relabel their int-cast result as the replicate pass.
// Result requirements:
//   majority, native nugget scores, per-ability scores, model revision and
//   judge prompt sha256; beam-fixed keeps/clamps 0.5, replicate int-casts it.
//   Include a wrong answer case so judges cannot redefine independent truth.
//   Three-vote evaluation does not assert production typed decisions vote 3x.
// Current gap: docs/beam-evaluation.md and ARCH-0042 #replicate-column-open
// name `int-cast-saw-question` as diagnostic, NOT the ruled replicate column.
// No public server-backed evaluation scoring call supplies both ruled passes.
suite.todo(test, "EVALUATION-02", "waits on server-backed independent answer/judge scoring and true beam-replicate@3e12035 pass");

// EVALUATION-03 — Comparator purity and fairness should work.
// Sources: ARCH-0042 #three-arm-scaffold; OF-256/262/266/267/269.
// Fixture: evaluation-contracts.comparators, same immutable corpus/question set.
// Request requirements:
//   deterministic full engine retrieval/fusion, frozen vanilla vector+BM25F
//   RAG with declared k, agentic read-execute, and empty-context backbone_solo;
//   same full answerer pin and byte-identical answer prompt across paired arms.
//   Chat's cheap answerer is separate; disclose the L0->L1 extractor confound.
//   Freeze all seven comparison axes: benchmark/tier, regime, native metric,
//   backbone + solo, judge/in-family flag, retrieval_k, provenance.
// Result requirements:
//   actual admitted inputs and call evidence show no gold/ability/arm leakage,
//   no harness rerank/summary/repair; solo has zero vault reads; agentic alone
//   gets its documented controls. Paired rows match question, effort and pin.
//   An uncarded row is refused/appendix/dropped, never a comparable headline.
//   Vector-infrastructure cost rows never become accuracy scores. Stub routing
//   cannot prove Oneiron beats RAG, and chat never becomes agency lift.
// Current gap: standalone measured arms link the engine instead of exercising
// the shipped server path. A local imitation would defeat the purity check.
suite.todo(test, "EVALUATION-03", "waits on server-backed paired comparator execution with admitted-input and no-memory control evidence");

// EVALUATION-04 — Cost and effort frontier accounting should work.
// Sources: ARCH-0042 #three-arm-scaffold, #cost-accounting; OF-258/263.
// Fixture: evaluation-contracts.cost; five levels light/medium/high/xhigh/max.
// Request requirements:
//   bounded sweep with declared provider usage/prices, two-question offline
//   denominator, independent answer truth, real target tokenizer, fixed pins.
// Result requirements:
//   accuracy/latency/query dollars remain separate for EVERY level; a frontier
//   is only a secondary view. Include query embed, retrieval/rerank/compression,
//   each REPL call, pack and answer work. Judge overhead stays outside query
//   cost; ingest/extraction/consolidation/index cost is separate and amortized.
//   Provider re-prefill is attributed to the edited block, labelled measured
//   or estimated; it is a subset of input usage, not charged twice. Pack tokens
//   already in answer input are not charged twice either. Check fixed totals
//   in the fixture, but observe actual elapsed latency rather than invent it.
//   No character-count token proxy and no constructed accuracy-win assertion.
// Current gap: ModelRunPlan/MeasuredReport exist in the in-process bench, not
// as server-backed CLI execution/reporting. Usage-only arithmetic is no E2E.
suite.todo(test, "EVALUATION-04", "waits on server-backed five-effort sweep and complete re-prefill/query/offline/judge cost report");

// EVALUATION-05 — Real-knowledge and extraction oracle smoke should work.
// Sources: ARCH-0042 #three-arm-scaffold; ARCH-0027 #ingest-contract; OF-360/433.
// Fixture: evaluation-contracts.knowledge; shared-observatory-note's curated
// person/place/utc/accessWord are the sole QA truth, fixed before any call.
// Typed shapes to preserve:
//   ParsedMessage {messageId, conversationId, platformSource, role, content,
//     occurredAt, recordedAt}; BEAM corpus timestamps come from the dataset,
//   with learned/recorded ordering from session order, never ingest now().
//   Of360GoldDataset {schema_version, dataset_id, revision, completeness,
//     source_refs, cases:[{case_id, turns, gold_memory_points, qa}]}.
//   Of360ExtractionRun {schema_version, run_id, system_id, dataset_id,
//     dataset_revision, cases:[{case_id, extracted_claims, qa_answers}]}.
// Flow: public import -> source/hash/evidence round-trip -> cold retrieval ->
// extraction/update/QA; inspect errors, omissions and hallucinations against
// independently curated gold, plus fixture digest, evidence sources and cost.
// Result must identify seed_subset/smoke and missing full corpus; neither a
// 500-point HaluMem claim nor 10M quality follows. Do not use a generator as
// retriever or let extracted_claims supply their own expected matched_gold.
// Current gaps: `beam fixture-protocol` seeds a local Vault; the public
// vault.research.evaluate_split consumes caller-supplied Of360ExtractionRun
// for a bound campaign, not this real extraction/update executor. Independent
// update/omission/hallucination labels are not supplied by the shared note.
suite.todo(test, "EVALUATION-05", "waits on public extraction/update evaluation executor and independently curated operation-level truth fixture");

// EVALUATION-06 — Edit-view comparison uses equivalent tasks should work.
// Sources: ARCH-0042 #three-arm-scaffold; ARCH-0050 #tested-pointer; OF-479/488.
// Fixtures: evaluation-edit-source, evaluation-edit-expected; task/budgets in
// evaluation-contracts.edit. Both arms start with identical bytes and truth.
// Request requirements:
//   A: sandbox files/shell/git, push arrives as ops;
//   B: read at a version, lease/propose, anchored edits or whole-text update.
//   Same task, source tree, model pin and budget. Drive each via real public
//   executor (CLI/MCP), never write the candidate file from the harness.
// Result requirements:
//   independently read actual artifact bytes and checked/tested frontier;
//   report tokens to parity, success, caught regressions, wall clock and actual
//   dollars per lane. Both see the same frozen outside oracle; candidate code
//   cannot replace the oracle. No presumed SDK winner or judge-scored edits.
// Current gap: `beam edit-path` scores supplied candidate directories, not
// equivalent public executor lanes or edit cost. It also invokes Cargo at
// runtime, which the prepared E2E runner forbids. Do not call it as a fallback.
suite.todo(test, "EVALUATION-06", "waits on paired plain-file/typed-edit public execution and build-free independent artifact oracle");

// EVALUATION-07 — Context-management diagnostics preserve exact values should work.
// Sources: ARCH-0042 #three-arm-scaffold; ARCH-0067 #what; OF-546.
// Fixtures: evaluation-context-value and evaluation-contracts.context. The
// synthetic marked span/state/value are outside truth, not world knowledge.
// Request requirements:
//   same marked-span retention, successive state assignments and over-budget
//   value for each arm; fixed query-time read budget and independent bytes.
//   Offload then recover the WHOLE value, not its preview or only its digest.
//   Canon fold calls: self.fold(span,{note?}) -> pending mark;
//   self.compact({note?}) -> one batched fold + stub;
//   self.unfold(f) -> raw turns appended, not an in-place prefix replacement.
// Result requirements:
//   exact answer bytes, latest state, restored bytes/hash, read budget validity,
//   edit tokens, cache/re-prefill usage and dollars beside correctness. A value
//   above budget must offload, not pass by increasing the query read allowance.
//   Include RESIDENT dynamic vs STREAM incremental board when those diagnostic
//   arms have typed admission; neither a pure renderer nor KV echo proves live
//   context management. No retrieval/world-knowledge quality claim.
// Current gap: no shipped ctx-arms command or generated fold/compact/unfold
// evaluation calls. Generic KV and context-board routes are not this executor.
suite.todo(test, "EVALUATION-07", "waits on public retention/in-place-edit/offload-recover diagnostic arms and typed fold/compact/unfold calls");

// EVALUATION-08 — Run observability links failures to evidence should work.
// Sources: ARCH-0042 #three-arm-scaffold; ARCH-0037 #storage; OF-257/259.
// Fixture: evaluation-contracts.observability; one success and one explicit
// budget-limited attempt, plus independently supplied disengagement outcome.
// Existing typed read: GET /v1/core/run-tree/observe?run_id=<actual run id>
//   -> SSE `run-tree` event data containing
//   {roots:[{job_id,run_id,parent_id,status,failure,events,children}],repairs}.
// Existing receipt reads: vault.receipts.get({receipt_ref}) and vault.receipts.
// Missing evaluation contract: run/turn/activation records joined by actual
// episode_id/turn_idx/run_id; RetrievalState + pack/trace replay lineage;
// linked RetrievalOutcome sidecar, never a success flag inferred from silence.
// Flow: execute both attempts -> read public report -> open every cited receipt
// and source -> record explicit turn outcome -> replay and inspect lineage.
// Result requirements: actual run/turn IDs, producing model/config/fixture
// hashes, reported limit and failure, resolvable content-addressed receipt
// references; disengagement stays an outcome, not silent success. Telemetry is
// opt-in, tenant-local and not CRDT-synced; never inspect its LMDB tables.
// Current gap: run-tree reads do not expose finalized per-turn retrieval state,
// activation/trace export, or typed retrieval outcome ingestion/replay. The
// `eval outcome-ingest` and corpus-export/replay commands open a local vault.
suite.todo(test, "EVALUATION-08", "waits on typed public run/turn/activation evidence report, retrieval outcome ingestion and replay lineage");
