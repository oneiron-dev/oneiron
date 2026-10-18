import { afterAll, test } from "bun:test";
import { defineFile } from "./support/run.ts";

/**
 * Typed judgments and telemetry (OF-092/093/105/106/259/260/265/403/493/506/508/516).
 *
 * Binding readback: HEAD d87313d7b261258435d5a202005367540be19608;
 * origin/main 1aec7a3c94647f7f2cb012aaa9e4e3c2ff3d7cd3 has no changes to the
 * inspected SDK, server API, decision configuration/host or CLI files.
 * Read packages/oneiron-client/src/{facade,facade-types}.ts, the public
 * Oneiron SDK, server OpenAPI assembly, api/{facade,saved_query}.rs,
 * api/facade/graph_ask_doors.rs, config/models/{decisions,decision_read}.rs,
 * decision_host.rs and cli.rs. Runtime OpenAPI is diagnostic, not an oracle.
 *
 * G01: keep a whole scenario BLOCKED when a required typed call is missing.
 * Available verdict/graph/question calls are not being called absent. They
 * cannot substitute for the missing setup, admission or observation below.
 * No generic facade cast, execute_code, vault.batch body, private storage or
 * Rust oracle is used to manufacture the missing behavior. In particular,
 * saved_query_oracle.rs supplies invariant ideas only, not its Vault seeding.
 *
 * Canon homes are ARCH-0076 #ask/#record/#escalation-doors-built and
 * #escalation-slot-divergence; ARCH-0036 #model-line; ARCH-0037 #storage;
 * ARCH-0004 #rrf-pipeline; ARCH-0003 #learning; ARCH-0040
 * #mcp-actor-ceilings/#memory-board-source-trust; ARCH-0078 #contract.
 * Source pins and registry coverage are in the shared suite-plan manifest.
 *
 * fixtures/judgments/manifest.json pins seven independently authored input
 * sets. The shared preflight loads them even though these registrations are
 * TODOs. Their aliases are not entity IDs or seeds: future flows resolve
 * them from public creation receipts. Fixture admission vectors are never
 * presented as actual server receipts. No expected value comes from code
 * under test. No new public URL or verb name is invented for a missing door.
 *
 * Activation uses loadFixtures, ScriptedProviders and EngineFixture, fresh
 * authenticated processes and only the documented public calls. No helper
 * replacement is needed. One slot; normal harness deadlines; no sleeps,
 * private clock, mutation retry, model download or changed engine constant.
 */
const profile = process.env.E2E_PROFILE === "real-small-model"
  ? "real-small-model" : "deterministic";
const suite = defineFile(import.meta, { profile, slots: 1 });
afterAll(suite.flush);

/* JUDGMENTS-01 — Typed decision ladder fails closed should work.
 * Fixture: judgments-ladder (ladder.json). OF-493.
 *
 * Existing typed shapes:
 *   ai.verdict({question, contract:{kind:"noul"}, evidence?, state?, ceiling?,
 *     reversibility?, deadline_ms?}) -> {answer, p?, rung?, receipt}.
 *   QuestionDefinition.dial = {first, ceiling, band:{low,high}};
 *   vault.questions.create({definition}) -> QuestionRecord;
 *   vault.questions.refresh({id}) -> AnswerRecord[].
 *   DecisionReceipt = {question, question_version, principal, providers,
 *     band, band_version?, evidence_versions?, paired?, person?, time?, ...}.
 *
 * Activate: publicly declare the fixture's question/version/reversibility
 * band as learned, then enforce it, with an explicit first rung and ceiling.
 * Ask below/in/above that band through HTTP and tool-first MCP. Check the
 * typed answers, probability, measuring pins and receipt principal. Repeat
 * with only an intermediate rung absent: uncertainty may step past it, never
 * past the ceiling. Separately remove the selected first rung, and fail a
 * present first provider with the scripted 503. Neither case may silently
 * try a higher rung or return a successful answer. Exhaust higher providers:
 * explicit abstain, or a queued ask only when the caller permits that role.
 * Compare grants, access to the withheld unit, egress and source trust before
 * and after every case; a yes, or an ask-up request, grants nothing.
 *
 * Blocker: the host starts DecisionBandPolicy in Shadow. A dial's seed band
 * is NOT an enforcement row. No typed HTTP/SDK band learn/enforce call or
 * equivalent host configuration exists. Calling ai.verdict at p=0.5 would
 * not exercise canon's enforced-band step-up; do not turn Shadow into a
 * production rule or substitute the private learn_shadow/enforce methods.
 * ai.verdict chooses its first capable rung itself and refuses a Human
 * ceiling. Use QuestionDefinition.dial for the selected-first cases and a
 * graph ask's permitted ceiling for the role case, not a made-up first field.
 * Optional real-small-model: use only well-formedness, citations, pins,
 * scope and explicit-failure checks for its real bindings, not scripted p.
 */
suite.todo(test, "JUDGMENTS-01", "waits on typed decision-band learning/enforcement (Typed decision ladder fails closed should work)");

/* JUDGMENTS-02 — Graph and artifact question parity should work.
 * Fixture: judgments-parity (parity.json). OF-506/508.
 *
 * Existing typed shapes:
 *   DecisionQuestion = {id, version, text, class, contract, accept_type};
 *   QuestionCriteria = {yes_if_all, no_if_any, not_a_reason_to_say_no};
 *   vault.graph.ask({question, units, criteria?, ceiling?}) ->
 *     {state:"done", answers:AnswerRecord[], abstained, declined} | failed;
 *   vault.questions.edit({id, expected_version, definition}) -> QuestionRecord;
 *   vault.artifacts.ask(ArtifactAskSubmit) -> {proposed?, abstained, refused}.
 *   PairedReading = {provider:{rung,model,version}, question,
 *     question_version, probability}; DecisionReceipt.paired is optional.
 *
 * Activate: create the graph note and artifact paragraph with identical
 * fixture text using public creation/import calls. Ask the same versioned
 * Noul under the asker, inspect each probability and attributable receipt,
 * and confirm the graph claim versus the inert artifact proposal. Edit one
 * criteria line via question edit, rerun both units, and retain v1 receipts
 * unchanged beside v2. Check the withheld-unit negative control too.
 *
 * Admit one valid provider-bound paired reading and read it back unchanged
 * on BOTH adapters. With no measurement, paired must be absent/empty, never
 * a fabricated zero. Submit the duplicate-provider, unmeasured-provider and
 * self-question vectors separately through the eventual typed provider-output
 * admission door. Also exercise zero version and invalid probability. Each
 * invalid vector must be refused before a claim/proposal is minted; compare
 * answer/proposal inventories and source versions before and after refusal.
 *
 * Blocker: returned receipts are typed, but there is no typed HTTP/SDK
 * provider-output admission call for these paired vectors. System One's
 * public wire returns one answer and its adapter sets paired/person to none;
 * the house read binds pairs itself. Neither allows submitting the required
 * wrong-provider/duplicate/self-question evidence for admission. Editing a
 * response in the test process would test the test, not the real gate.
 * ArtifactAskSubmit.question is also unknown in the generated SDK, not a
 * typed shared DecisionQuestion. Do not fill a generic body to bypass G01.
 */
suite.todo(test, "JUDGMENTS-02", "waits on typed paired provider-output admission and artifact question input (Graph and artifact question parity should work)");

/* JUDGMENTS-03 — Standing question and outcome binding should work.
 * Fixture: judgments-standing (standing.json). OF-516/506.
 *
 * Existing typed shapes:
 *   QuestionDefinition = {question,adapter,units,recipe,profile,dial,
 *     activation:"standing",refresh:{on_arrival,every_seconds?},delivery,
 *     learning,binding?,criteria?,audience?,posture?,...};
 *   OutcomeBinding = {source:{kind:"claim",predicate}, horizon, mapping,
 *     noise_weight, linked_by?};
 *   vault.questions.{create,read,backfill,refresh,answers,pause} exist.
 *   pause({id,paused:true}) -> {id,paused};
 *   OutcomeLabel = {answer,fact,fact_value_hash,label,noise_weight,occurred_at}.
 *
 * Activate: install the fixture predicate through the public pack contract;
 * create ONE standing definition, read back its horizon/mapping/noise weight,
 * and answer it via refresh without waiting for a daily timer. Write the
 * later fulfilled fact through its ordinary gate and await the public label
 * projection. Assert exactly one label linked to the answer and original
 * fact, correct mapped true value, 0.75 weight and provenance/hash/time.
 * Replay the same accepted outcome identity: still one label, never a second
 * training example. Read the old answer and definition, pause the schedule,
 * then observe no further provider work, including on manual refresh. Past
 * answers/label must remain readable. Do not make a new fact and call that
 * replay, or accelerate the pump by private clock or queue drain.
 *
 * Blocker: questions.answers returns graph/artifact answer records, not
 * OutcomeLabel/CalibrationPair rows or a schedule-head status. tasks.outcomes
 * returns CalibrationPair[] only for TaskAskHandle {group_ref}, not a standing
 * question. There is no typed standing-label/projection or schedule-head
 * read. Replay uses the original public outcome invocation/fact identity,
 * not an invented replay verb. A task ask, inferred label from a claim list,
 * or an internal projector cannot replace this standing-question scenario.
 */
suite.todo(test, "JUDGMENTS-03", "waits on typed standing-question outcome labels and schedule observation (Standing question and outcome binding should work)");

/* JUDGMENTS-04 — Saved query cache and live membership should work.
 * Fixture: judgments-saved-query (saved-query.json). OF-403.
 *
 * Canon's definition: {scope, filter:FilterAst, matcher:Hard|LlmJudge, eval};
 * version-CAS updates carry expected_definition_version. Verdict evidence is
 * keyed by definition/source revisions; membership is a local projection
 * evaluated as owner_actor, never the viewer. The currently shipped resource
 * HTTP routes create/read/update/archive a query and page its members.
 *
 * Activate: create the scoped leads and a hard-filter-then-judge query as its
 * owner. Execute twice: fixture membership {lead-a}; two initial measurements
 * then zero new measurements for unchanged evidence, with memo-hit receipts.
 * Change ONLY lead-b's source revision (90 -> 110 staff), execute again:
 * {lead-a,lead-b}, exactly one new verdict; lead-a's evidence is reused. Narrow
 * the owner's live grant to lead-a: owner membership must be only lead-a.
 * A wider viewer may be refused query access, but can never recover lead-b
 * or the private lead through this query. The private lead must never reach
 * the provider. Check owner, source pins, measured cost, cache hits and
 * entered/exited causes, not elapsed time as a proxy for caching.
 *
 * Blocker: /saved-queries CRUD/members are routed, but neither generated
 * HTTP facade SDK nor public Oneiron SDK has typed self.saved_query calls.
 * There is no public manual-evaluation/verdict-memo receipt call to perform
 * and observe the two executions. A 60-second Wake/Reactive sweep exists;
 * writes can wake it, but that is not a typed manual evaluation result. Do
 * not use a generic MCP/code-mode call, internal SavedQueryEvaluator or its
 * Rust oracle's seeding as a replacement.
 */
suite.todo(test, "JUDGMENTS-04", "waits on typed saved-query SDK calls and manual evaluation/cache receipts (Saved query cache and live membership should work)");

/* JUDGMENTS-05 — Local retrieval telemetry and replay should work.
 * Fixture: judgments-telemetry (telemetry.json). OF-106/259/260/265.
 *
 * Current recall is {query,effort,scope?,limit?,as_of?,deadline_ms?,...} ->
 * MemoryPack {items,scope_honesty,retrieval_meta,pack_version,narrowing,...}.
 * Canon's instrumented run is RetrievalState/action plus run identity and a
 * separately linked outcome (run_id); trace is opt-in per-stage candidates.
 * A turn outcome names exact retrievalRunIds[], never guessed overlap.
 *
 * Activate: use two fresh independent vaults serially inside this one-slot
 * file (not EngineFixture.peers, which needs two slots). Exercise capture
 * off, capture on without trace, and explicitly enabled trace. Recall the
 * fixed corpus/query, attach an owned outcome to the public serving run,
 * export through supported local diagnostic CLI/HTTP, then repeat the same
 * pinned replay on the SAME vault. Compare ordered source IDs/stage values
 * and fork identity; ignore run occurrence IDs and wall-clock metadata.
 * Change policy, model revision and source frontier ONE AT A TIME; each
 * material change must change that vault's replay identity. Deny cross-vault
 * run reads and outcome attachment with no foreign mutation. The per-vault
 * keyed hashes are not a cross-tenant equality oracle. Exports must contain
 * no raw query, pack text, raw frontier samples or trace key.
 *
 * Blocker: recall exposes neither the telemetry run handle/trace nor typed
 * run/outcome/export/replay operations. The shipped CLI catalog has no such
 * diagnostic commands; oneiron-bench's internal-vault tooling is outside
 * the allowed public server/CLI surface. Generic oneiron api and full-vault
 * export do not supply the missing typed diagnostic contract. Do not persist
 * the query in a fabricated run row or compare hashes across vaults.
 */
suite.todo(test, "JUDGMENTS-05", "waits on typed retrieval run/outcome, trace and diagnostic replay/export doors (Local retrieval telemetry and replay should work)");

/* JUDGMENTS-06 — Learned retrieval policy retains owner pins should work.
 * Fixture: judgments-policy (policy.json). OF-092/093.
 *
 * Canon: RetrievalState/action + gated owned outcomes train the retrieval
 * skill's parameters at sleep. Immutable held-out queries/labels score a
 * candidate; declared owner pin/manifest weight stays authoritative.
 * learning.* is recorded/projector-only, not an ordinary claim write.
 * Existing vault.settings.learning{,.put,.clear} manages catalogued owner
 * seeds/pins; it is NOT a retrieval training or weight-table update call.
 *
 * Activate: publicly populate the fixed corpus, pin the selected weight to
 * 0.7, and snapshot that row and authoritative source claims. Attach the
 * training outcomes to their contributing runs, retain held-out labels only
 * for evaluation, and request the declared policy update. Read its candidate,
 * acceptance result, routing/model pins, weight origins, corpus digest and
 * accuracy/cost tradeoff. Submit a regression, an attempted pin overwrite,
 * foreign/ungated outcomes and an attempt to turn derived reward into fact.
 * Each must preserve the owner pin and original facts. An accepted update
 * may change only unpinned policy parameters inside its authority. This tiny
 * set cannot establish not-worse sufficiency: unknown stays an offer, never
 * an auto-approved switch or invented universal quality threshold.
 *
 * Blocker: no typed retrieval-outcome training/update, held-out policy
 * evaluation/admission or retrieval weight/routing receipt call exists in
 * the public HTTP/SDK catalog. The private blend tuner and generic learned
 * settings calls cannot stand in for OF-092's retrieval-policy loop. No
 * direct learning.* claims, private tuner calls or new production knobs.
 */
suite.todo(test, "JUDGMENTS-06", "waits on typed retrieval-policy training/evaluation/update and weight receipts (Learned retrieval policy retains owner pins should work)");

/* JUDGMENTS-07 — Prospective hints remain derived should work.
 * Fixture: judgments-hints (hints.json). OF-105.
 * Canon also: write-path #prospective-query, ARCH-0038 derived invalidation.
 *
 * Current WitnessTurn {conversation_ref,messages,occurred_at,...} and
 * vault.search.bm25({query,limit}) give the ingest/read ends. ClaimInput has
 * {predicate,subject_ref,value,confidence,source,...}, no prospective hints.
 * ConsolidationEnqueueRequest is {scope,input:unknown,run_id?,dedupe_key?,
 * now?}; status returns DreamerAttemptView, not a typed extraction result.
 *
 * Activate: witness the source and distractor through the public door.
 * Before extraction the fixture's query words have no literal lexical hit.
 * Run the scripted extractor to emit the fixed claim plus prospective query,
 * await its public completion, then search for the hint wording. Assert the
 * hit resolves to the source claim, carries the original turn/revision and
 * generated hint provenance, and is not an independent identity/evidence
 * claim. Erase the source through the owner-confirmed public deletion flow,
 * await its receipt and requery: no source or orphan hint survives, while
 * the independent distractor remains readable. A hint must never authorize
 * a write or be counted as another corroborating source.
 *
 * Blocker: no typed HTTP/SDK extraction producer/result carries prospective
 * queries or their source links. The consolidation input's unknown payload
 * is not a typed extraction call. No generic vault.batch/claim-value seed,
 * manually written lexical_query_hint, private batch builder or raw index
 * manipulation may fabricate a successful extractor for this scenario.
 */
suite.todo(test, "JUDGMENTS-07", "waits on typed extraction prospective-query output and completion/source receipts (Prospective hints remain derived should work)");
