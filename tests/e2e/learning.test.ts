import { afterAll, test } from "bun:test";
import type { FacadeInput, FacadeResult, FacadeVerb } from "@oneiron/client";
import { defineFile } from "./support/run.ts";

const profile = process.env.E2E_PROFILE === "real-small-model"
  ? "real-small-model" : "deterministic";
const suite = defineFile(import.meta, { profile, slots: 1 });
afterAll(suite.flush);

/**
 * Skills and improvement, in plan order. These are COMPLETE-flow TODOs, not
 * passing tests of a subset. suite.todo creates Bun test.todo and BLOCKED rows.
 *
 * Binding read: main f8e2f8397685bc63405bc1a303b65f94aa26c33d (this worktree's
 * HEAD and origin/main). See fixtures/learning/bindings.json for source hashes.
 * Read: generated HTTP SDK, agent-verbs.json, public OpenAPI registry and owner
 * route table/DTOs, CLI, oneiron.skills.md by tier, and the public SDK README.
 * Existing research, critic, setting, offer-answer and swap doors are NOT absent.
 *
 * Oracle: ARCH-0053 #r4-lifecycle, #self-revision, #seal, #eval-sufficiency,
 * #training-pack, #training-offer; ARCH-0003 #learning; ARCH-0079 #work;
 * ARCH-0036 #model-line; ARCH-0069 #handles. Owner ruling G01 = typed call or wait.
 * Fixtures: learning-scenarios, pinned in fixtures/learning/manifest.json.
 * The shared runner verifies the fragment even while every case is blocked.
 *
 * Types beside each TODO are semantic CANON DESIGN NOTES, not invented HTTP
 * paths, SDK methods, or callable adapters. PublicCall names only EXISTING
 * generated DTOs. Missing operations await their own typed HTTP and SDK calls.
 * Never cast a new name into FacadeVerb, use execute_code, put private bodies
 * through structural.put/kv.put/batch, or seed a stored attempt/cohort/estimate.
 * References in fixture data are symbolic labels, not preexisting vault IDs.
 *
 * When armed, each case uses EngineFixture.start with its own authenticated
 * vault; ScriptedProviders supplies external wire responses only. Expected
 * values stay in the fixtures, never in an engine-derived snapshot. No fixed
 * sleeps, private ticks, probabilistic audit assertion or automatic retry.
 */
type Ref = string;
type PublicCall<V extends FacadeVerb> = {
  request: FacadeInput<V>;
  result: FacadeResult<V>;
};
type TaskType = { node_id: Ref; tree_version: number };
type Axis = { key: string; direction: "maximize" | "minimize" };
type GoalVector = Record<string, number>;
type GoalRecord = {
  goal: string;
  why: string;
  primary_axes: Axis[];
  floor_axes: Axis[];
  cost_axes: Axis[];
  preferences: { prefer: string; over: string; reason: string }[];
  exploration_budget: { unit: string; limit: number };
};

// LEARNING-01 — Goal-vector admission and tradeoff should work. OF-495.
// Waiting: human goal-intake WRITE of the complete vector record, plus typed
// optimizer candidate/proposal submission and admission readback. ProjectGoalDraft
// currently has goal, why, axes:string[]; goal.intake only READS interview context.
// Existing HTTP: POST /v1/owner/skills/judge/measure {proposal,pulls_per_axis?},
// GET /skills/judge/{preferences,tradeoff-asks,goal-revisions}, and
// POST /skills/judge/tradeoff-asks/pick {proposal,question_digest,choice}.
// MCP can read vault.projects.goal.intake/revisions; tool arguments use spec.
// Those reads and an existing proposal's measurement cannot create this setup.
// Run each candidate against the SAME fixed baseline, not the previous winner.
// Dominance: at least one better, none worse; ties reject. A floor regression
// rejects even a primary-axis win. Offline held-out evidence precedes any online
// bandit slice. Exhaust preference rule then typed judgment before the owner ask.
// Owner picks the tradeoff: it becomes attributed preference evidence, not a
// Grant. Repeated equivalent tradeoff uses that evidence. A loop-proposed goal
// edit leaves the effective goal/revision untouched until the human interview.
type Learning01 = {
  intake: GoalRecord;
  candidates: { candidate: Ref; baseline: Ref; measured: GoalVector }[];
  admission: { candidate: Ref; decision: "admit" | "reject" | "escalate"; evidence: Ref[] };
  owner_pick: { question_digest: string; candidate: Ref; baseline: Ref; prefer: Ref };
  goal_change: { proposed: GoalRecord; effective_goal_before: Ref; effective_goal_after: Ref };
};
type Learning01Current = PublicCall<"vault.projects.goal.intake">;
suite.todo(test, "LEARNING-01", "waits on typed full goal-vector intake write and optimizer candidate admission/proposal calls");

// LEARNING-02 — Measured learning rows cannot be forged should work. OF-542.
// Waiting: measured learning-cell view with explicit priors, outcome provenance
// and publicly observable attribution/projector completion. vault.settings.learning
// reads knob settings, NOT the four measured predicates. Claim list/history,
// upsert and recall already exist; they do not supply the missing measured view.
// Settle the fixture's anchored successes/loss through real public task/receipt
// paths, then await its projection, not an arbitrary delay. Read all four heads.
// Own runs must name their anchored receipts; prior origins/weights remain
// explicit and separate. UNTESTED is derived, not a handwritten status.
// Try reliability upsert as owner and as an admitted foreign actor, including a
// forged perfect estimate. Both ordinary writes fail without a new head/evidence.
// Recall must still return the ordinary note but NO learning.* state and must
// not charge learning rows against ordinary memory budgets. Follow provenance
// to receipt outcomes, not critic agreement, self-report or confession.
type EstimateValue =
  | { form: "beta"; value: { alpha: number; beta: number } }
  | { form: "mean"; value: { mean: number; spread: number } }
  | { form: "counts"; value: Record<string, number> };
type MeasuredEstimate = EstimateValue & {
  runs: number;
  prior: {
    origin: "shipped" | "provenance" | "carried" | "parent" | "model" | "seed";
    value: EstimateValue["value"];
    weight_runs: number;
    from?: Ref;
  };
  untested: boolean;
  of: string;
  labels: { by_judge: Record<string, number>; converted: number; on_judge_model: number };
  window: { half_life: number };
  ver: string;
};
type Learning02 = {
  cell: {
    subject: Ref;
    predicate: "learning.reliability" | "learning.edit_cost" | "learning.retest_noise" | "learning.setting";
    executor: Ref;
    typeRef: TaskType;
    axis?: string;
    consent_scope?: string;
    setting_key?: string;
  };
  view: { estimate: MeasuredEstimate; attributed_outcome_receipts: Ref[]; supersedes?: Ref };
};
type Learning02Write = PublicCall<"vault.claims.upsert">;
type Learning02Recall = PublicCall<"vault.recall">;
suite.todo(test, "LEARNING-02", "waits on typed measured learning-cell/prior/provenance view and attributed-outcome projection observation");

// LEARNING-03 — Autoresearch retains unsuccessful experiments should work.
// OF-351 / OF-366. Waiting: typed campaign archive/evidence read, sealed-cohort
// setup, and host-bound experiment child creation with HTTP+SDK bindings.
// vault.research.fork only RECORDS an already-enqueued child; it cannot enqueue
// one. run-tree reads only queue topology/status/result refs, not experiment
// search/held-out evidence. Do not forge IDs or redirect unrelated tasks to fake it.
// Existing calls below are the real generated wire shapes, carried by HTTP and
// tool-first MCP (arguments.spec); no made-up research endpoint is needed.
// Author the ruler first. Fork good, losing and buggy candidates. Evaluate on
// independent search/held-out/sealed families. Assert the selected candidate is
// fixture-best, not a magic random parent order. Crossover starts OFF: weave only
// after its held-out qualification. The woven claim must be Proposed with parent
// and diff lineage; research metadata never bypasses ordinary claim admission.
// Prune the loser from active exploration. Archive inspection after restart must
// retain EVERY candidate, original failed/buggy evidence, measurements and refs;
// no loser may be silently deleted or returned as an active parent.
type Learning03Current = {
  bind: PublicCall<"vault.research.bind">;
  fork: PublicCall<"vault.research.fork">;
  search: PublicCall<"vault.research.measure_search">;
  held_out: PublicCall<"vault.research.measure_held_out">;
  evaluate: PublicCall<"vault.research.evaluate_split">;
  select: PublicCall<"vault.research.select">;
  weave: PublicCall<"vault.research.weave">;
  prune: PublicCall<"vault.research.prune">;
  promote: PublicCall<"vault.research.promote">;
};
type Learning03Archive = {
  campaign: Ref;
  experiments: {
    attempt: Ref; parents: Ref[]; candidate: Ref;
    state: "active" | "pruned" | "woven" | "buggy";
    search_receipts: Ref[]; held_out_receipts: Ref[]; failure_receipts: Ref[];
  }[];
  proposed_claim: { claim: Ref; parents: Ref[]; diff_receipt: Ref; approval: "Proposed" };
};
suite.todo(test, "LEARNING-03", "waits on typed experiment child creation, sealed-cohort setup and campaign archive/evidence reads");

// LEARNING-04 — Multi-critic findings and seal audits should work. OF-352/544.
// Waiting: typed confession/recheck/audit receipt readback and controlled public
// completion/trigger. The Coach seal checker IS wired; do not call it absent.
// Existing vault.critic.review takes CriticReviewSubmit and returns triage,
// critique artifacts and decision receipts. Learned-setting seed/pin is public.
// Set up two independently anchored critic histories, same task type and axis.
// Merge duplicate findings with their evidence/attribution; a real hard-check
// veto cannot be outvoted by a reliable critic's unsupported reassurance.
// Read default audit_rate = .05, nonzero. Publicly pin it to 1 for this fixture:
// the hidden-flaw audit is guaranteed, NOT a probabilistic test or private seed.
// A confession schedules a directed recheck and changes NO score by itself.
// Once the random draw receipt exists, change the setting to .5, then release
// the external checker barrier. Finding weight is 1 / STAMPED rate (1), not 2.
// Only anchored findings update honesty/reliability after attribution; inspect
// both task score and honesty state. No confession-derived score feature.
type Learning04Current = {
  review: PublicCall<"vault.critic.review">;
  settings: PublicCall<"vault.settings.learning">;
  pin: PublicCall<"vault.settings.learning.put">;
};
type Learning04Seal = {
  confession: { attempt: Ref; objectives: { objective: Ref; met: boolean; uncertainty?: string }[] };
  draw: { receipt: Ref; attempt: Ref; rate: number };
  finding: { receipt: Ref; draw: Ref; evidence: Ref[]; hidden_flaw: boolean; weight: number };
  directed_recheck: { attempt: Ref; confession: Ref; finding_receipts: Ref[] };
};
suite.todo(test, "LEARNING-04", "waits on typed confession, directed-recheck and stamped seal-audit receipt/completion calls");

// LEARNING-05 — Niche archive and coverage floor should work. OF-545.
// Waiting: typed archive descriptor install, output placement/record and per-cell
// best readback. A CampaignArchivePin in research.promotion_basis is a CHECKED
// reference to an existing archive, not an archive-authoring door.
// Use two descriptor axes, pinned to one campaign. Insert uneven fixture scores
// and a replacement winner in cell A. Read both bests, not just the global best.
// A globally higher candidate that loses required cell B fails the GOAL's
// coverage floor, even though its global scalar rises. The cell-B output stays.
// Descriptor edits are versioned for a new campaign; they do not change the
// effective goal or mix cells across definitions. This is an OUTPUT archive,
// never a skill archive and never a second store of numeric learning claims.
type Learning05 = {
  descriptor: { campaign: Ref; revision: string; axes: { key: string; values: string[] }[] };
  placement: { output: Ref; output_revision: string; cell: string[]; scoring_receipt: Ref };
  view: { descriptor_revision: string; best: { cell: string[]; output: Ref; score: number }[] };
  admission: { candidate: Ref; required_cells: string[][]; covered_cells: string[][]; admitted: boolean };
};
type Learning05Current = PublicCall<"vault.research.promotion_basis">;
suite.todo(test, "LEARNING-05", "waits on typed campaign output-archive descriptor/placement/best reads and coverage-floor admission setup");

// LEARNING-06 — Eval authoring keeps independent held-out families should work.
// OF-578. G01 is RESOLVED: wait for typed HTTP+SDK authoring/ledger calls, not
// an owner answer or execute_code. The host's eval-authoring recipe exists.
// Missing public author-now/completion and family/date/exposure/sufficiency reads
// make its internal eval_set functions unavailable to this black-box test.
// Give families their purpose BEFORE deriving paraphrases, translations,
// summaries, rubrics or synthetic rows. Every derivative stays with its family.
// New sealed cohorts use explicit dates. Exposed labels retire to development;
// one fixed reference cohort stays. Near-copy similarity flags REVIEW only.
// Inspect counts of served candidates, queries and promotions independently.
// Tiny rare slice, interval crossing margin, changed set, changed rubric and
// divergent canary each yield unknown, never a confident invented number.
// No decision waiting => no label ask. A blocked switch => one scoped ask that
// quotes human minutes. No standing label session, no automatic deployment.
type Learning06 = {
  author: { seat: string; source_receipts: Ref[]; date_cut: number; reference_cohort: Ref };
  family_ledger: { family: Ref; purpose: "development" | "judge_audit" | "sealed_confirmation"; rows: Ref[] }[];
  exposure_ledger: { cohort: Ref; candidates: number; queries: number; promotions: number; retired: boolean }[];
  sufficiency: {
    independent_families: number; rare_slice_counts: Record<string, number>;
    retest_noise: number; paired_interval: [number, number]; detectable_effect: number;
    margin: number; verdict: "not_worse" | "unknown";
  };
  label_ask: { blocked_decision: Ref; families: Ref[]; human_minutes: number } | null;
};
type Learning06ExistingCard = PublicCall<"vault.research.promote">["request"]["sufficiency"];
suite.todo(test, "LEARNING-06", "waits on typed eval-authoring trigger/completion, family/date/exposure ledgers and sufficiency/blocked-label reads");

// LEARNING-07 — Training export and approval before deploy should work.
// OF-382/400. Owner routes already exist:
// POST /v1/owner/coach/training-offers/prepare {offer,draft,scope,connector}
//   -> {run,spec}; /authorize {offer,run,spec}; /training {offer}.
// POST /v1/owner/coach/training-runs/view {run} and /swap
//   {run,choice,expected:{spec,checkpoint}}. expected pins exactly what was viewed.
// Missing: a configured public trainer/seat-evaluator adapter, corpus export
// inspection and sealed-cohort setup. ai_host/training_pack.rs currently returns
// None for trainer_binding, training_connector and training_evaluator. A generic
// connector fake cannot make this production path call a nonexistent adapter.
// Only consented ON-RECORD permitted correction pairs may leave. Off-record,
// unconsented and other-person/private sources lacking consent stay excluded;
// owner opt-in can admit private sources, so this is NOT a blanket privacy ban.
// Inspect actual exported bytes at the local connector, not a fake echo.
// Pin starting revision and all load-file hashes. Check returned shard BLAKE3,
// fixed-probe flips/difference, zero exact training/holdout overlaps and family
// separation. Bad hash/probe/overlap cannot propose an evaluated swap. Canon
// permits a separate explicit owner override; do not invent a universal ban.
// Successful fake training must NOT auto-bind. Decline leaves old role binding;
// explicit approval of the viewed spec/checkpoint changes only that role, with
// receipt. Never claim sampled model quality or live trained-weight serving.
// Fixture need: pin actual checkpoint/load files and the real trainer protocol
// when that adapter ships; no fabricated model hashes or guessed wire frames.
type Learning07 = {
  export: { permitted_pair_receipts: Ref[]; excluded_pair_receipts: Ref[]; corpus_digest: string };
  run: {
    starting_revision: string; weight_shard_hashes: Record<string, string>;
    settings: Record<string, string | number | boolean>; harness_revision: string;
    verifier_logs: Ref[]; held_out_families: Ref[];
  };
  checks: { hash_match: boolean; argmax_flips: number; max_logit_difference: number; exact_hash_overlaps: number };
  swap: { run: Ref; viewed_spec: string; viewed_checkpoint: string; approve: boolean };
};
suite.todo(test, "LEARNING-07", "waits on public trainer/seat-evaluator adapter, inspectable consented corpus export and sealed-cohort setup");

// LEARNING-08 — Coach model offer keeps do-nothing baseline should work.
// OF-577/512. Existing GET /v1/owner/coach/training-offers lists pending offers;
// POST /answer {offer,digest,answer,training?} settles the EXACT shown snapshot;
// POST /undo {offer} undoes a stock switch. These are real public owner routes.
// Missing: typed trigger/completion and evidence readback for one Coach offer
// pass, plus pinned candidate/pilot setup. The nightly host wiring exists; do
// not drive its private queue, wait overnight, or insert a finished offer body.
// Exercise receipt-backed incumbent cost vs stock switch, train and self-train
// on the same projected workload with each tokenizer. Saving is AVOIDABLE cost;
// include pilot/migration/re-embed in one-off cost and disclose unknowns as null,
// never zero. Price/registry scores nominate; own-seat held-out evidence decides.
// Offers include do-nothing with today's cost/score, cheapest local, decline,
// postpone and evidence/sufficiency/risks/licence. New downloads show a card.
// Leave unanswered/close: baseline remains. Postpone: no swap; refresh numbers
// before resurfacing. Decline: label for offer skill, no swap. Approve qualifying
// SWITCH: only its seat changes, old binding remains undoable; a TRAIN approval
// authorizes work but still requires a separate result-swap choice (LEARNING-07).
// Auto-approve starts OFF. Unknown evidence cannot auto-approve even when ON.
type Learning08 = {
  offer: Ref; seat: string; snapshot_digest: string;
  options: {
    kind: "do_nothing" | "switch" | "train" | "self_train";
    monthly_before: number; monthly_after: number | null;
    one_off_cost: number | null; payback_months: number | null;
    evidence_receipts: Ref[]; sufficiency: "not_worse" | "unknown";
    licence_pin: Ref; destination: string; data_leaves_device: boolean;
  }[];
  answer: "decline" | "postpone" | "approve";
  changed_seats: string[];
};
suite.todo(test, "LEARNING-08", "waits on typed Coach offer-pass trigger/completion and per-seat candidate/pilot evidence setup/readback");

// LEARNING-09 — RSI budget holds rather than kills should work. OF-496.
// Existing research.reserve_work {root,purpose,units,attempt?} -> reservation ID,
// settle_work {root,reservation,actual} -> reservation and refund_work are typed.
// CampaignConfig's budget is {budget_id,max_units,exploration_units}; it does NOT
// create the owner/host's vault RSI line or set a soft/pinned share.
// Waiting: typed owner RSI line/share configure/read/top-up and separately
// unit-labelled exposure reserve/settle, plus observable campaign hold/resume.
// Owner /runs/hold and /runs/hold/resume are real general TASK budget-hold routes,
// not an RSI share/exposure setter. Do not replace RSI with an unrelated cap.
// Reserve before spending. Soft overdraw uses only the free pool and has an
// overdraft receipt. Pinned-share cap holds without silently taking that pool.
// Exposure units do not consume token units; its cap independently holds.
// Keep a pending experiment's attempt, candidate refs and partial outputs across
// both holds. Top up the exact limiting line, resume, and observe the SAME try
// continue without duplicate terminal receipts or another candidate/goal rewrite.
// Resource depletion is not failure, cancellation, pruning or a new experiment.
type Learning09Current = {
  reserve: PublicCall<"vault.research.reserve_work">;
  settle: PublicCall<"vault.research.settle_work">;
  refund: PublicCall<"vault.research.refund_work">;
};
type Learning09 = {
  work_line: { unit: "tokens"; limit: number; spent: number; reserved: number };
  shares: { goal: Ref; units: number; pinned: boolean }[];
  exposure_line: { unit: "exposures"; limit: number; spent: number; reserved: number };
  hold: { attempt: Ref; limiting_line: Ref; pending_candidate: Ref; partial_outputs: Ref[] };
  top_up: { line: Ref; units: number };
  resume: { attempt: Ref; same_candidate: Ref; preserved_outputs: Ref[] };
};
suite.todo(test, "LEARNING-09", "waits on typed vault RSI soft/pinned share and exposure controls, top-up and campaign hold/resume observation");
