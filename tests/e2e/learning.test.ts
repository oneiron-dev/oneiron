import { afterAll, test } from "bun:test";
import { createHash } from "node:crypto";
import { resolve } from "node:path";
import type { FacadeInput, FacadeResult, FacadeVerb } from "@oneiron/client";
import { EngineFixture, awaitPublic } from "./support/engine.ts";
import { PublicHttpClient, PublicHttpError } from "./support/clients.ts";
import { loadFixtures } from "./support/fixtures.ts";
import { ScriptedProviders, openaiStream } from "./support/providers.ts";
import { defineFile, expect } from "./support/run.ts";

const profile = process.env.E2E_PROFILE === "real-small-model"
  ? "real-small-model" : "deterministic";
const suite = defineFile(import.meta, { profile, slots: 1 });
afterAll(suite.flush);

/**
 * Skills and improvement, in plan order. Each case is a COMPLETE-flow TODO, not
 * a passing test of a subset, until its arming PR writes the whole flow (armed:
 * LEARNING-09). suite.todo creates Bun test.todo and BLOCKED rows.
 *
 * Binding read: main f8e2f8397685bc63405bc1a303b65f94aa26c33d (this worktree's
 * HEAD and origin/main). See fixtures/learning/bindings.json for source hashes.
 * Read: generated HTTP SDK, the verb table (scripts/sdk/verbs/), public OpenAPI registry and owner
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
// Waiting: the witnessed-intake and fixed-baseline production-judge fixture,
// grounded proposal evidence, and HTTP/MCP flow wiring. The doors exist:
// vault.projects.goal.intake.complete writes the full record after a witnessed
// interview, vault.projects.goal.get reads it, vault.skills.optimize.* propose,
// measure, score and admit, and vault.projects.goal.propose stores a full goal
// revision proposal (base claim + generation, engine diff) that
// vault.projects.goal.revisions and goal.intake show and goal.dismiss sets aside.
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
suite.todo(test, "LEARNING-01", "waits on the witnessed-intake and fixed-baseline production-judge fixture, grounded proposal evidence, and HTTP/MCP flow wiring; the full-goal proposal door and its Rust coverage do not arm it");

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
// Root: vault.research.create_root enqueues the run-bearing root vault.research.bind accepts.
suite.todo(test, "LEARNING-03", "waits on its arming PR: the OF-366 authoring bind, real experiment results and counted sealed-referee completion over a vault.research.create_root root");

// LEARNING-04 — Multi-critic findings and seal audits should work. OF-352/544.
// Waiting: typed confession/recheck/audit receipt readback and controlled public
// completion/trigger. The Coach seal checker IS wired; do not call it absent.
// A public tasks.update DONE through a host-bound run stamps that run's executor
// model on the held try (LEARN-CRITIC Q2), so a public completion can be sealed.
// vault.critic.outcome records an owner verdict, or a completed directed recheck an
// agent names for its own review, as a critique's anchored outcome; and
// vault.critic.findings reads the review with its outcomes and its critics' cells,
// provenance cut to the review (LEARN-CRITIC Q3).
// Existing vault.critic.review takes CriticReviewSubmit and returns triage,
// critique artifacts and decision receipts. Learned-setting seed/pin is public.
// Set up two independently anchored critic histories, same task type and axis.
// Merge duplicate findings with their evidence/attribution; a real hard-check
// veto cannot be outvoted by a reliable critic's unsupported reassurance.
// Duplicates merge on the flaw identity a critic's note names (target, kind,
// location; LEARN-CRITIC Q1 = B): give both fixture duplicates one flaw.
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
// Root: vault.research.create_root enqueues the run-bearing root vault.research.bind accepts.
suite.todo(test, "LEARNING-05", "waits on its arming PR: goal/TASK/real output/candidate setup with receipts and a valid two-bin axis fixture over a vault.research.create_root root");

// LEARNING-06 — Eval authoring keeps independent held-out families should work.
// OF-578. G01 is RESOLVED: wait for typed HTTP+SDK authoring/ledger calls, not
// an owner answer or execute_code. The host's eval-authoring recipe exists.
// Missing public author-now/completion and family/date/exposure/sufficiency reads
// make its internal eval_set functions unavailable to this black-box test.
// Give families their purpose BEFORE deriving paraphrases, translations,
// summaries, rubrics or synthetic rows. Every derivative stays with its family.
// New sealed cohorts use explicit dates. Exposed labels retire to development;
// one fixed reference cohort stays. Near-copy similarity flags REVIEW only.
// Retire: vault.evals.cohorts.retire (the owner, or an agent on a Grant that lists it)
// retires a served non-reference cohort; its receipt names that caller.
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
// Label ask: vault.evals.labels.ask asks one label for a pending stock-switch offer whose stored card labels can settle.
suite.todo(test, "LEARNING-06", "waits on vault.evals.authoring.execute with a stored report and grounded setup: terminal pack receipts, an installed eval-authoring recipe, a cut cohort with counted exposure, a Coach-recorded stock offer");

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
/*
 * Proves: a host-driven research campaign on a pinned RSI share runs from its bootstrap
 *   measure to one child candidate's confirmation and holds there twice without failing:
 *   first on the exposure line (no exposure left), then, after the owner tops up that line
 *   and resumes, on the pinned share (the confirmation's token work does not fit it, while
 *   the token line itself has room). Across both holds the SAME confirmation of the SAME
 *   child attempt waits at the front of the same continuation, and the child's candidate pin
 *   and recorded search and held-out evidence are unchanged. After the owner tops up the
 *   share and resumes, that candidate is confirmed and promoted once: one serving, one
 *   exposure spent on the exposure line (never on the token line), no second experiment, no
 *   second promotion, and a later pass adds nothing. A soft share's overdraw takes only the
 *   free pool, with an overdraft receipt signed by the install, and its refund returns it.
 * Doors: HTTP facade vault.agents.create, vault.budgets.rsi.configure, vault.budgets.rsi,
 *   vault.budgets.rsi.top_up, vault.budgets.rsi.hold.resume, vault.evals.families.assign,
 *   vault.evals.cases.record, vault.evals.inventory, vault.evals.cohorts.setup,
 *   vault.research.create_root, vault.research.bind, vault.research.advance,
 *   vault.research.select, vault.research.archive, vault.research.budget,
 *   vault.research.reserve_work, vault.research.refund_work, vault.agents.spawn.get. Every
 *   agent run (each root's own run, the scorer's four, the experimenter's and the referee's)
 *   is a real code-mode run whose one scripted reply is `finish(<answer>)`; the host pass
 *   records the answer it reads from the run (continuation.rs run_answer_text).
 * Mechanism (the owner, 13 Nov 22:44: "in general pick the more elegant version, updating
 *   canon is ok"): the engine holds a task at its reservation, before any run exists, so no
 *   live run is paused and nothing is lost. The kept "partial outputs" are the candidate's
 *   recorded search and held-out evidence and the continuation's run trail; "the same try"
 *   is the same child attempt's confirmation at the front of the same continuation. The
 *   Docs lane rewords canon's pause-a-pending-attempt wording to this.
 * Sizing: a run's token ceiling is its reservation, so the fixture's 30-unit shares (sized
 *   for an owner-only reservation script) would cap a real run's call. The constants below
 *   keep the order of refusals: every run before the confirmation fits the pinned share
 *   whatever it settles at (spent <= reserved; an Unknown settlement stays committed), the
 *   confirmation's work alone is larger than the share, and the token line and the
 *   campaign lease hold all of it, so only the pinned share refuses. The fixture gives the
 *   share labels and the expected facts.
 * Polling: vault.research.advance writes nothing while a run goes (the pass stops at the
 *   unfinished run), so the case polls it. The server's Coach host advances the same
 *   campaign on its own 60 s tick; when two passes meet one row the later is refused
 *   INVALID_STATE having written nothing, and the poll reads again.
 * Unproved: a hold of a run already going (no door pauses a live research run; every hold
 *   is at a reservation); the Coach host's own pass reaching these states unprompted.
 */
interface Learning09Scenario {
  id: "LEARNING-09";
  shares: { label: string; units: number; pinned: boolean }[];
  expected: {
    pending_attempt_preserved: boolean;
    pending_candidate_preserved: boolean;
    partial_outputs_preserved: boolean;
    resume_same_attempt: boolean;
    resource_hold_is_terminal_failure: boolean;
    loop_may_widen_budget: boolean;
    different_units_mixed: boolean;
  };
}
type Learning09View = FacadeResult<"vault.research.advance">;
type Learning09Row = Learning09View["continuations"][number];
type Learning09Archive = FacadeResult<"vault.research.archive">;
const L09_MODEL = "learning09-agent";
const L09_USAGE = { inputTokens: 256, outputTokens: 96 } as const;
const L09_DAY = 86_400;
/** Token units each scorer and experimenter run reserves, and so its run's token ceiling. */
const L09_RUN_UNITS = 100_000;
/** Runs that reserve on the pinned share before the confirmation: the bootstrap search
 * measure, the experiment, the child's search measure and the two held-out measures. */
const L09_RUNS_BEFORE_CONFIRM = 5;
/** The pinned share holds every run before the confirmation, whatever each one settles at. */
const L09_PINNED_UNITS = L09_RUN_UNITS * L09_RUNS_BEFORE_CONFIRM;
/** The confirmation's token work: alone more than the whole pinned share. */
const L09_CONFIRM_UNITS = L09_PINNED_UNITS + L09_RUN_UNITS;
const L09_SOFT_UNITS = 1_000;
/** One soft-share reservation past its share: the excess comes from the free pool. */
const L09_SOFT_RESERVE = 5_000;
/** The token line: both shares, the pinned top-up and the soft overdraw fit under it. */
const L09_TOKEN_LIMIT = 2_000_000;
/** Each campaign's own lease: never the limit that refuses here. */
const L09_LEASE_UNITS = 2_000_000;
const L09_CONCURRENT_PASS = "another pass advanced this research continuation";
const L09_HELD = { held: { reason: "budget" } } as const;

function learning09Id(label: string): string {
  return createHash("sha256").update(`learning-e2e:LEARNING-09:${label}`).digest("hex").slice(0, 32);
}
function learning09Sha(text: string): string {
  return createHash("sha256").update(text).digest("hex");
}
const L09_INCUMBENT = {
  config_ref: "learning09-config:baseline", config_sha256: learning09Sha(`{"parameter":"baseline"}`),
} as const;
const L09_CANDIDATE = {
  config_ref: "learning09-config:alternative", config_sha256: learning09Sha(`{"parameter":"alternative"}`),
} as const;
async function learning09Scenario(): Promise<Learning09Scenario> {
  const data = await (await loadFixtures()).readJson<{ scenarios: { id: string }[] }>("learning-scenarios");
  const row = data.scenarios.find(item => item.id === "LEARNING-09");
  if (!row) throw new Error("Missing LEARNING-09 fixture scenario");
  return row as Learning09Scenario; // Fixture discriminant, not an invented wire DTO.
}
/** An attempt id as the archive carries it (`{"bytes": [16 numbers]}`), in hex as the advance view names it. */
function learning09Hex(id: unknown): string {
  const bytes = (id as { bytes?: unknown } | null)?.bytes;
  if (!Array.isArray(bytes) || bytes.length !== 16) throw new Error(`Not an attempt id: ${JSON.stringify(id)}`);
  return bytes.map(byte => Number(byte).toString(16).padStart(2, "0")).join("");
}
async function learning09Agent(owner: PublicHttpClient, label: string): Promise<string> {
  const agent_def_ref = learning09Id(label);
  const created = await owner.call("vault.agents.create", {
    agent_def_ref, definition: { agent_id: label, display_name: label, desc: `LEARNING-09 ${label}`, version: "1" },
  });
  expect(created.agent_def_ref).toBe(agent_def_ref);
  return agent_def_ref;
}
/** The one reply to the next agent run's model call: a program that finishes with `answer`
 * (text, or the JSON the run's briefing asks for). The runs reach the provider one at a
 * time, in the order the single-flight pass dispatches them. */
function learning09Reply(providers: ScriptedProviders, id: string, purpose: string, answer: unknown): void {
  const text = typeof answer === "string" ? answer : JSON.stringify(answer);
  providers.enqueue({
    id, origin: "chat", role: "generative_reasoner", purpose,
    // The engine-native executor streams on a local-openai-compat provider (wire.rs:146-149).
    request: { method: "POST", path: "/v1/chat/completions", model: L09_MODEL,
      fields: { stream: true, stream_options: { include_usage: true } } },
    response: openaiStream(id, L09_MODEL, [`finish(${JSON.stringify(text)});`], L09_USAGE),
  });
}
/** The run's queue state once it has ended. */
async function learning09RunEnded(owner: PublicHttpClient, run: string, label: string): Promise<string> {
  const seen = await awaitPublic(() => owner.call("vault.agents.spawn.get", { spawn_ref: run }),
    view => ["completed", "failed", "cancelled", "abandoned"].includes(view.launched[0]?.state ?? ""),
    { label, timeoutMs: 30_000 });
  return seen.launched[0]?.state ?? "";
}
/** One sealed Companion family of one receipt case, cut by the owner into a cohort of its own. */
async function learning09SealedCohort(owner: PublicHttpClient): Promise<string> {
  const source = `learning09-source:${learning09Id("sealed-source")}`;
  const family = await owner.call("vault.evals.families.assign", {
    seat: "companion", roots: [source], purpose: "sealed_confirmation",
  });
  expect(family.purpose).toBe("sealed_confirmation");
  const sourceAt = Math.floor(Date.now() / 1000) - L09_DAY;
  await owner.call("vault.evals.cases.record", {
    seat: "companion", kind: "receipt", receipts: [source], parents: [], stratum: null,
    draw_probability: null, source_at: sourceAt,
  });
  const inventory = await owner.call("vault.evals.inventory", {});
  const setup = await owner.call("vault.evals.cohorts.setup", {
    inventory_at: inventory.built_at, inventory_digest: inventory.inventory_digest, families: [], cases: [],
    cuts: [{ seat: "companion", from: sourceAt - L09_DAY, until: inventory.built_at,
      rubric_revision: "learning09-rubric", reference: false }],
  });
  expect(setup.skipped).toEqual([]);
  expect(setup.cohorts_cut).toHaveLength(1);
  const cohort = setup.cohorts_cut[0];
  if (!cohort) throw new Error("The owner's setup cut no cohort");
  return cohort;
}
/** A config campaign: one primary metric, three distinct dataset revisions, its own lease. */
function learning09Config(campaign_id: string): FacadeInput<"vault.research.bind">["config"] {
  return {
    campaign_id,
    search_axes: [{ name: "parameter", values: ["baseline", "alternative"] }],
    metric_set: { set_id: "learning09-quality", revision: "r1",
      axes: [{ name: "quality", direction: "higher", role: "primary" }] },
    splits: {
      search: { dataset_id: "learning09-search", revision: "r1" },
      held_out: { dataset_id: "learning09-held-out", revision: "r1" },
      sealed: { dataset_id: "learning09-sealed", revision: "r1" },
    },
    budget: { budget_id: `${campaign_id}-lease`, max_units: L09_LEASE_UNITS, exploration_units: 10 },
    decide: { kind: "dominance" },
  };
}
/** One host pass; `null` when it met the Coach host's own pass on a row and wrote nothing. */
async function learning09Pass(owner: PublicHttpClient, root: string): Promise<Learning09View | null> {
  try {
    return await owner.call("vault.research.advance", { root });
  } catch (error) {
    if (error instanceof PublicHttpError && error.reply.status === 409 && error.error?.code === "INVALID_STATE"
      && error.error.message.includes(L09_CONCURRENT_PASS)) return null;
    throw error;
  }
}
/** Pass until `ready`; a failed continuation ends the case at once with its reason. */
async function learning09AdvanceUntil(owner: PublicHttpClient, root: string, label: string,
  ready: (view: Learning09View) => boolean, timeoutMs: number): Promise<Learning09View> {
  const view = await awaitPublic(() => learning09Pass(owner, root), seen => {
    if (seen === null) return false;
    for (const row of seen.continuations) {
      const state: unknown = row.state;
      if (state !== null && typeof state === "object" && "failed" in state) {
        throw new Error(`${label}: continuation ${JSON.stringify(row.work)} failed: ${JSON.stringify(state)}`);
      }
    }
    return ready(seen);
  }, { label, timeoutMs });
  if (view === null) throw new Error(`${label}: no pass answered`);
  return view;
}
function learning09Row(view: Learning09View, work: "bootstrap" | "round-0"): Learning09Row | undefined {
  return view.continuations.find(row => JSON.stringify(row.work) === (work === "bootstrap" ? `"bootstrap"` : `{"round":0}`));
}
function learning09Ended(row: Learning09Row | undefined): boolean {
  const state: unknown = row?.state;
  return state !== null && typeof state === "object" && "done" in state;
}
function learning09IsHeld(row: Learning09Row | undefined): boolean {
  return JSON.stringify(row?.state) === JSON.stringify(L09_HELD);
}
function learning09Node(archive: Learning09Archive, attempt: string): Learning09Archive["experiments"][number] {
  const node = archive.experiments.find(row => learning09Hex(row.attempt) === attempt);
  if (!node) throw new Error(`The campaign records no node ${attempt}`);
  return node;
}

suite.test(test, "LEARNING-09", "A host-driven research campaign holds on its exposure line and then on its pinned share without failing, keeps the same candidate and its recorded evidence, resumes after the owner tops up the exact line, and promotes that candidate once; a soft share overdraws the free pool with a signed receipt", async () => {
  const c = await learning09Scenario();
  const pinned = c.shares.find(share => share.pinned)?.label;
  const soft = c.shares.find(share => !share.pinned)?.label;
  if (!pinned || !soft) throw new Error("The LEARNING-09 fixture names no pinned and soft share");
  const providers = await ScriptedProviders.start({ id: "learning09-research", origins: ["chat"], steps: [] });
  const engine = await EngineFixture.start({ id: "LEARNING-09", profile, serverLog: "oneiron=info", serverConfig: `
[models.providers.learning09chat]
kind = "local-openai-compat"
base_url = "${providers.urls.chat}"
revision = "learning-v1"
[models.roles.generative_reasoner]
model = "learning09chat:${L09_MODEL}"
[models.dreamer]
enabled = false
[models.workflows]
enabled = false
[models.code_mode]
prompt_package = ${JSON.stringify(resolve(import.meta.dir, "fixtures/hooks/host/prompts"))}
` });
  try {
    const owner = engine.client;

    // ---- Setup by the owner over HTTP: the agents, both RSI lines with a pinned and a soft share, the sealed cohort. ----
    const rootAgent = await learning09Agent(owner, "learning09-root");
    const experimenter = await learning09Agent(owner, "learning09-experimenter");
    const scorer = await learning09Agent(owner, "learning09-scorer");
    const referee = await learning09Agent(owner, "learning09-referee");
    const configured = await owner.call("vault.budgets.rsi.configure", {
      limit: L09_TOKEN_LIMIT, exploration_exposure_limit: 0,
      shares: { [pinned]: { units: L09_PINNED_UNITS, pinned: true }, [soft]: { units: L09_SOFT_UNITS, pinned: false } },
    });
    expect(configured.suspended).toBe(false);
    expect(configured.work_line).toEqual({ unit: "tokens", limit: L09_TOKEN_LIMIT, spent: 0, reserved: 0 });
    expect(configured.exposure_line).toEqual({ unit: "exposures", limit: 0, spent: 0, reserved: 0 });
    const cohort = await learning09SealedCohort(owner);

    // ---- The campaign root: its own run is a real code-mode run, ended before the bind. ----
    learning09Reply(providers, "learning09-root-run", "the campaign root's own run reads its brief and finishes", "Campaign brief read.");
    const created = await owner.call("vault.research.create_root", {
      agent: rootAgent, intent_key: "learning-09/campaign", briefing: "Search the parameter axis for a better quality score.",
    });
    const root = created.root;
    expect(await learning09RunEnded(owner, root, "LEARNING-09 campaign root's run ends")).toBe("completed");
    // Each later run's answer, in the one order the single-flight pass dispatches the runs.
    learning09Reply(providers, "learning09-bootstrap-search", "the scorer measures the incumbent root on the search split",
      { scores: { quality: 0.2 }, confirmed_hits: 0.2, attribution: 1, hop_cost: 0 });
    learning09Reply(providers, "learning09-experiment", "the experimenter writes one child candidate", L09_CANDIDATE);
    learning09Reply(providers, "learning09-child-search", "the scorer measures the child on the search split: it beats the root",
      { scores: { quality: 0.8 }, confirmed_hits: 0.8, attribution: 1, hop_cost: 0 });
    learning09Reply(providers, "learning09-incumbent-held-out", "the scorer measures the incumbent on the held-out split",
      { scores: { quality: 0.2 } });
    learning09Reply(providers, "learning09-child-held-out", "the scorer measures the child on the held-out split",
      { scores: { quality: 0.8 } });
    learning09Reply(providers, "learning09-referee", "the referee scores the child against the incumbent on the sealed cases", {
      candidate: 0.8, incumbent: 0.2, referee_pin: `learning09-referee@sha256:${learning09Sha("learning09-referee")}`,
      sufficiency: { families: 2, floor_slices: {}, min_families_per_slice: 1, retest_noise: 0.1, owner_margin: null,
        paired_interval: [0, 0.2], detectable_effect: null, set_changed: false, rubric_changed: false, canary_diverged: false },
    });
    const bound = await owner.call("vault.research.bind", {
      root, config: learning09Config("learning09-campaign"), target: { config: { subject: "learning-09" } }, holder: null,
      confirmation: { seat: "companion", cohort }, share: pinned, incumbent: L09_INCUMBENT, prior_ladder: [],
      execution: { experimenter, scorer, referee, experiment_units: L09_RUN_UNITS, measure_units: L09_RUN_UNITS,
        confirm_units: L09_CONFIRM_UNITS },
    });
    expect(bound.share).toBe(pinned);

    // ---- Bootstrap: one scorer run measures the root; the owner's selection forks round 0. ----
    const boot = await learning09AdvanceUntil(owner, root, "LEARNING-09 bootstrap measure ends",
      view => learning09Ended(learning09Row(view, "bootstrap")), 30_000);
    const bootRow = learning09Row(boot, "bootstrap");
    expect(bootRow?.state).toEqual({ done: { note: "every task ran" } });
    expect(bootRow?.runs).toHaveLength(1);
    const selected = await owner.call("vault.research.select", { root, goal_met: false });
    expect(selected.round).toBe(0);
    const step: unknown = selected.step;
    if (step === null || typeof step !== "object" || !("fork" in step)) throw new Error(`Round 0 did not fork: ${JSON.stringify(step)}`);
    expect(learning09Hex((step as { fork: { parent: unknown } }).fork.parent)).toBe(root);

    // ---- Hold 1: the round runs to the confirmation, which holds on the exposure line. ----
    const exposureHold = await learning09AdvanceUntil(owner, root, "LEARNING-09 confirmation holds on the exposure line",
      view => learning09IsHeld(learning09Row(view, "round-0")), 60_000);
    const exposureRow = learning09Row(exposureHold, "round-0");
    if (!exposureRow) throw new Error("No round 0 continuation");
    expect(exposureRow.held_line).toBe("exploration");
    expect(exposureRow.running ?? null).toBeNull();
    // The experimenter's run is the child attempt; its confirmation waits at the front.
    expect(exposureRow.runs).toHaveLength(4);
    const child = exposureRow.runs[0];
    if (!child) throw new Error("Round 0 dispatched no experiment");
    expect(exposureRow.pending).toEqual([{ confirm: { candidate: child } }]);
    expect(exposureHold.budget.exploration_reserved).toBe(0);
    expect(exposureHold.budget.exploration_spent).toBe(0);
    const lineAtExposureHold = await owner.call("vault.budgets.rsi", {});
    expect(lineAtExposureHold.suspended).toBe(true);
    expect(lineAtExposureHold.exposure_line).toEqual({ unit: "exposures", limit: 0, spent: 0, reserved: 0 });
    const archiveAtExposureHold = await owner.call("vault.research.archive", { root });
    expect(archiveAtExposureHold.experiments).toHaveLength(2);
    const childAtExposureHold = learning09Node(archiveAtExposureHold, child);
    expect(childAtExposureHold.candidate).toEqual(L09_CANDIDATE);
    expect(childAtExposureHold.search ?? null).not.toBeNull();
    expect(childAtExposureHold.held_out ?? null).not.toBeNull();
    expect(archiveAtExposureHold.promotions).toHaveLength(1);
    const basis = archiveAtExposureHold.promotions[0];
    expect(basis && learning09Hex(basis.candidate)).toBe(child);
    expect(basis?.call).toBe("promote");
    expect(basis?.confirmation ?? null).toBeNull(); // the sealed shot is unspent
    // A top-up alone raises only that line and resumes nothing.
    const exposureTopUp = await owner.call("vault.budgets.rsi.top_up", { line: "exploration", units: 1 });
    expect(exposureTopUp.exposure_line.limit).toBe(1);
    expect(exposureTopUp.work_line.limit).toBe(L09_TOKEN_LIMIT);
    expect(c.expected.different_units_mixed).toBe(false);
    expect(exposureTopUp.suspended).toBe(true);
    const stillHeld = learning09Row(await learning09AdvanceUntil(owner, root, "LEARNING-09 pass after a top-up alone",
      () => true, 10_000), "round-0");
    expect(stillHeld?.state).toEqual(L09_HELD);
    expect(stillHeld?.held_line).toBe("exploration");
    expect(stillHeld?.runs).toEqual(exposureRow.runs);

    // ---- Hold 2: after the resume the exposure reserves, and the pinned share refuses the token work. ----
    expect((await owner.call("vault.budgets.rsi.hold.resume", {})).suspended).toBe(false);
    const shareHold = await learning09AdvanceUntil(owner, root, "LEARNING-09 confirmation holds on the pinned share",
      view => { const row = learning09Row(view, "round-0"); return learning09IsHeld(row) && row?.held_line !== "exploration"; }, 10_000);
    const shareRow = learning09Row(shareHold, "round-0");
    expect(shareRow?.held_line).toEqual({ work: { purpose: "HeldOut" } });
    expect(c.expected.pending_attempt_preserved).toBe(true);
    expect(c.expected.pending_candidate_preserved).toBe(true);
    expect(shareRow?.pending).toEqual(exposureRow.pending); // the same confirmation of the same child
    expect(shareRow?.running ?? null).toBeNull();
    expect(shareRow?.runs).toEqual(exposureRow.runs);
    const lineAtShareHold = await owner.call("vault.budgets.rsi", {});
    expect(lineAtShareHold.suspended).toBe(true);
    // The exposure it reserved first went back in the same write.
    expect(lineAtShareHold.exposure_line).toEqual({ unit: "exposures", limit: 1, spent: 0, reserved: 0 });
    // The token line itself had room: the pinned share refused without taking the free pool.
    const { work_line: workLine } = lineAtShareHold;
    expect(workLine.limit - workLine.spent - workLine.reserved).toBeGreaterThanOrEqual(L09_CONFIRM_UNITS);
    expect(lineAtShareHold.shares).toContainEqual({ label: pinned, units: L09_PINNED_UNITS, pinned: true });
    const budgetAtShareHold = await owner.call("vault.research.budget", { root });
    const exposuresAtShareHold = budgetAtShareHold.reservations.filter(row => row.line === "exploration");
    expect(exposuresAtShareHold).toHaveLength(1);
    expect(exposuresAtShareHold[0]?.settlement).toBe("Refunded");
    // Reserve before spending: one settled token reservation per run, none for the refused work.
    const workAtShareHold = budgetAtShareHold.reservations.filter(row => row.line !== "exploration");
    expect(workAtShareHold).toHaveLength(L09_RUNS_BEFORE_CONFIRM);
    expect(workAtShareHold.every(row => (row.settlement ?? null) !== null)).toBe(true);
    const archiveAtShareHold = await owner.call("vault.research.archive", { root });
    expect(c.expected.partial_outputs_preserved).toBe(true);
    expect(archiveAtShareHold.experiments).toEqual(archiveAtExposureHold.experiments);
    expect(archiveAtShareHold.promotions).toEqual(archiveAtExposureHold.promotions);

    // ---- Resume: the owner tops up the exact share and resumes; the SAME confirmation serves once and promotes. ----
    const shareTopUp = await owner.call("vault.budgets.rsi.top_up", { line: "share", share: pinned, units: L09_CONFIRM_UNITS });
    expect(shareTopUp.shares).toContainEqual({ label: pinned, units: L09_PINNED_UNITS + L09_CONFIRM_UNITS, pinned: true });
    expect(shareTopUp.suspended).toBe(true);
    expect((await owner.call("vault.budgets.rsi.hold.resume", {})).suspended).toBe(false);
    const done = await learning09AdvanceUntil(owner, root, "LEARNING-09 confirmation promotes the child",
      view => learning09Ended(learning09Row(view, "round-0")), 30_000);
    const doneRow = learning09Row(done, "round-0");
    expect(doneRow?.state).toEqual({ done: { note: "confirmed: promoted" } });
    expect(c.expected.resource_hold_is_terminal_failure).toBe(false);
    expect(doneRow?.pending).toEqual([]);
    expect(doneRow?.running ?? null).toBeNull();
    expect(doneRow?.runs).toHaveLength(5);
    expect(doneRow?.runs.slice(0, 4)).toEqual(exposureRow.runs);
    const refereeRun = doneRow?.runs[4];
    if (!refereeRun) throw new Error("No referee run");
    expect(await learning09RunEnded(owner, refereeRun, "LEARNING-09 referee run ends")).toBe("completed");
    const archiveDone = await owner.call("vault.research.archive", { root });
    expect(c.expected.resume_same_attempt).toBe(true);
    expect(archiveDone.experiments).toEqual(archiveAtExposureHold.experiments); // no second experiment
    expect(archiveDone.promotions).toHaveLength(1);
    const promoted = archiveDone.promotions[0];
    expect(promoted && learning09Hex(promoted.candidate)).toBe(child);
    expect(promoted?.candidate_pin).toEqual(L09_CANDIDATE);
    expect(promoted?.confirmation ?? null).not.toBeNull();
    expect(promoted?.promotion ?? null).not.toBeNull();
    const lineDone = await owner.call("vault.budgets.rsi", {});
    expect(lineDone.suspended).toBe(false);
    expect(lineDone.exposure_line).toEqual({ unit: "exposures", limit: 1, spent: 1, reserved: 0 });
    expect(done.budget.exploration_spent).toBe(1);
    expect(done.budget.exploration_reserved).toBe(0);
    const budgetDone = await owner.call("vault.research.budget", { root });
    expect(budgetDone.reservations.filter(row => row.line === "exploration").map(row => row.settlement))
      .toEqual(["Refunded", { Exposure: 1 }]);
    const workDone = budgetDone.reservations.filter(row => row.line !== "exploration");
    expect(workDone).toHaveLength(L09_RUNS_BEFORE_CONFIRM + 1);
    expect(workDone.every(row => (row.settlement ?? null) !== null)).toBe(true);
    // A pass after the end adds nothing: no run, no reservation, no serving.
    const after = await learning09AdvanceUntil(owner, root, "LEARNING-09 pass after the end", () => true, 10_000);
    expect(learning09Row(after, "round-0")).toEqual(doneRow);
    expect(after.budget).toEqual(done.budget);

    // ---- A soft share overdraws only the free pool, with a signed receipt; its refund returns the units. ----
    learning09Reply(providers, "learning09-soft-root-run", "the soft campaign root's own run reads its brief and finishes", "Soft brief read.");
    const softRoot = (await owner.call("vault.research.create_root", {
      agent: rootAgent, intent_key: "learning-09/soft", briefing: "Reserve loop work on the soft share.",
    })).root;
    expect(await learning09RunEnded(owner, softRoot, "LEARNING-09 soft root's run ends")).toBe("completed");
    const softBound = await owner.call("vault.research.bind", {
      root: softRoot, config: learning09Config("learning09-soft"), target: { config: { subject: "learning-09-soft" } },
      holder: null, confirmation: null, share: soft, incumbent: L09_INCUMBENT, prior_ladder: [], execution: null,
    });
    expect(softBound.share).toBe(soft);
    const overdraw = await owner.call("vault.research.reserve_work", {
      root: softRoot, purpose: "Experiment", units: L09_SOFT_RESERVE, attempt: null,
    });
    const softBudget = await owner.call("vault.research.budget", { root: softRoot });
    const softRow = softBudget.reservations.find(row => row.id === overdraw);
    expect(softRow?.settlement ?? null).toBeNull();
    expect(softRow?.overdraft).toMatchObject({ share: soft, units: L09_SOFT_RESERVE - L09_SOFT_UNITS, reservation: overdraw });
    expect(softRow?.overdraft?.public_key).toMatch(/^[0-9a-f]{64}$/);
    expect(softRow?.overdraft?.signature).toMatch(/^[0-9a-f]{128}$/);
    const lineAtOverdraw = await owner.call("vault.budgets.rsi", {});
    expect(c.expected.loop_may_widen_budget).toBe(false);
    expect(lineAtOverdraw.shares).toContainEqual({ label: soft, units: L09_SOFT_UNITS, pinned: false });
    expect(lineAtOverdraw.suspended).toBe(false);
    const refunded = await owner.call("vault.research.refund_work", { root: softRoot, reservation: overdraw });
    expect(refunded.settlement).toBe("Refunded");
  } finally {
    const errors: string[] = [];
    try { await engine.close(); } catch (error) { errors.push(error instanceof Error ? error.message : String(error)); }
    try { await providers.close(); } catch (error) { errors.push(error instanceof Error ? error.message : String(error)); }
    if (errors.length) throw new Error(`close: ${errors.join("; ")}`);
  }
}, 120_000);
