import { afterAll, test, expect } from "bun:test";
import type { FacadeInput, FacadeResult, FacadeVerb } from "@oneiron/client";
import { defineFile } from "./support/run.ts";
import { randomUUID } from "node:crypto";
import { EngineFixture, awaitPublic } from "./support/engine.ts";
import { PublicHttpError, type PublicHttpClient } from "./support/clients.ts";
import { loadFixtures, ownerBaseClaimScope } from "./support/fixtures.ts";
import { ScriptedProviders } from "./support/providers.ts";

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
// LEARNING-01 — Goal-vector admission and tradeoff should work. OF-495.
// Intake completion, goal readback, optimizer proposal/measurement/admission,
// preferences and tradeoff picks exist. The full floor-removal proposal still
// needs a public grant-checked full-goal proposal door and grounded run setup.
// Do not replace the full goal with a preference-only revision or seed scores.
suite.todo(test, "LEARNING-01", "waits on a public full goal-revision proposal verb behind a project grant for the floor-removal proposal and a pinned held-out/live-run setup; intake.complete, goal.get and optimizer propose/measure/score/admit already exist");

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
interface LearningForgeryScenario02 {
  id: "LEARNING-02";
  ordinary_note: string;
  cell: { executor: string; axis: string };
  forgery: { predicate: "learning.reliability"; value: unknown };
  expected: { allowed_prior_origins: string[]; refusal_must_identify_projector_only_policy: boolean };
}
type LearningCellRead02 = FacadeInput<"vault.learning.read">;
type LearningCellView02 = FacadeResult<"vault.learning.read">;
type LearningCallReceipt02 = NonNullable<FacadeResult<"vault.receipts.get">>;

function learningEvidenceState02({ cell, view }: LearningCellView02) {
  // Estimates may decay with time; head/evidence identity and own runs may not change here.
  return {
    cell, own: view.own, runs: view.estimate.runs,
    borrowed_from: view.borrowed_from ?? null,
    attributed_outcome_receipts: view.attributed_outcome_receipts,
    provenance: view.provenance,
    prior_provenance: view.prior_provenance ?? null,
  };
}

async function learningRefusal02<V extends FacadeVerb>(
  client: PublicHttpClient, actor: { principalRef: string; actorClass: string },
  verb: V, input: FacadeInput<V>, status: number, code: string, message: string,
) {
  let refusal: PublicHttpError | undefined;
  try { await client.call(verb, input) }
  catch (error) {
    if (!(error instanceof PublicHttpError)) throw error;
    refusal = error;
  }
  if (!refusal) throw new Error(`${verb} accepted a forbidden learning operation`);
  expect(refusal.reply.status).toBe(status);
  const error = refusal.error;
  if (!error) throw new Error("Learning refusal has no typed error envelope");
  expect(error.code).toBe(code);
  expect(error.message).toBe(message);
  const receiptRef = error.receiptRef;
  expect(typeof receiptRef).toBe("string");
  if (typeof receiptRef !== "string") throw new Error("Learning refusal has no receiptRef");
  expect(receiptRef).toMatch(/^call:/);
  expect(refusal.reply.headers.get("x-oneiron-receipt-ref")).toBe(receiptRef);
  const receipt = await client.call("vault.receipts.get", { receipt_ref: receiptRef });
  if (!receipt) throw new Error("Learning refusal receipt is not publicly readable by its actor");
  expect(receipt.receipt_ref).toBe(receiptRef);
  expect(receipt.actor_ref).toBe(actor.principalRef);
  expect(receipt.actor_class).toBe(actor.actorClass);
  expect(receipt.verb).toBe(`v1/core/facade/${verb}`);
  expect(receipt.transport).toBe("http_facade");
  expect(receipt.outcome).toEqual({ refused: { code } });
  return { error, receipt };
}

// LEARNING-02 — Measured learning rows cannot be forged should work. OF-542.
// Partial: admitted owner/agent ordinary writes cannot forge learning.reliability.
// Read all four learning cells and refusal receipts through separate public doors,
// then kill/restart and read them again. Ordinary recall still returns the note.
// Real anchored outcome production/retest/fitting remains outside this partial.
// Keep the promised projector-only explanation; today's generic refusal is a defect.
suite.test(test, "LEARNING-02", "owner and admitted agent cannot forge learning.reliability through claims.upsert", async () => {
  const catalog = await loadFixtures();
  const data = await catalog.readJson<{ scenarios: LearningForgeryScenario02[] }>("learning-scenarios");
  const scenario = data.scenarios.find(row => row.id === "LEARNING-02");
  if (!scenario) throw new Error("Missing LEARNING-02 fixture");
  const providers = await ScriptedProviders.start({ id: "LEARNING-02", steps: [] });
  let engine: EngineFixture | undefined;
  try {
    engine = await EngineFixture.start({ id: "LEARNING-02", profile });
    const owner = engine.pairedActor;
    const skills = await engine.client.call("vault.skills.list", { limit: 100 });
    const skill = skills.skills.find(row => row.loadable);
    if (!skill) throw new Error("Fresh vault has no public loadable skill for the forgery subject");
    const tree = (await engine.client.call("vault.task_types.get", {})).tree;
    if (!tree) throw new Error("Fresh vault has no public task-type tree");
    const scope = await ownerBaseClaimScope(engine.client, owner.principalRef);
    const executor = scenario.cell.executor;
    const axis = scenario.cell.axis;
    const subject = skill.entity;
    const typeRef = tree.root;
    const cells: LearningCellRead02[] = [
      { cell: { subject, predicate: "learning.reliability", executor, typeRef, axis } },
      { cell: { subject, predicate: "learning.edit_cost", executor, consent_scope: "learning-forgery-owner-edit" } },
      { cell: { subject, predicate: "learning.retest_noise", executor, axis } },
      { cell: { subject, predicate: "learning.setting", typeRef, setting_key: "audit_rate" } },
    ];
    const baseline: ReturnType<typeof learningEvidenceState02>[] = [];
    for (const input of cells) {
      const result = await engine.client.call("vault.learning.read", input);
      expect(result.cell).toMatchObject(input.cell);
      expect(result.view.own).toBe(false);
      expect(result.view.estimate.runs).toBe(0);
      expect(result.view.provenance.heads).toEqual([]);
      expect(result.view.provenance.evidence).toEqual([]);
      expect(result.view.attributed_outcome_receipts).toEqual([]);
      expect(scenario.expected.allowed_prior_origins).toContain(result.view.estimate.prior.origin);
      expect(result.view.estimate.prior.value).toBeDefined();
      expect(result.view.estimate.prior.weight_runs).toBeGreaterThanOrEqual(0);
      expect(result.view.estimate.untested).toBe(result.view.estimate.runs < result.view.estimate.prior.weight_runs);
      baseline.push(learningEvidenceState02(result));
    }
    const diary = await engine.client.call("self.memory.diary", { content: scenario.ordinary_note });
    expect(diary.entry_ref).not.toBe("");
    const assertRecall = async () => {
      const pack = await awaitPublic(
        () => owner.client.call("vault.recall", { query: scenario.ordinary_note, effort: "light", limit: 1 }),
        reply => reply.items.some(item => item.value_text.includes(scenario.ordinary_note)),
        { label: "ordinary learning-fixture note is recalled" },
      );
      expect(pack.items).toHaveLength(1);
      expect(pack.items[0]!.value_text).toContain(scenario.ordinary_note);
      expect(pack.items.every(item => !item.predicate?.startsWith("learning."))).toBe(true);
    };
    await assertRecall();

    // This UUID creates a new object; it is never used as a fabricated stored reference.
    const agentId = randomUUID().replaceAll("-", "");
    const created = await engine.client.call("vault.agents.create", {
      agent_def_ref: agentId,
      definition: { agent_id: "learning-forgery-writer", display_name: "Learning forgery writer",
        desc: "Ordinary scoped claim writer", version: "1" },
    });
    const agentEntity = (await engine.client.call("vault.get", { entity_ref: created.agent_def_ref })).value;
    expect(agentEntity?.kind).toBe("AGENT_DEF");
    const agent = await engine.pairActor({ principalRef: created.agent_def_ref, actorClass: "agent" });
    const identity = await agent.client.call("self.actor", {});
    expect(identity.actor_ref).toBe(agent.principalRef);
    expect(identity.actor_class).toBe("agent");
    const attack: FacadeInput<"vault.claims.upsert"> = {
      predicate: scenario.forgery.predicate, subject_ref: subject, value: scenario.forgery.value,
      confidence: 1, source: "observed", scope, evidence_turn_refs: [],
    };
    // One ordinary predicate per actor: a shared single-valued key would make the
    // agent's control a cross-author replacement of the owner's claim (403).
    const controls: { claim: string; predicate: string; value: string; actor: string }[] = [];
    const assertControls = async () => {
      for (const control of controls) {
        const rows = (await owner.client.call("vault.claims.list", {
          subject_ref: subject, predicate: control.predicate, limit: 100,
        })).value;
        const row = rows.find(row => row.short_ref === control.claim);
        if (!row) throw new Error("An admitted ordinary control is missing from claims.list");
        expect(row.value).toBe(control.value);
        expect(row.claim_scope).toEqual(scope);
        expect(row.source).toBe("observed");
        expect(row.made_by?.process.actor).toBe(control.actor);
      }
    };
    for (const actor of [owner, agent]) {
      const predicate = `core.learning_forgery_control.${actor.actorClass}`;
      const value = `${actor.actorClass} ordinary admission control`;
      const control = await actor.client.call("vault.claims.upsert", {
        ...attack, predicate, value,
      });
      expect(["auto", "proposed"]).toContain(control.approval);
      expect(control.claim_short_id).not.toBe("");
      controls.push({ claim: control.claim_short_id, predicate, value, actor: actor.principalRef });
      await assertControls();
    }
    const refusals: LearningCallReceipt02[] = [];
    const policyExplanations: string[] = [];
    for (const actor of [owner, agent]) {
      const refused = await learningRefusal02(actor.client, actor, "vault.claims.upsert", attack,
        400, "BAD_REQUEST", 'reserved claim predicate namespace: "learning.reliability"');
      refusals.push(refused.receipt);
      policyExplanations.push([refused.error.message, ...(refused.error.suggestions ?? [])].join("\n"));
    }
    const projection: FacadeInput<"vault.learning.projection"> = {
      attempt_receipt: `learning-forgery-unsettled-attempt:${agentId}`,
      outcome_receipt: `learning-forgery-unsettled-outcome:${agentId}`, axis,
    };
    expect((await owner.client.call("vault.learning.projection", projection)).receipt).toBeNull();
    for (const [verb, input] of [
      ["vault.learning.read", cells[0]!],
      ["vault.learning.projection", projection],
    ] as const) {
      const refused = await learningRefusal02(agent.client, agent, verb, input,
        403, "FORBIDDEN", `${verb} is the vault owner's`);
      expect(refused.error.suggestions).toContain("Present the owner's own verified, unattenuated credential.");
      refusals.push(refused.receipt);
    }
    const assertUnchanged = async () => {
      for (let i = 0; i < cells.length; i++) {
        const result = await owner.client.call("vault.learning.read", cells[i]!);
        expect(learningEvidenceState02(result)).toEqual(baseline[i]);
      }
      expect((await owner.client.call("vault.learning.projection", projection)).receipt).toBeNull();
      await assertControls();
      await assertRecall();
      for (const receipt of refusals) {
        expect(await owner.client.call("vault.receipts.get", { receipt_ref: receipt.receipt_ref })).toEqual(receipt);
      }
    };
    await assertUnchanged();
    // The public refusal receipts above establish the boundary before SIGKILL.
    await engine.kill();
    await engine.restart();
    await assertUnchanged();
    expect(providers.seenFixtureCalls).toEqual([]);

    // Fixture promise retained: reserved-namespace wording alone does not explain projector ownership.
    expect(scenario.expected.refusal_must_identify_projector_only_policy).toBe(true);
    for (const explanation of policyExplanations) expect(explanation).toMatch(/projector/i);
  } finally {
    try { await engine?.close() }
    finally { await providers.close() }
  }
});

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
// LEARNING-03 — Autoresearch retains unsuccessful experiments should work.
// OF-351 / OF-366.
// Research binding, child enqueue, archive, measurements and cohort setup exist.
// The fixture needs its own lawful run-bearing campaign root and grounded
// experiment/referee completion. An ordinary TASK root has no run; an unrelated
// shape root is not research setup. Retain losing and buggy evidence once armed.
suite.todo(test, "LEARNING-03", "waits on a public campaign-root creation verb behind a campaign-controller grant returning a lawful run-bearing root for vault.research.bind, and grounded experiment-result/sealed-referee completion; create_child, archive and cohort doors already exist");

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
// LEARNING-04 — Multi-critic findings and seal audits should work. OF-352/544.
// Critic review, learning settings and the seal lifecycle are public today.
// The full flow still needs a grant-checked anchored critic-outcome door and
// a real terminal measured-attempt producer. seal.run only enqueues work.
// Keep the promised duplicate merge with all evidence; different evidence sets
// currently prevent consolidation. This defect is not a reason to weaken it.
suite.todo(test, "LEARNING-04", "waits on a public critic-outcome attribution/readback verb behind a scoped critic grant and a public terminal measured-attempt producer for seal setup; confession, audit, completion, receipt and queued seal.run already exist");

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
// LEARNING-05 — Niche archive and coverage floor should work. OF-545.
// Output-archive install, placement, best/get, coverage and reproposal exist.
// The missing fresh-vault journey starts with a lawful run-bearing campaign
// root behind controller authority, then a human goal and live task/outputs.
// Do not substitute archive metadata for the actual coverage-floor decision.
suite.todo(test, "LEARNING-05", "waits on a public campaign-root creation verb behind a campaign-controller grant and a grounded goal/TASK/output/candidate setup for vault.research.bind; archive install/record/get/best/coverage/repropose already exist");

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
// LEARNING-06 — Eval authoring keeps independent held-out families should work.
// OF-578.
// Eval author_now/result, family/exposure reads, cohort setup/open, inventory
// and supplied-measurement sufficiency exist. author_now queues; an empty or
// recipe-less pass can do nothing. The complete flow still needs grant-checked
// cohort retirement and a positive blocked-decision label-ask producer.
// Do not count an empty ask list or echoed sufficiency inputs as authoring.
suite.todo(test, "LEARNING-06", "waits on a public cohort-retirement verb and blocked-decision label-ask producer behind an eval-authoring grant, plus bounded recipe-backed execution with grounded receipts; author_now/result, family/exposure reads and cohort setup already exist");

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
// LEARNING-07 — Training export and approval before deploy should work.
// OF-382/400.
// Source preview, sealed-cohort setup and owner training preparation,
// authorization, result view and separate swap are public. The served trainer
// and evaluator support question heads, not this role-training fixture.
// A grant-authorized role connector must expose actual corpus bytes and return
// a verified result; question-head training is not a role-swap substitute.
suite.todo(test, "LEARNING-07", "waits on public role-training connector execution and seat evaluation behind an owner-authorized compute grant, inspectable consented corpus bytes and bounded result completion; source preview, sealed-cohort setup and owner prepare/authorize/view/swap already exist");

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
// LEARNING-08 — Coach model offer keeps do-nothing baseline should work.
// OF-577/512.
// Coach offer trigger/result, candidates, pilots, source preview, cohort setup
// and owner answer/undo exist. Trigger only queues the pass; served metering,
// the offer recipe and grant-checked bounded execution remain prerequisites.
// Keep the decision-seat and separate input/output tokenizer-cost promises;
// the current served seat mapping and whole-bill ratio contradict them.
suite.todo(test, "LEARNING-08", "waits on an explicitly executable public Coach offer-pass verb behind a revocable read/engine.controls grant, served usage metering and its installed offer skill; trigger/result, candidate/pilot setup, cohort setup and owner answer/undo already exist");

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
// LEARNING-09 — RSI budget holds rather than kills should work. OF-496.
// RSI configure/read/top-up/hold/resume, work/exposure reservations and
// research budget reads exist. The case still needs a lawful run-bearing
// campaign-root producer behind controller authority and observable live work.
// A suspended-flag round-trip cannot prove preserved candidate, attempt and
// partial outputs through token and exposure holds.
suite.todo(test, "LEARNING-09", "waits on a public campaign-root creation verb behind a campaign-controller grant supplying a lawful run-bearing root and a grounded same-attempt/candidate/partial-output journey through both holds; RSI configure/read/top-up/hold/resume and work/exposure reservations already exist");
