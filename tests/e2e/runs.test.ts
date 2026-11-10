import { afterAll, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { readFile, readdir } from "node:fs/promises";
import { resolve } from "node:path";
import type { Facade, FacadeInput, FacadeResult, FacadeVerb } from "@oneiron/client";
import { EngineFixture, awaitPublic } from "./support/engine.ts";
import { PublicHttpClient, PublicHttpError } from "./support/clients.ts";
import { loadFixtures, ownerBaseClaimScope } from "./support/fixtures.ts";
import { ScriptedProviders, openaiStream } from "./support/providers.ts";
import { defineFile, secretHex } from "./support/run.ts";

const profile = process.env.E2E_PROFILE === "real-small-model"
  ? "real-small-model" : "deterministic";
const suite = defineFile(import.meta, { profile, slots: 1 });
afterAll(suite.flush);

/*
 * Canon, independent inputs, source hashes and the per-ID binding audit live in
 * fixtures/runs/scenarios.json (runs-scenarios in the area manifest).
 * Binding snapshot: main 6f2446660ef09f823131d6faaa7e586a75df0b72.
 * Read the current generated HTTP/Oneiron SDK catalogs, server OpenAPI
 * registration/DTOs and CLI, not the plan's older implementation snapshot.
 *
 * A written case proves exactly the subset its name states, and only when
 * that subset keeps a promise of the planned title (Engine E2E-PARTIAL = A,
 * 9 Nov 2026); its comment lists what stays unproved and the missing piece.
 * Every other case is a TODO naming its missing door, not a partial smoke
 * test. suite.todo registers Bun test.todo and the runner's BLOCKED result.
 * G01 requires the missing typed HTTP AND SDK call; a generic entity write,
 * consolidation input, app action or execute_code is not its replacement.
 * Canon's semantic types below do not invent endpoint paths or wire spellings.
 *
 * On activation use EngineFixture.start({ id, profile }) for every ID, with
 * authenticated public setup and loadFixtures().readJson("runs-scenarios").
 * ScriptedProviders controls external responses only. kill/restart owns only
 * that test's real process/vault. A sink ACK or model barrier is NOT a step
 * commit: first await a public settled-step receipt. Never read private queue
 * state, fabricate claims/leases/checkpoints, change a clock or copy Rust seeds.
 * Shared support and all pre-existing tests remain untouched.
 */

/* RUNS-01 — Dreamer survives a kill should work.
 * Rows: OF-193, OF-195, OF-210, OF-392. ARCH-0026 #run-tree, #wake-model.
 * Oracle: runs-scenarios / RUNS-01.
 *
 * Existing typed calls:
 *   vault.witness(WitnessInput) -> WitnessReceipt
 *     { turn_short_id, message_short_ids, receipt_ref, turn?, messages? }
 *   vault.consolidation.status({ job_ref }) -> DreamerAttemptView | null
 *     { job_ref, state, kind, lease_owner?, attempt_count, run_id?,
 *       last_error?, created_at, updated_at }
 *   GET /v1/core/run-tree?run_id=... -> { roots, repairs }
 * Canon design: a step completion records its result; resume reconstructs
 * checkpoint + tail, skips completed steps and injects those exact results.
 * The completion/effect/checkpoint records retain their original run identity.
 * There is no current typed public settled-step/checkpoint-result DTO.
 *
 * Wake the two-step program through a real incoming turn, not manual enqueue.
 * The local sink acknowledges the first idempotency key. Await that effect's
 * settled-step receipt, then hold the next provider response and SIGKILL.
 * Restart the same vault; release the next response (including a reconnect
 * request, without permitting replay of step one). Require exactly one run
 * with its original root identity, injected first result and one delivery per
 * key. The sink records attempts as well as accepted effects: do not let its
 * idempotency cache hide an engine repeat. Check final result + both receipts.
 *
 * Promise: an armed turn program, woken by a real turn, settles step one, is
 *   SIGKILLed while step two's provider reply is held, resumes as the same
 *   try with step one injected, never re-executed, and finishes once.
 * Doors: vault.witness, vault.turn_programs.arm/.admission, vault.runs.program,
 *   .program_step, .program_checkpoint, vault.skill_hubs.* + vault.skills.import.
 * Missing: a public door that makes a FIRST-PARTY callable SKILL active for
 *   vault.turn_programs.arm. Hub import is the only deterministic activation,
 *   and an imported callable runs on the Foreign tier, whose sandbox links no
 *   self.verbs.call import (no verb methods), so its program makes no write,
 *   model or send step: nothing settles, and no provider call can be held.
 * Also unproved: a verb write cut by SIGKILL replays Uncertain and holds for
 *   good (only a Read-scope ai.verdict would re-run), and the pinned entry
 *   commits its checkpoint only at entry end, so after a mid-entry kill step
 *   one answers from its kept receipt and program_checkpoint shows injected=false.
 */
suite.todo(test, "RUNS-01", "waits on a public door that activates a first-party callable SKILL for vault.turn_programs.arm: imported callables run Foreign with no self.verbs.call import, so no turn program settles a step a kill could interrupt (Dreamer survives a kill should work)");

/* RUNS-02 — Only waiting branch pauses should work.
 * Rows: OF-203, OF-390, OF-391. ARCH-0026 #run-tree.
 * Oracle: runs-scenarios / RUNS-02.
 *
 * Existing HTTP/SDK calls:
 *   ask(TaskAskSpec | TaskAskShort) -> TaskAskReceipt
 *     { handle: { group_ref }, task_refs, hold?, idempotent_replay, ... }
 *   wait({ handle: { group_ref }, step_key }) -> TaskAskWait
 *     { Pending: { trap_ref } } | { Changed: { voided, generation } }
 *     | { Ready: TaskAskResult } | { Park: SelfDurableWait }
 *   tasks.answer({ handle, word: { result_ref, option?, ... } }) -> TaskAskAnswer
 * A person's word is evidence, NEVER effect authorization. SelfDurableWait has
 * wait_id/effect/reason/prompt, not the canon's seconds/minutes/human class.
 * Run-tree snapshots have queued/running/paused/completed/failed/cancelled/
 * abandoned, not typed branch waits, next breakpoint or injected results.
 * Canon Query(run, branch) returns state, progress, waits, next breakpoint,
 * checkpoint and why alive. Signal(consent answer) targets the matching wait;
 * its retry returns the cached settled result. Wire DTOs still need binding.
 *
 * Start two real child branches. Observe A parked with human wait class and
 * its bound recipient; B must finish its sink effect while A remains parked.
 * Re-read A across restart to prove the wait durable. A mismatched reply must
 * not release it. Send the matching authorized answer, resend the same reply,
 * and inspect both outcomes: one A resume/effect, one B effect, same child IDs.
 * No polling-model calls while A waits. Do not replace children with two
 * unrelated root requests or treat tasks.answer as approval of an outbound act.
 *
 * Now public: holding a live parent run. A parent agent TASK whose code-mode program
 * asks and waits parks on a durable wait that keeps its lease and live entry
 * (resident_pump.rs:491-523, live_runs.rs:320-341); the agent's own paired
 * credential then gets its handle from self.run.attach, and self.agents.spawn
 * or vault.fanout.spawn admits real children under it.
 * Missing: a public read of a child branch's durable wait. A child that asks a
 * human parks, but no door returns that wait's ask handle, wait class or bound
 * recipient, so the authorized person cannot address tasks.answer to it:
 * - a self.agents.spawn child has no TASK and inherits run_id None
 *   (dispatch.rs:218-224, coordination.rs:343), so vault.runs.branches.get
 *   (needs task_ref) and GET /v1/core/run-tree (needs run_id) cannot read it;
 * - a vault.fanout.spawn child has a TASK, but RunBranchView.asks holds only
 *   run-tree signal asks (run_tree/signal.rs:55-92), TaskStatusView.asks lists
 *   asks only for a TASK in Blocked (highway_status.rs:267-275), and an in-run
 *   ask does not block its TASK;
 * - vault.runs.checkpoint shows committed steps, and parked waits only after
 *   they resume (CheckpointView.resumed).
 * Do not compute the ask's group_ref, read a private queue or use execute_code.
 * Fixture rule for the full case: one chat origin serves every agent run in
 * strict FIFO order (providers.ts:215-218), so admit child A, wait for its park,
 * then admit child B; never two children with outstanding model calls at once.
 */
suite.todo(test, "RUNS-02", "waits on a public read of a child branch's durable wait (its ask handle, wait class and bound recipient) for a child admitted under an attached live run (Only waiting branch pauses should work)");

type Runs03Branch = FacadeResult<"vault.runs.branches.get">["branches"][number];
type Runs03Outcome<T> = { readonly value: T } | { readonly refused: { readonly status: number; readonly code: string } };

/** The authored RUNS-03 inputs (steer wording and key) from runs-scenarios. */
async function runs03Inputs(): Promise<{ readonly steerInstruction: string; readonly steerKey: string }> {
  const data = await (await loadFixtures()).readJson<{
    scenarios: readonly { id: string; inputs: { steerInstruction: string; steerKey: string } }[];
  }>("runs-scenarios");
  const row = data.scenarios.find(scenario => scenario.id === "RUNS-03");
  if (!row) throw new Error("runs-scenarios has no RUNS-03 row");
  return row.inputs;
}

/** One door call, kept as its success body or its public refusal (status + error code). */
async function runs03Attempt<T>(call: () => Promise<T>): Promise<Runs03Outcome<T>> {
  try {
    return { value: await call() };
  } catch (error) {
    if (error instanceof PublicHttpError) return { refused: { status: error.reply.status, code: error.error?.code ?? "" } };
    throw error;
  }
}

/** A call that must be refused: its status and error code. */
async function runs03Refusal(call: () => Promise<unknown>): Promise<{ readonly status: number; readonly code: string }> {
  const outcome = await runs03Attempt(call);
  if ("value" in outcome) throw new Error("expected a public refusal, got a success body");
  return outcome.refused;
}

/** Mints one owner TASK with no assignee: the Dreamer lane's one local realizing attempt. */
async function runs03Task(engine: EngineFixture, title: string, label: string): Promise<string> {
  const created = await engine.client.call("tasks.create", {
    spec: { title, description: "RUNS-03 branch under owner run control", lane: "runs03" },
    label,
  });
  expect(created.approval).toBe("auto");
  expect(created.effected).toBe(true);
  expect(created.proposal_ref ?? null).toBeNull();
  if (!created.route || !("DreamerAttempt" in created.route)) throw new Error(`${title} did not route to a local Dreamer attempt`);
  if (!created.task_ref) throw new Error(`${title} returned no TASK ref`);
  return created.task_ref;
}

/** The TASK's single branch, read through the owner's branch door. */
async function runs03Branch(engine: EngineFixture, task: string): Promise<Runs03Branch> {
  const view = await engine.client.call("vault.runs.branches.get", { task_ref: task });
  expect(view.task_ref).toBe(task);
  expect(view.branches).toHaveLength(1);
  const [branch] = view.branches;
  if (!branch) throw new Error(`TASK ${task} has no branch`);
  return branch;
}

/* RUNS-03 (partial): the owner pauses, resumes and force-cancels real queued
 * TASK branches; an unauthorized caller's force, steer, pause and soft cancel
 * change nothing; a pause and a forced cancellation both survive a SIGKILL.
 * Doors: HTTP facade tasks.create, vault.runs.branches.get, vault.runs.pause,
 * vault.runs.resume, vault.tasks.cancel.force, steer, cancel,
 * vault.agents.create, self.actor; CLI `token pair` through engine.pairActor.
 * Unproved: steer consumed at a safe breakpoint (needs a live leased run with
 * a run_id, which needs a scripted live worker rig not bound here).
 * Unproved: graceful cancel refusal with a reason, landing and its saved
 * partial result (no public door makes a worker soft-reject or land).
 * Unproved: the owner's soft cancel effecting (fresh-vault gate likely
 * proposes it; see RUNS-03.report.md) and failed/abandoned branch status.
 */
suite.test(test, "RUNS-03", "Owner pause, resume and force-cancel of queued task branches survive a kill and refuse an unauthorized caller", async () => {
  const inputs = await runs03Inputs();
  // Explicit host setting: no Dreamer runs, so nothing claims the queued branches.
  const engine = await EngineFixture.start({ id: "RUNS-03", profile, serverConfig: "[models.dreamer]\nenabled = false\n" });

  const pauseTask = await runs03Task(engine, "RUNS-03 pause and resume", "runs03-pause");
  const forceTask = await runs03Task(engine, "RUNS-03 owner force", "runs03-force");
  const pauseBefore = await runs03Branch(engine, pauseTask);
  const forceBefore = await runs03Branch(engine, forceTask);
  for (const branch of [pauseBefore, forceBefore]) {
    expect(branch.branch).toMatch(/^[0-9a-f]{32}$/);
    expect(branch.state).toBe("Queued");
    expect(branch.agent_status).toBe("spawned");
    expect(branch.signals).toEqual([]);
    expect(branch.cancel_state.cancellation ?? null).toBeNull();
  }
  expect(pauseBefore.branch).not.toBe(forceBefore.branch);

  // An unauthorized caller: a real inert agent principal, paired with every verb,
  // holding no standing on either TASK.
  const strangerRef = createHash("sha256").update("runs-03:unauthorized-caller").digest("hex").slice(0, 32);
  const agent = await engine.client.call("vault.agents.create", {
    agent_def_ref: strangerRef,
    definition: { agent_id: "runs-03-unauthorized", display_name: "runs-03-unauthorized",
      desc: "Holds no standing on either RUNS-03 TASK", version: "1" },
  });
  expect(agent.agent_def_ref).toBe(strangerRef);
  const stranger = await engine.pairActor({ principalRef: strangerRef, actorClass: "agent" });
  const identity = await stranger.client.call("self.actor", {});
  expect(identity.actor_ref).toBe(strangerRef);
  expect(identity.actor_class).toBe("agent");

  expect(await runs03Refusal(() => stranger.client.call("vault.tasks.cancel.force",
    { task_ref: forceTask, reason: "runs-03 unauthorized force" }))).toEqual({ status: 403, code: "FORBIDDEN" });
  expect(await runs03Refusal(() => stranger.client.call("steer",
    { task_ref: pauseTask, instruction: inputs.steerInstruction, key: `${inputs.steerKey}-unauthorized` })))
    .toEqual({ status: 403, code: "FORBIDDEN" });
  const strangerPause = await runs03Refusal(() => stranger.client.call("vault.runs.pause",
    { branch: pauseBefore.branch, note: "runs-03 unauthorized pause" }));
  expect([403, 404]).toContain(strangerPause.status);
  expect(["FORBIDDEN", "NOT_FOUND"]).toContain(strangerPause.code);
  // The soft cancel is refused at the read admission when the stranger cannot
  // read the TASK, else parked as a proposal; on either path it stops nothing.
  const strangerCancel = await runs03Attempt(() => stranger.client.call("cancel", { task_ref: forceTask }));
  if ("value" in strangerCancel) {
    expect(strangerCancel.value.approval).toBe("proposed");
    expect(strangerCancel.value.effected).toBe(false);
    expect(strangerCancel.value.forced).toBe(false);
    expect(strangerCancel.value.cancel_requested).toBe(false);
  } else {
    expect([403, 404]).toContain(strangerCancel.refused.status);
  }
  expect(await runs03Branch(engine, pauseTask)).toEqual(pauseBefore);
  expect(await runs03Branch(engine, forceTask)).toEqual(forceBefore);

  // Owner pause; a repeat is a replay that changes nothing.
  const paused = await engine.client.call("vault.runs.pause", { branch: pauseBefore.branch, note: "runs-03 owner pause" });
  expect(paused.effect).toBe("paused");
  expect(paused.branch.branch).toBe(pauseBefore.branch);
  expect(paused.branch.state).toBe("Paused");
  expect(paused.branch.agent_status).toBe("needs_input");
  expect(paused.branch.attempt_count).toBe(pauseBefore.attempt_count);
  const pausedAgain = await engine.client.call("vault.runs.pause", { branch: pauseBefore.branch });
  expect(pausedAgain.effect).toBe("already_paused");
  expect(pausedAgain.branch).toEqual(paused.branch);
  expect(await runs03Branch(engine, pauseTask)).toEqual(paused.branch);

  // Owner force: unrefusable, receipted, and a repeat stops nothing more.
  const forced = await engine.client.call("vault.tasks.cancel.force", { task_ref: forceTask, reason: "runs-03 owner force" });
  expect(forced.task_ref).toBe(forceTask);
  expect(forced.effected).toBe(true);
  expect(forced.forced).toBe(1);
  expect(forced.branches).toHaveLength(1);
  const [stopped] = forced.branches;
  if (!stopped) throw new Error("Owner force returned no branch");
  expect(stopped.branch).toBe(forceBefore.branch);
  expect(stopped.state).toBe("Cancelled");
  expect(stopped.agent_status).toBe("cancelled");
  expect(stopped.cancel_state.cancellation?.mode).toBe("forced");
  expect(stopped.cancel_state.cancellation?.grounds).toBe("owner");
  expect(stopped.cancel_state.cancellation?.reason).toBe("runs-03 owner force");
  expect((stopped.cancel_state.receipts ?? []).filter(receipt => receipt.kind === "force_cancelled")).toHaveLength(1);
  const forcedAgain = await engine.client.call("vault.tasks.cancel.force", { task_ref: forceTask, reason: "runs-03 owner force" });
  expect(forcedAgain.effected).toBe(false);
  expect(forcedAgain.forced).toBe(0);
  expect(forcedAgain.branches).toEqual(forced.branches);
  expect(await runs03Branch(engine, forceTask)).toEqual(stopped);
  // The paused sibling is untouched by the other TASK's force.
  expect(await runs03Branch(engine, pauseTask)).toEqual(paused.branch);

  // Failure step: SIGKILL the owned server and restart the same vault.
  await engine.kill();
  await engine.restart();
  expect(await runs03Branch(engine, pauseTask)).toEqual(paused.branch);
  expect(await runs03Branch(engine, forceTask)).toEqual(stopped);

  // The durable pause resumes after the kill; a repeat is a replay.
  const resumed = await engine.client.call("vault.runs.resume", { branch: pauseBefore.branch, note: "runs-03 owner resume" });
  expect(resumed.effect).toBe("resumed");
  expect(resumed.branch.branch).toBe(pauseBefore.branch);
  expect(resumed.branch.state).toBe("Queued");
  expect(resumed.branch.agent_status).toBe("spawned");
  expect(resumed.branch.attempt_count).toBe(pauseBefore.attempt_count);
  const resumedAgain = await engine.client.call("vault.runs.resume", { branch: pauseBefore.branch });
  expect(resumedAgain.effect).toBe("already_resumed");
  expect(resumedAgain.branch).toEqual(resumed.branch);

  // Boundary, not steer coverage: a branch with no live run takes no steer
  // and keeps no stray signal.
  expect(await runs03Refusal(() => engine.client.call("steer",
    { task_ref: pauseTask, instruction: inputs.steerInstruction, key: inputs.steerKey })))
    .toEqual({ status: 409, code: "INVALID_STATE" });
  expect((await runs03Branch(engine, pauseTask)).signals).toEqual([]);

  // The resumed branch is still the owner's to stop.
  const finalForce = await engine.client.call("vault.tasks.cancel.force", { task_ref: pauseTask });
  expect(finalForce.effected).toBe(true);
  expect(finalForce.forced).toBe(1);
  const finalBranch = await runs03Branch(engine, pauseTask);
  expect(finalBranch.state).toBe("Cancelled");
  expect(finalBranch.agent_status).toBe("cancelled");
  expect(finalBranch.cancel_state.cancellation?.mode).toBe("forced");

  // Terminal retry: a soft cancel of the already-forced TASK stops nothing more.
  const terminalCancel = await engine.client.call("cancel", { task_ref: forceTask });
  expect(terminalCancel.effected).toBe(false);
  expect(terminalCancel.forced).toBe(false);
  expect(terminalCancel.cancel_requested).toBe(false);
  expect(await runs03Branch(engine, forceTask)).toEqual(stopped);
});

/* RUNS-04 — Wake stops at its wall-clock ceiling should work.
 * Row: OF-179. ARCH-0026 #wake-model, #run-tree.
 * Oracle: runs-scenarios / RUNS-04. Activation deadline: 200_000 ms.
 *
 * Canon: one wake has a MONOTONIC 180_000 ms ceiling. No new call/step is
 * admitted after it; an already leased LlmBackend call is not killed. Cut
 * work parks durably for a later wake. The public DreamerAttemptView gives
 * attempt timestamps, not wake start/deadline, call leases or continuation.
 * Needed semantic result: wake identity + admitted start/deadline + which
 * calls already hold leases + parked work/continuation refs. Canon does not
 * publish their HTTP/SDK field spellings, so do not invent a /wake endpoint.
 *
 * Start a standard wake with two eligible steps. Hold the first real provider
 * call across 180 s, using a declared provider timeout above the ceiling.
 * Anchor time to the public wake admission, not witness time or server logs.
 * After the ceiling observe zero new admissions; the held call remains live.
 * Complete it and require its receipt to settle, while step two stays durable
 * and unstarted in that wake. A separately observed later wake may resume it.
 * Assert the later call belongs to that later wake, not an overlong first one.
 * No private clock, shortened ceiling, token-limit surrogate or timeout abort.
 * This is a real 180-second observation, not a loop of immediate status reads.
 *
 * Missing (main e79eb76df3e): the wake reads now exist
 * (vault.consolidation.wake.status gives the ceiling, call leases and the
 * per-generation checkpoint). The case needs a real 180 s observation, which
 * is a nightly budget case, not a 30 s E2E case (Fable section 4, rule 8), and
 * a publicly armed two-step program whose provider calls are scripted.
 */
suite.todo(test, "RUNS-04", "waits on a nightly budget slot for a real 180 s wake observation and a publicly armed two-step program (Wake stops at its wall-clock ceiling should work)");

type Runs05Evidence = FacadeResult<"vault.sieve.evidence">;

/** Host models: one scripted origin serves the Dreamer's two seats, so a Dreamer
 * can start; this case scripts no answer, so any model call fails the case. */
function runs05Config(providers: ScriptedProviders): string {
  const origin = providers.urls.model;
  if (!origin) throw new Error("ScriptedProviders started no model origin");
  return `
[models]
extraction_egress = true
[models.providers.runs05]
kind = "local-openai-compat"
base_url = "${origin}"
revision = "e2e-v1"
[models.roles.extraction_teacher]
model = "runs05:runs05-extract"
[models.roles.dreamer_current]
model = "runs05:runs05-summary"
[models.dreamer]
enabled = true
[models.workflows]
enabled = false
`;
}

/** Public stopped-vault owner command that routes the vault's model purposes to the
 * own-server origin, as PRIVACY-01 does; without it the Dreamer does not start. */
async function runs05GrantRoute(engine: EngineFixture): Promise<void> {
  await engine.kill();
  const grant = await engine.cli.run(["dreamer", "grant", "--config", `${engine.root}/oneiron.toml`,
    "--extraction-route", "own_server"]);
  expect(grant.exitCode).toBe(0);
  await engine.restart();
}

/** Owner dials that keep paid work out: no follower session, and no wake
 * recipe can come due within the case. Read back through the public reads. */
async function runs05QuietRecipes(engine: EngineFixture, idempotencyKey: string): Promise<void> {
  const recipe = await engine.client.call("vault.sieve.recipe_policy", {});
  const quietRecipe = { ...recipe, follower_enabled: false };
  expect(await engine.client.call("vault.sieve.recipe_policy.set", { policy: quietRecipe })).toEqual(quietRecipe);
  const cadence = await engine.client.call("vault.sieve.cadence", {});
  const quietWake = { ...cadence.policy, wake_grain_turns: 1_000_000, new_records: 1_000_000, idle_secs: 86_400,
    quiet_weave_secs: 86_400, longest_wait_secs: 86_400, nightly_secs: 86_400 };
  await engine.client.call("vault.settings.wake_policy.set", { policy: quietWake, idempotency_key: idempotencyKey });
  expect((await engine.client.call("vault.sieve.cadence", {})).policy).toEqual(quietWake);
}

/** Awaits a committed sieve read of the turn: the read clears the owed marker in
 * the same transaction that queues (or keeps) its spans. Reads only. */
function runs05Read(engine: EngineFixture, turn: string): Promise<Runs05Evidence> {
  return awaitPublic(() => engine.client.call("vault.sieve.evidence", { turn }),
    view => view.turn === turn && !view.owed && !view.continuing && (view.reading ?? null) !== null,
    { label: `sieve read of TURN ${turn}` });
}

/** Every conclusion id the shared-scheduler settlement roots and their jobs name. */
async function runs05Conclusions(engine: EngineFixture): Promise<string[]> {
  const page = await engine.client.call("vault.sieve.settlements", { limit: 100 });
  const ids = new Set<string>();
  for (const wake of page.wakes) {
    for (const id of wake.outcome.conclusions) ids.add(id);
    for (const job of wake.jobs) for (const id of job.conclusions) ids.add(id);
  }
  return [...ids].sort();
}

/** The sieve's public evidence state: interest queue, retained readings, consumed receipts, conclusions. */
async function runs05Snapshot(engine: EngineFixture) {
  return {
    queue: await engine.client.call("vault.sieve.queue", { limit: 1000 }),
    retained: await engine.client.call("vault.sieve.retained", { limit: 1000 }),
    receipts: await engine.client.call("vault.sieve.receipts", { limit: 1000 }),
    conclusions: await runs05Conclusions(engine),
  };
}

/* RUNS-05 (partial): after the real sieve has read a novel turn, replaying
 * that same stored TURN (not a second witness of the same words) owes it a
 * read again; the Dreamer re-reads it and the TURN identity, reading digest,
 * queued span handles, retained readings, consumed receipts and conclusion
 * ids are all unchanged, before and after a SIGKILL restart.
 * Doors: HTTP facade vault.witness, vault.conversations.create,
 * vault.sieve.{evidence,evidence.replay,queue,retained,receipts,settlements,
 * recipe_policy,recipe_policy.set,cadence}, vault.settings.wake_policy.set;
 * CLI `dreamer grant` on the stopped vault; ScriptedProviders (no answers).
 * Unproved: the novel turn's own paid work and conclusions (owner dials keep
 * paid recipes out; the finite novelty/extraction script is unbound), so the
 * conclusion comparison holds trivially here.
 * Unproved: a cadence boundary, Dreamer+Coach on one scheduler and zero model
 * polling during a resident-bound durable human wait (no such wait binds).
 */
suite.test(test, "RUNS-05", "Replaying an already-read turn re-reads the same TURN and adds no new sieve evidence, even after a kill", async () => {
  const data = await (await loadFixtures()).readJson<{
    scenarios: readonly { id: string; inputs: { novelTurn: string } }[];
  }>("runs-scenarios");
  const novelTurn = data.scenarios.find(scenario => scenario.id === "RUNS-05")?.inputs.novelTurn;
  if (!novelTurn) throw new Error("runs-scenarios has no RUNS-05 novel turn");
  const providers = await ScriptedProviders.start({ id: "runs-05-no-paid-work", steps: [], origins: ["model"] });
  const engine = await EngineFixture.start({ id: "RUNS-05", profile, serverConfig: runs05Config(providers) });
  await runs05GrantRoute(engine);
  const client = engine.client;
  await runs05QuietRecipes(engine, "runs-05-novel-only");
  const room = await client.call("vault.conversations.create", {
    body: { v: 1, kind: "direct", member_ids: [engine.pairedActor.principalRef], title: "RUNS-05 evidence replay" },
    text: [{ field: "title", value: "RUNS-05 evidence replay" }],
  });

  const witnessed = await client.call("vault.witness", {
    conversation_ref: room.id, occurred_at: Math.floor(Date.now() / 1000),
    messages: [{ author: "user", message_type: "text", content: novelTurn, is_visible: true, order: 0 }],
  });
  const turn = witnessed.turn?.id;
  const message = witnessed.messages?.[0]?.id;
  if (!turn || !message) throw new Error("Witness returned no TURN or MESSAGE record");
  const first = await runs05Read(engine, turn);
  const before = await runs05Snapshot(engine);
  // The novel turn is the only evidence in the queue, and it yielded spans.
  expect(before.queue.spans.length).toBeGreaterThan(0);
  for (const span of before.queue.spans) {
    expect(span.turn).toBe(turn);
    expect(span.source).toBe(message);
  }
  expect(before.queue.skipped_unreadable).toBe(0);
  expect(before.receipts.receipts).toEqual([]);

  // Replay the same ingress identity twice: each answer names the original
  // TURN and its unchanged reading, and owes it one read.
  for (let replay = 0; replay < 2; replay++) {
    const replayed = await client.call("vault.sieve.evidence.replay", { turn });
    expect(replayed.turn).toBe(turn);
    expect(replayed.owed).toBe(true);
    expect(replayed.reading).toEqual(first.reading);
  }
  const reread = await runs05Read(engine, turn);
  expect(reread.turn).toBe(turn);
  expect(reread.reading).toEqual(first.reading);
  expect(await runs05Snapshot(engine)).toEqual(before);

  // Forged input: replaying a CONVERSATION is refused and owes nothing.
  try {
    await client.call("vault.sieve.evidence.replay", { turn: room.id });
    throw new Error("Replay of a non-TURN was accepted");
  } catch (error) {
    if (!(error instanceof PublicHttpError)) throw error;
    expect(error.reply.status).toBe(400);
    expect(error.error?.code).toBe("BAD_REQUEST");
  }
  const afterRefusal = await client.call("vault.sieve.evidence", { turn });
  expect(afterRefusal.owed).toBe(false);
  expect(afterRefusal.reading).toEqual(first.reading);

  // Failure step: SIGKILL the owned server and restart the same vault, no reseed.
  await engine.kill();
  await engine.restart();
  const durable = await client.call("vault.sieve.evidence", { turn });
  expect(durable.turn).toBe(turn);
  expect(durable.owed).toBe(false);
  expect(durable.reading).toEqual(first.reading);
  expect(await runs05Snapshot(engine)).toEqual(before);

  // The same replay after the restart is still identity-preserving and adds nothing.
  const replayedAfter = await client.call("vault.sieve.evidence.replay", { turn });
  expect(replayedAfter.turn).toBe(turn);
  expect(replayedAfter.owed).toBe(true);
  const rereadAfter = await runs05Read(engine, turn);
  expect(rereadAfter.reading).toEqual(first.reading);
  expect(await runs05Snapshot(engine)).toEqual(before);

  // No model call was made: the re-read is the rule sieve's, and paid work was dialed out.
  await engine.close();
  await providers.close();
  expect(providers.seenFixtureCalls).toEqual([]);
});

type Runs06Span = FacadeResult<"vault.sieve.queue">["spans"][number];
type Runs06Evidence = FacadeResult<"vault.sieve.evidence">;
interface Runs06Source { readonly label: string; readonly priority: string; readonly turn: string; readonly message: string;
  readonly evidence: Runs06Evidence; readonly spans: readonly Runs06Span[]; readonly top: Runs06Span }

/** The owner-authored ranking dial for each fixture priority. Owner data, not an engine default. */
function runs06DateInterest(priority: string): number {
  const interest = ({ highest: 300, middle: 200, lowest: 100 } as Readonly<Record<string, number>>)[priority];
  if (interest === undefined) throw new Error(`No RUNS-06 date interest for priority ${priority}`);
  return interest;
}

/** Host models: one scripted origin serves the Dreamer's two seats, so a Dreamer
 * can start; this case scripts no answer, so any model call fails the case. */
function runs06Config(providers: ScriptedProviders): string {
  const origin = providers.urls.model;
  if (!origin) throw new Error("ScriptedProviders started no model origin");
  return `
[models]
extraction_egress = true
[models.providers.runs06]
kind = "local-openai-compat"
base_url = "${origin}"
revision = "e2e-v1"
[models.roles.extraction_teacher]
model = "runs06:runs06-extract"
[models.roles.dreamer_current]
model = "runs06:runs06-summary"
[models.dreamer]
enabled = true
[models.workflows]
enabled = false
`;
}

/** Public stopped-vault owner command that routes the vault's model purposes to the
 * own-server origin, as PRIVACY-01 does; without it the Dreamer does not start. */
async function runs06GrantRoute(engine: EngineFixture): Promise<void> {
  await engine.kill();
  const grant = await engine.cli.run(["dreamer", "grant", "--config", `${engine.root}/oneiron.toml`,
    "--extraction-route", "own_server"]);
  expect(grant.exitCode).toBe(0);
  await engine.restart();
}

/** Owner dials that keep paid work out: no follower session, and no wake
 * recipe can come due within the case. Read back through the public reads. */
async function runs06QuietRecipes(engine: EngineFixture, idempotencyKey: string): Promise<void> {
  const recipe = await engine.client.call("vault.sieve.recipe_policy", {});
  const quietRecipe = { ...recipe, follower_enabled: false };
  expect(await engine.client.call("vault.sieve.recipe_policy.set", { policy: quietRecipe })).toEqual(quietRecipe);
  const cadence = await engine.client.call("vault.sieve.cadence", {});
  const quietWake = { ...cadence.policy, wake_grain_turns: 1_000_000, new_records: 1_000_000, idle_secs: 86_400,
    quiet_weave_secs: 86_400, longest_wait_secs: 86_400, nightly_secs: 86_400 };
  await engine.client.call("vault.settings.wake_policy.set", { policy: quietWake, idempotency_key: idempotencyKey });
  expect((await engine.client.call("vault.sieve.cadence", {})).policy).toEqual(quietWake);
}

/** Awaits the turn's first sieve read: the read clears the owed marker in the same
 * transaction that queues its spans, so this is a committed-read barrier. Reads only. */
function runs06Read(engine: EngineFixture, turn: string): Promise<Runs06Evidence> {
  return awaitPublic(() => engine.client.call("vault.sieve.evidence", { turn }),
    view => view.turn === turn && !view.owed && !view.continuing && (view.reading ?? null) !== null,
    { label: `sieve read of TURN ${turn}` });
}

async function runs06Refusal(call: () => Promise<unknown>): Promise<{ readonly status: number; readonly code: string }> {
  try { await call(); }
  catch (error) {
    if (error instanceof PublicHttpError) return { status: error.reply.status, code: error.error?.code ?? "" };
    throw error;
  }
  throw new Error("expected a public refusal, got a success body");
}

/* RUNS-06 (partial): three authored turns are read by the real rule sieve
 * under owner ranking dials; the lower-ranked spans stay queued, with their
 * original turn/source/range handles, past a one-span page, a policy
 * replacement and a SIGKILL restart, and nothing is consumed or dropped.
 * Doors: HTTP facade vault.witness, vault.conversations.create,
 * vault.sieve.{policy,policy.set,queue,retained,receipts,evidence,
 * recipe_policy,recipe_policy.set,cadence}, vault.settings.wake_policy.set;
 * CLI `dreamer grant` on the stopped vault; ScriptedProviders (no answers).
 * Unproved: budget-gated consumption of only the first unit and a refill
 * consuming the rest once (refill replaces a counter total; it is not a
 * per-queue gate, and the paid novelty/typing/extraction script is unbound).
 * Unproved: a later weave citing the retained evidence (no per-weave
 * consumed-source/citation read exists).
 */
suite.test(test, "RUNS-06", "Lower-ranked sieve spans stay queued with their source ranges past a one-span page, a policy change and a kill", async () => {
  const data = await (await loadFixtures()).readJson<{
    scenarios: readonly { id: string; inputs: { spans: readonly { label: string; text: string; priority: string }[] } }[];
  }>("runs-scenarios");
  const authored = data.scenarios.find(scenario => scenario.id === "RUNS-06")?.inputs.spans;
  if (!authored || authored.length !== 3) throw new Error("runs-scenarios RUNS-06 must author three spans");
  const providers = await ScriptedProviders.start({ id: "runs-06-no-paid-work", steps: [], origins: ["model"] });
  const engine = await EngineFixture.start({ id: "RUNS-06", profile, serverConfig: runs06Config(providers) });
  await runs06GrantRoute(engine);
  const client = engine.client;
  await runs06QuietRecipes(engine, "runs-06-retention-only");
  const basePolicy = await client.call("vault.sieve.policy", {});
  const room = await client.call("vault.conversations.create", {
    body: { v: 1, kind: "direct", member_ids: [engine.pairedActor.principalRef], title: "RUNS-06 sieve retention" },
    text: [{ field: "title", value: "RUNS-06 sieve retention" }],
  });

  // Each source is scored under its own owner ranking row; its first read is
  // awaited before the next row is written.
  const sources: Runs06Source[] = [];
  for (const input of authored) {
    const policy = { ...basePolicy, date_interest: runs06DateInterest(input.priority) };
    expect(await client.call("vault.sieve.policy.set", { policy })).toEqual(policy);
    const witnessed = await client.call("vault.witness", {
      conversation_ref: room.id, occurred_at: Math.floor(Date.now() / 1000),
      messages: [{ author: "user", message_type: "text", content: input.text, is_visible: true, order: 0 }],
    });
    const turn = witnessed.turn?.id;
    const message = witnessed.messages?.[0]?.id;
    if (!turn || !message) throw new Error(`Witness of ${input.label} returned no TURN or MESSAGE record`);
    expect(witnessed.messages).toHaveLength(1);
    const evidence = await runs06Read(engine, turn);
    const spans = (await client.call("vault.sieve.queue", { limit: 1000 })).spans.filter(span => span.turn === turn);
    for (const span of spans) {
      expect(span.source).toBe(message);
      expect(span.end).toBeGreaterThan(span.start);
      expect(span.owed).toContain("novelty");
    }
    const top = spans.find(span => span.kind === "date");
    if (!top) throw new Error(`The sieve queued no date span for ${input.label}`);
    sources.push({ label: input.label, priority: input.priority, turn, message, evidence, spans, top });
  }
  const [high, medium, low] = sources;
  if (!high || !medium || !low) throw new Error("Three sources were not read");
  expect([high.priority, medium.priority, low.priority]).toEqual(["highest", "middle", "lowest"]);
  // Each source kept the ranking row it was read under: later rows rescored nothing.
  expect(new Set([high.top.policy_digest, medium.top.policy_digest, low.top.policy_digest]).size).toBe(3);
  expect(high.top.score).toBeGreaterThan(medium.top.score);
  expect(medium.top.score).toBeGreaterThan(low.top.score);

  const queued = await client.call("vault.sieve.queue", { limit: 1000 });
  expect(queued.skipped_unreadable).toBe(0);
  expect(queued.skipped_detached).toBe(0);
  expect(queued.spans.every(span => sources.some(source => source.turn === span.turn))).toBe(true);
  for (const source of sources) for (const span of source.spans) expect(queued.spans).toContainEqual(span);
  const order = queued.spans.map(span => span.span);
  expect(order.indexOf(high.top.span)).toBeGreaterThanOrEqual(0);
  expect(order.indexOf(high.top.span)).toBeLessThan(order.indexOf(medium.top.span));
  expect(order.indexOf(medium.top.span)).toBeLessThan(order.indexOf(low.top.span));

  // A one-span page serves the highest-ranked span and deletes nothing.
  const head = await client.call("vault.sieve.queue", { limit: 1 });
  expect(head.spans).toEqual(queued.spans.slice(0, 1));
  expect(head.spans[0]?.turn).toBe(high.turn);
  expect(await client.call("vault.sieve.queue", { limit: 1000 })).toEqual(queued);

  // A replacement ranking row that would rank names above dates changes no
  // queued span: a priority change neither drops nor rescores queued work.
  const replaced = { ...basePolicy, date_interest: 1, name_interest: 1000 };
  expect(await client.call("vault.sieve.policy.set", { policy: replaced })).toEqual(replaced);
  expect(await client.call("vault.sieve.queue", { limit: 1000 })).toEqual(queued);
  // Forged input: an invalid ranking row is refused and replaces nothing.
  expect(await runs06Refusal(() => client.call("vault.sieve.policy.set", { policy: { ...replaced, max_turns_per_pass: 0 } })))
    .toEqual({ status: 400, code: "BAD_REQUEST" });
  expect(await client.call("vault.sieve.policy", {})).toEqual(replaced);

  // Every queued span is also a retained original reading; none was consumed.
  const retained = await client.call("vault.sieve.retained", { limit: 1000 });
  for (const span of queued.spans) expect(retained.spans).toContainEqual(span);
  expect((await client.call("vault.sieve.receipts", { limit: 1000 })).receipts).toEqual([]);

  // Failure step: SIGKILL the owned server and restart the same vault, no reseed.
  await engine.kill();
  await engine.restart();
  expect(await client.call("vault.sieve.queue", { limit: 1000 })).toEqual(queued);
  expect(await client.call("vault.sieve.queue", { limit: 1 })).toEqual(head);
  expect(await client.call("vault.sieve.retained", { limit: 1000 })).toEqual(retained);
  expect((await client.call("vault.sieve.receipts", { limit: 1000 })).receipts).toEqual([]);
  expect(await client.call("vault.sieve.policy", {})).toEqual(replaced);
  for (const source of sources) {
    const evidence = await client.call("vault.sieve.evidence", { turn: source.turn });
    expect(evidence.turn).toBe(source.turn);
    expect(evidence.owed).toBe(false);
    expect(evidence.reading).toEqual(source.evidence.reading);
  }

  // No model call was made: the read is the rule sieve's, and paid work was dialed out.
  await engine.close();
  await providers.close();
  expect(providers.seenFixtureCalls).toEqual([]);
});

/** 2026-10-17T00:00:00Z, the fixture's authored day, in Unix seconds: a setup input, never a clock change. */
const RUNS07_OCCURRED = 1792195200;
const RUNS07_PREDICATE = "observatory.lens";
/** predicate_root drops the final dotted segment (crates/oneiron/src/claim/predicate_grammar.rs:193-202). */
const RUNS07_PREDICATE_ROOT = "observatory";
const RUNS07_STRANGER = "07000000000000000000000000000030";
/** Arrival order is the reverse of sort order: the root stores children sorted by child_ref. */
const RUNS07_CHILD_FIRST_SORTED = "07000000000000000000000000000011";
const RUNS07_CHILD_SECOND_SORTED = "07000000000000000000000000000012";
const RUNS07_CHILD_FORGED = "07000000000000000000000000000013";
const RUNS07_CHILD_LIVE_HEAD = "07000000000000000000000000000014";
const RUNS07_CHILD_EMPTY_RANGE = "07000000000000000000000000000015";
const RUNS07_CHILD_STRANGER = "07000000000000000000000000000016";

interface Runs07Scenario {
  readonly id: string;
  readonly inputs: {
    readonly sources: readonly { readonly label: string; readonly sourceClass: Facade.ClaimSource; readonly text: string }[];
    readonly postPinSourceEdit: string;
    readonly invalidChildMetadata: { readonly hash: string; readonly trust: string };
  };
  readonly expected: {
    readonly rootPinnedRevisionCount: number;
    readonly duplicateCitationAddsSignals: number;
    readonly livePostPinEditUsedByOldWake: boolean;
    readonly childComputedHashTrusted: boolean;
  };
}
type Runs07Accounting = FacadeResult<"vault.consolidation.accounting">;
type Runs07BucketAccounting = Runs07Accounting["buckets"][number];
type Runs07Child = FacadeInput<"vault.consolidation.frontier">["children"][number];

async function runs07Scenario(): Promise<Runs07Scenario> {
  const fixture = await (await loadFixtures()).readJson<{ readonly scenarios: readonly Runs07Scenario[] }>("runs-scenarios");
  const scenario = fixture.scenarios.find(row => row.id === "RUNS-07");
  if (!scenario) throw new Error("Missing RUNS-07 fixture scenario");
  return scenario;
}
function runs07OnlyRow<T>(rows: readonly T[], label: string): T {
  expect(rows).toHaveLength(1);
  const row = rows[0];
  if (row === undefined) throw new Error(`${label} is empty`);
  return row;
}
function runs07OnlyBucket(accounting: Runs07Accounting): Runs07BucketAccounting {
  return runs07OnlyRow(accounting.buckets, "root accounting buckets");
}
function runs07SameBytes(left: readonly number[], right: readonly number[]): boolean {
  return left.length === right.length && left.every((byte, index) => byte === right[index]);
}
async function runs07EntityId(client: PublicHttpClient, entity_ref: string, kind: string): Promise<string> {
  const read = await client.call("vault.get", { entity_ref });
  if (!read.value) throw new Error(`Public entity missing: ${entity_ref}`);
  expect(read.value.kind).toBe(kind);
  return read.value.id_hex;
}
/** A typed call the engine must refuse; returns the public status and envelope code. */
async function runs07Refusal<V extends FacadeVerb>(client: PublicHttpClient, verb: V, input: FacadeInput<V>):
  Promise<{ readonly status: number; readonly code: string | undefined }> {
  try {
    await client.call(verb, input);
  } catch (error) {
    if (error instanceof PublicHttpError) return { status: error.reply.status, code: error.error?.code };
    throw error;
  }
  throw new Error(`${verb} was admitted where the engine must refuse it`);
}
function runs07Claim(owner: string, scope: Facade.ClaimScope, source: Facade.ClaimSource, value: string,
  id?: string): FacadeInput<"vault.claims.upsert"> {
  return { ...(id === undefined ? {} : { id }), predicate: RUNS07_PREDICATE, subject_ref: owner, value,
    confidence: 0.9, source, scope, evidence_turn_refs: [] };
}
function runs07Child(child_ref: string, bucket_hash: number[], value: string,
  evidence: Facade.ConsolidationReference[]): Runs07Child {
  return { child_ref, bucket_hash, judgement: { predicate: RUNS07_PREDICATE, value, confidence: 0.8 }, evidence };
}

/* RUNS-07 (partial) — the root trusts only its own pin and counts a duplicate child citation once.
 * Promise: after the owner pins source-a, children carry references only; the root counts one
 *   independent signal from its own source+hash however many children cite it, never takes a
 *   child's hash/trust, keeps its original pin across a live-head correction and a restart.
 * Doors: HTTP facade vault.structural.put, vault.claims.upsert, vault.get, vault.agents.create,
 *   vault.consolidation.pin/.frontier/.accounting; raw POST of the same frontier route for the
 *   malformed (forged hash/trust) wire; engine.pairActor for the stranger; engine.restart().
 * Unproved: summary-a (needs authorized generated lineage), foreign-tool second signal (tool_output
 *   lands Proposed, needs a public review path), bronze/crossProjectMerge (needs two real projects,
 *   which today need the model-driven project drafter), ancestor taint meet, settled claims and
 *   their corroboration receipts (bridge settlement has no root-attributed public read), the
 *   four-child [2,0,3,1] order (two children here), out-of-bounds byte ranges (needs a pinnable TURN).
 * Project axis: a public TASK stands in for amber because the default project id has no entity row
 *   and pin requires a readable project selector (root_evidence.rs:319-326, visibility.rs:139-141).
 * Guards a fixed defect: the bucket names the claim's own facet. Before bc240f4f5bf the pin read
 *   a facade claim's facet only from scope key "facet_ref" (the facade writes "facet" as hex), so
 *   this pin was refused as crossing its bucket axes. Red on main e79eb76df3e, green on the fix.
 */
suite.test(test, "RUNS-07", "Consolidation root trusts only its own pin and counts duplicate citations once should work", async () => {
  const engine = await EngineFixture.start({ id: "RUNS-07", profile, serverConfig: "[models.dreamer]\nenabled = false\n" });
  const scenario = await runs07Scenario();
  const sourceA = scenario.inputs.sources.find(row => row.label === "source-a");
  if (!sourceA) throw new Error("Missing RUNS-07 source-a");
  const client = engine.client;
  const owner = engine.pairedActor.principalRef;
  const base = await ownerBaseClaimScope(client, owner);
  // A readable project-axis carrier (see header). TASK bodies need the TaskRole::Task byte.
  const carrier = await client.call("vault.structural.put", {
    kind: "TASK", body: { title: "RUNS-07 project axis", role: 1 },
    occurred_at: RUNS07_OCCURRED, learned_at: RUNS07_OCCURRED,
  });
  const scope: Facade.ClaimScope = { ...base, scope_project_id: carrier.id_hex };

  const written = await client.call("vault.claims.upsert", runs07Claim(owner, scope, sourceA.sourceClass, sourceA.text));
  expect(written.approval).toBe("auto");
  const sourceId = await runs07EntityId(client, written.claim_short_id, "CLAIM");
  const pinnedRef: Facade.ConsolidationReference = { source_id: sourceId, claim_id: sourceId };
  // The claim's own six-axis placement: base world is stored as absent, the owner's substrate
  // facet, all relationships (absent), and the carrier project.
  const bucket: Facade.ConsolidationRootBucket = { subject: owner, predicate_root: RUNS07_PREDICATE_ROOT,
    world: null, facet: scope.scope_facet_id, relationship: null, project: scope.scope_project_id };

  const pinned = await client.call("vault.consolidation.pin", { buckets: [{ bucket, evidence: [pinnedRef] }] });
  const rootRef = pinned.root_ref;
  const revisions = new Set<number>([pinned.revision]);
  const pinnedBucket = runs07OnlyBucket(pinned);
  const bucketHash = pinnedBucket.bucket_hash;
  const pin = runs07OnlyRow(pinnedBucket.pinned, "root pins");
  expect(pin.reference.source_id).toBe(sourceId);
  expect(pin.trust_class).toBe(sourceA.sourceClass);
  expect(pin.corroborates).toBe(true);
  expect(pin.refusal ?? null).toBeNull();
  expect(pin.ancestors).toHaveLength(0);
  expect(pinnedBucket.children).toHaveLength(0);
  expect(pinnedBucket.independent).toHaveLength(0);

  // The owner corrects source-a after the pin: a fresh live head supersedes the pinned claim.
  const corrected = await client.call("vault.claims.upsert",
    runs07Claim(owner, scope, sourceA.sourceClass, scenario.inputs.postPinSourceEdit, sourceId));
  expect(corrected.approval).toBe("auto");
  expect(corrected.superseded_short_id).toBe(written.claim_short_id);
  expect(corrected.claim_short_id).not.toBe(written.claim_short_id);
  const liveHeadId = await runs07EntityId(client, corrected.claim_short_id, "CLAIM");
  const afterEdit = await client.call("vault.consolidation.accounting", { root_ref: rootRef });
  revisions.add(afterEdit.revision);
  expect(afterEdit).toEqual(pinned);
  // Control: a pin taken now reads the new head's bytes at a later revision, so an unchanged
  // old root proves it never re-read the live head.
  const livePin = await client.call("vault.consolidation.pin",
    { buckets: [{ bucket, evidence: [{ source_id: liveHeadId, claim_id: liveHeadId }] }] });
  expect(livePin.root_ref).not.toBe(rootRef);
  expect(livePin.revision).toBeGreaterThan(pinned.revision);
  const livePinRow = runs07OnlyRow(runs07OnlyBucket(livePin).pinned, "live-head pins");
  expect(runs07SameBytes(livePinRow.content_hash, pin.content_hash)).toBe(false);

  // Children finish out of order and both cite source-a: one independent signal.
  const first = await client.call("vault.consolidation.frontier", { root_ref: rootRef,
    children: [runs07Child(RUNS07_CHILD_SECOND_SORTED, bucketHash, "amber", [pinnedRef])] });
  revisions.add(first.revision);
  const firstBucket = runs07OnlyBucket(first);
  const firstSignal = runs07OnlyRow(firstBucket.independent, "independent sources after one child");
  expect(firstSignal.reference.source_id).toBe(sourceId);
  expect(firstBucket.duplicates_collapsed).toBe(0);
  const second = await client.call("vault.consolidation.frontier", { root_ref: rootRef,
    children: [runs07Child(RUNS07_CHILD_FIRST_SORTED, bucketHash, "amber", [pinnedRef])] });
  revisions.add(second.revision);
  const counted = runs07OnlyBucket(second);
  expect(counted.children.map(child => child.child_ref)).toEqual([RUNS07_CHILD_FIRST_SORTED, RUNS07_CHILD_SECOND_SORTED]);
  expect(counted.independent.length - firstBucket.independent.length).toBe(scenario.expected.duplicateCitationAddsSignals);
  expect(counted.duplicates_collapsed).toBe(1);
  expect(counted.excluded_references).toBe(0);
  const signal = runs07OnlyRow(counted.independent, "independent sources after two children");
  // The counted signal is the root's own verified source+hash and trust, never a child's.
  expect(signal.reference.source_id).toBe(sourceId);
  expect(runs07SameBytes(signal.content_hash, pin.content_hash)).toBe(true);
  expect(runs07SameBytes(signal.source_revision, pin.source_revision)).toBe(true);
  expect(signal.trust_class).toBe(sourceA.sourceClass);
  expect(runs07SameBytes(signal.content_hash, livePinRow.content_hash)).toBe(scenario.expected.livePostPinEditUsedByOldWake);
  expect(counted.independent.some(row => !runs07SameBytes(row.content_hash, pin.content_hash)))
    .toBe(scenario.expected.childComputedHashTrusted);
  for (const child of counted.children) {
    // Stored references serialize absent locator parts as null, so compare their identity.
    expect(child.evidence.map(ref => [ref.source_id, ref.claim_id ?? null, ref.byte_range ?? null]))
      .toEqual([[sourceId, sourceId, null]]);
    expect(child).not.toHaveProperty("content_hash");
    expect(child).not.toHaveProperty("trust_class");
  }

  // Identical replay changes nothing; every refused child leaves the accounting unchanged.
  const replayed = await client.call("vault.consolidation.frontier", { root_ref: rootRef,
    children: [runs07Child(RUNS07_CHILD_SECOND_SORTED, bucketHash, "amber", [pinnedRef])] });
  expect(replayed).toEqual(second);
  const changed = await runs07Refusal(client, "vault.consolidation.frontier", { root_ref: rootRef,
    children: [runs07Child(RUNS07_CHILD_SECOND_SORTED, bucketHash, "cobalt", [pinnedRef])] });
  expect(changed).toEqual({ status: 400, code: "BAD_REQUEST" });
  const liveHeadCitation = await runs07Refusal(client, "vault.consolidation.frontier", { root_ref: rootRef,
    children: [runs07Child(RUNS07_CHILD_LIVE_HEAD, bucketHash, "cobalt", [{ source_id: liveHeadId, claim_id: liveHeadId }])] });
  expect(liveHeadCitation).toEqual({ status: 400, code: "BAD_REQUEST" });
  const emptyRange = await runs07Refusal(client, "vault.consolidation.frontier", { root_ref: rootRef,
    children: [runs07Child(RUNS07_CHILD_EMPTY_RANGE, bucketHash, "amber", [{ source_id: sourceId, byte_range: [3, 3] }])] });
  expect(emptyRange).toEqual({ status: 400, code: "BAD_REQUEST" });
  // Malformed wire on purpose: a child-supplied hash/trust is not part of the typed input.
  const forged = await client.raw("POST", "/v1/core/facade/vault.consolidation.frontier", {
    root_ref: rootRef,
    children: [{ ...runs07Child(RUNS07_CHILD_FORGED, bucketHash, "amber", [pinnedRef]), ...scenario.inputs.invalidChildMetadata }],
  }, { "x-oneiron-invocation": secretHex(16) });
  expect(forged.status).toBe(400);
  // Only the owner's root vouches: a paired agent cannot add a child to it.
  await client.call("vault.agents.create", { agent_def_ref: RUNS07_STRANGER,
    definition: { agent_id: "runs07-stranger", desc: "RUNS-07 unauthorized child submitter", version: "1" } });
  const stranger = await engine.pairActor({ principalRef: RUNS07_STRANGER, actorClass: "agent" });
  const strangerChild = await runs07Refusal(stranger.client, "vault.consolidation.frontier", { root_ref: rootRef,
    children: [runs07Child(RUNS07_CHILD_STRANGER, bucketHash, "amber", [pinnedRef])] });
  expect(strangerChild.status).toBe(403);
  const settled = await client.call("vault.consolidation.accounting", { root_ref: rootRef });
  revisions.add(settled.revision);
  expect(settled).toEqual(second);

  await engine.restart();
  const restarted = await client.call("vault.consolidation.accounting", { root_ref: rootRef });
  revisions.add(restarted.revision);
  expect(restarted).toEqual(second);
  expect(revisions.size).toBe(scenario.expected.rootPinnedRevisionCount);
});

/** RUNS-08 authored inputs (fixture discriminant, not a wire DTO). */
interface Runs08Scenario {
  id: "RUNS-08";
  inputs: { widths: number[]; approvalMode: string };
  expected: {
    resultsStayInInputSlots: boolean;
    countAloneCausesRefusal: boolean;
    planStatesDollarsAndCapBeforeLaunch: boolean;
    enforcedBudgetScopes: number;
    capMultipliedByWidth: boolean;
  };
}
const RUNS08_MODEL = "runs08-agent";
/** The parent TASK's pinned budget, in its tree's unit: the one hard cap every child draws on. */
const RUNS08_BUDGET = 500_000;
/** 2026-10-17T00:00:00Z, the fixture's authored day: a setup input, never a clock change. */
const RUNS08_OCCURRED = 1792195200;
const RUNS08_USAGE = { inputTokens: 256, outputTokens: 96 } as const;

function runs08InputId(label: string): string {
  return createHash("sha256").update(`runs-e2e:RUNS-08:${label}`).digest("hex").slice(0, 32);
}
async function runs08Scenario(): Promise<Runs08Scenario> {
  const data = await (await loadFixtures()).readJson<{ scenarios: { id: string }[] }>("runs-scenarios");
  const row = data.scenarios.find(item => item.id === "RUNS-08");
  if (!row) throw new Error("Missing RUNS-08 fixture scenario");
  return row as Runs08Scenario; // Fixture discriminant, not an invented wire DTO.
}
async function runs08Agent(client: PublicHttpClient, label: string, ceiling?: "auto"): Promise<string> {
  const agent_def_ref = runs08InputId(label);
  const created = await client.call("vault.agents.create", {
    agent_def_ref, definition: { agent_id: label, display_name: label, desc: `RUNS-08 ${label}`, version: "1", ...(ceiling === undefined ? {} : { ceiling }) },
  });
  expect(created.agent_def_ref).toBe(agent_def_ref);
  return agent_def_ref;
}
/** The asking agent's ask authority, each part read back after the put: an actor-bound Auto ceiling, and a read
 * grant on TURN records. Ask admission checks that the asker can read the question it cites
 * (task_ask.rs validate_task_answer_unit), and the owner witnessed that TURN. That reader key carries no actor
 * class, so the grant names the exact actor_ref and no actor_class; it grants read only, on TURNs only. */
async function grantAgentAskAuthority(owner: PublicHttpClient, agentRef: string): Promise<void> {
  const before: FacadeResult<"vault.gate.policy.get"> = await owner.call("vault.gate.policy.get", {});
  const manifest = before.manifests.find(row => row.manifest_ref === before.default_manifest_ref);
  if (!manifest) throw new Error("RUNS-08 has no default policy manifest");
  const row: FacadeInput<"vault.gate.policy.put">["manifest"]["actor_ceilings"][number] = {
    actor_class: "agent", actor_ref: agentRef, ceiling: "auto",
  };
  const questionRead: Facade.PolicyScopedGrantRow = {
    actor_ref: agentRef, effector: "core:read", receipt_required: false,
    scope: {
      worlds: { kind: "all" }, facets: { kind: "all" },
      bands: { kind: "some", values: [1] }, // Kind bands hold type bytes: 1 is ENTITY_TYPE_TURN.
      audience: { kind: "all" }, verbs: { kind: "some", values: ["read"] },
      sensitivity: { kind: "at_most", value: "restricted" },
    },
  };
  const put: FacadeInput<"vault.gate.policy.put"> = {
    manifest_ref: manifest.manifest_ref, expected_body_hash: manifest.body_hash,
    manifest: {
      ...manifest.manifest,
      actor_ceilings: [...manifest.manifest.actor_ceilings, row],
      scoped_grants: [...(manifest.manifest.scoped_grants ?? []), questionRead],
    },
  };
  const receipt = await owner.call("vault.gate.policy.put", put);
  expect(receipt.receipt_ref.length).toBeGreaterThan(0);
  const after: FacadeResult<"vault.gate.policy.get"> = await owner.call("vault.gate.policy.get", {});
  const live = after.manifests.find(row => row.manifest_ref === after.default_manifest_ref);
  expect(live?.manifest.actor_ceilings).toContainEqual(row);
  expect(live?.manifest.scoped_grants?.find(grant => grant.actor_ref === agentRef)).toMatchObject({
    effector: "core:read", receipt_required: false,
    scope: { bands: { kind: "some", values: [1] }, verbs: { kind: "some", values: ["read"] } },
  });
  const stored = await owner.call("vault.agents.get", { agent_def_ref: agentRef });
  expect(stored.definition.ceiling).toBe("auto");
}
/** A witnessed TURN the parent's ask cites: actually written, never a fabricated ref. */
async function runs08Turn(client: PublicHttpClient, content: string): Promise<string> {
  const conversation = await client.call("vault.conversations.create", {
    body: {}, occurred_start: RUNS08_OCCURRED, occurred_end: RUNS08_OCCURRED, learned_at: RUNS08_OCCURRED,
  });
  const witnessed = await client.call("vault.witness", {
    conversation_ref: conversation.id, occurred_at: RUNS08_OCCURRED,
    messages: [{ author: "user", message_type: "text", content, is_visible: true, order: 0 }],
  });
  const turn = (await client.call("vault.get", { entity_ref: witnessed.turn_short_id })).value;
  expect(turn?.kind).toBe("TURN");
  if (!turn) throw new Error("Question TURN is not readable");
  return turn.id_hex;
}
/** The parent TASK's brief: a pinned budget opens its hard spend scope (create_facade.rs:581-583). */
function runs08Brief(ownerRef: string, request: string): Facade.QueueTaskBrief {
  return {
    schema: 1,
    type_ref: { node_id: runs08InputId("task-type"), tree_version: 1 },
    objective: request,
    intent: { need: request, care: "light" },
    constraints: { pins: { budget: RUNS08_BUDGET } },
    success: { question: "Did the batch go out under the one parent cap?",
      criteria: { yes_if_all: [{ text: "Every child is admitted in its input slot under the parent's cap." }] } },
    settled: [],
    escalation: { to: { people: [ownerRef] }, triggers: [], default: "proceed", reversibility: "reversible_read" },
  };
}
/** One step: ask the owner, then wait on that ask, which parks the run with its lease (read.rs:209-230). */
function runs08ParkProgram(ownerRef: string, questionTurn: string): string {
  return [
    `const receipt = await ask({ intent_key: "runs08/parent-hold", who: { people: ["${ownerRef}"] },`,
    `  what: { reference: { turn: "${questionTurn}" }, revision: 1, context_refs: [],`,
    `    options: { proceed: { label: "Proceed" }, stop: { label: "Stop" } } } });`,
    `await wait({ handle: receipt.handle, step_key: "runs08/parent-hold" });`,
  ].join("\n");
}
function runs08Children(agent_ref: string, width: number, tag: string): Facade.FanoutChildInput[] {
  return Array.from({ length: width }, (_, index) => ({
    agent_ref, label: `runs08-${tag}-slot-${index}`, prompt: `Survey batch ${tag}, slot ${index} of ${width}.`,
  }));
}
async function runs08Refusal(call: Promise<unknown>): Promise<{ status: number; code: string | undefined; message: string | undefined }> {
  try {
    await call;
  } catch (error) {
    if (!(error instanceof PublicHttpError)) throw error;
    return { status: error.reply.status, code: error.error?.code, message: error.error?.message };
  }
  throw new Error("Expected a public refusal");
}
function runs08Launch(answer: FacadeResult<"vault.fanout.resume">): Facade.FanoutLaunchView {
  if (!("launch_ref" in answer)) throw new Error(`vault.fanout.resume answered ${JSON.stringify(answer)}, not a launch`);
  return answer;
}
/** A well-formed digest that differs from the frozen one in its last digit. */
function runs08OtherDigest(digest: string): string {
  return `${digest.slice(0, 63)}${digest.endsWith("0") ? "1" : "0"}`;
}
/** The held batch, read before any child exists: its statement, its hold and its input-order slots. */
function runs08ExpectHeldBatch(view: Facade.FanoutBatchView, parentTask: string,
  children: readonly Facade.FanoutChildInput[]): Facade.SpendCapView {
  expect(view.parent_task_ref).toBe(parentTask);
  expect(view.launch.plan_digest).toMatch(/^[0-9a-f]{64}$/);
  expect(view.launch.held?.denied).toBe(false);
  expect(view.launch.task_refs).toEqual([]);
  const statement = view.launch.statement;
  expect(statement.task_count).toBe(children.length);
  expect(statement.agent_count).toBe(children.length);
  expect(statement.consult_count).toBe(0);
  // Width alone raises no check under the shipped threshold, and never refuses.
  expect(statement.width_check ?? null).toBeNull();
  expect(Number.isFinite(statement.expected.units)).toBe(true);
  // Every part is either priced into the dollar subtotal or named as unpriced.
  expect((statement.priced_subtotal_usd_micros ?? null) !== null || statement.unpriced_parts.length > 0).toBe(true);
  const cap = statement.cap;
  if (!cap) throw new Error("The held plan states no cap");
  expect(cap.cap_units).toBeGreaterThan(0);
  expect(cap.cap_units).toBeLessThanOrEqual(RUNS08_BUDGET);
  expect(view.slots.map(slot => slot.index)).toEqual(children.map((_, index) => index));
  expect(view.slots.map(slot => slot.input)).toEqual([...children]);
  for (const slot of view.slots) {
    expect(slot.state).toBe("held");
    expect(slot.task_ref ?? null).toBeNull();
    expect(slot.attempts).toEqual([]);
  }
  const hard = view.accounting.hard_cap;
  if (!hard) throw new Error("The batch names no hard cap lease");
  expect(hard.lease.hard).toBe(true);
  expect(hard.lease.cap_units).toBeLessThanOrEqual(RUNS08_BUDGET);
  return cap;
}

/** Diagnostic for the parked live run: a branch that is not Leased fails with its stored reason and the engine's own
 * failure warning first, since the fleet log keeps only the first 400 characters of a failure reason. The stored
 * last_error is only the stable code (agent_run_failed); the warning carries the underlying error. */
async function expectParkedBranchLeased(
  engine: EngineFixture,
  label: string,
  branch: { state: string; last_error?: string | null; attempt_count: number; asks: readonly unknown[] } | undefined,
): Promise<void> {
  if (branch?.state === "Leased") return;
  const warning = await serverRunFailureWarning(engine);
  throw new Error(`${label}: state=${branch?.state ?? "missing"} last_error=${(branch?.last_error ?? "none").slice(0, 60)}`
    + ` attempts=${branch?.attempt_count ?? 0} asks=${branch?.asks.length ?? 0} | engine: ${warning.slice(0, 260)}`);
}

/** The last agent-run failure warning in the server's captured log. Diagnostic only, after a failure: it stops the
 * server, which writes that log into the fixture's artifacts, and reads it before close deletes them. */
async function serverRunFailureWarning(engine: EngineFixture): Promise<string> {
  await engine.kill();
  const warnings: string[] = [];
  for (const name of await readdir(engine.artifacts.root)) {
    if (!/^server-[a-f0-9]+\.json$/.test(name)) continue;
    const capture = JSON.parse(await readFile(resolve(engine.artifacts.root, name), "utf8")) as
      { stdout?: string; stderr?: string; logs?: readonly string[] };
    for (const text of [capture.stdout ?? "", capture.stderr ?? "", ...(capture.logs ?? [])])
      for (const raw of text.split("\n")) {
        const line = raw.replace(/\u001b\[[0-9;]*m/g, "");
        const at = line.search(/an agent run (failed|did not settle|cannot be claimed|thread did not start)/);
        if (at >= 0) warnings.push(line.slice(at).replace(/AttemptId \{ bytes: \[[0-9, ]+\] \}/g, "AttemptId"));
      }
  }
  return warnings.at(-1) ?? "no agent-run failure warning in the server log";
}

/* RUNS-08 (partial, Engine E2E-PARTIAL option A).
 * Promise: a live agent's batched fan-out states its count, expected spend and one shared
 *   cap before anything launches, waits for the owner's approval of that exact plan digest
 *   (the agent cannot approve it, a stale digest is refused), and keeps every child in its
 *   input slot; a denied batch stays held with nothing minted; both survive a restart.
 * Doors: HTTP facade vault.agents.create, vault.conversations.create, vault.witness, vault.get,
 *   tasks.create, vault.runs.branches.get, vault.runs.checkpoint, self.run.attach (the agent's
 *   own paired credential), vault.fanout.spawn (through the attached handle),
 *   vault.fanout.launch, vault.fanout.resume, vault.fanout.slots; engine.restart(). The parent
 *   is a real TASK-bound agent run whose scripted program asks the owner and parks on that ask.
 * Unproved: manual approval mode. No public door sets it (set_consult_fanout_policy has no
 *   server caller; the typed policy manifest has no fan-out axis). The shipped auto mode with
 *   no decision model asks no model and holds every launch for the owner, which this proves.
 * Unproved: per-peer breakdown (agent children carry no per-peer row; only consults do).
 * Unproved: reverse completion order and a scripted structural failure in slot 1: the children's
 *   model requests are identical on the wire, so no script can address one child. Children run on
 *   one standing reply; their terminal states are not asserted.
 * Unproved: shared reserve/settle/refund receipts and the constrained-budget variant; MCP
 *   tool-first discovery (HTTP only here).
 */
suite.test(test, "RUNS-08", "A live agent's batched fan-out states its count, expected spend and one shared cap before launch, launches only on the owner's approval of that exact plan digest, and keeps every child in its input slot", async () => {
  const c = await runs08Scenario();
  const [narrowWidth, wideWidth] = c.inputs.widths;
  if (narrowWidth === undefined || wideWidth === undefined) throw new Error("Fixture names no widths");
  const providers = await ScriptedProviders.start({ id: "runs08-runs", origins: ["chat"], steps: [] });
  // No [models.decisions.*] and no [models.decision_read]: the fan-out ladder holds only its rule
  // rung, which abstains on a fresh vault, so auto mode surfaces every launch to the owner.
  const engine = await EngineFixture.start({ id: "RUNS-08", profile, serverLog: "oneiron=info", serverConfig: `
[models.providers.runs08chat]
kind = "local-openai-compat"
base_url = "${providers.urls.chat}"
revision = "runs-v1"
[models.roles.generative_reasoner]
model = "runs08chat:${RUNS08_MODEL}"
[models.dreamer]
enabled = false
[models.workflows]
enabled = false
[models.code_mode]
prompt_package = ${JSON.stringify(resolve(import.meta.dir, "fixtures/hooks/host/prompts"))}
` });
  try {
    const owner = engine.client;
    const ownerRef = engine.pairedActor.principalRef;
    const parentAgent = await runs08Agent(owner, "runs08-parent", "auto");
    const childAgent = await runs08Agent(owner, "runs08-child");
    await grantAgentAskAuthority(owner, parentAgent);
    const question = await runs08Turn(owner, "Hold the survey batch parent until the owner answers.");

    // ---- The parent: a real TASK-bound agent run that parks on its own ask, keeping its lease. ----
    providers.enqueue({
      id: "runs08-parent", origin: "chat", role: "generative_reasoner",
      purpose: "the parent agent's code-mode run asks the owner and parks on that ask",
      // The engine-native executor streams on a local-openai-compat provider (wire.rs:146-149).
      request: { method: "POST", path: "/v1/chat/completions", model: RUNS08_MODEL,
        fields: { stream: true, stream_options: { include_usage: true } } },
      response: openaiStream("runs08-parent", RUNS08_MODEL, [runs08ParkProgram(ownerRef, question)], RUNS08_USAGE),
    });
    const request = "Fan the visitor survey out to one batch of agents.";
    const posted = await owner.call("tasks.create", {
      spec: { title: request }, label: "runs-08-parent", assignee: { agent_def: { agent_def_ref: parentAgent } },
      intent_key: "runs-08/parent/post", brief: runs08Brief(ownerRef, request),
    });
    expect(posted.approval).toBe("auto");
    expect(posted.effected).toBe(true);
    const route = posted.route;
    if (!route || !("AgentDispatch" in route)) throw new Error(`Parent TASK routed ${JSON.stringify(route)}`);
    const task = posted.task_ref;
    if (!task) throw new Error("Parent TASK has no task_ref");
    const branches = await owner.call("vault.runs.branches.get", { task_ref: task });
    expect(branches.branches).toHaveLength(1);
    const run = branches.branches[0]?.branch;
    if (!run) throw new Error("Parent TASK has no branch");
    // Its asking step committed: no provider call remains in the entry.
    const stepped = await awaitPublic(() => owner.call("vault.runs.checkpoint", { run_ref: run }),
      view => view !== null && view.completed_steps >= 1, { label: "RUNS-08 parent run commits its asking step" });
    expect(stepped?.completed_steps).toBe(1);
    // The parked run keeps its lease. The whole branch first, so a failure prints its last_error.
    const parkedBranch = (await owner.call("vault.runs.branches.get", { task_ref: task })).branches[0];
    await expectParkedBranchLeased(engine, "RUNS-08 after its asking step", parkedBranch);
    expect(parkedBranch?.state).toBe("Leased");
    const agent = await engine.pairActor({ principalRef: parentAgent, actorClass: "agent", scope: ["core:read", "core:write"] });
    const attached = await agent.client.call("self.run.attach", { run });
    expect(attached.live_run.startsWith(`lr1.${run}.`)).toBe(true);

    // ---- The narrow batch: held before launch, with its statement and input-order slots. ----
    const narrowChildren = runs08Children(childAgent, narrowWidth, "narrow");
    const narrow = await agent.client.call("vault.fanout.spawn", {
      live_run: attached.live_run, spec: { intent_key: "runs08/narrow", children: narrowChildren },
    });
    expect(c.expected.planStatesDollarsAndCapBeforeLaunch).toBe(true);
    const narrowCap = runs08ExpectHeldBatch(narrow, task, narrowChildren);
    const narrowRef = narrow.launch.launch_ref;
    // The owner inspects the held plan by HTTP: the same digest and statement the spawn froze.
    const shown = await owner.call("vault.fanout.launch", { launch_ref: narrowRef });
    expect(shown?.plan_digest).toBe(narrow.launch.plan_digest);
    expect(shown?.statement).toEqual(narrow.launch.statement);
    expect(shown?.held?.denied).toBe(false);

    // ---- The wide batch: count alone refuses nothing, and width never multiplies the cap. ----
    const wideChildren = runs08Children(childAgent, wideWidth, "wide");
    const wide = await agent.client.call("vault.fanout.spawn", {
      live_run: attached.live_run, spec: { intent_key: "runs08/wide", children: wideChildren },
    });
    expect(c.expected.countAloneCausesRefusal).toBe(false);
    const wideCap = runs08ExpectHeldBatch(wide, task, wideChildren);
    const wideRef = wide.launch.launch_ref;
    expect(wideRef).not.toBe(narrowRef);
    expect(wide.launch.plan_digest).not.toBe(narrow.launch.plan_digest);
    expect(c.expected.capMultipliedByWidth).toBe(false);
    expect(c.expected.enforcedBudgetScopes).toBe(1);
    expect(wideCap.scope ?? null).toBe(narrowCap.scope ?? null);
    expect(wideCap.cap_units).toBe(narrowCap.cap_units);
    expect(wide.accounting.hard_cap?.lease.scope).toBe(narrow.accounting.hard_cap?.lease.scope);

    // ---- Failure steps: the agent cannot approve its own batch; a stale digest is refused. ----
    const selfApproval = await runs08Refusal(agent.client.call("vault.fanout.resume", {
      launch_ref: narrowRef, plan_digest: narrow.launch.plan_digest, ruling: "approve_once",
    }));
    expect(selfApproval.status).toBe(403);
    const stale = await runs08Refusal(owner.call("vault.fanout.resume", {
      launch_ref: narrowRef, plan_digest: runs08OtherDigest(narrow.launch.plan_digest), ruling: "approve_once",
    }));
    expect(stale.status).toBe(409);
    expect(stale.code).toBe("INVALID_STATE");
    expect(stale.message).toBe("fan-out launch digest does not match the frozen plan");
    const unmoved = await owner.call("vault.fanout.launch", { launch_ref: narrowRef });
    expect(unmoved?.held?.denied).toBe(false);
    expect(unmoved?.task_refs).toEqual([]);

    // ---- The owner approves the exact digest shown; the wide batch is denied. ----
    // Launched children run as real agent runs. Their requests are identical on the wire, so one
    // standing reply answers each, in any order, any number of times (zero included).
    providers.enqueue({
      id: "runs08-children", origin: "chat", role: "generative_reasoner", standing: true,
      purpose: "each launched child's code-mode run finishes its slot",
      request: { method: "POST", path: "/v1/chat/completions", model: RUNS08_MODEL,
        fields: { stream: true, stream_options: { include_usage: true } } },
      response: openaiStream("runs08-child", RUNS08_MODEL, [`finish("Survey slot done.");`], RUNS08_USAGE),
    });
    const approved = runs08Launch(await owner.call("vault.fanout.resume", {
      launch_ref: narrowRef, plan_digest: narrow.launch.plan_digest, ruling: "approve_once",
    }));
    expect(approved.plan_digest).toBe(narrow.launch.plan_digest);
    expect(approved.statement).toEqual(narrow.launch.statement);
    expect(approved.held ?? null).toBeNull();
    expect(approved.task_refs).toHaveLength(narrowWidth);
    expect(new Set(approved.task_refs).size).toBe(narrowWidth);
    const denied = runs08Launch(await owner.call("vault.fanout.resume", {
      launch_ref: wideRef, plan_digest: wide.launch.plan_digest, ruling: "deny",
    }));
    expect(denied.held?.denied).toBe(true);
    expect(denied.task_refs).toEqual([]);

    // ---- Launched children keep their input slots; the denied batch minted nothing. ----
    expect(c.expected.resultsStayInInputSlots).toBe(true);
    const launched = await owner.call("vault.fanout.slots", { launch_ref: narrowRef });
    if (!launched) throw new Error("The launched batch is not readable");
    expect(launched.slots.map(slot => slot.index)).toEqual(narrowChildren.map((_, index) => index));
    expect(launched.slots.map(slot => slot.input)).toEqual(narrowChildren);
    expect(launched.slots.map(slot => slot.task_ref ?? null)).toEqual(approved.task_refs);
    for (const slot of launched.slots) {
      expect(slot.state).not.toBe("held");
      if (!slot.task_ref) throw new Error(`Slot ${slot.index} has no TASK`);
      expect((await owner.call("vault.get", { entity_ref: slot.task_ref })).value?.kind).toBe("TASK");
    }
    const stillWide = await owner.call("vault.fanout.slots", { launch_ref: wideRef });
    expect(stillWide?.slots).toHaveLength(wideWidth);
    expect(stillWide?.slots.every(slot => slot.state === "held" && (slot.task_ref ?? null) === null)).toBe(true);

    // ---- Failure step: restart. The ruling, the frozen plan and the slot identities are durable. ----
    await engine.restart();
    const afterNarrow = await owner.call("vault.fanout.launch", { launch_ref: narrowRef });
    expect(afterNarrow?.plan_digest).toBe(approved.plan_digest);
    expect(afterNarrow?.statement).toEqual(approved.statement);
    expect(afterNarrow?.task_refs).toEqual(approved.task_refs);
    expect(afterNarrow?.held ?? null).toBeNull();
    const afterWide = await owner.call("vault.fanout.launch", { launch_ref: wideRef });
    expect(afterWide?.held?.denied).toBe(true);
    expect(afterWide?.task_refs).toEqual([]);
    const afterSlots = await owner.call("vault.fanout.slots", { launch_ref: narrowRef });
    expect(afterSlots?.slots.map(slot => slot.input)).toEqual(narrowChildren);
    expect(afterSlots?.slots.map(slot => slot.task_ref ?? null)).toEqual(approved.task_refs);
  } finally {
    const errors: string[] = [];
    try { await engine.close(); } catch (error) { errors.push(error instanceof Error ? error.message : String(error)); }
    try { await providers.close(); } catch (error) { errors.push(error instanceof Error ? error.message : String(error)); }
    if (errors.length) throw new Error(`close: ${errors.join("; ")}`);
  }
});

/* RUNS-09 — Proactive commitment waits for authorization should work.
 * Rows: OF-187, OF-194. ARCH-0026 #wake-model; ARCH-0067 #tasks.
 * Oracle: runs-scenarios / RUNS-09.
 *
 * Canon commitment: { obligor, beneficiary, content, schedule, strength,
 *   status: open|fulfilled|released|lapsed|superseded, birth provenance },
 * with separate occurrence/learning time. schedule has once/interval/quota/
 * rrule arms; use once only. An obligation is NOT an execution brief. Only
 * full commitment strength is timer-wake eligible. Fulfilment is explicit,
 * with evidence; a completed brief alone is no authorization/fulfilment.
 * Existing GET/PUT /v1/owner/commitments/reminder-route reads/sets { route }.
 * Its owner route chooses delivery and approves NOTHING. Owner runs/approve
 * can approve a run's proposed reminder. The catalog has no typed commitment
 * series/instance creation or explicit fulfilment HTTP + SDK lifecycle.
 * Generic claims.upsert/structural.put is not that indexed commitment door.
 *
 * Publicly set the fake connector route and create the authored promise with
 * occurrence < learning < due; due = runtime declaration + 2 s, no clock jump.
 * Await the real due event and proposal. Assert links back to the commitment
 * and birth evidence, still open and ZERO outbound attempts before consent.
 * Authorize only that proposed reminder as owner, await its delivery receipt,
 * repeat authorization and require one sink attempt/effect with the same
 * idempotency key. Witness observed fulfilment, explicitly confirm it through
 * the typed lifecycle door and read fulfilled with evidence + receipt. A later
 * due/cadence event must not emit another reminder for the closed obligation.
 *
 * Missing: the typed commitment doors now exist (vault.commitments.create/get/
 * instances/proposals/fulfill/release/supersede/ledger, reminder_route.get/set).
 * The due proposal is written only inside a served Dreamer pass, which admits
 * nothing without a routed extraction role and extraction egress. The birth
 * evidence TURN then wakes extraction producers that have no deterministic
 * script. Delivery needs a verified LINE/Slack/Telegram connection, whose
 * checks call fixed provider URLs, and no public read lists a reminder's
 * outbound attempts by key. With the Dreamer off, every "nothing sent before
 * consent" read is vacuous. Never write commitment/index internals or
 * auto-authorize a user promise to make the connector run.
 */
suite.todo(test, "RUNS-09", "waits on a scriptable served Dreamer pass for the due commitment wake, a verifiable loopback reminder connection and a public read of reminder outbound attempts (Proactive commitment waits for authorization should work)");
