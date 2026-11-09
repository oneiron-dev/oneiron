import { afterAll, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import type { Facade, FacadeInput, FacadeResult, FacadeVerb } from "@oneiron/client";
import { EngineFixture, awaitPublic } from "./support/engine.ts";
import { PublicHttpClient, PublicHttpError } from "./support/clients.ts";
import { loadFixtures, ownerBaseClaimScope } from "./support/fixtures.ts";
import { ScriptedProviders } from "./support/providers.ts";
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
 * Missing (main e79eb76df3e): fan-out admission now exists (vault.fanout.spawn
 * from an attached live run), but no typed branch wait/Query/Signal read binds
 * the human wait, its matching answer, the cached settlement and the resumed
 * child to the same live branch. vault.runs.branches.get invents no wait class
 * (task_verb/run_doors.rs:14-18); a facade `wait` binds a detached step with
 * run_id None (ask_facade/wait.rs:77-130), so it is not branch A's checkpoint.
 */
suite.todo(test, "RUNS-02", "waits on a typed branch wait/Signal read binding a human wait, its matching answer and the resumed child to one live branch (Only waiting branch pauses should work)");

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
 * DEFECT expected today: the bucket names the claim's own facet; pin reads a facade claim's facet
 *   from scope key "facet_ref" only, so this pin is refused as crossing its axes (see report).
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

/* RUNS-08 — Fanout preserves slots and cap should work.
 * Rows: OF-393, OF-290, OF-532. ARCH-0026 #swarm-fanout; ARCH-0079 #work,
 * #width. Oracle: runs-scenarios / RUNS-08. MCP + HTTP, not HTTP-only.
 *
 * Existing HTTP/SDK:
 *   tasks.wave({ epic_task_ref, planner_ref, objective, constraints? })
 *     -> { attempt_ref, state }
 *   vault.fanout.launch({ launch_ref }) -> FanoutLaunchView | null
 *     { launch_ref, plan_digest, statement, held?, task_refs, ... }
 *   statement: { agent_count, consult_count, task_count, per_peer, expected,
 *                unit, cap?, over_available, more_would_buy?, width_check?, ... }
 *   vault.fanout.resume({ launch_ref, plan_digest,
 *     ruling: approve_once|approve_and_remember|deny, remembered_cap? })
 *     -> FanoutLaunchView
 * The estimate/approval doors exist. They are NOT a typed batched spawn/result
 * slot API. TaskAskResult is ask evidence/settlement, not spawn-order slots.
 * Canon batch: one slot per input, input-order results despite completion
 * order; a child failure/budget exhaustion is an error in its own slot.
 * Shared reserve/settle/refund draws from ONE parent hard spend cap. Width
 * has no count cap; the huge-width check is never a limit. Manual approval
 * pauses; Auto checks/escalates; full access proceeds (owner 2026-10-17).
 *
 * Use tool-first MCP discovery + the actual typed fanout tool once it exists;
 * inspect the held plan by HTTP and approve its exact digest in manual mode.
 * Exercise fixture widths 3 and 26 (finite probes, not proof of unboundedness).
 * Require declared count, per-peer breakdown, expected dollars + hard cap
 * BEFORE launch. Let children finish in reverse order, with one scripted
 * structural failure. Verify slot/result identity against input, surviving
 * siblings and no abort-all. In the constrained variant exhaust the shared
 * cap: affected slots may error/park, but total settled+reserved spend cannot
 * multiply by width. Read real cost/reservation receipts and refunds; never
 * use provider call count or copied child budgets as the shared-spend oracle.
 *
 * Missing: the typed doors now exist (vault.fanout.spawn/slots/launch/resume/
 * resume_as/ack, tasks.wave, vault.budgets.lease/settlements). Two public
 * prerequisites do not: (1) an owner door that sets the fan-out approval mode
 * to manual. set_consult_fanout_policy has no server caller and the shipped
 * mode is auto with threshold 1000, so widths 3/26 raise no check. (2) A
 * deterministic public way to hold a task-bound live run between entries,
 * which spawn needs as its live_run handle: the attach guard spans a whole
 * entry, and a run leaves at settlement unless it parks. A refusal-only probe
 * (bad handle 400, stranger resume 403, absent launch null) proves no slot,
 * statement or cap and is not written. Do not use execute_code or an internal plan.
 */
suite.todo(test, "RUNS-08", "waits on an owner door that sets manual fan-out approval and a deterministic public hold of a task-bound live run for vault.fanout.spawn (Fanout preserves slots and cap should work)");

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
