import { afterAll, test } from "bun:test";
import { defineFile } from "./support/run.ts";

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
 * These are complete-flow TODOs, not passing partial smoke tests. suite.todo
 * registers Bun test.todo and the shared runner's mandatory BLOCKED result.
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
 * Missing: typed Dreamer workflow/program admission through the turn wake and
 * settled-step/checkpoint reads. Queue completion/result_ref and witness ACK
 * do not establish a committed intermediate step. The current consolidation
 * executor is not an arbitrary outbound-effect program. No private step seed.
 */
suite.todo(test, "RUNS-01", "waits on typed turn-woken Dreamer workflow admission and settled-step/checkpoint reads (Dreamer survives a kill should work)");

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
 * Missing: typed live branch fan-out and Query/Signal wait/result projection.
 * Existing ask/wait/answer verbs alone cannot prove a run-tree branch parked,
 * another child continued, or a matching consent signal was consumed once.
 */
suite.todo(test, "RUNS-02", "waits on typed live child-branch admission and Query/Signal wait/settlement reads (Only waiting branch pauses should work)");

/* RUNS-03 — Steer pause resume and cancel should work.
 * Rows: OF-203, OF-239, OF-419, OF-391. ARCH-0026 #run-tree.
 * Oracle: runs-scenarios / RUNS-03.
 *
 * Existing typed HTTP shapes:
 *   POST /v1/core/run-tree/intervene
 *     { job_id, kind: interrupt|pause|resume|cancel|redirect, note?, placement? }
 *     -> { job_id, run_id?, kind, effect, tree? }
 *   steer({ task_ref, instruction, key }) -> { task_ref, branch, run_id,
 *     key, state: Pending|Settled|RefusedCancelCapacity|RefusedCancelUnavailable }
 *   POST /v1/owner/steer takes the same SteerRequest/SteerReceipt; it exists.
 *   cancel({ task_ref }) -> TaskCancelReceipt
 *     { approval, effected, proposal_ref?, gate_decision_ref?, status?,
 *       cancel_requested, forced }
 * The task cancel can request graceful cancellation, but its input cannot
 * explicitly select owner force. Run-tree cancel is a queue intervention,
 * not the missing typed cancel.force with its landing/partial-result receipt.
 * Canon: cancel.request may be refused WITH a reason receipt; cancel.force
 * is owner-only and unrefusable. Landing preserves partial results/resume
 * points. AgentRunStatus distinguishes failed from lease-reclaimed abandoned;
 * it is not the queue status enum and has no cancelled member to invent.
 *
 * Start a held multi-step actor and pair a distinct unauthorized caller.
 * Require unauthorized steer/pause/cancel/force refusal with no state change.
 * Owner steers at a safe breakpoint, queries progress, pauses that branch,
 * resumes it, then requests graceful cancel. Script one refusal with reason,
 * re-request and inspect landing's saved partial result. On a second live
 * branch exercise owner force. Retry terminal control: no extra work or
 * receipt/effect. Inspect typed waits, completion, execution failure, lease
 * reclamation and cancellation distinctly, not by matching log/card strings.
 *
 * Missing: explicit typed owner force, cancellation/landing receipts and the
 * full branch Query/AgentRunStatus projection. No app-action/generic escape.
 */
suite.todo(test, "RUNS-03", "waits on typed owner cancel.force, landing receipts and branch lifecycle reads (Steer pause resume and cancel should work)");

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
 * Missing: typed wake admission/deadline and parked-continuation observation.
 * Attempt updated_at or a provider arrival cannot prove the wake's epoch.
 */
suite.todo(test, "RUNS-04", "waits on typed wake admission/deadline and parked-continuation reads (Wake stops at its wall-clock ceiling should work)");

/* RUNS-05 — Changed evidence wakes once and idle stays idle should work.
 * Rows: OF-191, OF-194, OF-218, OF-361, OF-498. ARCH-0026 #wake-model.
 * Oracle: runs-scenarios / RUNS-05.
 *
 * Current public setup includes vault.settings.wake_policy.set({ policy,
 * idempotency_key }) -> { outcome }; the policy body is opaque in the SDK.
 * vault.witness and vault.rooms.speak land turns and wake the Dreamer. Do not
 * claim those doors or the production wake supervisor are absent.
 * Canon: one engine scheduler; changed-evidence recipes only when idle and
 * within lease. Dreamer and Coach use that scheduler; an unchanged projection
 * writes no conclusions, and a durable wait performs zero model polling.
 * Needed typed observation: evidence identity/cursor, recipe/wake identity,
 * conclusions, Coach work and a receipted cadence boundary/idle wait state.
 * Needed duplicate intake: replay the SAME evidence/event id, not another
 * witnessed turn whose text happens to be identical. No frozen DTO is known.
 *
 * Seed the two residents publicly and set a short owner cadence. Witness the
 * fixture's novel turn, let the scripted sieve/worker settle and record the
 * public conclusion identities. Replay the same ingress event, await one
 * cadence boundary and inspect both conclusion sets and provider requests.
 * Require only the intended novel-evidence work; duplicates produce no new
 * conclusions. Park the human wait and observe the whole idle cadence: no
 * model requests. Check single-scheduler receipts across both resident jobs,
 * not just a momentary flat request count. Script unexpected calls as errors.
 *
 * Missing: typed identity-preserving evidence replay and sieve/Coach recipe
 * settlement/cadence reads. No fresh duplicate-text witness or private tick.
 */
suite.todo(test, "RUNS-05", "waits on typed evidence replay and sieve/Coach cadence/settlement reads (Changed evidence wakes once and idle stays idle should work)");

/* RUNS-06 — Sieve queue retains lower-priority work should work.
 * Rows: OF-498, OF-216. ARCH-0026 #wake-model.
 * Oracle: runs-scenarios / RUNS-06.
 *
 * Canon interest entry: span refs (source/turn/range), kind/entity, interest
 * and pending work, durably ordered by score. Priority changes order, never
 * retention. The rule sieve is implemented; a private sieve_queue accessor
 * is not a public typed queue read. ConsolidationStatus is one attempt, not
 * interest handles, outstanding span/rung membership or budget replenishment.
 * Needed typed calls: interest-page read, owner lease/refill, cadence/weave
 * settlement with consumed span refs. Wire names must wait for the catalog.
 *
 * Ingest the three authored spans. Owner policy permits exactly the first
 * unit of work; await its settled receipt. Read ordered queue handles and
 * require medium + low still pending with their original source/range refs.
 * Restart without reseeding. Both handles/refs must survive; then refill
 * through owner authorization and observe the remaining work consumed once.
 * A later weave consumes retained evidence, not merely the already-generated
 * prose. Assert all three source memberships and no priority-based drop.
 * Never predict numeric implementation scores or inspect queue storage.
 *
 * Missing: typed interest handles/page, lease refill and consumed-span receipts.
 */
suite.todo(test, "RUNS-06", "waits on typed sieve interest-queue reads, owner lease refill and consumed-span receipts (Sieve queue retains lower-priority work should work)");

/* RUNS-07 — Parallel consolidation preserves evidence trust should work.
 * Rows: OF-052, OF-204, OF-216. ARCH-0026 #swarm-fanout, #wake-model.
 * Oracle: runs-scenarios / RUNS-07.
 *
 * Canon typed DESIGN: bucket = subject * predicate_root * world * facet *
 * relationship * project. Child output = judgement + a set of references
 * (source id + claim id or byte range), NOT authoritative hash/trust/bytes.
 * Root pins ONE ledger revision, re-reads, derives hash/trust and deduplicates
 * source+hash before corroboration. A generated re-citation adds zero signals;
 * taint is the most restrictive ancestor, including edge.provenance. Only the
 * root vouches. The catalog has no typed root-frontier/accounting receipt.
 *
 * Publicly create the same-subject source, its generated re-citation, one
 * tool-output ancestor in project amber, and equal-text evidence in bronze.
 * Wake the six-axis buckets. Finish siblings out of order; after the root
 * pin, edit the first source through its real edit door. Require every root
 * read to use the original pin. Two amber children citing that source remain
 * ONE signal; its summary adds none, tool output adds a second, with taint
 * no stronger than tool_output. Bronze stays separate, never adding amber
 * support. A child's forged hash/trust must not influence accounting; reject
 * or receipt its integrity violation instead of silently trusting the value.
 * Check settled claims AND corroboration/provenance receipts, not just prose.
 *
 * Missing: typed reference-carrying parallel consolidation, revision-pinned
 * root reads and evidence accounting/taint receipts. Generic enqueue's unknown
 * input cannot seed child judgements or manufacture a pinned revision.
 */
suite.todo(test, "RUNS-07", "waits on typed parallel reference frontier and pinned-root evidence accounting receipts (Parallel consolidation preserves evidence trust should work)");

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
 * Missing: typed batch spawn/slot outcomes and shared lease accounting reads.
 * Do not use execute_code or construct an internal plan in unknown constraints.
 */
suite.todo(test, "RUNS-08", "waits on typed MCP/HTTP batched child slots and shared lease accounting reads (Fanout preserves slots and cap should work)");

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
 * Missing: typed indexed commitment birth, due proposal observation and
 * evidence-backed fulfilment calls. Never write commitment/index internals or
 * silently auto-authorize a user promise merely to get the connector to run.
 */
suite.todo(test, "RUNS-09", "waits on typed indexed commitment creation, due proposal and evidence-backed fulfilment (Proactive commitment waits for authorization should work)");
