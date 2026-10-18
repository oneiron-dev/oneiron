import { afterAll, test } from "bun:test";
import { defineFile } from "./support/run.ts";

const profile = process.env.E2E_PROFILE === "real-small-model"
  ? "real-small-model" : "deterministic";
const suite = defineFile(import.meta, { profile, slots: 1 });
afterAll(suite.flush);

/*
 * Public binding read at main c2239db2c8486fd18b7fe33ebe9bc272b689079a:
 * scripts/sdk/agent-verbs.json, both generated TypeScript facade catalogs,
 * api/openapi_registry.rs, conversation_dag/types.rs, conversation_members.rs,
 * mcp_gateway/tasks_response.rs, the host project-card/wave doors and cli.rs.
 * The shared harness's older binding pin is not edited by this area writer.
 * Canon, registry and binding-file hashes are in coordination-scenarios.
 *
 * G01: a designed operation needs its typed HTTP and SDK call. Run-context
 * rows such as self.leader.split, self.agents.spawn and tasks.refuse exist in
 * the code-mode catalog, but not in FacadeVerb/the public HTTP SDK. Sending
 * execute_code, casting to FacadeVerb or writing an AGENT_DEF/PROJECT through
 * structural.put/batch would not qualify the missing typed door.
 *
 * All nine complete flows are blocked, not passing partial coverage.
 * suite.todo emits Bun test.todo plus the harness's required BLOCKED row.
 * Names, full steps, authored inputs and expected facts are retained in
 * fixtures/coordination/scenarios.json. Labels there bind to public setup
 * results; they are not invented entity ids, signed proofs or vault records.
 *
 * Activation: (await loadFixtures()).readJson("coordination-scenarios"), then
 * EngineFixture.start({ id, profile }) per flow, using its paired public
 * clients. Pairing does not create a principal, agent definition or companion.
 * ScriptedProviders supplies external model/tracker responses only. Bind
 * public provider config and explicit owner policy; await public receipts,
 * statuses or provider barriers, never private ticks, fixed sleeps or logs.
 * HTTP facade DTOs are snake_case; do not substitute the native SDK's DTOs.
 * MCP tools take arguments.spec and return structuredContent.output; retain
 * isError/RPC refusals, and drain pages before asserting complete sets.
 */

/* COORDINATION-01 — Project proposal requires acceptance should work.
 * Rows: OF-497, OF-501. Canon: ARCH-0079 #work; ARCH-0067 #what.
 *
 * Existing typed HTTP/SDK calls (also projected as generated MCP tools):
 *   vault.projects.propose({ card_id, source_message_ref,
 *     goal: { goal, why, axes }, picks: { leader_agent_def_ref,
 *       board_human_refs, budget_share_bps, starting_skill_refs } })
 *     -> ProjectProposalCard { card_id, principal_ref, source_message_ref,
 *          source_room_ref?, source_thread_ref?, goal, leader_agent_def_ref,
 *          board_human_refs, budget_share_bps, starting_skill_refs }
 *   vault.projects.proposals({ conversation_ref }) -> ProjectCardRecord[]
 *     { card, conversation, detection, drafted_by, state, at }
 *   vault.projects.dismiss_card({ card_id }) -> { card_id, dismissed }
 *   vault.projects.confirm({ card_id, action_id: "mint_project", occurred_at })
 *     -> { project_id, card_id, grant_decision_id, grant_ref }
 *
 * Use the fixture conversation and a scripted typed YES from the real project
 * detection adapter. A drafting agent requests the card over MCP; the human
 * inspects and answers over HTTP. Compare every proposed pick with the fixture,
 * not with a second read of the same output. Before any tap, the root's child
 * set and project-room set must be unchanged: a detection YES is not consent.
 * Dismiss the first card. Confirming that card must not mint. Request a NEW
 * card on a new source message and accept it once. Require exactly one new
 * project, parent=root, one leader, the human board, a distinct claims scope,
 * the declared goal, 1,250-bps budget share and starting skill ancestry. The
 * minted home room is a channel with the admitted roster. An exact confirm
 * replay returns the same project/grant, never a second child or room.
 *
 * Missing prerequisite: typed public creation/import of the fixture's custom
 * AGENT_DEF leader/workers and house drafting setup. The fixture still needs
 * public roster/skill setup, never seeded records. shape.actor names an
 * existing agent_id and pairActor pairs an existing principal; neither
 * installs an AGENT_DEF. The project proposal and
 * confirmation calls above ARE present. Do not fabricate a held detection
 * verdict or seed a card to get past the real house drafting flow.
 */
suite.todo(test, "COORDINATION-01", "waits on typed AGENT_DEF creation/import for the project-card leader and house drafting fixture");

/* COORDINATION-02 — Home room thread to project should work.
 * Rows: OF-009, OF-460, OF-522. Canon: ARCH-0067 #room; ARCH-0079 #work.
 *
 * Existing HTTP topology:
 *   POST /v1/core/conversations/{conversation}/records/{trunk}/thread
 *     DagAppendRequest { actor: { entity_ref, actor_class }, advance: false,
 *       parent?, reply_to?, body, text?, occurred_start?, occurred_end?,
 *       learned_at?, session?, thread_audience?, addr?, to?, quote? }
 *     -> DagAppendResponse { id, ...CoreEntityWriteResponse, head?, parent? }
 *   GET /v1/core/conversations/{conversation}/records
 *     -> { head, root, main_line, page: { next }, ... }
 *   GET /v1/core/conversations/{conversation}/records/{trunk}/thread
 *     -> { roots, root, replies, count, last_at }
 *   vault.rooms.get({ room_ref, turn_ref }) -> RoomThread | null
 *     { handle, trunk, last_message_at, open_tasks, waits, result_header?,
 *       converted_project? }
 *   vault.rooms.trunk({ room_ref, turn_ref }) -> { turn, headers }
 *   vault.projects.confirm(ProjectCardConfirmRequest) -> ProjectMintReceipt
 *
 * Create the roster/project through public acceptance, then trunk-one and
 * trunk-two with a branch rooted at trunk-one and one open TASK on the branch.
 * Reply on that branch; both response head and a fresh paged main-line read
 * must still name trunk-two. Assert the exact original trunk id sequence and
 * branch reply ids, not just a count. The branch never becomes HEAD.
 *
 * Convert using the host-held thread card's confirmation (the present public
 * conversion path), with its explicit leader. Assert born_from is the MESSAGE
 * the card sat on, not the containing TURN. The new project names origin_room
 * and origin_thread, the old thread names converted_project, and the home
 * room's origin card/backlink points at the same source. Its trunk starts at
 * that origin. The SAME TASK id moves to the child's task list; no copy remains
 * assigned as parent work. Original history stays addressable by its old ids,
 * and the new room links it instead of copying its turns/messages. Replaying
 * acceptance adds neither a duplicate task nor another origin card/home room.
 *
 * Missing: the same typed project-leader/roster fixture setup as 01. Thread
 * append/read and host-backed confirm/conversion are not claimed absent.
 * Do not write ProjectRecord or task membership via generic entity bodies.
 */
suite.todo(test, "COORDINATION-02", "waits on typed project-leader and roster fixture setup for thread-card conversion");

/* COORDINATION-03 — Thread participation and offer card should work.
 * Rows: OF-528, OF-529, OF-530, OF-531. Canon: ARCH-0067 #room.
 *
 * Existing typed HTTP/SDK calls, mirrored on MCP:
 *   vault.rooms.participants({ room, branch?, after?, limit? })
 *     -> { rows: [{ subject, causes, since, currently_eligible, receipt_ref? }],
 *          next_after? }
 *   vault.rooms.offer({ room, branch, agent, what, artifact_ref?, spend_scope?,
 *     until?, intent_key }) -> OfferCard { offer_id, room, branch?, agent,
 *       what, artifact_ref?, lease_cap?, payer?, spend_scope?, join_ref, state,
 *       created_at, until?, last_engaged_at, vote_tally }
 *   vault.rooms.consent({ join_ref, part, grant, spend_scope? }) -> JoinOutcome
 *     { join_ref, decision: { state, consents, participation? }, receipt_ref? }
 *   vault.rooms.offer.answer({ offer_id, action: "join" | "not_now",
 *     intent_key }) -> { offer_id, state, join?, turn_ref?, diary_ref? }
 *   vault.rooms.offers({ room, branch?, after?, limit? }) -> OffersPage
 *
 * A human reply joins the branch with cause { kind: "wrote", turn } without
 * a separate invite. An unnamed agent reading the branch is NOT a participant.
 * A mention and a TASK assignment each admit only the named agent, carrying
 * the appropriate addressed/task cause. The nearest leader hosts; Dreamer
 * never acquires the speaking seat merely because it did mechanical upkeep.
 *
 * The unnamed agent offers via MCP. Before payer consent there is no spend
 * and no published offer. After spend consent it is ONE card for that agent
 * and thread, not an unsolicited turn. Inspect the join's separate spend,
 * membership and admission needs. The companion's person grants membership;
 * the payer grants the declared lease; the host admits the turn only where
 * required (project-paid admission is implied, not another universal ask).
 * Answering as an unrelated actor must not discharge someone else's need.
 * Before all REQUIRED consents, the agent is not eligible and has no turn.
 *
 * Accept: one new eligible participant/turn and the recorded cause/receipt.
 * Exact replay adds neither. On a second branch answer not_now: no turn or
 * participant, with a reasoned diary record. Offers do not widen room scope.
 * Expected parties derive from the fixture's payer/person/host, not engine
 * output. Do not conflate an ask receipt with permission to spend or disclose.
 *
 * Missing: typed companion/AGENT_DEF onboarding for the fixture. Allowance,
 * payer and room policy must also be established publicly. Offer,
 * participation and consent doors are present; do not bypass their provenance
 * by minting arbitrary people, grants or agents.
 */
suite.todo(test, "COORDINATION-03", "waits on typed companion/AGENT_DEF onboarding for the room-offer fixture");

/* COORDINATION-04 — Recursive leader never widens its slice should work.
 * Rows: OF-389, OF-497, OF-180. Canon: ARCH-0079 #work, #stacking;
 * ARCH-0040 #mcp-actor-ceilings. Current host-rooted authority wins over the
 * older OF-180 ID-JAG/device ceremony prose; no alternate credential is made.
 *
 * Canon operation: leader spawns a subproject inside a TASK wrapper; its board
 * contains the parent leader and its scope/budget/roster only narrow.
 * Existing RUN-ONLY typed design (not a callable HTTP SDK method):
 *   self.leader.split({ leader?: string, slice?: Scope })
 *     -> { project, task, parent, leader, depth_remaining }
 *   self.agents.spawn({ need, prompt, intent_key, agent?, care?, notes?,
 *     model?, width?, pattern?, budget?, context?, context_from?, depth?,
 *     project?, objectives? })
 *     -> { state: "queued", kind: "agent_spawn", attempt, launch? }
 *      | { state: "proposed_widen", kind: "agent_spawn", proposal }
 * Parent TASK, parent project, actor and attempt are host-bound, never inputs.
 * Existing owner calls: vault.widen_proposals({ state? }) -> { proposals };
 * vault.widen_proposals.decline/approve({ proposal_id }).
 *
 * Drive the leader over MCP after its public typed binding exists. Require
 * one child leader, board containing parent leader, same wrapper TASK id and
 * child.parent=parent. Compare each read/write resource with the independent
 * parent set, child budget <= parent cap and child roster <= permitted roster.
 * Try the fixture's extra private bucket: a proposal, no added read or write,
 * no child attempt using it. Deny as parent board: nothing widens. Re-propose,
 * approve as an authorised board holder: only that exact extra slice lands,
 * receipted to the board act. The subleader's own approval cannot land it.
 * Parent narrowing must still clamp its descendants. Messages confer nothing.
 *
 * Missing: typed HTTP/SDK self.leader.split and self.agents.spawn with a
 * host-bound parent run, plus typed leader fixture setup. Existing code-mode
 * implementations/owner widen doors are not substitutes for that binding.
 */
suite.todo(test, "COORDINATION-04", "waits on typed HTTP/SDK self.leader.split and self.agents.spawn with a host-bound parent run");

/* COORDINATION-05 — Task assignee routing and human reply should work.
 * Rows: OF-384, OF-388, OF-390, OF-392. Canon: ARCH-0067 #tasks;
 * ARCH-0026 #run-tree. Three fresh fixtures, sequentially, within one slot.
 *
 * Existing typed HTTP/SDK (and generated MCP tools):
 *   tasks.create({ spec, label?, assignee, intent_key, brief, ttl? })
 *     -> { task_ref?, proposal_ref?, approval, effected, route?, ... }
 *   assignee = { agent_def: { agent_def_ref } } | { peer: { actor_ref } }
 *            | { human: { actor_ref } }
 *   route = { AgentDispatch: { attempt_ref, agent_def_ref } }
 *         | { PeerSyncedOnly: { actor_ref } }
 *         | { HumanFollowup: { actor_ref } }  // no job for a human
 *   tasks.accept({ task_ref, intent_key }) -> TaskCallReceipt
 *   describe({ handle }) -> { kind: "task_status", receipt: TaskCallReceipt }
 *   tasks.update({ task_ref, report_key, attempt?, report })
 *     -> { task_ref, acked, report?: TaskCallReceipt }
 *   report = { failed: { error, retryable, result_ref? } }
 *          | { blocked: { on?, note?, ask?: TaskAskSpec } }
 *          | { done: { result_ref, confession? } }
 *   ask(TaskAskSpec) -> TaskAskReceipt; wait({ handle, step_key }) -> TaskAskWait;
 *   tasks.answer({ handle, word: { result_ref, provenance_refs? } })
 *     -> { task_ref, actor_ref, result_ref, word_ref, ...record refs }
 *
 * Dispatch the same fixture brief in the three assignee lanes; assert the
 * discriminant and exact assignee identity. A retryable failed attempt must
 * not mark TASK intent done or remove it. Re-accept the SAME TASK: a new
 * attempt/fence, not another promise; an old fence must not complete it.
 *
 * Have the running local/foreign work ask the human for the missing fixture
 * fact. Observe needs_input plus a public wait token; do not emulate it by
 * writing a blocked label. Answer as that human through the public ask/signal
 * door. The same logical run/branch resumes; unrelated work remains live.
 * For the human assignee, require follow-up/wait metadata and no realizing
 * execution job. Its authenticated word completes the same work, not an
 * owner-impersonated answer. Complete with the publicly written result handle.
 * Replay delivery with the SAME report_key/fence. Exactly one result_ref and
 * result-attached receipt/header remains; no duplicated effect or learning.
 *
 * Missing prerequisite: typed custom AGENT_DEF fixture creation for the local
 * lane. The foreign actor must be admitted through its public connection door.
 * Current task routing, accepts, ask/answer and durable status doors are
 * present; do not replace the local-agent case with a peer or use
 * generic task bodies to claim a needs_input runtime round-trip was exercised.
 */
suite.todo(test, "COORDINATION-05", "waits on typed custom AGENT_DEF fixture creation for the local assignee lane");

/* COORDINATION-06 — Addressed ask gets evidence or explicit refusal should work.
 * Rows: OF-383, OF-391. Canon: ARCH-0067 #tasks; ARCH-0026 #swarm-fanout.
 *
 * Existing typed calls:
 *   ask({ intent_key, who: { responder: TaskAssignee }, what: {
 *     reference: { claim } | { turn }, revision, options, context_refs },
 *     until, default: "hold", need?, decide?, ... }) -> TaskAskReceipt
 *   peek({ handle: { group_ref } }) -> TaskAskStatus
 *   tasks.answer({ handle, word: { result_ref, provenance_refs } })
 *     -> TaskAskAnswer { task_ref, actor_ref, result_ref, word_ref, ... }
 *   cancel({ task_ref }) -> TaskCancelReceipt
 * Canon result: an Answer carries a result ref and nonempty evidence refs;
 * an Abstain carries a result ref and a durable reason ref. A bare string or
 * missing reply is neither. The current native ConsultResultKind encodes
 * these separately; it has no typed HTTP/SDK consult-result landing method.
 *
 * Ask peer, child and unavailable responder, retaining input order. Admit the
 * child's explicit inability first and the peer's cited answer second, using
 * barriers instead of sleeps. Partial collection must retain identity and
 * reference provenance despite arrival order. Re-read the cited fixture fact
 * as root; a generated summary does not add corroboration. Cancel the third
 * while it is unanswered and inspect its receipt/status. It must remain
 * distinguishable from an answered consult, from an explicit inability, and
 * from execution failure; no empty result may be reported as success. If the
 * separate run view reports a never-answered/reclaimed run, it is abandoned,
 * never delivered/archived success. A cancellation need not be relabelled an
 * expiry; preserve each public terminal reason rather than collapsing them.
 *
 * Missing: typed HTTP/SDK child spawn and evidence-or-abstention consult
 * landing/inspection. Public tasks.answer is an ask word, not an invented
 * {abstain: ...} payload or automatic proof of successful agent execution.
 */
suite.todo(test, "COORDINATION-06", "waits on typed child spawn and evidence-or-abstention consult result landing/inspection");

/* COORDINATION-07 — One task type drives team plan should work.
 * Rows: OF-540, OF-541, OF-543. Canon: ARCH-0079 #task-type, #planner,
 * #seed-pin; ARCH-0003 #learning. No assertion of model quality/payoff scores.
 *
 * Canon spawn: { need, prompt, care?, notes?, model?, width?, pattern?, budget? }
 * Current RUN-ONLY AgentSpawnInput is documented in 04. A choice is
 *   { mode: "pin", value: T } | { mode: "seed", value: T, weight_runs: number }.
 * Required stamp: typeRef = { node_id, tree_version }; uncertain -> root.
 * Current public QueueTaskBrief uses type_ref; task status exposes
 * brief_current/brief_running { rev, digest, type_ref }. These fields must be
 * compared by value across consumers, not confused with retrieval intent_class.
 * Existing vault.settings.learning.put({ key, mode, choice?, value?, why,
 *   weight_runs?, project?, task_type?, goal? }) records owner steering.
 *
 * Pin a fixture tree and declare two scripted placement cases: build and
 * uncertain. Spawn the first task with solo-first priors and a hard budget.
 * Count exactly one placement call for that spawn at the external adapter.
 * Inspect its resolved team, route receipt, critic receipt and receipt-backed
 * learning view: ALL carry the same authored node/tree-version stamp. On the
 * uncertain spawn every consumer must use the fixture root, never null or a
 * second placement's guess. Reject a missing stamp where canon requires it.
 *
 * Use a NEW spawn intent with width=2 and the fixture model pinned; record the
 * override and preserve the hard cap. The planner must not override either.
 * Replay that spawn with its original key: no second placement/team. Do not
 * change a retry's meaning by reusing one key for different pins. Team pattern
 * and convergence are separate choices. The fixture supplies solo-first as a
 * declared prior; learned estimates and own runs are observed, never seeded
 * via hand-written learning.* claims. No consumer gets a private type list.
 *
 * Missing: typed HTTP/SDK planned spawn/team call, public type-tree fixture
 * pin/read and typed cross-consumer planner/typeRef receipt observations.
 * A manually supplied brief.type_ref alone does not test once-only placement.
 */
suite.todo(test, "COORDINATION-07", "waits on typed planned-spawn/team and type-tree pin/read with cross-consumer typeRef receipts");

/* COORDINATION-08 — Refusal dial and leadership chat should work.
 * Rows: OF-533, OF-522. Canon: ARCH-0079 #work; ARCH-0067 #room.
 *
 * Canon dial: per agent, bond/logistics domains; none|voice|veto|full.
 * Work default: voice; personal default: bond veto, logistics voice.
 * Current RUN-ONLY typed design (camelCase here is intentional):
 *   tasks.refuse({ taskRef?, domain: "bond" | "logistics", reasonRef, at? })
 *     -> { task, level, outcome: "proceed" | "object" | "decline", replay }
 * The reason is a durable cl_/tn_ ref, not an unproven free-text permission.
 * Existing public talk: self.message({ pr, text, mention?, from_project?,
 *   to_project? }) -> MessagePersonReceipt. Project-scoped leadership talk is
 * not missing merely because there is no verb named leaders.chat.
 *
 * Install a work voice agent and personal bond-veto agent, using explicit
 * fixture settings. Ask each to do the neutral fixture work; the scripted
 * agent makes its tagged objection. Voice records ONE reason and proceeds;
 * replay does not add another objection. Bond veto declines that act, not
 * logistics, not another actor's work and not policy. Read back the declared
 * dial and its diary entry under a reasoned, granted private-note read.
 *
 * Start a direct conversation between two same-vault project leaders without
 * asking a parent just for talk. A public fixture fact may cross. Then request
 * the first project's private fixture fact from the second project's leader.
 * It must be withheld under each speaker's own project scope and audience
 * law, even when the target leader asks or a message says permission granted.
 * Check forbidden content and its refs are absent from the delivered message
 * and room pack; the allowed control fact must still be present. A shared
 * ancestor rule may narrow chat but cannot widen either leader's grant.
 *
 * Missing: typed AGENT_DEF refusal-dial setup/read and HTTP/SDK tasks.refuse
 * bound to the actual running task. Do not substitute a vendor safety refusal,
 * an owner denial, arbitrary diary text or generic structural writes.
 */
suite.todo(test, "COORDINATION-08", "waits on typed refusal-dial setup/read and host-bound HTTP/SDK tasks.refuse");

/* COORDINATION-09 — Wave dependencies and issue mirror should work.
 * Row: OF-427. Canon: ARCH-0067 #tasks; ARCH-0079 #work.
 *
 * Existing typed HTTP/SDK:
 *   tasks.wave({ epic_task_ref, planner_ref, objective, constraints? })
 *     -> { attempt_ref, state }
 * Existing HTTP: POST /v1/ai/waves with those refs/objective/constraints;
 * GET /v1/ai/waves/{attempt} observes the durable planning status.
 * The planner emits task dependency data, not a new workflow DSL. Public
 * tasks.accept/update and run-tree reads remain the work/status surface.
 *
 * Use ScriptedProviders for the external planner and a local Linear-compatible
 * HTTP service, never a fake task store. Plan A -> B -> C from the fixture:
 * initially only A is ready, after A only B, after B only C. A failed/reclaimed
 * A attempt must not unlock B. Complete predecessors publicly and observe
 * readiness before accepting successors. The fixture's three task identities
 * and blocked_by edges must stay stable through mirrors and result retries.
 *
 * Mirror one task to issue COORD-101. Edit its title publicly and observe ONE
 * outbound update for the SAME issue with originating actor/provenance. Send
 * the inbound description edit with stable external event id, then replay
 * that exact webhook. Assert the same TASK/issue mapping, one imported change,
 * no new TASKs/edges and preserved external source/actor/event provenance.
 * Use disjoint fields to avoid inventing a conflict-resolution winner. Inspect
 * graph and mirror receipts, not logs, counts alone or computed engine hashes.
 *
 * Missing: typed Linear webhook/event intake and TASK-issue mapping/provenance
 * inspection/edit calls, plus the planner definition fixture setup. Main's
 * linear_host is a scheduled bridge/direct GraphQL poller, not a typed webhook
 * door. The direct adapter pins its vendor endpoint; do not use real Linear
 * or silently replace the requested webhook replay with polling. A public
 * local endpoint/config seam and observable mirror completion are prerequisites
 * for the full deterministic journey, not permission to call LinearTaskStore.
 */
suite.todo(test, "COORDINATION-09", "waits on typed Linear webhook intake and task-issue mirror edit/mapping/provenance doors");
