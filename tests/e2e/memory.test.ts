import { afterAll, test } from "bun:test";
import { defineFile } from "./support/run.ts";

const profile = process.env.E2E_PROFILE === "real-small-model"
  ? "real-small-model" : "deterministic";
const suite = defineFile(import.meta, { profile, slots: 1 });
afterAll(suite.flush);

/**
 * Memory and editable documents — MEMORY-01 through MEMORY-08.
 *
 * Public binding read at main 5ecd5af5bea2c70e25760f0583f276790f49fba4:
 * - scripts/sdk/agent-verbs.json and both generated TypeScript SDKs;
 * - the server OpenAPI registrations, owner schema augmentation, memory
 *   timeline/verbs, context-pack controls, facade routes and public CLI.
 * Runtime OpenAPI must still be captured by EngineFixture when these are armed.
 * No server, interpreter, build, typecheck or test was launched by this writer.
 *
 * Independent data: fixture asset `memory-canonical-cases`, cases[id]. The
 * fragment pins its bytes, canon hashes, source rows and synthetic truth. Its
 * @refs are roles to bind through public setup, never fabricated engine ids.
 * Two non-base worlds accompany the engine's reserved base world. PROJECT is
 * a scope, not a WORLD or a TaskRole. The paired owner is never a merge loser.
 *
 * G01: each complete journey waits for its missing typed HTTP AND SDK contract.
 * These are registered test.todo/BLOCKED rows, not partial passing coverage.
 * The signatures below describe canonical design data, NOT invented wire DTOs
 * or callable routes. App-layer camelCase must not be sent to today's
 * snake_case facade. There are no casts, execute-code substitutes, raw-body
 * escape hatches, private seeds, fake transports or conditional unblocking.
 *
 * When a door lands, bind its generated types and use EngineFixture, the
 * verified fixture loader, and (for extraction) ScriptedProviders. Fresh real
 * server per ID; mutations once; observe public reads/receipts; normal harness
 * deadlines and one slot. No engine defaults or harness constants are changed.
 */

/**
 * MEMORY-01 — Claim lifecycle with historical truth should work.
 * Canon: ARCH-0003 #claim-type/#lifecycle; ARCH-0004 #access; OF-006, OF-045.
 *
 * Canonical input:
 *   Claim { subjectId, predicate, value: ClaimValue, confidence, source,
 *     worldId, scopeFacetId, scopeRelationshipId, scopeProjectId,
 *     validFrom, validTo?, evidenceTurnIds,
 *     approvalStatus: "auto" | "proposed" | "approved" | "rejected",
 *     lifecycleStatus: "active" | "superseded" | "retracted", stale }
 * Consent is a holder act, never a caller-set approval field. Its result is
 * ProposalOutcome (Settlement): per-change and bundle verdicts, answered_by
 * (word ref, rule id@version or grant id), reason and revert handle.
 *
 * Deferred public journey (case MEMORY-01):
 * 1. Owner witnesses the original name and correction. Upsert the original;
 *    seed the alternative Proposed. Read recall AND review: only Morgan Vale
 *    is recalled, while the proposed Morgan Reed remains inspectable.
 * 2. An actor without the required authority must not settle it. The holder
 *    approves exactly the reviewed alternative; retain the Settlement receipt.
 * 3. Supersede the original, then retract the approved alternative through
 *    typed lifecycle calls. Recall after supersession contains only Morgan
 *    Reed; recall after retraction contains neither name as active truth.
 * 4. Read claims.history and the full HTTP memory timeline. Require both rows,
 *    old -> superseded, alternative -> retracted, the new-to-old supersedes
 *    edge, closed validity windows, original source/evidence and receipts.
 *    The recall admission conjunction is auto/approved AND active AND !stale;
 *    proposed/rejected/noncurrent/stale records are not recall candidates.
 *
 * Main has upsert, seed, retract and history. It has no typed settlement of an
 * arbitrary proposed claim in the generated HTTP/SDK catalog. Owner runs/approve
 * is a run-bound bundle, not approval of an arbitrary seed; its OpenAPI input
 * is an untyped object. Do not forge approval or a run_id to get around this.
 */
suite.todo(test, "MEMORY-01",
  "waits on typed proposed-claim approval/Settlement — Claim lifecycle with historical truth should work");

/**
 * MEMORY-02 — Claim admission rejects malformed scope should work.
 * Canon: ARCH-0003 #claim-type; ARCH-0040 #mcp-actor-ceilings;
 * OF-007, OF-016, OF-031, OF-464, OF-466, OF-494.
 *
 * Canonical scope is required on every claim:
 *   { worldId: WorldRef, scopeFacetId: FacetRef,
 *     scopeRelationshipId: "all" | RelationshipRef[],
 *     scopeProjectId: ProjectRef }
 * The facet is backed by the outgoing facet_of edge in the same write.
 * Missing is not an explicit top, bottom or set. Rule A is host-authored:
 *   made_by { inputs, process: { actor, class, identity, version, params_hash },
 *     at, trigger? }
 * A caller cannot choose a different author by supplying this envelope.
 *
 * Deferred public journey (case MEMORY-02), HTTP and tool-first MCP under the
 * SAME paired actor and scope:
 * 1. Establish one independently valid control. For each missing scope key,
 *    submit a batch containing a valid element and that malformed element.
 * 2. Repeat with a malformed typed value, out-of-range confidence, unknown
 *    named structural kind, and forged made_by.process.actor.
 * 3. Inspect each actual batch refusal/outcome and its receipt, then claim
 *    list, point reads and recall. No malformed row, facet edge or fragment
 *    may survive. Missing stored scope is InvalidClaimBody. The valid control
 *    keeps its explicit axes, type, clocks and host-authored provenance.
 * 4. Assert HTTP/MCP parity without guessing generated tool names. No numeric
 *    type-byte census, storage inspection or ABI migration is part of this ID.
 *
 * vault.commit is PER ELEMENT, not an all-or-nothing transaction: preserve a
 * valid sibling if it landed; never invent a blanket batch-rollback law.
 * Today's ClaimInput has optional world_ref/relationship_ref and opaque scope,
 * not the complete required four-axis typed input. Claim/entity reads also
 * lack a typed made_by result. A generic scope map is not the missing contract.
 */
suite.todo(test, "MEMORY-02",
  "waits on typed four-axis claim admission and host-authored made_by read — Claim admission rejects malformed scope should work");

/**
 * MEMORY-03 — Observed preference disagreement should work.
 * Canon: ARCH-0003 #observed-vs-stated; ARCH-0040 #memory-board-source-trust;
 * OF-023, OF-041, OF-072, OF-332.
 *
 * Canonical extraction candidate is Claim above with source="observed",
 * predicate="preference.language", value={kind:"string",value:"Japanese"},
 * and evidenceTurnIds naming all three observations. The owner's stated
 * English claim has source="user_stated". A disagreement is a persistent
 * Claim { predicate:"conflict.open", members:[stated, observed] } in semantic
 * terms; its member encoding must come from the future generated contract.
 *
 * Deferred public journey (case MEMORY-03):
 * 1. Witness the stated English preference. Witness the three distinct Japanese
 *    requests in two public sessions. Do not count a replay as more evidence.
 * 2. Drive signal_extraction through its typed public trigger, with an exact
 *    scripted provider response at the production inference adapter. Declare
 *    role/model/purpose and usage; no prompt matching, internal queue tick or
 *    direct observed upsert standing in for extraction.
 * 3. Recall both English/user_stated and Japanese/observed as active claims;
 *    require observed not to outrank stated under the default pack rule. Read
 *    the open conflict and require exactly this pair with original evidence.
 * 4. A real generated-writing actor attempts typed supersession of stated by
 *    the generated Japanese alternative. Require a refusal or held proposal
 *    as specified by that door, with a receipt: never closure of the stated
 *    claim, never source laundering, never removal of the observed sibling.
 *
 * A model-authored declaration of source="generated" on an owner call is NOT
 * proof of host stamping. Generic consolidation.enqueue accepts opaque job
 * input, not the typed signal_extraction operation. The generated SDK/HTTP
 * catalog also has no run-bound typed claims.supersede call; the code-mode
 * effect row is not a transport door. The existing owner conflicts read does
 * not supply either missing write operation.
 */
suite.todo(test, "MEMORY-03",
  "waits on typed signal_extraction trigger and generated claim supersession — Observed preference disagreement should work");

/**
 * MEMORY-04 — Opinion notes stay attributed should work.
 * Canon: ARCH-0032 #writers; ARCH-0040 #memory-board-source-trust;
 * OF-330, OF-015.
 *
 * Canonical semantic signature:
 *   author_take(target: SubjectRef | ClaimRef, markdown: string) -> NoteRef
 * The host binds the actor. NOTE kind="opinion/take" has author_ref and a
 * mandatory authored_by link. A claim-target take links via claim_of; a
 * subject-target take uses about. Edge provenance retains author and source
 * revision. No caller-supplied author parameter is allowed.
 *
 * Deferred public journey (case MEMORY-04):
 * 1. Publicly provision two distinct agent actors and pair each through
 *    EngineFixture.pairActor; do not mint holder authority or impersonate them
 *    by copying an author field into an owner's request.
 * 2. Owner writes the neutral Morgan Vale name claim. Each agent authors its
 *    opposite fixture take over that exact claim through typed author_take.
 * 3. Recall the subject. Require two distinct asides, labeled Reviewer North
 *    take / Reviewer South take, each tied to its actual paired actor.
 * 4. Read the neutral claim, its history, the notes, their links/provenance
 *    and public receipts. Its value, source, evidence, confidence, clocks and
 *    lifecycle must remain the authored neutral facts; opinions add notes,
 *    not supersession or retraction of the shared belief.
 *
 * Memory::author_take exists in the core, but no HTTP or generated SDK row
 * exposes it. notes.create has only kind/markdown, and from_entity has no
 * take payload. Neither is the designed author_take door. Structural NOTE
 * puts or hand-written provenance edges are explicitly not substitutes.
 */
suite.todo(test, "MEMORY-04",
  "waits on typed author_take HTTP and SDK call — Opinion notes stay attributed should work");

/**
 * MEMORY-05 — Bitemporal entity history should work.
 * Canon: ARCH-0003 #claim-type; OF-016, OF-466.
 *
 * Canonical rows retain occurredAt and learnedAt independently, their Claim
 * source/evidence and Rule A made_by {inputs, process, at}. Their public entity
 * envelope projects occurred_start, occurred_end and learned_at. Provenance
 * input refs and the writer come from the original public witness/credential,
 * not a value invented by a history reader or supplied as a forged envelope.
 *
 * Deferred public journey (case MEMORY-05):
 * 1. Witness/write the name fact (occurred Jan 3, learned Feb 10) and pronouns
 *    fact (occurred Jan 20, learned Feb 1), using the fixture's Unix-second
 *    constants and two different predicates so both facts remain active.
 * 2. POST the context pack with each of the four exact fixture time windows:
 *    time.{occurred_start,occurred_end} vs time.{learned_start,learned_end}.
 *    Require the fixture's singleton membership, and opposite ordering of
 *    the two facts by occurrence and learning. Do not demand ranking scores.
 * 3. Read both entity envelopes, their timelines/history and receipts. Both
 *    clocks and the original evidence, stated source and host-stamped writer
 *    survive. Each row has non-forgeable made_by, not just provenance prose.
 *
 * The public time filters ALREADY EXIST; this is not blocked on temporal
 * search. RecallRequest.as_of only anchors relative query words, so it is
 * not a learned-time view. The missing part is typed CLAIM/entity provenance:
 * EntityView and ClaimView expose no made_by. ArtifactVersionView does, but
 * moving these statements into artifacts would not test claim history.
 */
suite.todo(test, "MEMORY-05",
  "waits on typed claim/entity made_by provenance read — Bitemporal entity history should work");

/**
 * MEMORY-06 — Task and habit lifecycle should work.
 * Canon: ARCH-0067 #tasks; OF-019.
 *
 * Canonical intent kinds all share TASK:
 *   TaskRole = Task | Goal | Milestone | Habit | HabitCheckin
 *   Task hierarchy: Goal -> Milestone -> Task; Habit -> HabitCheckin.
 * PROJECT is the separate claims scope, never an invented Project TaskRole.
 * A check-in input names the Habit, intent/id, occurrence time and data;
 * its result is an immutable TASK/HabitCheckin plus child_of and a receipt.
 * Streak fields are derived, not supplied by the test or a provider.
 *
 * Deferred public journey (case MEMORY-06):
 * 1. Install the declared productivity pack by public pack setup. Create the
 *    project, goal, milestone, task and habit through typed productivity calls;
 *    read the valid nested tree and TASK role labels.
 * 2. Reject Goal -> Task, Task -> Task and Habit -> Task. After each refusal,
 *    inspect the tree and receipts: existing nodes/edges remain unchanged,
 *    and no rejected child/edge is partially stored.
 * 3. Append the fixture check-in, repeat the SAME intent without mutating its
 *    payload, then attempt to change that immutable check-in. Require one
 *    child, original data/time, currentStreak=1 and longestStreak=1. Read the
 *    task state too, so a task create/route failure cannot masquerade as a
 *    complete valid productivity tree.
 *
 * Main has habits.checkin, but tasks.create always mints Task role and has no
 * typed role/parent input. Putting a Goal/Habit body through structural.put,
 * or hiding role/child_of in tasks.create's opaque spec, would bypass the
 * designed productivity operation. Do not use a generic write to arm this ID.
 */
suite.todo(test, "MEMORY-06",
  "waits on typed productivity role creation and task nesting — Task and habit lifecycle should work");

/**
 * MEMORY-07 — Identity merge split and undo should work.
 * Canon: ARCH-0055 #trio/#entity-ids; ARCH-0040 #revert-run;
 * OF-398, OF-172, OF-443.
 *
 * Canonical semantic operations (wire names still wait):
 *   merge(sources[], survivor, evidence, survivorship_plan)
 *   split(entity, heads[], reassignment_map, evidence)
 *   facet(entity, facets[], reassignment_map, evidence)
 *   assert_distinct(a, b, reason) -> entity.distinct_from claim
 *   revert_run(run_id) -> compensating-op receipt, including partial undo
 * Apply yields append-only evidence/actor/rationale events and redirects;
 * resolution returns a set of 0/1/N current heads, never a rewritten subject.
 *
 * Deferred public journey (case MEMORY-07):
 * 1. Publicly mint the two candidate people, distinct evidence and intentional
 *    story facet. Neither candidate is the embedded owner. Merge B into A;
 *    resolve B to {A}, with B a merged shell, never a tombstone.
 * 2. Split A into north/south heads by the fixture evidence map. Resolve the
 *    old B through that chain to both heads; read split_into, merged_into and
 *    topology receipts. Original claims keep their original subjects, and
 *    unassigned evidence remains ambiguous on the shell, not force-assigned.
 * 3. Undo the split, then merge, through typed undo. Require counter-events,
 *    restored head sets and intact evidence/history, not deletion of ledger
 *    events or eager rewriting of references. Honor partial-undo receipts if
 *    later work depends on an op; this fixture creates no such later work.
 * 4. Assert distinctness for A/B and re-run typed candidate proposal. No merge
 *    suggestion for that pair may reappear. The intentional facet remains a
 *    mask of its person, never a candidate duplicate PERSON.
 *
 * Core merge_split_oracle supplied invariant orientation only; its Vault
 * setup and private topology calls are not reused. No public typed merge,
 * split, facet, topology resolution/undo or candidate-proposal door exists.
 * self.identity.answer/settle resolve a name/choice, not this op family;
 * vault.refs.resolve previews a record, not a topology head set. Per-change
 * owner dreamer/revert is not the designed revert_run contract.
 */
suite.todo(test, "MEMORY-07",
  "waits on typed identity topology, candidate proposal and undo calls — Identity merge split and undo should work");

/**
 * MEMORY-08 — World and project separation should work.
 * Canon: ARCH-0004 #access/#world-scope; ARCH-0043 #guest-grants;
 * ARCH-0022 #facet-read-ruling; OF-434, OF-464, OF-172.
 *
 * Canonical writes explicitly name all four axes:
 *   Claim { worldId, scopeFacetId, scopeRelationshipId, scopeProjectId, ... }
 * Read selection distinguishes All, Base and a world/set with base declined;
 * it also selects PROJECT, not a corpus alias or a topical WORLD.
 * Guest ceilings cross explicit world/facet/kind sets; bottom is distinct
 * from top. An absent/empty grant axis never becomes an unrestricted grant.
 *
 * Deferred public journey (case MEMORY-08):
 * 1. Write the six fixture name claims: one subject and predicate, reserved
 *    base plus dream and roleplay, crossed with the two separate projects.
 *    All six retain their explicit scope, rather than superseding across
 *    project/world boundaries or inferring a missing world as base.
 * 2. Query all. Require every fixture value with world/project labels, base
 *    partition first. Query each exact world/project intersection, explicitly
 *    declining inherited base in non-base reads: each returns its one fact.
 * 3. Under a separately granted guest credential, read with an empty world
 *    ceiling, omitted world ceiling, empty facet ceiling and omitted facet
 *    ceiling. Each admits zero claims. Inspect narrowing/refusal receipts,
 *    not just an accidentally empty query. Test a missing write axis too.
 * 4. Keep request and grant types distinct: an empty requested axis adds no
 *    narrowing but still meets the grant. The owner is never narrowed below
 *    the top of their own root. A facet relevance mode is not a permission.
 *
 * ClaimInput lacks the complete typed four-axis write contract. RecallScope
 * exposes only world_ref, facet and kinds, with no project/set/base-decline
 * selection. Opaque scope maps, made-up fields on a raw request or broad
 * structural writes would hide this missing public contract, not test it.
 */
suite.todo(test, "MEMORY-08",
  "waits on typed four-axis claim writes and world/project read selection — World and project separation should work");
