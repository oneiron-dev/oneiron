import { afterAll, test } from "bun:test";
import { defineFile } from "./support/run.ts";

const profile = process.env.E2E_PROFILE === "real-small-model"
  ? "real-small-model" : "deterministic";
const suite = defineFile(import.meta, { profile, slots: 1 });
afterAll(suite.flush);

/*
 * Skills and improvement. All eight complete journeys currently wait on G01.
 * suite.todo emits Bun test.todo plus a mandatory BLOCKED report row, never
 * passing coverage. Do not replace a missing typed verb with execute_code,
 * vault.batch, an opaque entity body, a Rust fixture, or a fabricated receipt.
 *
 * Binding readback: worktree head 3a829fe65a7282da4a5e44733ba35cc36fa36b80;
 * generated HTTP facade inputs/results and the public Oneiron SDK; server
 * OpenAPI registry/owner paths, owner pack handlers and CLI command enum.
 * The owner's HTTP pack routes exist, even where SDK/library doors do not.
 * self.skills.save/fork/callables exist; self.skills.call is run-context only,
 * not a generated HTTP/SDK verb. skills-pack prints the static API guide, not
 * the vault's skill library. Neither is a substitute for the missing flows.
 *
 * Independent inputs, expected facts and canon SHA-256 pins: skills-scenarios
 * in fixtures/skills/manifest.json. Hub aliases refer to immutable folder
 * assets, not invented vault ids or a fabricated wire index. The bootstrap
 * four are unmodified Apache-2.0 source snapshots, not private seed records.
 *
 * When the doors land, use a fresh EngineFixture.start({ id, profile }) for
 * each journey, loadFixtures(), authenticated public owner/actor setup, and
 * ScriptedProviders behind production wire adapters. MCP calls use the
 * generated tool's arguments.spec. Await public receipts/events, never a
 * private clock, queue drain, sleep, automatic mutation retry or direct store.
 * Canon below defines semantic types where no HTTP/SDK DTO exists yet; it
 * does not invent endpoint names, cursor encodings or model response DTOs.
 */

/* SKILLS-01 — Message to reusable skill should work. OF-206, OF-215.
 * Canon: ARCH-0053 #r4-lifecycle. Oracle: skills-scenarios / SKILLS-01.
 *
 * Publicly append the two owner messages in the fixture to one conversation.
 * The conversion request must select those message refs, not caller-supplied
 * trusted skill text. A scripted refiner returns the fixture's SKILL.md,
 * preserving all three procedure steps and adding no unsupported authority.
 * User initiation pre-approves conversion, but still runs normal admission.
 * Repeat the same selection/refinement. Require one canonical skill identity
 * and source provenance covering both messages, not two active copies.
 * Retrieve through MCP and execute the workflow on the fixture's [3,1,2];
 * require [1,2,3] plus an execution receipt naming the loaded/used version.
 *
 * Canon identity: SHA-256(canonical file tree), with aliases separate.
 * Provenance: selected source refs and source kind, retained on the skill.
 * Lifecycle: candidate | active | stale | archived | superseded.
 * Delete a selected source as owner, using public preview/confirm if required.
 * Await its deletion receipt, then read lifecycle/provenance again: stale,
 * evidence explicitly unavailable, excluded from trusted active loading; not
 * silently orphaned or erased. The deletion itself is never inferred from a
 * successful HTTP request alone.
 *
 * Existing self.skills.save({ files: [{path,content}], id?, expected_version? })
 * -> {skill_id, author, author_receipt, version} creates an agent candidate;
 * it is NOT selected-message conversion or its user pre-approval. Record
 * erasure is public, but conversion and typed library/lifecycle reads are not.
 */
suite.todo(test, "SKILLS-01", "waits on typed selected-message conversion, skill lifecycle/provenance reads and MCP workflow execution");

/* SKILLS-02 — Hub content identity and pinned update should work.
 * OF-213, OF-396. Canon: ARCH-0053 #r4b-hubs, ARCH-0040 #mcp-actor-ceilings,
 * ARCH-0076 #escalation-doors-built. Oracle: SKILLS-02, skills-hub-aliases.
 *
 * Register two loopback hubs with different aliases serving the SAME v1 tree.
 * Canon SKILL_HUB = {kind, endpoint, trust_tier, sync_policy}; hub_ref =
 * {hub_id, ref_string, pin:{type:semver|tag|commit|content_hash|none,value}}.
 * Import both: one content identity, exactly two distinct source rows, the
 * same tree digest, and scan evidence keyed by (content_hash, provider, time),
 * never by alias. No dependency inherits the importing hub's trust.
 * Move hub A's alias to v2 without changing v1's immutable bytes. Sync its
 * content-hash-frozen pin: it must not silently adopt v2. A refusal on drift
 * is acceptable; the trusted v1 pin/content and both source rows must remain.
 * Explicitly offer v2 with fixture-mcp:lookup widening allowed-tools. Require
 * a pending re-consent proposal/receipt, unchanged effective capabilities and
 * trusted version until the OWNER accepts. An agent cannot accept for them.
 *
 * Separately fork a local improvement and request useful-upstream review.
 * Use a supported System One OR escalation first pin, with pinned model and
 * revision, not a hardcoded vendor. Inspect the review's own providers and
 * paired rows: one per measuring provider, nonzero question_version,
 * probability in [0,1], auxiliary question != answered question. No invented
 * zero row for a missing pair. A supported yes still needs held-out admission;
 * no keeps the resident fork without deleting it. Reject mismatched-provider
 * evidence through the real provider protocol, not a forged internal verdict.
 *
 * Existing owner HTTP (prefix /v1/owner/packs):
 * POST /skills/import {hub,folder,pin_type,pin_value,publisher} -> {entity};
 * PUT /ref-sync {hub,ref,sync_policy,pin_type,pin_value} -> stored ref view;
 * POST /skills/{entity}/sync -> {outcome:applied|proposed|refused_by_policy,
 *                              proposal?,approval?};
 * GET /skills/{entity}/receipts -> {imports:HubImportReceipt[],admission?}.
 * Hub registration/inspection, matching SDK skill doors and useful-upstream
 * review/evidence are missing. Do not fabricate a configured hub entity.
 */
suite.todo(test, "SKILLS-02", "waits on typed SKILL_HUB register/read, skill import/sync SDK calls and useful-upstream review with paired evidence");

/* SKILLS-03 — Skill admission and soft retirement should work.
 * OF-213, OF-215. Canon: ARCH-0053 #r4-lifecycle, #r4b-hubs.
 * Oracle: SKILLS-03, clean-v1, suspicious, code-pack assets.
 *
 * Import clean text, an owner-declared known-bad hash rule hit, and the local
 * code-bearing capability pack under a publicly declared code-auto-install
 * flag OFF. Publish the suspicious hash rule through a named public owner
 * policy door. Clean text passes fit to Active. Suspicious content is Candidate
 * with a stated rule-hit reason (not an executable trusted instruction).
 * Code stays Candidate while the flag is off. Inspect the grant ask, source,
 * capability envelope and scan receipts; scanner prose never supplies consent.
 *
 * Archive the active skill: archived, absent from loadable packs, body/source
 * and prior receipts retained. Restore explicitly: loadable only after the
 * same admission rules; original evidence survives. Replace via local fork:
 * child remembers its parent document AND frontier, independent content
 * identity, original hub ancestry, and upstream auto-update becomes proposal.
 * Admit the replacement: old version superseded and never loaded as current.
 * No automatic deletion, history rewrite, second fork law or trust inheritance.
 *
 * Existing self.skills.fork({parent,id?,skill_id}) -> SkillAuthoringReceipt
 * retains ancestry; self.skills.save remains proposed. vault.packs.put accepts
 * {files:[{path,text}]} and returns {outcome,reason?,receipt?}. Owner HTTP skill
 * import/permission/activation routes exist (SKILLS-02/04). They do not expose
 * typed skill lifecycle/archive/restore or document-frontier lineage reads.
 * Canon SDK names vault.skills.put(folder), .fork(h), .archive(h), .export(h)
 * are designed, not current generated calls. Wait for their actual DTOs.
 */
suite.todo(test, "SKILLS-03", "waits on typed skill rule policy/admission/lifecycle reads, archive/restore and fork-frontier inspection");

/* SKILLS-04 — Bootstrap skills and restore defaults should work. OF-518.
 * Canon: ARCH-0053 #r4b-hubs, #r4-lifecycle. Oracle: SKILLS-04.
 *
 * CLI init is performed by EngineFixture, with no network or model downloads.
 * Read the required embedded set: skill-optimize, judge, goal-intake, wake.
 * Compare their bodies against the four pinned source snapshots. Other
 * shipped skills must have import provenance from hub one at immutable pins;
 * do not bless today's 15 embedded entries as the expected bootstrap four.
 * Point the first hub's pinned source at the fixture's local mirror using
 * supported owner setup, never an inherited override or private seeded row.
 *
 * Customize one non-bootstrap default through the common fork law. Preserve
 * that fork, then owner-delete its shipped source with a receipt. No read,
 * restart or background sync may silently restore it. Invoke restore defaults
 * explicitly. Require a fresh import of the pinned ORIGINAL content identity,
 * new import receipt, unchanged custom fork and lineage, and unchanged other
 * defaults. Fresh import does not mean inventing a new content hash. Reopen
 * the same fresh vault and require persistence of these facts.
 *
 * Existing POST /v1/owner/packs/skills/restore-defaults (no input body)
 * -> {entity:string}[]; /skills/restore {subtree:string} -> {entity:string}.
 * Existing activation/prepare {publisher,evidence_skill,effect_digest?}
 * -> {candidate,content_hash,effect_digest,surface}; activation/approve takes
 * the shown digest and returns {outcome,decision}. These are real HTTP doors,
 * not proof that typed bootstrap reads, mirror setup or the canon's SDK
 * vault.skills.restoreDefaults() exist. CLI skills-pack prints the API guide;
 * it does not inspect or restore resident skills.
 */
suite.todo(test, "SKILLS-04", "waits on pinned first-hub mirror setup, typed bootstrap/hub reads and vault.skills.restoreDefaults SDK call");

/* SKILLS-05 — Skill receipt attribution and reliability should work.
 * OF-184, OF-395, OF-397, OF-394. Canon: ARCH-0053 #r4-lifecycle,
 * #r3-reliability and ARCH-0003 #learning. Oracle: SKILLS-05.
 *
 * Publicly create two versions and two distinct actors, then pair the actors;
 * pairActor creates credentials for existing principals, never an actor.
 * Execute via MCP with scripted anchored success, skill-defect failure and
 * execution-lapse failure. Include a loaded-but-unused skill, an unanchored
 * self-reported win, an environment failure and an unclear judgment control.
 * Settle through public outcome doors, await the projector's public receipt,
 * then inspect next retrieval through HTTP/MCP. Pack manifests are append-only
 * across mid-run pulls. Each receipt names loaded vs actually used versions,
 * actor, executor/judge revisions, outcome anchor and required
 * typeRef={node_id,tree_version}. Superseded versions never load as current.
 *
 * learning.reliability is one states-only, projector-only estimate keyed by
 * subject, executor, typeRef and axis. Its value is {form:beta,value:{alpha,beta},
 * runs,prior:{origin,value,weight_runs,from?},untested,of,labels,window,ver}.
 * Own runs count only anchored attributed evidence: used contribution earns
 * wins, skill defect charges skill, lapse charges actor prose/actor lane,
 * environment/unclear blame nobody. No success from load alone, agreement or
 * self-report. Provider reliability uses the same family, not a second score.
 * The next retrieval must expose its reliability/UCB evidence without a fixed
 * randomized rank or locally reimplemented posterior formula. Judge identity
 * is evidence, never part of the reliability cell key.
 *
 * Existing call receipts prove a transport invocation, NOT its task outcome.
 * vault.settings.learning reads knob seeds/pins, NOT skill effectiveness.
 * vault.claims.list has an opaque value leaf, not a substitute typed learning
 * projection. Never hand-write a learning.* claim to manufacture this flow.
 */
suite.todo(test, "SKILLS-05", "waits on typed MCP skill execution/pack outcomes, attributed learning projection and retrieval evidence");

/* SKILLS-06 — Held-out skill optimization should work. OF-214, OF-379.
 * Canon: ARCH-0053 #r4-lifecycle, #self-revision; ARCH-0003 #learning.
 * Oracle: SKILLS-06. Train and sealed case families are disjoint authored
 * inputs; the fixture score table is external judge output, not engine state.
 *
 * Start optimize on a standard skill with real source/evidence and fixed
 * search/holdout family assignments. The scripted overfit candidate improves
 * training (4/4 vs 3/4) but loses sealed holdout (2/4 vs 3/4). Read rejection,
 * incumbent unchanged/active, candidate not active, holdout receipt retained,
 * and rejected-edit rationale available to the next search. Provider request
 * history must show no sealed case fed to author/search before confirmation.
 * A new, independently authored candidate scores 4/4 on sealed cases with
 * floors/cost unchanged. Require admission, parent/frontier lineage, evidence
 * and judge/rubric pins, original superseded and no new capability permission.
 * Run the same request against identity and alignment tiers. Neither enters
 * automatic editing or activation; preserve original content and authority.
 *
 * Canon admission reads the human goal record: primary axes, never-regressing
 * floors, costs (including human minutes), preferences, exploration budget.
 * Dominance admits, ties reject, tradeoffs escalate. The search never admits
 * its own draft or edits the ruler/goal/Grant. A supported typed model pin is
 * permitted on a tradeoff; it still cannot waive held-out admission.
 *
 * Existing vault.research.promote({root,candidate,referee,sufficiency,
 * skill_proposal?}) settles an existing bound campaign. It is not a typed
 * skill_optimize launch, governed skill creation or automatic tier-exclusion
 * door. Do not seed an ATTEMPT or send an opaque consolidation job instead.
 */
suite.todo(test, "SKILLS-06", "waits on typed skill_optimize start/result and identity/alignment governance reads");

/* SKILLS-07 — Edit-delta attribution split should work. OF-400, OF-379.
 * Canon: ARCH-0056 #attribution-split, ARCH-0053 #r4-lifecycle,
 * ARCH-0003 #learning. Oracle: SKILLS-07.
 *
 * Save an agent draft as a public proposal artifact; record the owner's two
 * exact replacement operations before settlement. Use the authored 7:3 edit
 * masses and a scripted 70% skill_defect / 30% preference_shift judgment.
 * Read original/final refs, actor-bound recorded hunks, nonzero normalized
 * delta and judgment evidence. Do not reconstruct the in-app changes from
 * final text or stamp a client-supplied d_norm as measured by the server.
 * Attribution labels are skill_defect | execution_lapse | discovery |
 * environment | preference_shift | unclear. Hunk-weighted shares sum to 1.
 *
 * Require the skill's learning.reliability/edit_cost to receive ONLY 0.7 of
 * the attributed mass and preference outputs to receive ONLY the other 0.3;
 * preference is never an edit-cost charge or a numeric claim about the person.
 * Both projections cite the same settled delta and retain their qualifiers.
 * Inspect fresh receipt evidence, not wall-clock-decayed posterior equality.
 * An unclear control includes a note and updates no reliability or blame.
 * A malformed split (sum 0.9) must not silently renormalize or charge the skill.
 * Whitespace/rewrap-only edits carry no edit mass. Outcome rows and preference
 * notes stay visible even when no skill score changes.
 *
 * Canon delta shape: proposed/final refs + d_norm + recorded ops summary;
 * judgment: changed-hunk labels and percentage vector; consumers route each
 * share after judgment. No current typed public DTO exposes this end-to-end
 * settlement/projector path. Office Keep/Discard/Undo is not that door, and
 * generic report({category,note,evidence_refs}) does not settle attribution.
 */
suite.todo(test, "SKILLS-07", "waits on typed proposal delta/hunk settlement, attribution projector results and preference evidence reads");

/* SKILLS-08 — Consent graduation is an offer should work. OF-399.
 * Canon: ARCH-0040 #mcp-actor-ceilings, ARCH-0003 #learning;
 * ARCH-0056 #graduation and OF-399 define the offer. Oracle: SKILLS-08.
 *
 * Declare the fixture's short threshold/backoff policy through supported
 * owner policy doors; values are test inputs, never changed engine defaults.
 * Publicly settle untouched/amended/rejected outcomes for one exact scope
 * (operation kind x target class x skill/agent). Read counts/deltas and earn
 * the streak plus posterior guard. Before and after reading the offer, the
 * standing grant is ABSENT: eligibility and an agent's request grant nothing.
 * The offer proposes the existing create_standing_grant, scoped and receipted.
 *
 * Decline using not-now: streak resets; no immediate repeat. With fixture
 * backoff zero, re-earn the WHOLE streak before another offer. Owner accepts
 * that offer: exactly one existing standing grant, precise audience/budget,
 * receipt linked to the offer, durable after restart, and no duplicate offer.
 * An agent answer must be refused without changing authority. Inspect the
 * before/after reach line. Amend/reject/undo signals remain in the trust table.
 * Enough undo/amend evidence may support transparent receipted demotion;
 * require scope returns to propose, no erased history, owner-reversible.
 *
 * Canon answers: auto | not-now (snooze+backoff) | manual_pinned (settings-only
 * unflip). The policy guard, sample minimum and streak are required; raw
 * successes alone never self-grant. If zero backoff cannot be owner-configured
 * publicly, this scenario waits on a supported short policy, not a fake clock.
 * Existing room consent and context-widen proposals are DIFFERENT operations;
 * neither is a consent-graduation offer/answer. Wait for typed policy, outcome,
 * trust-table, offer/answer and demotion doors, with matching SDK bindings.
 */
suite.todo(test, "SKILLS-08", "waits on typed consent-graduation policy, offer/answer, trust-table and receipted demotion doors");
