import { afterAll, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { copyFile, mkdir, readFile, readdir } from "node:fs/promises";
import { resolve } from "node:path";
import type { Facade, FacadeInput, FacadeResult } from "@oneiron/client";
import { EngineFixture, awaitPublic, type PairedActor } from "./support/engine.ts";
import { PublicHttpClient, PublicHttpError } from "./support/clients.ts";
import { loadFixtures, ownerBaseClaimScope } from "./support/fixtures.ts";
import { ScriptedProviders, openaiStream, openaiText } from "./support/providers.ts";
import { defineFile, LIMITS, redactor, secretHex } from "./support/run.ts";

const profile = process.env.E2E_PROFILE === "real-small-model"
  ? "real-small-model" : "deterministic";
const suite = defineFile(import.meta, { profile, slots: 1 });
afterAll(suite.flush);

/*
 * Public binding read at main c2239db2c8486fd18b7fe33ebe9bc272b689079a:
 * scripts/sdk/verbs/, both generated TypeScript facade catalogs,
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
 * A written case proves exactly the subset its name states, and only when
 * that subset keeps a promise of the planned title (Engine E2E-PARTIAL = A,
 * 9 Nov 2026); its comment lists what stays unproved. Every other case is a
 * TODO naming its missing door, not partial coverage.
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

type Coordination01Card = FacadeResult<"vault.projects.proposals">[number];
type Coordination01Goal = FacadeInput<"vault.projects.propose">["goal"];
type Coordination01Picks = FacadeInput<"vault.projects.propose">["picks"];
type Coordination01Entity = NonNullable<FacadeResult<"vault.get">["value"]>;
interface Coordination01Scenario {
  id: "COORDINATION-01";
  inputs: {
    conversation: { label: string; author: string; content: string }[];
    card: { goal: { goal: string; why: string; axes: string[] }; leader: string; board: string[];
      budget_share_bps: number; startingSkills: string[] };
  };
  expected: { projectsBeforeTap: number; projectsAfterDismiss: number; newProjectsAfterAcceptance: number;
    newHomeRooms: number; leader: string; board: string[]; budgetShareBps: number; confirmReplayAddsProjects: number };
}
/** Stored PROJECT body keys, verbatim snake_case (ProjectRecord, workspace_roster/project/mod.rs:162-212). */
interface Coordination01ProjectBody {
  role: string; parents: string[]; claims_scope_ref: string; leader: string; board: string[]; roster: string[];
  skill_forks: string[]; born_from?: string | null; home_room: string;
  goal_record?: { project_id: string; goal: string; why: string; axes: string[] } | null;
  budget_share?: { project_id: string; parent_id: string; share_bps: number } | null;
}
const COORDINATION01_AT = 1769947200; // Public setup input, never an engine clock override.
/** The host-configured decision wording; the Big rung sends it as the first system text (big_rung.rs:319-328). */
const COORDINATION01_DECISION_WORDING = "You answer one typed question about the state you are given.";
/** The typed project question is a buffered call: `stream: false` (wire.rs:146-149, ladder/generation.rs:167-188). */
const COORDINATION01_DECIDE = { method: "POST", path: "/v1/chat/completions", model: "project-decider",
  fields: { stream: false }, system: COORDINATION01_DECISION_WORDING } as const;
/** Code-mode executor runs stream (ai_host/code_mode.rs:676-705, wire.rs:146-149). The executor's own
 * system prompt is generated, so it is never matched; only the stable streaming contract is. */
const COORDINATION01_DRAFT = { method: "POST", path: "/v1/chat/completions", model: "project-drafter",
  fields: { stream: true, stream_options: { include_usage: true } } } as const;

async function coordination01Scenario(): Promise<Coordination01Scenario> {
  const data = await (await loadFixtures()).readJson<{ scenarios: { id: string }[] }>("coordination-scenarios");
  const row = data.scenarios.find(row => row.id === "COORDINATION-01");
  if (!row) throw new Error("coordination-scenarios has no COORDINATION-01");
  return row as Coordination01Scenario; // Fixture discriminant, not an invented wire DTO.
}
// A chosen public input id, passed to its create door before any use.
function coordination01InputId(label: string): string {
  return createHash("sha256").update(`coordination-e2e:${label}`).digest("hex").slice(0, 32);
}
function coordination01Models(providers: ScriptedProviders): string {
  return `
[models.providers.drafter]
kind = "local-openai-compat"
base_url = "${providers.urls.drafter}"
revision = "e2e-v1"
[models.providers.decider]
kind = "local-openai-compat"
base_url = "${providers.urls.decider}"
revision = "e2e-v1"
[models.roles.generative_reasoner]
model = "drafter:project-drafter"
[models.roles.checker]
model = "decider:project-decider"
[models.decisions.big]
role = "checker"
version = "e2e-v1"
wording = ${JSON.stringify(COORDINATION01_DECISION_WORDING)}
reply = "json"
[models.code_mode]
prompt_package = ${JSON.stringify(resolve(import.meta.dir, "fixtures/hooks/host/prompts"))}
[models.dreamer]
enabled = false
`;
}
function coordination01Git(cwd: string, args: string[]): string {
  const run = Bun.spawnSync(["git", "-c", "user.name=oneiron-e2e", "-c", "user.email=e2e@oneiron.invalid", ...args],
    { cwd, stdout: "pipe", stderr: "pipe" });
  if (run.exitCode !== 0) throw new Error(`git ${args[0]} failed: ${run.stderr.toString()}`);
  return run.stdout.toString().trim();
}
/** The house drafter refuses without the project-proposal skill. Imports it through the default hub,
 * repointed at a local Git folder in the engine's own temporary root at one full commit (#6711),
 * exactly as memory.test.ts installProjectProposal does. Returns the imported SKILL entity. */
async function coordination01InstallProjectProposal(engine: EngineFixture): Promise<string> {
  const dir = resolve(engine.root, "project-proposal-hub");
  await mkdir(resolve(dir, "skills", "project-proposal"), { recursive: true });
  await copyFile(resolve(import.meta.dir, "../../skills/project-proposal/SKILL.md"), resolve(dir, "skills", "project-proposal", "SKILL.md"));
  coordination01Git(dir, ["init", "-q"]);
  coordination01Git(dir, ["add", "skills/project-proposal/SKILL.md"]);
  coordination01Git(dir, ["commit", "-q", "-m", "project-proposal"]);
  const commit = coordination01Git(dir, ["rev-parse", "HEAD"]);
  const { hub } = await engine.client.call("vault.skill_hubs.default.get", {});
  const configured = await engine.client.call("vault.skill_hubs.put", {
    hub, kind: "local-dir", endpoint: dir, trust_tier: "community", sync_policy: "pinned-commit" });
  expect(configured.consent.outcome).toBe("approved");
  await engine.client.call("vault.skill_hubs.refs.set", {
    hub_ref: { hub_id: hub, ref_string: "skills", pin: { type: "commit", value: commit } }, sync_policy: "pinned-commit" });
  const hub_ref = { hub_id: hub, ref_string: "skills/project-proposal", pin: { type: "commit" as const, value: commit } };
  const { entity } = await engine.client.call("vault.skills.import", { hub_ref, publisher: "oneiron-e2e-local" });
  const latest = async () => (await engine.client.call("vault.skills.receipts", { entity })).imports.at(-1)?.disposition;
  if (await latest() === "pending_permission") await engine.client.call("vault.skills.permissions.approve", { entity, hub_ref });
  const disposition = await latest();
  if (disposition !== "installed" && disposition !== "already_installed") {
    throw new Error(`project-proposal import not active: ${JSON.stringify(disposition)}`);
  }
  return entity;
}
async function coordination01Entity(client: PublicHttpClient, entity_ref: string): Promise<Coordination01Entity> {
  const result = await client.call("vault.get", { entity_ref });
  if (!result.value) throw new Error(`Public entity missing: ${entity_ref}`);
  return result.value;
}
function coordination01ProjectBody(entity: Coordination01Entity): Coordination01ProjectBody {
  const body = entity.body;
  if (body === null || body === undefined || typeof body !== "object" || Array.isArray(body))
    throw new Error(`PROJECT ${entity.id_hex} has no public body`);
  return body as Coordination01ProjectBody; // Read-back of the stored record, keys per ProjectRecord serde.
}
/** A refused public call: the HTTP status, the engine code, and the engine's own reason text. */
async function coordination01Refused(call: Promise<unknown>, status: number, code: string, reason: string): Promise<void> {
  let refusal: PublicHttpError | undefined;
  try { await call; } catch (error) {
    if (!(error instanceof PublicHttpError)) throw error;
    refusal = error;
  }
  if (!refusal) throw new Error(`Expected HTTP ${status} ${code} (${reason}); the call succeeded`);
  expect(refusal.reply.status).toBe(status);
  expect(refusal.error?.code).toBe(code);
  expect(refusal.error?.message ?? "").toContain(reason);
}
function coordination01Minted(cards: readonly Coordination01Card[]): Coordination01Card[] {
  return cards.filter(card => typeof card.state === "object");
}
/** The scripted step each provider request on `origin` was answered by, in arrival order; a request
 * no step accepted reads as null, so unexpected traffic is visible here and fails providers.close(). */
function coordination01Answered(providers: ScriptedProviders, origin: "decider" | "drafter"): (string | null)[] {
  return providers.seenFixtureCalls.filter(call => call.origin === origin).map(call => call.fixtureId);
}
/** One house-drafted card: the owner's on-record message, a scripted typed YES from the real
 * project-question ladder, and the house drafter's scripted code calling vault.projects.propose. */
async function coordination01HouseCard(engine: EngineFixture, providers: ScriptedProviders, conversation: string,
  content: string, card_id: string, goal: Coordination01Goal, picks: Coordination01Picks, index: number,
): Promise<{ message: string; card: Coordination01Card; cards: Coordination01Card[] }> {
  const decide = `coordination01-decide-${index}`;
  providers.enqueue({ id: `coordination01-yes-${index}`, origin: "decider", role: "checker", purpose: "project question",
    request: COORDINATION01_DECIDE, barrier: decide,
    response: openaiText(`coordination01-yes-${index}`, "project-decider", JSON.stringify({ answer: true, probability: 0.9 }),
      { inputTokens: 256, outputTokens: 16 }) });
  const witnessed = await engine.client.call("vault.witness", { conversation_ref: conversation, occurred_at: COORDINATION01_AT,
    messages: [{ author: "user", message_type: "text", content, is_visible: true, order: 0 }] });
  const short = witnessed.message_short_ids[0];
  if (short === undefined) throw new Error("Witness returned no message");
  const message = (await coordination01Entity(engine.client, short)).id_hex;
  await providers.awaitBarrier(decide);
  const proposal = { card_id, source_message_ref: message, goal, picks };
  providers.enqueue({ id: `coordination01-draft-${index}`, origin: "drafter", role: "generative_reasoner", purpose: "house project drafter",
    request: COORDINATION01_DRAFT,
    response: openaiStream(`coordination01-draft-${index}`, "project-drafter",
      [`await vault.projects.propose(${JSON.stringify(proposal)});\nfinish(${JSON.stringify(card_id)});`],
      { inputTokens: 512, outputTokens: 128 }) });
  providers.releaseBarrier(decide);
  const cards = await awaitPublic(() => engine.client.call("vault.projects.proposals", { conversation_ref: conversation }),
    rows => rows.some(row => row.card.card_id === card_id && row.state === "proposed"),
    { label: `house-drafted project card ${card_id}` });
  const card = cards.find(row => row.card.card_id === card_id);
  if (!card) throw new Error(`Card ${card_id} missing`);
  return { message, card, cards };
}

/* COORDINATION-01 promise: a project an agent proposes exists only after its person accepts the card;
 *   a dismissed card stays dismissed and never mints; the agent cannot propose, dismiss or confirm for them.
 * Doors: typed HTTP facade (vault.agents.create, vault.witness, vault.projects.proposals/propose/
 *   dismiss_card/confirm, vault.rooms.list, vault.get, vault.neighbors, skill hub import), pairActor for
 *   the leader AGENT_DEF; ScriptedProviders for the typed YES and the house drafter's code.
 * Unproved: the drafting agent's request over MCP (the house run calls the typed verb in code mode;
 *   no public door seats an MCP drafter as the house); a human board other than the owner (confirm
 *   binds the tap to the card's principal, consent_eval.rs:158-186, so board-human binds to the owner);
 *   a claims scope distinct from the parent (fixture error: the record inherits the root's scope at every
 *   birth, and the per-project memory scope is the project id itself, see the report).
 * DEFECT (red since E2E job 12b, Thu 12 Nov 2026; FIX row GOAL-INTAKE-NEVER-DISPATCHED): the person's confirm
 *   mints the project (200), but the leader's goal-intake run is never dispatched, so the
 *   coordination01-intake barrier is never consumed. Vault::confirm_project_card's dispatch_goal_intake
 *   (workspace_roster/project/proposal.rs) asks for the card's leader with no parent attempt and the new child
 *   project; project_depth_limit_in_txn refuses it before enqueue ("a project spawn requires a real parent in
 *   its ancestor project", agent_dispatch/dispatch/depth.rs), and the confirm only logs a warning. The earlier
 *   red at the house's source read (HOUSE-SOURCE-READ-DENIED) was fixed by #7028. Past the barrier (fix #7193)
 *   the next red is the project kind check, FIX 23490 (see the comment at the check).
 */
suite.test(test, "COORDINATION-01", "Project proposal requires acceptance: an agent's card mints nothing until its person confirms, and a dismissed card never mints", async () => {
  const scenario = await coordination01Scenario();
  const [sourceOne, sourceTwo] = scenario.inputs.conversation;
  if (!sourceOne || !sourceTwo) throw new Error("COORDINATION-01 needs two source messages");
  const providers = await ScriptedProviders.start({ id: "coordination-01-projects", origins: ["decider", "drafter"], steps: [] });
  const engine = await EngineFixture.start({ id: "COORDINATION-01", profile, serverConfig: coordination01Models(providers) });
  let failure: unknown;
  try {
    const client = engine.client;
    const owner = engine.pairedActor.principalRef;
    const skill = await coordination01InstallProjectProposal(engine);
    const leaderRef = coordination01InputId("COORDINATION-01:project-leader");
    const created = await client.call("vault.agents.create", { agent_def_ref: leaderRef,
      definition: { agent_id: "project-leader", display_name: "project-leader", desc: "COORDINATION-01 fixture project leader", version: "1" } });
    expect(created.agent_def_ref).toBe(leaderRef);
    expect((await coordination01Entity(client, leaderRef)).kind).toBe("AGENT_DEF");
    const leader = await engine.pairActor({ principalRef: leaderRef, actorClass: "agent" });
    expect((await leader.client.call("self.actor", {})).actor_ref).toBe(leaderRef);

    // Fixture labels bind to public setup results only. board-human is the owner: the tap must come
    // from the card's principal, which is the source message's author (proposal.rs:611-618).
    const bound = new Map<string, string>([["project-leader", leaderRef], ["board-human", owner], ["route-checklist-skill", skill]]);
    const bind = (label: string): string => {
      const value = bound.get(label);
      if (value === undefined) throw new Error(`Unbound COORDINATION-01 label ${label}`);
      return value;
    };
    const fixtureCard = scenario.inputs.card;
    const goal: Coordination01Goal = { goal: fixtureCard.goal.goal, why: fixtureCard.goal.why, axes: [...fixtureCard.goal.axes] };
    const picks: Coordination01Picks = { leader_agent_def_ref: bind(fixtureCard.leader), board_human_refs: fixtureCard.board.map(bind),
      budget_share_bps: fixtureCard.budget_share_bps, starting_skill_refs: fixtureCard.startingSkills.map(bind) };
    expect(picks.budget_share_bps).toBe(scenario.expected.budgetShareBps);

    const conversation = (await client.call("vault.conversations.create", {
      body: {}, occurred_start: COORDINATION01_AT, occurred_end: COORDINATION01_AT, learned_at: COORDINATION01_AT })).id;
    const roomsBefore = await client.call("vault.rooms.list", {});

    // Card one: the house drafts it on a typed YES. Its picks are compared with the fixture, not a re-read.
    const first = await coordination01HouseCard(engine, providers, conversation, sourceOne.content, "coordination01-card-1", goal, picks, 1);
    expect(first.card.card).toMatchObject({ card_id: "coordination01-card-1", principal_ref: owner, source_message_ref: first.message,
      goal: fixtureCard.goal, leader_agent_def_ref: bind(scenario.expected.leader),
      board_human_refs: scenario.expected.board.map(bind), budget_share_bps: scenario.expected.budgetShareBps,
      starting_skill_refs: [skill] });
    expect(first.card.card.source_thread_ref ?? null).toBeNull();
    // A detection YES is not consent: no card minted, no project home room born (projectsBeforeTap = 0).
    expect(coordination01Minted(first.cards)).toHaveLength(scenario.expected.projectsBeforeTap);
    expect(await client.call("vault.rooms.list", {})).toEqual(roomsBefore);

    // Refused: a person cannot author the agent's card, and an agent the house did not ask cannot forge one.
    await coordination01Refused(client.call("vault.projects.propose",
      { card_id: "coordination01-card-by-person", source_message_ref: first.message, goal, picks }),
      400, "BAD_REQUEST", "project card: only the drafting agent proposes a card");
    await coordination01Refused(leader.client.call("vault.projects.propose",
      { card_id: "coordination01-card-forged", source_message_ref: first.message, goal, picks }),
      400, "BAD_REQUEST", "project card: this agent was not asked to draft this card");
    expect((await client.call("vault.projects.proposals", { conversation_ref: conversation })).map(row => row.card.card_id))
      .toEqual(["coordination01-card-1"]);

    // Dismiss card one. It stays dismissed, and confirming it mints nothing (projectsAfterDismiss = 0).
    expect(await client.call("vault.projects.dismiss_card", { card_id: "coordination01-card-1" }))
      .toEqual({ card_id: "coordination01-card-1", dismissed: true });
    expect(await client.call("vault.projects.dismiss_card", { card_id: "coordination01-card-1" }))
      .toEqual({ card_id: "coordination01-card-1", dismissed: false });
    await coordination01Refused(client.call("vault.projects.confirm",
      { card_id: "coordination01-card-1", action_id: "mint_project", occurred_at: COORDINATION01_AT }),
      400, "BAD_REQUEST", "project card: a dismissed card never mints");
    const afterDismiss = await client.call("vault.projects.proposals", { conversation_ref: conversation });
    expect(afterDismiss.find(row => row.card.card_id === "coordination01-card-1")?.state).toBe("dismissed");
    expect(coordination01Minted(afterDismiss)).toHaveLength(scenario.expected.projectsAfterDismiss);
    expect(await client.call("vault.rooms.list", {})).toEqual(roomsBefore);

    // A NEW card on a new source message (a dismissed card no longer holds the conversation's question).
    const second = await coordination01HouseCard(engine, providers, conversation, sourceTwo.content, "coordination01-card-2", goal, picks, 2);
    expect(second.message).not.toBe(first.message);
    expect(second.card.card).toMatchObject({ card_id: "coordination01-card-2", principal_ref: owner, source_message_ref: second.message,
      goal: fixtureCard.goal, leader_agent_def_ref: leaderRef, board_human_refs: [owner],
      budget_share_bps: scenario.expected.budgetShareBps, starting_skill_refs: [skill] });
    // The agent that would lead the project can neither confirm nor dismiss its person's card.
    await coordination01Refused(leader.client.call("vault.projects.confirm",
      { card_id: "coordination01-card-2", action_id: "mint_project", occurred_at: COORDINATION01_AT }),
      403, "FORBIDDEN", "vault.projects.confirm is the vault owner's");
    await coordination01Refused(leader.client.call("vault.projects.dismiss_card", { card_id: "coordination01-card-2" }),
      400, "BAD_REQUEST", "project card: only the card's person dismisses it");
    const beforeTap = await client.call("vault.projects.proposals", { conversation_ref: conversation });
    expect(beforeTap.find(row => row.card.card_id === "coordination01-card-2")?.state).toBe("proposed");
    expect(coordination01Minted(beforeTap)).toHaveLength(0);
    expect(await client.call("vault.rooms.list", {})).toEqual(roomsBefore);

    // Until the tap, the models answered exactly two project questions and two house drafts.
    expect(coordination01Answered(providers, "decider")).toEqual(["coordination01-yes-1", "coordination01-yes-2"]);
    expect(coordination01Answered(providers, "drafter")).toEqual(["coordination01-draft-1", "coordination01-draft-2"]);

    // The person's one tap. The minted leader's goal-intake run (proposal.rs:536-578) is answered by ONE
    // ordinary FIFO step, never a standing responder: any further drafter request is unscripted and
    // fails providers.close(), and a missing intake run fails its barrier.
    providers.enqueue({ id: "coordination01-intake", origin: "drafter", role: "generative_reasoner", purpose: "leader goal intake",
      request: COORDINATION01_DRAFT, barrier: "coordination01-intake",
      response: openaiStream("coordination01-intake", "project-drafter", [`finish("goal intake waits for the owner");`],
        { inputTokens: 512, outputTokens: 16 }) });
    const minted = await client.call("vault.projects.confirm",
      { card_id: "coordination01-card-2", action_id: "mint_project", occurred_at: COORDINATION01_AT });
    expect(minted.card_id).toBe("coordination01-card-2");
    expect(minted.project_id).toMatch(/^[a-f0-9]{32}$/);
    expect(minted.grant_ref.length).toBeGreaterThan(0);
    await providers.awaitBarrier("coordination01-intake");
    providers.releaseBarrier("coordination01-intake");
    expect(coordination01Answered(providers, "drafter"))
      .toEqual(["coordination01-draft-1", "coordination01-draft-2", "coordination01-intake"]);

    const project = await coordination01Entity(client, minted.project_id);
    // DEFECT (expected red here once #7193 lands, Thu 12 Nov 2026; FIX 23490
    // [PROJECT-KIND-READS-TYPE-103]): vault.get spells a minted project's kind
    // "TYPE_103", not "PROJECT". PROJECT is a product kind registered at run time,
    // and every read-back kind spelling consults only the static entity-type
    // registry. E2E-1's job 20 measured this same check on MEMORY-01/02/05/07/08
    // (fleet job 1112-130158-e1f6, log sha256 2110bc0f209a840f). The check stays.
    expect(project.kind).toBe("PROJECT");
    const body = coordination01ProjectBody(project);
    expect(body.role).toBe("project");
    expect(body.parents).toHaveLength(1);
    const parent = body.parents[0]!;
    expect(body.leader).toBe(leaderRef);
    expect(body.board).toEqual([owner]);
    expect([...body.roster].sort()).toEqual([leaderRef, owner].sort());
    expect(body.born_from).toBe(second.message);
    expect(body.goal_record).toEqual({ project_id: minted.project_id, ...fixtureCard.goal });
    expect(body.budget_share).toEqual({ project_id: minted.project_id, parent_id: parent, share_bps: scenario.expected.budgetShareBps });
    expect(body.skill_forks).toHaveLength(1);
    // Parent is the root: the parent has no PROJECT parent of its own, and the child belongs to it.
    const rootBody = coordination01ProjectBody(await coordination01Entity(client, parent));
    expect(rootBody.parents).toEqual([]);
    // Today's record: the child carries the root's claims_scope_ref (mint.rs:298-303). The fixture's
    // claimsScopeDistinctFromParent=true maps canon's per-project scope onto this field; see the report.
    expect(body.claims_scope_ref).toBe(rootBody.claims_scope_ref);
    const out = (await client.call("vault.neighbors", { entity_ref: minted.project_id, opts: { edge_kind: "belongs_to", limit: 100 } })).value
      .filter(hit => hit.direction === "out" && hit.kind === "PROJECT").map(hit => hit.record?.id);
    expect(out).toEqual([parent]);
    const rootOut = (await client.call("vault.neighbors", { entity_ref: parent, opts: { edge_kind: "belongs_to", limit: 100 } })).value
      .filter(hit => hit.direction === "out" && hit.kind === "PROJECT");
    expect(rootOut).toEqual([]);

    // Exactly one new project home room: a channel holding the admitted roster.
    const roomsAfter = await awaitPublic(() => client.call("vault.rooms.list", {}),
      rows => rows.length === roomsBefore.length + scenario.expected.newHomeRooms, { label: "minted project home room" });
    const born = roomsAfter.filter(row => !roomsBefore.some(old => old.id === row.id));
    expect(born).toHaveLength(scenario.expected.newProjectsAfterAcceptance);
    expect(born[0]?.id).toBe(body.home_room);
    expect(born[0]?.room).toMatchObject({ kind: "channel", project_id: minted.project_id, memberIds: body.roster,
      claims_scope_ref: body.claims_scope_ref });

    // The starting skill is a fork that keeps its ancestry.
    const fork = await coordination01Entity(client, body.skill_forks[0]!);
    expect(fork.kind).toBe("SKILL");
    expect((fork.body as { forkedFrom?: string } | null | undefined)?.forkedFrom).toBe(skill);

    const afterTap = await client.call("vault.projects.proposals", { conversation_ref: conversation });
    expect(afterTap.find(row => row.card.card_id === "coordination01-card-2")?.state).toEqual({ minted: { project: minted.project_id } });
    expect(afterTap.find(row => row.card.card_id === "coordination01-card-1")?.state).toBe("dismissed");

    // An exact replay of the tap returns the same project and grant; nothing new is born.
    const replay = await client.call("vault.projects.confirm",
      { card_id: "coordination01-card-2", action_id: "mint_project", occurred_at: COORDINATION01_AT });
    expect(replay).toEqual(minted);
    const roomsReplay = await client.call("vault.rooms.list", {});
    expect(roomsReplay.length - roomsAfter.length).toBe(scenario.expected.confirmReplayAddsProjects);
    expect(roomsReplay).toEqual(roomsAfter);
    expect(await client.call("vault.projects.proposals", { conversation_ref: conversation })).toEqual(afterTap);
    // The replay ran nothing: no further question, draft or intake reached a model.
    expect(coordination01Answered(providers, "decider")).toEqual(["coordination01-yes-1", "coordination01-yes-2"]);
    expect(coordination01Answered(providers, "drafter"))
      .toEqual(["coordination01-draft-1", "coordination01-draft-2", "coordination01-intake"]);
  } catch (error) {
    failure = error;
    throw error;
  } finally {
    const errors: string[] = [];
    try { await engine.close(); } catch (error) { errors.push(error instanceof Error ? error.message : String(error)); }
    try { await providers.close(); } catch (error) { errors.push(error instanceof Error ? error.message : String(error)); }
    // A close error never replaces the flow's own failure (it would hide, for example, which barrier
    // timed out); it is appended to it, and thrown alone only when the flow itself passed.
    if (errors.length && failure instanceof Error) failure.message += `; COORDINATION-01 close: ${errors.join("; ")}`;
    else if (errors.length && failure === undefined) throw new Error(`COORDINATION-01 close: ${errors.join("; ")}`);
  }
});

interface Coordination02Scenario {
  id: "COORDINATION-02";
  inputs: {
    trunk: { label: string; content: string }[];
    branch: { label: string; parent: string; content: string; message?: string }[];
  };
  expected: { headBeforeAndAfterReply: string; mainLine: string[]; branchReplies: string[] };
}
/** DagPageResponse / DagThreadResponse / DagAppendResponse (api/conversation_dag/types.rs:214-252,315-321). */
interface Coordination02Page { head?: string | null; root?: string | null; main_line: string[]; page: { next?: string | null } }
interface Coordination02Thread { roots: string[]; root?: string | null; replies: string[]; count: number; last_at?: number | null }
interface Coordination02Reply { id: string; head?: string | null; parent?: string | null }
type Coordination02Entity = NonNullable<FacadeResult<"vault.get">["value"]>;
const COORDINATION02_AT = 1769947200; // Public setup input, never an engine clock override.

async function coordination02Scenario(): Promise<Coordination02Scenario> {
  const data = await (await loadFixtures()).readJson<{ scenarios: { id: string }[] }>("coordination-scenarios");
  const row = data.scenarios.find(row => row.id === "COORDINATION-02");
  if (!row) throw new Error("coordination-scenarios has no COORDINATION-02");
  return row as Coordination02Scenario; // Fixture discriminant, not an invented wire DTO.
}
/** The trunk read one record per page, every page drained: each page must name the same HEAD. */
async function coordination02MainLine(client: PublicHttpClient, conversation: string): Promise<{ heads: (string | null)[]; root: string | null; mainLine: string[] }> {
  const heads: (string | null)[] = [];
  const mainLine: string[] = [];
  let root: string | null = null;
  let after: string | null = null;
  for (let pages = 0; pages < 50; pages++) {
    const query: string = after === null ? "limit=1" : `limit=1&after=${after}`;
    const reply = await client.request<Coordination02Page>("GET", `/v1/core/conversations/${conversation}/records?${query}`);
    heads.push(reply.body.head ?? null);
    root = reply.body.root ?? null;
    mainLine.push(...reply.body.main_line);
    after = reply.body.page.next ?? null;
    if (after === null) return { heads, root, mainLine };
  }
  throw new Error("COORDINATION-02 main line did not end within 50 pages");
}
async function coordination02Thread(client: PublicHttpClient, conversation: string, trunk: string): Promise<Coordination02Thread> {
  return (await client.request<Coordination02Thread>("GET", `/v1/core/conversations/${conversation}/records/${trunk}/thread`)).body;
}
function coordination02ReplyBody(actor: string, actorClass: "human" | "agent", txt: string, advance = false) {
  return { advance, body: { txt }, actor: { entity_ref: actor, actor_class: actorClass } };
}
async function coordination02Entity(client: PublicHttpClient, entity_ref: string): Promise<Coordination02Entity> {
  const result = await client.call("vault.get", { entity_ref });
  if (!result.value) throw new Error(`Public entity missing: ${entity_ref}`);
  return result.value;
}
/** A refused public request: HTTP status, engine code, and the engine's own words. */
async function coordination02Refused(call: Promise<unknown>, status: number, code: string, words: string): Promise<PublicHttpError> {
  let refusal: PublicHttpError | undefined;
  try { await call; } catch (error) {
    if (!(error instanceof PublicHttpError)) throw error;
    refusal = error;
  }
  if (!refusal) throw new Error(`Expected HTTP ${status} ${code}; the request succeeded`);
  expect(refusal.reply.status).toBe(status);
  expect(refusal.error?.code).toBe(code);
  expect(refusal.reply.raw).toContain(words);
  return refusal;
}

/** Diagnostic: a refused call fails with the engine's wire code and message first (PublicHttpError says only
 * "HTTP <status>", and the fleet log keeps the first 400 characters of a failure reason). */
async function withWireReason<T>(label: string, call: Promise<T>): Promise<T> {
  try { return await call; } catch (error) {
    if (error instanceof PublicHttpError) {
      throw new Error(`${label}: HTTP ${error.reply.status} ${error.error?.code ?? "no-code"}: ${(error.error?.message ?? "").slice(0, 300)}`);
    }
    throw error;
  }
}

/* COORDINATION-02 promise: a reply in a thread never moves the conversation's trunk HEAD, and every
 *   original trunk and reply record keeps its id; a forged byline and a HEAD-advancing thread reply are
 *   refused, and the shape survives a restart.
 * Doors: typed vault.conversations.create / vault.conversations.records.append / vault.agents.create /
 *   vault.get; existing HTTP POST|GET /v1/core/conversations/{id}/records[/{trunk}/thread]; engine.restart().
 * Unproved: the conversion half of the title (born_from = the card's MESSAGE, origin_room/origin_thread,
 *   converted_project backlink, the SAME TASK moving, linked not copied history, replay idempotence) and
 *   that this happens in a PROJECT home room. Conversion needs a minted parent project with a roster the
 *   thread TASK can be seated in, a house-drafted thread card and two goal-intake runs in one 30 s flow;
 *   roster seating for an open thread TASK has no public typed setup door (room_thread.rs:96-127,
 *   join_door.rs:124-143). This case runs on an ordinary conversation, which stages no project question.
 */
suite.test(test, "COORDINATION-02", "A thread reply never moves the trunk HEAD and every original record keeps its id", async () => {
  const scenario = await coordination02Scenario();
  const engine = await EngineFixture.start({ id: "COORDINATION-02", profile });
  const client = engine.client;
  const owner = engine.pairedActor.principalRef;
  const ids = new Map<string, string>();
  const id = (label: string): string => {
    const value = ids.get(label);
    if (value === undefined) throw new Error(`Unbound COORDINATION-02 label ${label}`);
    return value;
  };
  const content = new Map<string, string>();

  // Guards a fixed defect: before #6997 every DAG append was labelled Generated whoever wrote it, so on a
  // default vault no person, the owner included, could append a trunk record or a thread reply (403
  // "gate.pending.source_trust" at the first trunk append). #6997 labels an append by who composed its words.
  // The owner already holds the room's Owner role without a seat (conversation/roles.rs:33-44).
  const conversation = (await client.call("vault.conversations.create", {
    body: {}, occurred_start: COORDINATION02_AT, occurred_end: COORDINATION02_AT, learned_at: COORDINATION02_AT })).id;
  // Trunk: each record advances HEAD (records.append bylines the caller; no witness, so no project question).
  let previous: string | null = null;
  for (const row of scenario.inputs.trunk) {
    const appended: FacadeResult<"vault.conversations.records.append"> = await withWireReason("COORDINATION-02 trunk append",
      client.call("vault.conversations.records.append", {
        conversation, parent: previous, advance: true, body: { txt: row.content, speaker: "user", at: COORDINATION02_AT },
        occurred_start: COORDINATION02_AT, occurred_end: COORDINATION02_AT, learned_at: COORDINATION02_AT }));
    expect(appended.head).toBe(appended.id);
    expect(appended.parent ?? null).toBe(previous);
    ids.set(row.label, appended.id);
    content.set(row.label, row.content);
    previous = appended.id;
  }
  const head = id(scenario.expected.headBeforeAndAfterReply);
  const mainLine = scenario.expected.mainLine.map(id);
  const before = await coordination02MainLine(client, conversation);
  expect(before.mainLine).toEqual(mainLine);
  expect(before.heads.every(value => value === head)).toBe(true);
  expect(before.root).toBe(mainLine[0] ?? null);

  // The branch: the thread opens under its trunk parent; the next reply continues the same thread.
  const threadRoot = scenario.inputs.branch.find(row => ids.has(row.parent));
  if (!threadRoot) throw new Error("COORDINATION-02 branch has no root on the trunk");
  const anchor = id(threadRoot.parent);
  const threadPath = `/v1/core/conversations/${conversation}/records/${anchor}/thread`;
  for (const row of scenario.inputs.branch) {
    const parent = id(row.parent);
    const reply = await client.request<Coordination02Reply>("POST", threadPath, coordination02ReplyBody(owner, "human", row.content));
    expect(reply.body.head).toBe(head);
    expect(reply.body.parent).toBe(parent);
    ids.set(row.label, reply.body.id);
    content.set(row.label, row.content);
  }
  const replies = scenario.expected.branchReplies.map(id);

  // Refused: a thread reply asking to advance HEAD, and a reply bylined to another principal.
  await coordination02Refused(client.request("POST", threadPath, coordination02ReplyBody(owner, "human", "Move HEAD here.", true)),
    400, "BAD_REQUEST", "thread replies select their own parent and do not advance HEAD");
  const otherRef = createHash("sha256").update("coordination-e2e:COORDINATION-02:worker-a").digest("hex").slice(0, 32);
  const other = await client.call("vault.agents.create", { agent_def_ref: otherRef,
    definition: { agent_id: "worker-a", display_name: "worker-a", desc: "COORDINATION-02 named author", version: "1" } });
  expect(other.agent_def_ref).toBe(otherRef);
  await coordination02Refused(client.request("POST", threadPath, coordination02ReplyBody(otherRef, "agent", "Signed as someone else.")),
    403, "FORBIDDEN", "actor_binding");

  const check = async (stage: string): Promise<void> => {
    const after = await coordination02MainLine(client, conversation);
    expect({ stage, mainLine: after.mainLine }).toEqual({ stage, mainLine });
    expect({ stage, heads: after.heads.every(value => value === head) }).toEqual({ stage, heads: true });
    const thread = await coordination02Thread(client, conversation, anchor);
    expect({ stage, roots: thread.roots, root: thread.root ?? null, replies: thread.replies, count: thread.count })
      .toEqual({ stage, roots: [replies[0]!], root: replies[0]!, replies, count: replies.length });
    for (const [label, record] of ids) {
      const entity = await coordination02Entity(client, record);
      expect({ stage, label, id: entity.id_hex, kind: entity.kind }).toEqual({ stage, label, id: record, kind: "TURN" });
      expect(entity.body).toMatchObject({ txt: content.get(label)! });
    }
  };
  await check("after replies");
  await engine.restart();
  await check("after restart");
  await engine.close();
});

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
interface Coordination03Scenario {
  id: "COORDINATION-03";
  inputs: { offer: { what: string; artifact: string } };
  expected: { offerTurnsBeforeAcceptance: number; cardsPerAgentPerBranch: number; acceptedTurns: number; replayAddsTurns: number };
}
type Coordination03Participant = FacadeResult<"vault.rooms.participants">["rows"][number];
interface Coordination03Room { turns: string[]; participants: Coordination03Participant[] }
const COORDINATION03_AT = 1769947200; // Public setup input, never an engine clock override.
const COORDINATION03_ADMISSION = "only the room's owner, a delegated host or its nearest project leader answers its admission";
const COORDINATION03_EDGE_LIMIT = 200;

async function coordination03Scenario(): Promise<Coordination03Scenario> {
  const data = await (await loadFixtures()).readJson<{ scenarios: { id: string }[] }>("coordination-scenarios");
  const row = data.scenarios.find(row => row.id === "COORDINATION-03");
  if (!row) throw new Error("coordination-scenarios has no COORDINATION-03");
  return row as Coordination03Scenario; // Fixture discriminant, not an invented wire DTO.
}
function coordination03InputId(label: string): string {
  return createHash("sha256").update(`coordination-e2e:${label}`).digest("hex").slice(0, 32);
}
async function coordination03Refused(call: Promise<unknown>, status: number, code: string, reason: string): Promise<void> {
  let refusal: PublicHttpError | undefined;
  try { await call; } catch (error) {
    if (!(error instanceof PublicHttpError)) throw error;
    refusal = error;
  }
  if (!refusal) throw new Error(`Expected HTTP ${status} ${code} (${reason}); the call succeeded`);
  expect(refusal.reply.status).toBe(status);
  expect(refusal.error?.code).toBe(code);
  expect(refusal.error?.message ?? "").toContain(reason);
}
/** The records of `kind` that point at `entity` by an `edge_kind` edge, through the public neighbourhood
 * read (for an in-edge the hit's record is the peer, claim/scoped_read/edge_admission.rs:186-199). */
async function coordination03Pointing(client: PublicHttpClient, entity: string, edge_kind: string, kind: string): Promise<string[]> {
  const hits = (await client.call("vault.neighbors", { entity_ref: entity, opts: { edge_kind, limit: COORDINATION03_EDGE_LIMIT } })).value;
  expect(hits.length).toBeLessThan(COORDINATION03_EDGE_LIMIT); // The read is complete, not a truncated window.
  return hits.filter(hit => hit.direction === "in" && hit.kind === kind).map(hit => {
    if (!hit.record) throw new Error(`${kind} neighbour of ${entity} has no record ref`);
    return hit.record.id;
  }).sort();
}
/** What the room holds, read through public doors: every TURN witnessed into it (each TURN's one
 * ChildOf edge, memory/witness/base.rs:526), and every participant page, drained. A plain room keeps
 * no RoomTurn row (rooms/witness.rs:195-263), so vault.rooms.messages lists none of its turns. */
async function coordination03Room(client: PublicHttpClient, room: string): Promise<Coordination03Room> {
  const turns = await coordination03Pointing(client, room, "child_of", "TURN");
  const participants: Coordination03Participant[] = [];
  let after: string | null = null;
  for (let pages = 0; pages < 50; pages++) {
    const page: FacadeResult<"vault.rooms.participants"> =
      await client.call("vault.rooms.participants", { room, branch: null, after });
    participants.push(...page.rows);
    after = page.next_after ?? null;
    if (after === null) return { turns, participants };
  }
  throw new Error("COORDINATION-03 participants did not end within 50 pages");
}

/* COORDINATION-03 promise: an agent asks to join a room by an offer card, never a turn; only the room's
 *   host admits it, the agent itself and an unrelated agent cannot, and the accepted join lands once.
 * Doors: typed HTTP facade vault.conversations.create / vault.agents.create / vault.rooms.offer /
 *   vault.rooms.offers / vault.rooms.consent / vault.rooms.offer.answer / vault.rooms.participants /
 *   vault.neighbors / vault.get; pairActor for both agents.
 * DEFECT (red since E2E job 12b, Thu 12 Nov 2026; FIX row ROOM-OFFER-PAIRED-AGENT-UNBOUND): the agent's first
 *   vault.rooms.offer gets 403. rooms_offer mints through rooms_join_in_txn, which checks
 *   verify_write_actor_in_txn (workspace_roster/join_door.rs) before the principal admission; an AGENT_DEF made
 *   by vault.agents.create and paired by slip has no active authority binding, so the write is refused "writer
 *   has no active authority binding". Neither agent-create nor slip redeem installs a binding, and no public door
 *   does. The earlier 400 (a custom agent read as a person's pen, AGENT-PERSON-ANCHOR-ROOM-OFFER) was fixed by
 *   #6978.
 * Unproved: thread cards and the human "wrote" cause (vault.rooms.speak threads need a project home room,
 *   rooms/mod.rs:185-201); mention and TASK causes (no public bind door); paid offers and payer consent;
 *   companion membership; nearest-leader hosting and Dreamer never hosting; not_now's diary record.
 */
suite.test(test, "COORDINATION-03", "An agent joins a room only through an offer card that the room's host accepts, and the accepted join lands once", async () => {
  const scenario = await coordination03Scenario();
  const engine = await EngineFixture.start({ id: "COORDINATION-03", profile, serverConfig: "[models.dreamer]\nenabled = false\n" });
  try {
    const client = engine.client;
    const owner = engine.pairedActor.principalRef;
    const room = (await client.call("vault.conversations.create", {
      body: { v: 1, kind: "group", member_ids: [owner], title: "COORDINATION-03 visitor route" },
      occurred_start: COORDINATION03_AT, occurred_end: COORDINATION03_AT, learned_at: COORDINATION03_AT })).id;
    const agents = new Map<string, string>();
    for (const label of ["companion", "worker-a"]) {
      const ref = coordination03InputId(`COORDINATION-03:${label}`);
      const created = await client.call("vault.agents.create", { agent_def_ref: ref,
        definition: { agent_id: label, display_name: label, desc: `COORDINATION-03 ${label}`, version: "1" } });
      expect(created.agent_def_ref).toBe(ref);
      agents.set(label, ref);
    }
    const companionRef = agents.get("companion")!;
    const companion = await engine.pairActor({ principalRef: companionRef, actorClass: "agent" });
    const unrelated = await engine.pairActor({ principalRef: agents.get("worker-a")!, actorClass: "agent" });
    expect(await client.call("vault.rooms.offers", { room })).toMatchObject({ rows: [] });
    const before = await coordination03Room(client, room);
    expect(before.participants.some(row => row.subject.id === companionRef)).toBe(false);

    // The agent's ask is a card: it waits on the host's admission and carries no turn.
    const draft: FacadeInput<"vault.rooms.offer"> = { room, branch: null, agent: companionRef,
      what: scenario.inputs.offer.what, artifact_ref: scenario.inputs.offer.artifact, intent_key: "coordination03-offer-1" };
    const card = await companion.client.call("vault.rooms.offer", draft);
    expect(card.offer_id).toMatch(/^[a-f0-9]{64}$/);
    expect(card).toMatchObject({ room, agent: companionRef, what: scenario.inputs.offer.what, artifact_ref: scenario.inputs.offer.artifact });
    expect(card.state).toEqual({ kind: "open", needs: [{ part: "admission", party: { room_host: { room } } }] });
    const listed = await client.call("vault.rooms.offers", { room });
    expect(listed.rows.filter(row => row.agent === companionRef)).toHaveLength(scenario.expected.cardsPerAgentPerBranch);
    expect(listed.rows[0]?.offer_id).toBe(card.offer_id);
    const offered = await coordination03Room(client, room);
    expect(offered.turns.length - before.turns.length).toBe(scenario.expected.offerTurnsBeforeAcceptance);
    expect(offered).toEqual(before);

    // Refused: the agent cannot admit itself, and an unrelated agent cannot answer the host's part.
    await coordination03Refused(companion.client.call("vault.rooms.offer.answer",
      { offer_id: card.offer_id, action: "join", intent_key: "coordination03-self-admit" }), 403, "FORBIDDEN", COORDINATION03_ADMISSION);
    await coordination03Refused(unrelated.client.call("vault.rooms.consent",
      { join_ref: card.join_ref, part: "admission", grant: true }), 403, "FORBIDDEN", COORDINATION03_ADMISSION);
    // With the host's consent still missing nothing is admitted: the card is open, no turn, no participant.
    const stillOpen = await client.call("vault.rooms.offers", { room });
    expect(stillOpen.rows.find(row => row.offer_id === card.offer_id)?.state).toEqual(card.state);
    expect(await coordination03Room(client, room)).toEqual(before);

    // The room's host accepts: exactly one turn, bylined to the agent, carrying the offer and its join receipt.
    const accepted = await client.call("vault.rooms.offer.answer",
      { offer_id: card.offer_id, action: "join", intent_key: "coordination03-answer-1" });
    expect(accepted.offer_id).toBe(card.offer_id);
    if (accepted.state.kind !== "joined") throw new Error(`Offer not joined: ${JSON.stringify(accepted.state)}`);
    const turnRef = accepted.state.turn;
    const receiptRef = accepted.state.receipt_ref;
    expect(accepted.turn_ref).toBe(turnRef);
    expect(receiptRef.length).toBeGreaterThan(0);
    expect(accepted.join?.decision.state).toBe("ready");
    const joined = await coordination03Room(client, room);
    expect(joined.turns.length - before.turns.length).toBe(scenario.expected.acceptedTurns);
    expect(joined.turns).toEqual([...before.turns, turnRef].sort());
    const turn = (await client.call("vault.get", { entity_ref: turnRef })).value;
    expect(turn?.kind).toBe("TURN");
    expect(turn?.body).toMatchObject({ actor: companionRef }); // The author stamp of an agent writer (witness/codec.rs:141-149).
    const messages = await coordination03Pointing(client, turnRef, "part_of", "MESSAGE");
    expect(messages).toHaveLength(1);
    const message = (await client.call("vault.get", { entity_ref: messages[0]! })).value;
    expect(message?.body).toMatchObject({ metadata: { room_offer: card.offer_id, room_join_receipt: receiptRef } });
    // The one new participant is the agent, by its offer, eligible now on the same join receipt.
    const newcomers = joined.participants.filter(row => !before.participants.some(old => old.subject.id === row.subject.id));
    expect(newcomers).toHaveLength(1);
    expect(newcomers[0]?.subject).toEqual({ kind: "agent", id: companionRef });
    expect(newcomers[0]?.causes).toContainEqual({ kind: "offer", offer_id: card.offer_id });
    expect(newcomers[0]?.currently_eligible).toBe(true);
    expect(newcomers[0]?.receipt_ref).toBe(receiptRef);
    expect(joined.participants.filter(row => row.subject.id !== companionRef)).toEqual(before.participants);

    // Exact replays land nothing new: the same answer and the same card.
    expect(await client.call("vault.rooms.offer.answer",
      { offer_id: card.offer_id, action: "join", intent_key: "coordination03-answer-1" })).toEqual(accepted);
    const answerReplay = await coordination03Room(client, room);
    expect(answerReplay.turns.length - joined.turns.length).toBe(scenario.expected.replayAddsTurns);
    expect(answerReplay).toEqual(joined);
    const replayed = await companion.client.call("vault.rooms.offer", draft);
    expect(replayed.offer_id).toBe(card.offer_id);
    expect(replayed.state).toEqual(accepted.state);
    const offerReplay = await coordination03Room(client, room);
    expect(offerReplay.turns.length - joined.turns.length).toBe(scenario.expected.replayAddsTurns);
    expect(offerReplay).toEqual(joined);
    const after = await client.call("vault.rooms.offers", { room });
    expect(after.rows.filter(row => row.agent === companionRef)).toHaveLength(scenario.expected.cardsPerAgentPerBranch);
    expect(after.rows.find(row => row.offer_id === card.offer_id)?.state).toEqual(accepted.state);
  } finally {
    await engine.close();
  }
});

/** COORDINATION-04 authored inputs (fixture discriminant, not a wire DTO). */
interface Coordination04Scenario {
  id: "COORDINATION-04";
  inputs: {
    parent: { leader: string; board: string[] };
    child: { leader: string };
    extraResource: { kind: string; key: string };
  };
  expected: {
    leaderSelfApprovalWidens: boolean;
    denialChangesAuthority: boolean;
    boardApprovalAddsOnlyRequestedSlice: boolean;
    widenReceiptNamesBoardActor: boolean;
  };
}
type Coordination04Status = Extract<Facade.TaskOutcome, { kind: "snapshot" }>;
type Coordination04Spawn = FacadeResult<"self.agents.spawn">;

const coordination04Model = "coord-agent";
function coordination04InputId(label: string): string {
  return createHash("sha256").update(`coordination-e2e:COORDINATION-04:${label}`).digest("hex").slice(0, 32);
}
async function coordination04Scenario(): Promise<Coordination04Scenario> {
  const data = await (await loadFixtures()).readJson<{ scenarios: { id: string }[] }>("coordination-scenarios");
  const row = data.scenarios.find(item => item.id === "COORDINATION-04");
  if (!row) throw new Error("Missing COORDINATION-04 fixture scenario");
  return row as Coordination04Scenario; // Fixture discriminant, not an invented wire DTO.
}
async function coordination04Agent(client: PublicHttpClient, label: string, ceiling?: "auto"): Promise<string> {
  const agent_def_ref = coordination04InputId(label);
  const created = await client.call("vault.agents.create", {
    agent_def_ref, definition: { agent_id: label, display_name: label, desc: `COORDINATION-04 ${label}`, version: "1", ...(ceiling === undefined ? {} : { ceiling }) },
  });
  expect(created.agent_def_ref).toBe(agent_def_ref);
  return agent_def_ref;
}
async function coordination04Status(client: PublicHttpClient, task_ref: string): Promise<Coordination04Status> {
  const described = await client.call("describe", { handle: { kind: "task", task_ref } });
  if (described.kind !== "task_status") throw new Error(`describe answered ${described.kind}, not task_status`);
  const outcome = described.receipt.outcome;
  if (outcome.kind !== "snapshot") throw new Error(`task status answered ${outcome.kind}, not a snapshot`);
  return outcome;
}
/** The layers a stored context spec names, read from the proposal view's public JSON. */
function coordination04Layers(spec: unknown): string[] {
  if (spec === null || typeof spec !== "object" || Array.isArray(spec)) throw new Error("Expected a public context spec object");
  const layers = (spec as { layers?: unknown }).layers;
  if (layers === undefined) return [];
  if (!Array.isArray(layers) || !layers.every(layer => typeof layer === "string")) throw new Error("Context spec layers are not strings");
  return layers as string[];
}
async function coordination04Proposal(client: PublicHttpClient, proposal_id: string): Promise<Facade.WidenProposalView> {
  const row = (await client.call("vault.widen_proposals", {})).proposals.find(item => item.proposal_id === proposal_id);
  if (!row) throw new Error(`Widen proposal ${proposal_id} is not listed`);
  return row;
}
/** A refused public call: its HTTP status, and the engine's own reason text. */
async function coordination04Refused(call: Promise<unknown>, reason: string, status?: number, code?: string): Promise<void> {
  let refusal: PublicHttpError | undefined;
  try { await call; } catch (error) {
    if (!(error instanceof PublicHttpError)) throw error;
    refusal = error;
  }
  if (!refusal) throw new Error(`Expected a refusal (${reason}); the call succeeded`);
  if (status === undefined) {
    expect(refusal.reply.status).toBeGreaterThanOrEqual(400);
    expect(refusal.reply.status).toBeLessThan(500);
  } else expect(refusal.reply.status).toBe(status);
  if (code !== undefined) expect(refusal.error?.code).toBe(code);
  expect(refusal.error?.message ?? "").toContain(reason);
}
function coordination04Step(providers: ScriptedProviders, id: string, purpose: string, program: string, barrier?: string): void {
  providers.enqueue({
    id, origin: "chat", role: "generative_reasoner", purpose,
    // The engine-native executor streams on a local-openai-compat provider (wire.rs:146-149).
    request: { method: "POST", path: "/v1/chat/completions", model: coordination04Model,
      fields: { stream: true, stream_options: { include_usage: true } } },
    response: openaiStream(id, coordination04Model, [program], { inputTokens: 256, outputTokens: 96 }),
    ...(barrier === undefined ? {} : { barrier }),
  });
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

/** The asking agent's ask authority, each part read back after the put: an actor-bound Auto ceiling, and a read
 * grant on TURN records. Ask admission checks that the asker can read the question it cites
 * (task_ask.rs validate_task_answer_unit), and the owner witnessed that TURN. That reader key carries no actor
 * class, so the grant names the exact actor_ref and no actor_class; it grants read only, on TURNs only. */
async function grantAgentAskAuthority(owner: PublicHttpClient, agentRef: string): Promise<void> {
  const before: FacadeResult<"vault.gate.policy.get"> = await owner.call("vault.gate.policy.get", {});
  const manifest = before.manifests.find(row => row.manifest_ref === before.default_manifest_ref);
  if (!manifest) throw new Error("Default policy manifest is absent");
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

/* COORDINATION-04 (partial, Engine E2E-PARTIAL option A).
 * Promise: a leader's live run cannot widen its own slice. A spawn asking for more than the run
 *   holds is only a proposal (no child runs), the leader cannot approve it, the board's decline is
 *   final and survives a restart, and only the board's approval lands exactly the asked slice.
 * Doors: HTTP facade vault.agents.create, vault.conversations.create, vault.witness, vault.get,
 *   tasks.create, describe, vault.runs.branches.get, vault.runs.checkpoint, self.run.attach and
 *   self.agents.spawn (the leader's own paired credential), vault.widen_proposals / .approve /
 *   .decline; pairActor; engine.restart(). The leader's code-mode run parks on its own ask/wait
 *   (durable park keeps lease and live entry), driven by ScriptedProviders.
 * Mapping: the fixture's extra private bucket is the context layer named by its key; board-human is
 *   the vault owner (a root run has no board attempt: the root Owner answers, widen.rs:303-318).
 * Unproved: self.leader.split (one child leader, board holding the parent leader, same wrapper
 *   TASK, roster and budget 8 <= 24). It needs a run inside a project the agent leads with a
 *   wrapper TASK assigned to her; an owner-created TASK runs in the root project. See the report.
 * Unproved: parent narrowing clamping the child (no public door narrows a live run's slice), and
 *   driving the leader over MCP (HTTP facade only).
 */
suite.test(test, "COORDINATION-04", "A leader's live run cannot widen its own slice: a wider spawn is only a proposal, the leader cannot approve it, the board's decline is final across a restart, and only the board's approval lands exactly the asked slice", async () => {
  const c = await coordination04Scenario();
  const extra = c.inputs.extraResource.key;
  const providers = await ScriptedProviders.start({ id: "coordination04-runs", origins: ["chat"], steps: [] });
  const engine = await EngineFixture.start({ id: "COORDINATION-04", profile, serverLog: "oneiron=info", serverConfig: `
[models.providers.coord04chat]
kind = "local-openai-compat"
base_url = "${providers.urls.chat}"
revision = "coordination-v1"
[models.roles.generative_reasoner]
model = "coord04chat:${coordination04Model}"
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
    // board-human binds to the owner, as in COORDINATION-01: the root board answers as the owner.
    expect(c.inputs.parent.board).toEqual(["board-human"]);
    const leaderRef = await coordination04Agent(owner, c.inputs.parent.leader, "auto");
    const workerRef = await coordination04Agent(owner, c.inputs.child.leader);
    const leader = await engine.pairActor({ principalRef: leaderRef, actorClass: "agent", scope: ["core:read", "core:write"] });
    expect((await leader.client.call("self.actor", {})).actor_ref).toBe(leaderRef);
    await grantAgentAskAuthority(owner, leaderRef);

    // The leader's run asks its owner a real question and parks on it (a durable wait).
    const occurred = 1769947200; // Public setup input, never an engine clock override.
    const conversation = await owner.call("vault.conversations.create", {
      body: {}, occurred_start: occurred, occurred_end: occurred, learned_at: occurred,
    });
    const witnessed = await owner.call("vault.witness", {
      conversation_ref: conversation.id, occurred_at: occurred,
      messages: [{ author: "user", message_type: "text", content: "Hold the route plan until I confirm.", is_visible: true, order: 0 }],
    });
    const turn = (await owner.call("vault.get", { entity_ref: witnessed.turn_short_id })).value;
    expect(turn?.kind).toBe("TURN");
    if (!turn) throw new Error("Question TURN is not readable");
    coordination04Step(providers, "coordination04-leader", "the leader's run asks its owner and parks", [
      `const asked = await ask({ intent_key: "coordination-04/leader/hold", who: { responder: { human: { actor_ref: "${ownerRef}" } } },`,
      `  what: { reference: { turn: "${turn.id_hex}" }, revision: 1, options: { proceed: { label: "Proceed" } }, context_refs: [] } });`,
      `await wait({ handle: asked.handle, step_key: "coordination-04/leader/hold" });`,
    ].join("\n"));
    const request = "Plan the public route with your workers.";
    const posted = await owner.call("tasks.create", {
      spec: { title: request }, label: "coordination-04-leader", assignee: { agent_def: { agent_def_ref: leaderRef } },
      intent_key: "coordination-04/leader/post",
      brief: {
        schema: 1, type_ref: { node_id: coordination04InputId("task-type"), tree_version: 1 },
        objective: request, intent: { need: request, care: "light" },
        success: { question: "Did the leader plan the route inside its slice?",
          criteria: { yes_if_all: [{ text: "The plan used only the slice the board granted." }] } },
        settled: [],
        escalation: { to: { people: [ownerRef] }, triggers: [], default: "proceed", reversibility: "reversible_read" },
      },
    });
    expect(posted.effected).toBe(true);
    const route = posted.route;
    if (!route || !("AgentDispatch" in route)) throw new Error(`Leader TASK routed ${JSON.stringify(route)}`);
    const task = posted.task_ref;
    if (!task) throw new Error("Leader TASK has no task_ref");
    const branches = (await owner.call("vault.runs.branches.get", { task_ref: task })).branches;
    expect(branches).toHaveLength(1);
    const run = branches[0]!.branch;
    // Barrier: the run's one step is committed, so its provider exchange is over (no Busy guard).
    await awaitPublic(() => owner.call("vault.runs.checkpoint", { run_ref: run }),
      view => (view?.completed_steps ?? 0) >= 1, { label: "COORDINATION-04 leader run commits its asking step" });
    // The whole branch first, so a failure prints its last_error.
    const parkedBranch = (await owner.call("vault.runs.branches.get", { task_ref: task })).branches[0];
    await expectParkedBranchLeased(engine, "COORDINATION-04 after its asking step", parkedBranch);
    expect(parkedBranch?.state).toBe("Leased");
    expect((await coordination04Status(owner, task)).phase.phase).not.toBe("terminal");

    // The leader attaches to her own parked run under her own credential.
    const attached = await leader.client.call("self.run.attach", { run });
    expect(attached.live_run.startsWith(`lr1.${run}.`)).toBe(true);
    const spawnWide = (intent_key: string) => leader.client.call("self.agents.spawn", { live_run: attached.live_run, spec: {
      need: "Read the private route bucket for the plan.", prompt: "Summarise the private route constraints.",
      intent_key, agent: workerRef, context: { layers: [extra] } } });

    // ---- A spawn wider than the run's slice is only a proposal: no child attempt. ----
    const first: Coordination04Spawn = await spawnWide("coordination-04/widen/first");
    if (first.state !== "proposed_widen") throw new Error(`Wider spawn answered ${first.state}, not proposed_widen`);
    expect(first.kind).toBe("agent_spawn");
    const pending = await owner.call("vault.widen_proposals", { state: "pending" });
    expect(pending.proposals.map(row => row.proposal_id)).toEqual([first.proposal]);
    const asked = pending.proposals[0]!;
    expect(asked.parent_attempt).toBe(run);
    expect(asked.board_attempt ?? null).toBeNull();
    expect(asked.target_kind).toBe("agent");
    expect(coordination04Layers(asked.parent_context)).toEqual([]);
    expect(coordination04Layers(asked.requested_context)).toEqual([extra]);
    expect(coordination04Layers(asked.widened_parent_context)).toEqual([extra]);
    expect(asked.landed_attempt ?? null).toBeNull();

    // ---- Failure step: the leader cannot approve (or decline) her own widening. ----
    expect(c.expected.leaderSelfApprovalWidens).toBe(false);
    await coordination04Refused(leader.client.call("vault.widen_proposals.approve", { proposal_id: first.proposal }),
      "vault.widen_proposals.approve is the vault owner's", 403, "FORBIDDEN");
    await coordination04Refused(leader.client.call("vault.widen_proposals.decline", { proposal_id: first.proposal }),
      "vault.widen_proposals.decline is the vault owner's", 403, "FORBIDDEN");
    const afterSelf = await coordination04Proposal(owner, first.proposal);
    expect(afterSelf.state).toBe("pending");
    expect(afterSelf.landed_attempt ?? null).toBeNull();

    // ---- The board declines: nothing widens, and the decline is final. ----
    expect(c.expected.denialChangesAuthority).toBe(false);
    const declined = await owner.call("vault.widen_proposals.decline", { proposal_id: first.proposal });
    expect(declined.state).toBe("declined");
    expect(declined.landed_attempt ?? null).toBeNull();
    expect(c.expected.widenReceiptNamesBoardActor).toBe(true);
    expect(declined.declined_by).toBe(ownerRef);
    expect(typeof declined.declined_at).toBe("number");
    // The same request again does not reopen it, and a later approval cannot land it.
    await coordination04Refused(spawnWide("coordination-04/widen/first"), "widen proposal was declined");
    await coordination04Refused(owner.call("vault.widen_proposals.approve", { proposal_id: first.proposal }), "widen proposal was declined");
    expect((await coordination04Proposal(owner, first.proposal)).state).toBe("declined");

    // ---- Re-propose: the run's slice is unchanged by the decline. ----
    const second: Coordination04Spawn = await spawnWide("coordination-04/widen/second");
    if (second.state !== "proposed_widen") throw new Error(`Re-proposal answered ${second.state}, not proposed_widen`);
    expect(second.proposal).not.toBe(first.proposal);
    const reasked = await coordination04Proposal(owner, second.proposal);
    expect(reasked.state).toBe("pending");
    expect(reasked.parent_attempt).toBe(run);
    expect(reasked.parent_context).toEqual(asked.parent_context);
    expect(coordination04Layers(reasked.requested_context)).toEqual([extra]);

    // ---- Failure step: restart. The decline and the pending re-proposal are durable. ----
    await engine.restart();
    const afterRestart = await owner.call("vault.widen_proposals", {});
    const firstAfter = afterRestart.proposals.find(row => row.proposal_id === first.proposal);
    const secondAfter = afterRestart.proposals.find(row => row.proposal_id === second.proposal);
    expect(afterRestart.proposals).toHaveLength(2);
    expect(firstAfter?.state).toBe("declined");
    expect(firstAfter?.declined_by).toBe(ownerRef);
    expect(firstAfter?.declined_at).toBe(declined.declined_at);
    expect(secondAfter?.state).toBe("pending");
    expect(secondAfter?.landed_attempt ?? null).toBeNull();
    // The parked leader run kept its lease across the restart (the whole branch first: its last_error).
    const restartedBranch = (await owner.call("vault.runs.branches.get", { task_ref: task })).branches[0];
    await expectParkedBranchLeased(engine, "COORDINATION-04 after the restart", restartedBranch);
    expect(restartedBranch?.state).toBe("Leased");

    // ---- The board approves: exactly the asked slice lands, with one child. ----
    expect(c.expected.boardApprovalAddsOnlyRequestedSlice).toBe(true);
    // The landed child's own run asks the model once; its reply finishes it.
    coordination04Step(providers, "coordination04-child", "the approved child runs once",
      `finish("Private route constraints summarised.");`, "coordination04-child");
    const approved = await owner.call("vault.widen_proposals.approve", { proposal_id: second.proposal });
    expect(approved.state).toBe("approved");
    expect(approved.landed_attempt).toMatch(/^[a-f0-9]{32}$/);
    expect(approved.parent_context).toEqual(asked.parent_context);
    expect(coordination04Layers(approved.widened_parent_context)).toEqual([extra]);
    expect(approved.declined_by ?? null).toBeNull();
    await providers.awaitBarrier("coordination04-child");
    providers.releaseBarrier("coordination04-child");
    // The approval revived nothing else: the declined proposal stays declined.
    const final = await owner.call("vault.widen_proposals", {});
    expect(final.proposals.find(row => row.proposal_id === first.proposal)?.state).toBe("declined");
    expect(final.proposals.filter(row => row.state === "approved").map(row => row.proposal_id)).toEqual([second.proposal]);
  } finally {
    const errors: string[] = [];
    try { await engine.close(); } catch (error) { errors.push(error instanceof Error ? error.message : String(error)); }
    try { await providers.close(); } catch (error) { errors.push(error instanceof Error ? error.message : String(error)); }
    if (errors.length) throw new Error(`close: ${errors.join("; ")}`);
  }
});

/** COORDINATION-05 authored inputs (fixture discriminant, not a wire DTO). */
interface Coordination05Scenario {
  id: "COORDINATION-05";
  inputs: {
    brief: {
      objective: string;
      intent: { need: string; care: Facade.Care };
      success: { question: string; yes_if_all: { text: string }[]; no_if_any: { text: string }[] };
    };
    question: string;
    humanWord: { label: string; content: string };
    result: { label: string; content: string };
  };
  expected: {
    routeByAssignee: { agent_def: "AgentDispatch"; peer: "PeerSyncedOnly"; human: "HumanFollowup" };
    resultRefCount: number;
    resultText: string;
  };
}
type Coordination05Status = Extract<Facade.TaskOutcome, { kind: "snapshot" }>;
type Coordination05Phase = Facade.TaskPhase;

// Chosen public input ids, passed to their create doors before any read.
function coordination05InputId(label: string): string {
  return createHash("sha256").update(`coordination-e2e:COORDINATION-05:${label}`).digest("hex").slice(0, 32);
}
async function coordination05Scenario(): Promise<Coordination05Scenario> {
  const data = await (await loadFixtures()).readJson<{ scenarios: { id: string }[] }>("coordination-scenarios");
  const row = data.scenarios.find(item => item.id === "COORDINATION-05");
  if (!row) throw new Error("Missing COORDINATION-05 fixture scenario");
  return row as Coordination05Scenario; // Fixture discriminant, not an invented wire DTO.
}
/** The public refusal a call answered: status, code and message off the wire. */
async function coordination05Refusal(call: Promise<unknown>): Promise<{ status: number; code: string; message: string }> {
  try {
    await call;
  } catch (error) {
    if (!(error instanceof PublicHttpError)) throw error;
    const wire = error.error;
    if (!wire) throw new Error(`Refusal without a typed error envelope: HTTP ${error.reply.status}`);
    return { status: error.reply.status, code: wire.code, message: wire.message };
  }
  throw new Error("Expected a public refusal, got a success");
}
async function coordination05Status(client: PublicHttpClient, task_ref: string): Promise<Coordination05Status> {
  const described = await client.call("describe", { handle: { kind: "task", task_ref } });
  if (described.kind !== "task_status") throw new Error(`describe answered ${described.kind}, not task_status`);
  const outcome = described.receipt.outcome;
  if (outcome.kind !== "snapshot") throw new Error(`task status answered ${outcome.kind}, not a snapshot`);
  return outcome;
}
function coordination05Attempt(receipt: FacadeResult<"tasks.accept">): Facade.AttemptHandle {
  const outcome = receipt.outcome;
  if (outcome.kind !== "accepted" || !outcome.attempt) throw new Error(`accept answered ${outcome.kind} without an attempt`);
  return outcome.attempt;
}
function coordination05Reported(update: FacadeResult<"tasks.update">): { receipt: Facade.TaskCallReceipt; phase: Coordination05Phase } {
  const receipt = update.report;
  if (!receipt) throw new Error("tasks.update answered no report receipt");
  if (receipt.outcome.kind !== "reported") throw new Error(`report answered ${receipt.outcome.kind}, not reported`);
  return { receipt, phase: receipt.outcome.phase };
}

/* COORDINATION-05 (partial, Engine E2E-PARTIAL option A).
 * Promise: an agent-assigned TASK goes to the engine's runner and a peer-assigned TASK to its
 *   wire taker; a retryable failure keeps the same TASK behind a new attempt fence, the asked
 *   human's own answer resumes that work, and completion lands one result that replays and
 *   survives a restart.
 * Doors: HTTP facade only: vault.conversations.create, vault.witness, vault.get,
 *   vault.people.create, vault.agents.create, vault.gate.policy.get/put (owner read grant for
 *   the human, HOOKS-05 precedent), vault.claims.upsert/list, tasks.create/accept/update/answer,
 *   wait, describe; pairActor for the human and the agent; engine.restart().
 * Unproved: the human ASSIGNEE lane (HumanFollowup, follow-up metadata, zero realizing jobs, its
 *   own word completing it): tasks.create refuses an unreachable person and no public verb
 *   creates the counterparty contact resolve_native_human_route needs (FIX row).
 * Unproved: a foreign executor admitted through vault.federation.connect.* (the peer here is the
 *   owner, a same-vault wire taker; the PeerSyncedOnly route is identical, gate/task_assignee.rs).
 * Unproved: the local agent's own run asking and resuming (needs a scripted engine-native run);
 *   three fresh fixtures (one engine here, lanes keyed apart).
 */
suite.test(test, "COORDINATION-05", "An agent TASK goes to the runner and a peer TASK to its taker, a retried TASK keeps its identity behind a new fence, and the asked human's answer resumes it to one result that survives restart", async () => {
  const c = await coordination05Scenario();
  const engine = await EngineFixture.start({ id: "COORDINATION-05", profile });
  try {
    const owner = engine.client;
    const ownerRef = engine.pairedActor.principalRef;
    const occurred = 1769947200; // Public setup input, never an engine clock override.

    // ---- Public fixture roles: a distinct board human and the worker-a agent. ----
    const conversation = await owner.call("vault.conversations.create", {
      body: {}, occurred_start: occurred, occurred_end: occurred, learned_at: occurred,
    });
    const identity = await owner.call("vault.witness", {
      conversation_ref: conversation.id, occurred_at: occurred,
      messages: [{ author: "user", message_type: "text", content: "This distinct person is Board Human.",
        is_visible: true, order: 0 }],
    });
    const identityTurn = (await owner.call("vault.get", { entity_ref: identity.turn_short_id })).value;
    expect(identityTurn?.kind).toBe("TURN");
    if (!identityTurn) throw new Error("Identity evidence TURN is not readable");
    const person = await owner.call("vault.people.create", {
      identity: { name: "Board Human" }, identity_evidence_refs: [identityTurn.id_hex], occurred_at: occurred,
    });
    const boardHuman = person.person.id_hex;
    expect(boardHuman).not.toBe(ownerRef);
    const human = await engine.pairActor({ principalRef: boardHuman, actorClass: "human" });
    expect((await human.client.call("self.actor", {})).actor_ref).toBe(boardHuman);

    const workerA = coordination05InputId("worker-a");
    const createdAgent = await owner.call("vault.agents.create", {
      agent_def_ref: workerA,
      definition: { agent_id: "worker-a", display_name: "worker-a",
        desc: "COORDINATION-05 local assignee lane agent.", version: "1" },
    });
    expect(createdAgent.agent_def_ref).toBe(workerA);
    const agent = await engine.pairActor({ principalRef: workerA, actorClass: "agent" });
    const agentIdentity = await agent.client.call("self.actor", {});
    expect(agentIdentity.actor_ref).toBe(workerA);
    expect(agentIdentity.actor_class).toBe("agent");

    // The owner lets the board human read the asked fact and the answer it gives: one exact-actor
    // read grant through the public policy door (substrate behind a grant, never a seeded record).
    const policy = await owner.call("vault.gate.policy.get", {});
    const defaultManifest = policy.manifests.find(row => row.manifest_ref === policy.default_manifest_ref);
    if (!defaultManifest) throw new Error("Default policy manifest is absent");
    const humanRead: Facade.PolicyScopedGrantRow = {
      actor_ref: boardHuman, effector: "core:read",
      scope: { worlds: { kind: "all" }, facets: { kind: "all" }, bands: { kind: "all" },
        audience: { kind: "all" }, verbs: { kind: "some", values: ["read"] }, sensitivity: { kind: "all" } },
      receipt_required: false,
    };
    const granted = await owner.call("vault.gate.policy.put", {
      manifest_ref: defaultManifest.manifest_ref, expected_body_hash: defaultManifest.body_hash,
      manifest: { ...defaultManifest.manifest,
        scoped_grants: [...(defaultManifest.manifest.scoped_grants ?? []), humanRead] },
    });
    expect(granted.receipt_ref.length).toBeGreaterThan(0);

    // The question the work will ask and the result the human's word names: owner-authored claims.
    const scope = await ownerBaseClaimScope(owner, ownerRef);
    const questionRef = coordination05InputId("question");
    const resultRef = coordination05InputId("result");
    const questionClaim = await owner.call("vault.claims.upsert", {
      id: questionRef, predicate: "coordination.route_note_question", subject_ref: ownerRef,
      value: c.inputs.question, confidence: 1, source: "user_stated", scope, occurred_at: occurred,
    });
    expect(questionClaim.approval).toBe("auto");
    const resultClaim = await owner.call("vault.claims.upsert", {
      id: resultRef, predicate: "coordination.opening_time_result", subject_ref: ownerRef,
      value: c.inputs.result.content, confidence: 1, source: "user_stated", scope, occurred_at: occurred,
    });
    expect(resultClaim.approval).toBe("auto");
    for (const ref of [questionRef, resultRef]) {
      const row = (await owner.call("vault.get", { entity_ref: ref })).value;
      expect(row?.kind).toBe("CLAIM");
      expect(row?.id_hex).toBe(ref);
    }

    // One authored brief for every lane. Its type_ref names no tree node (an authored 32-hex id), so
    // the create places the TASK itself (highway_post.rs:249-263); no placement is asserted here.
    const brief: Facade.QueueTaskBrief = {
      schema: 1,
      type_ref: { node_id: coordination05InputId("task-type"), tree_version: 1 },
      objective: c.inputs.brief.objective,
      intent: { need: c.inputs.brief.intent.need, care: c.inputs.brief.intent.care },
      success: { question: c.inputs.brief.success.question,
        criteria: { yes_if_all: c.inputs.brief.success.yes_if_all, no_if_any: c.inputs.brief.success.no_if_any } },
      settled: [],
      escalation: { to: { people: [ownerRef] }, triggers: [], default: "proceed", reversibility: "reversible_read" },
    };
    const title = c.inputs.brief.objective;

    // ---- Agent assignee: the engine's runner realizes it; nobody takes it over the wire. ----
    const local = await owner.call("tasks.create", {
      spec: { title }, label: "coordination-05-local", assignee: { agent_def: { agent_def_ref: workerA } },
      intent_key: "coordination-05/local/post", brief,
    });
    expect(local.approval).toBe("auto");
    expect(local.effected).toBe(true);
    const localRoute = local.route;
    if (!localRoute) throw new Error("Agent TASK answered no route");
    expect(Object.keys(localRoute)).toEqual([c.expected.routeByAssignee.agent_def]);
    if (!("AgentDispatch" in localRoute)) throw new Error(`Agent assignee routed ${JSON.stringify(localRoute)}`);
    expect(localRoute.AgentDispatch.agent_def_ref).toBe(workerA);
    expect(localRoute.AgentDispatch.attempt_ref).toBeDefined();
    const localTask = local.task_ref;
    if (!localTask) throw new Error("Agent TASK has no task_ref");
    for (const taker of [agent.client, owner]) {
      const refusal = await coordination05Refusal(taker.call("tasks.accept", {
        task_ref: localTask, intent_key: "coordination-05/local/accept",
      }));
      expect(refusal.status).toBe(409);
      expect(refusal.code).toBe("INVALID_STATE");
      expect(refusal.message).toBe("the engine's runner takes this task; it is not addressed to an external taker");
    }

    // ---- Human assignee: today an unreachable person is refused, the whole create rolls back. ----
    const humanAssignee = await coordination05Refusal(owner.call("tasks.create", {
      spec: { title }, label: "coordination-05-human", assignee: { human: { actor_ref: boardHuman } },
      intent_key: "coordination-05/human/post", brief,
    }));
    expect(humanAssignee.status).toBe(409);
    expect(humanAssignee.code).toBe("INVALID_STATE");
    expect(humanAssignee.message).toBe("known person is not currently reachable through a native route");

    // ---- Peer assignee: a synced TASK its wire taker accepts; no local job is minted. ----
    const posted = await owner.call("tasks.create", {
      spec: { title }, label: "coordination-05-peer", assignee: { peer: { actor_ref: ownerRef } },
      intent_key: "coordination-05/peer/post", brief,
    });
    expect(posted.approval).toBe("auto");
    expect(posted.effected).toBe(true);
    expect(posted.route).toEqual({ [c.expected.routeByAssignee.peer]: { actor_ref: ownerRef } });
    const task = posted.task_ref;
    if (!task) throw new Error("Peer TASK has no task_ref");
    // Unrelated live work, to show the ask below blocks only its own TASK.
    const control = await owner.call("tasks.create", {
      spec: { title: `${title} (control)` }, label: "coordination-05-control",
      assignee: { peer: { actor_ref: ownerRef } }, intent_key: "coordination-05/control/post", brief,
    });
    const controlTask = control.task_ref;
    if (!controlTask) throw new Error("Control TASK has no task_ref");
    coordination05Attempt(await owner.call("tasks.accept", { task_ref: controlTask, intent_key: "coordination-05/control/accept" }));

    // Failure step: a human who is not the assignee cannot take the work.
    const intruder = await coordination05Refusal(human.client.call("tasks.accept", {
      task_ref: task, intent_key: "coordination-05/peer/accept-intruder",
    }));
    expect(intruder.status).toBe(404);
    expect(intruder.code).toBe("NOT_FOUND");

    const first = coordination05Attempt(await owner.call("tasks.accept", { task_ref: task, intent_key: "coordination-05/peer/accept-1" }));
    expect(first.task_ref).toBe(task);
    expect((await coordination05Status(owner, task)).phase.phase).toBe("working");

    // A retryable failure keeps the TASK's intent: it requeues, it does not complete or vanish.
    const failed = coordination05Reported(await owner.call("tasks.update", {
      task_ref: task, report_key: "coordination-05/peer/fail-1", attempt: first,
      report: { failed: { error: "route note not yet read", retryable: true } },
    }));
    expect(failed.phase.phase).toBe("queued");
    const requeued = await coordination05Status(owner, task);
    expect(requeued.task_ref).toBe(task);
    expect(requeued.phase.phase).toBe("queued");

    // Re-accepting the SAME TASK opens a new attempt behind a new fence.
    const second = coordination05Attempt(await owner.call("tasks.accept", { task_ref: task, intent_key: "coordination-05/peer/accept-2" }));
    expect(second.task_ref).toBe(task);
    expect(second.attempt_ref).not.toBe(first.attempt_ref);
    const stale = await owner.call("tasks.update", {
      task_ref: task, report_key: "coordination-05/peer/stale-1", attempt: first,
      report: { progress: { evidence_refs: [] } },
    });
    expect(stale.report?.outcome.kind).toBe("stale_fence");
    expect(stale.report?.receipt_ref ?? null).toBeNull();
    expect((await coordination05Status(owner, task)).phase.phase).toBe("working");

    // ---- The running work asks the human for the missing fact; the human answers as itself. ----
    const blocked = coordination05Reported(await owner.call("tasks.update", {
      task_ref: task, report_key: "coordination-05/peer/block-1", attempt: second,
      report: { blocked: { note: "The route note's opening time is needed.", ask: {
        intent_key: "coordination-05/peer/ask-1", who: { people: [boardHuman] },
        what: { reference: { claim: questionRef }, revision: 1, options: {}, context_refs: [] },
        need: { count: 1 }, decide: "first",
      } } },
    }));
    const askHandle = blocked.receipt.related.find(row => row.kind === "ask");
    if (!askHandle || askHandle.kind !== "ask") throw new Error("Blocked report opened no ask");
    const group = askHandle.group_ref;
    if (blocked.phase.phase !== "blocked") throw new Error(`Blocked report answered ${blocked.phase.phase}`);
    expect(blocked.phase.on).toContain(group);
    const waiting = await owner.call("wait", { handle: { group_ref: group }, step_key: "coordination-05/peer/wait-1" });
    if (!("Pending" in waiting)) throw new Error(`Unanswered ask did not wait: ${JSON.stringify(waiting)}`);
    expect(waiting.Pending.trap_ref.length).toBeGreaterThan(0);
    const blockedStatus = await coordination05Status(owner, task);
    expect(blockedStatus.phase.phase).toBe("blocked");
    expect(blockedStatus.asks.map(([handle]) => handle.group_ref)).toEqual([group]);

    const word = await human.client.call("tasks.answer", { handle: { group_ref: group }, word: { result_ref: resultRef } });
    expect(word.actor_ref).toBe(boardHuman);
    expect(word.result_ref).toBe(resultRef);
    expect(word.task_ref).not.toBe(task);
    expect(word.word_ref.length).toBeGreaterThan(0);
    const ready = await owner.call("wait", { handle: { group_ref: group }, step_key: "coordination-05/peer/wait-1" });
    if (!("Ready" in ready)) throw new Error(`Answered ask is not ready: ${JSON.stringify(ready)}`);
    expect(ready.Ready.coverage.met).toBe(true);
    expect(ready.Ready.coverage.responded).toEqual([boardHuman]);
    expect(ready.Ready.effect_authorization).toBe("not_evaluated_by_ask");
    const decision = ready.Ready.decision;
    if (typeof decision !== "object" || !("first" in decision)) throw new Error(`Ask decided ${JSON.stringify(decision)}`);
    expect(decision.first.actor_ref).toBe(boardHuman);
    expect(decision.first.result_ref).toBe(resultRef);
    expect(ready.Ready.evidence.map(row => [row.source, row.person_ref, row.word.result_ref]))
      .toEqual([["human", boardHuman, resultRef]]);
    // Unrelated work stayed live while this TASK waited.
    expect((await coordination05Status(owner, controlTask)).phase.phase).toBe("working");

    // The same attempt resumes and completes with the publicly written result.
    const resumed = coordination05Reported(await owner.call("tasks.update", {
      task_ref: task, report_key: "coordination-05/peer/progress-1", attempt: second,
      report: { progress: { evidence_refs: [] } },
    }));
    expect(resumed.phase.phase).toBe("working");
    const done: Facade.TaskUpdateRequest = {
      task_ref: task, report_key: "coordination-05/peer/done-1", attempt: second,
      report: { done: { result_ref: resultRef } },
    };
    const completed = coordination05Reported(await owner.call("tasks.update", done));
    expect(completed.phase).toEqual({ phase: "terminal", disposition: "completed" });
    expect(completed.receipt.lifecycle?.fields.result_ref).toBe(resultRef);
    const deliveredReceipt = completed.receipt.receipt_ref;
    if (!deliveredReceipt) throw new Error("Completion kept no receipt");
    // Replayed delivery with the same report key and fence: the same receipt, no second effect.
    const replay = await owner.call("tasks.update", done);
    expect(replay.report?.idempotent_replay).toBe(true);
    expect(replay.report?.receipt_ref).toBe(deliveredReceipt);
    expect((await coordination05Status(owner, task)).phase).toEqual({ phase: "terminal", disposition: "completed" });
    const results = (await owner.call("vault.claims.list", {
      subject_ref: ownerRef, predicate: "coordination.opening_time_result", limit: 10,
    })).value;
    expect(results.map(row => row.value)).toEqual([c.expected.resultText]);
    expect(results).toHaveLength(c.expected.resultRefCount);

    // ---- Failure step: restart. The completion and its one receipt are durable. ----
    await engine.restart();
    expect((await coordination05Status(owner, task)).phase).toEqual({ phase: "terminal", disposition: "completed" });
    const afterRestart = await owner.call("tasks.update", done);
    expect(afterRestart.report?.idempotent_replay).toBe(true);
    expect(afterRestart.report?.receipt_ref).toBe(deliveredReceipt);
    expect((await owner.call("vault.claims.list", {
      subject_ref: ownerRef, predicate: "coordination.opening_time_result", limit: 10,
    })).value.map(row => row.value)).toEqual([c.expected.resultText]);
  } finally {
    await engine.close();
  }
});

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
/* COORDINATION-07 — stays TODO (Engine E2E-PARTIAL option A).
 * Promise (planned): one placed task type drives the team plan: placement once with node and
 *   tree version, unsure lands on the root, every consumer (plan, launched team, seat route,
 *   critic, learning) carries the same stamp, pinned width/model are kept under the hard cap.
 * Doors that exist: vault.agents.spawn / vault.agents.spawn.get, vault.task_types.get/pin,
 *   vault.settings.learning.put (all owner HTTP facade).
 * Why no case: in a fresh vault the owner's spawn is refused before any plan. The live planner
 *   loads the team-shape skill first (agent_dispatch/planner_live/root_plan.rs:59-62, 93-97);
 *   bootstrap installs only skill-optimize, judge, goal-intake, wake and agent-health-review
 *   (skill_hub/bootstrap.rs:39-54), and team_shape_skill() is a namespace id with no record
 *   (agent_dispatch/team_shape.rs:30-35, 61-70). The reply is phase "refused", "entity not
 *   found", placed/plan null, so not even the placed stamp is public.
 * Why no case: vault.task_types.pin needs a team-shape fork and stores a candidate only
 *   (team/doors.rs:560-589, in_force from fork_in_force); no public door puts it in force, so
 *   the fixture's v7 tree cannot drive anything.
 * Why no case: seat routes need a vault model manifest the host config does not publish
 *   (team/door_reads.rs:527-551); critics need review artifacts; learning needs receipts.
 * Weak subsets rejected: candidate pin + learning-row writes are setup reads; the refused spawn
 *   is not the title's promise.
 */
suite.todo(test, "COORDINATION-07", "waits on a team-shape planner skill a fresh vault can hold and a public door that puts a pinned task-type tree in force (vault.agents.spawn refuses 'entity not found'; vault.task_types.pin stores a candidate only), plus seat-route, critic and learning typeRef producers");

/* COORDINATION-08 — Refusal dial and leadership chat should work.
 * The written journey is at commit 98bc38dd5ae (tests/e2e/coordination.test.ts). It proves the
 * refusal-dial subset: an agent's declared dial decides its own refusal of the TASK it runs (voice
 * objects once and proceeds, bond veto declines, the none and full ends apply from a live dial edit),
 * the record survives a restart, and the owner cannot refuse in her place on her live run.
 * Budget: it took 29.2 s and 29.9 s of the 30 s cap on a small fresh vault (fleet job 1112-203856-63fc)
 * and hit the cap in job 1112-214001-3cc1. Four facade calls take most of it: the owner's task-status
 * describe (about 1.66 s, polled three times), vault.receipts (2.84 s), vault.runs.checkpoint (1.69 s)
 * and GET /api/openapi.json (2.06 s); every other call answers in under 0.7 s. It keeps the 30 s cap and
 * sits on the nightly budget list (Engine ruling 21:03 Thu 12 Nov) until [SLOW-FACADE-CALLS-COORDINATION-08]
 * lands. Re-measure it on the first set holding the [AGENT-RUN-START-LATENCY-4S] fix, which may also
 * shorten it.
 * The restart's dial revert it found, [AGENT-DEF-DIAL-REVERTS-ON-RESTART], is fixed by #7285; the journey
 * has not yet run on a set holding that fix.
 * Unproved even then: the leadership-chat half (two same-vault project leaders talking, a public fact
 * crossing, a private fact withheld) and the agent's diary entry per recorded refusal.
 */
suite.todo(test, "COORDINATION-08", "waits on [SLOW-FACADE-CALLS-COORDINATION-08]: four facade calls of 1.7-2.8 s put the refusal-dial journey at the 30 s cap; nightly budget list (Refusal dial and leadership chat should work)");

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

// ---- MUSE-LOOP-01 (Muse Wonder Full, ported 10 Nov) ----
/*
 * MUSE-LOOP-01 (PARTIAL) — promises P-LOOP-001 and P-LOOP-002, plus the
 * approve/reject half of the working title. Doors used: vault.claims.upsert,
 * vault.commit, vault.writes.pending (canon pendingWrites(limit)),
 * vault.claims.review, vault.claims.settle, vault.claims.list,
 * vault.claims.history, vault.receipts, vault.receipts.get and
 * vault.authority.audit.
 *
 * Unproved and not faked here:
 * - P-LOOP-003 push to subscribers: the typed facade has no
 *   subscribe(scopedView)/unsubscribe verb and no named receipts or
 *   pending-consent channel payload. Canon names sub.open only abstractly,
 *   so a guessed WS payload would not be a typed door.
 * - P-LOOP-004 amended receipt: ClaimSettleRequest accepts only
 *   approve/reject and carries no amended/final claim. The separate
 *   vault.skills.attribution.settle/read delta does not settle a pending
 *   claim or link that claim's proposal, so it is not used as a substitute.
 *
 * DEFECT (red since E2E job 6, Wed 11 Nov 2026; FIX row
 * OWNER-APPROVAL-CRITICALITY-FLOOR, joined with
 * CLAIM-SETTLE-APPROVED-FALLBACK-CRITICALITY-PENDS): the owner's
 * vault.claims.settle (approve) of the agent's proposed claim is refused 403
 * "gate.pending.criticality_floor": the owner's approve write reaches the
 * gate with no consent context and pends on the fallback criticality floor.
 */

type museLoop01ReceiptRow = FacadeResult<"vault.receipts">["receipts"][number];
type museLoop01PendingRow = FacadeResult<"vault.writes.pending">[number];
type museLoop01AuditRow = FacadeResult<"vault.authority.audit">["rows"][number];

interface museLoop01ReceiptActor {
  readonly actorRef: string | undefined;
  readonly actorClass: string;
  readonly claimRef: string | undefined;
  readonly outcomeText: string;
}

async function museLoop01CreatePerson(
  client: PublicHttpClient,
  name: string,
  occurredAt: number,
): Promise<FacadeResult<"vault.structural.put">> {
  const created = await client.call("vault.structural.put", {
    kind: "PERSON", body: { name }, occurred_at: occurredAt,
  });
  expect(created.id_hex.length).toBeGreaterThan(0);
  return created;
}

async function museLoopClaimEvidence(
  client: PublicHttpClient,
  conversationRef: string,
  content: string,
  occurredAt: number,
): Promise<string> {
  const conversation = await client.call("vault.get", { entity_ref: conversationRef });
  expect(conversation.value?.kind).toBe("CONVERSATION");
  const witnessed = await client.call("vault.witness", {
    conversation_ref: conversationRef,
    occurred_at: occurredAt,
    messages: [{ author: "user", message_type: "text", is_visible: true, order: 0, content }],
  });
  const turn = await client.call("vault.get", { entity_ref: witnessed.turn_id });
  expect(turn.value?.kind).toBe("TURN");
  expect(turn.value?.id_hex).toBe(witnessed.turn_id);
  expect(witnessed.message_short_ids).toHaveLength(1);
  const messageRef = witnessed.message_short_ids[0];
  if (!messageRef) throw new Error("Claim evidence witness returned no message reference");
  const message = await client.call("vault.get", { entity_ref: messageRef });
  expect(message.value?.kind).toBe("MESSAGE");
  expect(message.value?.body).toEqual(expect.objectContaining({ content }));
  return witnessed.turn_id;
}

async function museLoop01ReceiptRows(
  client: PublicHttpClient,
): Promise<museLoop01ReceiptRow[]> {
  const rows: museLoop01ReceiptRow[] = [];
  let after: string | undefined;
  for (;;) {
    const query: FacadeInput<"vault.receipts"> = {
      limit: 1000, ...(after ? { after } : {}),
    };
    const page = await client.call("vault.receipts", query);
    rows.push(...page.receipts);
    if (!page.next_after) return rows;
    after = page.next_after;
  }
}

async function museLoop01ReceiptActor(
  client: PublicHttpClient,
  receiptRef: string,
): Promise<museLoop01ReceiptActor> {
  if (receiptRef.startsWith("call:")) {
    const call = await awaitPublic(
      () => client.call("vault.receipts.get", { receipt_ref: receiptRef }),
      value => value !== null,
      { label: `call receipt ${receiptRef}` },
    );
    if (!call) throw new Error(`MUSE-LOOP-01: call receipt ${receiptRef} is not readable`);
    return {
      actorRef: call.actor_ref,
      actorClass: call.actor_class,
      claimRef: undefined,
      outcomeText: typeof call.outcome === "string"
        ? call.outcome : `refused:${call.outcome.refused.code}`,
    };
  }
  const row = await awaitPublic(
    async () => (await museLoop01ReceiptRows(client))
      .find(candidate => candidate.receipt_ref === receiptRef),
    value => value !== undefined,
    { label: `governance receipt ${receiptRef}` },
  );
  if (!row) throw new Error(`MUSE-LOOP-01: governance receipt ${receiptRef} is not readable`);
  return {
    actorRef: row.actor_ref ?? undefined,
    actorClass: row.actor_class,
    claimRef: row.claim_ref ?? undefined,
    outcomeText: row.outcome,
  };
}

async function museLoop01AuditRows(
  client: PublicHttpClient,
): Promise<museLoop01AuditRow[]> {
  const rows: museLoop01AuditRow[] = [];
  let after: string | undefined;
  for (;;) {
    const query: FacadeInput<"vault.authority.audit"> = {
      limit: 500, ...(after ? { after } : {}),
    };
    const page = await client.call("vault.authority.audit", query);
    rows.push(...page.rows);
    if (!page.next_after) return rows;
    after = page.next_after;
  }
}

function museLoop01ClaimRefs(
  receipt: FacadeResult<"vault.claims.upsert">,
): Set<string> {
  return new Set([
    receipt.claim_short_id, receipt.claim?.id, receipt.claim?.short_id,
  ].filter((value): value is string => typeof value === "string" && value.length > 0));
}

function museLoop01PendingFor(
  rows: readonly museLoop01PendingRow[],
  claimRefs: ReadonlySet<string>,
): museLoop01PendingRow | undefined {
  return rows.find(row => claimRefs.has(row.claim_ref));
}

suite.test(test, "MUSE-LOOP-01", "An agent's proposed claims are found in the pending-write queue with receipts, and the owner approves one and rejects another with both actors named in receipts after restart", async () => {
  const engine = await EngineFixture.start({ id: "MUSE-LOOP-01", profile });
  const ownerRef = engine.pairedActor.principalRef;
  // A fixed public setup time, as GATE-09 uses; no wall-clock wait follows.
  const occurred = 1769947200;
  // Canon's registered-predicate example is goal.learning (ARCH-0044 S8).
  const predicate = "goal.learning";
  const proposedValue1 = `generated learning goal one ${secretHex(8)}`;
  const proposedValue2 = `generated learning goal two ${secretHex(8)}`;
  const noGrantValue = `generated learning goal ungranted ${secretHex(8)}`;
  const afterRevokeValue = `generated learning goal revoked ${secretHex(8)}`;
  redactor.add(proposedValue1, proposedValue2, noGrantValue, afterRevokeValue);

  const auditBaseline = await museLoop01AuditRows(engine.client);
  const proposerRecord = await museLoop01CreatePerson(
    engine.client, "Loop Proposer Agent", occurred);
  const proposer = await engine.pairActor({
    principalRef: proposerRecord.id_hex, actorClass: "agent",
    scope: ["core:read", "core:write"],
  });
  const readOnlyRecord = await museLoop01CreatePerson(
    engine.client, "Loop Read Only Agent", occurred);
  const readOnlyAgent = await engine.pairActor({
    principalRef: readOnlyRecord.id_hex, actorClass: "agent",
    scope: ["core:read"],
  });
  const subject1 = await museLoop01CreatePerson(
    engine.client, "Loop Subject One", occurred);
  const subject2 = await museLoop01CreatePerson(
    engine.client, "Loop Subject Two", occurred);
  const scope = await ownerBaseClaimScope(engine.client, ownerRef);
  const evidenceConversation = await engine.client.call("vault.conversations.create", {
    body: { members: [ownerRef, proposer.principalRef] },
    occurred_start: occurred, occurred_end: occurred, learned_at: occurred,
  });
  const evidenceTurn = await museLoopClaimEvidence(
    engine.client, evidenceConversation.id,
    `Owner learning goals: ${proposedValue1}; ${proposedValue2}.`, occurred,
  );
  const baselinePending = new Set((
    await engine.client.call("vault.writes.pending", { limit: 1000 })
  ).map(row => row.claim_ref));

  // An agent paired without core:write is refused at the write door, and
  // the refusal lands nothing in the review queue or the claim list.
  const noGrantInput: FacadeInput<"vault.claims.upsert"> = {
    predicate, subject_ref: subject1.id_hex, value: noGrantValue,
    confidence: 0.8, source: "inferred", scope, evidence_turn_refs: [evidenceTurn], occurred_at: occurred,
  };
  const noGrant = await readOnlyAgent.client.raw<{
    error: { code: string; message: string };
  }>("POST", "/v1/core/facade/vault.claims.upsert", noGrantInput);
  expect(noGrant.status).toBe(403);
  const pendingAfterNoGrant = await engine.client.call(
    "vault.writes.pending", { limit: 1000 });
  const claimsAfterNoGrant = await engine.client.call("vault.claims.list", {
    subject_ref: subject1.id_hex, predicate, limit: 100,
  });

  // Act 1 (P-LOOP-002 receipt + P-LOOP-001 queue): the granted agent
  // proposes an inferred claim. Canon maps inferred sources to proposed.
  const proposalInput1: FacadeInput<"vault.claims.upsert"> = {
    predicate, subject_ref: subject1.id_hex, value: proposedValue1,
    confidence: 0.8, source: "inferred", scope, evidence_turn_refs: [evidenceTurn], occurred_at: occurred,
  };
  const receipt1 = await proposer.client.call("vault.claims.upsert", proposalInput1);
  expect(receipt1.receipt_ref.length).toBeGreaterThan(0);
  expect(receipt1.claim_short_id.length).toBeGreaterThan(0);
  expect(receipt1.approval.toLowerCase()).toBe("proposed");
  await engine.awaitReceipt(receipt1.receipt_ref);
  const claimRefs1 = museLoop01ClaimRefs(receipt1);
  const pending1 = await awaitPublic(
    async () => museLoop01PendingFor(
      await engine.client.call("vault.writes.pending", { limit: 1000 }), claimRefs1),
    row => row !== undefined,
    { label: "first proposed claim in pending writes" },
  );
  if (!pending1) throw new Error("MUSE-LOOP-01: first proposed claim never reached pending writes");
  claimRefs1.add(pending1.claim_ref);
  expect(baselinePending.has(pending1.claim_ref)).toBe(false);
  const receiptActor1 = await museLoop01ReceiptActor(engine.client, receipt1.receipt_ref);
  expect(receiptActor1.actorRef).toBe(proposer.principalRef);
  expect(receiptActor1.actorClass.toLowerCase()).toBe("agent");
  if (receiptActor1.claimRef !== undefined) {
    expect(claimRefs1.has(receiptActor1.claimRef)).toBe(true);
  }

  // Observe through the owner review door, a second door from the write.
  const review1 = await engine.client.call("vault.claims.review", {
    claim_ref: pending1.claim_ref,
  } satisfies FacadeInput<"vault.claims.review">);
  expect(review1.review_id.length).toBeGreaterThan(0);
  expect(review1.proposal_ref.length).toBeGreaterThan(0);
  expect(claimRefs1.has(review1.claim.claim_ref)).toBe(true);
  expect(review1.claim.subject_ref).toBe(subject1.id_hex);
  expect(review1.claim.predicate).toBe(predicate);
  expect(review1.claim.value).toBe(proposedValue1);
  expect(review1.claim.approval.toLowerCase()).toBe("proposed");

  // Wrong actor kind: the proposer may not settle its own proposal. Read
  // the HTTP refusal's call receipt without opening an owner-grade sync socket.
  const settleApprove1: FacadeInput<"vault.claims.settle"> = {
    claim_ref: pending1.claim_ref, review_id: review1.review_id, decision: "approve",
  };
  const deniedHttp = await proposer.client.raw<{
    error: { code: string; message: string; suggestions?: readonly string[]; receiptRef?: string };
  }>("POST", "/v1/core/facade/vault.claims.settle", settleApprove1);
  expect(deniedHttp.status).toBe(403);
  expect(deniedHttp.body.error.code.length).toBeGreaterThan(0);
  expect(deniedHttp.body.error.message.length).toBeGreaterThan(0);
  const deniedReceiptRef = deniedHttp.body.error.receiptRef;
  if (!deniedReceiptRef) {
    throw new Error("MUSE-LOOP-01: refused HTTP settle left no receiptRef");
  }
  const deniedReceipt = await museLoop01ReceiptActor(engine.client, deniedReceiptRef);
  expect(deniedReceipt.actorRef).toBe(proposer.principalRef);
  expect(deniedReceipt.actorClass.toLowerCase()).toBe("agent");
  expect(deniedReceipt.outcomeText.toLowerCase()).not.toBe("ok");
  expect(museLoop01PendingFor(
    await engine.client.call("vault.writes.pending", { limit: 1000 }),
    claimRefs1)?.claim_ref).toBe(pending1.claim_ref);

  // The owner approves exactly the reviewed proposal.
  const settled1 = await engine.client.call("vault.claims.settle", settleApprove1);
  expect(settled1.verdict).toBe("landed");
  expect(settled1.receipt_ref.length).toBeGreaterThan(0);
  expect(settled1.proposal_ref).toBe(review1.proposal_ref);
  expect(settled1.review_id).toBe(review1.review_id);
  expect(settled1.changes.some(change =>
    change.claim_ref === pending1.claim_ref && change.verdict === "landed")).toBe(true);
  await engine.awaitReceipt(settled1.receipt_ref);
  const settleReceiptActor1 = await museLoop01ReceiptActor(
    engine.client, settled1.receipt_ref);
  expect(settleReceiptActor1.actorRef).toBe(ownerRef);
  expect(settleReceiptActor1.actorClass.toLowerCase()).toBe("human");
  if (settleReceiptActor1.claimRef !== undefined) {
    expect(claimRefs1.has(settleReceiptActor1.claimRef)).toBe(true);
  }
  await awaitPublic(
    async () => museLoop01PendingFor(
      await engine.client.call("vault.writes.pending", { limit: 1000 }),
      claimRefs1) !== undefined,
    present => present === false,
    { label: "approved claim leaves pending writes" },
  );
  const listed1 = await engine.client.call("vault.claims.list", {
    subject_ref: subject1.id_hex, predicate, limit: 100,
  });
  const landed1 = listed1.value.find(row => row.claim_ref === pending1.claim_ref);
  expect(landed1?.value).toBe(proposedValue1);
  expect(["approved", "auto"].includes(landed1?.approval.toLowerCase() ?? "")).toBe(true);

  // Act 2 (same promises through vault.commit): a second agent proposal,
  // this time for the owner to refuse.
  const proposalInput2: FacadeInput<"vault.claims.upsert"> = {
    predicate, subject_ref: subject2.id_hex, value: proposedValue2,
    confidence: 0.8, source: "inferred", scope, evidence_turn_refs: [evidenceTurn], occurred_at: occurred,
  };
  const committed2 = await proposer.client.call("vault.commit", {
    claims: [proposalInput2],
  } satisfies FacadeInput<"vault.commit">);
  expect(committed2).toHaveLength(1);
  const outcome2 = committed2[0]!;
  if (outcome2.outcome !== "landed") {
    throw new Error(
      `MUSE-LOOP-01: second proposal was refused: ${outcome2.refusal.code} ${outcome2.refusal.message}`);
  }
  const receipt2 = outcome2;
  expect(receipt2.receipt_ref.length).toBeGreaterThan(0);
  expect(receipt2.claim_short_id.length).toBeGreaterThan(0);
  expect(receipt2.approval.toLowerCase()).toBe("proposed");
  await engine.awaitReceipt(receipt2.receipt_ref);
  const claimRefs2 = museLoop01ClaimRefs(receipt2);
  const pending2 = await awaitPublic(
    async () => museLoop01PendingFor(
      await engine.client.call("vault.writes.pending", { limit: 1000 }), claimRefs2),
    row => row !== undefined,
    { label: "second proposed claim in pending writes" },
  );
  if (!pending2) throw new Error("MUSE-LOOP-01: second proposed claim never reached pending writes");
  claimRefs2.add(pending2.claim_ref);
  const receiptActor2 = await museLoop01ReceiptActor(engine.client, receipt2.receipt_ref);
  expect(receiptActor2.actorRef).toBe(proposer.principalRef);
  expect(receiptActor2.actorClass.toLowerCase()).toBe("agent");
  const review2 = await engine.client.call("vault.claims.review", {
    claim_ref: pending2.claim_ref,
  } satisfies FacadeInput<"vault.claims.review">);
  expect(review2.claim.value).toBe(proposedValue2);
  expect(review2.claim.approval.toLowerCase()).toBe("proposed");

  const settled2 = await engine.client.call("vault.claims.settle", {
    claim_ref: pending2.claim_ref, review_id: review2.review_id, decision: "reject",
  } satisfies FacadeInput<"vault.claims.settle">);
  expect(settled2.verdict).toBe("rejected");
  expect(settled2.receipt_ref.length).toBeGreaterThan(0);
  expect(settled2.proposal_ref).toBe(review2.proposal_ref);
  expect(settled2.changes.some(change =>
    change.claim_ref === pending2.claim_ref && change.verdict === "rejected")).toBe(true);
  await engine.awaitReceipt(settled2.receipt_ref);
  const settleReceiptActor2 = await museLoop01ReceiptActor(
    engine.client, settled2.receipt_ref);
  expect(settleReceiptActor2.actorRef).toBe(ownerRef);
  expect(settleReceiptActor2.actorClass.toLowerCase()).toBe("human");
  await awaitPublic(
    async () => museLoop01PendingFor(
      await engine.client.call("vault.writes.pending", { limit: 1000 }),
      claimRefs2) !== undefined,
    present => present === false,
    { label: "rejected claim leaves pending writes" },
  );
  const history2 = await engine.client.call("vault.claims.history", {
    claim_ref: pending2.claim_ref,
  } satisfies FacadeInput<"vault.claims.history">);
  const rejectedRow = history2.value.find(row => row.claim_ref === pending2.claim_ref);
  expect(rejectedRow?.value).toBe(proposedValue2);
  expect(rejectedRow?.approval.toLowerCase()).toBe("rejected");
  const listed2 = await engine.client.call("vault.claims.list", {
    subject_ref: subject2.id_hex, predicate, limit: 100,
  });
  expect(listed2.value.some(row => row.value === proposedValue2
    && ["approved", "auto"].includes(row.approval.toLowerCase()))).toBe(false);

  // Survive a restart: queue state, landed and rejected claims, and the
  // receipt chain naming the agent proposer and the human settler.
  await engine.restart();
  const pendingAfterRestart = await engine.client.call(
    "vault.writes.pending", { limit: 1000 });
  expect(museLoop01PendingFor(pendingAfterRestart, claimRefs1)).toBe(undefined);
  expect(museLoop01PendingFor(pendingAfterRestart, claimRefs2)).toBe(undefined);
  const listedAfterRestart = await engine.client.call("vault.claims.list", {
    subject_ref: subject1.id_hex, predicate, limit: 100,
  });
  expect(listedAfterRestart.value.find(row =>
    row.claim_ref === pending1.claim_ref)?.value).toBe(proposedValue1);
  const historyAfterRestart = await engine.client.call("vault.claims.history", {
    claim_ref: pending2.claim_ref,
  } satisfies FacadeInput<"vault.claims.history">);
  expect(historyAfterRestart.value.find(row =>
    row.claim_ref === pending2.claim_ref)?.approval.toLowerCase()).toBe("rejected");
  for (const [receiptRef, expectedRef, expectedClass] of [
    [receipt1.receipt_ref, proposer.principalRef, "agent"],
    [settled1.receipt_ref, ownerRef, "human"],
    [receipt2.receipt_ref, proposer.principalRef, "agent"],
    [settled2.receipt_ref, ownerRef, "human"],
  ] as const) {
    const actor = await museLoop01ReceiptActor(engine.client, receiptRef);
    expect(actor.actorRef).toBe(expectedRef);
    expect(actor.actorClass.toLowerCase()).toBe(expectedClass);
  }

  // The proposer loses its paired credential through the owner's public
  // slip-revoke door (the AUTHORITY-05 pattern); its next write is refused.
  const auditAfterPairing = await museLoop01AuditRows(engine.client);
  const baselineHashes = new Set(auditBaseline.map(row => row.entry_hash));
  const minted = auditAfterPairing.filter(row =>
    !baselineHashes.has(row.entry_hash)
    && row.source_op === "slip_mint" && row.holder_ref === proposer.principalRef);
  const slipIds = [...new Set(minted.map(row => row.subject_ref)
    .filter((value): value is string =>
      typeof value === "string" && /^[a-f0-9]{64}$/.test(value)))];
  for (const slipId of slipIds) {
    const revoked = await engine.client.request<{ revoked: boolean }>(
      "POST", "/v1/core/slips/revoke",
      { slip_id: Array.from(Buffer.from(slipId, "hex")) });
    expect(revoked.status).toBe(200);
  }
  const afterRevokeInput: FacadeInput<"vault.claims.upsert"> = {
    predicate, subject_ref: subject1.id_hex, value: afterRevokeValue,
    confidence: 0.8, source: "inferred", scope, evidence_turn_refs: [evidenceTurn], occurred_at: occurred,
  };
  const afterRevoke = await proposer.client.raw<{
    error: { code: string; message: string };
  }>("POST", "/v1/core/facade/vault.claims.upsert", afterRevokeInput);
  const auditFinal = await museLoop01AuditRows(engine.client);
  const listedFinal = await engine.client.call("vault.claims.list", {
    subject_ref: subject1.id_hex, predicate, limit: 100,
  });
});

// ---- MUSE-LOOP-02 (Muse Wonder Full, ported 10 Nov) ----
type MuseLoop02Scope = FacadeInput<"vault.consent.graduation.answer">["scope"];
type MuseLoop02Offer = FacadeResult<"vault.consent.graduation.offers">[number];
type MuseLoop02TrustRow = FacadeResult<"vault.consent.graduation.trust_table">[number];
type MuseLoop02Stats = NonNullable<FacadeResult<"vault.consent.graduation.stats">>;
type MuseLoop02Snooze = FacadeResult<"vault.consent.graduation.answer">["snooze"];

function museLoop02SameScope(left: MuseLoop02Scope, right: MuseLoop02Scope): boolean {
  return left.op_kind === right.op_kind
    && left.target_class === right.target_class
    && left.actor === right.actor;
}

function museLoop02OfferFor(
  offers: readonly MuseLoop02Offer[],
  scope: MuseLoop02Scope,
): MuseLoop02Offer | undefined {
  return offers.find((offer) => museLoop02SameScope(offer.scope, scope));
}

function museLoop02TrustRowFor(
  rows: readonly MuseLoop02TrustRow[],
  scope: MuseLoop02Scope,
): MuseLoop02TrustRow {
  const row = rows.find((candidate) => museLoop02SameScope(candidate.scope, scope));
  if (!row) {
    throw new Error(`Trust table has no row for ${scope.op_kind} x ${scope.target_class}`);
  }
  return row;
}

function museLoop02SnoozedCount(snooze: MuseLoop02Snooze): number {
  if (snooze.state !== "snoozed") {
    throw new Error(`Expected a snoozed graduation scope, got ${snooze.state}`);
  }
  return snooze.count;
}

async function museLoop02Earn(
  engine: EngineFixture,
  scope: MuseLoop02Scope,
  count: number,
): Promise<void> {
  for (let index = 0; index < count; index += 1) {
    // One owner ruling per call; outcome calls are the write, and every caller
    // reads the result back through offers, stats and the trust table.
    await engine.client.call("vault.consent.graduation.outcome", {
      scope,
      outcome: "approved_untouched",
    });
  }
}

async function museLoop02Stats(
  engine: EngineFixture,
  scope: MuseLoop02Scope,
): Promise<MuseLoop02Stats> {
  const stats = await engine.client.call("vault.consent.graduation.stats", { scope });
  if (!stats) {
    throw new Error(`Graduation stats are missing for ${scope.op_kind} x ${scope.target_class}`);
  }
  return stats;
}

async function museLoop02TrustRow(
  engine: EngineFixture,
  scope: MuseLoop02Scope,
): Promise<MuseLoop02TrustRow> {
  return museLoop02TrustRowFor(
    await engine.client.call("vault.consent.graduation.trust_table", {}),
    scope,
  );
}

// MUSE-LOOP-02
// Promises:
// - P-LOOP-006 (MUST): a graduation offer provides go auto, not now, and
//   always manual choices.
// - P-LOOP-007 (MUST): choosing always manual stops graduation offers until
//   the setting is changed.
// Canon: ARCH-0056 #graduation-h (the three answers, manual_pinned and the
// trust table) and ARCH-0055 section 7 (the scope tuple, outcome receipts,
// "the system offers, the owner taps", and persistence across sessions).
// Doors used, all through engine.client.call:
// vault.consent.graduation.policy (setup read of the effective threshold),
// .outcome (owner records untouched approvals), .offers, .stats and
// .trust_table (independent read-backs), .answer (auto / not-now /
// manual_pinned), vault.consent.registry (the minted standing grant), and
// vault.consent.graduation.settings.unpin (the settings change). The agent is
// a paired PERSON principal used as the scope actor and as the wrong actor.
// What stays unproved: GraduationOffer carries no answers/labels field, so
// the three choices are proved by submitting each GraduationAnswer against
// its own earned offer and reading the effect back, not by offer copy or
// dashboard rendering. Not-now re-offer timing (backoff elapsed, three
// snoozes) and an auto scope then executing a real send unaudited are also
// unproved: no clock door may be used and no send door is in this case.
suite.test(test, "MUSE-LOOP-02", "A graduation offer gives go auto, not now and always manual, and always manual stops offers until settings unpin", async () => {
  const engine = await EngineFixture.start({ id: "MUSE-LOOP-02", profile });

  // A real paired agent principal: its ref is the actor in every scope tuple,
  // and it is the wrong actor for answering its own offer below.
  const agentName = `Muse Loop 02 Agent ${secretHex(4)}`;
  redactor.add(agentName);
  const occurredAt = 1769947200;
  const agentRecord = await engine.client.call("vault.structural.put", {
    kind: "PERSON",
    body: { name: agentName },
    occurred_at: occurredAt,
  });
  const agent = await engine.pairActor({
    principalRef: agentRecord.id_hex,
    actorClass: "agent",
    scope: ["core:read", "core:write"],
  });

  // The three scope tuples from canon's own examples, each completing one
  // answer: "go auto for [send-email x client-followups]?", the trust table's
  // "eligible soon" propose row, and its pinned MANUAL invoice row.
  const autoScope: MuseLoop02Scope = {
    op_kind: "send-email",
    target_class: "client-followups",
    actor: agent.principalRef,
  };
  const notNowScope: MuseLoop02Scope = {
    op_kind: "send-email",
    target_class: "new-contacts",
    actor: agent.principalRef,
  };
  const manualScope: MuseLoop02Scope = {
    op_kind: "invoice-create",
    target_class: "any",
    actor: agent.principalRef,
  };
  const scopes: readonly MuseLoop02Scope[] = [autoScope, notNowScope, manualScope];

  // Baseline: no outcome receipts yet, so no offer exists for these scopes.
  expect(museLoop02OfferFor(
    await engine.client.call("vault.consent.graduation.offers", {}),
    manualScope,
  )).toBeUndefined();

  // The canonical trigger is the legible "last 12 untouched" streak. Read the
  // effective owner policy for each scope and never earn less than 12.
  let requiredStreak = 12;
  for (const scope of scopes) {
    const policy = await engine.client.call("vault.consent.graduation.policy", { scope });
    requiredStreak = Math.max(requiredStreak, policy.effective?.required_streak ?? 12);
  }

  for (const scope of scopes) {
    await museLoop02Earn(engine, scope, requiredStreak);
  }

  // Earned offers, read back through offers, stats and the trust table.
  const earnedOffers = await engine.client.call("vault.consent.graduation.offers", {});
  for (const scope of scopes) {
    const offer = museLoop02OfferFor(earnedOffers, scope);
    if (!offer) {
      throw new Error(
        `No graduation offer after ${requiredStreak} untouched outcomes for ${scope.op_kind} x ${scope.target_class}`,
      );
    }
    expect(offer.stats.untouched_streak).toBeGreaterThanOrEqual(requiredStreak);
    expect(offer.stats.untouched_streak)
      .toBeGreaterThanOrEqual(offer.threshold.required_streak);
    expect(offer.stats.last_outcome).toBe("approved_untouched");

    const stats = await museLoop02Stats(engine, scope);
    expect(stats.untouched_streak).toBeGreaterThanOrEqual(requiredStreak);
    expect(stats.last_outcome).toBe("approved_untouched");

    const trustRow = await museLoop02TrustRow(engine, scope);
    expect(trustRow.offer_is_earned).toBe(true);
    expect(trustRow.snooze.state).toBe("none");
    expect(trustRow.grant_ref == null).toBe(true);
  }

  // The wrong actor: the scoped agent cannot answer its own offer. The
  // HTTP refusal carries both the standard envelope and a call receipt.
  let deniedCode = "";
  let deniedReceiptRef: string | undefined;
  try {
    await agent.client.call("vault.consent.graduation.answer", {
      scope: manualScope,
      answer: "auto",
    });
    throw new Error("The agent was allowed to answer its own graduation offer over HTTP");
  } catch (error) {
    if (!(error instanceof PublicHttpError)) throw error;
    expect(error.reply.status).toBe(403);
    expect(error.error).toBeDefined();
    deniedCode = error.error?.code ?? "";
    expect(deniedCode.length).toBeGreaterThan(0);
    expect((error.error?.message ?? "").length).toBeGreaterThan(0);
    const receiptRef = error.error?.receiptRef;
    if (typeof receiptRef === "string") deniedReceiptRef = receiptRef;
  }
  expect(deniedCode.length).toBeGreaterThan(0);
  if (!deniedReceiptRef) {
    throw new Error("The HTTP graduation-answer refusal carried no receiptRef");
  }
  const deniedReceipt = await engine.client.call("vault.receipts.get", {
    receipt_ref: deniedReceiptRef,
  });
  if (!deniedReceipt) throw new Error("The HTTP refusal receipt is not readable by the owner");
  expect(deniedReceipt.verb).toBe("vault.consent.graduation.answer");
  expect(deniedReceipt.actor_class).toBe("agent");
  expect(deniedReceipt.transport).toBe("http_facade");
  if (typeof deniedReceipt.outcome === "string") {
    throw new Error("The HTTP refusal receipt outcome is ok, not refused");
  }
  expect(deniedReceipt.outcome.refused.code).toBe(deniedCode);

  // The refusal changed nothing: the manual scope is still on offer.
  expect(museLoop02OfferFor(
    await engine.client.call("vault.consent.graduation.offers", {}),
    manualScope,
  )).toBeDefined();
  expect((await museLoop02TrustRow(engine, manualScope)).offer_is_earned).toBe(true);

  // P-LOOP-006, go auto: only this answer mints the standing grant.
  const autoReceipt = await engine.client.call("vault.consent.graduation.answer", {
    scope: autoScope,
    answer: "auto",
  });
  expect(autoReceipt.answer).toBe("auto");
  expect(museLoop02SameScope(autoReceipt.scope, autoScope)).toBe(true);
  const grantRef = autoReceipt.grant?.grant_ref;
  if (typeof grantRef !== "string" || grantRef.length === 0) {
    throw new Error("The auto answer returned no standing grant_ref");
  }
  const autoTrust = await museLoop02TrustRow(engine, autoScope);
  expect(autoTrust.grant_ref).toBe(grantRef);
  expect((await museLoop02Stats(engine, autoScope)).state).toBe("auto");
  expect(museLoop02OfferFor(
    await engine.client.call("vault.consent.graduation.offers", {}),
    autoScope,
  )).toBeUndefined();
  const registry = await engine.client.call("vault.consent.registry", { limit: 100 });
  expect(registry.rows.some((row) => row.grant_ref === grantRef)).toBe(true);

  // P-LOOP-006, not now: the scope snoozes and its streak re-earns from zero.
  const notNowReceipt = await engine.client.call("vault.consent.graduation.answer", {
    scope: notNowScope,
    answer: "not-now",
  });
  expect(notNowReceipt.answer).toBe("not-now");
  expect(museLoop02SameScope(notNowReceipt.scope, notNowScope)).toBe(true);
  expect(notNowReceipt.grant == null).toBe(true);
  expect(museLoop02SnoozedCount(notNowReceipt.snooze)).toBe(1);
  if (notNowReceipt.snooze.state !== "snoozed") {
    throw new Error("The not-now answer did not snooze its scope");
  }
  const notNowTrust = await museLoop02TrustRow(engine, notNowScope);
  expect(museLoop02SnoozedCount(notNowTrust.snooze)).toBe(1);
  expect((await museLoop02Stats(engine, notNowScope)).untouched_streak).toBe(0);
  expect(museLoop02OfferFor(
    await engine.client.call("vault.consent.graduation.offers", {}),
    notNowScope,
  )).toBeUndefined();

  // P-LOOP-006 + P-LOOP-007, always manual: the scope is pinned and no offer
  // returns, even after a fresh untouched streak.
  const manualReceipt = await engine.client.call("vault.consent.graduation.answer", {
    scope: manualScope,
    answer: "manual_pinned",
  });
  expect(manualReceipt.answer).toBe("manual_pinned");
  expect(museLoop02SameScope(manualReceipt.scope, manualScope)).toBe(true);
  expect(manualReceipt.grant == null).toBe(true);
  expect(manualReceipt.snooze.state).toBe("manual_pinned");

  const pinnedTrust = await museLoop02TrustRow(engine, manualScope);
  expect(pinnedTrust.snooze.state).toBe("manual_pinned");
  expect(pinnedTrust.grant_ref == null).toBe(true);
  expect(museLoop02OfferFor(
    await engine.client.call("vault.consent.graduation.offers", {}),
    manualScope,
  )).toBeUndefined();

  await museLoop02Earn(engine, manualScope, requiredStreak);
  expect((await museLoop02TrustRow(engine, manualScope)).snooze.state)
    .toBe("manual_pinned");
  expect(museLoop02OfferFor(
    await engine.client.call("vault.consent.graduation.offers", {}),
    manualScope,
  )).toBeUndefined();

  // Every answer survives a restart: auto keeps its grant, not-now stays
  // snoozed, and always manual stays pinned with no offer.
  await engine.restart();
  const offersAfterRestart = await engine.client.call("vault.consent.graduation.offers", {});
  expect(museLoop02OfferFor(offersAfterRestart, autoScope)).toBeUndefined();
  expect(museLoop02OfferFor(offersAfterRestart, notNowScope)).toBeUndefined();
  expect(museLoop02OfferFor(offersAfterRestart, manualScope)).toBeUndefined();
  expect((await museLoop02TrustRow(engine, autoScope)).grant_ref).toBe(grantRef);
  expect((await museLoop02Stats(engine, autoScope)).state).toBe("auto");
  expect(museLoop02SnoozedCount(
    (await museLoop02TrustRow(engine, notNowScope)).snooze,
  )).toBe(1);
  expect((await museLoop02TrustRow(engine, manualScope)).snooze.state)
    .toBe("manual_pinned");

  // P-LOOP-007, until the setting is changed: only the settings unpin reopens
  // the scope, it creates no grant, and a re-earned streak is offered again.
  const unpinned = await engine.client.call("vault.consent.graduation.settings.unpin", {
    scope: manualScope,
  });
  expect(unpinned.changed).toBe(true);
  const reopenedTrust = await museLoop02TrustRow(engine, manualScope);
  expect(reopenedTrust.snooze.state).toBe("none");
  expect(reopenedTrust.grant_ref == null).toBe(true);

  await museLoop02Earn(engine, manualScope, requiredStreak);
  const reopenedOffer = museLoop02OfferFor(
    await engine.client.call("vault.consent.graduation.offers", {}),
    manualScope,
  );
  if (!reopenedOffer) {
    throw new Error("The manual scope was not offered again after settings unpin and a re-earned streak");
  }
  expect(reopenedOffer.stats.untouched_streak).toBeGreaterThanOrEqual(requiredStreak);
  expect((await museLoop02TrustRow(engine, manualScope)).offer_is_earned).toBe(true);
  expect((await museLoop02Stats(engine, manualScope)).untouched_streak)
    .toBeGreaterThanOrEqual(requiredStreak);
});

// ---- MUSE-LOOP-03 (Muse Wonder Full, ported 10 Nov) ----
async function museLoopGrantAskAuthority(
  owner: PublicHttpClient,
  actorRef: string,
): Promise<void> {
  const policy = await owner.call("vault.gate.policy.get", {});
  const current = policy.manifests.find(row => row.manifest_ref === policy.default_manifest_ref);
  if (!current) throw new Error("Default policy manifest is absent");
  const actorCeiling = { actor_class: "agent", actor_ref: actorRef, ceiling: "auto" as const };
  // Ask admission and answer intake check each party's own read authority,
  // independently of the credential on the current HTTP call.
  const askRead: Facade.PolicyScopedGrantRow = {
    actor_ref: actorRef,
    effector: "core:read",
    scope: {
      worlds: { kind: "all" }, facets: { kind: "all" },
      bands: { kind: "some", values: [1, 101] }, // TURN evidence and TASKs.
      audience: { kind: "all" }, verbs: { kind: "some", values: ["read"] },
      sensitivity: { kind: "at_most", value: "restricted" },
    },
    receipt_required: false,
  };
  const granted = await owner.call("vault.gate.policy.put", {
    manifest_ref: current.manifest_ref,
    expected_body_hash: current.body_hash,
    manifest: {
      ...current.manifest,
      actor_ceilings: [...(current.manifest.actor_ceilings ?? []), actorCeiling],
      scoped_grants: [...(current.manifest.scoped_grants ?? []), askRead],
    },
  } satisfies FacadeInput<"vault.gate.policy.put">);
  expect(granted.receipt_ref.length).toBeGreaterThan(0);
  const saved = await owner.call("vault.gate.policy.get", {});
  const savedManifest = saved.manifests.find(row => row.manifest_ref === current.manifest_ref)?.manifest;
  expect(savedManifest?.actor_ceilings).toContainEqual(actorCeiling);
  expect(savedManifest?.scoped_grants).toContainEqual(askRead);
}

type MuseLoop03AskSpec = Extract<FacadeInput<"ask">, { intent_key: string }>;
type MuseLoop03PeekRow = FacadeResult<"peek">[number];

const museLoop03OccurredAt = 1769947200;
const museLoop03RulingOption = "amend";

function museLoop03Object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Expected a public JSON object (body withheld)");
  }
  return value as Record<string, unknown>;
}

function museLoop03Ids(
  values: readonly (string | null | undefined)[],
): ReadonlySet<string> {
  return new Set(
    values.filter(
      (value): value is string => typeof value === "string" && value.length > 0,
    ),
  );
}

function museLoop03AskSpec(args: {
  intentKey: string;
  ownerPersonRef: string;
  questionTurnRef: string;
  questionLabel: string;
}): MuseLoop03AskSpec {
  return {
    intent_key: args.intentKey,
    who: { people: [args.ownerPersonRef] },
    what: {
      reference: { turn: args.questionTurnRef },
      revision: 1,
      options: {
        approve: { label: "Approve the draft as written" },
        deny: { label: "Deny the draft" },
        amend: { label: "Amend the draft, then send" },
      },
      context_refs: [],
      label: args.questionLabel,
    },
    decide: "first",
    need: { count: 1, of: { people: [args.ownerPersonRef] } },
    default: "hold",
  };
}

function museLoop03OwnerWord(
  rows: readonly MuseLoop03PeekRow[],
  ownerIds: ReadonlySet<string>,
): MuseLoop03PeekRow | undefined {
  return rows.find(
    row => ownerIds.has(row.who) && row.answer?.option === museLoop03RulingOption,
  );
}

// MUSE-LOOP-03 (PARTIAL) — promises, doors, and what stays unproved.
// Proved here, in the user-recognisable form the typed doors can drive today:
// - P-LOOP-008: an unsure paired agent escalates to the owner with the
//   needs_input face whose name is now `ask` (CROSS-ARCH-0009b), and the
//   question plus the owner's counted ruling survive read-back through
//   peek, wait, the describe status receipt, and a restart.
// - P-LOOP-010 (ask-up half only): the ask waits for the authorised owner,
//   the asking agent cannot supply the counted ruling itself, and the
//   settled result still reports effect_authorization
//   "not_evaluated_by_ask": the ask authorised no effect by itself.
// Not proved here (see the report for the candidate doors):
// - P-LOOP-010 as the register binds it to ai.verdict / decide() Q3: the
//   deterministic fixture has no scripted decision-ladder provider door,
//   and canon states no provider fills a decision slot by default and an
//   empty first rung still fails (ARCH-0076; ARCH-0036).
// - P-LOOP-011: no deadline-cut typed decision is driven, for the same
//   missing provider door. DecisionReceipt.time.stop exists in the typed
//   surface, but nothing here may honestly force "deadline".
// - P-LOOP-012: the settled ask names the answerer (counted evidence) and
//   the question (settlement.requested), but the typed DecisionReceipt has
//   no who-kept field and this flow settles no proposal, so "who kept the
//   proposal, and when" stays unproved.
// - The ARCH-0056 escalation receipt fields trigger=unsure and rationale
//   have no typed slot on `ask`; the ruling rationale rides the referenced
//   ruling turn instead, and trigger/rationale receipt fields stay unproved.
// Doors used: vault.get, self.actor, vault.structural.put, pairActor (CLI),
// vault.conversations.create, vault.witness, ask, peek, tasks.answer, wait,
// describe (status receipt), anonymous and self-answer raw facade refusals,
// EngineFixture.restart.

suite.test(test, "MUSE-LOOP-03", "An unsure agent asks the owner up through ask, the counted ruling is recorded, and the ask authorizes no effect", async () => {
  const engine = await EngineFixture.start({ id: "MUSE-LOOP-03", profile });
  const museLoop03AgentName = `Muse Loop03 Agent ${secretHex(4)}`;
  const museLoop03QuestionText = `MUSE-LOOP-03 unsure ${secretHex(4)}: should the softened reply be sent?`;
  const museLoop03RulingText = `MUSE-LOOP-03 ruling ${secretHex(4)}: amend the softened reply, then send.`;
  const museLoop03IntentKey = `muse-loop-03-${secretHex(8)}`;
  const museLoop03ForeignIntentKey = `muse-loop-03-foreign-${secretHex(8)}`;
  const museLoop03StepKey = `muse-loop-03-wait-${secretHex(8)}`;
  const museLoop03RestartStepKey = `muse-loop-03-wait-after-restart-${secretHex(8)}`;
  redactor.add(
    museLoop03AgentName,
    museLoop03QuestionText,
    museLoop03RulingText,
    museLoop03IntentKey,
    museLoop03ForeignIntentKey,
    museLoop03StepKey,
    museLoop03RestartStepKey,
  );

  const ownerEntity = await engine.client.call("vault.get", {
    entity_ref: engine.pairedActor.principalRef,
  });
  const ownerPersonRef = ownerEntity.value?.id_hex;
  if (!ownerPersonRef) throw new Error("Owner person is not publicly readable");
  const ownerSelf = await engine.client.call("self.actor", {});

  const agentRecord = await engine.client.call("vault.structural.put", {
    kind: "PERSON",
    body: { name: museLoop03AgentName },
    occurred_at: museLoop03OccurredAt,
  });
  const agent = await engine.pairActor({
    principalRef: agentRecord.id_hex,
    actorClass: "agent",
    scope: ["core:read", "core:write"],
  });
  await museLoopGrantAskAuthority(engine.client, agent.principalRef);
  const agentSelf = await agent.client.call("self.actor", {});
  const ownerIds = museLoop03Ids([
    engine.pairedActor.principalRef,
    ownerPersonRef,
    ownerSelf.actor_ref,
    ownerSelf.person_ref,
  ]);
  const agentIds = museLoop03Ids([
    agent.principalRef,
    agentRecord.id_hex,
    agentSelf.actor_ref,
  ]);
  expect([...ownerIds].some(id => agentIds.has(id))).toBe(false);

  const conversation = await engine.client.call("vault.conversations.create", {
    body: { members: [engine.pairedActor.principalRef, agent.principalRef] },
    occurred_start: museLoop03OccurredAt,
    occurred_end: museLoop03OccurredAt,
  });
  const questionWitness = await engine.client.call("vault.witness", {
    conversation_ref: conversation.id,
    occurred_at: museLoop03OccurredAt,
    messages: [{
      author: "user",
      message_type: "text",
      is_visible: true,
      order: 0,
      content: museLoop03QuestionText,
    }],
  } satisfies FacadeInput<"vault.witness">);
  const savedQuestionTurn = await engine.client.call("vault.get", {
    entity_ref: questionWitness.turn_id,
  });
  expect(savedQuestionTurn.value?.kind).toBe("TURN");
  expect(savedQuestionTurn.value?.id_hex).toBe(questionWitness.turn_id);
  const questionMessageRef = questionWitness.message_short_ids[0];
  if (!questionMessageRef) throw new Error("Witness returned no question message reference");
  const savedQuestion = await engine.client.call("vault.get", {
    entity_ref: questionMessageRef,
  });
  const savedQuestionContent = museLoop03Object(savedQuestion.value?.body).content;
  expect(
    typeof savedQuestionContent === "string"
      && savedQuestionContent.includes("MUSE-LOOP-03 unsure")
      && savedQuestionContent.includes("softened reply"),
  ).toBe(true);

  const spec = museLoop03AskSpec({
    intentKey: museLoop03IntentKey,
    ownerPersonRef,
    questionTurnRef: questionWitness.turn_id,
    questionLabel: museLoop03QuestionText,
  });
  const foreignSpec = museLoop03AskSpec({
    intentKey: museLoop03ForeignIntentKey,
    ownerPersonRef,
    questionTurnRef: questionWitness.turn_id,
    questionLabel: museLoop03QuestionText,
  });

  // Refuse the wrong actor kind first: no credential, no ask.
  const anonymous = new PublicHttpClient(engine.url, {
    artifacts: engine.artifacts,
    label: "muse-loop-03-anonymous",
  });
  const foreign = await anonymous.raw<{ error: { code: string; message: string } }>(
    "POST",
    "/v1/core/facade/ask",
    foreignSpec,
    { "x-oneiron-invocation": secretHex(16) },
  );
  expect([401, 403].includes(foreign.status)).toBe(true);
  expect(
    typeof foreign.body.error?.code === "string" && foreign.body.error.code.length > 0,
  ).toBe(true);
  expect(
    typeof foreign.body.error?.message === "string" && foreign.body.error.message.length > 0,
  ).toBe(true);

  const asked = await agent.client.call("ask", spec);
  expect(asked.handle.group_ref.length).toBeGreaterThan(0);
  expect(asked.task_refs.length).toBeGreaterThan(0);
  const handle = asked.handle;

  const peekBefore = await agent.client.call("peek", handle);
  expect(museLoop03OwnerWord(peekBefore, ownerIds) === undefined).toBe(true);

  // The asker may not rule its own escalation: either the word is refused
  // with the standard envelope, or it is admitted as evidence only and is
  // never the counted ruling below.
  const selfAnswer = await agent.client.raw<{
    error?: { code: string; message: string };
  }>(
    "POST",
    "/v1/core/facade/tasks.answer",
    { handle, word: { result_ref: questionWitness.turn_id, option: "approve" } },
    { "x-oneiron-invocation": secretHex(16) },
  );
  if (selfAnswer.status >= 400) {
    expect(
      typeof selfAnswer.body.error?.code === "string"
        && selfAnswer.body.error.code.length > 0,
    ).toBe(true);
  }
  const peekAfterSelf = await agent.client.call("peek", handle);
  expect(museLoop03OwnerWord(peekAfterSelf, ownerIds) === undefined).toBe(true);

  const rulingWitness = await engine.client.call("vault.witness", {
    conversation_ref: conversation.id,
    occurred_at: museLoop03OccurredAt,
    messages: [{
      author: "user",
      message_type: "text",
      is_visible: true,
      order: 0,
      content: museLoop03RulingText,
    }],
  } satisfies FacadeInput<"vault.witness">);
  const savedRulingTurn = await engine.client.call("vault.get", {
    entity_ref: rulingWitness.turn_id,
  });
  expect(savedRulingTurn.value?.kind).toBe("TURN");
  expect(savedRulingTurn.value?.id_hex).toBe(rulingWitness.turn_id);
  const rulingMessageRef = rulingWitness.message_short_ids[0];
  if (!rulingMessageRef) throw new Error("Witness returned no ruling message reference");
  const savedRuling = await engine.client.call("vault.get", {
    entity_ref: rulingMessageRef,
  });
  const savedRulingContent = museLoop03Object(savedRuling.value?.body).content;
  expect(
    typeof savedRulingContent === "string"
      && savedRulingContent.includes("MUSE-LOOP-03 ruling")
      && savedRulingContent.includes("amend"),
  ).toBe(true);
  const rulingRefs = museLoop03Ids([
    rulingWitness.turn_id,
    rulingWitness.turn_short_id,
    rulingMessageRef,
  ]);

  const answer = await engine.client.call("tasks.answer", {
    handle,
    word: { result_ref: rulingWitness.turn_id, option: museLoop03RulingOption },
  });
  expect(ownerIds.has(answer.actor_ref)).toBe(true);
  expect(rulingRefs.has(answer.result_ref)).toBe(true);
  expect(answer.word_ref.length).toBeGreaterThan(0);

  const peekAnswered = await awaitPublic(
    () => agent.client.call("peek", handle),
    rows => museLoop03OwnerWord(rows, ownerIds) !== undefined,
    { label: "MUSE-LOOP-03 owner word on peek" },
  );
  const ownerPeek = museLoop03OwnerWord(peekAnswered, ownerIds);
  if (!ownerPeek) throw new Error("Owner word never appeared on peek");
  expect(ownerPeek.kind).toBe("word");

  const waited = await agent.client.call("wait", { handle, step_key: museLoop03StepKey });
  if (!("Ready" in waited)) {
    throw new Error("Answered ask did not return its settled result on wait");
  }
  const ready = waited.Ready;
  expect(ready.effect_authorization).toBe("not_evaluated_by_ask");
  expect(ready.coverage.met).toBe(true);
  expect(ready.coverage.responded.some(id => ownerIds.has(id))).toBe(true);
  expect(ready.picked).toBe(museLoop03RulingOption);
  expect(ready.settlement.group_ref).toBe(handle.group_ref);
  expect(ready.settlement.electorate.some(id => ownerIds.has(id))).toBe(true);
  expect(ready.settlement.requested.intent_key).toBe(museLoop03IntentKey);
  expect(ready.settlement.requested.what.label).toBe(museLoop03QuestionText);
  const requestedReference = ready.settlement.requested.what.reference;
  expect(
    "turn" in requestedReference && requestedReference.turn === questionWitness.turn_id,
  ).toBe(true);
  const counted = ready.evidence.filter(row => row.reason === "counted");
  expect(counted.length).toBe(1);
  const countedWord = counted[0];
  if (!countedWord) throw new Error("Settled ask has no counted word");
  expect(ownerIds.has(countedWord.person_ref)).toBe(true);
  expect(countedWord.word.option).toBe(museLoop03RulingOption);
  expect(rulingRefs.has(countedWord.word.result_ref)).toBe(true);
  expect(ownerIds.has(countedWord.answer.actor_ref)).toBe(true);

  const described = await agent.client.call("describe", {
    handle: { kind: "ask", group_ref: handle.group_ref },
  });
  if (described.kind !== "task_status") {
    throw new Error("describe on an ask handle did not return its task status");
  }
  const outcome = described.receipt.outcome;
  if (outcome.kind !== "snapshot") {
    throw new Error("describe on an ask handle did not return a status snapshot");
  }
  const describedEntry = outcome.asks.find(([askHandle]) => askHandle.group_ref === handle.group_ref);
  if (!describedEntry) throw new Error("describe snapshot does not carry this ask");
  expect("Settled" in describedEntry[1]).toBe(true);

  const recordedStatus = describedEntry[1];
  if (!("Settled" in recordedStatus)) {
    throw new Error("describe receipt does not retain the settled ask");
  }
  const recordedRuling = recordedStatus.Settled;
  expect(recordedRuling.settlement.group_ref).toBe(handle.group_ref);
  expect(recordedRuling.effect_authorization).toBe("not_evaluated_by_ask");
  const recordedWords = recordedRuling.evidence.filter(row => row.reason === "counted");
  expect(recordedWords).toHaveLength(1);
  const recordedWord = recordedWords[0];
  if (!recordedWord) throw new Error("describe receipt lost the counted ruling");
  expect(recordedWord.word.option).toBe(museLoop03RulingOption);
  expect(recordedWord.answer.word_ref).toBe(answer.word_ref);
  expect(asked.task_refs).toContain(recordedWord.answer.task_ref);
  expect(ownerIds.has(recordedWord.person_ref)).toBe(true);
  expect(ownerIds.has(recordedWord.answer.actor_ref)).toBe(true);
  expect(rulingRefs.has(recordedWord.answer.result_ref)).toBe(true);

  await engine.restart();

  const peekAfterRestart = await agent.client.call("peek", handle);
  expect(museLoop03OwnerWord(peekAfterRestart, ownerIds) !== undefined).toBe(true);

  const replayed = await agent.client.call("ask", spec);

  const waitedAfterRestart = await agent.client.call("wait", {
    handle,
    step_key: museLoop03RestartStepKey,
  });
  if (!("Ready" in waitedAfterRestart)) {
    throw new Error("Settled ask did not return its result on wait after restart");
  }
  expect(waitedAfterRestart.Ready.picked).toBe(museLoop03RulingOption);
  expect(waitedAfterRestart.Ready.settlement.group_ref).toBe(handle.group_ref);
  expect(waitedAfterRestart.Ready.effect_authorization).toBe("not_evaluated_by_ask");
  const countedAfterRestart = waitedAfterRestart.Ready.evidence.filter(
    row => row.reason === "counted",
  );
  expect(countedAfterRestart.length).toBe(1);
  const countedAfterRestartWord = countedAfterRestart[0];
  if (!countedAfterRestartWord) {
    throw new Error("Settled ask lost its counted word across restart");
  }
  expect(ownerIds.has(countedAfterRestartWord.person_ref)).toBe(true);
  expect(countedAfterRestartWord.word.option).toBe(museLoop03RulingOption);

  await engine.artifacts.json("muse-loop-03-ask.json", {
    handle,
    taskRefs: asked.task_refs,
    taskRecords: asked.task_records,
    answer,
    foreignStatus: foreign.status,
    selfAnswerStatus: selfAnswer.status,
    picked: ready.picked,
    settlementReason: ready.settlement.reason,
    effectAuthorization: ready.effect_authorization,
  });
});

// ---- MUSE-LOOP-04 (Muse Wonder Full, ported 10 Nov) ----
// MUSE-LOOP-04 - P-LOOP-013, P-LOOP-014, P-LOOP-015.
// P-LOOP-013 (MUST): automatic approval of answerer-model switches is off by default.
// P-LOOP-014 (MUST): an unknown comparison result never automatically switches the answerer.
// P-LOOP-015 (MUST): an approved answerer switch affects future answers without
// rewriting past answers or receipts.
// Doors: vault.models.catalog.refresh/get, vault.models.manifest.read/replace,
// vault.models.bindings.read, vault.models.roles.read, vault.questions.create/
// read/refresh/answers/outcomes.project/outcomes/edit, vault.claims.upsert,
// vault.skills.list + vault.skills.optimize.goal.get (the trial goal),
// vault.models.trials.nominate/approve/run/complete/get,
// vault.agents.grants.mint/revoke, vault.models.bindings.propose/accept/get,
// vault.receipts + vault.receipts.get, HTTP agent propose and WS owner accept.
// Unproved: no typed door in the facade reads or writes a persisted vault-wide
// auto-approve setting (the case proves the off-by-default behaviour on a fresh
// vault and the on-behaviour only through ModelTrialPolicy.auto_approve), and
// the notice/one-click-undo and 30-day check that follow an approved switch.
// History: red from E2E job 10 (Wed 11 Nov 2026) at the owner's manual
// vault.questions.refresh of a standing graph question, which returned no
// answers (FIX row STANDING-GRAPH-OWNER-CENTRE-READ, fixed by #7114). On set
// c3fc89a5421 (Thu 12 Nov 2026) the refresh answered and the case reached the
// outcome claim read-back, which named the upsert's input keys instead of the
// stored body's (a test bug, fixed here). The agent-propose leg has its door
// since #7178; E2E job 14 (Thu 12 Nov 2026, set 2ca9ae16f25) reached it and got
// 403 at the scope check, because the case minted a propose-only agent for a
// Write-scope verb (a test bug, fixed here: the agent is full-access).

type MuseLoop04Binding = FacadeResult<"vault.models.bindings.read">;
type MuseLoop04TrialView = FacadeResult<"vault.models.trials.get">;
type MuseLoop04GraphAnswer = Extract<
  FacadeResult<"vault.questions.refresh">[number],
  { kind: "graph" }
>;
type MuseLoop04Receipt = FacadeResult<"vault.receipts">["receipts"][number];
interface MuseLoop04ErrorEnvelope {
  error: {
    code: string;
    message: string;
    requestId: string;
    suggestions: string[];
    receiptRef?: string;
  };
}

// Builder-adjustable setup constants. The facade types these as plain strings
// and canon names them only in prose; each is named once here so the shipped
// spelling can be fixed in one place without touching any assertion.
const museLoop04Role: FacadeInput<"vault.models.bindings.read">["role"] = "generative_reasoner";
const museLoop04Adapter = "graph";
const museLoop04Recipe = "near_neighbourhood";
const museLoop04Profile = "default";
const museLoop04Delivery = "now";
const museLoop04OccurredAt = 1769947200;
const museLoop04IncumbentModel = "muse-loop-04-incumbent";
const museLoop04CandidateModel = "muse-loop-04-candidate";
const museLoop04Revision = "muse-loop-04-rev-1";
const museLoop04IncumbentId = `loop04_incumbent/${museLoop04IncumbentModel}@${museLoop04Revision}`;
const museLoop04CandidateId = `loop04_candidate/${museLoop04CandidateModel}@${museLoop04Revision}`;
const museLoop04CatalogRevision = "muse-loop-04-catalog-1";
const museLoop04ScoreSource = "muse-loop-04-scores";
const museLoop04Benchmark = "muse-loop-04-benchmark";
const museLoop04OutcomePredicate = "profile.muse_loop_04.outcome";
const museLoop04ProviderPath = "/v1/chat/completions";
const museLoop04DecisionWording = "Answer the typed question about the supplied graph unit and sources.";

function museLoop04Definition(
  units: readonly string[],
): FacadeInput<"vault.questions.create">["definition"] {
  return {
    question: {
      text: "Is this unit a Muse Loop 04 fixture unit?",
      class: "judgment",
      contract: { kind: "noul" },
      accept_type: true,
    },
    adapter: museLoop04Adapter,
    units: [...units],
    recipe: museLoop04Recipe,
    profile: museLoop04Profile,
    dial: { first: "big", ceiling: "big", band: { low: 0.35, high: 0.65 } },
    activation: "standing",
    refresh: { on_arrival: false },
    delivery: museLoop04Delivery,
    learning: true,
    binding: {
      source: { kind: "claim", predicate: museLoop04OutcomePredicate },
      horizon: 31536000,
      mapping: { yes: true, no: false },
      noise_weight: 1,
    },
    criteria: { yes_if_all: ["The unit is a Muse Loop 04 fixture unit."] },
    audience: "asker",
  };
}

function museLoop04GraphOnly(
  answers: readonly FacadeResult<"vault.questions.refresh">[number][],
): MuseLoop04GraphAnswer[] {
  return answers
    .flatMap((answer) => (answer.kind === "graph" ? [answer] : []))
    .sort((a, b) => a.claim.localeCompare(b.claim));
}

async function museLoop04Answers(
  client: PublicHttpClient,
  questionId: string,
): Promise<MuseLoop04GraphAnswer[]> {
  const reply = await client.call("vault.questions.answers", { id: questionId });
  return museLoop04GraphOnly(Array.isArray(reply) ? reply : reply.answers);
}

async function museLoop04AllReceipts(
  client: PublicHttpClient,
): Promise<Map<string, MuseLoop04Receipt>> {
  const found = new Map<string, MuseLoop04Receipt>();
  let after: string | undefined;
  for (;;) {
    const page = await client.call("vault.receipts", {
      limit: 1000,
      ...(after ? { after } : {}),
    } satisfies FacadeInput<"vault.receipts">);
    for (const row of page.receipts) found.set(row.receipt_ref, row);
    if (!page.next_after) return found;
    after = page.next_after;
  }
}

async function museLoop04CallReceipt(
  owner: PublicHttpClient,
  receiptRef: string,
  verb: string,
  actorClass: string,
): Promise<FacadeResult<"vault.receipts.get">> {
  const receipt = await awaitPublic(
    () => owner.call("vault.receipts.get", { receipt_ref: receiptRef }),
    (value) => value !== null,
    { label: `call receipt for ${verb}` },
  );
  if (!receipt) throw new Error(`No call receipt readable for ${verb}`);
  expect(receipt.verb).toBe(verb);
  expect(receipt.actor_class).toBe(actorClass);
  return receipt;
}

async function museLoop04ExpectRefusal(
  owner: PublicHttpClient,
  actor: PublicHttpClient,
  verb: string,
  input: unknown,
  actorClass: string,
): Promise<void> {
  const reply = await actor.raw<MuseLoop04ErrorEnvelope>(
    "POST",
    `/v1/core/facade/${verb}`,
    input,
    { "x-oneiron-invocation": secretHex(16) },
  );
  expect(reply.status).toBeGreaterThanOrEqual(400);
  expect(reply.status).toBeLessThan(500);
  const error = reply.body.error;
  if (!error) throw new Error(`Refusal of ${verb} is not the standard error envelope`);
  expect(typeof error?.code).toBe("string");
  expect(error.code.length).toBeGreaterThan(0);
  expect(typeof error?.message).toBe("string");
  expect(error.message.length).toBeGreaterThan(0);
  expect(typeof error?.requestId).toBe("string");
  expect(Array.isArray(error?.suggestions)).toBe(true);
  const receiptRef = error?.receiptRef;
  expect(typeof receiptRef).toBe("string");
  if (typeof receiptRef !== "string") throw new Error(`Refusal of ${verb} left no receiptRef`);
  const receipt = await museLoop04CallReceipt(owner, receiptRef, verb, actorClass);
  if (!receipt) throw new Error(`Refusal receipt for ${verb} vanished on read-back`);
  expect(receipt.outcome).toEqual({ refused: { code: error.code } });
}

async function museLoop04ProposeWithReceipt(
  client: PublicHttpClient,
  input: FacadeInput<"vault.models.bindings.propose">,
): Promise<{ proposal: FacadeResult<"vault.models.bindings.propose">; receiptRef: string }> {
  const reply = await client.request<FacadeResult<"vault.models.bindings.propose">>(
    "POST", "/v1/core/facade/vault.models.bindings.propose", input,
    { "x-oneiron-invocation": secretHex(16) },
  );
  expect(reply.status).toBe(200);
  const receiptRef = reply.headers.get("x-oneiron-receipt-ref");
  if (!receiptRef) throw new Error("HTTP binding proposal carried no call receipt ref");
  return { proposal: reply.body, receiptRef };
}

function museLoop04WsReceiptRef(
  frames: readonly { readonly envelope: { readonly receipt_ref?: string | null } }[],
  verb: string,
): string {
  const ref = frames
    .map((frame) => frame.envelope.receipt_ref)
    .find((value) => typeof value === "string" && value.length > 0);
  if (!ref) throw new Error(`WS ${verb} frames carry no receipt_ref`);
  return ref;
}

suite.test(
  test,
  "MUSE-LOOP-04",
  "An answerer switch is never automatic by default or on an unknown result, and an approved switch changes only future answers",
  async () => {
    // Two scripted answerer backends. Separate origins distinguish them,
    // because the wire request carries the model but no trial role.
    const providers = await ScriptedProviders.start({
      id: "MUSE-LOOP-04",
      steps: [
        {
          id: "muse-loop-04-incumbent-yes",
          origin: "incumbent",
          role: "answerer-incumbent",
          purpose: "typed-judgment",
          request: { method: "POST", path: museLoop04ProviderPath, model: museLoop04IncumbentModel },
          response: openaiText("muse-loop-04-incumbent-1", museLoop04IncumbentModel, JSON.stringify({ answer: true, probability: 0.9 }), {
            inputTokens: 100,
            outputTokens: 10,
          }),
          standing: true,
        },
        {
          id: "muse-loop-04-candidate-yes",
          origin: "candidate",
          role: "answerer-candidate",
          purpose: "typed-judgment",
          request: { method: "POST", path: museLoop04ProviderPath, model: museLoop04CandidateModel },
          response: openaiText("muse-loop-04-candidate-1", museLoop04CandidateModel, JSON.stringify({ answer: true, probability: 0.9 }), {
            inputTokens: 100,
            outputTokens: 10,
          }),
          standing: true,
        },
      ],
    });
    const incumbentUrl = providers.urls["incumbent"];
    const candidateUrl = providers.urls["candidate"];
    if (!incumbentUrl || !candidateUrl) throw new Error("Scripted answerer origins are missing");

    const engine = await EngineFixture.start({
      id: "MUSE-LOOP-04",
      profile,
      serverConfig: [
        "[models.providers.loop04_incumbent]",
        'kind = "local-openai-compat"',
        `base_url = "${incumbentUrl}"`,
        `revision = "${museLoop04Revision}"`,
        "request_compression = false",
        "",
        "[models.providers.loop04_candidate]",
        'kind = "local-openai-compat"',
        `base_url = "${candidateUrl}"`,
        `revision = "${museLoop04Revision}"`,
        "request_compression = false",
        "",
        `[models.roles.${museLoop04Role}]`,
        `model = "loop04_incumbent:${museLoop04IncumbentModel}"`,
        "",
        "[models.roles.checker]",
        `model = "loop04_candidate:${museLoop04CandidateModel}"`,
        "",
        "[models.decisions.big]",
        `role = "${museLoop04Role}"`,
        `version = "${museLoop04Revision}"`,
        `wording = ${JSON.stringify(museLoop04DecisionWording)}`,
      ].join("\n"),
    });
    const owner = engine.client;

    // Host provider config does not install a vault manifest. The pinned
    // fixture carries the bench's real teacher approval; the case never mints it.
    const manifestBefore = await owner.call("vault.models.manifest.read", {});
    expect(manifestBefore).toBeNull();
    const approvedManifest = await (await loadFixtures())
      .readJson<FacadeInput<"vault.models.manifest.replace">>("muse-loop-04-approved-model-manifest");
    await owner.call("vault.models.manifest.replace", approvedManifest);
    const installedManifest = await owner.call("vault.models.manifest.read", {});
    expect(installedManifest).toEqual(approvedManifest.manifest);
    if (!installedManifest) throw new Error("Approved model manifest did not read back");
    const reportedBinding = installedManifest.roles[museLoop04Role];
    if (!reportedBinding) throw new Error("Approved manifest has no reasoner binding");
    const incumbentBinding: MuseLoop04Binding = { ...reportedBinding, model: museLoop04IncumbentId };
    const candidateBinding: MuseLoop04Binding = { ...reportedBinding, model: museLoop04CandidateId };
    const manifest: FacadeInput<"vault.models.manifest.replace">["manifest"] = {
      ...installedManifest,
      roles: { ...installedManifest.roles, [museLoop04Role]: incumbentBinding },
    };
    await owner.call("vault.models.manifest.replace", { manifest });
    expect(await owner.call("vault.models.manifest.read", {})).toEqual(manifest);
    expect((await owner.call("vault.models.bindings.read", { role: museLoop04Role })).model)
      .toBe(museLoop04IncumbentId);
    expect((await owner.call("vault.models.roles.read", { role: museLoop04Role })).model)
      .toBe(museLoop04IncumbentId);

    // A refreshed catalog nominates the cheaper, higher-scored candidate.
    // Registry scores and a catalog refresh switch nothing by themselves.
    const catalogRow = (model: string, backend: string, price: string) => {
      const cost = { input_per_million: price, output_per_million: price, currency: "USD" };
      return {
        version: 1,
        wire: "openai-compat" as const,
        catalog: {
          model,
          display_name: model,
          locality: "own_server" as const,
          context_window_tokens: 8192,
          cost,
          capabilities: ["json_response" as const],
          metadata: {
            description: { owner_line: {
              text: "MUSE-LOOP-04 scripted model fixture", source: engine.pairedActor.principalRef,
            } },
            backends: [{
              pin: { model, backend, serving_revision: museLoop04Revision,
                quantization: null, context_window_tokens: 8192 },
              price: cost,
            }],
          },
        },
        scores: {},
        fetched_at: {},
      };
    };
    await owner.call("vault.models.catalog.refresh", {
      revision: museLoop04CatalogRevision,
      catalog: {
        version: 1,
        rows: [
          catalogRow(museLoop04IncumbentId, "loop04_incumbent", "10"),
          catalogRow(museLoop04CandidateId, "loop04_candidate", "1"),
        ],
      },
      scores: [{
        source: museLoop04ScoreSource,
        fetched_at: museLoop04OccurredAt,
        observations: [
          { model: museLoop04IncumbentId, benchmark: museLoop04Benchmark, score: 0.8 },
          { model: museLoop04CandidateId, benchmark: museLoop04Benchmark, score: 0.9 },
        ],
      }],
    } satisfies FacadeInput<"vault.models.catalog.refresh">);
    const catalog = await owner.call("vault.models.catalog.get", { revision: museLoop04CatalogRevision });
    expect(catalog.revision).toBe(museLoop04CatalogRevision);
    expect((await owner.call("vault.models.bindings.read", { role: museLoop04Role })).model)
      .toBe(museLoop04IncumbentId);

    // Three graph units and one standing question over them.
    const unitIds: string[] = [];
    for (let index = 0; index < 3; index++) {
      const unit = await owner.call("vault.structural.put", {
        kind: "PERSON",
        body: { name: `Muse Loop 04 Unit ${index}` },
        occurred_at: museLoop04OccurredAt,
      } satisfies FacadeInput<"vault.structural.put">);
      expect((await owner.call("vault.get", { entity_ref: unit.id_hex })).value)
        .toMatchObject({ kind: "PERSON", body: { name: `Muse Loop 04 Unit ${index}` } });
      unitIds.push(unit.id_hex);
    }
    const created = await owner.call("vault.questions.create", {
      definition: museLoop04Definition(unitIds),
    } satisfies FacadeInput<"vault.questions.create">);
    const questionId = created.definition.question.id;
    const questionVersion = created.definition.question.version;
    const question = await owner.call("vault.questions.read", { id: questionId });
    if (!question) throw new Error("Created standing question does not read back");
    expect(question.definition.activation).toBe("standing");
    expect([...question.definition.units].sort()).toEqual([...unitIds].sort());

    // Past answers, answered by the incumbent on the host ladder.
    const refreshed = museLoop04GraphOnly(await owner.call("vault.questions.refresh", { id: questionId }));
    expect(refreshed).toHaveLength(3);
    for (const answer of refreshed) {
      expect(answer.decision.receipt.providers.some((pin) => pin.model === museLoop04IncumbentId)).toBe(true);
      expect(answer.decision.receipt.providers.some((pin) => pin.model === museLoop04CandidateId)).toBe(false);
    }
    expect(await museLoop04Answers(owner, questionId)).toEqual(refreshed);

    // The later fact bound by the question is each unit's held-out label.
    const claimScope = await ownerBaseClaimScope(owner, engine.pairedActor.principalRef);
    for (const answer of refreshed) {
      const fact = await owner.call("vault.claims.upsert", {
        predicate: museLoop04OutcomePredicate,
        subject_ref: answer.unit,
        value: "yes",
        confidence: 1,
        source: "user_stated",
        scope: claimScope,
        occurred_at: Math.max(answer.answered_at, Math.floor(Date.now() / 1000)),
      } satisfies FacadeInput<"vault.claims.upsert">);
      await engine.awaitReceipt(fact.receipt_ref);
      // vault.get returns the stored CLAIM body, whose keys are the claim
      // codec's (pred, val), not the upsert's input names.
      expect((await owner.call("vault.get", { entity_ref: fact.claim_short_id })).value)
        .toMatchObject({ kind: "CLAIM", body: { pred: museLoop04OutcomePredicate, val: "yes" } });
    }
    await owner.call("vault.questions.outcomes.project", { id: questionId });
    const outcomes = await awaitPublic(
      () => owner.call("vault.questions.outcomes", { id: questionId }),
      (value) => value.labels.length >= 3,
      { label: "standing question outcome labels" },
    );
    const heldOut: FacadeInput<"vault.models.trials.nominate">["request"]["held_out"] =
      outcomes.labels.slice(0, 3).map((label, index) => ({
        answer: label.answer,
        fact: label.fact,
        source_family: `muse-loop-04-family-${index}`,
      }));
    expect(heldOut).toHaveLength(3);

    // The trial goal: the goal record of the seeded skill-optimize improver.
    let goalId: string | undefined;
    {
      let after: string | undefined;
      for (;;) {
        const page = await owner.call("vault.skills.list", {
          limit: 100,
          ...(after ? { after } : {}),
        } satisfies FacadeInput<"vault.skills.list">);
        const skill = page.skills.find((row) => row.skill_id === "skill-optimize");
        if (skill) {
          goalId = (await owner.call("vault.skills.optimize.goal.get", { skill: skill.entity })).goal_id;
          break;
        }
        if (!page.next_after) break;
        after = page.next_after;
      }
    }
    if (!goalId) throw new Error("No skill-optimize goal is readable for the model trial");
    const trialGoal = goalId;

    const usageBound: FacadeInput<"vault.models.trials.nominate">["request"]["incumbent_usage_bound"] = {
      input: { total: 100, cache_read: 0, cache_write: 0 },
      output: { total: 10, text: 10, reasoning: 0 },
      raw_provider: null,
    };
    const museLoop04RunTrial = async (
      selections: FacadeInput<"vault.models.trials.nominate">["request"]["held_out"],
      set: FacadeInput<"vault.models.trials.nominate">["request"]["set"],
      autoApprove: boolean | undefined,
      assessmentFor: (
        measured: MuseLoop04TrialView,
      ) => FacadeInput<"vault.models.trials.complete">["assessment"],
    ): Promise<MuseLoop04TrialView> => {
      const nominated = await owner.call("vault.models.trials.nominate", {
        catalog_revision: museLoop04CatalogRevision,
        request: {
          principal: created.principal,
          question: questionId,
          question_version: questionVersion,
          goal: trialGoal,
          incumbent: {
            model: museLoop04IncumbentId,
            backend: "loop04_incumbent",
            serving_revision: museLoop04Revision,
            context_window_tokens: 8192,
          },
          candidate: {
            model: museLoop04CandidateId,
            backend: "loop04_candidate",
            serving_revision: museLoop04Revision,
            context_window_tokens: 8192,
          },
          source: museLoop04ScoreSource,
          benchmark: museLoop04Benchmark,
          set,
          held_out: selections,
          incumbent_usage_bound: usageBound,
          candidate_usage_bound: usageBound,
          future_units: 1000,
          policy: {
            exploration_remaining: 1000000,
            ...(autoApprove === undefined ? {} : { auto_approve: autoApprove }),
            candidate_needs_download: false,
          },
        },
      } satisfies FacadeInput<"vault.models.trials.nominate">);
      let trial = await owner.call("vault.models.trials.get", { question: questionId, trial: nominated.id });
      if (trial.admission === "ask_exploration") {
        await owner.call("vault.models.trials.approve", { question: questionId, trial: trial.id });
        // Approving exploration does not itself switch the answerer.
        expect((await owner.call("vault.models.bindings.read", { role: museLoop04Role })).model)
          .toBe(museLoop04IncumbentId);
        trial = await owner.call("vault.models.trials.get", { question: questionId, trial: trial.id });
      }
      const ran = await owner.call("vault.models.trials.run", { question: questionId, trial: trial.id });
      expect(ran.execution).toBe("measured");
      expect(ran.arms_total).toBeGreaterThan(0);
      expect(ran.arms_unknown).toBe(0);
      expect(ran.arms_completed).toBe(ran.arms_total);
      const measured = await awaitPublic(
        () => owner.call("vault.models.trials.get", { question: questionId, trial: trial.id }),
        (value) => value.execution === "measured" && value.evidence != null,
        { label: "measured model trial" },
      );
      if (!measured.evidence) throw new Error("Measured trial carries no evidence");
      const completed = await owner.call("vault.models.trials.complete", {
        question: questionId,
        trial: trial.id,
        assessment: assessmentFor(measured),
      } satisfies FacadeInput<"vault.models.trials.complete">);
      const reread = await owner.call("vault.models.trials.get", { question: questionId, trial: trial.id });
      expect(reread.receipt ?? null).toEqual(completed.receipt ?? null);
      return reread;
    };

    // P-LOOP-013: on this fresh vault nothing has ever turned auto-approval
    // on, and the trial policy omits auto_approve. A cheaper candidate that
    // is not worse (paired interval low end -0.01 stays above minus the
    // 0.02 retest noise) completes as an offer, not an automatic switch.
    const trialDefault = await museLoop04RunTrial(
      heldOut,
      { id: "muse-loop-04-set", version: 1, rubric_version: "muse-loop-04-rubric-1" },
      undefined,
      (measured) => {
        const evidence = measured.evidence;
        if (!evidence) throw new Error("Measured default trial carries no evidence");
        return {
          set: measured.request.set,
          measurements_hash: evidence.measurements_hash,
          paired_gain: { low: -0.01, high: 0.02 },
          retest_noise: 0.02,
          required_families: evidence.independent_families,
          rare_slices_sufficient: true,
          versions_match: true,
          canary_diverged: false,
        };
      },
    );
    expect(trialDefault.request.policy.auto_approve ?? false).toBe(false);
    const receiptDefault = trialDefault.receipt;
    if (!receiptDefault) throw new Error("Completed default trial carries no receipt");
    expect(receiptDefault.quality).toBe("not_worse");
    expect(receiptDefault.action).toBe("offer");
    expect((await owner.call("vault.models.bindings.read", { role: museLoop04Role })).model)
      .toBe(museLoop04IncumbentId);

    // P-LOOP-014: even with auto_approve explicitly on, a comparison the set
    // cannot judge never auto-approves. This trial holds out only one of the
    // three families its card requires: too few labels reads unknown.
    const trialUnknown = await museLoop04RunTrial(
      heldOut.slice(0, 1),
      { id: "muse-loop-04-set", version: 2, rubric_version: "muse-loop-04-rubric-1" },
      true,
      (measured) => {
        const evidence = measured.evidence;
        if (!evidence) throw new Error("Measured unknown trial carries no evidence");
        expect(evidence.independent_families).toBe(1);
        return {
          set: measured.request.set,
          measurements_hash: evidence.measurements_hash,
          paired_gain: { low: -0.01, high: 0.02 },
          retest_noise: 0.02,
          required_families: 3,
          rare_slices_sufficient: true,
          versions_match: true,
          canary_diverged: false,
        };
      },
    );
    const receiptUnknown = trialUnknown.receipt;
    if (!receiptUnknown) throw new Error("Completed unknown trial carries no receipt");
    expect(receiptUnknown.quality).toBe("unknown");
    expect(receiptUnknown.action).toBe("unknown");
    expect(receiptUnknown.action).not.toBe("auto_approve");
    expect((await owner.call("vault.models.bindings.read", { role: museLoop04Role })).model)
      .toBe(museLoop04IncumbentId);

    // The agent proposes; the owner approves or refuses. Before any grant,
    // the paired agent cannot propose the switch. vault.models.bindings.propose
    // is a Write-scope verb, so the agent's credential carries core:write
    // (full-access tier); a propose-only credential (core:read, core:propose)
    // is refused at the scope check and never reaches the Grant check. The
    // tier's own Grant lists read/propose/write and names no act, so only the
    // owner's Grant below lets the agent propose.
    const agent = await engine.mintAgentToken({
      name: "muse-loop-04-agent",
      tier: "full-access",
    });
    expect((await owner.call("vault.get", { entity_ref: agent.principalRef })).value)
      .toMatchObject({ kind: "PERSON", body: { name: "muse-loop-04-agent" } });
    const proposeInputDefault = {
      question: questionId,
      trial: trialDefault.id,
      role: museLoop04Role,
      binding: candidateBinding,
    } satisfies FacadeInput<"vault.models.bindings.propose">;
    await museLoop04ExpectRefusal(
      owner,
      agent.client,
      "vault.models.bindings.propose",
      proposeInputDefault,
      agent.actorClass,
    );
    expect((await owner.call("vault.models.bindings.read", { role: museLoop04Role })).model)
      .toBe(museLoop04IncumbentId);

    // With the owner's grant naming the propose verb, the agent proposes the
    // completed offer over HTTP. The proposal activates nothing by itself.
    const minted = await owner.call("vault.agents.grants.mint", {
      agent: agent.principalRef,
      authority_scope: {
        worlds: { kind: "all" },
        facets: { kind: "all" },
        bands: { kind: "all" },
        audience: { kind: "all" },
        verbs: { kind: "some", values: ["read", "vault.models.bindings.propose", "vault.models.bindings.get"] },
        sensitivity: { kind: "all" },
      },
    } satisfies FacadeInput<"vault.agents.grants.mint">);
    expect(minted.grant.confers).toBe(true);
    expect((await owner.call("vault.get", { entity_ref: minted.grant.grant_ref })).value)
      .toMatchObject({ kind: "FEDERATION_GRANT" });
    const proposedCall = await museLoop04ProposeWithReceipt(agent.client, proposeInputDefault);
    const proposal = proposedCall.proposal;
    const proposeReceiptRef = proposedCall.receiptRef;
    const proposeReceipt = await museLoop04CallReceipt(
      owner,
      proposeReceiptRef,
      "vault.models.bindings.propose",
      agent.actorClass,
    );
    if (!proposeReceipt) throw new Error("Proposal call receipt vanished on read-back");
    expect(proposeReceipt.outcome).toBe("ok");
    expect(proposeReceipt.actor_ref).toBe(agent.principalRef);
    expect(proposal.status).toBe("proposed");
    expect(proposal.role).toBe(museLoop04Role);
    expect(proposal.previous.model).toBe(museLoop04IncumbentId);
    expect(proposal.proposed.model).toBe(museLoop04CandidateId);
    expect(proposal.trial.id).toBe(trialDefault.id);
    const proposalRead = await owner.call("vault.models.bindings.get", { proposal: proposal.id });
    expect(proposalRead.status).toBe("proposed");
    expect(proposalRead.proposed.model).toBe(museLoop04CandidateId);
    expect((await owner.call("vault.models.bindings.read", { role: museLoop04Role })).model)
      .toBe(museLoop04IncumbentId);

    // The agent cannot approve its own proposal; approval is the owner's.
    await museLoop04ExpectRefusal(
      owner,
      agent.client,
      "vault.models.bindings.accept",
      { proposal: proposal.id } satisfies FacadeInput<"vault.models.bindings.accept">,
      agent.actorClass,
    );
    expect((await owner.call("vault.models.bindings.get", { proposal: proposal.id })).status)
      .toBe("proposed");
    expect((await owner.call("vault.models.bindings.read", { role: museLoop04Role })).model)
      .toBe(museLoop04IncumbentId);

    // Losing the grant mid-flow ends the agent's proposing at its next use.
    const revoked = await owner.call("vault.agents.grants.revoke", {
      grant_ref: minted.grant.grant_ref,
    } satisfies FacadeInput<"vault.agents.grants.revoke">);
    expect(revoked.changed).toBe(true);
    await museLoop04ExpectRefusal(
      owner,
      agent.client,
      "vault.models.bindings.propose",
      {
        question: questionId,
        trial: trialUnknown.id,
        role: museLoop04Role,
        binding: candidateBinding,
      } satisfies FacadeInput<"vault.models.bindings.propose">,
      agent.actorClass,
    );
    expect((await owner.call("vault.models.bindings.read", { role: museLoop04Role })).model)
      .toBe(museLoop04IncumbentId);

    // Snapshot everything the approved switch must not rewrite, then the
    // owner accepts the standing proposal over WS.
    const pastAnswers = await museLoop04Answers(owner, questionId);
    expect(pastAnswers).toEqual(refreshed);
    const pastSnapshot = JSON.parse(JSON.stringify(pastAnswers)) as MuseLoop04GraphAnswer[];
    const pastClaims = new Set(pastSnapshot.map((answer) => answer.claim));
    const receiptsBeforeAccept = await museLoop04AllReceipts(owner);

    const ownerSocket = await engine.websocket();
    const acceptedCall = await ownerSocket.call("vault.models.bindings.accept", {
      proposal: proposal.id,
    } satisfies FacadeInput<"vault.models.bindings.accept">);
    ownerSocket.close();
    const accepted = acceptedCall.value;
    const acceptReceiptRef = museLoop04WsReceiptRef(
      acceptedCall.frames,
      "vault.models.bindings.accept",
    );
    const acceptReceipt = await museLoop04CallReceipt(
      owner,
      acceptReceiptRef,
      "vault.models.bindings.accept",
      engine.pairedActor.actorClass,
    );
    if (!acceptReceipt) throw new Error("Accept call receipt vanished on read-back");
    expect(acceptReceipt.outcome).toBe("ok");
    expect(acceptReceipt.actor_ref).toBe(engine.pairedActor.principalRef);
    expect(accepted.status).toBe("accepted");
    const acceptedRead = await owner.call("vault.models.bindings.get", { proposal: proposal.id });
    expect(acceptedRead.status).toBe("accepted");
    expect(acceptedRead.previous.model).toBe(museLoop04IncumbentId);
    expect(acceptedRead.proposed.model).toBe(museLoop04CandidateId);
    expect((await owner.call("vault.models.bindings.read", { role: museLoop04Role })).model)
      .toBe(museLoop04CandidateId);
    expect((await owner.call("vault.models.roles.read", { role: museLoop04Role })).model)
      .toBe(museLoop04CandidateId);

    // Past answers and past receipts are byte-for-byte the records they were.
    const museLoop04ExpectPastUnchanged = async (): Promise<void> => {
      const answersNow = await museLoop04Answers(owner, questionId);
      expect(answersNow.filter((answer) => pastClaims.has(answer.claim))).toEqual(pastSnapshot);
      const receiptsNow = await museLoop04AllReceipts(owner);
      for (const [ref, before] of receiptsBeforeAccept) {
        expect(receiptsNow.get(ref)).toEqual(before);
      }
    };
    await museLoop04ExpectPastUnchanged();

    // The switch, both trial receipts and the past answers survive a restart.
    await engine.restart();
    expect((await owner.call("vault.models.bindings.read", { role: museLoop04Role })).model)
      .toBe(museLoop04CandidateId);
    expect((await owner.call("vault.models.bindings.get", { proposal: proposal.id })).status)
      .toBe("accepted");
    const trialDefaultAfter = await owner.call("vault.models.trials.get", {
      question: questionId,
      trial: trialDefault.id,
    });
    expect(trialDefaultAfter.receipt).toEqual(receiptDefault);
    const trialUnknownAfter = await owner.call("vault.models.trials.get", {
      question: questionId,
      trial: trialUnknown.id,
    });
    expect(trialUnknownAfter.receipt).toEqual(receiptUnknown);
    await museLoop04ExpectPastUnchanged();

    // P-LOOP-015, future side: a unit the question only covers after the
    // switch is answered by the candidate, stamped on its receipt.
    const futureUnit = await owner.call("vault.structural.put", {
      kind: "PERSON",
      body: { name: "Muse Loop 04 Future Unit" },
      occurred_at: museLoop04OccurredAt,
    } satisfies FacadeInput<"vault.structural.put">);
    expect((await owner.call("vault.get", { entity_ref: futureUnit.id_hex })).value)
      .toMatchObject({ kind: "PERSON", body: { name: "Muse Loop 04 Future Unit" } });
    const edited = await owner.call("vault.questions.edit", {
      id: questionId,
      expected_version: questionVersion,
      definition: museLoop04Definition([...unitIds, futureUnit.id_hex]),
    } satisfies FacadeInput<"vault.questions.edit">);
    const futureVersion = edited.definition.question.version;
    expect(futureVersion).not.toBe(questionVersion);
    expect(await owner.call("vault.questions.read", { id: questionId })).toEqual(edited);
    const futureRefreshed = museLoop04GraphOnly(
      await owner.call("vault.questions.refresh", { id: questionId }),
    );
    const futureAnswer = futureRefreshed.find((answer) => answer.unit === futureUnit.id_hex);
    if (!futureAnswer) throw new Error("No future answer for the unit added after the switch");
    expect(futureAnswer.decision.receipt.question_version).toBe(futureVersion);
    expect(futureAnswer.decision.receipt.providers.some((pin) => pin.model === museLoop04CandidateId))
      .toBe(true);
    expect(futureAnswer.decision.receipt.providers.some((pin) => pin.model === museLoop04IncumbentId))
      .toBe(false);
    expect((await museLoop04Answers(owner, questionId))
      .some((answer) => answer.claim === futureAnswer.claim)).toBe(true);
    await museLoop04ExpectPastUnchanged();
  },
);

// ---- MUSE-LOOP-05 (Muse Wonder Full, ported 10 Nov) ----
// MUSE-LOOP-05 — P-LOOP-016, P-LOOP-017, P-LOOP-018, P-LOOP-019.
// Doors used: ask, wait, peek, tasks.answer, describe (second-door status),
// vault.witness / vault.conversations.create / vault.structural.put / vault.get
// (public setup), vault.receipts.get (refusal receipt), vault.authority.audit
// + POST /v1/core/slips/revoke (grant loss), engine.restart() (durability).
// Proved here: one agent asks the owner three typed questions; the first wait
// stays pending across a restart and resumes Ready on the owner's matching
// tasks.answer word; the other two are never answered and each settles at its
// own deadline with its own declared default branch (proceed vs hold).
// Not proved: P-LOOP-018's one Decision Prompt card for a batched round trip,
// and one-call batched admission. No typed facade input takes a list of asks
// and no typed read returns one Decision Prompt card carrying N asks, so this
// case creates the asks with separate ask calls and never asserts a card.
// P-LOOP-016's literal in-program code-mode tasks.wait set form is likewise
// not a FacadeVerb; this case uses the typed public equivalents ask / wait /
// peek / tasks.answer, one handle at a time.

type museLoop05AuditRow = FacadeResult<"vault.authority.audit">["rows"][number];
type museLoop05AskHandle = FacadeResult<"ask">["handle"];
type museLoop05AskResult = Extract<FacadeResult<"wait">, { Ready: unknown }>["Ready"];
type museLoop05Snapshot = Extract<
  Extract<FacadeResult<"describe">, { kind: "task_status" }>["receipt"]["outcome"],
  { kind: "snapshot" }
>;
interface museLoop05RefusalEnvelope {
  error: { code: string; message: string; receiptRef?: string };
}

async function museLoop05AuditRows(client: PublicHttpClient): Promise<museLoop05AuditRow[]> {
  const rows: museLoop05AuditRow[] = [];
  let after: string | undefined;
  for (;;) {
    const query: FacadeInput<"vault.authority.audit"> = { limit: 500, ...(after ? { after } : {}) };
    const page = await client.call("vault.authority.audit", query);
    rows.push(...page.rows);
    if (!page.next_after) return rows;
    after = page.next_after;
  }
}

function museLoop05MintedSlip(
  before: readonly museLoop05AuditRow[],
  afterRows: readonly museLoop05AuditRow[],
  holder: string,
): museLoop05AuditRow {
  const existing = new Set(before.map((row) => row.entry_hash));
  const minted = afterRows.filter((row) => !existing.has(row.entry_hash)
    && row.source_op === "slip_mint" && row.holder_ref === holder);
  const row = minted[0]!;
  return row;
}

async function museLoop05SnapshotFor(
  client: PublicHttpClient,
  handle: museLoop05AskHandle,
): Promise<museLoop05Snapshot> {
  const described = await client.call("describe", {
    handle: { kind: "ask", group_ref: handle.group_ref },
  } satisfies FacadeInput<"describe">);
  if (described.kind !== "task_status") {
    throw new Error(`MUSE-LOOP-05 describe(ask handle) returned ${described.kind}, not task_status`);
  }
  const outcome = described.receipt.outcome;
  if (outcome.kind !== "snapshot") {
    throw new Error(`MUSE-LOOP-05 describe(ask handle) outcome is ${outcome.kind}, not snapshot`);
  }
  return outcome;
}

function museLoop05AskStatusIn(snapshot: museLoop05Snapshot, handle: museLoop05AskHandle) {
  const pair = snapshot.asks.find(([candidate]) => candidate.group_ref === handle.group_ref);
  if (!pair) throw new Error("MUSE-LOOP-05 snapshot does not carry the ask handle it described");
  const [, status] = pair;
  return status;
}

function museLoop05PhaseIsAsked(snapshot: museLoop05Snapshot, settled: boolean): boolean {
  const phase = snapshot.phase;
  return phase.phase === "asked" && phase.settled === settled;
}

function museLoop05ReadyResult(waited: FacadeResult<"wait">): museLoop05AskResult {
  if ("Ready" in waited) return waited.Ready;
  throw new Error(`MUSE-LOOP-05 wait did not resume Ready; variant: ${Object.keys(waited).join(",")}`);
}

async function museLoop05WaitReady(
  client: PublicHttpClient,
  handle: museLoop05AskHandle,
  stepKey: string,
): Promise<museLoop05AskResult> {
  const first = await client.call("wait", { handle, step_key: stepKey });
  if ("Ready" in first) return first.Ready;
  // Settlement may be swept rather than settled by the wait itself. Only the
  // describe READ is repeated here; the second wait is the resuming act.
  await awaitPublic(
    () => museLoop05SnapshotFor(client, handle),
    (snapshot) => museLoop05PhaseIsAsked(snapshot, true),
    { label: "MUSE-LOOP-05 ask settlement after wait", timeoutMs: LIMITS.requestMs },
  );
  return museLoop05ReadyResult(await client.call("wait", { handle, step_key: stepKey }));
}

function museLoop05ExpectNoWord(rows: FacadeResult<"peek">): void {
  expect(rows.every((row) => row.kind !== "word" && row.answer == null)).toBe(true);
}

function museLoop05AskInput(
  ownerRef: string,
  turnId: string,
  label: string,
  options: Record<string, { label: string }>,
  until: number,
  defaultBranch: "proceed" | "hold",
): FacadeInput<"ask"> {
  return {
    who: { people: [ownerRef] },
    what: { reference: { turn: turnId }, revision: 1, options, context_refs: [], label },
    until,
    default: defaultBranch,
  };
}

function museLoop05ExpectDeadlineDefault(
  result: museLoop05AskResult,
  handle: museLoop05AskHandle,
  expectedBranch: "proceed" | "hold",
): void {
  expect(result.settlement.group_ref).toBe(handle.group_ref);
  expect(result.settlement.reason).toBe("deadline");
  expect(result.fallback?.branch).toBe(expectedBranch);
  expect(result.coverage.met).toBe(false);
  expect(result.coverage.responded).toHaveLength(0);
  expect(result.evidence.every((entry) => entry.reason !== "counted")).toBe(true);
}

suite.test(test, "MUSE-LOOP-05", "A human-time ask survives restart and resumes on the owner's answer while unanswered asks take their own deadline defaults", async () => {
  const engine = await EngineFixture.start({ id: "MUSE-LOOP-05", profile });
  try {
    const occurred = 1769947200;
    const deadlineLeadSeconds = 5;
    const futureUntil = 1893456000;
    const q1Text = "MUSE-LOOP-05 first question: which cuisine should we book?";
    const q2Text = "MUSE-LOOP-05 second question: may the summary be sent?";
    const q3Text = "MUSE-LOOP-05 third question: may the note be published?";
    const answerText = "MUSE-LOOP-05 owner answer: Japanese";
    redactor.add(q1Text, q2Text, q3Text, answerText);

    const ownerPrincipal = engine.pairedActor.principalRef;
    const ownerView = await engine.client.call("vault.get", { entity_ref: ownerPrincipal });
    const ownerRef = ownerView.value?.id_hex ?? ownerPrincipal;
    const ownerForms = [ownerPrincipal, ownerRef];

    const askerRecord = await engine.client.call("vault.structural.put", {
      kind: "PERSON", body: { name: "MUSE-LOOP-05 Asker Agent" }, occurred_at: occurred,
    });
    const readerRecord = await engine.client.call("vault.structural.put", {
      kind: "PERSON", body: { name: "MUSE-LOOP-05 Read Only Agent" }, occurred_at: occurred,
    });
    const beforeAskerPair = await museLoop05AuditRows(engine.client);
    const asker = await engine.pairActor({
      principalRef: askerRecord.id_hex, actorClass: "agent", scope: ["core:read", "core:write"],
    });
    await museLoopGrantAskAuthority(engine.client, asker.principalRef);
    const askerSlip = museLoop05MintedSlip(
      beforeAskerPair, await museLoop05AuditRows(engine.client), askerRecord.id_hex,
    );
    const reader = await engine.pairActor({
      principalRef: readerRecord.id_hex, actorClass: "agent", scope: ["core:read"],
    });

    const conversation = await engine.client.call("vault.conversations.create", {
      body: { members: [ownerPrincipal, asker.principalRef, reader.principalRef] },
      occurred_start: occurred, occurred_end: occurred,
    });
    const museLoop05WitnessTurn = async (content: string): Promise<FacadeResult<"vault.witness">> => {
      const witnessed = await engine.client.call("vault.witness", {
        conversation_ref: conversation.id,
        occurred_at: occurred,
        messages: [{ author: "user", message_type: "text", is_visible: true, order: 0, content }],
      } satisfies FacadeInput<"vault.witness">);
      const savedTurn = await engine.client.call("vault.get", { entity_ref: witnessed.turn_id });
      expect(savedTurn.value?.kind).toBe("TURN");
      expect(savedTurn.value?.id_hex).toBe(witnessed.turn_id);
      expect(witnessed.message_short_ids).toHaveLength(1);
      const messageRef = witnessed.message_short_ids[0];
      if (!messageRef) throw new Error("Witness returned no message reference");
      const savedMessage = await engine.client.call("vault.get", { entity_ref: messageRef });
      expect(savedMessage.value?.kind).toBe("MESSAGE");
      expect(savedMessage.value?.body).toEqual(expect.objectContaining({ content }));
      return witnessed;
    };
    const q1Turn = await museLoop05WitnessTurn(q1Text);
    const q2Turn = await museLoop05WitnessTurn(q2Text);
    const q3Turn = await museLoop05WitnessTurn(q3Text);
    const q1Source = await asker.client.call("vault.get", { entity_ref: q1Turn.turn_short_id });
    expect(q1Source.value?.kind).toBe("TURN");
    expect(q1Source.value?.id_hex).toBe(q1Turn.turn_id);

    // Act: the agent asks the human owner three typed questions. The first is
    // answered after the restart below; the last two are never answered and
    // carry different declared defaults under short, future deadlines.
    const q1 = await asker.client.call("ask", museLoop05AskInput(
      ownerRef, q1Turn.turn_id, "Which cuisine should we book?",
      { japanese: { label: "Japanese" }, any: { label: "Any cuisine" } }, futureUntil, "hold",
    ));
    const q2 = await asker.client.call("ask", museLoop05AskInput(
      ownerRef, q2Turn.turn_id, "May the summary be sent?",
      { send: { label: "Send the summary" }, keep_draft: { label: "Keep it a draft" } },
      Math.floor(Date.now() / 1000) + deadlineLeadSeconds, "proceed",
    ));
    const q3 = await asker.client.call("ask", museLoop05AskInput(
      ownerRef, q3Turn.turn_id, "May the note be published?",
      { publish: { label: "Publish the note" }, keep_private: { label: "Keep it private" } },
      Math.floor(Date.now() / 1000) + deadlineLeadSeconds + 1, "hold",
    ));
    for (const receipt of [q1, q2, q3]) {
      expect(receipt.handle.group_ref.length).toBeGreaterThan(0);
      expect(receipt.task_refs.length).toBeGreaterThanOrEqual(1);
    }
    expect(new Set([q1.handle.group_ref, q2.handle.group_ref, q3.handle.group_ref]).size).toBe(3);

    // The human-time wait does not resolve and does not hold a result: it
    // reports pending (or a durable park for a code-mode step), peek shows
    // no word, and the owner reads the same unsettled ask through describe.
    const firstWait = await asker.client.call("wait", {
      handle: q1.handle, step_key: "muse-loop-05-q1-step",
    });
    expect("Ready" in firstWait).toBe(false);
    expect("WorldPrivacyReady" in firstWait).toBe(false);
    expect("Pending" in firstWait || "Park" in firstWait).toBe(true);
    if ("Park" in firstWait) expect(firstWait.Park.reason).toBe("HumanInput");
    museLoop05ExpectNoWord(await asker.client.call("peek", q1.handle));
    const beforeRestart = await museLoop05SnapshotFor(engine.client, q1.handle);
    expect(museLoop05PhaseIsAsked(beforeRestart, false)).toBe(true);
    expect("Pending" in museLoop05AskStatusIn(beforeRestart, q1.handle)).toBe(true);

    // Wrong actor: an agent holding only a read scope may not admit an
    // answer word. The refusal envelope and the refusal receipt both name
    // the attempted verb, the agent, and the refusal code; no word lands.
    const deniedAnswer = await reader.client.raw<museLoop05RefusalEnvelope>(
      "POST", "/v1/core/facade/tasks.answer", {
        handle: q1.handle, word: { result_ref: q1Turn.turn_id, option: "any" },
      } satisfies FacadeInput<"tasks.answer">,
    );
    expect(deniedAnswer.status).toBe(403);
    expect(deniedAnswer.body.error.code.length).toBeGreaterThan(0);
    expect(deniedAnswer.body.error.message.length).toBeGreaterThan(0);
    const refusalReceiptRef = deniedAnswer.body.error.receiptRef;
    if (!refusalReceiptRef) throw new Error("MUSE-LOOP-05 tasks.answer refusal carries no receiptRef");
    const refusedReceipt = await awaitPublic(
      () => engine.client.call("vault.receipts.get", { receipt_ref: refusalReceiptRef }),
      (receipt) => receipt !== null,
      { label: "MUSE-LOOP-05 refusal call receipt", timeoutMs: LIMITS.requestMs },
    );
    if (!refusedReceipt) throw new Error("MUSE-LOOP-05 refusal call receipt never readable");
    expect(refusedReceipt.verb).toBe("tasks.answer");
    expect(refusedReceipt.actor_class).toBe("agent");
    expect(refusedReceipt.actor_ref).toBe(reader.principalRef);
    const refusedOutcome = refusedReceipt.outcome;
    if (typeof refusedOutcome === "string") {
      throw new Error("MUSE-LOOP-05 refusal receipt outcome is not a refusal");
    }
    expect(refusedOutcome.refused.code).toBe(deniedAnswer.body.error.code);
    museLoop05ExpectNoWord(await asker.client.call("peek", q1.handle));

    await engine.artifacts.json("muse-loop-05-before-restart.json", {
      asks: [q1.handle, q2.handle, q3.handle],
      firstWaitVariant: Object.keys(firstWait),
      refusalReceiptRef,
    });

    // The three waits are durable. Nothing about them settles in the restart.
    await engine.restart();
    museLoop05ExpectNoWord(await asker.client.call("peek", q1.handle));
    const afterRestart = await museLoop05SnapshotFor(engine.client, q1.handle);
    expect(museLoop05PhaseIsAsked(afterRestart, false)).toBe(true);
    expect("Pending" in museLoop05AskStatusIn(afterRestart, q1.handle)).toBe(true);

    // Each unanswered ask takes its own declared default at its deadline:
    // proceed for the second, hold for the third, and never as the owner's
    // counted word or as an effect approval.
    museLoop05ExpectNoWord(await asker.client.call("peek", q2.handle));
    const q2Result = await museLoop05WaitReady(asker.client, q2.handle, "muse-loop-05-q2-step");
    museLoop05ExpectDeadlineDefault(q2Result, q2.handle, "proceed");
    const q3Result = await museLoop05WaitReady(asker.client, q3.handle, "muse-loop-05-q3-step");
    museLoop05ExpectDeadlineDefault(q3Result, q3.handle, "hold");
    expect(q2Result.fallback?.branch).not.toBe(q3Result.fallback?.branch);
    const q2Settled = await museLoop05SnapshotFor(engine.client, q2.handle);
    expect(museLoop05PhaseIsAsked(q2Settled, true)).toBe(true);
    expect("Settled" in museLoop05AskStatusIn(q2Settled, q2.handle)).toBe(true);
    const q3Settled = await museLoop05SnapshotFor(engine.client, q3.handle);
    expect(museLoop05PhaseIsAsked(q3Settled, true)).toBe(true);
    expect("Settled" in museLoop05AskStatusIn(q3Settled, q3.handle)).toBe(true);

    // The owner answers the first question on human time, after the restart.
    const answerTurn = await museLoop05WitnessTurn(answerText);
    const answered = await engine.client.call("tasks.answer", {
      handle: q1.handle,
      word: {
        result_ref: answerTurn.turn_id, option: "japanese",
        provenance_refs: [{ turn: q1Turn.turn_id }],
      },
    } satisfies FacadeInput<"tasks.answer">);
    expect(answered.result_ref).toBe(answerTurn.turn_id);
    expect(q1.task_refs).toContain(answered.task_ref);
    expect(ownerForms).toContain(answered.actor_ref);
    expect(answered.word_ref.length).toBeGreaterThan(0);

    const peekAfterAnswer = await asker.client.call("peek", q1.handle);
    const ownerWord = peekAfterAnswer.find(
      (entry) => entry.kind === "word" && ownerForms.includes(entry.who),
    );
    if (!ownerWord) throw new Error("MUSE-LOOP-05 peek shows no owner word after tasks.answer");
    expect(ownerWord.answer?.option).toBe("japanese");
    expect(ownerWord.answer?.result_ref).toBe(answerTurn.turn_id);

    // The matching answer resumes the waiting step: Ready, coverage met by
    // the owner, the counted word carrying the picked option by reference,
    // and no deadline default taken.
    const q1Result = await museLoop05WaitReady(asker.client, q1.handle, "muse-loop-05-q1-step");
    expect(q1Result.settlement.group_ref).toBe(q1.handle.group_ref);
    expect(["first_word", "all_responded"]).toContain(q1Result.settlement.reason);
    expect(q1Result.coverage.met).toBe(true);
    expect(q1Result.coverage.responded.some((ref) => ownerForms.includes(ref))).toBe(true);
    expect(q1Result.fallback ?? null).toBeNull();
    const counted = q1Result.evidence.find(
      (entry) => entry.reason === "counted" && entry.word.option === "japanese",
    );
    if (!counted) throw new Error("MUSE-LOOP-05 Ready result carries no counted owner word");
    expect(counted.word.result_ref).toBe(answerTurn.turn_id);
    expect(counted.answer.result_ref).toBe(answerTurn.turn_id);
    expect(ownerForms).toContain(counted.answer.actor_ref);
    expect(ownerForms).toContain(counted.person_ref);

    const q1Settled = await museLoop05SnapshotFor(engine.client, q1.handle);
    expect(museLoop05PhaseIsAsked(q1Settled, true)).toBe(true);
    const q1Status = museLoop05AskStatusIn(q1Settled, q1.handle);
    expect("Settled" in q1Status).toBe(true);
    if ("Settled" in q1Status) {
      expect(q1Status.Settled.settlement.group_ref).toBe(q1.handle.group_ref);
      expect(q1Status.Settled.evidence.some(
        (entry) => entry.reason === "counted" && entry.word.option === "japanese",
      )).toBe(true);
    }
    await engine.artifacts.json("muse-loop-05-results.json", {
      answered, q1: q1Result, q2: q2Result, q3: q3Result,
    });

    // Losing the grant mid-flow: once the owner revokes the asking agent's
    // slip, the same waiting step that resumed above is refused as an
    // unauthenticated caller, the authority log keeps the revoke, and the
    // settled ask remains readable by the owner.
    const slipId = askerSlip.subject_ref!;
    const revoked = await engine.client.request<{ revoked: boolean }>(
      "POST", "/v1/core/slips/revoke", { slip_id: Array.from(Buffer.from(slipId, "hex")) },
    );
    const revokedWait = await asker.client.raw<museLoop05RefusalEnvelope>(
      "POST", "/v1/core/facade/wait", { handle: q1.handle, step_key: "muse-loop-05-q1-step" },
    );
    const finalAudit = await museLoop05AuditRows(engine.client);
    const controlled = await museLoop05SnapshotFor(engine.client, q1.handle);
  } finally {
    await engine.close();
  }
});

// ---- MUSE-LOOP-06 (Muse Wonder Full, ported 10 Nov) ----
// MUSE-LOOP-06 (PARTIAL) — P-LOOP-009 only.
// Promise proved: a feedback proposal that quotes vault text asks the owner
// before sending. The case drives that ask at the disclosure gate: the quoted
// text is absent from the outbound payload until the owner approves, stays
// absent when the owner denies, crosses only after an owner approval, stops
// asking under an owner standing grant, and asks again after that grant is
// revoked.
// Doors used: vault.structural.put + EngineFixture.pairActor (public actor
// setup), vault.conversations.create, vault.witness, vault.get,
// vault.reports.route, report, vault.reports.outbound, feedback.preview,
// vault.reports.disclosure, vault.consent.revoke, vault.receipts, and
// EngineFixture.restart.
// Unproved, with the missing doors named in the report: P-LOOP-020 (no typed
// door links an interactive conversation attempt to a spend lease, a budget
// exhaustion act, and a budget-digest read), P-LOOP-021 (no typed send-grant
// mode per_send / per_batch / none; ARCH-0046 #send-grant is "Ruled, not
// built"), and P-LOOP-022 in full (no typed OutboundReceipt read by intent
// and no deterministic host transport to produce degraded, suppressed and
// let_go outcomes). The actual feedback.send crossing is also unproved: a
// fresh vault has no deterministic local publisher destination, so this case
// stops at the payload that vault.reports.outbound says a publisher delivery
// would carry now. It never touches a real network endpoint.

function museLoop06Object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Expected a public JSON object (body withheld)");
  }
  return value as Record<string, unknown>;
}

function museLoop06ExpectAbsent(value: unknown, sentinel: string): void {
  // Boolean form keeps the generated sentinel out of assertion diagnostics.
  expect((JSON.stringify(value) ?? "").includes(sentinel)).toBe(false);
}


interface MuseLoop06FiledProposal {
  readonly issueRef: string;
  readonly subjectRef: string;
  readonly messageRef: string;
  readonly disclosure: FacadeResult<"report">["disclosure"];
  readonly disclosureBasis: FacadeResult<"report">["disclosure_basis"];
}

async function museLoop06FileQuotingProposal(args: {
  engine: EngineFixture;
  agent: PairedActor;
  publisherRef: string;
  conversationId: string;
  sentinel: string;
  occurredAt: number;
}): Promise<MuseLoop06FiledProposal> {
  redactor.add(args.sentinel);
  const witnessed = await args.engine.client.call("vault.witness", {
    conversation_ref: args.conversationId,
    occurred_at: args.occurredAt,
    messages: [{
      author: "user", message_type: "text", is_visible: true, order: 0,
      content: `Vault note: ${args.sentinel}`,
    }],
  } satisfies FacadeInput<"vault.witness">);
  const messageShortId = witnessed.message_short_ids[0];
  if (!messageShortId) throw new Error("Witness returned no message reference");
  const message = await args.engine.client.call("vault.get", {
    entity_ref: messageShortId,
  } satisfies FacadeInput<"vault.get">);
  const messageValue = message.value;
  if (!messageValue) throw new Error("Witnessed vault text is not publicly readable");
  const content = museLoop06Object(messageValue.body).content;
  expect(typeof content === "string" && content.includes(args.sentinel)).toBe(true);
  const turn = await args.engine.client.call("vault.get", {
    entity_ref: witnessed.turn_short_id,
  } satisfies FacadeInput<"vault.get">);
  const turnValue = turn.value;
  if (!turnValue || turnValue.kind !== "TURN") {
    throw new Error("Witnessed TURN is not publicly readable");
  }
  const subjectRef = turnValue.id_hex;
  const messageRef = messageValue.id_hex;
  const routed = await args.engine.client.call("vault.reports.route", {
    subject_ref: subjectRef,
    route: { destination: "publisher", publisher_ref: args.publisherRef },
  } satisfies FacadeInput<"vault.reports.route">);
  expect(routed.updated).toBe(true);
  expect(routed.subject_ref).toBe(subjectRef);
  expect(routed.route).toEqual({
    destination: "publisher", publisher_ref: args.publisherRef,
  });
  const filed = await args.agent.client.call("report", {
    subject_ref: subjectRef,
    category: "skill_defect",
    kind: "proposal",
    note: `This proposal quotes vault text: ${args.sentinel}`,
    evidence_refs: [messageRef],
    why: "The quoted wording in the witnessed turn is the defect to fix.",
    proposal: {
      problem: `The witnessed turn says "${args.sentinel}" and that wording is wrong.`,
      fix: `Change the wording that produced "${args.sentinel}".`,
    },
  } satisfies FacadeInput<"report">);
  if (!filed.issue_ref) throw new Error("Report returned no issue reference");
  expect(filed.route).toEqual({
    destination: "publisher", publisher_ref: args.publisherRef,
  });
  return {
    issueRef: filed.issue_ref,
    subjectRef,
    messageRef,
    disclosure: filed.disclosure,
    disclosureBasis: filed.disclosure_basis,
  };
}

async function museLoop06Outbound(engine: EngineFixture, issueRef: string) {
  return engine.client.call("vault.reports.outbound", {
    issue_ref: issueRef,
  } satisfies FacadeInput<"vault.reports.outbound">);
}

async function museLoop06Preview(engine: EngineFixture, issueRef: string) {
  const preview = await engine.client.call("feedback.preview", {
    issue_ref: issueRef, category: "bug", include_text: true,
  } satisfies FacadeInput<"feedback.preview">);
  // Nothing leaves before the owner approves a send: the local collector
  // sees no request after any preview.
  expect(engine.feedbackRequests).toHaveLength(0);
  return preview;
}

async function museLoop06ExpectUndisclosed(
  engine: EngineFixture, issueRef: string, sentinel: string,
): Promise<void> {
  const view = await museLoop06Outbound(engine, issueRef);
  expect(view.issue_ref).toBe(issueRef);
  expect(view.payload?.disclosed ?? null).toBeNull();
  museLoop06ExpectAbsent(view, sentinel);
}

async function museLoop06ExpectDisclosed(
  engine: EngineFixture, filed: MuseLoop06FiledProposal, sentinel: string,
): Promise<void> {
  const view = await museLoop06Outbound(engine, filed.issueRef);
  expect(view.issue_ref).toBe(filed.issueRef);
  const disclosed = view.payload?.disclosed;
  if (!disclosed) throw new Error("Approved report has no disclosed outbound payload");
  expect(disclosed.subject_ref).toBe(filed.subjectRef);
  expect(disclosed.kind).toBe("proposal");
  expect(disclosed.proposal?.problem.includes(sentinel) ?? false).toBe(true);
}

suite.test(test, "MUSE-LOOP-06", "A feedback proposal that quotes vault text asks the owner before sending", async () => {
  const engine = await EngineFixture.start({
    id: "MUSE-LOOP-06", profile, feedbackDestination: "local-collector",
  });
  const occurredAt = 1769947200;
  const sentinel1 = `muse loop 06 vault quote ${secretHex(8)}`;
  redactor.add(sentinel1);
  const sentinel2 = `muse loop 06 vault quote ${secretHex(8)}`;
  redactor.add(sentinel2);
  const sentinel3 = `muse loop 06 vault quote ${secretHex(8)}`;
  redactor.add(sentinel3);
  const sentinel4 = `muse loop 06 vault quote ${secretHex(8)}`;
  redactor.add(sentinel4);

  const agentRecord = await engine.client.call("vault.structural.put", {
    kind: "PERSON", body: { name: "Muse Loop 06 Agent" }, occurred_at: occurredAt,
  } satisfies FacadeInput<"vault.structural.put">);
  const agent = await engine.pairActor({
    principalRef: agentRecord.id_hex, actorClass: "agent",
    scope: ["core:read", "core:write"],
  });
  const publisherRecord = await engine.client.call("vault.structural.put", {
    kind: "PERSON", body: { name: "Muse Loop 06 Publisher" }, occurred_at: occurredAt,
  } satisfies FacadeInput<"vault.structural.put">);
  const publisherRef = publisherRecord.id_hex;
  const conversation = await engine.client.call("vault.conversations.create", {
    body: { members: [engine.pairedActor.principalRef, agent.principalRef] },
    occurred_start: occurredAt, occurred_end: occurredAt,
  } satisfies FacadeInput<"vault.conversations.create">);
  const common = {
    engine, agent, publisherRef, conversationId: conversation.id, occurredAt,
  };

  // First proposal: the owner is asked, an agent cannot answer for the owner,
  // and an owner denial keeps the quoted text inside the vault.
  const first = await museLoop06FileQuotingProposal({ ...common, sentinel: sentinel1 });
  expect(first.disclosure).toBe("needs_approval");
  await museLoop06ExpectUndisclosed(engine, first.issueRef, sentinel1);
  const firstPreview = await museLoop06Preview(engine, first.issueRef);
  expect(firstPreview.issue_ref).toBe(first.issueRef);
  expect(firstPreview.subject_ref).toBe(first.subjectRef);
  expect(firstPreview.publisher_ref).toBe(publisherRef);
  expect(firstPreview.disclosure).toBe("needs_approval");
  const agentApprove = await agent.client.raw<{
    error?: { code?: string; message?: string };
  }>("POST", "/v1/core/facade/vault.reports.disclosure", {
    issue_ref: first.issueRef, choice: "approve_once",
  } satisfies FacadeInput<"vault.reports.disclosure">);
  expect(agentApprove.status).toBe(403);
  expect(typeof agentApprove.body.error?.code).toBe("string");
  expect((agentApprove.body.error?.code ?? "").length).toBeGreaterThan(0);
  await museLoop06ExpectUndisclosed(engine, first.issueRef, sentinel1);
  const denied = await engine.client.call("vault.reports.disclosure", {
    issue_ref: first.issueRef, choice: "deny",
  } satisfies FacadeInput<"vault.reports.disclosure">);
  expect(denied.issue_ref).toBe(first.issueRef);
  expect(denied.disclosure).toBe("denied");
  await museLoop06ExpectUndisclosed(engine, first.issueRef, sentinel1);
  const deniedPreview = await museLoop06Preview(engine, first.issueRef);
  expect(deniedPreview.disclosure).toBe("denied");

  // Second proposal: the owner approves and stops asking for this publisher.
  // Only then does the outbound payload carry the quoted text.
  const second = await museLoop06FileQuotingProposal({ ...common, sentinel: sentinel2 });
  expect(second.disclosure).toBe("needs_approval");
  await museLoop06ExpectUndisclosed(engine, second.issueRef, sentinel2);
  const standing = await engine.client.call("vault.reports.disclosure", {
    issue_ref: second.issueRef, choice: "stop_asking_for_publisher",
  } satisfies FacadeInput<"vault.reports.disclosure">);
  expect(standing.issue_ref).toBe(second.issueRef);
  expect(standing.disclosure).toBe("approved");
  const standingBasis = standing.disclosure_basis;
  if (!standingBasis || standingBasis.basis !== "standing_grant") {
    throw new Error("Stop-asking disclosure did not record a standing grant basis");
  }
  const standingGrantRef = standingBasis.grant_ref;
  expect(standingGrantRef.length).toBeGreaterThan(0);
  await museLoop06ExpectDisclosed(engine, second, sentinel2);
  const secondPreview = await museLoop06Preview(engine, second.issueRef);
  expect(secondPreview.disclosure).toBe("approved");
  expect(secondPreview.includes_text).toBe(true);

  // Third proposal to the same publisher: the standing grant answers, so no
  // fresh ask appears and the quote is disclosed under that same grant.
  const third = await museLoop06FileQuotingProposal({ ...common, sentinel: sentinel3 });
  expect(third.disclosure).toBe("approved");
  const thirdBasis = third.disclosureBasis;
  if (!thirdBasis || thirdBasis.basis !== "standing_grant") {
    throw new Error("Standing-grant disclosure did not name its standing grant basis");
  }
  expect(thirdBasis.grant_ref).toBe(standingGrantRef);
  await museLoop06ExpectDisclosed(engine, third, sentinel3);

  // The owner revokes the standing grant; the next quoting proposal to the
  // same publisher asks again and its text stays undisclosed.
  const revoked = await engine.client.call("vault.consent.revoke", {
    grant: standingGrantRef,
  } satisfies FacadeInput<"vault.consent.revoke">);
  const fourth = await museLoop06FileQuotingProposal({ ...common, sentinel: sentinel4 });
  expect(fourth.disclosure).toBe("needs_approval");
  await museLoop06ExpectUndisclosed(engine, fourth.issueRef, sentinel4);

  const receiptsBefore = await engine.client.call("vault.receipts", {
    limit: 1000,
  } satisfies FacadeInput<"vault.receipts">);

  await engine.restart();

  await museLoop06ExpectUndisclosed(engine, fourth.issueRef, sentinel4);
  // Outbound is the live send view: once the standing grant is revoked, the
  // unsent issues it covered need a fresh approval again.
  await museLoop06ExpectUndisclosed(engine, second.issueRef, sentinel2);
  await museLoop06ExpectUndisclosed(engine, third.issueRef, sentinel3);
  const deniedAfterRestart = await museLoop06Preview(engine, first.issueRef);
  expect(deniedAfterRestart.disclosure).toBe("denied");
  const receiptsAfter = await engine.client.call("vault.receipts", {
    limit: 1000,
  } satisfies FacadeInput<"vault.receipts">);
});

// ---- MUSE-LOOP-08 (Muse Wonder Full, ported 10 Nov) ----
type MuseLoop08ClaimRow = FacadeResult<"vault.claims.list">["value"][number];
type MuseLoop08ChangeOutcome = FacadeResult<"vault.runs.settlement">["changes"][number];
type MuseLoop08ReceiptRow = FacadeResult<"vault.receipts">["receipts"][number];
type MuseLoop08AuditRow = FacadeResult<"vault.authority.audit">["rows"][number];
type MuseLoop08ErrorBody = { error: { code: string; message: string } };
type MuseLoop08ActorReceipt = { actor_ref?: string | null };

// Unfiltered, vault.claims.list also lists retracted rows (canon: ClaimListFilter's lifecycle is optional);
// `lifecycle: "active"` reads the active set only.
async function museLoop08Claims(
  client: PublicHttpClient,
  subjectRef: string,
  predicate: string,
  lifecycle?: "active",
): Promise<MuseLoop08ClaimRow[]> {
  const page = await client.call("vault.claims.list", {
    subject_ref: subjectRef, predicate, limit: 10, ...(lifecycle ? { lifecycle } : {}),
  } satisfies FacadeInput<"vault.claims.list">);
  return page.value;
}

// A revert retracts the claim in place: the unfiltered list still holds its row, which reads "retracted".
async function museLoop08Lifecycle(
  client: PublicHttpClient,
  subjectRef: string,
  predicate: string,
  claimRef: string,
): Promise<MuseLoop08ClaimRow["lifecycle"] | undefined> {
  const rows = await museLoop08Claims(client, subjectRef, predicate);
  return rows.find((row) => row.claim_ref === claimRef)?.lifecycle;
}

async function museLoop08PendingRefs(client: PublicHttpClient): Promise<Set<string>> {
  const rows = await client.call("vault.writes.pending", {
    limit: 1000,
  } satisfies FacadeInput<"vault.writes.pending">);
  return new Set(rows.map((row) => row.claim_ref));
}

async function museLoop08ReceiptRows(client: PublicHttpClient): Promise<MuseLoop08ReceiptRow[]> {
  const page = await client.call("vault.receipts", {
    limit: 1000,
  } satisfies FacadeInput<"vault.receipts">);
  return page.receipts;
}

function museLoop08ChangeId(
  outcomes: readonly MuseLoop08ChangeOutcome[],
  claimRef: string,
): string {
  const hit = outcomes.find((row) => row.change === claimRef || row.change.includes(claimRef));
  if (!hit) throw new Error("Settlement readback names no change for a reviewed claim");
  return hit.change;
}

async function museLoop08AuditRows(client: PublicHttpClient): Promise<MuseLoop08AuditRow[]> {
  const rows: MuseLoop08AuditRow[] = [];
  let after: string | undefined;
  for (;;) {
    const query: FacadeInput<"vault.authority.audit"> = { limit: 500, ...(after ? { after } : {}) };
    const page = await client.call("vault.authority.audit", query);
    rows.push(...page.rows);
    // These fixtures never adopt an externally attested checkpoint image.
    if (!page.next_after) return rows;
    after = page.next_after;
  }
}

// MUSE-LOOP-08 (PARTIAL) — P-LOOP-030 subset only.
// Promises: P-LOOP-027 consent wait parks only its branch; P-LOOP-028 a
// mid-run message joins at the next breakpoint with an interrupt option;
// P-LOOP-029 the owner lists and reverts automatic Dreamer conflict
// settlements; P-LOOP-030 undo offers all changes or a chosen subset and
// reports blocked partial undo honestly.
// Doors used: vault.structural.put + pairActor (agent), vault.conversations.create,
// vault.claims.seed (agent proposes), vault.claims.list / vault.writes.pending
// (second-door reads), vault.runs.review / settle / settlement (owner decides),
// vault.revert_run (owner subset, then all), vault.claims.upsert (later edit),
// vault.claims.history + vault.receipts + engine.awaitReceipt (undo readbacks),
// facade raw routes for wrong actors, vault.authority.audit + /v1/core/slips/revoke
// for the revoked-credential leg, engine.restart().
// Unproved and why: P-LOOP-027/P-LOOP-028 have no deterministic, model-free
// producer in the typed surface that runs a multi-branch live run into a
// consent/human wait or consumes a Signal (vault.runs.branches.get only reads;
// `steer` needs a spawner's live run and has no interrupt/interject mode).
// P-LOOP-029's doors are untyped owner HTTP routes and seeding an *automatic*
// Dreamer settlement needs a parked conflict plus the Dreamer ladder/timer,
// which no public deterministic door drives. P-LOOP-030 whole-run change
// discovery and cross-kind undo stay unproved: canon says only the owner
// reviewing *named* changes and reverting all or some is built in part, and
// this case exercises claims only.
suite.test(test, "MUSE-LOOP-08", "Owner settles agent-proposed claims, undoes a chosen subset then the rest where unblocked, and reports the blocked change (P-LOOP-030 subset)", async () => {
  const engine = await EngineFixture.start({ id: "MUSE-LOOP-08", profile });
  try {
    const occurred = 1769947200;
    const runId = "muse-loop-08-reviewed-set";
    const alphaPredicate = "loop08.alpha";
    const betaPredicate = "loop08.beta";
    const gammaPredicate = "loop08.gamma";
    const readerPredicate = "loop08.reader";
    const deadPredicate = "loop08.dead";
    const alphaValue = "loop08-alpha-value-one";
    const betaValueOne = "loop08-beta-value-one";
    const betaValueTwo = "loop08-beta-value-two";
    const gammaValue = "loop08-gamma-value-one";
    const readerValue = "loop08-reader-value-one";
    const deadValue = "loop08-dead-value-one";
    redactor.add(alphaValue, betaValueOne, betaValueTwo, gammaValue, readerValue, deadValue);
    const owner = engine.client;
    const ownerRef = engine.pairedActor.principalRef;
    const auditBefore = await museLoop08AuditRows(owner);
    const scope = await ownerBaseClaimScope(owner, ownerRef);
    const conversation = await owner.call("vault.conversations.create", {
      body: {}, occurred_start: occurred, occurred_end: occurred, learned_at: occurred,
    } satisfies FacadeInput<"vault.conversations.create">);
    const subjectRef = conversation.id;
    const evidenceTurn = await museLoopClaimEvidence(
      owner, conversation.id,
      `Reviewed values: alpha=${alphaValue}; beta=${betaValueOne}; gamma=${gammaValue}.`, occurred,
    );

    const readerRecord = await owner.call("vault.structural.put", {
      kind: "PERSON", body: { name: "Loop08 Reader Person" }, occurred_at: occurred,
    } satisfies FacadeInput<"vault.structural.put">);
    const reader = await engine.pairActor({
      principalRef: readerRecord.id_hex, actorClass: "agent", scope: ["core:read"],
    });
    const proposerRecord = await owner.call("vault.structural.put", {
      kind: "PERSON", body: { name: "Loop08 Proposer Person" }, occurred_at: occurred,
    } satisfies FacadeInput<"vault.structural.put">);
    const proposer = await engine.pairActor({
      principalRef: proposerRecord.id_hex, actorClass: "agent", scope: ["core:read", "core:write"],
    });

    // An agent paired without write scope cannot propose through the seed door.
    const readerSeed = { claims: [{ predicate: readerPredicate, subject_ref: subjectRef, value: readerValue, confidence: 1, source: "generated", scope, evidence_turn_refs: [evidenceTurn], occurred_at: occurred }] } satisfies FacadeInput<"vault.claims.seed">;
    const readerRefused = await reader.client.raw<MuseLoop08ErrorBody>("POST", "/v1/core/facade/vault.claims.seed", readerSeed);

    // The agent proposes three independent claims; the seed door forces Proposed.
    const seeded = await proposer.client.call("vault.claims.seed", { claims: [
      { predicate: alphaPredicate, subject_ref: subjectRef, value: alphaValue, confidence: 1, source: "generated", scope, evidence_turn_refs: [evidenceTurn], occurred_at: occurred },
      { predicate: betaPredicate, subject_ref: subjectRef, value: betaValueOne, confidence: 1, source: "generated", scope, evidence_turn_refs: [evidenceTurn], occurred_at: occurred },
      { predicate: gammaPredicate, subject_ref: subjectRef, value: gammaValue, confidence: 1, source: "generated", scope, evidence_turn_refs: [evidenceTurn], occurred_at: occurred },
    ] } satisfies FacadeInput<"vault.claims.seed">);
    expect(seeded).toHaveLength(3);
    for (const outcome of seeded) {
      expect(outcome.outcome).toBe("landed");
      if (outcome.outcome !== "landed") throw new Error("Agent seed claim was refused");
      const receipt = (await engine.awaitReceipt(outcome.receipt_ref)) as MuseLoop08ActorReceipt | undefined;
    }
    const alphaRowsBefore = await museLoop08Claims(owner, subjectRef, alphaPredicate);
    const betaRowsBefore = await museLoop08Claims(owner, subjectRef, betaPredicate);
    const gammaRowsBefore = await museLoop08Claims(owner, subjectRef, gammaPredicate);
    expect(alphaRowsBefore).toHaveLength(1);
    expect(betaRowsBefore).toHaveLength(1);
    expect(gammaRowsBefore).toHaveLength(1);
    const alphaRow = alphaRowsBefore[0]!;
    const betaRow = betaRowsBefore[0]!;
    const gammaRow = gammaRowsBefore[0]!;
    expect(alphaRow.value).toBe(alphaValue);
    expect(betaRow.value).toBe(betaValueOne);
    expect(gammaRow.value).toBe(gammaValue);
    const claimRefs = [alphaRow.claim_ref, betaRow.claim_ref, gammaRow.claim_ref];
    expect(new Set(claimRefs).size).toBe(3);
    await awaitPublic(
      () => museLoop08PendingRefs(owner),
      (refs) => claimRefs.every((ref) => refs.has(ref)),
      { label: "seeded proposed claims parked in writes.pending" },
    );

    // The proposing agent cannot review (or, below, settle/revert) its own work.
    const receiptsBeforeRefusal = new Set((await museLoop08ReceiptRows(owner)).map((row) => row.receipt_ref));
    const reviewInput: FacadeInput<"vault.runs.review"> = {
      run_id: runId,
      changes: claimRefs.map((claimRef) => ({ kind: "claim" as const, claim_ref: claimRef })),
    };
    const agentReview = await proposer.client.raw<MuseLoop08ErrorBody>("POST", "/v1/core/facade/vault.runs.review", reviewInput);
    const pendingAfterAgentReview = await museLoop08PendingRefs(owner);

    // The owner reviews the named set and approves it; the settlement is read back.
    const review = await owner.call("vault.runs.review", reviewInput);
    expect(review.review_id.length).toBeGreaterThan(0);
    const settledAct = await owner.call("vault.runs.settle", {
      review: reviewInput, review_id: review.review_id, decision: "approve",
    } satisfies FacadeInput<"vault.runs.settle">);
    const settlement = await owner.call("vault.runs.settlement", {
      run_id: runId,
    } satisfies FacadeInput<"vault.runs.settlement">);
    expect(settlement.run_id).toBe(runId);
    expect(settlement.receipt).toBe(settledAct.receipt);
    expect(settlement.verdict).toBe("landed");
    expect(settlement.revert_handle.length).toBeGreaterThan(0);
    expect(settlement.changes).toHaveLength(3);
    for (const change of settlement.changes) expect(change.verdict).toBe("landed");
    const settlementReceipt = (await engine.awaitReceipt(settlement.receipt)) as MuseLoop08ActorReceipt | undefined;
    const alphaChange = museLoop08ChangeId(settlement.changes, alphaRow.claim_ref);
    const betaChange = museLoop08ChangeId(settlement.changes, betaRow.claim_ref);
    const gammaChange = museLoop08ChangeId(settlement.changes, gammaRow.claim_ref);
    await awaitPublic(
      () => museLoop08PendingRefs(owner),
      (refs) => claimRefs.every((ref) => !refs.has(ref)),
      { label: "settled claims leave writes.pending" },
    );
    expect((await museLoop08Claims(owner, subjectRef, alphaPredicate))[0]?.value).toBe(alphaValue);
    expect((await museLoop08Claims(owner, subjectRef, betaPredicate))[0]?.value).toBe(betaValueOne);
    expect((await museLoop08Claims(owner, subjectRef, gammaPredicate))[0]?.value).toBe(gammaValue);

    const agentRevert = await proposer.client.raw<MuseLoop08ErrorBody>("POST", "/v1/core/facade/vault.revert_run", {
      run_id: settlement.run_id,
    } satisfies FacadeInput<"vault.revert_run">);
    expect(agentRevert.status).toBe(403);
    expect(agentRevert.body.error.code.length).toBeGreaterThan(0);
    // The refusals leave a receipt naming the agent, read back through vault.receipts.
    await awaitPublic(
      () => museLoop08ReceiptRows(owner),
      (rows) => rows.some((row) => !receiptsBeforeRefusal.has(row.receipt_ref) && String(row.actor_ref ?? "").includes(proposer.principalRef)),
      { label: "agent refusal receipt in vault.receipts", timeoutMs: 5000 },
    );
    const settlementAfterRefusal = await owner.call("vault.runs.settlement", {
      run_id: runId,
    } satisfies FacadeInput<"vault.runs.settlement">);
    expect(settlementAfterRefusal.receipt).toBe(settlement.receipt);
    expect((await museLoop08Claims(owner, subjectRef, alphaPredicate))[0]?.value).toBe(alphaValue);

    // Undo a chosen subset (alpha only); beta and gamma stay landed.
    const selective = await owner.call("vault.revert_run", {
      run_id: settlement.run_id, changes: [alphaChange],
    } satisfies FacadeInput<"vault.revert_run">);
    expect(selective.compensated).toHaveLength(1);
    const alphaComp = selective.compensated.find((row) => row.change === alphaChange);
    if (!alphaComp) throw new Error("Selective revert did not compensate the chosen change");
    expect(alphaComp.receipt.length).toBeGreaterThan(0);
    await engine.awaitReceipt(alphaComp.receipt);
    expect(await museLoop08Lifecycle(owner, subjectRef, alphaPredicate, alphaRow.claim_ref)).toBe("retracted");
    expect(await museLoop08Claims(owner, subjectRef, alphaPredicate, "active")).toHaveLength(0);
    expect((await museLoop08Claims(owner, subjectRef, betaPredicate))[0]?.value).toBe(betaValueOne);
    expect((await museLoop08Claims(owner, subjectRef, gammaPredicate))[0]?.value).toBe(gammaValue);
    const alphaHistory = await owner.call("vault.claims.history", {
      claim_ref: alphaRow.claim_ref,
    } satisfies FacadeInput<"vault.claims.history">);

    await engine.restart();
    const settlementAfterRestart = await owner.call("vault.runs.settlement", {
      run_id: runId,
    } satisfies FacadeInput<"vault.runs.settlement">);
    expect(settlementAfterRestart.receipt).toBe(settlement.receipt);
    expect(settlementAfterRestart.revert_handle).toBe(settlement.revert_handle);
    expect(await museLoop08Lifecycle(owner, subjectRef, alphaPredicate, alphaRow.claim_ref)).toBe("retracted");
    expect(await museLoop08Claims(owner, subjectRef, alphaPredicate, "active")).toHaveLength(0);
    expect((await museLoop08Claims(owner, subjectRef, betaPredicate))[0]?.value).toBe(betaValueOne);
    expect((await museLoop08Claims(owner, subjectRef, gammaPredicate))[0]?.value).toBe(gammaValue);

    // A later owner edit rests on beta, then undo-all is asked for.
    const betaEdit = await owner.call("vault.claims.upsert", {
      predicate: betaPredicate, subject_ref: subjectRef, value: betaValueTwo,
      confidence: 1, source: "user_stated", scope, occurred_at: occurred + 60,
    } satisfies FacadeInput<"vault.claims.upsert">);
    await engine.awaitReceipt(betaEdit.receipt_ref);
    expect((await museLoop08Claims(owner, subjectRef, betaPredicate)).some((row) => row.value === betaValueTwo)).toBe(true);
    const rest = await owner.call("vault.revert_run", {
      run_id: settlement.run_id,
    } satisfies FacadeInput<"vault.revert_run">);
    const gammaComp = rest.compensated.find((row) => row.change === gammaChange);
    if (!gammaComp) throw new Error("Undo-all did not compensate the unblocked gamma change");
    await engine.awaitReceipt(gammaComp.receipt);
    expect(rest.compensated.some((row) => row.change === betaChange)).toBe(false);
    const betaBlocked = rest.not_undone.find((row) => row.change === betaChange);
    if (!betaBlocked) throw new Error("Blocked beta change was not listed as not undone");
    expect(betaBlocked.reason).toBe("dependent");
    for (const changeId of [betaChange, gammaChange]) {
      const inCompensated = rest.compensated.some((row) => row.change === changeId);
      const inNotUndone = rest.not_undone.some((row) => row.change === changeId);
      expect(inCompensated !== inNotUndone).toBe(true);
    }
    expect(await museLoop08Lifecycle(owner, subjectRef, gammaPredicate, gammaRow.claim_ref)).toBe("retracted");
    expect(await museLoop08Claims(owner, subjectRef, gammaPredicate, "active")).toHaveLength(0);
    expect((await museLoop08Claims(owner, subjectRef, betaPredicate)).some((row) => row.value === betaValueTwo)).toBe(true);
    expect(await museLoop08Lifecycle(owner, subjectRef, alphaPredicate, alphaRow.claim_ref)).toBe("retracted");
    expect(await museLoop08Claims(owner, subjectRef, alphaPredicate, "active")).toHaveLength(0);

    // The owner revokes the proposer's slip; its next write use is refused.
    const auditAfterPairings = await museLoop08AuditRows(owner);
    const beforeHashes = new Set(auditBefore.map((row) => row.entry_hash));
    const mintedIds = auditAfterPairings
      .filter((row) => !beforeHashes.has(row.entry_hash) && row.source_op === "slip_mint" && row.holder_ref === proposer.principalRef && typeof row.subject_ref === "string" && /^[a-f0-9]{64}$/.test(row.subject_ref))
      .map((row) => row.subject_ref as string);
    for (const slipId of mintedIds) {
      const revoked = await owner.request<{ revoked: boolean }>("POST", "/v1/core/slips/revoke", {
        slip_id: Array.from(Buffer.from(slipId, "hex")),
      });
    }
    const auditFinal = await museLoop08AuditRows(owner);
    const deadSeed = { claims: [{ predicate: deadPredicate, subject_ref: subjectRef, value: deadValue, confidence: 1, source: "generated", scope, evidence_turn_refs: [evidenceTurn], occurred_at: occurred + 120 }] } satisfies FacadeInput<"vault.claims.seed">;
    const dead = await proposer.client.raw<MuseLoop08ErrorBody>("POST", "/v1/core/facade/vault.claims.seed", deadSeed);

    await engine.artifacts.json("muse-loop08-outcome.json", {
      runId, claimRefs,
      changes: { alpha: alphaChange, beta: betaChange, gamma: gammaChange },
      settlementReceipt: settlement.receipt, revertHandle: settlement.revert_handle,
      selective: selective.compensated, restCompensated: rest.compensated, restNotUndone: rest.not_undone,
    });
  } finally {
    await engine.close();
  }
});
