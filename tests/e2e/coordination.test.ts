import { afterAll, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { copyFile, mkdir, readFile, readdir } from "node:fs/promises";
import { resolve } from "node:path";
import type { Facade, FacadeInput, FacadeResult } from "@oneiron/client";
import { EngineFixture, awaitPublic } from "./support/engine.ts";
import { PublicHttpClient, PublicHttpError } from "./support/clients.ts";
import { loadFixtures, ownerBaseClaimScope } from "./support/fixtures.ts";
import { ScriptedProviders, openaiStream, openaiText } from "./support/providers.ts";
import { defineFile } from "./support/run.ts";

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
 * DEFECT (red since the first fleet run, Tue 10 Nov 2026; FIX row HOUSE-SOURCE-READ-DENIED): the decider is never asked. The
 *   house reads the source MESSAGE through a key with no proof, authority or explicit scope
 *   (agent_dispatch/project_proposal.rs:159-166); require_relationship_grants grants nothing on its own
 *   (claim/scoped_read/actor_key.rs:691-709). With no scoped grant for that actor, a non-owner's read floor is
 *   deny_all (gate/retrieval_filter.rs:205-214). The shipped manifest carries read rows only for the Dreamer
 *   and the Coach, none for the house (gate/default_manifest.rs:1054-1060). So the message is refused
 *   (claim/scoped_read/visibility.rs:629), and the question settles Unread before the ladder
 *   (project_proposal.rs:91-94). PR #6857 relaxed the relationship conjunct only. Not worked around: an owner
 *   read grant for the house through vault.gate.policy.put would hide it.
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

  // DEFECT (fleet: HTTP 403 at the first trunk append): every DAG append runs check_append_policy
  // (conversation_dag/writes.rs:417), which labels the caller's record ClaimSource::Generated whoever writes it
  // (conversation_dag/policy.rs:247-300). Generated needs an explicit actor-bound source-trust permit
  // (oneiron-contracts claim/status.rs:137-141, gate/ceiling.rs:579-609), and the shipped manifest grants one only
  // to the commitment projector and the seal actor (gate/default_manifest.rs:676-737). So on a default vault no
  // person, the owner included, appends a trunk record or a thread reply: 403 "gate.pending.source_trust".
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
 * DEFECT (expected FAIL today, at the first offer; FIX [AGENT-PERSON-ANCHOR-ROOM-OFFER]): vault.agents.create
 *   anchors every custom AGENT_DEF to a model PERSON (agent_def/doors.rs:313-334, context_board/people.rs:491-521),
 *   the join subject then reads it as a person's pen (join_consent.rs:439-453, rooms/participation.rs:268-275),
 *   and the mint refuses it: 400 "a person's pen joins by writing as its person, not by an offer card"
 *   (rooms/offers.rs:434-442). The fix also gives the agent vault-owned-agent standing, so the host's
 *   admission alone settles the card (no membership need).
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

/** COORDINATION-08 authored inputs (fixture discriminant, not a wire DTO). */
interface Coordination08Scenario {
  id: "COORDINATION-08";
  inputs: {
    workAgent: { label: string; dial: Facade.RefusalDial; request: string; objectionReason: string };
    personalAgent: { label: string; dial: Facade.RefusalDial; request: string; objectionReason: string };
    settingsControls: Facade.RefusalLevel[];
  };
  expected: {
    workOutcome: Facade.RefusalOutcome;
    workProceeds: boolean;
    workObjectionsIncludingReplay: number;
    personalBondOutcome: Facade.RefusalOutcome;
    personalLogisticsLevel: Facade.RefusalLevel;
    dialEndsSettable: Facade.RefusalLevel[];
  };
}
type Coordination08Status = Extract<Facade.TaskOutcome, { kind: "snapshot" }>;

const coordination08Model = "coord-agent";
function coordination08InputId(label: string): string {
  return createHash("sha256").update(`coordination-e2e:COORDINATION-08:${label}`).digest("hex").slice(0, 32);
}
async function coordination08Scenario(): Promise<Coordination08Scenario> {
  const data = await (await loadFixtures()).readJson<{ scenarios: { id: string }[] }>("coordination-scenarios");
  const row = data.scenarios.find(item => item.id === "COORDINATION-08");
  if (!row) throw new Error("Missing COORDINATION-08 fixture scenario");
  return row as Coordination08Scenario; // Fixture discriminant, not an invented wire DTO.
}
function coordination08Object(value: unknown, what: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error(`Expected public ${what} object`);
  return value as Record<string, unknown>;
}
async function coordination08Status(client: PublicHttpClient, task_ref: string): Promise<Coordination08Status> {
  const described = await client.call("describe", { handle: { kind: "task", task_ref } });
  if (described.kind !== "task_status") throw new Error(`describe answered ${described.kind}, not task_status`);
  const outcome = described.receipt.outcome;
  if (outcome.kind !== "snapshot") throw new Error(`task status answered ${outcome.kind}, not a snapshot`);
  return outcome;
}
/** The TASK's public body as the owner reads it: its one refusal record and terminal state. */
async function coordination08TaskBody(client: PublicHttpClient, task_ref: string): Promise<Record<string, unknown>> {
  const row = (await client.call("vault.get", { entity_ref: task_ref })).value;
  expect(row?.kind).toBe("TASK");
  return coordination08Object(row?.body, "TASK body");
}
/** A durable reason TURN the agent cites: actually witnessed, never a fabricated ref. */
async function coordination08Reason(client: PublicHttpClient, conversation: string, content: string, at: number): Promise<string> {
  const witnessed = await client.call("vault.witness", {
    conversation_ref: conversation, occurred_at: at,
    messages: [{ author: "user", message_type: "text", content, is_visible: true, order: 0 }],
  });
  const turn = (await client.call("vault.get", { entity_ref: witnessed.turn_short_id })).value;
  expect(turn?.kind).toBe("TURN");
  if (!turn) throw new Error("Reason TURN is not readable");
  return turn.id_hex;
}
async function coordination08Agent(client: PublicHttpClient, label: string, dial: Facade.RefusalDial, ceiling?: "auto"): Promise<string> {
  const agent_def_ref = coordination08InputId(label);
  const created = await client.call("vault.agents.create", {
    agent_def_ref, definition: { agent_id: label, display_name: label,
      desc: `COORDINATION-08 ${label}`, version: "1", refusal: dial, ...(ceiling === undefined ? {} : { ceiling }) },
  });
  expect(created.agent_def_ref).toBe(agent_def_ref);
  expect(created.definition.refusal).toEqual(dial);
  return agent_def_ref;
}
function coordination08Brief(ownerRef: string, request: string): Facade.QueueTaskBrief {
  return {
    schema: 1,
    type_ref: { node_id: coordination08InputId("task-type"), tree_version: 1 },
    objective: request,
    intent: { need: request, care: "light" },
    success: { question: "Did the agent do the act, or refuse it under its declared dial?",
      criteria: { yes_if_all: [{ text: "The act is done, or the agent's own refusal is recorded with its reason." }] } },
    settled: [],
    // No question_ref and default proceed: Done needs no model judgment (done.rs:327-333).
    escalation: { to: { people: [ownerRef] }, triggers: [], default: "proceed", reversibility: "reversible_read" },
  };
}
/** Queue the agent run's one scripted step, then post its TASK and wait for a public terminal phase. */
async function coordination08Run(
  engine: EngineFixture, providers: ScriptedProviders, agent: string, label: string, request: string, program: string,
): Promise<{ task: string; status: Coordination08Status }> {
  providers.enqueue({
    id: `coordination08-${label}`, origin: "chat", role: "generative_reasoner",
    purpose: `${label}'s own code-mode run applies its refusal dial`,
    // The engine-native executor streams on a local-openai-compat provider (wire.rs:146-149),
    // so its one program arrives as an SSE stream, never a buffered completion.
    request: { method: "POST", path: "/v1/chat/completions", model: coordination08Model,
      fields: { stream: true, stream_options: { include_usage: true } } },
    response: openaiStream(`coordination08-${label}`, coordination08Model, [program], { inputTokens: 256, outputTokens: 96 }),
  });
  const posted = await engine.client.call("tasks.create", {
    spec: { title: request }, label: `coordination-08-${label}`, assignee: { agent_def: { agent_def_ref: agent } },
    intent_key: `coordination-08/${label}/post`, brief: coordination08Brief(engine.pairedActor.principalRef, request),
  });
  expect(posted.approval).toBe("auto");
  expect(posted.effected).toBe(true);
  const route = posted.route;
  if (!route || !("AgentDispatch" in route)) throw new Error(`Agent TASK routed ${JSON.stringify(route)}`);
  expect(route.AgentDispatch.agent_def_ref).toBe(agent);
  const task = posted.task_ref;
  if (!task) throw new Error("Agent TASK has no task_ref");
  const status = await awaitPublic(() => coordination08Status(engine.client, task),
    row => row.phase.phase === "terminal", { label: `COORDINATION-08 ${label} run settles its TASK` });
  return { task, status };
}
/** A public refusal: its HTTP status and the engine's typed code and message. */
async function coordination08Refused(call: Promise<unknown>): Promise<{ status: number; code: string; message: string }> {
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
/**
 * Queue the agent run's one scripted step, a program that asks the owner a typed question and waits
 * on it, then post its TASK. The wait parks the run on a durable wait, which keeps its lease and its
 * live entry (resident_pump.rs:491-523, live_runs.rs:320-341). Barrier: the run's asking step is
 * committed, so its provider exchange is over and no entry holds the run's guard for long.
 */
async function coordination08ParkedRun(
  engine: EngineFixture, providers: ScriptedProviders, agent: string, label: string, request: string, question: string,
): Promise<{ task: string; run: string }> {
  const ownerRef = engine.pairedActor.principalRef;
  providers.enqueue({
    id: `coordination08-${label}`, origin: "chat", role: "generative_reasoner",
    purpose: `${label}'s own code-mode run asks its owner and parks on the ask`,
    // The engine-native executor streams on a local-openai-compat provider (wire.rs:146-149).
    request: { method: "POST", path: "/v1/chat/completions", model: coordination08Model,
      fields: { stream: true, stream_options: { include_usage: true } } },
    // `ask` and `wait` are the catalog rows (wire.rs:389-402): the ask binds to this run's TASK, and
    // a wait on a pending ask parks instead of answering Pending (read.rs:209-230).
    response: openaiStream(`coordination08-${label}`, coordination08Model, [[
      `const asked = await ask({ intent_key: "coordination-08/${label}/hold", who: { people: ["${ownerRef}"] },`,
      `  what: { reference: { turn: "${question}" }, revision: 1, options: {}, context_refs: [] }, need: { count: 1 }, decide: "first" });`,
      `await wait({ handle: asked.handle, step_key: "coordination-08/${label}/hold" });`,
    ].join("\n")], { inputTokens: 256, outputTokens: 96 }),
  });
  const posted = await engine.client.call("tasks.create", {
    spec: { title: request }, label: `coordination-08-${label}`, assignee: { agent_def: { agent_def_ref: agent } },
    intent_key: `coordination-08/${label}/post`, brief: coordination08Brief(ownerRef, request),
  });
  expect(posted.effected).toBe(true);
  const route = posted.route;
  if (!route || !("AgentDispatch" in route)) throw new Error(`Agent TASK routed ${JSON.stringify(route)}`);
  expect(route.AgentDispatch.agent_def_ref).toBe(agent);
  const task = posted.task_ref;
  if (!task) throw new Error("Agent TASK has no task_ref");
  const branches = (await engine.client.call("vault.runs.branches.get", { task_ref: task })).branches;
  expect(branches).toHaveLength(1);
  const run = branches[0]!.branch; // The run id is its attempt's own id (execution.rs:47-49).
  await awaitPublic(() => engine.client.call("vault.runs.checkpoint", { run_ref: run }),
    view => (view?.completed_steps ?? 0) >= 1, { label: `COORDINATION-08 ${label} run commits its asking step` });
  // Parked, not settled: the try keeps its lease (store.rs:1173-1174) and the TASK stays open.
  // The whole branch first, so a failure prints its last_error.
  const parkedBranch = (await engine.client.call("vault.runs.branches.get", { task_ref: task })).branches[0];
  await expectParkedBranchLeased(engine, `COORDINATION-08 ${label}`, parkedBranch);
  expect(parkedBranch?.state).toBe("Leased");
  expect((await coordination08Status(engine.client, task)).phase.phase).not.toBe("terminal");
  return { task, run };
}

/* COORDINATION-08 (partial, Engine E2E-PARTIAL option A).
 * Promise: an agent's declared refusal dial decides what its own refusal of the TASK it runs
 *   becomes: voice records one objection (replay adds none) and the work proceeds, bond veto
 *   declines only that act, the none and full ends both apply from a live dial edit, and the
 *   record survives a restart.
 * Doors: HTTP facade vault.agents.create/get/update, vault.conversations.create, vault.witness,
 *   vault.get, tasks.create, describe, tasks.refuse (owner, unknown-live-run status check); the
 *   agents' own engine-native code-mode runs call run-only tasks.refuse (host-bound lease),
 *   driven by ScriptedProviders.
 * The owner refusing on the agent's behalf, against the agent's REAL live run: the agent's run parks
 *   on its own ask (a durable wait keeps its lease and live entry), her own paired credential attaches
 *   (self.run.attach) and holds the handle; the owner can neither attach to that run nor refuse her
 *   TASK through her handle (403 live_run_unavailable), nothing is recorded, and the same handle then
 *   lands her own objection under her dial. Doors added: vault.runs.branches.get, vault.runs.checkpoint,
 *   self.run.attach, tasks.refuse (host door, LiveRunRequest); pairActor for the agent.
 * Unproved: the leadership-chat half (two same-vault project leaders talking, public fact crossing,
 *   private fact withheld): needs two publicly confirmed projects with person-anchored leaders and
 *   a scripted receiver run; not attempted here.
 * Unproved: the agent's diary entry (one per recorded refusal): self.memory.diary.query needs an
 *   owner diary.read standing grant whose envelope literals are not verified.
 * Unproved: the in-run return values are not public; the scripts throw unless they match, so a
 *   mismatch surfaces as an unsettled TASK or an unscripted extra model call.
 */
suite.test(test, "COORDINATION-08", "An agent's refusal dial decides its own refusal of its TASK: voice objects once and proceeds, bond veto declines, none and full apply live, and the owner cannot refuse in her place on her live run", async () => {
  const c = await coordination08Scenario();
  const providers = await ScriptedProviders.start({ id: "coordination08-runs", origins: ["chat"], steps: [] });
  const engine = await EngineFixture.start({ id: "COORDINATION-08", profile, serverLog: "oneiron=info", serverConfig: `
[models.providers.coord08chat]
kind = "local-openai-compat"
base_url = "${providers.urls.chat}"
revision = "coordination-v1"
[models.roles.generative_reasoner]
model = "coord08chat:${coordination08Model}"
[models.dreamer]
enabled = false
[models.workflows]
enabled = false
[models.code_mode]
prompt_package = ${JSON.stringify(resolve(import.meta.dir, "fixtures/hooks/host/prompts"))}
` });
  try {
    const owner = engine.client;
    const occurred = 1769947200; // Public setup input, never an engine clock override.

    // ---- Declared dials, read back as declared. ----
    const work = await coordination08Agent(owner, c.inputs.workAgent.label, c.inputs.workAgent.dial);
    const personal = await coordination08Agent(owner, c.inputs.personalAgent.label, c.inputs.personalAgent.dial, "auto");
    for (const [agent, dial] of [[work, c.inputs.workAgent.dial], [personal, c.inputs.personalAgent.dial]] as const) {
      const read = await owner.call("vault.agents.get", { agent_def_ref: agent });
      expect(read.definition.refusal).toEqual(dial);
      expect(read.lifecycle_status).toBe("active");
    }
    expect(c.inputs.personalAgent.dial.logistics).toBe(c.expected.personalLogisticsLevel);
    // Both ends of the dial are settable through the owner's versioned edit, read live later.
    const [lowest, highest] = c.expected.dialEndsSettable;
    if (!lowest || !highest) throw new Error("Fixture names no dial ends");
    expect(c.inputs.settingsControls).toEqual([lowest, highest]);
    const ends = await coordination08Agent(owner, "dial-ends-agent", { bond: "voice", logistics: "voice" });
    const edited = await owner.call("vault.agents.update", {
      agent_def_ref: ends, expected_version: "1",
      definition: { agent_id: "dial-ends-agent", display_name: "dial-ends-agent",
        desc: "COORDINATION-08 dial-ends-agent", version: "2", refusal: { bond: lowest, logistics: highest } },
    });
    expect(edited.definition.version).toBe("2");
    const endsRead = await owner.call("vault.agents.get", { agent_def_ref: ends });
    expect(endsRead.definition.refusal).toEqual({ bond: lowest, logistics: highest });
    await grantAgentAskAuthority(owner, personal);

    const conversation = await owner.call("vault.conversations.create", {
      body: {}, occurred_start: occurred, occurred_end: occurred, learned_at: occurred,
    });
    const workReason = await coordination08Reason(owner, conversation.id, c.inputs.workAgent.objectionReason, occurred);
    const personalReason = await coordination08Reason(owner, conversation.id, c.inputs.personalAgent.objectionReason, occurred);
    // A past second, fixed before each run: the engine refuses a later one, and an identical
    // retry must name the same second to replay (task_verb/refusal.rs:95-117).
    const refusedAt = Math.floor(Date.now() / 1000);

    // ---- Work agent, voice: one objection, its identical retry replays, the work proceeds. ----
    const voice = await coordination08Run(engine, providers, work, "work-voice", c.inputs.workAgent.request, [
      `const first = await tasks.refuse({ domain: "logistics", reasonRef: "tn_${workReason}", at: ${refusedAt} });`,
      `const again = await tasks.refuse({ domain: "logistics", reasonRef: "tn_${workReason}", at: ${refusedAt} });`,
      `if (first.outcome !== "${c.expected.workOutcome}" || first.level !== "voice" || first.replay !== false || again.replay !== true || again.outcome !== "${c.expected.workOutcome}") throw new Error("voice dial mismatch");`,
      `finish("Visitor schedule prepared after one recorded objection.");`,
    ].join("\n"));
    expect(c.expected.workProceeds).toBe(true);
    expect(voice.status.phase).toEqual({ phase: "terminal", disposition: "completed" });
    const voiceBody = await coordination08TaskBody(owner, voice.task);
    // The TASK carries exactly one refusal record (one objection, replay included).
    expect(c.expected.workObjectionsIncludingReplay).toBe(1);
    expect(voiceBody.refusal).toEqual({ by: work, domain: "logistics", level: "voice",
      reason_ref: { kind: "turn", entity_ref: workReason }, at: refusedAt });

    // ---- Personal agent, bond veto: that act is declined, with her reason as the result. ----
    const veto = await coordination08Run(engine, providers, personal, "personal-veto", c.inputs.personalAgent.request, [
      `const declined = await tasks.refuse({ domain: "bond", reasonRef: "tn_${personalReason}", at: ${refusedAt} });`,
      `if (declined.outcome !== "${c.expected.personalBondOutcome}" || declined.level !== "veto" || declined.replay !== false) throw new Error("veto dial mismatch");`,
    ].join("\n"));
    expect(veto.status.phase).toEqual({ phase: "terminal", disposition: "rejected" });
    const vetoBody = await coordination08TaskBody(owner, veto.task);
    expect(vetoBody.refusal).toEqual({ by: personal, domain: "bond", level: "veto",
      reason_ref: { kind: "turn", entity_ref: personalReason }, at: refusedAt });
    const vetoState = coordination08Object(vetoBody.state, "TASK state");
    expect(vetoState.state).toBe("terminal");
    const vetoTerminal = coordination08Object(vetoState.terminal, "TASK terminal record");
    expect(vetoTerminal.disposition).toBe("rejected");
    expect(vetoTerminal.result_ref).toBe(personalReason);
    // The veto declined one act: the other agent's work and the personal agent's logistics dial stand.
    expect((await coordination08Status(owner, voice.task)).phase).toEqual({ phase: "terminal", disposition: "completed" });
    expect((await owner.call("vault.agents.get", { agent_def_ref: personal })).definition.refusal)
      .toEqual(c.inputs.personalAgent.dial);

    // ---- Dial ends, edited live: none proceeds with no record, then full declines. ----
    const endsRun = await coordination08Run(engine, providers, ends, "dial-ends", c.inputs.workAgent.request, [
      `const proceed = await tasks.refuse({ domain: "bond", reasonRef: "tn_${workReason}", at: ${refusedAt} });`,
      `if (proceed.outcome !== "proceed" || proceed.level !== "${lowest}") throw new Error("none dial mismatch");`,
      `const full = await tasks.refuse({ domain: "logistics", reasonRef: "tn_${workReason}", at: ${refusedAt} });`,
      `if (full.outcome !== "decline" || full.level !== "${highest}") throw new Error("full dial mismatch");`,
    ].join("\n"));
    expect(endsRun.status.phase).toEqual({ phase: "terminal", disposition: "rejected" });
    expect((await coordination08TaskBody(owner, endsRun.task)).refusal).toEqual({ by: ends, domain: "logistics",
      level: highest, reason_ref: { kind: "turn", entity_ref: workReason }, at: refusedAt });

    // ---- The owner on the agent's behalf, against her REAL live run: refused; only she refuses. ----
    // Every live-run act comes before the restart: the host's live runs are in memory, and a parked
    // run registers again only when it re-enters (live_runs.rs:275-314).
    const holdQuestion = await coordination08Reason(owner, conversation.id, "Hold the relationship terms until I confirm.", occurred);
    const held = await coordination08ParkedRun(engine, providers, personal, "personal-held", c.inputs.personalAgent.request, holdQuestion);
    const personalAgent = await engine.pairActor({ principalRef: personal, actorClass: "agent", scope: ["core:read", "core:write"] });
    expect((await personalAgent.client.call("self.actor", {})).actor_ref).toBe(personal);
    // Her own credential attaches to her parked run (live_runs.rs:377-435) and gets its handle.
    const attached = await personalAgent.client.call("self.run.attach", { run: held.run });
    expect(attached.live_run.startsWith(`lr1.${held.run}.`)).toBe(true);
    const unavailable = { status: 403, code: "live_run_unavailable", message: "no live run this credential may act for" };
    // The owner cannot attach to the agent's run: only the run's own agent may (live_runs.rs:382-385).
    expect(await coordination08Refused(owner.call("self.run.attach", { run: held.run }))).toEqual(unavailable);
    // Nor refuse the agent's TASK through her real, live handle (live_runs.rs:514-524).
    expect(await coordination08Refused(owner.call("tasks.refuse", { live_run: attached.live_run,
      spec: { domain: "bond", reasonRef: `tn_${personalReason}`, at: refusedAt } }))).toEqual(unavailable);
    // Nothing was recorded on her TASK, and it is still open.
    expect((await coordination08TaskBody(owner, held.task)).refusal ?? null).toBeNull();
    expect((await coordination08Status(owner, held.task)).phase.phase).not.toBe("terminal");
    // The same handle still acts for her: her own logistics objection lands under her voice dial.
    const own = await personalAgent.client.call("tasks.refuse", { live_run: attached.live_run,
      spec: { domain: "logistics", reasonRef: `tn_${personalReason}`, at: refusedAt } });
    expect(c.inputs.personalAgent.dial.logistics).toBe("voice");
    expect(own).toEqual({ task: held.task, level: "voice", outcome: c.expected.workOutcome, replay: false });
    const heldBody = await coordination08TaskBody(owner, held.task);
    expect(heldBody.refusal).toEqual({ by: personal, domain: "logistics", level: "voice",
      reason_ref: { kind: "turn", entity_ref: personalReason }, at: refusedAt });
    // A voice objection proceeds: her TASK stays open, and her run stays parked on its ask.
    expect((await coordination08Status(owner, held.task)).phase.phase).not.toBe("terminal");
    const heldBranch = (await owner.call("vault.runs.branches.get", { task_ref: held.task })).branches[0];
    await expectParkedBranchLeased(engine, "COORDINATION-08 after her own refusal", heldBranch);
    expect(heldBranch?.state).toBe("Leased");

    // ---- Failure step: restart. Dials and refusal records are durable. ----
    await engine.restart();
    expect((await owner.call("vault.agents.get", { agent_def_ref: work })).definition.refusal).toEqual(c.inputs.workAgent.dial);
    expect((await owner.call("vault.agents.get", { agent_def_ref: ends })).definition.refusal).toEqual({ bond: lowest, logistics: highest });
    expect((await coordination08TaskBody(owner, voice.task)).refusal).toEqual(voiceBody.refusal);
    expect((await coordination08TaskBody(owner, veto.task)).refusal).toEqual(vetoBody.refusal);
    expect((await coordination08Status(owner, veto.task)).phase).toEqual({ phase: "terminal", disposition: "rejected" });
    // Her own objection on the held TASK is durable too; the owner's refused attempt left no record.
    expect((await coordination08TaskBody(owner, held.task)).refusal).toEqual(heldBody.refusal);
    expect((await coordination08Status(owner, held.task)).phase.phase).not.toBe("terminal");

    // ---- Failure step: unknown-live-run status check. A well-formed handle naming no issued run
    // is refused with the guard's own 403, not 500 (guards 8f218ef07cc; live_runs.rs:118-134,
    // errors.rs:196-207). It checks an unknown run; the owner against the agent's real live run is checked above.
    let ownerRefusal: PublicHttpError | undefined;
    try {
      // An authored run id that no run was issued under; never an AGENT_DEF id standing in for one.
      await owner.call("tasks.refuse", { live_run: `lr1.${coordination08InputId("unknown-run")}.00000000000000000000000000000000`,
        spec: { domain: "bond", reasonRef: `tn_${personalReason}`, at: refusedAt } });
    } catch (error) {
      if (!(error instanceof PublicHttpError)) throw error;
      ownerRefusal = error;
    }
    expect(ownerRefusal).toBeDefined();
    expect(ownerRefusal?.error?.code).toBe("live_run_unavailable");
    expect(ownerRefusal?.error?.message).toBe("no live run this credential may act for");
    expect(ownerRefusal?.reply.status).toBe(403);
  } finally {
    const errors: string[] = [];
    try { await engine.close(); } catch (error) { errors.push(error instanceof Error ? error.message : String(error)); }
    try { await providers.close(); } catch (error) { errors.push(error instanceof Error ? error.message : String(error)); }
    if (errors.length) throw new Error(`close: ${errors.join("; ")}`);
  }
});

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
