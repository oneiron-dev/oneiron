import { afterAll, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { mkdir, copyFile } from "node:fs/promises";
import { resolve } from "node:path";
import type { Facade, FacadeInput, FacadeResult } from "@oneiron/client";
import { EngineFixture, awaitPublic } from "./support/engine.ts";
import { credentialParts, PublicHttpClient } from "./support/clients.ts";
import { loadFixtures, ownerBaseClaimScope } from "./support/fixtures.ts";
import { ScriptedProviders, openaiStream, openaiText } from "./support/providers.ts";
import { BlockedDoor, defineFile } from "./support/run.ts";

const profile = process.env.E2E_PROFILE === "real-small-model"
  ? "real-small-model" : "deterministic";
const suite = defineFile(import.meta, { profile, slots: 1 });
afterAll(suite.flush);

/* Source binding: e2440c3302aa2fcca0b1855e1d9f1d1161a94a47.
 * Expected behavior comes from generatedmarkdown ARCH-0003/0004/0022/0032/
 * 0040/0043/0055, not handlers or runtime OpenAPI. Canonical fixture values
 * are translated to the current snake_case facade, never sent as app DTOs.
 * Fresh real server per ID. No engine defaults or harness deadlines change.
 * MEMORY-03 and MEMORY-06 are pending doors (Engine CORE-FOUR-SKIPS = A) and keep their full journeys.
 * MEMORY-01 asserts the fixture's full lifecycle: an approved proposal supersedes the head on its
 * conflict set (#6930), and the holder's retraction keeps history. MEMORY-07 asserts the fixture's
 * full split promise: split membership reads through merged_into (#6924). MEMORY-05 ends on a dated
 * engine-defect label while a context pack drops a window's CLAIM for token_budget. MEMORY-08 mints
 * two projects inside the 30 s cap (#7297). MEMORY-02 mints two and stays todo on the nightly budget
 * list until its MCP tool calls get faster.
 */

type ClaimInput = FacadeInput<"vault.claims.upsert">;
type Claim = FacadeResult<"vault.claims.list">["value"][number];
type Entity = NonNullable<FacadeResult<"vault.get">["value"]>;
type Receipt = FacadeResult<"vault.claims.upsert">;
type Topology = FacadeResult<"vault.identity.merge">;
type Applied = Extract<Topology, { outcome: "applied" }>;
type Position = ClaimInput["scope"];
interface CanonicalClaim {
  subjectId: string; predicate: string; value: { kind: "string"; value: string };
  confidence: number; source: string; worldId: string; scopeFacetId: string;
  scopeRelationshipId: "all" | string[]; scopeProjectId: string;
  evidenceTurnIds?: string[]; occurredAt?: number; learnedAt?: number;
}
interface Roles {
  people: { ref: string; name: string }[];
  agents: { ref: string; name: string }[];
  projects: { ref: string; name: string; role: "project" }[];
  worlds: { ref: string; name: string; kind: string }[];
  facets: { ref: string; person: string; name: string }[];
}
interface Cases {
  "MEMORY-01": { id: "MEMORY-01"; current: CanonicalClaim; alternative: CanonicalClaim;
    expected: { recallBeforeApproval: string[]; recallAfterAuthorizedApprovalAndSupersession: string[];
      recallAfterRetraction: string[] } };
  "MEMORY-02": { id: "MEMORY-02"; valid: CanonicalClaim;
    malformed: { case: string; omit?: string; value?: unknown; confidence?: number;
      subjectType?: string; made_by?: unknown }[];
    opaqueControl: { case: string; replaces: string; predicate: string;
      subjectId: string; worldId: string; scopeFacetId: string;
      scopeRelationshipId: "all" | string[]; scopeProjectId: string;
      value: unknown; confidence: number; source: string;
      evidenceTurnIds?: string[]; note: string; canon: string[] } };
  "MEMORY-04": { id: "MEMORY-04"; neutral: CanonicalClaim;
    takes: { actor: string; markdown: string }[];
    expected: { labels: string[]; noteKind: string; distinctTakeRecords: number; eachTakeLinksToNeutralBy: string;
      neutralSource: string; neutralLifecycle: string } };
  "MEMORY-05": { id: "MEMORY-05"; statements: (CanonicalClaim & { ref: string;
      occurredAt: number; learnedAt: number })[];
    windows: { axis: "occurred" | "learned"; start: number; end: number; expected: string[] }[];
    expected: { occurredOrder: string[]; learnedOrder: string[] } };
  "MEMORY-07": { id: "MEMORY-07";
    evidence: { ref: string; subject: string; content: string }[];
    intentionalFacet: { entity: string; facet: string };
    merge: { sources: string[]; survivor: string; evidence: string[] };
    split: { entity: string; heads: string[]; evidence: string[];
      reassignment_map: { evidence: string; head: string }[] };
    expected: { distinct: { reason: string } } };
  "MEMORY-08": { id: "MEMORY-08"; claims: CanonicalClaim[];
    expected: { guestCeilingCases: { name: string; worlds?: string[]; facets?: string[];
      expectedReadableClaims: number }[] } };
}
type Case = Cases[keyof Cases];
interface Data { fixture: Roles; cases: (Case | { id: "MEMORY-03" | "MEMORY-06" })[] }
interface World {
  engine: EngineFixture; providers: ScriptedProviders; data: Data; refs: Map<string, string>; conversation: string;
  scope: Position; occurred: number;
}
// Chosen public input ids, not purported existing engine handles. Every one
// is passed to its create door before being read or used as an existing ref.
function inputId(label: string): string {
  return createHash("sha256").update(`memory-e2e:${label}`).digest("hex").slice(0, 32);
}
function ref(w: World, role: string): string {
  const value = w.refs.get(role);
  if (!value) throw new Error(`Unbound fixture role ${role}`);
  return value;
}
function scenario<K extends keyof Cases>(w: World, id: K): Cases[K] {
  const row = w.data.cases.find(row => row.id === id);
  if (!row) throw new Error(`Missing canonical fixture case ${id}`);
  return row as Cases[K]; // Fixture discriminant, not an invented wire DTO.
}
function object(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value))
    throw new Error("Expected a public JSON object");
  return value as Record<string, unknown>;
}
function applied(value: Topology): Applied {
  expect(value.outcome).toBe("applied");
  if (value.outcome !== "applied") throw new Error("Topology operation did not apply");
  return value;
}
async function entity(client: PublicHttpClient, entity_ref: string): Promise<Entity> {
  const result = await client.call("vault.get", { entity_ref });
  if (!result.value) throw new Error(`Public entity missing: ${entity_ref}`);
  return result.value;
}
async function witnessed(w: World, role: string, content: string, at = w.occurred): Promise<string> {
  const receipt = await w.engine.client.call("vault.witness", {
    conversation_ref: w.conversation, occurred_at: at,
    messages: [{ author: "user", message_type: "text", content, is_visible: true, order: 0 }],
  });
  const turn = await entity(w.engine.client, receipt.turn_short_id);
  expect(turn.kind).toBe("TURN");
  w.refs.set(role, turn.id_hex);
  await w.engine.artifacts.json(`witness-${role.replace(/[^a-z0-9]/gi, "-")}.json`, receipt);
  return turn.id_hex;
}
async function person(w: World, role: string, name: string): Promise<string> {
  const evidence = await witnessed(w, `${role}-identity`, `This distinct person is ${name}.`);
  const created = await w.engine.client.call("vault.people.create", {
    identity: { name }, identity_evidence_refs: [evidence], occurred_at: w.occurred,
  });
  expect(created.person.id_hex).not.toBe(w.engine.pairedActor.principalRef);
  expect((await entity(w.engine.client, created.person.entity_ref)).kind).toBe("PERSON");
  w.refs.set(role, created.person.id_hex);
  return created.person.id_hex;
}
async function agent(w: World, role: string) {
  const input = w.data.fixture.agents.find(row => row.ref === role);
  if (!input) throw new Error(`Missing agent fixture ${role}`);
  const id = inputId(`${scenarioName(w)}:${role}`);
  const created = await w.engine.client.call("vault.agents.create", {
    agent_def_ref: id,
    definition: { agent_id: input.name, display_name: input.name,
      desc: `Authored memory reviewer ${input.name}`, version: "1" },
  });
  expect(created.agent_def_ref).toBe(id);
  expect((await entity(w.engine.client, id)).kind).toBe("AGENT_DEF");
  // An inert definition is a real agent-capable principal. Pairing gives it
  // its own credential; it does not grant a run lease or holder authority.
  const paired = await w.engine.pairActor({ principalRef: id, actorClass: "agent" });
  const identity = await paired.client.call("self.actor", {});
  expect(identity.actor_ref).toBe(id);
  expect(identity.actor_class).toBe("agent");
  w.refs.set(role, id);
  return paired;
}
function scenarioName(w: World): string { return w.engine.options.id! }
const PROJECT_LEADER = "aaaaaaaaaaaaaaaaaaaaaaaaaaaa1709"; // seeded sys.team_lead (system_agent_definitions.v1.json)
/** The wire fields of a streamed executor request; decision (Big rung) calls stay buffered. */
const EXECUTOR_STREAM = { stream: true, stream_options: { include_usage: true } } as const;
const memoryModels = (providers: ScriptedProviders) => `
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
wording = "You answer one typed question about the state you are given."
reply = "json"
[models.code_mode]
prompt_package = ${JSON.stringify(resolve(import.meta.dir, "fixtures/hooks/host/prompts"))}
[models.dreamer]
enabled = false
`;
function git(cwd: string, args: string[]): string {
  const run = Bun.spawnSync(["git", "-c", "user.name=oneiron-e2e", "-c", "user.email=e2e@oneiron.invalid", ...args],
    { cwd, stdout: "pipe", stderr: "pipe" });
  if (run.exitCode !== 0) throw new Error(`git ${args[0]} failed: ${run.stderr.toString()}`);
  return run.stdout.toString().trim();
}
/** Imports the repo's project-proposal skill through the default hub, repointed
 * at a local Git folder at one full commit (#6711), and reads its activation back. */
async function installProjectProposal(engine: EngineFixture): Promise<void> {
  // Fixture input inside the engine's own temporary root, as HOOKS-05 does
  // (hooks.test.ts about lines 1034-1046): never a project repository, never pushed.
  const dir = resolve(engine.root, "project-proposal-hub");
  await mkdir(resolve(dir, "skills", "project-proposal"), { recursive: true });
  await copyFile(resolve(import.meta.dir, "../../skills/project-proposal/SKILL.md"), resolve(dir, "skills", "project-proposal", "SKILL.md"));
  git(dir, ["init", "-q"]);
  git(dir, ["add", "skills/project-proposal/SKILL.md"]);
  git(dir, ["commit", "-q", "-m", "project-proposal"]);
  const commit = git(dir, ["rev-parse", "HEAD"]);
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
}
/** One real project: source turn, typed YES, house-dispatched drafter
 * propose, owner confirm, and the leader's goal-intake run. */
async function mintProject(engine: EngineFixture, providers: ScriptedProviders, row: { ref: string; name: string },
  index: number, occurred: number): Promise<string> {
  const client = engine.client;
  const conversation = await client.call("vault.conversations.create", {
    body: {}, occurred_start: occurred, occurred_end: occurred, learned_at: occurred });
  const decide = `project-decide-${index}`;
  providers.enqueue({ id: `project-yes-${index}`, origin: "decider", role: "checker", purpose: "project question",
    request: { method: "POST", path: "/v1/chat/completions", model: "project-decider" }, barrier: decide,
    response: openaiText(`project-yes-${index}`, "project-decider", JSON.stringify({ answer: true, probability: 0.9 }),
      { inputTokens: 256, outputTokens: 16 }) });
  const witnessed = await client.call("vault.witness", { conversation_ref: conversation.id, occurred_at: occurred,
    messages: [{ author: "user", message_type: "text", is_visible: true, order: 0,
      content: `I am starting ${row.name}, a project I will plan, build and review over several weeks of sittings.` }] });
  const message = (await entity(client, witnessed.message_short_ids[0]!)).id_hex;
  try {
    await providers.awaitBarrier(decide);
  } catch (error) {
    await engine.artifacts.json(`diagnostic-project-decide-${index}-timeout.json`, {
      conversation_ref: conversation.id, message_ref: message,
      seenFixtureCalls: providers.seenFixtureCalls.map(call => ({
        origin: call.origin, fixtureId: call.fixtureId, path: call.path,
        model: (call.body as {model?:unknown})?.model,
      })),
    });
    if(process.env.E2E_MEMORY_RETAIN_VAULT==="1") await engine.close({retainVault:true});
    throw error;
  }
  const card_id = `project-${message}`;
  const proposal = { card_id, source_message_ref: message,
    goal: { goal: `Build ${row.name}`, why: `${row.name} is the owner's stated multi-week project.`, axes: ["plan", "build", "review"] },
    picks: { leader_agent_def_ref: PROJECT_LEADER, board_human_refs: [engine.pairedActor.principalRef],
      budget_share_bps: 1000, starting_skill_refs: [] } };
  // A code-mode executor call on a local-openai-compat provider is streamed: it is answered as a stream.
  providers.enqueue({ id: `project-draft-${index}`, origin: "drafter", role: "generative_reasoner", purpose: "house project drafter",
    request: { method: "POST", path: "/v1/chat/completions", model: "project-drafter", fields: EXECUTOR_STREAM },
    response: openaiStream(`project-draft-${index}`, "project-drafter",
      [`await vault.projects.propose(${JSON.stringify(proposal)});\nfinish(${JSON.stringify(card_id)});`],
      { inputTokens: 512, outputTokens: 128 }) });
  providers.releaseBarrier(decide);
  await awaitPublic(async () => client.call("vault.projects.proposals", { conversation_ref: conversation.id }),
    cards => cards.some(card => card.card.card_id === card_id && card.state === "proposed"),
    { label: `house-drafted project card ${card_id}` });
  const intake = `project-intake-${index}`;
  providers.enqueue({ id: `project-intake-${index}`, origin: "drafter", role: "generative_reasoner", purpose: "leader goal intake",
    request: { method: "POST", path: "/v1/chat/completions", model: "project-drafter", fields: EXECUTOR_STREAM }, barrier: intake,
    response: openaiStream(`project-intake-${index}`, "project-drafter", [`finish("goal intake waits for the owner");`],
      { inputTokens: 512, outputTokens: 16 }) });
  const minted = await client.call("vault.projects.confirm", { card_id, action_id: "mint_project", occurred_at: occurred });
  expect(minted.card_id).toBe(card_id);
  try {
    await providers.awaitBarrier(intake);
  } catch (error) {
    await engine.artifacts.json(`diagnostic-project-intake-${index}-timeout.json`, {
      project_ref: minted.project_id, card_id,
      seenFixtureCalls: providers.seenFixtureCalls.map(call => ({
        origin: call.origin, fixtureId: call.fixtureId, path: call.path,
        model: (call.body as {model?:unknown})?.model,
      })),
    });
    throw new Error(`ENGINE DEFECT 2026-11-12: the owner's confirm minted project ${minted.project_id}, but its leader's `
      + `goal-intake run never called the drafter (FIX GOAL-INTAKE-NEVER-DISPATCHED). ${error instanceof Error ? error.message : String(error)}`,
      { cause: error });
  }
  providers.releaseBarrier(intake);
  const project = await entity(client, minted.project_id);
  try {
    expect(project.kind).toBe("PROJECT");
  } catch (error) {
    throw new Error(`ENGINE DEFECT 2026-11-12: project ${minted.project_id} reads back with kind ${JSON.stringify(project.kind)}: `
      + `the PROJECT kind registers at run time with no kind name, so every read spelling falls back to TYPE_<byte> `
      + `(FIX PROJECT-KIND-READS-TYPE-103). ${error instanceof Error ? error.message : String(error)}`,
      { cause: error });
  }
  return minted.project_id;
}
async function closeWorld(w: World): Promise<void> {
  const errors: string[] = [];
  const text = (error: unknown): string => error instanceof Error ? error.message : String(error);
  try { await w.engine.close({retainVault:process.env.E2E_MEMORY_RETAIN_VAULT==="1"}); } catch (error) { errors.push(text(error)); }
  try { await w.providers.close(); } catch (error) { errors.push(text(error)); }
  if (errors.length) throw new Error(`close: ${errors.join("; ")}`);
}
async function setup(id: string, projectRefs: readonly string[] = ["@project-north"]): Promise<World> {
  const data = await (await loadFixtures()).readJson<Data>("memory-canonical-cases");
  const providers = await ScriptedProviders.start({ id: `memory-projects-${id}`, origins: ["decider", "drafter"], steps: [] });
  const engine = await EngineFixture.start({ id, profile, serverConfig: memoryModels(providers),
    serverLog: "debug,oneiron::workflow_pump=info,hyper=info,hyper_util=info,h2=info,tower=info,tower_http=info,reqwest=info,rustls=info,wasmtime=info,wasmtime_cranelift=info,cranelift_codegen=info,cranelift_frontend=info,heed=info,tokio=info,runtime=info,mio=info" });
  const occurred = 1769947200; // Public setup input, never an engine clock override.
  await installProjectProposal(engine);
  // Each minted project costs the house three agent runs (decide, draft, goal intake), about 4.5 s
  // on the fleet: each run's model call comes about 2 s after the call that queues it (job 1113-014554-4015).
  // A case therefore mints only the projects it names; a case that names an unminted one fails at ref().
  const base = await ownerBaseClaimScope(engine.client, engine.pairedActor.principalRef);
  const projects = new Map<string, string>();
  for (const [index, row] of data.fixture.projects.entries()) {
    if (!projectRefs.includes(row.ref)) continue;
    projects.set(row.ref, await mintProject(engine, providers, row, index, occurred));
  }
  // Every later witness stages a project question on its own conversation:
  // the house answers no, so no further card or project appears.
  providers.enqueue({ id: "project-no", origin: "decider", role: "checker", purpose: "project question (not a project)",
    standing: true, request: { method: "POST", path: "/v1/chat/completions", model: "project-decider" },
    response: openaiText("project-no", "project-decider", JSON.stringify({ answer: false, probability: 0.9 }),
      { inputTokens: 256, outputTokens: 16 }) });
  const conversation = await engine.client.call("vault.conversations.create", {
    body: {}, occurred_start: occurred, occurred_end: occurred, learned_at: occurred,
  });
  const w: World = { engine, providers, data, refs: new Map(), conversation: conversation.id,
    scope: base, occurred };
  w.refs.set("@base", base.world_id);
  for (const [ref, id] of projects) w.refs.set(ref, id);
  for (const row of data.fixture.people) await person(w, row.ref, row.name);
  const mask = applied(await engine.client.call("vault.identity.facet", {
    entity: ref(w, "@person-a"), facets: [{ label: "work" }], reassignment_map: [],
    evidence: { refs: [ref(w, "@person-a-identity")], rationale: "Declare the person's work mask." },
  }));
  if (mask.receipt.action.op !== "facet") throw new Error("Wrong facet receipt action");
  expect(mask.receipt.action.facets).toHaveLength(1);
  w.refs.set("@facet-work", mask.receipt.action.facets[0]!);
  for (const row of data.fixture.worlds) {
    const result = await engine.client.call("vault.structural.put", {
      kind: "WORLD", body: { name: row.name, kind: row.kind }, occurred_at: occurred,
      text_fields: [{ field: "name", value: row.name }],
    });
    expect(result.id_hex).not.toBe(base.world_id);
    expect((await entity(engine.client, result.entity_ref)).kind).toBe("WORLD");
    w.refs.set(row.ref, result.id_hex);
  }
  w.scope = { ...base, scope_facet_id: ref(w, "@facet-work"),
    scope_project_id: ref(w, "@project-north") };
  return w;
}
function claimInput(w: World, row: CanonicalClaim, id?: string): ClaimInput {
  return { ...(id === undefined ? {} : { id }), subject_ref: ref(w, row.subjectId),
    predicate: row.predicate, value: row.value.value, confidence: row.confidence,
    source: row.source, scope: { world_id: ref(w, row.worldId),
      scope_facet_id: ref(w, row.scopeFacetId), scope_project_id: ref(w, row.scopeProjectId),
      scope_relationship_id: row.scopeRelationshipId === "all" ? "all"
        : row.scopeRelationshipId.map(role => ref(w, role)) },
    evidence_turn_refs: (row.evidenceTurnIds ?? []).map(role => ref(w, role)),
    occurred_at: row.occurredAt ?? w.occurred, learned_at: row.learnedAt ?? w.occurred,
  };
}
async function claims(w: World, subject = "@person-a"): Promise<Claim[]> {
  return (await w.engine.client.call("vault.claims.list", {
    subject_ref: ref(w, subject), limit: 1000,
  })).value;
}
async function claim(w: World, id: string): Promise<Claim> {
  const history = (await w.engine.client.call("vault.claims.history", { claim_ref: id })).value;
  const wanted = await entity(w.engine.client, id);
  const found = history.find(row => row.claim_ref === wanted.id_hex || row.short_ref === id);
  if (!found) throw new Error(`Claim absent from its history: ${id}`);
  return found;
}
function birth(row: Claim | Entity, actor: string, evidence: readonly string[]): void {
  const made = row.made_by;
  if (!made) throw new Error("Missing host-authored made_by");
  expect(made.process.actor).toBe(actor);
  expect(made.process.class).toBe("stated");
  expect(made.process.identity.length).toBeGreaterThan(0);
  expect(made.process.version.length).toBeGreaterThan(0);
  expect(made.process.params_hash).toMatch(/^[a-f0-9]{64}$/);
  expect(made.at).toBeGreaterThan(0);
  expect(made.inputs.map(input => input.row).sort()).toEqual([...evidence].sort());
}
// Recall scope kinds are registry kinds (CLAIM). RecallScope.person_ref selects the conversations a
// person authored, not claims about a subject, so a subject's values are cut by its own claim rows.
async function recalled(w: World, query: string, scope?: Facade.RecallScope) {
  return w.engine.client.call("vault.recall", {
    query, effort: "light", limit: 100, token_budget: 8192, format: "md",
    scope: scope ?? { kinds: ["CLAIM"], worlds: { kind: "all" } },
  });
}
function values(pack: FacadeResult<"vault.recall">, predicate: string): string[] {
  return pack.items.filter(item => item.predicate === predicate).map(item => item.value_text).sort();
}
// Subsets of existing REST response DTOs from api/memory/mod.rs and
// api/context_pack/{controls,response}.rs. These are not new facade DTOs.
interface Timeline {
  anchor_id: string; narrowing: Facade.ScopedReadReceipt;
  records: { id: string; state: string; occurred_start?: number; occurred_end?: number;
    learned_at?: number; supersedes: string[]; superseded_by: string[]; item?: unknown }[];
}
async function timeline(w: World, id: string): Promise<Timeline> {
  await w.engine.requireHttpDoor("/v1/core/memory/{id}/timeline", "GET");
  return (await w.engine.client.request<Timeline>("GET",
    `/v1/core/memory/${encodeURIComponent(id)}/timeline?view=full`)).body;
}

// ARCH-0003 lifecycle; ARCH-0040 settlement and holder authority.
suite.test(test, "MEMORY-01", "Claim lifecycle: only the holder settles a proposal, its approval supersedes the original and retraction keeps history", async () => {
  const w = await setup("MEMORY-01");
  try {
    const c = scenario(w, "MEMORY-01");
    await witnessed(w, "@name-statement", `The name is ${c.current.value.value}.`);
    await witnessed(w, "@name-correction", `The name is now ${c.alternative.value.value}.`);
    const original = await w.engine.client.call("vault.claims.upsert", { ...claimInput(w, c.current), valid_from: w.occurred });
    // The opener never settles: a paired agent opens the proposal so the
    // holder (owner) can settle it. An owner-opened proposal is unsettleable.
    const outsider = await agent(w, "@agent-a");
    const seeded = await outsider.client.call("vault.claims.seed", {
      claims: [{ ...claimInput(w, c.alternative), valid_from: w.occurred }],
    });
    expect(seeded).toHaveLength(1);
    const alternative = seeded[0]!;
    expect(alternative.outcome).toBe("landed");
    if (alternative.outcome !== "landed") throw new Error("Alternative refused at setup");
    expect(alternative.approval).toBe("proposed");
    const oldId = (await entity(w.engine.client, original.claim_short_id)).id_hex;
    const newId = (await entity(w.engine.client, alternative.claim_short_id)).id_hex;
    const review = await w.engine.client.call("vault.claims.review", { claim_ref: newId });
    expect(review.claim.value).toBe(c.alternative.value.value);
    expect(review.claim.approval).toBe("proposed");
    expect(values(await recalled(w, "Morgan name"), c.current.predicate)).toEqual(c.expected.recallBeforeApproval);
    const refused = await outsider.client.raw("POST", "/v1/core/facade/vault.claims.settle", {
      claim_ref: newId, review_id: review.review_id, decision: "approve",
    } satisfies FacadeInput<"vault.claims.settle">);
    expect(refused.status).toBe(403);
    expect((await claim(w, newId)).approval).toBe("proposed");
    const settled = await w.engine.client.call("vault.claims.settle", {
      claim_ref: newId, review_id: review.review_id, decision: "approve",
    });
    expect(settled.review_id).toBe(review.review_id);
    expect(settled.proposal_ref).toBe(review.proposal_ref);
    expect(settled.verdict).toBe("landed");
    expect(settled.changes).toEqual([{ claim_ref: newId, verdict: "landed" }]);
    expect(settled.answered_by).toEqual({ kind: "word", person_ref: w.engine.pairedActor.principalRef });
    expect(settled.reason).toBe("gate.claim.settle.approved");
    expect(settled.revert?.claim_ref).toBe(newId);
    await w.engine.awaitReceipt(settled.receipt_ref);
    // The approval closes the supersession the proposal proposed (#6930; ARCH-0040): the agent's
    // approved claim supersedes the owner's original on its conflict set, so one head stands.
    // Settlement changes approval, never authorship: the settled row stays the agent's.
    const approved = await claim(w, newId);
    expect(approved.approval).toBe("approved"); expect(approved.lifecycle).toBe("active");
    const closed = await claim(w, oldId);
    expect(closed.approval).toBe("auto"); expect(closed.lifecycle).toBe("superseded");
    const standing = (await claims(w)).filter(row => row.predicate === c.current.predicate && row.lifecycle === "active");
    expect(standing.map(row => row.claim_ref)).toEqual([newId]);
    expect(values(await recalled(w, "Morgan name"), c.current.predicate))
      .toEqual(c.expected.recallAfterAuthorizedApprovalAndSupersession);
    // Retraction keeps history: the holder withdraws the approved claim, nothing stands in its
    // place, and the superseded original does not come back. The holder retracts, not the
    // authoring agent: at its Proposed ceiling an agent's retract must defer until the holder
    // approves it (ARCH-0040:131), and the engine has no deferred retract yet; it refuses the
    // agent's retract with 403 gate.pending.actor_ceiling (FIX AGENT-RETRACT-REFUSED-NOT-DEFERRED).
    const retracted = await w.engine.client.call("vault.claims.retract", { claim_ref: newId });
    expect(values(await recalled(w, "Morgan name"), c.current.predicate)).toEqual(c.expected.recallAfterRetraction);
    const history = (await w.engine.client.call("vault.claims.history", { claim_ref: newId })).value;
    const old = history.find(row => row.claim_ref === oldId);
    const current = history.find(row => row.claim_ref === newId);
    if (!old || !current) throw new Error("History lost a lifecycle row");
    expect(old.value).toBe(c.current.value.value);
    expect(old.lifecycle).toBe("superseded"); expect(old.approval).toBe("auto");
    expect(current.value).toBe(c.alternative.value.value);
    expect(current.lifecycle).toBe("retracted"); expect(current.approval).toBe("approved");
    // Validity closes without deleting: each row keeps its start and gains an end.
    expect(old.valid_from).toBe(w.occurred);
    for (const row of [old, current]) {
      expect(row.valid_to).not.toBeNull();
      expect(row.valid_to!).toBeGreaterThanOrEqual(row.valid_from!);
    }
    expect(old.source).toBe("user_stated");
    birth(old, w.engine.pairedActor.principalRef, [ref(w, "@name-statement")]);
    birth(current, ref(w, "@agent-a"), [ref(w, "@name-correction")]);
    // The Supersedes edge runs from the approved alternative to the original.
    const full = await timeline(w, newId);
    expect(full.records.map(row => row.id).sort()).toEqual([oldId, newId].sort());
    expect(full.records.find(row => row.id === oldId)?.state).toBe("superseded");
    const newer = full.records.find(row => row.id === newId)!;
    expect(newer.state).toBe("retracted"); expect(newer.supersedes).toContain(oldId);
    expect(full.records.find(row => row.id === oldId)?.superseded_by).toContain(newId);
    await w.engine.artifacts.json("lifecycle.json", { original, alternative, review, refusal: refused.body,
      settled, approved, closed, standing, retracted, history, timeline: full });
  } finally { await closeWorld(w) }
});

/* ARCH-0003 D18 and four required axes; ARCH-0040 host authorship.
 * Seven of eight malformed cases bind: four missing-axis cases refuse at
 * decode (deny_unknown_fields, required ClaimScope), out-of-range
 * confidence refuses per element (conf finite in [0,1] at encode),
 * unknown structural kinds refuse (registry lookup), and forged made_by
 * refuses at decode (made_by is not an input field). HTTP and tool-first
 * MCP use the same owner credential with positive controls on both.
 * The eighth case is a POSITIVE opaque-value control, not a refusal (Engine 10:14
 * YES on the 10:11 ASK): ARCH-0003:90 makes Claim/ClaimValue TypeScript the
 * app-layer view only, and :223-225 makes the per-predicate valueKind tuple
 * extractor/consolidator guidance rather than a Rust crate contract, while D18
 * (:92/:94) validates only the structural body plus the required scope keys; the
 * native predicate_validators.rs:294 treats generic val as opaque MessagePack with
 * specific families owning their own validators. The suite's own valid control is
 * itself an object, so object-ness cannot refuse. The {kind:number,
 * value:not-a-number} object therefore lands opaquely on @person-b (same four axes
 * as the control, distinct subject so the subject+scope+predicate supersession key
 * never closes the valid control) and reads back whole; asserting a refusal here
 * would contradict the canon-pinned oracle correction recorded in the fixture.
 * MCP arming note: tool-first verb calls need {schema_version, consent,
 * arguments: {spec}} (bare {spec} is refused); refusals arrive as
 * JSON-RPC errors, hook stops as isError results.
 * Keep the complete journey: paired valid control, all seven malformed cases plus
 * the opaque positive control over HTTP+MCP with per-element receipts, no surviving
 * bad row in claims/point-reads/neighbors/recall, HTTP/MCP parity, valid siblings
 * preserved, batch per-element outcomes (never blanket rollback).
 */
// The journey described above is at commit 0023232ce73 (tests/e2e/memory.test.ts). With #7297 its two
// house-minted projects take about 9 s, but its MCP half still costs about 1.6 s per tool call (the same
// verb over HTTP: about 0.04 s), and it reached only its MCP vault.get at 30 s (fleet job
// 1113-014554-4015). It keeps the 30 s cap and sits on the nightly budget list (Engine ruling 21:1x
// Thu 12 Nov, B) until [SLOW-FACADE-CALLS-COORDINATION-08] lands.
suite.todo(test, "MEMORY-02", "waits on [SLOW-FACADE-CALLS-COORDINATION-08]: 1.6 s MCP tool calls exceed the 30 s cap; nightly budget list (Claim admission rejects malformed scope should work)");

/* ARCH-0003 observed/stated disagreement; ARCH-0040 source trust.
 * The extraction and run-bound supersession doors NOW EXIST:
 * vault.memory.signal_extraction/result, self.run.attach, vault.claims.supersede.
 * Engine 2026-11-07 07:12 JST confirms the real run composition: agents.spawn,
 * pair the genuine agent_def_ref holder, read agents.spawn.get until leased,
 * then self.run.attach and claims.supersede as that agent. A queue receipt
 * alone does not let the human owner borrow the agent's run.
 * Engine 07:32 keeps this WHOLE/BLOCKED on the production Observed/language
 * producer FIX 21842. Model JSON is not a host-stamped Observed producer;
 * any source/value/scope oracle change is an Engine decision, not this suite's.
 * This fixture has not established deterministic timing for one attach while
 * the real run keeps its lease. A barrier inside the model entry holds the
 * same guard attach needs. Do not invent a new registration/hold API, retry
 * a Busy mutating attach, or substitute an inert AGENT_DEF, queued task,
 * guessed run id, execute_code or a weaker attach-only smoke test.
 * Keep the complete journey: English/user_stated; three Japanese requests
 * over two sessions; exact scripted production extraction; both active with
 * stated first and an exact conflict pair; a genuine generated supersession
 * attempt with refusal/held-proposal receipt and unchanged stated source,
 * evidence and lifecycle. Never directly upsert an observed result instead.
 */
suite.pendingDoor(test, "MEMORY-03",
  "waits on the production Observed/language producer (PR #6666, open) and qualification of the whole original leased supersession fixture; spawn/agent-pair/leased-get/attach composition exists. Observed and stated disagreement should work",
  { fix: "FIX 21842", deadline: "2026-12-01" });

/* MEMORY-04: ARCH-0032 writers, ARCH-0002 NOTE beside CLAIM, OF-330.
 * The owner writes the neutral Morgan Vale claim; two separately paired reviewer agents
 * (real AGENT_DEF principals) author opposite takes with vault.notes.author_take, each pinned to
 * the claim's matched revision. vault.edges.provenance audits each take's two authored links
 * (authored_by to its own reviewer, claim_of to the neutral claim): author, actor class and the
 * original source revision. Recall carries both NOTEs as opinion/take with their author refs,
 * bound to the reviewers' created names. The neutral claim's value, source, evidence, confidence,
 * lifecycle and history stay unchanged. This case declares the neutral claim in the owner's base
 * scope (default project), so it needs no project minting: the fixture's @project-north scope
 * is the project lane's, not this attribution promise's.
 */
suite.test(test, "MEMORY-04", "Opinion notes stay attributed should work", async () => {
  const data = await (await loadFixtures()).readJson<Data>("memory-canonical-cases");
  const providers = await ScriptedProviders.start({ id: "memory-attribution-MEMORY-04", steps: [] });
  const engine = await EngineFixture.start({ id: "MEMORY-04", profile });
  const occurred = 1769947200; // Public setup input, never an engine clock override.
  const conversation = await engine.client.call("vault.conversations.create", {
    body: {}, occurred_start: occurred, occurred_end: occurred, learned_at: occurred });
  const base = await ownerBaseClaimScope(engine.client, engine.pairedActor.principalRef);
  const w: World = { engine, providers, data, refs: new Map(), conversation: conversation.id, scope: base, occurred };
  const c = scenario(w, "MEMORY-04");
  const subject = await person(w, c.neutral.subjectId, c.neutral.value.value);
  const evidence = await witnessed(w, "@name-statement", `The name is ${c.neutral.value.value}.`);
  const neutral = await engine.client.call("vault.claims.upsert", {
    subject_ref: subject, predicate: c.neutral.predicate, value: c.neutral.value.value,
    confidence: c.neutral.confidence, source: c.neutral.source, scope: base,
    evidence_turn_refs: [evidence], occurred_at: occurred, learned_at: occurred,
  });
  expect(neutral.approval).toBe("auto");
  const neutralId = (await entity(engine.client, neutral.claim_short_id)).id_hex;
  const before = await claim(w, neutral.claim_short_id);
  const historyBefore = (await engine.client.call("vault.claims.history", { claim_ref: neutral.claim_short_id })).value;
  // The claim's matched revision, as the lexical index pins it: the source the takes cite.
  const hits = await engine.client.call("vault.search.bm25", { query: c.neutral.value.value, limit: 100 });
  let pinned: string | undefined;
  for (const hit of hits.value) {
    if (!/@[0-9a-f]{32}$/.test(hit.short_id)) continue;
    if ((await engine.client.call("vault.get", { entity_ref: hit.short_id })).value?.id_hex === neutralId) pinned = hit.short_id;
  }
  if (!pinned) throw new Error("The neutral claim has no revision-pinned lexical hit");
  const revision = pinned.slice(pinned.lastIndexOf("@") + 1);
  const reviewers = new Map<string, Awaited<ReturnType<typeof agent>>>();
  for (const take of c.takes) reviewers.set(take.actor, await agent(w, take.actor));
  const notes: { actor: string; note: string; reviewer: string }[] = [];
  for (const take of c.takes) {
    const reviewer = reviewers.get(take.actor)!;
    const written = await reviewer.client.call("vault.notes.author_take", {
      target: { claim: neutralId }, markdown: take.markdown, source_ref: pinned });
    const note = (await entity(engine.client, written.entity_ref)).id_hex;
    expect((await entity(engine.client, note)).kind).toBe("NOTE");
    const read = await engine.client.call("vault.notes.read", { note_ref: note });
    expect(read.value?.markdown).toContain(take.markdown);
    notes.push({ actor: take.actor, note, reviewer: reviewer.principalRef });
  }
  expect(new Set(notes.map(row => row.note)).size).toBe(c.expected.distinctTakeRecords);
  // Each take's two authored links keep their author and the original source revision.
  const audits: unknown[] = [];
  for (const row of notes) {
    for (const [edge_kind, target_ref] of [["authored_by", row.reviewer], [c.expected.eachTakeLinksToNeutralBy, neutralId]] as const) {
      const audit = await engine.client.call("vault.edges.provenance", { source_ref: row.note, edge_kind, target_ref });
      audits.push({ note: row.note, edge_kind, audit });
      expect(audit.value).toHaveLength(1);
      expect(audit.value[0]).toMatchObject({ source_ref: row.note, edge_kind, target_ref,
        actor_entity_ref: row.reviewer, actor_class: "agent", source_revision_ref: revision,
        supersession_status: "confirmed", lifecycle: "active", stale: false, valid_to: null });
      expect(audit.value[0]!.confidence).toBe(1);
    }
  }
  await engine.artifacts.json("memory04-edge-provenance.json", audits);
  // Recall labels both asides by kind and their bound authors; neither changes the neutral value.
  const pack = await engine.client.call("vault.recall", {
    query: `${c.neutral.value.value} full name given name observatory report reports`, effort: "medium",
    limit: 100, token_budget: 8192, format: "json", scope: { kinds: ["CLAIM", "NOTE"] } });
  await engine.artifacts.json("memory04-recall.json", pack);
  const recalled = new Set(pack.items.map(item => item.short_id));
  for (const id of [neutral.claim_short_id, ...notes.map(row => row.note)]) {
    const short = (await entity(engine.client, id)).short_ref ?? id;
    expect(recalled.has(short) || recalled.has(id)).toBe(true);
  }
  // Medium effort hydrates the fields the pack renders (light renders ids and scores only).
  for (const row of notes) expect(pack.rendered).toContain(row.reviewer);
  expect(pack.rendered).toContain(c.expected.noteKind);
  // The neutral claim is untouched: same value, source, evidence, confidence, lifecycle, history.
  const after = await claim(w, neutral.claim_short_id);
  expect(after).toEqual(before);
  expect(after.lifecycle).toBe(c.expected.neutralLifecycle);
  expect(after.source).toBe(c.expected.neutralSource);
  expect((await engine.client.call("vault.claims.history", { claim_ref: neutral.claim_short_id })).value).toEqual(historyBefore);
  await closeWorld(w);
});

interface TimedPackRequest {
  query: string; limit: number; edge_hop: number; view: "full";
  time: { occurred_start?: number; occurred_end?: number; learned_start?: number; learned_end?: number };
  budget: { token_budget?: number; retrieval: { claims: number } };
}
interface TimedPackReply {
  results: { id: string }[]; neighbors: { id: string }[]; narrowing: Facade.ScopedReadReceipt;
  stats?: { items_dropped?: { count: number; reason: string } };
}
// ARCH-0003 two clocks and Rule A; ARCH-0004 occurrence vs learned filters.
suite.test(test, "MEMORY-05", "Bitemporal entity history should work", async () => {
  const w = await setup("MEMORY-05");
  try {
    await w.engine.requireHttpDoor("/v1/core/context-pack", "POST");
    const c = scenario(w, "MEMORY-05");
    const rows: { role: string; id: string; input: typeof c.statements[number]; view: Entity; receipt: Receipt }[] = [];
    for (const input of c.statements) {
      for (const role of input.evidenceTurnIds ?? [])
        await witnessed(w, role, `${input.predicate}: ${input.value.value}`, input.occurredAt);
      const receipt = await w.engine.client.call("vault.claims.upsert", claimInput(w, input));
      const view = await entity(w.engine.client, receipt.claim_short_id);
      w.refs.set(input.ref, view.id_hex); rows.push({ role: input.ref, id: view.id_hex, input, view, receipt });
    }
    // One identical broad lexical query for all four windows. Filtering,
    // not query-word differences or as_of, must choose the singleton.
    const windows: { request: TimedPackRequest; pack: TimedPackReply; returned: { id: string; kind: Entity["kind"] }[] }[] = [];
    const lost: string[] = [];
    const packClaims = async (request: TimedPackRequest) => {
      const pack = (await w.engine.client.request<TimedPackReply>("POST", "/v1/core/context-pack", request)).body;
      const returned = await Promise.all(pack.results.map(item => entity(w.engine.client, item.id)));
      windows.push({ request, pack, returned: returned.map(item => ({ id: item.id_hex, kind: item.kind })) });
      await w.engine.artifacts.json("bitemporal-windows.json", windows);
      return { pack, claims: returned.filter(item => item.kind === "CLAIM").map(item => item.id_hex).sort() };
    };
    for (const window of c.windows) {
      const request: TimedPackRequest = { query: "profile Morgan Vale they them", limit: 100,
        edge_hop: 0, view: "full", budget: { token_budget: 8192, retrieval: { claims: 100 } },
        time: window.axis === "occurred"
          ? { occurred_start: window.start, occurred_end: window.end }
          : { learned_start: window.start, learned_end: window.end } };
      const expected = window.expected.map(role => ref(w, role)).sort();
      const { pack, claims: matched } = await packClaims(request);
      if (JSON.stringify(matched) === JSON.stringify(expected)) continue;
      // Only one difference is the engine's: the window is right, but the pack dropped an expected
      // CLAIM for token_budget far under its budget. The same window without a token budget must
      // return exactly the expected rows, and the budgeted pack may only lose rows, never add one.
      expect(pack.stats?.items_dropped?.reason).toBe("token_budget");
      expect(matched.filter(id => !expected.includes(id))).toEqual([]);
      expect((await packClaims({ ...request, budget: { retrieval: request.budget.retrieval } })).claims).toEqual(expected);
      const larger = await packClaims({ ...request, budget: { ...request.budget, token_budget: 65_536 } });
      lost.push(`${window.axis} ${window.start}..${window.end} lost ${expected.filter(id => !matched.includes(id)).join(",")}`
        + ` (at 65536 tokens: ${JSON.stringify(larger.claims) === JSON.stringify(expected) ? "kept" : "lost too"})`);
    }
    expect([...rows].sort((a, b) => a.view.occurred_start - b.view.occurred_start).map(row => row.role))
      .toEqual(c.expected.occurredOrder);
    expect([...rows].sort((a, b) => a.view.learned_at - b.view.learned_at).map(row => row.role))
      .toEqual(c.expected.learnedOrder);
    for (const row of rows) {
      const evidence = (row.input.evidenceTurnIds ?? []).map(role => ref(w, role));
      expect(row.view.occurred_start).toBe(row.input.occurredAt);
      expect(row.view.occurred_end).toBe(row.input.occurredAt);
      expect(row.view.learned_at).toBe(row.input.learnedAt);
      birth(row.view, w.engine.pairedActor.principalRef, evidence);
      expect(row.receipt.claim?.id).toBe(row.id);
      await w.engine.awaitReceipt(row.receipt.receipt_ref);
      const current = await claim(w, row.id);
      expect(current.value).toBe(row.input.value.value); expect(current.source).toBe("user_stated");
      expect(current.lifecycle).toBe("active"); birth(current, w.engine.pairedActor.principalRef, evidence);
      expect(current.made_by).toEqual(row.view.made_by);
      const full = await timeline(w, row.id);
      const record = full.records.find(item => item.id === row.id);
      if (!record) throw new Error("Timeline omitted historical statement");
      expect(record.occurred_start).toBe(row.input.occurredAt);
      expect(record.occurred_end).toBe(row.input.occurredAt);
      expect(record.learned_at).toBe(row.input.learnedAt);
      expect(await entity(w.engine.client, row.id)).toEqual(row.view);
      await w.engine.artifacts.json(`history-${row.role.replace(/[^a-z0-9]/gi, "-")}.json`, { row, current, timeline: full });
    }
    await w.engine.artifacts.json("bitemporal-windows.json", windows);
    if (lost.length) throw new Error(`ENGINE DEFECT 2026-11-12: the context pack drops a window's CLAIM for token_budget `
      + `although the same window without a token budget returns it (FIX CONTEXT-PACK-GROUP-SPLIT-DROPS-ROW): ${lost.join("; ")}`);
  } finally { await closeWorld(w) }
});

/* ARCH-0067 TASK roles and ARCH-0003 productivity vocabulary.
 * Role creation/tree and immutable check-in doors NOW EXIST. Install takes
 * HubImportRequest {hub_ref:{hub_id,ref_string,pin},publisher}, not a name.
 * Engine 2026-11-07 07:36 JST names the real pack oneiron.productivity.
 * Keep this whole journey BLOCKED until OPUS-L06's hub PR AND engine pin
 * PR merge and supply the exact HubImportRequest/pin/publisher. No invented
 * pack, arbitrary hub ref, new built-in install door, or omitted install.
 * Keep the full journey: install the declared pack; project scope plus
 * Goal -> Milestone -> routed Task and Habit; reject Goal/Task/Habit -> Task
 * with unchanged trees and no partial child; repeat the same check-in id
 * and immutable payload; refuse changed payload; one HabitCheckin child,
 * original clocks/data, current_streak=1 and longest_streak=1; task readback.
 */
suite.pendingDoor(test, "MEMORY-06",
  "waits on a pinned offline copy of the released oneiron.productivity pack with its authored install, routedTask and check-in data; #6668 is merged and every native install/role/tree/check-in door exists. Productivity pack journey should work",
  { fix: "FIX 22509", deadline: "2026-12-01" });

// ARCH-0055 redirect shells, evidence-guided split, masks and counter-events.
suite.test(test, "MEMORY-07", "Identity merge split and undo should work", async () => {
  const w = await setup("MEMORY-07");
  try {
    const c = scenario(w, "MEMORY-07");
    const originals: { id: string; subject: string; before: Claim }[] = [];
    for (const input of c.evidence) {
      const turn = await witnessed(w, `${input.ref}-turn`, input.content);
      const receipt = await w.engine.client.call("vault.claims.upsert", {
        subject_ref: ref(w, input.subject),
        predicate: input.ref === "@ambiguous-evidence" ? "profile.description" : "profile.name",
        value: input.ref === "@ambiguous-evidence" ? input.content
          : w.data.fixture.people.find(person => person.ref === input.subject)!.name,
        confidence: 1, source: "user_stated", scope: w.scope, evidence_turn_refs: [turn],
      });
      const id = (await entity(w.engine.client, receipt.claim_short_id)).id_hex;
      w.refs.set(input.ref, id); originals.push({ id, subject: ref(w, input.subject), before: await claim(w, id) });
    }
    const mask = applied(await w.engine.client.call("vault.identity.facet", {
      entity: ref(w, c.intentionalFacet.entity), facets: [{ label: "story" }], reassignment_map: [],
      evidence: { refs: [ref(w, "@evidence-a")], rationale: "The same person's intentional story mask." },
    }));
    if (mask.receipt.action.op !== "facet") throw new Error("Wrong mask action");
    const facetId = mask.receipt.action.facets[0]!;
    w.refs.set(c.intentionalFacet.facet, facetId);
    expect((await entity(w.engine.client, facetId)).kind).toBe("FACET");
    const mergeSpec: FacadeInput<"vault.identity.merge"> = {
      sources: c.merge.sources.map(role => ref(w, role)), survivor: ref(w, c.merge.survivor),
      evidence: { refs: c.merge.evidence.map(role => ref(w, role)), rationale: "Review the two source identities together." },
      survivorship_plan: "read_through",
    };
    const merged = applied(await w.engine.client.call("vault.identity.merge", mergeSpec));
    // Read through the merge: the survivor's remaining claims include the merged source's, which keep their subject.
    const survivor = await w.engine.client.call("vault.identity.resolve", { entity: ref(w, "@person-a") });
    for (const role of ["@evidence-a", "@evidence-b", "@ambiguous-evidence"]) expect(survivor.remaining_claims).toContain(ref(w, role));
    const bMerged = await w.engine.client.call("vault.identity.resolve", { entity: ref(w, "@person-b") });
    expect(bMerged.state).toBe("merged"); expect(bMerged.heads).toEqual([ref(w, "@person-a")]);
    expect(bMerged.merged_into).toEqual([ref(w, "@person-a")]);
    expect((await entity(w.engine.client, ref(w, "@person-b"))).kind).toBe("PERSON");
    for (const role of c.split.heads) await person(w, role, role === "@head-north" ? "Morgan North head" : "Morgan South head");
    // A claim of a person never merged into the survivor: a split map entry naming it is dropped.
    const outsiderId = await person(w, "@person-outsider", "Morgan Outsider");
    const outsiderTurn = await witnessed(w, "@outsider-turn", "Morgan Outsider made no observatory report.");
    const outsiderReceipt = await w.engine.client.call("vault.claims.upsert", {
      subject_ref: outsiderId, predicate: "profile.name", value: "Morgan Outsider",
      confidence: 1, source: "user_stated", scope: w.scope, evidence_turn_refs: [outsiderTurn],
    });
    const outsiderClaim = (await entity(w.engine.client, outsiderReceipt.claim_short_id)).id_hex;
    const outsiderBefore = await claim(w, outsiderClaim);
    const splitMap = c.split.reassignment_map;
    const splitSpec: FacadeInput<"vault.identity.split"> = {
      entity: ref(w, c.split.entity), heads: c.split.heads.map(role => ref(w, role)),
      // The fixture's map (the survivor's own claim to North, the merged source's claim to South), the
      // ambiguous claim named as residue, and the never-merged outsider's claim, which the split drops.
      reassignment_map: [
        ...splitMap.map(item => ({
          item: { kind: "claim" as const, claim: ref(w, item.evidence) }, target: { kind: "head" as const, head: ref(w, item.head) },
        })),
        { item: { kind: "claim" as const, claim: ref(w, "@ambiguous-evidence") }, target: { kind: "residue" as const } },
        { item: { kind: "claim" as const, claim: outsiderClaim }, target: { kind: "head" as const, head: ref(w, "@head-south") } },
      ],
      evidence: { refs: c.split.evidence.map(role => ref(w, role)), rationale: "North and South evidence identify separate people." },
    };
    const split = applied(await w.engine.client.call("vault.identity.split", splitSpec));
    const shell = await w.engine.client.call("vault.identity.resolve", { entity: ref(w, "@person-a") });
    const chain = await w.engine.client.call("vault.identity.resolve", { entity: ref(w, "@person-b") });
    const heads = c.split.heads.map(role => ref(w, role)).sort();
    expect(shell.state).toBe("split"); expect(shell.heads.sort()).toEqual(heads);
    expect(shell.split_into.sort()).toEqual(heads); expect(chain.heads.sort()).toEqual(heads);
    expect(shell.ambiguous_residue).toContain(ref(w, "@ambiguous-evidence"));
    for (const mapping of splitMap) {
      const head = await w.engine.client.call("vault.identity.resolve", { entity: ref(w, mapping.head) });
      expect(head.assigned_claims).toContain(ref(w, mapping.evidence));
      expect(head.assigned_claims).not.toContain(outsiderClaim);
    }
    // The merged source's claim is assigned away from the survivor; the outsider's claim is untouched.
    expect(shell.remaining_claims).not.toContain(ref(w, "@evidence-b"));
    expect(await claim(w, outsiderClaim)).toEqual(outsiderBefore);
    for (const original of originals) {
      const current = await claim(w, original.id);
      expect(current.subject_ref).toBe(original.subject);
      expect(current.value).toEqual(original.before.value);
      expect(current.made_by).toEqual(original.before.made_by);
    }
    for (const operation of [merged, split]) {
      const stored = await w.engine.client.call("vault.identity.events.get", { event: operation.receipt.event });
      expect(stored).toEqual(operation.receipt);
      expect(stored.actor).toBe(w.engine.pairedActor.principalRef);
      expect(stored.evidence).toEqual(operation.receipt.action.op === "merge" ? mergeSpec.evidence : splitSpec.evidence);
    }
    const undoSplit = applied(await w.engine.client.call("vault.identity.undo", {
      event: split.receipt.event, seen: split.receipt.seen,
    }));
    expect(undoSplit.receipt.action).toEqual({ op: "undo", target: split.receipt.event });
    expect(undoSplit.receipt.seq).toBeGreaterThan(split.receipt.seq);
    expect((await w.engine.client.call("vault.identity.resolve", { entity: ref(w, "@person-b") })).heads)
      .toEqual([ref(w, "@person-a")]);
    const undoMerge = applied(await w.engine.client.call("vault.identity.undo", {
      event: merged.receipt.event, seen: merged.receipt.seen,
    }));
    expect(undoMerge.receipt.action).toEqual({ op: "undo", target: merged.receipt.event });
    expect(undoMerge.receipt.seq).toBeGreaterThan(undoSplit.receipt.seq);
    for (const role of ["@person-a", "@person-b"]) {
      const resolution = await w.engine.client.call("vault.identity.resolve", { entity: ref(w, role) });
      expect(resolution.heads).toEqual([ref(w, role)]); expect(resolution.state).toBe("active");
    }
    // The undos are counter-events: every logged field of both events reads back unchanged. `seen` is the
    // topology seal revision, computed at read time over the live deciding rows (verbs/identity_topology/
    // ops.rs:136), so the undo rows move it.
    for (const operation of [merged, split]) {
      const { seen: before, ...logged } = operation.receipt;
      const { seen: now, ...stored } = await w.engine.client.call("vault.identity.events.get", { event: operation.receipt.event });
      expect(stored).toEqual(logged);
      for (const revision of [before, now]) expect(revision).toMatch(/^[0-9a-f]{64}$/);
    }
    for (const original of originals) expect(await claim(w, original.id)).toEqual(original.before);
    const distinct = applied(await w.engine.client.call("vault.identity.assert_distinct", {
      a: ref(w, "@person-a"), b: ref(w, "@person-b"), reason: c.expected.distinct.reason,
    }));
    const proposal = await w.engine.client.raw("POST", "/v1/core/facade/vault.identity.propose", {
      operation: { op: "merge", spec: mergeSpec },
    } satisfies FacadeInput<"vault.identity.propose">);
    if (proposal.status >= 200 && proposal.status < 300) {
      expect(object(proposal.body).outcome).toBe("noop");
    } else {
      expect(proposal.status).toBeGreaterThanOrEqual(400); expect(proposal.status).toBeLessThan(500);
      expect(proposal.raw.length).toBeGreaterThan(0);
    }
    const suggestions = await w.engine.client.call("vault.identity.proposals.for_pair", {
      a: ref(w, "@person-a"), b: ref(w, "@person-b"),
    });
    expect(suggestions.proposals).toEqual([]); expect(suggestions.distinct_claims.length).toBeGreaterThan(0);
    const distinctRows = (await claims(w)).filter(row => row.predicate === "entity.distinct_from");
    expect(distinctRows.length).toBeGreaterThan(0);
    const masks = await w.engine.client.call("vault.identity.resolve", { entity: ref(w, "@person-a") });
    expect(masks.facets).toContain(facetId);
    expect((await entity(w.engine.client, facetId)).kind).toBe("FACET");
    await w.engine.artifacts.json("identity-topology.json", { mask, merged, bMerged, split, shell, chain,
      undoSplit, undoMerge, distinct, proposal: { status: proposal.status, body: proposal.body }, suggestions, originals });
  } finally { await closeWorld(w) }
});

// ARCH-0022 four explicit axes; ARCH-0004 labelled world partitions;
// ARCH-0043 grant axes are distinct from requested axes.
suite.test(test, "MEMORY-08", "World and project separation should work", async () => {
  const w = await setup("MEMORY-08", ["@project-north", "@project-south"]);
  try {
    const c = scenario(w, "MEMORY-08");
    const ids: string[] = [];
    for (const input of c.claims) {
      const receipt = await w.engine.client.call("vault.claims.upsert", claimInput(w, input));
      const id = (await entity(w.engine.client, receipt.claim_short_id)).id_hex; ids.push(id);
      const stored = await claim(w, id);
      expect(stored.claim_scope).toEqual(claimInput(w, input).scope);
      expect(stored.value).toBe(input.value.value); expect(stored.lifecycle).toBe("active");
    }
    // Same subject/predicate in six explicit partitions must not supersede.
    const nameRows = (await claims(w)).filter(row => row.predicate === c.claims[0]!.predicate);
    expect(nameRows).toHaveLength(6); expect(nameRows.every(row => row.lifecycle === "active")).toBe(true);
    // An All-world pack keeps at most half its claims from non-base worlds unless a facet is named;
    // every claim here sits at the shared work facet, which lifts that share without widening authority.
    const all = await recalled(w, "Morgan Vale Glass keeper Paper captain north south name", {
      worlds: { kind: "all" }, facet: ref(w, "@facet-work"),
      project_refs: w.data.fixture.projects.map(row => ref(w, row.ref)), kinds: ["CLAIM"],
    });
    expect(values(all, c.claims[0]!.predicate)).toEqual(c.claims.map(row => row.value.value).sort());
    const names = all.items.filter(item => item.predicate === c.claims[0]!.predicate);
    expect(names.slice(0, 2).map(item => item.world)).toEqual([ref(w, "@base"), ref(w, "@base")]);
    for (const world of ["@base", "@dream", "@roleplay"]) {
      const positions = names.map((item, index) => item.world === ref(w, world) ? index : -1)
        .filter(index => index >= 0);
      expect(positions).toHaveLength(2);
      expect(positions[1]! - positions[0]!).toBe(1);
    }
    for (const input of c.claims) {
      const item = names.find(item => item.value_text === input.value.value);
      expect(item?.world).toBe(ref(w, input.worldId));
      expect(item?.project_ref).toBe(ref(w, input.scopeProjectId));
      const selected = await recalled(w, "Morgan Vale Glass keeper Paper captain north south name", {
        worlds: input.worldId === "@base" ? { kind: "base" }
          : { kind: "world", world_ref: ref(w, input.worldId), include_base: false },
        project_refs: [ref(w, input.scopeProjectId)], kinds: ["CLAIM"],
      });
      expect(values(selected, input.predicate)).toEqual([input.value.value]);
    }
    // Mint a real, distinct reader. Attenuation below narrows that reader's
    // actual paired read grant, never the owner's own-root authority.
    const guestId = await person(w, "@guest", "Observatory guest reader");
    const guest = await w.engine.pairActor({ principalRef: guestId, actorClass: "human", scope: ["core:read"] });
    expect((await guest.client.call("self.actor", {})).actor_ref).toBe(guestId);
    const { seed } = credentialParts(guest.credential);
    const topRest: Pick<Facade.Scope, "bands" | "audience" | "verbs" | "sensitivity"> = {
      bands: { kind: "all" }, audience: { kind: "all" },
      verbs: { kind: "some", values: ["core:read"] }, sensitivity: { kind: "all" },
    };
    async function reader(scope: Facade.Scope): Promise<PublicHttpClient> {
      const narrowed = await guest.client.call("self.credential.attenuate", {
        holder_seed: [...Buffer.from(seed, "hex")], caveat: { scope: { kind: "ceiling", scope } },
      });
      expect(narrowed.token.startsWith("v2.slip.")).toBe(true);
      // binding_key is public. No transfer was requested: retain our own
      // seed, not the returned public key, in the paired credential format.
      return new PublicHttpClient(w.engine.url, { credential: `v2.cred.${narrowed.token.slice(8)}.${seed}`,
        artifacts: w.engine.artifacts });
    }
    const positive = await reader({ ...topRest, worlds: { kind: "some", values: [ref(w, "@dream")] },
      facets: { kind: "some", values: [ref(w, "@facet-work")] } });
    const query: FacadeInput<"vault.recall"> = { query: "Glass keeper north south name", effort: "light",
      limit: 100, token_budget: 8192, scope: { worlds: { kind: "all" }, facet: ref(w, "@facet-work"), kinds: ["CLAIM"] } };
    const readable = await positive.call("vault.recall", query);
    // The world ceiling admits exactly the two @dream rows, one per project. A guest connection reads at
    // the Public band, so each name-class value prints as the subject's handle, never a fake and never a
    // drop (ARCH-0069 S9; disclosure/model_channel.rs claim_handle_in).
    const dream = c.claims.filter(row => row.worldId === "@dream");
    const guestNames = readable.items.filter(item => item.predicate === c.claims[0]!.predicate);
    expect(guestNames.map(item => item.world)).toEqual(dream.map(() => ref(w, "@dream")));
    expect(guestNames.map(item => item.project_ref).sort()).toEqual(dream.map(row => ref(w, row.scopeProjectId)).sort());
    for (const item of guestNames) {
      expect(item.value_text.length).toBeGreaterThan(0);
      expect(c.claims.map(row => row.value.value)).not.toContain(item.value_text);
    }
    const receipts = [];
    for (const input of c.expected.guestCeilingCases) {
      const scope: Facade.Scope = { ...topRest,
        ...(input.worlds === undefined ? {} : { worlds: { kind: "some" as const, values: input.worlds.map(role => ref(w, role)) } }),
        ...(input.facets === undefined ? {} : { facets: { kind: "some" as const, values: input.facets.map(role => ref(w, role)) } }) };
      const client = await reader(scope);
      const ceiling = await client.call("vault.scope.ceiling", {});
      const deniedAxis = input.name.includes("world") ? ceiling.scope.worlds : ceiling.scope.facets;
      expect(deniedAxis?.kind).toBe("bottom");
      const pack = await client.call("vault.recall", query);
      expect(pack.items).toHaveLength(input.expectedReadableClaims);
      // A bottom world floors the scalar read ceiling (deny_all); a bottom facet withholds rows by
      // facet admission instead, so its scalar ceiling stays open while the items stay empty.
      const worldBottom = input.name.includes("world");
      expect(pack.narrowing.actor_ceiling.deny_all).toBe(worldBottom);
      expect(pack.narrowing.applied.deny_all).toBe(worldBottom);
      // The receipt names deny_all for a bottom world. A bottom facet is the key's own baseline:
      // its per-row withholding stays opaque, so it names no axis and counts no suppressed row
      // (oneiron-contracts claim/receipt.rs record_axes; claim/scoped_read/search.rs, FIX 8670).
      if (worldBottom) expect(pack.narrowing.narrowed_axes).toContain("deny_all");
      else { expect(pack.narrowing.narrowed_axes).toEqual([]); expect(pack.narrowing.suppressed_count).toBe(0); }
      // An empty *requested* world set adds no narrowing; it cannot lift a
      // bottom credential to top. Same zero result and same applied ceiling.
      const emptyRequested = await client.call("vault.recall", { ...query,
        scope: { worlds: { kind: "worlds", world_refs: [], include_base: false }, kinds: ["CLAIM"] } });
      expect(emptyRequested.items).toEqual([]);
      expect(emptyRequested.narrowing.applied.deny_all).toBe(worldBottom);
      receipts.push({ name: input.name, ceiling, pack, emptyRequested });
    }
    const missing = claimInput(w, c.claims[0]!, inputId("MEMORY-08:missing-world"));
    const malformed: Record<string, unknown> = { ...missing, scope: { ...missing.scope } };
    delete object(malformed.scope).world_id;
    const rejected = await w.engine.client.raw("POST", "/v1/core/facade/vault.claims.upsert", malformed);
    expect(rejected.status).toBeGreaterThanOrEqual(400); expect(rejected.status).toBeLessThan(500);
    expect((await w.engine.client.call("vault.get", { entity_ref: missing.id! })).value).toBeNull();
    expect((await claims(w)).filter(row => row.predicate === c.claims[0]!.predicate)).toHaveLength(6);
    await w.engine.artifacts.json("world-project-scopes.json", { ids, all, positive: readable, receipts, refusal: rejected.body });
  } finally { await closeWorld(w) }
});
