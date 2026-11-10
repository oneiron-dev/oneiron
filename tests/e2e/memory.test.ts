import { afterAll, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { mkdir, copyFile } from "node:fs/promises";
import { resolve } from "node:path";
import { inflateRawSync } from "node:zlib";
import { blake3 } from "@noble/hashes/blake3";
import type { Facade, FacadeInput, FacadeResult, FacadeVerb } from "@oneiron/client";
import { EngineFixture, awaitPublic } from "./support/engine.ts";
import { credentialParts, PublicHttpClient, PublicHttpError } from "./support/clients.ts";
import { loadFixtures, ownerBaseClaimScope } from "./support/fixtures.ts";
import { ScriptedProviders, openaiStream, openaiText } from "./support/providers.ts";
import { BlockedDoor, defineFile, LIMITS, redactor, secretHex } from "./support/run.ts";

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
 * MEMORY-01 and MEMORY-07 are E2E-PARTIAL subsets (Engine 23:01), named for what they prove:
 * an approved proposal does not supersede the original, and a split reads only the split person's
 * own claims; each case says what stays unproved, with a FIX row filed at READY.
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
  await providers.awaitBarrier(intake);
  providers.releaseBarrier(intake);
  expect((await entity(client, minted.project_id)).kind).toBe("PROJECT");
  return minted.project_id;
}
async function closeWorld(w: World): Promise<void> {
  const errors: string[] = [];
  const text = (error: unknown): string => error instanceof Error ? error.message : String(error);
  try { await w.engine.close({retainVault:process.env.E2E_MEMORY_RETAIN_VAULT==="1"}); } catch (error) { errors.push(text(error)); }
  try { await w.providers.close(); } catch (error) { errors.push(text(error)); }
  if (errors.length) throw new Error(`close: ${errors.join("; ")}`);
}
async function setup(id: string): Promise<World> {
  const data = await (await loadFixtures()).readJson<Data>("memory-canonical-cases");
  const providers = await ScriptedProviders.start({ id: `memory-projects-${id}`, origins: ["decider", "drafter"], steps: [] });
  const engine = await EngineFixture.start({ id, profile, serverConfig: memoryModels(providers),
    serverLog: "info,oneiron::workflow_pump=debug,oneiron_server::ai_host=debug,oneiron_server::big_rung=debug,oneiron_server::decision_host=debug,oneiron::agent_dispatch=debug,oneiron::llm::decision=debug,oneiron::workspace_roster=debug" });
  const occurred = 1769947200; // Public setup input, never an engine clock override.
  await installProjectProposal(engine);
  // DEFECT (2026-11-10, FIX HOUSE-SOURCE-READ-DENIED, being fixed by OPUS-E2E-3): on a fresh vault
  // the house (the seeded sys.team_lead) has no scoped read row for the unscoped source MESSAGE, as
  // the Dreamer and the Coach have (project_proposal.rs:159-166), so its project question settles
  // unread and never reaches the decider. MEMORY-01, -02, -05, -07 and -08 stay red here until that
  // fix lands. No owner grant works around it (Engine 07:00).
  const base = await ownerBaseClaimScope(engine.client, engine.pairedActor.principalRef);
  const projects = new Map<string, string>();
  for (const [index, row] of data.fixture.projects.entries()) {
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
/** Recalled values of `predicate` whose item is one of `rows`, one subject's claims. */
function subjectValues(pack: FacadeResult<"vault.recall">, predicate: string, rows: readonly Claim[]): string[] {
  const own = new Set(rows.flatMap(row => [row.claim_ref, ...(row.short_ref ? [row.short_ref] : [])]));
  return pack.items.filter(item => item.predicate === predicate && own.has(item.short_id))
    .map(item => item.value_text).sort();
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
suite.test(test, "MEMORY-01", "Claim lifecycle: only the holder settles a proposal, the owner's correction supersedes and retraction keeps history", async () => {
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
    // E2E-PARTIAL: settlement changes approval, never authorship, and an approved proposal does not
    // supersede the original (FIX row filed with the READY). The settled row stays the agent's: its
    // author withdraws it, and the owner's own correction of the original (FIX 22041) lands at once
    // and closes the original in the same write. No proposal opens, so nothing is settled twice.
    expect((await claim(w, newId)).approval).toBe("approved");
    await outsider.client.call("vault.claims.retract", { claim_ref: newId });
    const supersession = await w.engine.client.call("vault.claims.upsert", { ...claimInput(w, c.alternative), valid_from: w.occurred });
    const correctionId = (await entity(w.engine.client, supersession.claim_short_id)).id_hex;
    expect(correctionId).not.toBe(newId);
    expect(supersession.approval).toBe("auto");
    expect(supersession.superseded_short_id).toBe(original.claim_short_id);
    expect(supersession.superseded?.id).toBe(oldId);
    await w.engine.awaitReceipt(supersession.receipt_ref);
    expect((await claim(w, correctionId)).approval).toBe("auto");
    expect(values(await recalled(w, "Morgan name"), c.current.predicate))
      .toEqual(c.expected.recallAfterAuthorizedApprovalAndSupersession);
    const retracted = await w.engine.client.call("vault.claims.retract", { claim_ref: correctionId });
    expect(values(await recalled(w, "Morgan name"), c.current.predicate)).toEqual(c.expected.recallAfterRetraction);
    const history = (await w.engine.client.call("vault.claims.history", { claim_ref: correctionId })).value;
    const old = history.find(row => row.claim_ref === oldId);
    const current = history.find(row => row.claim_ref === correctionId);
    if (!old || !current) throw new Error("History lost a lifecycle row");
    expect(old.value).toBe(c.current.value.value);
    expect(old.lifecycle).toBe("superseded"); expect(old.approval).toBe("auto");
    expect(current.value).toBe(c.alternative.value.value);
    expect(current.lifecycle).toBe("retracted"); expect(current.approval).toBe("auto");
    for (const [row, evidence] of [[old, ref(w, "@name-statement")], [current, ref(w, "@name-correction")]] as const) {
      expect(row.valid_from).toBe(w.occurred); expect(row.valid_to).not.toBeNull();
      expect(row.valid_to!).toBeGreaterThanOrEqual(row.valid_from!);
      expect(row.source).toBe("user_stated"); birth(row, w.engine.pairedActor.principalRef, [evidence]);
    }
    // The settled proposal keeps its own record: the agent's, approved, then withdrawn by its author.
    const proposalRow = await claim(w, newId);
    expect(proposalRow.approval).toBe("approved"); expect(proposalRow.lifecycle).toBe("retracted");
    birth(proposalRow, ref(w, "@agent-a"), [ref(w, "@name-correction")]);
    const full = await timeline(w, correctionId);
    expect(full.records.map(row => row.id).sort()).toEqual([oldId, correctionId].sort());
    expect(full.records.find(row => row.id === oldId)?.state).toBe("superseded");
    const newer = full.records.find(row => row.id === correctionId)!;
    expect(newer.state).toBe("retracted"); expect(newer.supersedes).toContain(oldId);
    expect(full.records.find(row => row.id === oldId)?.superseded_by).toContain(correctionId);
    await w.engine.artifacts.json("lifecycle.json", { original, alternative, review, refusal: refused.body,
      settled, correctionId, supersession, retracted, history, proposalRow, timeline: full });
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
suite.test(test, "MEMORY-02", "Claim admission rejects malformed scope should work", async () => {
  const w = await setup("MEMORY-02");
  const errorText = (error: unknown): string => error instanceof Error ? error.message : String(error);
  let primaryFailed = false;
  let primary: unknown;
  try {
    await w.engine.mcp.initialize();
    type McpTool = { name: string; inputSchema: { properties: { schema_version: { const: string } } } };
    type McpTools = { surfaceMode: string; tools: McpTool[] };
    const tools = await w.engine.mcp.listTools() as McpTools;
    // Consent producer (this suite) + consumer (MCP validate: nonblank policy_ref/purpose
    // only, no registry lookup): the label below is caller-owned, like policy:boot-session.
    const toolArguments = (name: string, fields: Record<string, unknown>): Record<string, unknown> => {
      const tool = tools.tools.find(item => item.name === name);
      if (!tool) throw new Error(`Required public MCP tool not registered: ${name}`);
      // The version is a transport binding from tools/list, not an expected outcome.
      return { schema_version: tool.inputSchema.properties.schema_version.const,
        consent: { policy_ref: "policy:memory-02-claim-admission", purpose: "MEMORY-02 claim admission journey" }, ...fields };
    };
    type McpCallResult = { isError: boolean; structuredContent?: { output?: unknown; actor?: unknown; meta?: unknown } };
    const mcpCall = async <V extends FacadeVerb>(verb: V, input: FacadeInput<V>): Promise<FacadeResult<V>> => {
      const reply = await w.engine.mcp.callTool(verb, toolArguments(verb, { arguments: { spec: input } })) as McpCallResult;
      expect(reply.isError).toBe(false);
      const output = reply.structuredContent?.output as FacadeResult<V> | undefined;
      if (output === undefined) throw new Error(`MCP ${verb} returned no structured output`);
      return output;
    };
    const mcpRefused = async (verb: string, spec: unknown): Promise<unknown> => {
      const reply = await w.engine.mcp.rpc("tools/call",
        { name: verb, arguments: toolArguments(verb, { arguments: { spec } }) });
      if (!("error" in reply)) throw new Error(`Expected an MCP JSON-RPC refusal for ${verb}`);
      const data = reply.error.data as Record<string, unknown> | undefined;
      if (!data || typeof data !== "object") throw new Error(`MCP ${verb} refusal has no data envelope`);
      // Structural shape only (boot pattern): no refusal-literal pinning without an observed run.
      expect(typeof data.kind).toBe("string");
      expect((data.kind as string).length).toBeGreaterThan(0);
      expect(data.error_code).toBe(data.kind);
      expect(Array.isArray(data.recovery_suggestions)).toBe(true);
      expect((data.recovery_suggestions as unknown[]).length).toBeGreaterThan(0);
      return reply;
    };
    const errMessage = (body: unknown): unknown => (body as { error?: { message?: unknown } }).error?.message;
    const errCode = (body: unknown): unknown => (body as { error?: { code?: unknown } }).error?.code;
    // Both decode and typed InvalidClaimBody-family refusals answer 400; literals stay archived.
    const expectRefused = (status: number, body: unknown): void => {
      expect(status).toBe(400);
      expect(typeof errCode(body)).toBe("string");
      expect((errCode(body) as string).length).toBeGreaterThan(0);
      expect(typeof errMessage(body)).toBe("string");
      expect((errMessage(body) as string).length).toBeGreaterThan(0);
    };
    const neighborSet = async (subject: string): Promise<string[]> =>
      // Page size mirrors ownerBaseClaimScope (support/fixtures.ts), not a new constant.
      (await w.engine.client.call("vault.neighbors", { entity_ref: ref(w, subject), opts: { limit: 100 } }))
        .value.map(hit => `${hit.short_id}|${hit.kind}|${hit.edge_kind}|${hit.direction}|${hit.weight}`).sort();
    const scopedValues = async (person: string, project: string, query: string, rows?: readonly Claim[]): Promise<string[]> =>
      subjectValues(await recalled(w, query, { worlds: { kind: "all" }, project_refs: [ref(w, project)],
        kinds: ["CLAIM"] }), "profile.name", rows ?? await claims(w, person));
    type Memory02Snapshot = { listA: string[]; listB: string[]; predA: string[]; predB: string[];
      neighborsA: string[]; neighborsB: string[]; recallANorth: string[]; recallBNorth: string[];
      recallASouth: string[]; recallBSouth: string[] };
    const snapshot = async (): Promise<Memory02Snapshot> => {
      const rowsA = await claims(w, "@person-a");
      const rowsB = await claims(w, "@person-b");
      return {
        listA: rowsA.map(row => row.claim_ref).sort(),
        listB: rowsB.map(row => row.claim_ref).sort(),
        predA: [...new Set(rowsA.map(row => row.predicate))].sort(),
        predB: [...new Set(rowsB.map(row => row.predicate))].sort(),
        neighborsA: await neighborSet("@person-a"),
        neighborsB: await neighborSet("@person-b"),
        recallANorth: await scopedValues("@person-a", "@project-north", "Morgan Vale", rowsA),
        recallBNorth: await scopedValues("@person-b", "@project-north", "not-a-number number kind", rowsB),
        recallASouth: await scopedValues("@person-a", "@project-south", "Morgan Vale", rowsA),
        recallBSouth: await scopedValues("@person-b", "@project-south", "not-a-number number kind", rowsB),
      };
    };
    const expectUnchanged = async (before: Memory02Snapshot): Promise<void> => {
      expect(await snapshot()).toEqual(before);
    };
    const c = scenario(w, "MEMORY-02");
    expect(c.malformed).toHaveLength(7);
    expect(c.opaqueControl.replaces).toBe("invalid-value");
    expect(c.malformed.some(item => item.case === "invalid-value")).toBe(false);
    await witnessed(w, "@name-statement", `The name is ${c.valid.value.value}.`);
    const owner = w.engine.pairedActor.principalRef;
    const refusals: { case: string; surface: string; status?: number; body: unknown }[] = [];
    // HTTP valid control (original placement: @person-a + north axes).
    const validInput = claimInput(w, c.valid, inputId("MEMORY-02:valid-http"));
    const validReceipt = await w.engine.client.call("vault.claims.upsert", validInput);
    expect(validReceipt.approval).toBe("auto");
    await w.engine.awaitReceipt(validReceipt.receipt_ref);
    const validId = (await entity(w.engine.client, validReceipt.claim_short_id)).id_hex;
    const validRow = await claim(w, validId);
    expect(validRow.value).toBe(c.valid.value.value);
    expect(validRow.claim_scope).toEqual(validInput.scope);
    birth(validRow, owner, [ref(w, "@name-statement")]);
    expect(validRow.approval).toBe("auto");
    expect(validRow.lifecycle).toBe("active");
    expect(validRow.source).toBe("user_stated");
    expect((await entity(w.engine.client, validId)).made_by).toEqual(validRow.made_by);
    expect(await scopedValues("@person-a", "@project-north", "Morgan Vale")).toEqual([c.valid.value.value]);
    // HTTP opaque control (@person-b + same four axes; subject differs so the
    // subject+scope+predicate supersession key never closes the valid control).
    const opaqueBase: CanonicalClaim = { subjectId: c.opaqueControl.subjectId, predicate: c.opaqueControl.predicate,
      value: { kind: "string", value: "opaque-placeholder-never-sent" }, confidence: c.opaqueControl.confidence,
      source: c.opaqueControl.source, worldId: c.opaqueControl.worldId, scopeFacetId: c.opaqueControl.scopeFacetId,
      scopeRelationshipId: c.opaqueControl.scopeRelationshipId, scopeProjectId: c.opaqueControl.scopeProjectId,
      ...(c.opaqueControl.evidenceTurnIds === undefined ? {} : { evidenceTurnIds: c.opaqueControl.evidenceTurnIds }) };
    // Stock claimInput sends row.value.value; the opaque control overrides with the whole
    // fixture object through the real `value: unknown` typed boundary (no cast, no second door).
    const opaqueInput: ClaimInput = { ...claimInput(w, opaqueBase, inputId("MEMORY-02:opaque-http")), value: c.opaqueControl.value };
    const opaqueReceipt = await w.engine.client.call("vault.claims.upsert", opaqueInput);
    expect(opaqueReceipt.approval).toBe("auto");
    await w.engine.awaitReceipt(opaqueReceipt.receipt_ref);
    const opaqueId = (await entity(w.engine.client, opaqueReceipt.claim_short_id)).id_hex;
    const opaqueRow = await claim(w, opaqueId);
    expect(opaqueRow.value).toEqual(c.opaqueControl.value);
    expect(opaqueRow.claim_scope).toEqual(opaqueInput.scope);
    birth(opaqueRow, owner, [ref(w, "@name-statement")]);
    expect(opaqueRow.approval).toBe("auto");
    expect(opaqueRow.lifecycle).toBe("active");
    expect(opaqueRow.source).toBe("user_stated");
    expect((await entity(w.engine.client, opaqueId)).made_by).toEqual(opaqueRow.made_by);
    const opaqueTextNorth = await scopedValues("@person-b", "@project-north", "not-a-number number kind");
    expect(opaqueTextNorth).toHaveLength(1);
    expect(opaqueTextNorth[0]!.length).toBeGreaterThan(0);
    // MCP mirrors on @project-south (project differs, so no supersession either way).
    const mcpValidInput = claimInput(w, { ...c.valid, scopeProjectId: "@project-south" }, inputId("MEMORY-02:valid-mcp"));
    const mcpValidReceipt = await mcpCall("vault.claims.upsert", mcpValidInput);
    expect(mcpValidReceipt.approval).toBe("auto");
    await w.engine.awaitReceipt(mcpValidReceipt.receipt_ref);
    const mcpValidId = (await entity(w.engine.client, mcpValidReceipt.claim_short_id)).id_hex;
    const mcpValidRow = await claim(w, mcpValidId);
    expect(mcpValidRow.value).toBe(c.valid.value.value);
    expect(mcpValidRow.claim_scope).toEqual(mcpValidInput.scope);
    birth(mcpValidRow, owner, [ref(w, "@name-statement")]);
    expect(mcpValidRow.approval).toBe("auto");
    expect(mcpValidRow.lifecycle).toBe("active");
    expect(await scopedValues("@person-a", "@project-south", "Morgan Vale")).toEqual([c.valid.value.value]);
    const mcpOpaqueInput: ClaimInput = { ...claimInput(w, { ...opaqueBase, scopeProjectId: "@project-south" },
      inputId("MEMORY-02:opaque-mcp")), value: c.opaqueControl.value };
    const mcpOpaqueReceipt = await mcpCall("vault.claims.upsert", mcpOpaqueInput);
    expect(mcpOpaqueReceipt.approval).toBe("auto");
    await w.engine.awaitReceipt(mcpOpaqueReceipt.receipt_ref);
    const mcpOpaqueId = (await entity(w.engine.client, mcpOpaqueReceipt.claim_short_id)).id_hex;
    const mcpOpaqueRow = await claim(w, mcpOpaqueId);
    expect(mcpOpaqueRow.value).toEqual(c.opaqueControl.value);
    expect(mcpOpaqueRow.claim_scope).toEqual(mcpOpaqueInput.scope);
    birth(mcpOpaqueRow, owner, [ref(w, "@name-statement")]);
    expect(mcpOpaqueRow.approval).toBe("auto");
    expect(mcpOpaqueRow.lifecycle).toBe("active");
    const opaqueTextSouth = await scopedValues("@person-b", "@project-south", "not-a-number number kind");
    expect(opaqueTextSouth).toHaveLength(1);
    expect(opaqueTextSouth[0]!.length).toBeGreaterThan(0);
    // Quartet: four mutually non-superseding rows, every scope stamp pinned.
    expect((await claims(w, "@person-a")).filter(row => row.predicate === "profile.name")).toHaveLength(2);
    expect((await claims(w, "@person-b")).filter(row => row.predicate === "profile.name")).toHaveLength(2);
    // HTTP/MCP field-level parity on the same-owner readbacks (full bodies archived).
    const pick = (row: Claim): unknown => ({ value: row.value, predicate: row.predicate, lifecycle: row.lifecycle,
      approval: row.approval, subject_ref: row.subject_ref, source: row.source, claim_scope: row.claim_scope, made_by: row.made_by });
    const byRef = (rows: Claim[]): unknown[] =>
      [...rows].sort((a, b) => a.claim_ref.localeCompare(b.claim_ref)).map(pick);
    // List page size mirrors the claims() helper, not a new constant.
    const mcpListA = await mcpCall("vault.claims.list", { subject_ref: ref(w, "@person-a"), limit: 1000 });
    const mcpListB = await mcpCall("vault.claims.list", { subject_ref: ref(w, "@person-b"), limit: 1000 });
    expect(byRef(mcpListA.value)).toEqual(byRef(await claims(w, "@person-a")));
    expect(byRef(mcpListB.value)).toEqual(byRef(await claims(w, "@person-b")));
    const mcpHistory = await mcpCall("vault.claims.history", { claim_ref: validId });
    const httpHistory = (await w.engine.client.call("vault.claims.history", { claim_ref: validId })).value;
    expect(byRef(mcpHistory.value)).toEqual(byRef(httpHistory));
    const mcpGet = await mcpCall("vault.get", { entity_ref: validId });
    const httpGet = (await w.engine.client.call("vault.get", { entity_ref: validId })).value;
    expect(mcpGet.value?.kind).toBe(httpGet?.kind);
    expect(mcpGet.value?.made_by).toEqual(httpGet?.made_by);
    // Recall input mirrors the recalled() helper budget; only the transport differs.
    const recallInput: FacadeInput<"vault.recall"> = { query: "Morgan Vale", effort: "light", limit: 100,
      token_budget: 8192, format: "md", scope: { worlds: { kind: "all" }, project_refs: [ref(w, "@project-north")],
        kinds: ["CLAIM"] } };
    expect(values(await mcpCall("vault.recall", recallInput), "profile.name"))
      .toEqual(values(await w.engine.client.call("vault.recall", recallInput), "profile.name"));
    // Seven malformed cases, each over HTTP then MCP with no surviving bad row.
    const omitToSnake: Record<string, string> = { worldId: "world_id", scopeFacetId: "scope_facet_id",
      scopeRelationshipId: "scope_relationship_id", scopeProjectId: "scope_project_id" };
    for (const row of c.malformed.filter(item => item.omit !== undefined)) {
      const snake = omitToSnake[row.omit!]!;
      const before = await snapshot();
      const id = inputId(`MEMORY-02:${row.case}`);
      const full = claimInput(w, c.valid, id);
      const wire: Record<string, unknown> = { ...full, scope: { ...full.scope } };
      delete object(wire.scope)[snake];
      const refused = await w.engine.client.raw("POST", "/v1/core/facade/vault.claims.upsert", wire);
      expectRefused(refused.status, refused.body);
      refusals.push({ case: row.case, surface: "http", status: refused.status, body: refused.body });
      expect((await w.engine.client.call("vault.get", { entity_ref: id })).value).toBeNull();
      await expectUnchanged(before);
      const mcpId = inputId(`MEMORY-02:${row.case}:mcp`);
      const mcpFull = claimInput(w, c.valid, mcpId);
      const mcpWire: Record<string, unknown> = { ...mcpFull, scope: { ...mcpFull.scope } };
      delete object(mcpWire.scope)[snake];
      refusals.push({ case: row.case, surface: "mcp", body: await mcpRefused("vault.claims.upsert", mcpWire) });
      expect((await w.engine.client.call("vault.get", { entity_ref: mcpId })).value).toBeNull();
      await expectUnchanged(before);
    }
    {
      const before = await snapshot();
      const id = inputId("MEMORY-02:invalid-confidence");
      const refused = await w.engine.client.raw("POST", "/v1/core/facade/vault.claims.upsert",
        { ...claimInput(w, c.valid, id), confidence: 1.1 });
      expectRefused(refused.status, refused.body);
      refusals.push({ case: "invalid-confidence", surface: "http", status: refused.status, body: refused.body });
      expect((await w.engine.client.call("vault.get", { entity_ref: id })).value).toBeNull();
      await expectUnchanged(before);
      const mcpId = inputId("MEMORY-02:invalid-confidence:mcp");
      refusals.push({ case: "invalid-confidence", surface: "mcp",
        body: await mcpRefused("vault.claims.upsert", { ...claimInput(w, c.valid, mcpId), confidence: 1.1 }) });
      expect((await w.engine.client.call("vault.get", { entity_ref: mcpId })).value).toBeNull();
      await expectUnchanged(before);
    }
    {
      const before = await snapshot();
      const id = inputId("MEMORY-02:unknown-structural-kind");
      // Body/text_fields mirror setup(); only the kind is not in the registry.
      const spec = { id, kind: "not-a-kind", body: { name: "Morgan Vale" },
        text_fields: [{ field: "name", value: "Morgan Vale" }], occurred_at: w.occurred };
      const refused = await w.engine.client.raw("POST", "/v1/core/facade/vault.structural.put", spec);
      expectRefused(refused.status, refused.body);
      // The ONE sourced engine-Display literal: codec registry lookup, forwarded whole.
      expect(String(errMessage(refused.body))).toContain('unknown entity kind "not-a-kind"');
      refusals.push({ case: "unknown-structural-kind", surface: "http", status: refused.status, body: refused.body });
      expect((await w.engine.client.call("vault.get", { entity_ref: id })).value).toBeNull();
      await expectUnchanged(before);
      const mcpId = inputId("MEMORY-02:unknown-structural-kind:mcp");
      refusals.push({ case: "unknown-structural-kind", surface: "mcp",
        body: await mcpRefused("vault.structural.put", { ...spec, id: mcpId }) });
      expect((await w.engine.client.call("vault.get", { entity_ref: mcpId })).value).toBeNull();
      await expectUnchanged(before);
    }
    {
      const forged = c.malformed.find(item => item.case === "forged-author")!;
      const before = await snapshot();
      const id = inputId("MEMORY-02:forged-author");
      // made_by is not an input field: typed call() cannot send this, raw can.
      const refused = await w.engine.client.raw("POST", "/v1/core/facade/vault.claims.upsert",
        { ...claimInput(w, c.valid, id), made_by: forged.made_by });
      expectRefused(refused.status, refused.body);
      refusals.push({ case: "forged-author", surface: "http", status: refused.status, body: refused.body });
      expect((await w.engine.client.call("vault.get", { entity_ref: id })).value).toBeNull();
      await expectUnchanged(before);
      const mcpId = inputId("MEMORY-02:forged-author:mcp");
      refusals.push({ case: "forged-author", surface: "mcp",
        body: await mcpRefused("vault.claims.upsert", { ...claimInput(w, c.valid, mcpId), made_by: forged.made_by }) });
      expect((await w.engine.client.call("vault.get", { entity_ref: mcpId })).value).toBeNull();
      await expectUnchanged(before);
    }
    // Batch: per-element gates, forced proposed, no rollback of valid siblings.
    const sibAId = inputId("MEMORY-02:batch-sib-a");
    const confId = inputId("MEMORY-02:batch-conf");
    const sibBId = inputId("MEMORY-02:batch-sib-b");
    const batch = await w.engine.client.call("vault.claims.seed", { claims: [
      claimInput(w, c.valid, sibAId),
      { ...claimInput(w, c.valid, confId), confidence: 1.1 },
      claimInput(w, { ...c.valid, subjectId: "@person-b" }, sibBId),
    ] });
    expect(batch).toHaveLength(3);
    expect(batch[0]!.outcome).toBe("landed");
    if (batch[0]!.outcome !== "landed") throw new Error("HTTP batch sibling A refused");
    expect(batch[0]!.approval).toBe("proposed");
    expect(batch[1]!.outcome).toBe("refused");
    if (batch[1]!.outcome !== "refused") throw new Error("HTTP batch conf element landed");
    expect(typeof batch[1]!.refusal.reason).toBe("string");
    expect(typeof batch[1]!.refusal.code).toBe("string");
    expect((batch[1]!.refusal.code as string).length).toBeGreaterThan(0);
    expect(typeof batch[1]!.refusal.message).toBe("string");
    expect((batch[1]!.refusal.message as string).length).toBeGreaterThan(0);
    expect(Array.isArray(batch[1]!.refusal.suggestions)).toBe(true);
    expect(typeof batch[1]!.refusal.field).toBe("string");
    expect(batch[2]!.outcome).toBe("landed");
    if (batch[2]!.outcome !== "landed") throw new Error("HTTP batch sibling B refused");
    expect(batch[2]!.approval).toBe("proposed");
    expect((await w.engine.client.call("vault.get", { entity_ref: confId })).value).toBeNull();
    await w.engine.awaitReceipt(batch[0]!.receipt_ref);
    await w.engine.awaitReceipt(batch[2]!.receipt_ref);
    const sibAEntity = (await entity(w.engine.client, batch[0]!.claim_short_id)).id_hex;
    const sibBEntity = (await entity(w.engine.client, batch[2]!.claim_short_id)).id_hex;
    const sibARow = await claim(w, sibAEntity);
    const sibBRow = await claim(w, sibBEntity);
    expect(sibARow.value).toBe(c.valid.value.value);
    expect(sibARow.claim_scope).toEqual(claimInput(w, c.valid).scope);
    birth(sibARow, owner, [ref(w, "@name-statement")]);
    expect(sibARow.approval).toBe("proposed");
    expect(sibARow.lifecycle).toBe("active");
    expect(sibBRow.value).toBe(c.valid.value.value);
    expect(sibBRow.claim_scope).toEqual(claimInput(w, { ...c.valid, subjectId: "@person-b" }).scope);
    birth(sibBRow, owner, [ref(w, "@name-statement")]);
    expect(sibBRow.approval).toBe("proposed");
    expect(sibBRow.lifecycle).toBe("active");
    // Proposed seed siblings are excluded from recall: no rollback, no surfacing.
    expect(await scopedValues("@person-a", "@project-north", "Morgan Vale")).toEqual([c.valid.value.value]);
    expect(await scopedValues("@person-b", "@project-north", "not-a-number number kind")).toEqual(opaqueTextNorth);
    const mcpSibAId = inputId("MEMORY-02:batch-sib-a:mcp");
    const mcpConfId = inputId("MEMORY-02:batch-conf:mcp");
    const mcpSibBId = inputId("MEMORY-02:batch-sib-b:mcp");
    const mcpBatch = await mcpCall("vault.claims.seed", { claims: [
      claimInput(w, c.valid, mcpSibAId),
      { ...claimInput(w, c.valid, mcpConfId), confidence: 1.1 },
      claimInput(w, { ...c.valid, subjectId: "@person-b" }, mcpSibBId),
    ] });
    expect(mcpBatch).toHaveLength(3);
    expect(mcpBatch.map(outcome => outcome.outcome)).toEqual(batch.map(outcome => outcome.outcome));
    expect(mcpBatch.map(outcome => outcome.outcome === "landed" ? outcome.approval : null))
      .toEqual(batch.map(outcome => outcome.outcome === "landed" ? outcome.approval : null));
    expect(mcpBatch[1]!.outcome).toBe("refused");
    if (mcpBatch[1]!.outcome !== "refused") throw new Error("MCP batch conf element landed");
    expect(typeof mcpBatch[1]!.refusal.reason).toBe("string");
    expect(typeof mcpBatch[1]!.refusal.code).toBe("string");
    expect((mcpBatch[1]!.refusal.code as string).length).toBeGreaterThan(0);
    expect(typeof mcpBatch[1]!.refusal.message).toBe("string");
    expect((mcpBatch[1]!.refusal.message as string).length).toBeGreaterThan(0);
    expect(Array.isArray(mcpBatch[1]!.refusal.suggestions)).toBe(true);
    expect(typeof mcpBatch[1]!.refusal.field).toBe("string");
    expect((await w.engine.client.call("vault.get", { entity_ref: mcpConfId })).value).toBeNull();
    expect((await claims(w, "@person-a")).some(row => row.claim_ref === mcpConfId)).toBe(false);
    if (mcpBatch[0]!.outcome !== "landed") throw new Error("MCP batch sibling A refused");
    if (mcpBatch[2]!.outcome !== "landed") throw new Error("MCP batch sibling B refused");
    await w.engine.awaitReceipt(mcpBatch[0]!.receipt_ref);
    await w.engine.awaitReceipt(mcpBatch[2]!.receipt_ref);
    const mcpSibAEntity = (await entity(w.engine.client, mcpBatch[0]!.claim_short_id)).id_hex;
    const mcpSibBEntity = (await entity(w.engine.client, mcpBatch[2]!.claim_short_id)).id_hex;
    const mcpSibARow = await claim(w, mcpSibAEntity);
    const mcpSibBRow = await claim(w, mcpSibBEntity);
    expect(mcpSibARow.value).toBe(c.valid.value.value);
    expect(mcpSibARow.claim_scope).toEqual(claimInput(w, c.valid).scope);
    birth(mcpSibARow, owner, [ref(w, "@name-statement")]);
    expect(mcpSibARow.approval).toBe("proposed");
    expect(mcpSibARow.lifecycle).toBe("active");
    expect(mcpSibBRow.value).toBe(c.valid.value.value);
    expect(mcpSibBRow.claim_scope).toEqual(claimInput(w, { ...c.valid, subjectId: "@person-b" }).scope);
    birth(mcpSibBRow, owner, [ref(w, "@name-statement")]);
    expect(mcpSibBRow.approval).toBe("proposed");
    expect(mcpSibBRow.lifecycle).toBe("active");
    const batchFields = (row: Claim): unknown => ({ value: row.value, predicate: row.predicate,
      subject_ref: row.subject_ref, source: row.source, confidence: row.confidence,
      claim_scope: row.claim_scope, approval: row.approval, lifecycle: row.lifecycle });
    expect(batchFields(mcpSibARow)).toEqual(batchFields(sibARow));
    expect(batchFields(mcpSibBRow)).toEqual(batchFields(sibBRow));
    // Finale: quartet + four seed siblings intact; per-(subject,predicate) counts exact.
    const finalA = (await claims(w, "@person-a")).filter(row => row.predicate === "profile.name");
    const finalB = (await claims(w, "@person-b")).filter(row => row.predicate === "profile.name");
    expect(finalA).toHaveLength(4);
    expect(finalB).toHaveLength(4);
    expect(finalA.every(row => row.lifecycle === "active")).toBe(true);
    expect(finalB.every(row => row.lifecycle === "active")).toBe(true);
    expect((await claim(w, validId)).value).toBe(c.valid.value.value);
    expect((await claim(w, opaqueId)).value).toEqual(c.opaqueControl.value);
    expect((await claim(w, mcpValidId)).value).toBe(c.valid.value.value);
    expect((await claim(w, mcpOpaqueId)).value).toEqual(c.opaqueControl.value);
    expect((await claim(w, validId)).claim_scope).toEqual(validInput.scope);
    expect((await claim(w, opaqueId)).claim_scope).toEqual(opaqueInput.scope);
    birth(await claim(w, validId), owner, [ref(w, "@name-statement")]);
    birth(await claim(w, opaqueId), owner, [ref(w, "@name-statement")]);
    await w.engine.artifacts.json("memory-02-claim-admission.json", { note: c.opaqueControl.note,
      canon: c.opaqueControl.canon, receipts: { validReceipt, opaqueReceipt, mcpValidReceipt, mcpOpaqueReceipt },
      readbacks: { validRow, opaqueRow, mcpValidRow, mcpOpaqueRow, sibARow, sibBRow, mcpSibARow, mcpSibBRow },
      opaqueRecall: { opaqueTextNorth, opaqueTextSouth }, refusals, batch, mcpBatch,
      parity: { mcpListA, mcpListB, mcpHistory, mcpGet }, finale: { finalA, finalB } });
  } catch (error) {
    primaryFailed = true;
    primary = error;
  } finally {
    const cleanups: string[] = [];
    try { await w.engine.close({retainVault:process.env.E2E_MEMORY_RETAIN_VAULT==="1"}); } catch (error) { cleanups.push(errorText(error)); }
    try { await w.providers.close(); } catch (error) { cleanups.push(errorText(error)); }
    if (primaryFailed) {
      if (cleanups.length) throw new Error(`${errorText(primary)}; cleanup: ${cleanups.join("; ")}`);
      throw primary;
    }
    if (cleanups.length) throw new Error(`cleanup: ${cleanups.join("; ")}`);
  }
});

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
  budget: { token_budget: number; retrieval: { claims: number } };
}
interface TimedPackReply {
  results: { id: string }[]; neighbors: { id: string }[]; narrowing: Facade.ScopedReadReceipt;
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
    const windows = [];
    for (const window of c.windows) {
      const request: TimedPackRequest = { query: "profile Morgan Vale they them", limit: 100,
        edge_hop: 0, view: "full", budget: { token_budget: 8192, retrieval: { claims: 100 } },
        time: window.axis === "occurred"
          ? { occurred_start: window.start, occurred_end: window.end }
          : { learned_start: window.start, learned_end: window.end } };
      const pack = (await w.engine.client.request<TimedPackReply>("POST", "/v1/core/context-pack", request)).body;
      const returned = await Promise.all(pack.results.map(item => entity(w.engine.client, item.id)));
      const matched = returned.filter(item => item.kind === "CLAIM").map(item => item.id_hex).sort();
      expect(matched).toEqual(window.expected.map(role => ref(w, role)).sort());
      windows.push({ request, pack });
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
suite.test(test, "MEMORY-07", "Identity merge, split of the survivor's own evidence with named residue, and undo keep original claim subjects", async () => {
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
    const bMerged = await w.engine.client.call("vault.identity.resolve", { entity: ref(w, "@person-b") });
    expect(bMerged.state).toBe("merged"); expect(bMerged.heads).toEqual([ref(w, "@person-a")]);
    expect(bMerged.merged_into).toEqual([ref(w, "@person-a")]);
    expect((await entity(w.engine.client, ref(w, "@person-b"))).kind).toBe("PERSON");
    for (const role of c.split.heads) await person(w, role, role === "@head-north" ? "Morgan North head" : "Morgan South head");
    const splitMap = c.split.reassignment_map.filter(item =>
      c.evidence.find(row => row.ref === item.evidence)?.subject === c.split.entity);
    expect(splitMap.map(item => item.evidence)).toEqual(["@evidence-a"]);
    const splitSpec: FacadeInput<"vault.identity.split"> = {
      entity: ref(w, c.split.entity), heads: c.split.heads.map(role => ref(w, role)),
      // Only the split person's own claims are mapped: the engine reads a split's claim membership
      // through the direct claim_of edge, so a merged source's claim (@evidence-b) is not reassigned
      // (E2E-PARTIAL; FIX row filed with the READY). The ambiguous claim is named as residue.
      reassignment_map: [
        ...splitMap.map(item => ({
          item: { kind: "claim" as const, claim: ref(w, item.evidence) }, target: { kind: "head" as const, head: ref(w, item.head) },
        })),
        { item: { kind: "claim" as const, claim: ref(w, "@ambiguous-evidence") }, target: { kind: "residue" as const } },
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
    }
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
    for (const operation of [merged, split])
      expect(await w.engine.client.call("vault.identity.events.get", { event: operation.receipt.event })).toEqual(operation.receipt);
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
  const w = await setup("MEMORY-08");
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
    expect(values(readable, c.claims[0]!.predicate)).toEqual(c.claims.filter(row => row.worldId === "@dream")
      .map(row => row.value.value).sort());
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
      expect(pack.narrowing.narrowed_axes.length).toBeGreaterThan(0);
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

// MUSE-DURA-01 - P-DURA-031 (MUST): "A restart preserves durable writes that
// were ahead of their sync mirror."
// Register door: getEntity, driven here as the typed facade verb vault.get.
// Canon: oneiron-arch-0023b #recovery and #pm. An entity write and its pm:*
// pending-mirror marker land in one LMDB transaction; the marker says LMDB is
// ahead of the Loro Doc. On startup, pending-mirror replay (step 4) and
// reverse re-materialization (step 5) must run before forward
// re-materialization (step 6), or LMDB-ahead data is lost.
// PARTIAL by design: no public door can create or observe the pm:*
// ahead-of-mirror instant, and no public door can hold the mirror between the
// LMDB commit and the Loro mirror. This case therefore proves the
// user-recognisable subset: a receipted ledger write, killed at once with
// SIGKILL, survives the restart and reads back equal through vault.get and
// through a second door (vault.claims.list, plus a WebSocket vault.get after
// the final restart). It does not prove the write was still unmirrored at
// the kill instant. The ledger plane is used because canon states it is the
// shipped carrier; the per-entity text plane is stated designed, not
// shipped, and is not used.
// Wrong-actor legs: vault.claims.upsert is core:write; an agent paired with
// core:read only is refused, with no change read back. That agent then loses
// its slip through the owner's public slips/revoke door and is refused at
// its next use, before and after a further restart. A refused HTTP call's
// own call-receipt ref cannot be discovered from the canon error envelope
// (it carries requestId), so the refusal-specific receipt is captured to
// artifacts where the governance ledger shows one, and is listed as an
// unproved missing door in the report rather than asserted by invention.
type museDura01AuditRow = FacadeResult<"vault.authority.audit">["rows"][number];
type museDura01EntityView = NonNullable<FacadeResult<"vault.get">["value"]>;
type museDura01Claim = FacadeResult<"vault.claims.list">["value"][number];

async function museDura01AuditRows(client: PublicHttpClient): Promise<museDura01AuditRow[]> {
  const rows: museDura01AuditRow[] = [];
  let after: string | undefined;
  const cursors = new Set<string>();
  for (;;) {
    const query: FacadeInput<"vault.authority.audit"> = { limit: 500, ...(after ? { after } : {}) };
    const page = await client.call("vault.authority.audit", query);
    rows.push(...page.rows);
    // These fixtures never adopt an externally attested checkpoint image.
    if (!page.next_after) return rows;
    cursors.add(page.next_after);
    after = page.next_after;
  }
}

function museDura01MintedSlipId(
  before: readonly museDura01AuditRow[],
  after: readonly museDura01AuditRow[],
  holder: string,
): string {
  const existing = new Set(before.map(row => row.entry_hash));
  const minted = after.filter(row => !existing.has(row.entry_hash)
    && row.source_op === "slip_mint" && row.holder_ref === holder);
  expect(minted).toHaveLength(1);
  const row = minted[0]!;
  expect(row.subject_ref).toMatch(/^[a-f0-9]{64}$/);
  return row.subject_ref!;
}

async function museDura01Entity(
  client: PublicHttpClient,
  entity_ref: string,
): Promise<museDura01EntityView> {
  const result = await client.call("vault.get", { entity_ref });
  if (!result.value) throw new Error(`Public entity missing or withheld: ${entity_ref}`);
  return result.value;
}

async function museDura01OnlyClaim(
  client: PublicHttpClient,
  subject_ref: string,
  predicate: string,
): Promise<museDura01Claim> {
  const list = await client.call("vault.claims.list", { subject_ref, predicate, limit: 1000 });
  expect(list.value).toHaveLength(1);
  const row = list.value[0];
  return row!;
}

function museDura01ErrorField(body: unknown, field: "code" | "message"): unknown {
  return (body as { error?: Record<string, unknown> }).error?.[field];
}

function museDura01ExpectErrorEnvelope(body: unknown): void {
  expect(typeof museDura01ErrorField(body, "code")).toBe("string");
  expect((museDura01ErrorField(body, "code") as string).length).toBeGreaterThan(0);
  expect(typeof museDura01ErrorField(body, "message")).toBe("string");
  expect((museDura01ErrorField(body, "message") as string).length).toBeGreaterThan(0);
}

suite.test(test, "MUSE-DURA-01", "A receipted durable write survives a kill and restarts and reads back equal", async () => {
  const engine = await EngineFixture.start({ id: "MUSE-DURA-01", profile });
  try {
    // Public setup input only, the same fixed instant the sibling memory and
    // gate flows author with. It never moves an engine clock.
    const occurred = 1769947200;
    const token = secretHex(8);
    const personName = `Dura Person ${token}`;
    const claimValue = `dura keeper ${token}`;
    const refusedValue = `dura refused ${token}`;
    const agentName = `Dura Agent ${token}`;
    redactor.add(token, personName, claimValue, refusedValue, agentName);
    const predicate = "profile.description";

    // Subject setup through public doors only: conversation, witnessed turn,
    // then the owner person door using that turn as identity evidence.
    const conversation = await engine.client.call("vault.conversations.create", {
      body: {}, occurred_start: occurred, occurred_end: occurred, learned_at: occurred,
    } satisfies FacadeInput<"vault.conversations.create">);
    const witnessed = await engine.client.call("vault.witness", {
      conversation_ref: conversation.id, occurred_at: occurred,
      messages: [{ author: "user", message_type: "text",
        content: `This distinct person is ${personName}.`, is_visible: true, order: 0 }],
    } satisfies FacadeInput<"vault.witness">);
    await engine.awaitReceipt(witnessed.receipt_ref);
    const turn = await museDura01Entity(engine.client, witnessed.turn_short_id);
    expect(turn.kind).toBe("TURN");
    const created = await engine.client.call("vault.people.create", {
      identity: { name: personName }, identity_evidence_refs: [turn.id_hex], occurred_at: occurred,
    } satisfies FacadeInput<"vault.people.create">);
    const personBefore = await museDura01Entity(engine.client, created.person.entity_ref);
    expect(personBefore.kind).toBe("PERSON");
    expect(personBefore.id_hex).toBe(created.person.id_hex);

    // The durable write under test: one explicit four-axis claim. The ledger
    // plane carries claims, so this is an entity write on the shipped
    // dual-storage carrier, not the unshipped text plane.
    const scope = await ownerBaseClaimScope(engine.client, engine.pairedActor.principalRef);
    const claimInput: FacadeInput<"vault.claims.upsert"> = {
      predicate, subject_ref: created.person.id_hex, value: claimValue,
      confidence: 1, source: "user_stated", scope,
      occurred_at: occurred, learned_at: occurred,
    };
    const committed = await engine.client.call("vault.claims.upsert", claimInput);
    expect(committed.claim_short_id.length).toBeGreaterThan(0);
    expect(committed.receipt_ref.length).toBeGreaterThan(0);
    // A public receipt is in hand and read back before any kill. No voluntary
    // entity read is inserted between this receipt and the kill, so the kill
    // lands as close to the receipted write as public doors allow.
    await engine.awaitReceipt(committed.receipt_ref);
    await engine.kill();
    await engine.restart();

    // Read the write back after the kill and restart, first by the receipt
    // door, then by getEntity (vault.get), then by a second door
    // (vault.claims.list). Every value below is the authored input above,
    // never a value copied out of an acting response alone.
    await engine.awaitReceipt(committed.receipt_ref);
    const claimEntityAfterKill = await museDura01Entity(engine.client, committed.claim_short_id);
    expect(claimEntityAfterKill.kind).toBe("CLAIM");
    const claimAfterKill = await museDura01OnlyClaim(engine.client, created.person.id_hex, predicate);
    expect(claimAfterKill.claim_ref).toBe(claimEntityAfterKill.id_hex);
    expect(claimAfterKill.subject_ref).toBe(created.person.id_hex);
    expect(claimAfterKill.predicate).toBe(predicate);
    expect(claimAfterKill.value).toBe(claimValue);
    expect(await museDura01Entity(engine.client, created.person.entity_ref)).toEqual(personBefore);
    expect(await museDura01Entity(engine.client, witnessed.turn_short_id)).toEqual(turn);

    // Wrong actor for the write door: an agent whose slip carries core:read
    // and not core:write. Its own identity first reads back, so a later 403
    // is a scope refusal of a working credential, not a broken pairing.
    const agentRecord = await engine.client.call("vault.structural.put", {
      kind: "PERSON", body: { name: agentName }, occurred_at: occurred,
    } satisfies FacadeInput<"vault.structural.put">);
    const auditBeforePair = await museDura01AuditRows(engine.client);
    const agent = await engine.pairActor({
      principalRef: agentRecord.id_hex, actorClass: "agent", scope: ["core:read"],
    });
    const agentIdentity = await agent.client.call("self.actor", {});
    expect(agentIdentity.actor_ref).toBe(agentRecord.id_hex);
    expect(agentIdentity.actor_class).toBe("agent");
    const slipId = museDura01MintedSlipId(
      auditBeforePair, await museDura01AuditRows(engine.client), agentRecord.id_hex);

    const receiptsBeforeRefusal = await engine.client.call("vault.receipts", { limit: 1000 });
    const refusedInput: FacadeInput<"vault.claims.upsert"> = { ...claimInput, value: refusedValue };
    const refused = await agent.client.raw("POST", "/v1/core/facade/vault.claims.upsert", refusedInput);
    expect(refused.status).toBe(403);
    museDura01ExpectErrorEnvelope(refused.body);
    // The refusal changed nothing: the same single claim, with the authored
    // value, is still the only row on the second door.
    const claimAfterRefusal = await museDura01OnlyClaim(engine.client, created.person.id_hex, predicate);
    expect(claimAfterRefusal.claim_ref).toBe(claimAfterKill.claim_ref);
    expect(claimAfterRefusal.value).toBe(claimValue);
    const receiptsAfterRefusal = await engine.client.call("vault.receipts", { limit: 1000 });
    const receiptsBeforeRefs = new Set(receiptsBeforeRefusal.receipts.map(row => row.receipt_ref));
    await engine.artifacts.json("muse-dura-01-refusal-receipts.json", {
      refusalStatus: refused.status,
      newReceipts: receiptsAfterRefusal.receipts.filter(row => !receiptsBeforeRefs.has(row.receipt_ref)),
    });
    expect(receiptsAfterRefusal.receipts.some(
      row => row.receipt_ref === committed.receipt_ref)).toBe(true);

    // The same agent loses its slip through the owner's public revoke door,
    // is refused at its next use, and the revoke is read back in the
    // owner's authority audit. The owner's durable write is untouched.
    const revoked = await engine.client.request<{ revoked: boolean }>("POST", "/v1/core/slips/revoke", {
      slip_id: Array.from(Buffer.from(slipId, "hex")),
    });
    expect(revoked.status).toBe(200);
    expect(revoked.body.revoked).toBe(true);
    const claimGet: FacadeInput<"vault.get"> = { entity_ref: committed.claim_short_id };
    const afterRevoke = await agent.client.raw("POST", "/v1/core/facade/vault.get", claimGet);
    expect(afterRevoke.status).toBe(401);
    museDura01ExpectErrorEnvelope(afterRevoke.body);
    expect((await museDura01AuditRows(engine.client)).some(
      row => row.source_op === "slip_revoke" && row.subject_ref === slipId && row.fold_valid)).toBe(true);
    expect(await museDura01Entity(engine.client, committed.claim_short_id))
      .toEqual(claimEntityAfterKill);

    // A further graceful restart: write, receipt, person, turn and the slip
    // revoke all survive it, and the claim still reads back equal over a
    // different route (the app WebSocket) as well as over HTTP.
    await engine.restart();
    await engine.awaitReceipt(committed.receipt_ref);
    expect(await museDura01Entity(engine.client, committed.claim_short_id))
      .toEqual(claimEntityAfterKill);
    expect(await museDura01Entity(engine.client, created.person.entity_ref)).toEqual(personBefore);
    expect(await museDura01Entity(engine.client, witnessed.turn_short_id)).toEqual(turn);
    const finalClaim = await museDura01OnlyClaim(engine.client, created.person.id_hex, predicate);
    expect(finalClaim.claim_ref).toBe(claimAfterKill.claim_ref);
    expect(finalClaim.subject_ref).toBe(claimAfterKill.subject_ref);
    expect(finalClaim.predicate).toBe(claimAfterKill.predicate);
    expect(finalClaim.value).toBe(claimValue);
    expect(finalClaim.approval).toBe(claimAfterKill.approval);
    expect(finalClaim.lifecycle).toBe(claimAfterKill.lifecycle);
    expect(finalClaim.claim_scope).toEqual(claimAfterKill.claim_scope);
    const revokedAfterRestart = await agent.client.raw("POST", "/v1/core/facade/vault.get", claimGet);
    expect(revokedAfterRestart.status).toBe(401);
    museDura01ExpectErrorEnvelope(revokedAfterRestart.body);
    const socket = await engine.websocket();
    try {
      const viaSocket = await socket.call("vault.get", claimGet);
      expect(viaSocket.value.value?.id_hex).toBe(claimEntityAfterKill.id_hex);
      expect(viaSocket.value.value?.kind).toBe("CLAIM");
    } finally { socket.close() }
    await engine.artifacts.json("muse-dura-01-readbacks.json", {
      committed, claimEntityAfterKill, claimAfterKill, claimAfterRefusal, finalClaim,
      personBefore, turn,
    });
  } finally {
    await engine.close();
  }
});

// MUSE-DURA-02 — hard delete, content-free receipt, queued sweep, maintain, restart.
// Promises: P-DURA-001 (active payloads and indexes are purged before the
// deletion receipt returns), P-DURA-002 (the receipt holds no erased name,
// content, quote, predicate or personal data), P-DURA-004 (purge completion
// is distinct from a queued historical sweep), P-DURA-005 (the owner can
// force the historical cleanup through maintain).
// Doors used: vault.witness / vault.claims.upsert to write;
// vault.get / vault.recall / vault.export / vault.claims.list to read back;
// vault.delete to hard-delete; vault.receipts and vault.records.erase_sweep
// for the receipt and its sweep state; POST /v1/owner/maintain to force the
// sweep; EngineFixture.restart() for the restart leg. A paired agent (wrong
// actor kind for a human-only delete) is refused, the owner later revokes
// that agent's paired slip through POST /v1/core/slips/revoke, and the dead
// credential is refused again after the restart.
// Unproved: the typed DeleteReceipt carries no purge/sweep timestamps, so
// P-DURA-004 is proved in its public linked form (immediate gone reads plus
// queued -> complete sweep state) and not as fields inside the delete
// response itself; the agent delete-Grant mint -> succeed -> revoke path;
// peer sync non-resurrection; the exact 30-day deadline arithmetic (the
// typed surface does not name the timestamp unit); raw historical bytes.

type museDura02AuditRow = FacadeResult<"vault.authority.audit">["rows"][number];

interface museDura02ErrorBody {
  readonly error?: { readonly code?: unknown; readonly message?: unknown };
}

function museDura02NoSentinels(value: unknown, sentinels: readonly string[]): void {
  const text = JSON.stringify(value) ?? "";
  // Boolean assertion only: sentinel bytes stay out of assertion diagnostics.
  expect(sentinels.every(sentinel => !text.includes(sentinel)
    && !text.includes(Buffer.from(sentinel).toString("base64")))).toBe(true);
}

function museDura02ItemsContain(
  items: FacadeResult<"vault.recall">["items"],
  sentinels: readonly string[],
): boolean {
  return items.some(item => {
    const text = JSON.stringify(item);
    return sentinels.some(sentinel => text.includes(sentinel));
  });
}

async function museDura02Recall(
  engine: EngineFixture,
  query: string,
): Promise<FacadeResult<"vault.recall">> {
  return engine.client.call("vault.recall", { query, effort: "light", limit: 10 });
}

function museDura02ZipText(encoded: string): string {
  const zip = Buffer.from(encoded, "base64");
  let end = zip.length - 22;
  for (; end >= Math.max(0, zip.length - 65_557); end--) {
    if (zip.readUInt32LE(end) === 0x06054b50
      && end + 22 + zip.readUInt16LE(end + 20) === zip.length) break;
  }
  if (end < 0 || end < Math.max(0, zip.length - 65_557)) {
    throw new Error("Public export is not a complete ZIP");
  }
  const entries = zip.readUInt16LE(end + 10);
  let cursor = zip.readUInt32LE(end + 16);
  const directoryEnd = cursor + zip.readUInt32LE(end + 12);
  const files = new Map<string, Buffer>();
  for (let index = 0; index < entries; index++) {
    expect(zip.readUInt32LE(cursor)).toBe(0x02014b50);
    expect(zip.readUInt16LE(cursor + 8) & 1).toBe(0);
    const method = zip.readUInt16LE(cursor + 10);
    const compressed = zip.readUInt32LE(cursor + 20);
    const length = zip.readUInt32LE(cursor + 24);
    const nameLength = zip.readUInt16LE(cursor + 28);
    const extraLength = zip.readUInt16LE(cursor + 30);
    const commentLength = zip.readUInt16LE(cursor + 32);
    const local = zip.readUInt32LE(cursor + 42);
    const name = zip.subarray(cursor + 46, cursor + 46 + nameLength).toString("utf8");
    expect(files.has(name)).toBe(false);
    expect(zip.readUInt32LE(local)).toBe(0x04034b50);
    const start = local + 30 + zip.readUInt16LE(local + 26) + zip.readUInt16LE(local + 28);
    expect(start + compressed <= zip.length).toBe(true);
    const wire = zip.subarray(start, start + compressed);
    if (method !== 0 && method !== 8) throw new Error("Unsupported public ZIP compression");
    const bytes = method === 0 ? wire : inflateRawSync(wire);
    files.set(name, bytes);
    cursor += 46 + nameLength + extraLength + commentLength;
  }
  return [...files.values()].map(bytes => bytes.toString("utf8")).join("\n");
}

async function museDura02ExportedText(engine: EngineFixture): Promise<string> {
  const exported = await engine.client.call("vault.export", {
    format: "archive", include_secrets: false, delivery: "inline",
  });
  if (!("archive" in exported)) throw new Error("Inline export returned no archive");
  return museDura02ZipText(exported.archive);
}

async function museDura02AuditRows(engine: EngineFixture): Promise<museDura02AuditRow[]> {
  const rows: museDura02AuditRow[] = [];
  let after: string | undefined;
  const cursors = new Set<string>();
  for (;;) {
    const query: FacadeInput<"vault.authority.audit"> = { limit: 500, ...(after ? { after } : {}) };
    const page = await engine.client.call("vault.authority.audit", query);
    rows.push(...page.rows);
    if (!page.next_after) return rows;
    expect(cursors.has(page.next_after)).toBe(false);
    cursors.add(page.next_after);
    after = page.next_after;
  }
}

async function museDura02ReceiptRefs(engine: EngineFixture): Promise<ReadonlySet<string>> {
  const page = await engine.client.call("vault.receipts", { limit: 1000 });
  return new Set(page.receipts.map(row => row.receipt_ref));
}

async function museDura02Sweep(
  engine: EngineFixture,
  receiptRef: string,
): Promise<NonNullable<FacadeResult<"vault.records.erase_sweep">>> {
  const sweep = await engine.client.call("vault.records.erase_sweep", { receipt_ref: receiptRef });
  if (!sweep) throw new Error("Deletion receipt has no public sweep read");
  return sweep;
}

function museDura02DeleteReceiptRef(
  receipt: FacadeResult<"vault.delete">,
  sentinels: readonly string[],
): string {
  expect(receipt.existed).toBe(true);
  museDura02NoSentinels(receipt, sentinels);
  if (!receipt.receipt_ref) throw new Error("Hard delete returned no deletion receipt reference");
  return receipt.receipt_ref;
}

async function museDura02ExpectQueuedSweep(
  engine: EngineFixture,
  receiptRef: string,
  sentinels: readonly string[],
): Promise<NonNullable<FacadeResult<"vault.records.erase_sweep">>> {
  const sweep = await museDura02Sweep(engine, receiptRef);
  expect(sweep.sweep_queued_at != null).toBe(true);
  expect(sweep.sweep_complete_at ?? null).toBeNull();
  museDura02NoSentinels(sweep, sentinels);
  return sweep;
}

async function museDura02ExpectDeadAgentDelete(
  actor: EngineFixture["pairedActor"],
  input: FacadeInput<"vault.delete">,
): Promise<void> {
  const denied = await actor.client.raw<museDura02ErrorBody>(
    "POST", "/v1/core/facade/vault.delete", input,
  );
  expect(denied.status).toBe(401);
  expect(denied.body.error?.code).toBe("UNAUTHORIZED");
}

suite.test(test, "MUSE-DURA-02", "A hard delete is gone from recall and export before its content-free receipt returns, owner maintain completes its queued sweep, and it stays gone after restart", async () => {
  const engine = await EngineFixture.start({ id: "MUSE-DURA-02", profile });
  const occurred = 1769947200;
  const tag = secretHex(6);
  const nameSentinel = `Dura02Name${tag}`;
  const quoteSentinel = `Dura02Quote${tag}`;
  const claimValueSentinel = `Dura02ClaimValue${tag}`;
  const predicateSentinel = `dura02.note_${tag}`;
  const messageSentinels = [nameSentinel, quoteSentinel];
  const claimSentinels = [predicateSentinel, claimValueSentinel];
  const allSentinels = [...messageSentinels, ...claimSentinels];
  redactor.add(...allSentinels);
  const content = `${nameSentinel} said ${quoteSentinel} at the observatory.`;
  redactor.add(content);

  // A paired agent with ordinary read/write scope, but no delete Grant and
  // the wrong actor kind for a human-only delete. Its minted slip is read
  // back through the authority audit so the owner can revoke it later.
  const auditBeforeAgent = await museDura02AuditRows(engine);
  const agentRecord = await engine.client.call("vault.structural.put", {
    kind: "PERSON", body: { name: "Dura02 Agent" }, occurred_at: occurred,
  } satisfies FacadeInput<"vault.structural.put">);
  const agent = await engine.pairActor({
    principalRef: agentRecord.id_hex, actorClass: "agent", scope: ["core:read", "core:write"],
  });
  const auditAfterAgent = await museDura02AuditRows(engine);
  const auditBeforeHashes = new Set(auditBeforeAgent.map(row => row.entry_hash));
  const agentMints = auditAfterAgent.filter(row => !auditBeforeHashes.has(row.entry_hash)
    && row.source_op === "slip_mint" && row.holder_ref === agent.principalRef);
  expect(agentMints).toHaveLength(1);
  const agentSlipId = agentMints[0]?.subject_ref;
  if (!agentSlipId || !/^[a-f0-9]{64}$/.test(agentSlipId)) {
    throw new Error("Paired agent has no audited slip id to revoke");
  }

  // Write one witnessed message and one claim, then read both back through
  // doors other than the ones that wrote them.
  const conversation = await engine.client.call("vault.conversations.create", {
    body: {}, occurred_start: occurred, occurred_end: occurred, learned_at: occurred,
  } satisfies FacadeInput<"vault.conversations.create">);
  expect((await engine.client.call("vault.get", { entity_ref: conversation.id })).value).not.toBeNull();
  const witnessed = await engine.client.call("vault.witness", {
    conversation_ref: conversation.id,
    occurred_at: occurred,
    messages: [{
      author: "user", message_type: "text", content, is_visible: true, order: 0,
    }],
  } satisfies FacadeInput<"vault.witness">);
  await engine.awaitReceipt(witnessed.receipt_ref);
  expect(witnessed.message_short_ids).toHaveLength(1);
  const messageRef = witnessed.message_short_ids[0];
  if (!messageRef) throw new Error("Witness returned no message reference");

  const claimScope = await ownerBaseClaimScope(engine.client, engine.pairedActor.principalRef);
  const claimReceipt = await engine.client.call("vault.claims.upsert", {
    scope: claimScope,
    predicate: predicateSentinel,
    subject_ref: conversation.id,
    value: claimValueSentinel,
    source: "user_stated",
    confidence: 1,
    occurred_at: occurred,
  } satisfies FacadeInput<"vault.claims.upsert">);
  await engine.awaitReceipt(claimReceipt.receipt_ref);
  expect(claimReceipt.claim_short_id.length).toBeGreaterThan(0);

  const savedMessage = await engine.client.call("vault.get", { entity_ref: messageRef });
  if (!savedMessage.value) throw new Error("Witnessed message is not publicly readable");
  expect((JSON.stringify(savedMessage.value.body) ?? "").includes(quoteSentinel)).toBe(true);
  const preClaims = await engine.client.call("vault.claims.list", {
    subject_ref: conversation.id, predicate: predicateSentinel, limit: 10,
  } satisfies FacadeInput<"vault.claims.list">);
  expect(preClaims.value).toHaveLength(1);
  const claimRow = preClaims.value[0];
  if (!claimRow) throw new Error("Written claim is not publicly readable");
  expect(claimRow.predicate).toBe(predicateSentinel);
  expect(claimRow.value).toBe(claimValueSentinel);
  const claimRef = claimRow.claim_ref;
  expect(claimRef.length).toBeGreaterThan(0);
  expect((await engine.client.call("vault.get", { entity_ref: claimRef })).value).not.toBeNull();

  const preRecall = await awaitPublic(
    () => museDura02Recall(engine, quoteSentinel),
    pack => museDura02ItemsContain(pack.items, [quoteSentinel]),
    { label: "pre-delete recall finds the witnessed message", timeoutMs: LIMITS.requestMs },
  );
  expect(museDura02ItemsContain(preRecall.items, [nameSentinel])).toBe(true);
  const preExport = await museDura02ExportedText(engine);
  expect(allSentinels.every(sentinel => preExport.includes(sentinel))).toBe(true);

  // Wrong actor kind: the same typed delete, from the paired agent, is
  // refused, leaves a readable receipt, and changes nothing.
  const receiptRefsBeforeRefusal = await museDura02ReceiptRefs(engine);
  const deleteMessageInput: FacadeInput<"vault.delete"> = {
    entity_ref: messageRef, reason: "user_hard_delete",
  };
  let agentDeleteRefusal: unknown = undefined;
  try {
    await agent.client.call("vault.delete", deleteMessageInput);
  } catch (error) {
    agentDeleteRefusal = error;
  }
  expect(agentDeleteRefusal instanceof PublicHttpError).toBe(true);
  if (!(agentDeleteRefusal instanceof PublicHttpError)) {
    throw new Error("Agent hard delete was not refused with the public HTTP envelope");
  }
  expect(agentDeleteRefusal.reply.status).toBe(403);
  expect(typeof agentDeleteRefusal.error?.code).toBe("string");
  expect(typeof agentDeleteRefusal.error?.message).toBe("string");
  museDura02NoSentinels(agentDeleteRefusal.reply.body, allSentinels);
  const receiptsAfterRefusal = await engine.client.call("vault.receipts", { limit: 1000 });
  const refusalReceipts = receiptsAfterRefusal.receipts.filter(
    row => !receiptRefsBeforeRefusal.has(row.receipt_ref),
  );
  expect(refusalReceipts.some(row => row.actor_class === "agent"
    || row.actor_ref === agent.principalRef)).toBe(true);
  museDura02NoSentinels(refusalReceipts, allSentinels);
  expect((await engine.client.call("vault.get", { entity_ref: messageRef })).value).not.toBeNull();

  // Owner hard delete of the message. The first reads after the receipt
  // returns already find nothing: no wait, no maintain, no restart.
  const messageDeleteReceipt = await engine.client.call("vault.delete", deleteMessageInput);
  const messageReceiptRef = museDura02DeleteReceiptRef(messageDeleteReceipt, allSentinels);
  expect((await engine.client.call("vault.get", { entity_ref: messageRef })).value).toBeNull();
  const exportAfterMessageDelete = await museDura02ExportedText(engine);
  expect(messageSentinels.every(sentinel => !exportAfterMessageDelete.includes(sentinel))).toBe(true);
  expect(claimSentinels.every(sentinel => exportAfterMessageDelete.includes(sentinel))).toBe(true);
  const recallAfterMessageDelete = await museDura02Recall(engine, quoteSentinel);
  expect(museDura02ItemsContain(recallAfterMessageDelete.items, messageSentinels)).toBe(false);
  museDura02NoSentinels(await engine.awaitReceipt(messageReceiptRef), allSentinels);
  await museDura02ExpectQueuedSweep(engine, messageReceiptRef, allSentinels);

  // Owner hard delete of the claim, whose receipt must also stay free of
  // the erased predicate and value.
  const deleteClaimInput: FacadeInput<"vault.delete"> = {
    entity_ref: claimRef, reason: "user_hard_delete",
  };
  const claimDeleteReceipt = await engine.client.call("vault.delete", deleteClaimInput);
  const claimReceiptRef = museDura02DeleteReceiptRef(claimDeleteReceipt, allSentinels);
  expect((await engine.client.call("vault.claims.list", {
    subject_ref: conversation.id, predicate: predicateSentinel, limit: 10,
  })).value).toHaveLength(0);
  expect((await engine.client.call("vault.get", { entity_ref: claimRef })).value).toBeNull();
  museDura02NoSentinels(await engine.awaitReceipt(claimReceiptRef), allSentinels);
  await museDura02ExpectQueuedSweep(engine, claimReceiptRef, allSentinels);

  // Only the owner can force the queued sweep: the agent is refused and the
  // sweep stays incomplete; the owner's maintain completes it.
  await engine.requireHttpDoor("/v1/owner/maintain", "POST");
  const agentMaintain = await agent.client.raw<museDura02ErrorBody>("POST", "/v1/owner/maintain", {});
  expect(agentMaintain.status).toBe(403);
  museDura02NoSentinels(agentMaintain.body, allSentinels);
  expect((await museDura02Sweep(engine, messageReceiptRef)).sweep_complete_at ?? null).toBeNull();
  const maintained = await engine.client.raw("POST", "/v1/owner/maintain", {});
  expect(maintained.status >= 200 && maintained.status < 300).toBe(true);
  museDura02NoSentinels(maintained.body, allSentinels);
  const sweepAfterMaintain = await awaitPublic(
    () => museDura02Sweep(engine, messageReceiptRef),
    sweep => sweep.sweep_complete_at != null,
    { label: "owner maintain completes the message sweep", timeoutMs: LIMITS.requestMs },
  );
  expect((sweepAfterMaintain.sweep_complete_at ?? 0)
    >= (sweepAfterMaintain.sweep_queued_at ?? 0)).toBe(true);
  expect((await museDura02Sweep(engine, claimReceiptRef)).sweep_complete_at != null).toBe(true);

  // The owner revokes the agent's paired slip; its next delete is refused
  // as unauthenticated, its target survives, and the audit shows the revoke.
  const deleteConversationInput: FacadeInput<"vault.delete"> = {
    entity_ref: conversation.id, reason: "user_hard_delete",
  };
  const revoked = await engine.client.request<{ revoked: boolean }>(
    "POST", "/v1/core/slips/revoke", { slip_id: Array.from(Buffer.from(agentSlipId, "hex")) },
  );
  expect(revoked.status).toBe(200);
  expect(revoked.body.revoked).toBe(true);
  await museDura02ExpectDeadAgentDelete(agent, deleteConversationInput);
  expect((await engine.client.call("vault.get", { entity_ref: conversation.id })).value).not.toBeNull();
  const auditAfterRevoke = await museDura02AuditRows(engine);

  // Restart: the deleted records stay gone, the receipts and the completed
  // sweep state persist, and the revoked agent credential stays dead.
  await engine.restart();
  await museDura02ExpectDeadAgentDelete(agent, deleteConversationInput);
  expect((await engine.client.call("vault.get", { entity_ref: messageRef })).value).toBeNull();
  expect((await engine.client.call("vault.get", { entity_ref: claimRef })).value).toBeNull();
  expect((await engine.client.call("vault.claims.list", {
    subject_ref: conversation.id, predicate: predicateSentinel, limit: 10,
  })).value).toHaveLength(0);
  const recallAfterRestart = await museDura02Recall(engine, quoteSentinel);
  expect(museDura02ItemsContain(recallAfterRestart.items, messageSentinels)).toBe(false);
  const exportAfterRestart = await museDura02ExportedText(engine);
  expect(allSentinels.every(sentinel => !exportAfterRestart.includes(sentinel))).toBe(true);
  museDura02NoSentinels(await engine.awaitReceipt(messageReceiptRef), allSentinels);
  museDura02NoSentinels(await engine.awaitReceipt(claimReceiptRef), allSentinels);
  const sweepAfterRestart = await museDura02Sweep(engine, messageReceiptRef);
  expect(sweepAfterRestart.sweep_complete_at != null).toBe(true);
  museDura02NoSentinels(sweepAfterRestart, allSentinels);
  await engine.artifacts.json("muse-dura02.json", {
    messageReceiptRef,
    claimReceiptRef,
    messageSweepCompleteAt: sweepAfterRestart.sweep_complete_at ?? null,
  });
});

type museDura03ClaimRow = FacadeResult<"vault.claims.list">["value"][number];

interface museDura03Refusal {
  readonly code: string;
  readonly admissionCode: string;
  readonly receiptRef: string;
  readonly invocation: string;
}

function museDura03Id(seed: string, label: string): string {
  return createHash("sha256").update(`muse-dura-03:${seed}:${label}`).digest("hex").slice(0, 32);
}

function museDura03Object(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown> : undefined;
}

function museDura03ErrorField(body: unknown, field: "code" | "message"): string | undefined {
  const root = museDura03Object(body);
  const error = museDura03Object(root?.error) ?? root;
  const value = error?.[field];
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

// One wrong-actor facade attempt: the standard HTTP refusal envelope, then
// the durable admission receipt that refusal leaves, read back as its actor.
async function museDura03RefusedFacadeCall<V extends FacadeVerb>(
  client: PublicHttpClient, verb: V, input: FacadeInput<V>,
): Promise<museDura03Refusal> {
  const invocation = secretHex(16);
  const reply = await client.raw("POST", `/v1/core/facade/${verb}`, input, {
    "x-oneiron-invocation": invocation,
  });
  expect(reply.status).toBeGreaterThanOrEqual(400);
  expect(reply.status).toBeLessThan(500);
  const code = museDura03ErrorField(reply.body, "code");
  const message = museDura03ErrorField(reply.body, "message");
  if (!code || !message) throw new Error(`${verb} refusal is not the standard error envelope`);
  const admission = await awaitPublic(
    () => client.call("self.admission.status", { intent_key: invocation }),
    (value) => value !== null && value.state.status === "refused",
    { label: `${verb} refusal admission receipt` },
  );
  if (!admission) throw new Error(`${verb} refusal left no admission receipt`);
  const state = admission.state;
  if (state.status !== "refused") throw new Error(`${verb} admission receipt is not refused`);
  expect(admission.verb).toBe(verb);
  expect(admission.intent_key).toBe(invocation);
  expect(admission.receipt_ref.length).toBeGreaterThan(0);
  expect(state.code.length).toBeGreaterThan(0);
  return { code, admissionCode: state.code, receiptRef: admission.receipt_ref, invocation };
}

async function museDura03MarkerRows(
  client: PublicHttpClient, personRef: string, predicate: string, marker: string,
): Promise<museDura03ClaimRow[]> {
  const page = await client.call("vault.claims.list", {
    subject_ref: personRef, predicate, limit: 100,
  });
  return page.value.filter((row) => row.lifecycle === "active" && row.value === marker);
}

async function museDura03RecalledValues(
  client: PublicHttpClient, personRef: string, name: string, predicate: string,
): Promise<string[]> {
  const pack = await client.call("vault.recall", {
    query: name, effort: "light", limit: 100, token_budget: 8192, format: "md",
    scope: { person_ref: personRef, kinds: ["semantic"], worlds: { kind: "all" } },
  });
  return pack.items.filter((item) => item.predicate === predicate)
    .map((item) => item.value_text).sort();
}

async function museDura03ExpectClaimLive(
  client: PublicHttpClient, personRef: string, name: string, predicate: string, marker: string,
): Promise<void> {
  expect(await museDura03MarkerRows(client, personRef, predicate, marker)).toHaveLength(1);
  expect(await museDura03RecalledValues(client, personRef, name, predicate)).toEqual([marker]);
}

async function museDura03ExpectClaimGone(
  client: PublicHttpClient, personRef: string, name: string, predicate: string,
  marker: string, claimShortId: string,
): Promise<void> {
  expect((await client.call("vault.get", { entity_ref: claimShortId })).value).toBeNull();
  const page = await client.call("vault.claims.list", {
    subject_ref: personRef, predicate, limit: 100,
  });
  expect(page.value.filter((row) => row.lifecycle === "active")).toHaveLength(0);
  expect(page.value.some((row) => row.value === marker)).toBe(false);
  expect(await museDura03RecalledValues(client, personRef, name, predicate)).toEqual([]);
}

// MUSE-DURA-03 (PARTIAL). Promises attempted: P-DURA-010 in full (no Grant
// authorizes an agent to erase; the Owner erases by hand through preview and
// confirm, and the erased record stays gone after a restart), plus the
// negative half of P-DURA-009 on vault.delete (a paired agent with no delete
// Grant does not delete; at most its attempt raises the owner ask) and a
// supporting P-DURA-015 observation (one cleanup pass destroys no live
// record). Doors used: vault.conversations.create, vault.witness,
// vault.people.create, vault.claims.upsert (+ vault.claims.review/settle only
// if the claim lands proposed), vault.agents.create, self.actor,
// vault.cleanup.run, vault.delete, vault.agents.grants.mint/revoke,
// vault.records.erase_preview, vault.records.erase_confirm,
// vault.records.erase_sweep, and read-back through vault.get,
// vault.claims.list, vault.recall and self.admission.status.
// Unproved here: P-DURA-008 (no typed public verb archives one named record
// for an agent inside its Grant), the positive half of P-DURA-009 (an agent
// deletes an archived record under a Grant that names delete, on
// vault.archive.delete.confirm; it needs an archived record and the
// delete-grant spelling), P-DURA-013 and P-DURA-014 (they need the same
// missing archive setup; vault.entities.mention and the cleanup surface are
// the candidate doors once an archived record can be made in public).
suite.test(test, "MUSE-DURA-03", "An agent never erases, with or without a grant attempt; the owner erases by hand and the record stays gone after restart", async () => {
  const engine = await EngineFixture.start({ id: "MUSE-DURA-03", profile });
  try {
    const occurred = 1769947200; // Public setup input, never an engine clock override.
    const predicate = "profile.description";
    const sentinel = secretHex(8);
    const marker = `Lantern archive marker ${sentinel}`;
    const personName = `Lantern Keeper ${sentinel.slice(0, 6)}`;
    redactor.add(sentinel, marker, personName);

    // A live, recalled record to aim the ladder at: one CLAIM on one PERSON.
    const conversation = await engine.client.call("vault.conversations.create", {
      body: {}, occurred_start: occurred, occurred_end: occurred, learned_at: occurred,
    });
    const witnessed = await engine.client.call("vault.witness", {
      conversation_ref: conversation.id, occurred_at: occurred,
      messages: [{
        author: "user", message_type: "text", content: `This distinct person is ${personName}.`,
        is_visible: true, order: 0,
      }],
    });
    await engine.awaitReceipt(witnessed.receipt_ref);
    const turn = (await engine.client.call("vault.get", {
      entity_ref: witnessed.turn_short_id,
    })).value;
    if (!turn || turn.kind !== "TURN") throw new Error("Witnessed turn is not readable as a TURN");
    const personRecord = await engine.client.call("vault.people.create", {
      identity: { name: personName }, identity_evidence_refs: [turn.id_hex],
      occurred_at: occurred,
    });
    const personRef = personRecord.person.id_hex;
    expect((await engine.client.call("vault.get", {
      entity_ref: personRecord.person.entity_ref,
    })).value?.kind).toBe("PERSON");

    const scope = await ownerBaseClaimScope(engine.client, engine.pairedActor.principalRef);
    const claimReceipt = await engine.client.call("vault.claims.upsert", {
      predicate, subject_ref: personRef, value: marker, confidence: 1,
      source: "user_stated", scope, occurred_at: occurred, learned_at: occurred,
    });
    await engine.awaitReceipt(claimReceipt.receipt_ref);
    const claimShortId = claimReceipt.claim_short_id;
    const claimView = (await engine.client.call("vault.get", {
      entity_ref: claimShortId,
    })).value;
    if (!claimView || claimView.kind !== "CLAIM") throw new Error("Written claim is not readable as a CLAIM");
    const claimIdHex = claimView.id_hex;
    if (claimReceipt.approval === "proposed") {
      const review = await engine.client.call("vault.claims.review", { claim_ref: claimIdHex });
      const settled = await engine.client.call("vault.claims.settle", {
        claim_ref: claimIdHex, review_id: review.review_id, decision: "approve",
      });
      expect(settled.verdict).toBe("landed");
      await engine.awaitReceipt(settled.receipt_ref);
    }
    await museDura03ExpectClaimLive(engine.client, personRef, personName, predicate, marker);

    // The wrong actor kind: a real paired agent, verified as an agent.
    const agentDefRef = museDura03Id(sentinel, "agent");
    const agentDefinition = await engine.client.call("vault.agents.create", {
      agent_def_ref: agentDefRef,
      definition: {
        agent_id: "muse-dura-03-agent", display_name: "Muse Dura03 Agent",
        desc: "Generated durability reviewer for MUSE-DURA-03", version: "1",
      },
    });
    expect(agentDefinition.agent_def_ref).toBe(agentDefRef);
    expect((await engine.client.call("vault.get", {
      entity_ref: agentDefRef,
    })).value?.kind).toBe("AGENT_DEF");
    const agent = await engine.pairActor({
      principalRef: agentDefRef, actorClass: "agent", scope: ["core:read", "core:write"],
    });
    const agentIdentity = await agent.client.call("self.actor", {});
    expect(agentIdentity.actor_ref).toBe(agentDefRef);
    expect(agentIdentity.actor_class).toBe("agent");

    // P-DURA-015 (supporting): the standing cleanup pass archives at most;
    // it destroys no live record here.
    const cleanup = await engine.client.call("vault.cleanup.run", {});
    await museDura03ExpectClaimLive(engine.client, personRef, personName, predicate, marker);

    // P-DURA-009 (negative half): with no delete Grant the agent does not
    // delete. A refused envelope, or a 202 owner ask that lands nothing,
    // are the two promised shapes; the record must survive either way.
    const deleteReply = await agent.client.raw("POST", "/v1/core/facade/vault.delete", {
      entity_ref: claimShortId, reason: "user_delete",
    } satisfies FacadeInput<"vault.delete">);
    expect(deleteReply.status === 202
      || (deleteReply.status >= 400 && deleteReply.status < 500)).toBe(true);
    if (!museDura03ErrorField(deleteReply.body, "code")
      || !museDura03ErrorField(deleteReply.body, "message")) {
      throw new Error("Agent delete attempt did not answer the standard refusal/ask envelope");
    }
    await museDura03ExpectClaimLive(engine.client, personRef, personName, predicate, marker);

    // P-DURA-010: with no Grant at all, the agent's erase preview is
    // refused and leaves a read-back refusal receipt; nothing is erased.
    const noGrantPreviewRefusal = await museDura03RefusedFacadeCall(
      agent.client, "vault.records.erase_preview", { record: claimIdHex },
    );
    await museDura03ExpectClaimLive(engine.client, personRef, personName, predicate, marker);

    // The owner now tries to mint the strongest erase grant the typed agent
    // Grant door can name: both erase verbs, every scope axis all. Canon
    // allows two shapes only - the mint itself is refused/asked because no
    // Grant names erase, or a row is minted that still authorizes no erase.
    // Either way the confirm below must refuse.
    const mintInput: FacadeInput<"vault.agents.grants.mint"> = {
      agent: agentDefRef,
      authority_scope: {
        worlds: { kind: "all" }, facets: { kind: "all" }, bands: { kind: "all" },
        audience: { kind: "all" },
        verbs: { kind: "some", values: ["vault.records.erase_preview", "vault.records.erase_confirm"] },
        sensitivity: { kind: "all" },
      },
    };
    const mintReply = await engine.client.raw(
      "POST", "/v1/core/facade/vault.agents.grants.mint", mintInput,
    );
    const mintGrant = museDura03Object(museDura03Object(mintReply.body)?.grant);
    let eraseGrantRef: string | undefined;
    if (mintReply.status >= 200 && mintReply.status < 300 && mintGrant) {
      expect(mintGrant.agent).toBe(agentDefRef);
      if (typeof mintGrant.grant_ref !== "string" || mintGrant.grant_ref.length === 0) {
        throw new Error("Minted erase-named grant carries no grant reference");
      }
      eraseGrantRef = mintGrant.grant_ref;
    } else {
      expect(mintReply.status === 202
        || (mintReply.status >= 400 && mintReply.status < 500)).toBe(true);
      if (!museDura03ErrorField(mintReply.body, "code")) {
        throw new Error("Refused erase-grant mint did not answer the standard refusal/ask envelope");
      }
    }

    // The Owner previews by hand; the preview alone erases nothing.
    let ownerPreview = await engine.client.call("vault.records.erase_preview", {
      record: claimIdHex,
    });
    expect(ownerPreview.preview_digest.length).toBeGreaterThan(0);
    await museDura03ExpectClaimLive(engine.client, personRef, personName, predicate, marker);

    // The agent may not spend the Owner's preview, grant attempt or not.
    const confirmRefusal = await museDura03RefusedFacadeCall(
      agent.client, "vault.records.erase_confirm",
      { record: claimIdHex, preview_digest: ownerPreview.preview_digest },
    );
    await museDura03ExpectClaimLive(engine.client, personRef, personName, predicate, marker);

    // The loses-the-grant leg, when a grant row was minted: the Owner
    // revokes it through the public door, and the agent's next erase use
    // is still refused, with its own refusal receipt.
    if (eraseGrantRef) {
      const revoked = await engine.client.call("vault.agents.grants.revoke", {
        grant_ref: eraseGrantRef,
      });
      expect(revoked.grant_ref).toBe(eraseGrantRef);
      expect(revoked.changed).toBe(true);
      await museDura03RefusedFacadeCall(
        agent.client, "vault.records.erase_preview", { record: claimIdHex },
      );
      await museDura03ExpectClaimLive(engine.client, personRef, personName, predicate, marker);
    }

    // The act: the Owner erases by hand - a fresh preview, then confirm.
    ownerPreview = await engine.client.call("vault.records.erase_preview", {
      record: claimIdHex,
    });
    const erased = await engine.client.call("vault.records.erase_confirm", {
      record: claimIdHex, preview_digest: ownerPreview.preview_digest,
    });
    if (!("first" in erased)) throw new Error("Owner erase confirm returned no erase outcome");
    expect(erased.first.existed).toBe(true);
    const eraseReceiptRef = erased.first.receipt_ref;
    if (typeof eraseReceiptRef !== "string" || eraseReceiptRef.length === 0) {
      throw new Error("Owner erase left no receipt reference");
    }
    const sweep = await awaitPublic(
      () => engine.client.call("vault.records.erase_sweep", { receipt_ref: eraseReceiptRef }),
      (value) => value !== null,
      { label: "erase sweep receipt" },
    );
    if (!sweep) throw new Error("Owner erase left no read-back sweep receipt");
    expect(sweep.receipt_ref).toBe(eraseReceiptRef);
    expect(sweep.request_id.length).toBeGreaterThan(0);

    // Gone from active reads through three other doors; the subject stands.
    await museDura03ExpectClaimGone(
      engine.client, personRef, personName, predicate, marker, claimShortId,
    );

    await engine.restart();

    // Still gone after restart; the subject and both receipts still read.
    await museDura03ExpectClaimGone(
      engine.client, personRef, personName, predicate, marker, claimShortId,
    );
    const sweepAfterRestart = await awaitPublic(
      () => engine.client.call("vault.records.erase_sweep", { receipt_ref: eraseReceiptRef }),
      (value) => value !== null,
      { label: "erase sweep receipt after restart" },
    );
    if (!sweepAfterRestart) throw new Error("Erase sweep receipt is unreadable after restart");
    expect(sweepAfterRestart.request_id).toBe(sweep.request_id);
    const admissionAfterRestart = await awaitPublic(
      () => agent.client.call("self.admission.status", {
        intent_key: noGrantPreviewRefusal.invocation,
      }),
      (value) => value !== null && value.state.status === "refused",
      { label: "agent erase refusal receipt after restart" },
    );
    if (!admissionAfterRestart || admissionAfterRestart.state.status !== "refused") {
      throw new Error("Agent erase refusal receipt is not a durable refusal after restart");
    }
    expect(admissionAfterRestart.receipt_ref).toBe(noGrantPreviewRefusal.receiptRef);

    await engine.artifacts.json("muse-dura-03.json", {
      personRef, claimIdHex, claimShortId, agentDefRef,
      deleteAttemptStatus: deleteReply.status,
      grantMintStatus: mintReply.status,
      grantMinted: eraseGrantRef !== undefined,
      noGrantPreviewRefusal, confirmRefusal,
      eraseReceiptRef, sweepRequestId: sweep.request_id,
    });
  } finally {
    await engine.close();
  }
});

// MUSE-DURA-04 — promises P-DURA-011, P-DURA-021, P-DURA-022 and the HTTP/CLI part
// of P-OTHER-023 (source lines are in MUSE-DURA-04.report.md).
// Doors used, all public: vault.artifacts.put/append/read (two blob-artifact holders
// of the same bytes), vault.records.erase_preview/erase_confirm/erase_sweep,
// vault.get (second read door), vault.structural.put + pairActor + self.actor (an
// agent actor), raw HTTP facade calls for the refusals, self.admission.status (the
// refusal receipt, read back), the real CLI via cli.call / cli.run ("api call") and
// engine.restart().
// Stays unproved (see the report): the MCP erase surface (McpClient.callTool is
// untyped and no MCP erase tool name/argument contract is in the typed facade),
// the legacy HTTP hard_delete rail (not in the typed facade given to this case),
// recall/export/peer disappearance, shared-vault veto and grant loss (no Grant
// ever names erase).

const museDura04OccurredAt = 1769947200; // Same explicit public time the suite already uses.

interface museDura04Payload {
  readonly text: string;
  readonly base64: string;
}
interface museDura04Holder {
  readonly artifactRef: string;
  readonly recordId: string;
  readonly version: number;
  readonly contentHash: string;
  readonly ids: readonly string[];
}
interface museDura04WireError {
  readonly code?: unknown;
  readonly message?: unknown;
}
interface museDura04ErrorEnvelope {
  readonly error?: museDura04WireError;
}

function museDura04MakePayload(label: string): museDura04Payload {
  const token = secretHex(8);
  // Space the generated hex out so the payload is plain test prose, not a
  // credential-shaped string. Register every form before first use.
  const text = `MUSE DURA 04 ${label} shared bytes ${token.split("").join(" ")}`;
  const base64 = Buffer.from(text, "utf8").toString("base64");
  redactor.add(token, text, base64);
  return { text, base64 };
}

async function museDura04CreateHolder(
  engine: EngineFixture,
  name: string,
  payload: museDura04Payload,
): Promise<museDura04Holder> {
  const put = await engine.client.call("vault.artifacts.put", {
    name, media_type: "text/plain", occurred_at: museDura04OccurredAt,
  } satisfies FacadeInput<"vault.artifacts.put">);
  const appended = await engine.client.call("vault.artifacts.append", {
    artifact_ref: put.entity_ref, content_base64: payload.base64,
    occurred_at: museDura04OccurredAt,
  } satisfies FacadeInput<"vault.artifacts.append">);
  if (!("landed" in appended)) {
    throw new Error("An owner blob append was proposed, not landed");
  }
  const landed = appended.landed;
  const idSet = new Set<string>([put.entity_ref, put.id_hex, landed.artifact_ref]);
  for (const candidate of [put.record?.id, put.record?.short_id, landed.artifact?.id, landed.artifact?.short_id]) {
    if (candidate) idSet.add(candidate);
  }
  const holder: museDura04Holder = {
    artifactRef: landed.artifact_ref, recordId: put.id_hex,
    version: landed.version, contentHash: landed.content_hash_hex, ids: [...idSet],
  };
  // Read the write back through a different verb before anything relies on it.
  expect(await museDura04ReadText(engine, holder) === payload.text).toBe(true);
  expect(await museDura04Exists(engine, holder)).toBe(true);
  return holder;
}

async function museDura04ReadText(engine: EngineFixture, holder: museDura04Holder): Promise<string | null> {
  const read = await engine.client.call("vault.artifacts.read", {
    artifact_ref: holder.artifactRef, version: holder.version,
  } satisfies FacadeInput<"vault.artifacts.read">);
  return read === null ? null : Buffer.from(read.content_base64, "base64").toString("utf8");
}

async function museDura04Exists(engine: EngineFixture, holder: museDura04Holder): Promise<boolean> {
  const got = await engine.client.call("vault.get", {
    entity_ref: holder.recordId,
  } satisfies FacadeInput<"vault.get">);
  return got.value !== null;
}

function museDura04Identifies(ids: readonly string[], candidates: readonly string[]): boolean {
  const wanted = new Set(candidates);
  return ids.some((id) => wanted.has(id));
}

function museDura04EraseOutcome(
  value: FacadeResult<"vault.records.erase_confirm">,
): Facade.RecordEraseOutcome {
  if (!("first" in value)) {
    throw new Error("Erase confirm answered without an erase outcome");
  }
  return value;
}

function museDura04ExpectRefusal(
  reply: { readonly status: number; readonly body: museDura04ErrorEnvelope },
): void {
  expect(reply.status >= 400 && reply.status < 600).toBe(true);
  const code = reply.body.error?.code;
  const message = reply.body.error?.message;
  if (typeof code !== "string" || code.length === 0) {
    throw new Error("Refusal does not carry the standard error envelope code");
  }
  if (typeof message !== "string" || message.length === 0) {
    throw new Error("Refusal does not carry the standard error envelope message");
  }
}

async function museDura04ExpectSweepReceipt(
  engine: EngineFixture,
  outcome: Facade.RecordEraseOutcome,
): Promise<string> {
  const receiptRef = outcome.first.receipt_ref!;
  const sweep = await engine.client.call("vault.records.erase_sweep", {
    receipt_ref: receiptRef,
  } satisfies FacadeInput<"vault.records.erase_sweep">);
  return receiptRef;
}

suite.test(test, "MUSE-DURA-04", "Owner previewed erase takes effect at once over HTTP and CLI, spares a live same-bytes holder unless also_same_bytes is chosen, and stays erased after restart", async () => {
  const engine = await EngineFixture.start({ id: "MUSE-DURA-04", profile });
  try {
    const payloadOne = museDura04MakePayload("one");
    const payloadTwo = museDura04MakePayload("two");

    // Two distinct records, one shared blob: same bytes appended to two artifacts.
    const a = await museDura04CreateHolder(engine, "MUSE-DURA-04 holder A", payloadOne);
    const b = await museDura04CreateHolder(engine, "MUSE-DURA-04 holder B", payloadOne);
    expect(a.recordId === b.recordId).toBe(false);
    expect(a.contentHash === b.contentHash).toBe(true);

    // The wrong actor kind: a real agent, paired with read and write scope.
    const agentRecord = await engine.client.call("vault.structural.put", {
      kind: "PERSON", body: { name: "Muse Dura Agent" }, occurred_at: museDura04OccurredAt,
    } satisfies FacadeInput<"vault.structural.put">);
    const agent = await engine.pairActor({
      principalRef: agentRecord.id_hex, actorClass: "agent", scope: ["core:read", "core:write"],
    });
    const agentSelf = await agent.client.call("self.actor", {});
    expect(agentSelf.actor_class.toLowerCase().includes("agent")).toBe(true);

    // The agent's preview is refused, and the refusal leaves a receipt the
    // agent itself can read back through a second door.
    const agentInvocation = secretHex(16);
    redactor.add(agentInvocation);
    museDura04ExpectRefusal(await agent.client.raw<museDura04ErrorEnvelope>(
      "POST", "/v1/core/facade/vault.records.erase_preview",
      { record: a.recordId } satisfies FacadeInput<"vault.records.erase_preview">,
      { "x-oneiron-invocation": agentInvocation },
    ));
    const admission = await awaitPublic(
      () => agent.client.call("self.admission.status", { intent_key: agentInvocation }),
      (value) => value?.state.status === "refused",
      { timeoutMs: 5_000, label: "agent erase preview admission receipt" },
    );
    if (!admission) throw new Error("The refused agent preview left no admission receipt");
    expect(admission.verb).toBe("vault.records.erase_preview");
    expect(admission.state.status).toBe("refused");
    expect(await museDura04ReadText(engine, a) === payloadOne.text).toBe(true);

    // The owner's preview names its record, the other holder of the same bytes
    // and the digest a confirm must hand back. The CLI answers the same preview.
    const previewA = await engine.client.call("vault.records.erase_preview", {
      record: a.recordId,
    } satisfies FacadeInput<"vault.records.erase_preview">);
    expect(a.ids.includes(previewA.record)).toBe(true);
    expect(previewA.preview_digest.length).toBeGreaterThan(0);
    expect(museDura04Identifies(previewA.same_bytes, b.ids)).toBe(true);
    const previewACli = await engine.cli.call("vault.records.erase_preview", {
      record: a.recordId,
    } satisfies FacadeInput<"vault.records.erase_preview">);
    expect(previewACli.preview_digest.length).toBeGreaterThan(0);

    // A confirm is bound to the preview: a wrong digest erases nothing, and
    // even the right digest does not make the agent an owner.
    const bogusDigest = secretHex(32);
    redactor.add(bogusDigest);
    museDura04ExpectRefusal(await engine.client.raw<museDura04ErrorEnvelope>(
      "POST", "/v1/core/facade/vault.records.erase_confirm",
      { record: a.recordId, preview_digest: bogusDigest } satisfies FacadeInput<"vault.records.erase_confirm">,
    ));
    museDura04ExpectRefusal(await agent.client.raw<museDura04ErrorEnvelope>(
      "POST", "/v1/core/facade/vault.records.erase_confirm",
      { record: a.recordId, preview_digest: previewACli.preview_digest } satisfies FacadeInput<"vault.records.erase_confirm">,
    ));
    expect(await museDura04ReadText(engine, a) === payloadOne.text).toBe(true);

    // The owner's confirm, through the CLI, with also_same_bytes omitted (off
    // by default): A is gone at once, B keeps the shared bytes.
    const previewAConfirm = await engine.client.call("vault.records.erase_preview", {
      record: a.recordId,
    } satisfies FacadeInput<"vault.records.erase_preview">);
    expect(museDura04Identifies(previewAConfirm.same_bytes, b.ids)).toBe(true);
    const outcomeA = museDura04EraseOutcome(await engine.cli.call("vault.records.erase_confirm", {
      record: a.recordId, preview_digest: previewAConfirm.preview_digest,
    } satisfies FacadeInput<"vault.records.erase_confirm">));
    expect(outcomeA.first.existed).toBe(true);
    const sweepRefA = await museDura04ExpectSweepReceipt(engine, outcomeA);
    expect(await museDura04ReadText(engine, a)).toBeNull();
    expect(await museDura04Exists(engine, a)).toBe(false);
    expect(await museDura04ReadText(engine, b) === payloadOne.text).toBe(true);
    expect(await museDura04Exists(engine, b)).toBe(true);
    const previewBAfter = await engine.client.call("vault.records.erase_preview", {
      record: b.recordId,
    } satisfies FacadeInput<"vault.records.erase_preview">);
    expect(b.ids.includes(previewBAfter.record)).toBe(true);
    expect(museDura04Identifies(previewBAfter.same_bytes, a.ids)).toBe(false);
    expect(await museDura04ReadText(engine, b) === payloadOne.text).toBe(true);

    // A fresh same-bytes pair, this time with the explicit opt-in: both go.
    const c = await museDura04CreateHolder(engine, "MUSE-DURA-04 holder C", payloadTwo);
    const d = await museDura04CreateHolder(engine, "MUSE-DURA-04 holder D", payloadTwo);
    expect(c.contentHash === d.contentHash).toBe(true);
    const previewC = await engine.client.call("vault.records.erase_preview", {
      record: c.recordId,
    } satisfies FacadeInput<"vault.records.erase_preview">);
    expect(museDura04Identifies(previewC.same_bytes, d.ids)).toBe(true);
    const outcomeC = museDura04EraseOutcome(await engine.client.call("vault.records.erase_confirm", {
      record: c.recordId, preview_digest: previewC.preview_digest, also_same_bytes: true,
    } satisfies FacadeInput<"vault.records.erase_confirm">));
    expect(outcomeC.first.existed).toBe(true);
    expect(outcomeC.same_bytes).toHaveLength(1);
    const sameBytesRow = outcomeC.same_bytes.find((row) => d.ids.includes(row.record));
    if (!sameBytesRow) throw new Error("also_same_bytes left no row for the other holder");
    await museDura04ExpectSweepReceipt(engine, outcomeC);
    expect(await museDura04ReadText(engine, c)).toBeNull();
    expect(await museDura04ReadText(engine, d)).toBeNull();
    expect(await museDura04Exists(engine, c)).toBe(false);
    expect(await museDura04Exists(engine, d)).toBe(false);
    // Different bytes are outside the flag: B is untouched.
    expect(await museDura04ReadText(engine, b) === payloadOne.text).toBe(true);

    // The CLI refuses the agent too, and refuses without erasing.
    const agentCli = await agent.cli.run(
      ["api", "call", "vault.records.erase_preview", "--data", "-"],
      JSON.stringify({ record: b.recordId } satisfies FacadeInput<"vault.records.erase_preview">),
    );
    expect(agentCli.exitCode).not.toBe(0);
    expect(await museDura04ReadText(engine, b) === payloadOne.text).toBe(true);

    // Survive a restart: the erased records stay gone, the spared holder keeps
    // its bytes, and the first erase receipt is still readable.
    await engine.restart();
    expect(await museDura04ReadText(engine, a)).toBeNull();
    expect(await museDura04ReadText(engine, c)).toBeNull();
    expect(await museDura04ReadText(engine, d)).toBeNull();
    expect(await museDura04Exists(engine, a)).toBe(false);
    expect(await museDura04Exists(engine, d)).toBe(false);
    expect(await museDura04ReadText(engine, b) === payloadOne.text).toBe(true);
    expect(await museDura04Exists(engine, b)).toBe(true);
    const previewBAfterRestart = await engine.client.call("vault.records.erase_preview", {
      record: b.recordId,
    } satisfies FacadeInput<"vault.records.erase_preview">);
    expect(museDura04Identifies(previewBAfterRestart.same_bytes, a.ids)).toBe(false);
    const sweepAfterRestart = await engine.client.call("vault.records.erase_sweep", {
      receipt_ref: sweepRefA,
    } satisfies FacadeInput<"vault.records.erase_sweep">);
  } finally {
    await engine.close();
  }
});

// MUSE-DURA-05 (PARTIAL) — P-DURA-016, P-DURA-017, P-DURA-018.
// Doors used: vault.structural.put, vault.conversations.create, vault.witness,
// vault.get, vault.recall, vault.export, vault.records.erase_preview,
// vault.records.erase_confirm, vault.records.erase_sweep,
// self.admission.status, and EngineFixture restart.
// Proved here: the export half of P-DURA-018 plus the live-vault half of
// P-DURA-017 — an owner export taken before an erase still holds the erased
// record afterwards, while the live vault, its recall and a fresh export lose
// that record and keep losing it after a restart.
// Unproved: P-DURA-016 (delete, then a backup/checkpoint restore inside the
// 90-day window), the backup/checkpoint copies in P-DURA-017, and the
// independently restored side copy in P-DURA-018. The typed facade has no
// vault backup, checkpoint-restore, side-restore or whole-vault import verb,
// so no public door in the allowed surface can drive those acts. The case
// report names the candidate missing doors.

type museDura05InlineExportAnswer = Extract<FacadeResult<"vault.export">, { archive: string }>;
type museDura05EraseOutcome = Extract<FacadeResult<"vault.records.erase_confirm">, { first: unknown }>;

function museDura05Object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Expected a public JSON object (body withheld)");
  }
  return value as Record<string, unknown>;
}

function museDura05TextHas(value: unknown, needle: string): boolean {
  return (JSON.stringify(value) ?? "").includes(needle);
}

function museDura05WireError(body: unknown): { code: string; message: string } {
  const root = museDura05Object(body);
  const candidate = root.error;
  const error = candidate && typeof candidate === "object" && !Array.isArray(candidate)
    ? candidate as Record<string, unknown>
    : root;
  if (typeof error.code !== "string" || typeof error.message !== "string") {
    throw new Error("Refusal is not the standard code/message envelope (body withheld)");
  }
  return { code: error.code, message: error.message };
}

function museDura05WithinDays(start: number, end: number, days: number): boolean {
  const scale = start >= 1_000_000_000_000_000 ? 1_000_000
    : start >= 1_000_000_000_000 ? 1_000
    : 1;
  const elapsedSeconds = (end - start) / scale;
  return elapsedSeconds >= 0 && elapsedSeconds <= days * 24 * 60 * 60;
}

function museDura05RequireInlineExport(
  answer: FacadeResult<"vault.export">,
): museDura05InlineExportAnswer {
  if (!("archive" in answer)) throw new Error("Unexpected export transfer for inline request");
  return answer;
}

function museDura05RequireEraseOutcome(
  answer: FacadeResult<"vault.records.erase_confirm">,
): museDura05EraseOutcome {
  if (!("first" in answer)) throw new Error("Owner erase did not return its outcome in this call");
  return answer;
}

/** Reads the public ZIP export response. Single-disk ZIP, stored or deflated
 * members, as in SECRETS-01; no filesystem extraction or engine codec. */
function museDura05PublicZip(encoded: string): Map<string, Buffer> {
  const zip = Buffer.from(encoded, "base64");
  let end = zip.length - 22;
  for (; end >= Math.max(0, zip.length - 65_557); end--) {
    if (zip.readUInt32LE(end) === 0x06054b50
      && end + 22 + zip.readUInt16LE(end + 20) === zip.length) break;
  }
  if (end < 0 || end < Math.max(0, zip.length - 65_557)) {
    throw new Error("Public export is not a complete ZIP");
  }
  expect(zip.readUInt16LE(end + 4)).toBe(0);
  expect(zip.readUInt16LE(end + 6)).toBe(0);
  const entries = zip.readUInt16LE(end + 10);
  expect(zip.readUInt16LE(end + 8)).toBe(entries);
  let cursor = zip.readUInt32LE(end + 16);
  const directoryEnd = cursor + zip.readUInt32LE(end + 12);
  const files = new Map<string, Buffer>();
  for (let index = 0; index < entries; index++) {
    expect(zip.readUInt32LE(cursor)).toBe(0x02014b50);
    expect(zip.readUInt16LE(cursor + 8) & 1).toBe(0);
    const method = zip.readUInt16LE(cursor + 10);
    const compressed = zip.readUInt32LE(cursor + 20);
    const length = zip.readUInt32LE(cursor + 24);
    const nameLength = zip.readUInt16LE(cursor + 28);
    const extraLength = zip.readUInt16LE(cursor + 30);
    const commentLength = zip.readUInt16LE(cursor + 32);
    const local = zip.readUInt32LE(cursor + 42);
    const name = zip.subarray(cursor + 46, cursor + 46 + nameLength).toString("utf8");
    expect(files.has(name)).toBe(false);
    expect(zip.readUInt32LE(local)).toBe(0x04034b50);
    const start = local + 30 + zip.readUInt16LE(local + 26) + zip.readUInt16LE(local + 28);
    expect(start + compressed <= zip.length).toBe(true);
    const wire = zip.subarray(start, start + compressed);
    if (method !== 0 && method !== 8) throw new Error("Unsupported public ZIP compression");
    const bytes = method === 0 ? wire : inflateRawSync(wire);
    expect(bytes.length).toBe(length);
    files.set(name, bytes);
    cursor += 46 + nameLength + extraLength + commentLength;
  }
  expect(cursor).toBe(directoryEnd);
  expect(directoryEnd).toBe(end);
  return files;
}

function museDura05ArchiveText(encoded: string): string {
  return [...museDura05PublicZip(encoded).values()]
    .map(bytes => bytes.toString("utf8"))
    .join("\n");
}

suite.test(test, "MUSE-DURA-05", "A prior owner export keeps an erased record while the live vault loses it", async () => {
  const engine = await EngineFixture.start({ id: "MUSE-DURA-05", profile });
  try {
    const occurred = 1769947200;
    const aHex = secretHex(6);
    const bHex = secretHex(6);
    const aPhrase = `dura zero five alpha ${aHex}`;
    const bPhrase = `dura zero five bravo ${bHex}`;
    redactor.add(aPhrase, bPhrase, aHex, bHex);

    const agentRecord = await engine.client.call("vault.structural.put", {
      kind: "PERSON", body: { name: "Dura Zero Five Agent" }, occurred_at: occurred,
    } satisfies FacadeInput<"vault.structural.put">);
    const agent = await engine.pairActor({
      principalRef: agentRecord.id_hex, actorClass: "agent", scope: ["core:read", "core:write"],
    });
    const conversation = await engine.client.call("vault.conversations.create", {
      body: { members: [engine.pairedActor.principalRef, agent.principalRef] },
      occurred_start: occurred, occurred_end: occurred,
    } satisfies FacadeInput<"vault.conversations.create">);

    const museDura05Witness = async (
      phrase: string,
    ): Promise<{ shortId: string; idHex: string }> => {
      const witnessed = await engine.client.call("vault.witness", {
        conversation_ref: conversation.id,
        occurred_at: occurred,
        messages: [{
          author: "user", message_type: "text", is_visible: true, order: 0,
          content: `Please remember the phrase ${phrase} for the picnic list.`,
        }],
      } satisfies FacadeInput<"vault.witness">);
      await engine.awaitReceipt(witnessed.receipt_ref);
      expect(witnessed.message_short_ids).toHaveLength(1);
      const shortId = witnessed.message_short_ids[0];
      if (!shortId) throw new Error("Witness returned no message reference");
      const saved = await engine.client.call("vault.get", { entity_ref: shortId });
      if (!saved.value) throw new Error("Witnessed message is not publicly readable");
      const content = museDura05Object(saved.value.body).content;
      expect(museDura05TextHas(content, phrase)).toBe(true);
      return { shortId, idHex: saved.value.id_hex };
    };

    const museDura05RecallHas = async (phrase: string): Promise<boolean> => {
      const pack = await engine.client.call("vault.recall", {
        query: phrase, effort: "light", limit: 10,
      } satisfies FacadeInput<"vault.recall">);
      return pack.items.some(item => item.value_text.includes(phrase)
        || (item.cited_messages?.some(message => message.value_text.includes(phrase)) ?? false));
    };

    const museDura05Export = async (): Promise<museDura05InlineExportAnswer> => {
      const exported = await engine.client.call("vault.export", {
        format: "archive", include_secrets: false, delivery: "inline",
      } satisfies FacadeInput<"vault.export">);
      return museDura05RequireInlineExport(exported);
    };

    const main = await museDura05Witness(aPhrase);
    const spare = await museDura05Witness(bPhrase);
    expect(await museDura05RecallHas(aPhrase)).toBe(true);
    const agentSparePeek = await agent.client.call("vault.get", { entity_ref: spare.shortId });
    expect(agentSparePeek.value !== null).toBe(true);

    const prior = await museDura05Export();
    expect(Buffer.from(blake3(Buffer.from(prior.archive, "base64"))).toString("hex")).toBe(prior.digest);
    const priorText = museDura05ArchiveText(prior.archive);
    expect(priorText.includes(aPhrase)).toBe(true);
    expect(priorText.includes(bPhrase)).toBe(true);

    const sparePreview = await engine.client.call("vault.records.erase_preview", {
      record: spare.idHex,
    } satisfies FacadeInput<"vault.records.erase_preview">);
    expect(sparePreview.preview_digest.length).toBeGreaterThan(0);
    const museDura05Intent = secretHex(16);
    const agentErase = await agent.client.raw<unknown>(
      "POST", "/v1/core/facade/vault.records.erase_confirm",
      {
        record: sparePreview.record, preview_digest: sparePreview.preview_digest,
      } satisfies FacadeInput<"vault.records.erase_confirm">,
      { "x-oneiron-invocation": museDura05Intent },
    );
    expect(agentErase.status >= 400 && agentErase.status < 500).toBe(true);
    const agentEraseError = museDura05WireError(agentErase.body);
    expect(agentEraseError.code.length).toBeGreaterThan(0);
    expect(agentEraseError.message.length).toBeGreaterThan(0);
    const refusalReceipt = await awaitPublic(
      () => agent.client.call("self.admission.status", { intent_key: museDura05Intent }),
      receipt => receipt !== null && receipt.state.status === "refused",
      { timeoutMs: 5_000, label: "agent erase refusal admission receipt" },
    );
    if (!refusalReceipt || refusalReceipt.state.status !== "refused") {
      throw new Error("Agent erase refusal left no refused admission receipt");
    }
    expect(refusalReceipt.verb).toBe("vault.records.erase_confirm");
    expect(refusalReceipt.intent_key).toBe(museDura05Intent);
    expect(refusalReceipt.state.code.length).toBeGreaterThan(0);

    const agentExportIntent = secretHex(16);
    const agentExport = await agent.client.raw<unknown>(
      "POST", "/v1/core/facade/vault.export",
      {
        format: "archive", include_secrets: false, delivery: "inline",
      } satisfies FacadeInput<"vault.export">,
      { "x-oneiron-invocation": agentExportIntent },
    );

    const spareAfterRefusal = await engine.client.call("vault.get", { entity_ref: spare.shortId });
    expect(spareAfterRefusal.value !== null).toBe(true);
    expect(museDura05TextHas(spareAfterRefusal.value?.body, bPhrase)).toBe(true);

    const mainPreview = await engine.client.call("vault.records.erase_preview", {
      record: main.idHex,
    } satisfies FacadeInput<"vault.records.erase_preview">);
    expect(mainPreview.preview_digest.length).toBeGreaterThan(0);
    const erased = museDura05RequireEraseOutcome(
      await engine.client.call("vault.records.erase_confirm", {
        record: mainPreview.record, preview_digest: mainPreview.preview_digest,
      } satisfies FacadeInput<"vault.records.erase_confirm">),
    );
    expect(erased.first.existed).toBe(true);
    const eraseReceiptRef = erased.first.receipt_ref;
    if (!eraseReceiptRef) throw new Error("Owner erase returned no deletion receipt reference");
    const sweep = await awaitPublic(
      () => engine.client.call("vault.records.erase_sweep", { receipt_ref: eraseReceiptRef }),
      value => value !== null,
      { timeoutMs: 5_000, label: "erase sweep receipt read" },
    );

    const mainAfterErase = await engine.client.call("vault.get", { entity_ref: main.shortId });
    expect(mainAfterErase.value).toBeNull();
    expect(await museDura05RecallHas(aPhrase)).toBe(false);
    const spareAfterErase = await engine.client.call("vault.get", { entity_ref: spare.shortId });

    const fresh = await museDura05Export();
    expect(Buffer.from(blake3(Buffer.from(fresh.archive, "base64"))).toString("hex")).toBe(fresh.digest);
    expect(fresh.digest === prior.digest).toBe(false);
    const freshText = museDura05ArchiveText(fresh.archive);
    expect(freshText.includes(aPhrase)).toBe(false);
    expect(Buffer.from(blake3(Buffer.from(prior.archive, "base64"))).toString("hex")).toBe(prior.digest);
    expect(museDura05ArchiveText(prior.archive).includes(aPhrase)).toBe(true);

    await engine.restart();
    const mainAfterRestart = await engine.client.call("vault.get", { entity_ref: main.shortId });
    expect(mainAfterRestart.value).toBeNull();
    expect(await museDura05RecallHas(aPhrase)).toBe(false);
    const sweepAfterRestart = await engine.client.call("vault.records.erase_sweep", {
      receipt_ref: eraseReceiptRef,
    });
    expect(museDura05ArchiveText(prior.archive).includes(aPhrase)).toBe(true);

    await engine.artifacts.json("muse-dura05-erase.json", {
      priorDigest: prior.digest,
      freshDigest: fresh.digest,
      eraseReceiptRef,
      sweepRequestId: sweep?.request_id,
      refusalReceipt: refusalReceipt.receipt_ref,
    });
  } finally {
    await engine.close();
  }
});

// MUSE-DURA-06 — A deleted record stays gone on the peer: sync never resurrects
// it and a tombstone-removal delta is quarantined.
//
// Promises (ratified promise register):
// - P-DURA-006 (MUST): Sync cannot resurrect a tombstoned record.
// - P-DURA-007 (MUST): A tombstone-removal delta is quarantined rather than applied.
//
// Canon (the oracle; no engine code was read):
// - ARCH-0038 #materialization-gate: materialization is refused if a CRDT
//   tombstone is present OR a local dt:{entity_id} marker is present; local
//   truth outranks the replicated tombstones map. A removal of a tombstone is
//   never honoured as a merge: no engine version emits a tombstone-removal
//   delta, so such a delta is a protocol violation and is quarantined (the x:
//   family on ARCH-0023b), never silently applied.
// - ARCH-0023b, protocol-violation policy: a tombstone-removal delta is
//   quarantined as an x: row (hash + length + metadata only, never content),
//   never silently ignored. Honest-replay safety: a node replaying real
//   protocol traffic can never resurrect erased content.
//
// Doors that EXIST on the typed surface (checked against the generated facade):
// - Act (local half only): vault.delete (SafeDeleteRequest ->
//   DeleteReceipt), "an owner verb that only a verified human may call".
// - Observe: vault.get, vault.recall, vault.export.scoped on each vault, and
//   vault.sync.quarantine.held_edits (EmptyRequest ->
//   [number, SyncHeldEditEvidence][]), whose evidence rows name a
//   QuarantineContainer that includes "tombstones" — the right second door
//   for P-DURA-007 once a delta can be delivered.
// - Survive a restart: EngineFixture.restart().
//
// Core acts for which NO public door exists (so this case is a TODO, per G01):
// 1. Same-vault peer sync. Both promises are about a peer replica of the SAME
//    vault. EngineFixture.peers creates extra INDEPENDENT vaults with "no
//    membership or sync authority silently installed" (support/engine.ts), and
//    no facade verb enrols a second engine as an authorized replica/device of
//    the first vault or opens a sync session between them. The shipped
//    examples confirm the gap: AUTHORITY-02 waits on a "public same-vault
//    sync fixture" and SECRETS-04 notes peers are "independent vaults, NOT
//    two devices of one vault". Federation (vault.federation.connect.* /
//    burst.ingress) is not a substitute: it moves host-signed updates of a
//    named world into a FOREIGN vault, and canon keeps cross-vault erasure on
//    the notify-do-not-coerce path, so a federation peer keeping its copy
//    after our delete would be correct behaviour, not a resurrection.
// 2. Delivering a tombstone-removal delta. Canon says no engine version emits
//    one, so no public verb can be asked to produce it; and no grant-gated
//    peer-ingress verb accepts a raw window update from an enrolled replica
//    through which a test could deliver one. The WsClient deliberately does
//    not negotiate private sync state (support/clients.ts: sync frames stay
//    on "a separate caller-owned raw socket" the harness does not provide),
//    and hand-crafting Loro bytes would be a fabricated seed, which the E2E
//    rules forbid. vault.federation.burst.ingress takes a host-SIGNED
//    ConnectDelivery, so editing its update bytes tests signature refusal,
//    not tombstone-removal quarantine.
//
// Planned journey once those doors land (kept here so the case can be written
// without re-deriving it; assertions cite the canon lines in the report):
//   a. Start vault A plus enrolled replica B; write one claim with a
//      generated sentinel value on A; sync; read it back on B via vault.get
//      and vault.recall (second doors).
//   b. P-DURA-006: hard-delete it on A (vault.delete, user_hard_delete); sync;
//      assert on B: vault.get is none, recall and scoped export carry neither
//      the id nor the sentinel. Then replay the retained pre-delete A->B
//      window update and sync B->A; assert the record is still absent on
//      both peers through the same read doors.
//   c. P-DURA-007: read vault.sync.quarantine.held_edits on the receiving
//      peer before/after delivering a tombstone-removal delta for that id
//      through the future ingress verb; assert exactly one new evidence row
//      with container "tombstones", that its fields are hashes/lengths only
//      (no sentinel anywhere in the row), and that the record stays absent.
//   d. Wrong actor: an agent without a delete Grant calling vault.delete is
//      refused with the standard envelope and the refusal receipt reads back
//      via vault.receipts; an agent whose delete Grant the owner revokes
//      mid-flow is refused at its next use; a non-owner reading
//      vault.sync.quarantine.held_edits is refused.
//   e. Restart both engines; repeat every absence read and the quarantine
//      read; the tombstone, the dt marker's effect and the x: evidence must
//      all survive.
// Do NOT assert the ARCH-0023b "open by design" items (new-id re-creation by
// a Byzantine peer; hard->soft downgrade via raw imports): canon explicitly
// leaves them open, so they are not part of P-DURA-006/007.
suite.todo(test, "MUSE-DURA-06", "waits on a public same-vault replica sync fixture and a grant-gated peer window-update ingress that can carry a tombstone-removal delta");

interface museDura07SlipRevoked { revoked: boolean }

type museDura07AuditRow = FacadeResult<"vault.authority.audit">["rows"][number];
type museDura07NoticeAct = FacadeResult<"vault.off_record.rooms.status">["notices"][number]["act"];

function museDura07PackHas(pack: FacadeResult<"vault.recall">, token: string): boolean {
  return pack.items.some((item) => item.value_text.includes(token)
    || (item.cited_messages ?? []).some((message) => message.value_text.includes(token)));
}

function museDura07RoomExportHas(
  copy: FacadeResult<"vault.off_record.rooms.export">, token: string,
): boolean {
  return copy.turns.some((turn) => turn.messages.some((message) => message.content.includes(token)));
}

function museDura07NoticeHas(
  view: FacadeResult<"vault.off_record.rooms.status">,
  act: museDura07NoticeAct,
  actorRef: string,
): boolean {
  return view.notices.some((notice) => notice.act === act && notice.by.includes(actorRef));
}

function museDura07Excludes(value: unknown, tokens: readonly string[]): boolean {
  const text = JSON.stringify(value) ?? "";
  return tokens.every((token) => !text.includes(token));
}

/** Reads the public whole-vault export ZIP in memory; it never opens a vault. */
function museDura07ArchiveText(encoded: string): string {
  const zip = Buffer.from(encoded, "base64");
  const earliest = Math.max(0, zip.length - 65_557);
  let end = zip.length - 22;
  for (; end >= earliest; end--) {
    if (zip.readUInt32LE(end) === 0x06054b50
      && end + 22 + zip.readUInt16LE(end + 20) === zip.length) break;
  }
  if (end < earliest) throw new Error("Public export is not a complete ZIP");
  expect(zip.readUInt16LE(end + 4)).toBe(0);
  expect(zip.readUInt16LE(end + 6)).toBe(0);
  const entries = zip.readUInt16LE(end + 10);
  expect(zip.readUInt16LE(end + 8)).toBe(entries);
  let cursor = zip.readUInt32LE(end + 16);
  const directoryEnd = cursor + zip.readUInt32LE(end + 12);
  let text = "";
  for (let index = 0; index < entries; index++) {
    expect(zip.readUInt32LE(cursor)).toBe(0x02014b50);
    expect(zip.readUInt16LE(cursor + 8) & 1).toBe(0);
    const method = zip.readUInt16LE(cursor + 10);
    const compressed = zip.readUInt32LE(cursor + 20);
    const length = zip.readUInt32LE(cursor + 24);
    const nameLength = zip.readUInt16LE(cursor + 28);
    const extraLength = zip.readUInt16LE(cursor + 30);
    const commentLength = zip.readUInt16LE(cursor + 32);
    const local = zip.readUInt32LE(cursor + 42);
    expect(zip.readUInt32LE(local)).toBe(0x04034b50);
    const start = local + 30 + zip.readUInt16LE(local + 26) + zip.readUInt16LE(local + 28);
    expect(start + compressed <= zip.length).toBe(true);
    if (method !== 0 && method !== 8) throw new Error("Unsupported public ZIP compression");
    const wire = zip.subarray(start, start + compressed);
    const bytes = method === 0 ? wire : inflateRawSync(wire);
    expect(bytes.length).toBe(length);
    text += bytes.toString("utf8");
    text += "\n";
    cursor += 46 + nameLength + extraLength + commentLength;
  }
  expect(cursor).toBe(directoryEnd);
  expect(directoryEnd).toBe(end);
  return text;
}

async function museDura07AuditRows(client: PublicHttpClient): Promise<museDura07AuditRow[]> {
  const rows: museDura07AuditRow[] = [];
  const cursors = new Set<string>();
  let after: string | undefined;
  for (;;) {
    const query: FacadeInput<"vault.authority.audit"> = {
      limit: 500, ...(after ? { after } : {}),
    };
    const page = await client.call("vault.authority.audit", query);
    rows.push(...page.rows);
    if (!page.next_after) return rows;
    cursors.add(page.next_after);
    after = page.next_after;
  }
}

async function museDura07Person(
  engine: EngineFixture, name: string, occurredAt: number,
): Promise<string> {
  const record = await engine.client.call("vault.structural.put", {
    kind: "PERSON", body: { name }, occurred_at: occurredAt,
  });
  return record.id_hex;
}

async function museDura07VaultRowsText(
  engine: EngineFixture, refs: readonly string[],
): Promise<string> {
  const rows: FacadeResult<"vault.get">[] = [];
  for (const ref of refs) rows.push(await engine.client.call("vault.get", { entity_ref: ref }));
  expect(rows.every((row) => row.value !== null)).toBe(true);
  return JSON.stringify(rows);
}

/*
 * MUSE-DURA-07 — P-DURA-024, P-DURA-027, P-DURA-028, P-DURA-029, P-DURA-030.
 * Doors: typed vault.off_record.* and vault.off_record.rooms.* calls, read back
 * through rooms.status, rooms.export, vault.get, vault.recall and vault.export;
 * the typed spellings of the register's /v1/core/off-record/* and owner close.
 * Unproved: an explicit close of a room stretch (no rooms.discard verb; the
 * solo discard and a restart stand in), the one-owner-plus-own-agents notice
 * exception, rollback of a save that fails mid-transaction, and revoking a
 * holder agent's vault write grant (only a slip revocation is driven).
 */
suite.test(test, "MUSE-DURA-07", "Unsaved off-record turns vanish at close or restart, a holder save lands every kept turn, whole-vault export skips the live room, copy notices name the actor, and a propose-only agent cannot save", async () => {
  const engine = await EngineFixture.start({ id: "MUSE-DURA-07", profile });
  try {
    const occurredAt = 1769947200;
    const ownerRef = engine.pairedActor.principalRef;
    const suffix = secretHex(6).split("")
      .map((digit) => String.fromCharCode(97 + Number.parseInt(digit, 16))).join("");
    const baseControl = `basecontrol${suffix}`;
    const keptAlpha = `keptalpha${suffix}`;
    const keptBeta = `keptbeta${suffix}`;
    const lateDelta = `latedelta${suffix}`;
    const vanishEpsilon = `vanishepsilon${suffix}`;
    redactor.add(baseControl, keptAlpha, keptBeta, lateDelta, vanishEpsilon);
    const roomSession = "muse-dura07-room";
    const soloSession = "muse-dura07-vanish";

    const museDura07BaseRecallHas = async (token: string): Promise<boolean> =>
      museDura07PackHas(await engine.client.call("vault.recall", {
        query: token, effort: "light", limit: 10,
      }), token);
    const museDura07AwaitBaseRecall = async (token: string, label: string): Promise<void> => {
      const pack = await awaitPublic(
        () => engine.client.call("vault.recall", { query: token, effort: "light", limit: 10 }),
        (value) => museDura07PackHas(value, token),
        { label, timeoutMs: 5000 },
      );
      expect(museDura07PackHas(pack, token)).toBe(true);
    };
    const museDura07WholeExportText = async (): Promise<string> => {
      const exported = await engine.client.call("vault.export", {
        format: "archive", include_secrets: false, delivery: "inline",
      });
      if (!("archive" in exported)) throw new Error("Whole-vault export was not inline");
      return museDura07ArchiveText(exported.archive);
    };

    // A second person in the room takes this case outside the no-notice room
    // of one owner plus the vault's own agents. The agent holds only a
    // propose slip: it may ask for a save, and it holds no write grant.
    const guestRef = await museDura07Person(engine, "Dura07 Guest Person", occurredAt);
    const guest = await engine.pairActor({
      principalRef: guestRef, actorClass: "human", scope: ["core:read", "core:write"],
    });
    const agentRef = await museDura07Person(engine, "Dura07 Suggesting Agent", occurredAt);
    const beforeAgentPair = await museDura07AuditRows(engine.client);
    const agent = await engine.pairActor({
      principalRef: agentRef, actorClass: "agent", scope: ["core:read", "core:propose"],
    });
    const afterAgentPair = await museDura07AuditRows(engine.client);
    const earlierHashes = new Set(beforeAgentPair.map((row) => row.entry_hash));
    const minted = afterAgentPair.filter((row) => !earlierHashes.has(row.entry_hash)
      && row.source_op === "slip_mint" && row.holder_ref === agentRef);
    expect(minted).toHaveLength(1);
    const agentSlipId = minted[0]?.subject_ref;
    if (!agentSlipId) throw new Error("Agent pairing left no minted slip in the audit");

    // On-record control in its own conversation, so the room's whole-talk
    // save is expected to land exactly the two off-record turns below.
    const baseConversation = await engine.client.call("vault.conversations.create", {
      body: {},
      occurred_start: occurredAt, occurred_end: occurredAt,
    });
    const baseWitness = await engine.client.call("vault.witness", {
      conversation_ref: baseConversation.id,
      occurred_at: occurredAt,
      messages: [{ author: "user", message_type: "text", is_visible: true, order: 0,
        content: `An ordinary on-record turn, ${baseControl}.` }],
    } satisfies FacadeInput<"vault.witness">);
    await engine.awaitReceipt(baseWitness.receipt_ref);

    const roomConversation = await engine.client.call("vault.conversations.create", {
      body: { members: [ownerRef, guest.principalRef, agent.principalRef] },
      occurred_start: occurredAt, occurred_end: occurredAt,
    });
    const room = roomConversation.id;
    const roomRequest: FacadeInput<"vault.off_record.rooms.status"> = {
      room, session_ref: roomSession,
    };
    const started = await engine.client.call("vault.off_record.rooms.start", {
      room, session_ref: roomSession, backend: "local",
    });
    expect(started.mode).toBe("off_record");

    const alphaReceipt = await engine.client.call("vault.off_record.rooms.witness", {
      room, session_ref: roomSession,
      turn: {
        conversation_ref: room, occurred_at: occurredAt,
        messages: [{ author: "user", message_type: "text", is_visible: true, order: 0,
          content: `A kept off-record turn, ${keptAlpha}.` }],
      },
    } satisfies FacadeInput<"vault.off_record.rooms.witness">);
    const betaReceipt = await guest.client.call("vault.off_record.rooms.witness", {
      room, session_ref: roomSession,
      turn: {
        conversation_ref: room, occurred_at: occurredAt,
        messages: [{ author: "user", message_type: "text", is_visible: true, order: 0,
          content: `Another kept off-record turn, ${keptBeta}.` }],
      },
    } satisfies FacadeInput<"vault.off_record.rooms.witness">);

    // The vault must not see the room before a save: base get and recall.
    for (const receipt of [alphaReceipt, betaReceipt]) {
      const row = await engine.client.call("vault.get", { entity_ref: receipt.turn_short_id });
      expect(row.value).toBeNull();
    }
    expect(await museDura07BaseRecallHas(keptAlpha)).toBe(false);
    expect(await museDura07BaseRecallHas(keptBeta)).toBe(false);

    // P-DURA-028: whole-vault export runs while the room is live, carries the
    // on-record control, and skips both unsaved room turns.
    const beforeSaveArchive = await museDura07WholeExportText();
    expect(beforeSaveArchive.includes(baseControl)).toBe(true);
    expect(beforeSaveArchive.includes(keptAlpha)).toBe(false);
    expect(beforeSaveArchive.includes(keptBeta)).toBe(false);

    // A write slip alone is not the vault's grant: the guest person, who
    // holds core:write but is no vault holder, cannot save either.
    const guestSave = await guest.client.raw(
      "POST", "/v1/core/facade/vault.off_record.rooms.save", roomRequest,
    );
    expect(guestSave.status).toBe(403);

    // P-DURA-030, first half: the propose-only agent cannot perform the save.
    const agentSave = await agent.client.raw(
      "POST", "/v1/core/facade/vault.off_record.rooms.save", roomRequest,
    );
    expect(agentSave.status).toBe(403);
    const afterRefusal = await guest.client.call("vault.off_record.rooms.status", roomRequest);
    expect(museDura07NoticeHas(afterRefusal, "saved_talk", guest.principalRef)).toBe(false);
    expect(museDura07NoticeHas(afterRefusal, "saved_talk", agent.principalRef)).toBe(false);
    expect(afterRefusal.waiting_suggestions).toHaveLength(0);
    expect(museDura07Excludes(afterRefusal, [keptAlpha, keptBeta])).toBe(true);
    expect(await museDura07BaseRecallHas(keptAlpha)).toBe(false);

    // P-DURA-030, second half: the same agent may suggest, and the suggestion
    // waits in the room without saving anything.
    await agent.client.call("vault.off_record.rooms.suggest_save", roomRequest);
    const afterSuggest = await guest.client.call("vault.off_record.rooms.status", roomRequest);
    expect(afterSuggest.waiting_suggestions
      .some((suggestion) => suggestion.by.includes(agent.principalRef))).toBe(true);
    expect(museDura07NoticeHas(afterSuggest, "save_suggested", agent.principalRef)).toBe(true);
    expect(await museDura07BaseRecallHas(keptBeta)).toBe(false);

    // P-DURA-029 for export: a person keeps a copy, and the room hears who.
    const guestCopy = await guest.client.call("vault.off_record.rooms.export", roomRequest);
    expect(museDura07RoomExportHas(guestCopy, keptAlpha)).toBe(true);
    expect(museDura07RoomExportHas(guestCopy, keptBeta)).toBe(true);
    const afterGuestExport = await engine.client.call("vault.off_record.rooms.status", roomRequest);
    expect(museDura07NoticeHas(afterGuestExport, "exported", guest.principalRef)).toBe(true);
    expect(museDura07Excludes(afterGuestExport.notices, [keptAlpha, keptBeta])).toBe(true);

    // P-DURA-027: the holder saves the whole talk; both kept turns land, and
    // the waiting suggestion is answered by that save.
    const saved = await engine.client.call("vault.off_record.rooms.save", roomRequest);
    expect(saved.saved).toHaveLength(2);
    const canonicalRefs = [...new Set(saved.saved
      .flatMap((turn) => turn.short_ids.map((pair) => pair.vault)))];
    expect(canonicalRefs.length).toBeGreaterThan(0);
    const savedText = await museDura07VaultRowsText(engine, canonicalRefs);
    expect(savedText.includes(keptAlpha)).toBe(true);
    expect(savedText.includes(keptBeta)).toBe(true);
    await museDura07AwaitBaseRecall(keptAlpha, "first saved turn in base recall");
    await museDura07AwaitBaseRecall(keptBeta, "second saved turn in base recall");
    const afterSave = await guest.client.call("vault.off_record.rooms.status", roomRequest);
    expect(museDura07NoticeHas(afterSave, "saved_talk", ownerRef)).toBe(true);
    expect(museDura07Excludes(afterSave.notices, [keptAlpha, keptBeta])).toBe(true);

    // One more room turn stays unsaved; a guest copy proves the room held it
    // before the restart below proves the vault never kept it.
    await engine.client.call("vault.off_record.rooms.witness", {
      room, session_ref: roomSession,
      turn: {
        conversation_ref: room, occurred_at: occurredAt,
        messages: [{ author: "user", message_type: "text", is_visible: true, order: 0,
          content: `A later turn nobody saves, ${lateDelta}.` }],
      },
    } satisfies FacadeInput<"vault.off_record.rooms.witness">);
    const lateCopy = await guest.client.call("vault.off_record.rooms.export", roomRequest);
    expect(museDura07RoomExportHas(lateCopy, lateDelta)).toBe(true);
    expect(await museDura07BaseRecallHas(lateDelta)).toBe(false);

    // P-DURA-024: an owner's solo session holds a turn in-session, the base
    // never sees it, and closing the session drops it for good.
    const soloStarted = await engine.client.call("vault.off_record.start", {
      session_ref: soloSession, mode: "off_record", backend: "local",
    });
    expect(soloStarted.mode).toBe("off_record");
    const vanishReceipt = await engine.client.call("vault.off_record.witness", {
      session_ref: soloSession,
      turn: {
        conversation_ref: baseConversation.id, occurred_at: occurredAt,
        messages: [{ author: "user", message_type: "text", is_visible: true, order: 0,
          content: `A turn meant to vanish, ${vanishEpsilon}.` }],
      },
    } satisfies FacadeInput<"vault.off_record.witness">);
    const soloPack = await awaitPublic(
      () => engine.client.call("vault.off_record.recall", {
        session_ref: soloSession, query: vanishEpsilon, limit: 10,
      }),
      (value) => museDura07PackHas(value, vanishEpsilon),
      { label: "unsaved turn visible inside its own session", timeoutMs: 5000 },
    );
    expect(museDura07PackHas(soloPack, vanishEpsilon)).toBe(true);
    expect(await museDura07BaseRecallHas(vanishEpsilon)).toBe(false);
    const closed = await engine.client.call("vault.off_record.discard", {
      session_ref: soloSession,
    });
    expect(closed.turns_dropped).toBeGreaterThanOrEqual(1);
    expect(closed.promoted_turns_kept).toBe(0);
    const soloAfterClose = await engine.client.raw(
      "POST", "/v1/core/facade/vault.off_record.status", { session_ref: soloSession },
    );
    expect(soloAfterClose.status).toBe(404);
    const vanishRow = await engine.client.call("vault.get", {
      entity_ref: vanishReceipt.turn_short_id,
    });
    expect(vanishRow.value).toBeNull();

    // Authority is rechecked live: once the owner revokes the agent's slip,
    // its next save attempt is refused as unauthorised and saves nothing.
    const revoked = await engine.client.request<museDura07SlipRevoked>(
      "POST", "/v1/core/slips/revoke",
      { slip_id: Array.from(Buffer.from(agentSlipId, "hex")) },
    );
    expect(revoked.status).toBe(200);
    expect(revoked.body.revoked).toBe(true);
    const auditAfterRevoke = await museDura07AuditRows(engine.client);
    const agentAfterRevoke = await agent.client.raw(
      "POST", "/v1/core/facade/vault.off_record.rooms.save", roomRequest,
    );
    expect(agentAfterRevoke.status).toBe(401);
    const afterRevoke = await guest.client.call("vault.off_record.rooms.status", roomRequest);
    expect(afterRevoke.waiting_suggestions).toHaveLength(0);
    expect(museDura07NoticeHas(afterRevoke, "saved_talk", agent.principalRef)).toBe(false);
    expect(await museDura07BaseRecallHas(lateDelta)).toBe(false);

    // Restart: saved turns and the on-record control survive; every unsaved
    // turn and both live stretches are gone.
    await engine.restart();
    await museDura07AwaitBaseRecall(keptAlpha, "first saved turn after restart");
    await museDura07AwaitBaseRecall(keptBeta, "second saved turn after restart");
    const savedTextAfterRestart = await museDura07VaultRowsText(engine, canonicalRefs);
    expect(savedTextAfterRestart.includes(keptAlpha)).toBe(true);
    expect(savedTextAfterRestart.includes(keptBeta)).toBe(true);
    expect(await museDura07BaseRecallHas(vanishEpsilon)).toBe(false);
    expect(await museDura07BaseRecallHas(lateDelta)).toBe(false);
    const afterRestartArchive = await museDura07WholeExportText();
    expect(afterRestartArchive.includes(keptAlpha)).toBe(true);
    expect(afterRestartArchive.includes(keptBeta)).toBe(true);
    expect(afterRestartArchive.includes(vanishEpsilon)).toBe(false);
    expect(afterRestartArchive.includes(lateDelta)).toBe(false);
    const roomAfterRestart = await guest.client.raw(
      "POST", "/v1/core/facade/vault.off_record.rooms.status", roomRequest,
    );
    expect(roomAfterRestart.status).toBe(404);
    const soloAfterRestart = await engine.client.raw(
      "POST", "/v1/core/facade/vault.off_record.status", { session_ref: soloSession },
    );
    expect(soloAfterRestart.status).toBe(404);
  } finally {
    await engine.close();
  }
});

/*
 * MUSE-DURA-08 — P-DURA-012 and P-DURA-023 (PARTIAL).
 *
 * P-DURA-012: in a multi-Owner shared vault, an erase waits for the Owner
 * veto window unless it is a legal erasure request. This case proves the
 * ordinary-erase waiting half: the same erase door lands at once while the
 * vault has one Owner, then, after a second Owner is added through the
 * shared doors, it starts an act, tells the other Owner, cannot be executed
 * early, and an Owner objection is recorded while the record stays readable.
 * The legal-erasure bypass half is not asserted: the typed erase confirm
 * input carries no legal-erasure/GDPR reason, and `vault.delete` with
 * `gdpr_delete` is a delete (deleting records never waits), not the
 * backup-clearing erase these promises name. Completion after the shipped
 * seven-day window is also not asserted; maturing it inside the 30 s flow
 * would need a clock change or a change to the wait under test.
 *
 * P-DURA-023: a legal hold preserves only the ordered scope in a separate
 * sealed store while vault erase remains available. This case proves the
 * scope and vault sides through public doors: the hold names exactly one
 * record, a later record does not join it, the ordinary record erase (not
 * lift-and-erase) still erases the held record from the vault, and the held
 * value is then absent from claims, recall and export while the hold row
 * and its log stay. The sealed copy itself is not asserted: no typed door
 * returns its fingerprint, contents, production or access log, and the
 * place door found is the owner customer-hold door, not a host-order door.
 *
 * Doors: vault.claims.upsert/list, vault.get, vault.recall, vault.export,
 * vault.legal_holds.place/list/log, vault.records.erase_preview,
 * vault.records.erase_confirm, vault.records.erase_sweep,
 * vault.authority.audit, vault.shared.propose_add_owner,
 * vault.shared.execute, vault.shared.receipt, vault.members.projection,
 * vault.shared.policy.get, vault.shared.started, vault.shared.matured,
 * vault.shared.outcomes, vault.shared.object, plus raw wrong-actor calls to
 * the same facade paths and one engine.restart().
 */

const museDura08OccurredAt = 1769947200;
type museDura08EntityView = NonNullable<FacadeResult<"vault.get">["value"]>;
type museDura08AuditRow = FacadeResult<"vault.authority.audit">["rows"][number];
type museDura08LegalHoldEvent = FacadeResult<"vault.legal_holds.log">[number];
interface museDura08ClaimRecord { id: string; receipt_ref: string }
interface museDura08ErrorEnvelope { error?: { code?: unknown; message?: unknown } }

function museDura08Sentinel(label: string): string {
  const value = `muse-dura08-${label}-${secretHex(8)}`;
  redactor.add(value);
  return value;
}

async function museDura08Entity(client: PublicHttpClient, entity_ref: string): Promise<museDura08EntityView> {
  const result = await client.call("vault.get", { entity_ref });
  if (!result.value) throw new Error(`Public entity missing: ${entity_ref}`);
  return result.value;
}

async function museDura08WitnessTurnId(engine: EngineFixture, conversation_ref: string, content: string): Promise<string> {
  const receipt = await engine.client.call("vault.witness", {
    conversation_ref, occurred_at: museDura08OccurredAt,
    messages: [{ author: "user", message_type: "text", content, is_visible: true, order: 0 }],
  });
  await engine.awaitReceipt(receipt.receipt_ref);
  return (await museDura08Entity(engine.client, receipt.turn_short_id)).id_hex;
}

async function museDura08WriteClaim(
  engine: EngineFixture, scope: Facade.ClaimScope, subject_ref: string, predicate: string, value: string,
): Promise<museDura08ClaimRecord> {
  const receipt = await engine.client.call("vault.claims.upsert", {
    predicate, subject_ref, value, confidence: 1, source: "user_stated", scope,
    occurred_at: museDura08OccurredAt, learned_at: museDura08OccurredAt,
  });
  await engine.awaitReceipt(receipt.receipt_ref);
  const id = (await museDura08Entity(engine.client, receipt.claim_short_id)).id_hex;
  return { id, receipt_ref: receipt.receipt_ref };
}

async function museDura08ClaimValues(
  client: PublicHttpClient, subject_ref: string, predicate: string, id: string,
): Promise<unknown[]> {
  const rows = (await client.call("vault.claims.list", { subject_ref, predicate, limit: 100 })).value;
  return rows.filter(row => row.claim_ref === id).map(row => row.value);
}

async function museDura08RecallHas(
  client: PublicHttpClient, subject_ref: string, predicate: string, sentinel: string,
): Promise<boolean> {
  const pack = await client.call("vault.recall", {
    query: sentinel, effort: "light", limit: 10, token_budget: 8192, format: "md",
    scope: { person_ref: subject_ref, kinds: ["semantic"], worlds: { kind: "all" } },
  });
  return pack.items.some(item => item.predicate === predicate && item.value_text.includes(sentinel));
}

function museDura08ZipText(encoded: string): string {
  const zip = Buffer.from(encoded, "base64");
  let end = zip.length - 22;
  for (; end >= Math.max(0, zip.length - 65_557); end--) {
    if (zip.readUInt32LE(end) === 0x06054b50
      && end + 22 + zip.readUInt16LE(end + 20) === zip.length) break;
  }
  if (end < 0 || zip.readUInt32LE(end) !== 0x06054b50) throw new Error("Public export is not a complete ZIP");
  const entries = zip.readUInt16LE(end + 10);
  let cursor = zip.readUInt32LE(end + 16);
  const texts: string[] = [];
  for (let index = 0; index < entries; index++) {
    if (zip.readUInt32LE(cursor) !== 0x02014b50) throw new Error("Public export ZIP directory is malformed");
    const method = zip.readUInt16LE(cursor + 10);
    const compressed = zip.readUInt32LE(cursor + 20);
    const length = zip.readUInt32LE(cursor + 24);
    const nameLength = zip.readUInt16LE(cursor + 28);
    const extraLength = zip.readUInt16LE(cursor + 30);
    const commentLength = zip.readUInt16LE(cursor + 32);
    const local = zip.readUInt32LE(cursor + 42);
    if (zip.readUInt32LE(local) !== 0x04034b50) throw new Error("Public export ZIP member is malformed");
    const start = local + 30 + zip.readUInt16LE(local + 26) + zip.readUInt16LE(local + 28);
    if (start + compressed > zip.length) throw new Error("Public export ZIP member overruns the archive");
    const wire = zip.subarray(start, start + compressed);
    if (method !== 0 && method !== 8) throw new Error("Unsupported public ZIP compression");
    const bytes = method === 0 ? wire : inflateRawSync(wire);
    if (bytes.length !== length) throw new Error("Public export ZIP member length mismatch");
    texts.push(bytes.toString("utf8"));
    cursor += 46 + nameLength + extraLength + commentLength;
  }
  return texts.join("\n");
}

async function museDura08ExportText(client: PublicHttpClient): Promise<string> {
  const exported = await client.call("vault.export", {
    format: "archive", include_secrets: false, delivery: "inline",
  });
  if (!("archive" in exported)) throw new Error("Unexpected export transfer for inline request");
  return museDura08ZipText(exported.archive);
}

function museDura08TargetRecords(targets: readonly Facade.LegalHoldTarget[]): string[] {
  return targets.flatMap(target => "record" in target ? [target.record] : []);
}

function museDura08DeleteRefusedCount(events: readonly museDura08LegalHoldEvent[], holdId: string, record: string): number {
  return events.filter(event => event.hold_id === holdId
    && event.event === "delete_refused"
    && event.actor_kind === "agent"
    && museDura08TargetRecords(event.targets).includes(record)).length;
}

function museDura08ExpectErrorEnvelope(body: museDura08ErrorEnvelope): void {
  expect(typeof body.error?.code).toBe("string");
  expect(String(body.error?.code).length).toBeGreaterThan(0);
  expect(typeof body.error?.message).toBe("string");
  expect(String(body.error?.message).length).toBeGreaterThan(0);
}

function museDura08EraseOutcomeValue(value: FacadeResult<"vault.records.erase_confirm">): Facade.RecordEraseOutcome {
  if (!("first" in value)) throw new Error("Record erase did not return its typed outcome");
  return value;
}

async function museDura08EraseRecord(client: PublicHttpClient, record: string): Promise<Facade.RecordEraseOutcome> {
  const preview = await client.call("vault.records.erase_preview", { record });
  expect(preview.preview_digest.length).toBeGreaterThan(0);
  return museDura08EraseOutcomeValue(await client.call("vault.records.erase_confirm", {
    record, preview_digest: preview.preview_digest,
  }));
}

async function museDura08AuditRows(client: PublicHttpClient): Promise<museDura08AuditRow[]> {
  const rows: museDura08AuditRow[] = [];
  let after: string | undefined;
  const cursors = new Set<string>();
  for (;;) {
    const query: FacadeInput<"vault.authority.audit"> = { limit: 500, ...(after ? { after } : {}) };
    const page = await client.call("vault.authority.audit", query);
    rows.push(...page.rows);
    if (!page.next_after) return rows;
    cursors.add(page.next_after);
    after = page.next_after;
  }
}

async function museDura08VaultId(client: PublicHttpClient, ownerRef: string): Promise<string> {
  const rows = await museDura08AuditRows(client);
  const mint = rows.find(row => row.source_op === "slip_mint"
    && row.holder_ref === ownerRef && typeof row.vault_ref === "string");
  if (!mint || typeof mint.vault_ref !== "string") throw new Error("Minted owner slip has no vault reference");
  return mint.vault_ref;
}

function museDura08SharedExecutedValue(value: FacadeResult<"vault.shared.execute">): Facade.SharedActExecuted {
  if (!("receipt" in value)) throw new Error("Shared act execution did not return its receipt");
  return value;
}

async function museDura08ErasePolicy(client: PublicHttpClient, vault_id: string): Promise<Facade.SharedActPolicy> {
  const view = await client.call("vault.shared.policy.get", { vault_id });
  const entry = Object.entries(view.effective).find(([name]) => name.toLowerCase().includes("erase"));
  if (!entry) throw new Error("Shared-act policy has no erase row");
  return entry[1];
}

suite.test(test, "MUSE-DURA-08", "In a shared vault an ordinary record erase waits for the Owner veto window, and a legal hold keeps only its target while vault erase lands", async () => {
  const engine = await EngineFixture.start({ id: "MUSE-DURA-08", profile });
  try {
    const ownerRef = engine.pairedActor.principalRef;
    const scope = await ownerBaseClaimScope(engine.client, ownerRef);
    const conversation = await engine.client.call("vault.conversations.create", {
      body: {}, occurred_start: museDura08OccurredAt, occurred_end: museDura08OccurredAt,
      learned_at: museDura08OccurredAt,
    });

    const heldPredicate = "muse_dura08.held_marker";
    const outsidePredicate = "muse_dura08.outside_marker";
    const vetoPredicate = "muse_dura08.veto_marker";
    const heldSentinel = museDura08Sentinel("held");
    const outsideSentinel = museDura08Sentinel("outside");
    const vetoSentinel = museDura08Sentinel("veto");

    // P-DURA-023, vault side first, while this is still a one-Owner vault:
    // a personal-vault erase lands at once, hold or no hold.
    const held = await museDura08WriteClaim(engine, scope, ownerRef, heldPredicate, heldSentinel);
    expect(await museDura08ClaimValues(engine.client, ownerRef, heldPredicate, held.id)).toEqual([heldSentinel]);
    expect(await museDura08RecallHas(engine.client, ownerRef, heldPredicate, heldSentinel)).toBe(true);

    const agentDefRef = secretHex(16);
    redactor.add(agentDefRef);
    const agentName = museDura08Sentinel("agent");
    const agentCreated = await engine.client.call("vault.agents.create", {
      agent_def_ref: agentDefRef,
      definition: {
        agent_id: agentName, display_name: agentName,
        desc: "Generated MUSE-DURA-08 wrong-actor agent", version: "1",
      },
    });
    expect(agentCreated.agent_def_ref).toBe(agentDefRef);
    const agent = await engine.pairActor({
      principalRef: agentDefRef, actorClass: "agent", scope: ["core:read", "core:write"],
    });
    const agentSelf = await agent.client.call("self.actor", {});
    expect(agentSelf.actor_ref).toBe(agentDefRef);
    expect(agentSelf.actor_class).toBe("agent");

    const matterRef = museDura08Sentinel("matter");
    const hold = await engine.client.call("vault.legal_holds.place", {
      targets: [{ record: held.id }], matter_ref: matterRef,
    });
    expect(hold.targets).toHaveLength(1);
    expect(museDura08TargetRecords(hold.targets)).toEqual([held.id]);

    // A record written after the hold does not join its scope.
    const outside = await museDura08WriteClaim(engine, scope, ownerRef, outsidePredicate, outsideSentinel);
    const listedAfterOutside = await engine.client.call("vault.legal_holds.list", {});
    const listedHold = listedAfterOutside.find(row => row.hold_id === hold.hold_id);
    if (!listedHold) throw new Error("Placed legal hold is absent from the owner list");
    expect(listedHold.targets).toHaveLength(1);
    expect(museDura08TargetRecords(listedHold.targets)).toEqual([held.id]);
    expect(listedAfterOutside.some(row => museDura08TargetRecords(row.targets).includes(outside.id))).toBe(false);

    const logBeforeRefusal = await engine.client.call("vault.legal_holds.log", {});
    const placedEvent = logBeforeRefusal.find(event => event.hold_id === hold.hold_id && event.event === "placed");
    if (!placedEvent) throw new Error("Legal hold log has no placed event for the hold");
    expect(museDura08TargetRecords(placedEvent.targets)).toEqual([held.id]);

    const exportBeforeErase = await museDura08ExportText(engine.client);
    expect(exportBeforeErase.includes(heldSentinel)).toBe(true);
    expect(exportBeforeErase.includes(outsideSentinel)).toBe(true);

    // Wrong actor kind: no Grant names erase, so a write-scoped agent is
    // refused at both the owner-checked preview and the confirm, the record
    // stays, and the hold log records the refused delete.
    const refusalsBefore = museDura08DeleteRefusedCount(logBeforeRefusal, hold.hold_id, held.id);
    const agentPreviewRefused = await agent.client.raw<museDura08ErrorEnvelope>(
      "POST", "/v1/core/facade/vault.records.erase_preview", { record: held.id },
    );
    expect(agentPreviewRefused.status).toBe(403);
    museDura08ExpectErrorEnvelope(agentPreviewRefused.body);
    const ownerPreview = await engine.client.call("vault.records.erase_preview", { record: held.id });
    const agentConfirmRefused = await agent.client.raw<museDura08ErrorEnvelope>(
      "POST", "/v1/core/facade/vault.records.erase_confirm",
      { record: held.id, preview_digest: ownerPreview.preview_digest },
    );
    expect(agentConfirmRefused.status).toBe(403);
    museDura08ExpectErrorEnvelope(agentConfirmRefused.body);
    expect(await museDura08ClaimValues(engine.client, ownerRef, heldPredicate, held.id)).toEqual([heldSentinel]);
    const logAfterRefusal = await engine.client.call("vault.legal_holds.log", {});
    expect(museDura08DeleteRefusedCount(logAfterRefusal, hold.hold_id, held.id)).toBeGreaterThan(refusalsBefore);

    // The Owner's ordinary record erase remains available on the held
    // record. This deliberately does not use lift-and-erase.
    const heldOutcome = await museDura08EraseRecord(engine.client, held.id);
    expect(heldOutcome.first.existed).toBe(true);
    expect(heldOutcome.first_act ?? null).toBeNull();
    if (!heldOutcome.first.receipt_ref) throw new Error("Personal-vault erase returned no deletion receipt");
    const sweep = await engine.client.call("vault.records.erase_sweep", {
      receipt_ref: heldOutcome.first.receipt_ref,
    });
    if (!sweep) throw new Error("Erase sweep read returned nothing for the deletion receipt");
    expect(sweep.receipt_ref).toBe(heldOutcome.first.receipt_ref);

    expect(await museDura08ClaimValues(engine.client, ownerRef, heldPredicate, held.id)).toEqual([]);
    expect(await museDura08RecallHas(engine.client, ownerRef, heldPredicate, heldSentinel)).toBe(false);
    const exportAfterErase = await museDura08ExportText(engine.client);
    expect(exportAfterErase.includes(heldSentinel)).toBe(false);
    expect(exportAfterErase.includes(outsideSentinel)).toBe(true);
    expect(await museDura08ClaimValues(engine.client, ownerRef, outsidePredicate, outside.id)).toEqual([outsideSentinel]);

    // The hold row keeps exactly its target after the vault erase, and its
    // log records the erase confirmation without carrying the erased value.
    const listedAfterErase = await engine.client.call("vault.legal_holds.list", {});
    const survivingHold = listedAfterErase.find(row => row.hold_id === hold.hold_id);
    if (!survivingHold) throw new Error("Legal hold vanished when the vault record was erased");
    expect(survivingHold.targets).toHaveLength(1);
    expect(museDura08TargetRecords(survivingHold.targets)).toEqual([held.id]);
    const logAfterErase = await engine.client.call("vault.legal_holds.log", {});
    expect(logAfterErase.some(event => event.hold_id === hold.hold_id && event.event === "erase_confirmed")).toBe(true);

    // P-DURA-012: add a second Owner through the public shared doors.
    // Owner changes are instant by default, so the add act executes now.
    const secondName = museDura08Sentinel("second-owner");
    const evidence = await museDura08WitnessTurnId(engine, conversation.id, `This distinct person is ${secondName}.`);
    const secondCreated = await engine.client.call("vault.people.create", {
      identity: { name: secondName }, identity_evidence_refs: [evidence], occurred_at: museDura08OccurredAt,
    });
    const secondId = secondCreated.person.id_hex;
    expect(secondId).not.toBe(ownerRef);
    expect((await museDura08Entity(engine.client, secondCreated.person.entity_ref)).kind).toBe("PERSON");

    const vaultId = await museDura08VaultId(engine.client, ownerRef);
    const addAct = await engine.client.call("vault.shared.propose_add_owner", {
      vault_id: vaultId, owner: secondId,
    });
    expect(addAct.vault_id).toBe(vaultId);
    const added = museDura08SharedExecutedValue(await engine.client.call("vault.shared.execute", {
      act_id: addAct.id,
    }));
    expect(added.receipt.vault_id).toBe(vaultId);
    const addedChange = added.receipt.change;
    if (!("owner_added" in addedChange)) throw new Error("Add-owner act executed a different change");
    expect(addedChange.owner_added.owner).toBe(secondId);
    const addedReceipt = await engine.client.call("vault.shared.receipt", { receipt_id: added.receipt.id });
    const addedReceiptChange = addedReceipt.change;
    if (!("owner_added" in addedReceiptChange)) throw new Error("Add-owner receipt read back a different change");
    expect(addedReceiptChange.owner_added.owner).toBe(secondId);
    const projection = await engine.client.call("vault.members.projection", {
      vault_id: vaultId, member: secondId,
    });
    expect(projection.member_ref).toBe(secondId);
    expect(projection.grants.some(grant => grant.role === "owner" && grant.active)).toBe(true);

    const secondOwner = await engine.pairActor({
      principalRef: secondId, actorClass: "human", scope: ["core:read", "core:write"],
    });
    const secondSelf = await secondOwner.client.call("self.actor", {});
    expect(secondSelf.actor_ref).toBe(secondId);
    expect(secondSelf.actor_class).toBe("human");
    // Positive control: the new Owner reads a surviving record in this
    // vault through the same door that shows the erased record is gone.
    expect(await museDura08ClaimValues(secondOwner.client, ownerRef, outsidePredicate, outside.id)).toEqual([outsideSentinel]);
    expect(await museDura08ClaimValues(secondOwner.client, ownerRef, heldPredicate, held.id)).toEqual([]);

    const erasePolicy = await museDura08ErasePolicy(engine.client, vaultId);
    expect(erasePolicy.objector_roles).toContain("owner");
    expect(erasePolicy.initiator_roles).toContain("owner");

    const veto = await museDura08WriteClaim(engine, scope, ownerRef, vetoPredicate, vetoSentinel);
    expect(await museDura08ClaimValues(engine.client, ownerRef, vetoPredicate, veto.id)).toEqual([vetoSentinel]);

    const vetoOutcome = await museDura08EraseRecord(engine.client, veto.id);
    expect(vetoOutcome.first.existed).toBe(true);
    expect(vetoOutcome.first.state).toBe("completion_pending");
    if (!vetoOutcome.first_act) throw new Error("Shared-vault erase started no veto act");
    const vetoActId = vetoOutcome.first_act;

    // The erase waits: the record is still readable and findable.
    expect(await museDura08ClaimValues(engine.client, ownerRef, vetoPredicate, veto.id)).toEqual([vetoSentinel]);
    expect(await museDura08RecallHas(engine.client, ownerRef, vetoPredicate, vetoSentinel)).toBe(true);

    // Every other Owner is told at once, through that Owner's own door.
    const started = await secondOwner.client.call("vault.shared.started", { vault_id: vaultId });
    const startedRow = started.find(row => row.act_id === vetoActId);
    if (!startedRow) throw new Error("Second Owner was not told of the erase act");
    expect(startedRow.vault_id).toBe(vaultId);
    expect(startedRow.recipient).toBe(secondId);
    const matured = await secondOwner.client.call("vault.shared.matured", { vault_id: vaultId });
    expect(matured.some(row => row.act_id === vetoActId)).toBe(false);

    // It cannot be executed inside its window, and no outcome is recorded.
    const earlyExecute = await engine.client.raw<museDura08ErrorEnvelope>(
      "POST", "/v1/core/facade/vault.shared.execute", { act_id: vetoActId },
    );
    expect(earlyExecute.status).toBeGreaterThanOrEqual(400);
    museDura08ExpectErrorEnvelope(earlyExecute.body);
    const outcomes = await engine.client.call("vault.shared.outcomes", { vault_id: vaultId });
    expect(outcomes.some(row => row.act_id === vetoActId)).toBe(false);
    expect(await museDura08ClaimValues(engine.client, ownerRef, vetoPredicate, veto.id)).toEqual([vetoSentinel]);

    // An Owner objection inside the window is recorded on the act.
    const objected = await secondOwner.client.call("vault.shared.object", { act_id: vetoActId });
    expect(objected.id).toBe(vetoActId);
    expect(objected.starter).toBe(ownerRef);
    expect(objected.deadline).toBe(startedRow.deadline);
    expect(objected.completed).toBe(false);
    expect(objected.objections).toContain(secondId);
    expect(await museDura08ClaimValues(engine.client, ownerRef, vetoPredicate, veto.id)).toEqual([vetoSentinel]);

    await engine.artifacts.json("muse-dura08-before-restart.json", {
      held: held.id, outside: outside.id, veto: veto.id, hold: hold.hold_id,
      vaultId, vetoActId, agentPreviewStatus: agentPreviewRefused.status,
      agentConfirmStatus: agentConfirmRefused.status, earlyExecuteStatus: earlyExecute.status,
    });

    await engine.restart();

    // After restart: the erased held record is still gone from claims,
    // recall and export; the out-of-scope record still survives; the
    // waiting erase still waits and its record is still there; the hold
    // and the seven-day erase policy are unchanged.
    expect(await museDura08ClaimValues(engine.client, ownerRef, heldPredicate, held.id)).toEqual([]);
    expect(await museDura08ClaimValues(engine.client, ownerRef, outsidePredicate, outside.id)).toEqual([outsideSentinel]);
    expect(await museDura08ClaimValues(engine.client, ownerRef, vetoPredicate, veto.id)).toEqual([vetoSentinel]);
    expect(await museDura08RecallHas(engine.client, ownerRef, heldPredicate, heldSentinel)).toBe(false);
    expect(await museDura08RecallHas(engine.client, ownerRef, vetoPredicate, vetoSentinel)).toBe(true);
    const exportAfterRestart = await museDura08ExportText(engine.client);
    expect(exportAfterRestart.includes(heldSentinel)).toBe(false);
    expect(exportAfterRestart.includes(outsideSentinel)).toBe(true);
    expect(exportAfterRestart.includes(vetoSentinel)).toBe(true);

    const listedAfterRestart = await engine.client.call("vault.legal_holds.list", {});
    const holdAfterRestart = listedAfterRestart.find(row => row.hold_id === hold.hold_id);
    if (!holdAfterRestart) throw new Error("Legal hold did not survive restart");
    expect(museDura08TargetRecords(holdAfterRestart.targets)).toEqual([held.id]);
    const startedAfterRestart = await secondOwner.client.call("vault.shared.started", { vault_id: vaultId });
    const startedRowAfterRestart = startedAfterRestart.find(row => row.act_id === vetoActId);
    if (!startedRowAfterRestart) throw new Error("Started erase notice did not survive restart");
    expect(startedRowAfterRestart.deadline).toBe(startedRow.deadline);
  } finally {
    await engine.close();
  }
});

// MUSE-DURA-09 - X-DURA-ARTIFACT-REPLICAS (MUST): a deleted artifact's version
// bytes leave every replica. P-DURA-006 (MUST): sync cannot resurrect a
// tombstoned record.
//
// Canon for the full journey (see MUSE-DURA-09.report.md for line cites):
// blob-artifact bytes go at zero references on every replica, the release
// running on remote tombstone replay, unless another live artifact holds the
// same bytes; a destructive delete writes the CRDT tombstone first so sync
// cannot resurrect it; materialization is refused when a tombstone or a
// permanent local dt: hard-delete marker stands, and replicated ingest also
// refuses a stale carrier under the artifact release fence.
//
// Doors that already exist and were type-checked by hand in the generated
// facade: vault.artifacts.put (BlobArtifactInput -> EntityRefReceipt),
// vault.artifacts.append (AppendBlobVersionRequest ->
// BlobVersionAppendOutcome), vault.artifacts.read (ReadBlobVersionRequest ->
// BlobContent | null), vault.artifacts.view (ArtifactRefRequest ->
// ArtifactView | null), vault.artifacts.export (ArtifactExportRequest ->
// ArtifactExportFile | null), vault.get (EntityRequest ->
// ScopedReadResult<EntityView | null>), vault.delete (SafeDeleteRequest ->
// DeleteReceipt, an owner verb only a verified human may call), and
// vault.receipts.get (CallReceiptRequest -> CallReceipt | null).
//
// What stays unproved, and why this is a TODO and not a passing subset:
// there is no public door or harness fixture for the core act - a second
// replica OF THIS VAULT. EngineFixture.peers are extra independent vaults
// with no sync authority installed. Federation is not a substitute: the
// owner's account and devices are not federation, a federated/guest copy
// lands foreign in another vault under its own refcount, and cross-vault
// erasure is an authenticated request, not a recall guarantee. Expecting a
// federation peer's retained copy to vanish on an origin delete would
// assert the opposite of canon. vault.mesh.dial closes without an
// application stream, and no typed enrol-a-second-device, sync/apply
// observation, offline/online control, or replica-local artifact read is
// bound in the harness; pairing alone yields a remote credential, not a
// local replica store the case can read while the origin is away.
//
// Future journey, once that fixture exists (design notes only; no invented
// verb is sent anywhere): on the origin the owner registers one blob
// artifact and lands two versions with distinct generated sentinels (each
// sentinel and its base64 to redactor.add before first use), plus one
// control artifact with different bytes; enrol the replica, sync, and read
// both versions back ON THE REPLICA with vault.artifacts.read/view/export
// so the replica provably holds the bytes (partial sync loads a full item
// only on first touch); take the replica offline; a paired agent without a
// delete Grant is refused vault.delete and the bytes still read back; the
// owner deletes with vault.delete {entity_ref, reason:"user_hard_delete"}
// and reads the delete receipt back; origin read/view/export/get all read
// the artifact and both versions as gone while the control stays; bring
// the stale replica back, sync both ways, and read both versions as gone
// on the replica and still gone on the origin; restart origin and replica,
// sync again, and read the same absence on both. Do not assert a content
// hash ban: the release fence lifts when a live artifact holds the same
// bytes again, and do not reuse those bytes in this case.
suite.todo(test, "MUSE-DURA-09", "waits on a public same-vault replica sync fixture (enrol a second device of this vault, drive and observe sync/apply, take it offline and back, and read artifact bytes locally on that replica)");
