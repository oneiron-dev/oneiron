import { afterAll, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import type { Facade, FacadeInput, FacadeResult, FacadeVerb } from "@oneiron/client";
import { EngineFixture } from "./support/engine.ts";
import { credentialParts, PublicHttpClient } from "./support/clients.ts";
import { loadFixtures, ownerBaseClaimScope } from "./support/fixtures.ts";
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
 * MEMORY-03, MEMORY-04 and MEMORY-06 retain their full journeys as TODOs.
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
    takes: { actor: string; markdown: string }[]; expected: { labels: string[] } };
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
  engine: EngineFixture; data: Data; refs: Map<string, string>; conversation: string;
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
async function setup(id: string): Promise<World> {
  const data = await (await loadFixtures()).readJson<Data>("memory-canonical-cases");
  if (data.fixture.projects.length) throw new BlockedDoor("waits on a deterministic house-dispatched project drafting fixture: project-question YES, dispatched vault.projects.propose, owner vault.projects.confirm; raw structural PROJECT is not a setup door");
  const engine = await EngineFixture.start({ id, profile });
  const occurred = 1769947200; // Public setup input, never an engine clock override.
  const conversation = await engine.client.call("vault.conversations.create", {
    body: {}, occurred_start: occurred, occurred_end: occurred, learned_at: occurred,
  });
  const base = await ownerBaseClaimScope(engine.client, engine.pairedActor.principalRef);
  const w: World = { engine, data, refs: new Map(), conversation: conversation.id,
    scope: base, occurred };
  w.refs.set("@base", base.world_id);
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
async function recalled(w: World, query: string, scope?: Facade.RecallScope) {
  return w.engine.client.call("vault.recall", {
    query, effort: "light", limit: 100, token_budget: 8192, format: "md",
    scope: scope ?? { person_ref: ref(w, "@person-a"), kinds: ["semantic"],
      worlds: { kind: "all" } },
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
suite.test(test, "MEMORY-01", "Claim lifecycle with historical truth should work", async () => {
  const w = await setup("MEMORY-01");
  try {
    const c = scenario(w, "MEMORY-01");
    await witnessed(w, "@name-statement", `The name is ${c.current.value.value}.`);
    await witnessed(w, "@name-correction", `The name is now ${c.alternative.value.value}.`);
    const original = await w.engine.client.call("vault.claims.upsert", claimInput(w, c.current));
    // The opener never settles: a paired agent opens the proposal so the
    // holder (owner) can settle it. An owner-opened proposal is unsettleable.
    const outsider = await agent(w, "@agent-a");
    const seeded = await outsider.client.call("vault.claims.seed", {
      claims: [claimInput(w, c.alternative)],
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
    // Current ordinary-owner supersession is upsert-driven. Reuse the
    // approved row's public id; no caller-set approval or run-id substitute.
    const supersession = await w.engine.client.call("vault.claims.upsert", claimInput(w, c.alternative, newId));
    expect((await entity(w.engine.client, supersession.claim_short_id)).id_hex).toBe(newId);
    expect(supersession.superseded_short_id).toBe(original.claim_short_id);
    // A replacement re-proposes: the superseding upsert lands proposed and
    // closes the original, so the holder settles the same proposal again.
    expect((await claim(w, newId)).approval).toBe("proposed");
    expect(values(await recalled(w, "Morgan name"), c.current.predicate)).toEqual([]);
    const review2 = await w.engine.client.call("vault.claims.review", { claim_ref: newId });
    expect(review2.proposal_ref).toBe(newId);
    const settled2 = await w.engine.client.call("vault.claims.settle", {
      claim_ref: newId, review_id: review2.review_id, decision: "approve",
    });
    expect(settled2.verdict).toBe("landed");
    expect(settled2.changes).toEqual([{ claim_ref: newId, verdict: "landed" }]);
    await w.engine.awaitReceipt(settled2.receipt_ref);
    expect((await claim(w, newId)).approval).toBe("approved");
    expect(values(await recalled(w, "Morgan name"), c.current.predicate))
      .toEqual(c.expected.recallAfterAuthorizedApprovalAndSupersession);
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
    for (const [row, evidence, actor] of [[old, ref(w, "@name-statement"), w.engine.pairedActor.principalRef],
      [current, ref(w, "@name-correction"), ref(w, "@agent-a")]] as const) {
      expect(row.valid_from).not.toBeNull(); expect(row.valid_to).not.toBeNull();
      expect(row.valid_to!).toBeGreaterThanOrEqual(row.valid_from!);
      expect(row.source).toBe("user_stated"); birth(row, actor, [evidence]);
    }
    const full = await timeline(w, newId);
    expect(full.records.map(row => row.id).sort()).toEqual([oldId, newId].sort());
    expect(full.records.find(row => row.id === oldId)?.state).toBe("superseded");
    const newer = full.records.find(row => row.id === newId)!;
    expect(newer.state).toBe("retracted"); expect(newer.supersedes).toContain(oldId);
    expect(full.records.find(row => row.id === oldId)?.superseded_by).toContain(newId);
    await w.engine.artifacts.json("lifecycle.json", { original, alternative, review, refusal: refused.body,
      settled, supersession, review2, settled2, retracted, history, timeline: full });
  } finally { await w.engine.close() }
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
    const scopedValues = async (person: string, project: string, query: string): Promise<string[]> =>
      values(await recalled(w, query, { worlds: { kind: "all" }, project_refs: [ref(w, project)],
        person_ref: ref(w, person), kinds: ["semantic"] }), "profile.name");
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
        recallANorth: await scopedValues("@person-a", "@project-north", "Morgan Vale"),
        recallBNorth: await scopedValues("@person-b", "@project-north", "not-a-number number kind"),
        recallASouth: await scopedValues("@person-a", "@project-south", "Morgan Vale"),
        recallBSouth: await scopedValues("@person-b", "@project-south", "not-a-number number kind"),
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
        person_ref: ref(w, "@person-a"), kinds: ["semantic"] } };
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
    try { await w.engine.close(); } catch (error) { cleanups.push(errorText(error)); }
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
suite.todo(test, "MEMORY-03",
  "waits on merged FIX 21842 production Observed/language producer and qualification of the whole original leased supersession fixture; spawn/agent-pair/leased-get/attach composition exists, not a new registration API");

/* MEMORY-04: ARCH-0032 writers, ARCH-0002 NOTE beside CLAIM, OF-330.
 * author_take NOW EXISTS as AuthorTakeRequest -> EntityRefReceipt, and real
 * AGENT_DEF principals can be created and paired without forging an author.
 * Keep the full journey: owner writes the neutral Morgan Vale claim; two
 * separately paired Reviewer North/South agents author opposite takes; recall
 * labels both asides; neutral value/source/evidence/confidence/clocks/history
 * stay unchanged; both notes link to their actual authors and neutral claim;
 * every link's provenance retains its author and original source revision.
 * Complete read binding is still missing: NeighborHit exposes only target,
 * kind, direction and weight. NoteReadView exposes text/frontier, EntityView
 * leaves body opaque and redacts binary values, and ExplainMemoryReply is
 * rank evidence, not edge provenance. No named typed edge-provenance read is
 * in this catalog. A NOTE's birth revision or retrieval frontier is NOT the
 * edge's source revision. Raw entity/export byte comparison would not prove
 * that link-level invariant, so do not arm an attribution-only partial test.
 */
suite.todo(test, "MEMORY-04",
  "waits on typed per-edge author/source-revision provenance read; author_take and real agent pairing already exist");

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
  } finally { await w.engine.close() }
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
suite.todo(test, "MEMORY-06",
  "waits on merged real oneiron.productivity hub pack and engine pin PRs supplying the exact HubImportRequest/pin/publisher; role/tree/check-in calls exist");

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
    const bMerged = await w.engine.client.call("vault.identity.resolve", { entity: ref(w, "@person-b") });
    expect(bMerged.state).toBe("merged"); expect(bMerged.heads).toEqual([ref(w, "@person-a")]);
    expect(bMerged.merged_into).toEqual([ref(w, "@person-a")]);
    expect((await entity(w.engine.client, ref(w, "@person-b"))).kind).toBe("PERSON");
    for (const role of c.split.heads) await person(w, role, role === "@head-north" ? "Morgan North head" : "Morgan South head");
    const splitSpec: FacadeInput<"vault.identity.split"> = {
      entity: ref(w, c.split.entity), heads: c.split.heads.map(role => ref(w, role)),
      reassignment_map: c.split.reassignment_map.map(item => ({
        item: { kind: "claim", claim: ref(w, item.evidence) }, target: { kind: "head", head: ref(w, item.head) },
      })),
      evidence: { refs: c.split.evidence.map(role => ref(w, role)), rationale: "North and South evidence identify separate people." },
    };
    const split = applied(await w.engine.client.call("vault.identity.split", splitSpec));
    const shell = await w.engine.client.call("vault.identity.resolve", { entity: ref(w, "@person-a") });
    const chain = await w.engine.client.call("vault.identity.resolve", { entity: ref(w, "@person-b") });
    const heads = c.split.heads.map(role => ref(w, role)).sort();
    expect(shell.state).toBe("split"); expect(shell.heads.sort()).toEqual(heads);
    expect(shell.split_into.sort()).toEqual(heads); expect(chain.heads.sort()).toEqual(heads);
    expect(shell.ambiguous_residue).toContain(ref(w, "@ambiguous-evidence"));
    for (const mapping of c.split.reassignment_map) {
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
  } finally { await w.engine.close() }
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
    const all = await recalled(w, "Morgan Vale Glass keeper Paper captain north south name", {
      worlds: { kind: "all" }, project_refs: w.data.fixture.projects.map(row => ref(w, row.ref)),
      person_ref: ref(w, "@person-a"), kinds: ["semantic"],
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
        project_refs: [ref(w, input.scopeProjectId)], kinds: ["semantic"], person_ref: ref(w, "@person-a"),
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
      limit: 100, token_budget: 8192, scope: { worlds: { kind: "all" }, kinds: ["semantic"] } };
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
      expect(pack.narrowing.actor_ceiling.deny_all).toBe(true);
      expect(pack.narrowing.applied.deny_all).toBe(true);
      expect(pack.narrowing.narrowed_axes.length).toBeGreaterThan(0);
      // An empty *requested* world set adds no narrowing; it cannot lift a
      // bottom credential to top. Same zero result and same applied ceiling.
      const emptyRequested = await client.call("vault.recall", { ...query,
        scope: { worlds: { kind: "worlds", world_refs: [], include_base: false }, kinds: ["semantic"] } });
      expect(emptyRequested.items).toEqual([]);
      expect(emptyRequested.narrowing.applied.deny_all).toBe(true);
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
  } finally { await w.engine.close() }
});
