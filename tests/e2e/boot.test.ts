import { afterAll, test } from "bun:test";
import { resolve } from "node:path";
import type { Facade, FacadeInput, FacadeResult } from "@oneiron/client";
import type { MemoryPack, WitnessReceipt } from "oneiron";
import { EngineFixture } from "./support/engine.ts";
import type { PairedActor } from "./support/engine.ts";
import { McpClient, PublicHttpClient } from "./support/clients.ts";
import type { JsonRpcReply, SdkDriverResult, SdkOperation, SdkTarget } from "./support/clients.ts";
import { loadFixtures, ownerBaseClaimScope, requireAsset } from "./support/fixtures.ts";
import { defineFile, expect, redactor, runProcess } from "./support/run.ts";
import { ScriptedProviders, openaiText } from "./support/providers.ts";

const profile = process.env.E2E_PROFILE === "real-small-model"
  ? "real-small-model" : "deterministic";
const suite = defineFile(import.meta, { profile, slots: 1 });
afterAll(suite.flush);

interface Journey {
  conversationId: string;
  turnId: string;
  messageId: string;
  claimId: string;
  marker: string;
  text: string;
  predicate: string;
  value: { seat: string; marker: string };
}
interface Corpus {
  occurredAt: number;
  restart: Journey;
  typescript: Journey;
  python: Journey;
  native: Journey;
  cli: Journey;
  mcp: Journey;
  execute: Journey;
  isolationA: Journey;
  isolationB: Journey;
  deniedMessageId: string;
  deniedTurnId: string;
  deniedText: string;
}
async function corpus(): Promise<Corpus> {
  return (await loadFixtures()).readJson<Corpus>("boot-journeys");
}
function witness(journey: Journey, at: number): FacadeInput<"vault.witness"> {
  return {
    conversation_ref: journey.conversationId, turn_ref: journey.turnId, occurred_at: at,
    messages: [{ id: journey.messageId, author: "user", message_type: "dialogue",
      content: journey.text, is_visible: true, order: 0 }],
  };
}
function sdkWitness(journey: Journey, at: number): SdkOperation {
  return { verb: "witness", input: {
    conversationRef: journey.conversationId, turnRef: journey.turnId, occurredAt: at,
    messages: [{ id: journey.messageId, author: "user", messageType: "dialogue",
      content: journey.text, isVisible: true, order: 0 }],
  } };
}
function sdkClaim(journey: Journey, at: number, scope: Facade.ClaimScope): SdkOperation {
  return { verb: "claimUpsert", input: {
    id: journey.claimId, subject_ref: journey.turnId, predicate: journey.predicate, scope,
    value: journey.value, confidence: 1, source: "user_stated", occurred_at: at, learned_at: at,
  } };
}
async function embeddedClaimScope(engine: EngineFixture, target: SdkTarget): Promise<Facade.ClaimScope> {
  const people = sdkValue<FacadeResult<"vault.people.list">>(await engine.sdk.run("napi",target,[{verb:"people",input:{}}]));
  const owner = people.people.find(person => person.kind === "human" && person.role === "owner");
  if (!owner) throw new Error("Embedded vault has no human owner PERSON");
  const facets = sdkValue<FacadeResult<"vault.neighbors">>(await engine.sdk.run("napi",target,[{
    verb:"neighbors",input:{entity_ref:owner.person,opts:{edge_kind:"has_facet",limit:100}},
  }]));
  const views = await engine.sdk.run("napi",target,facets.value.map(facet => ({
    verb:"get" as const,input:{entity_ref:facet.short_id},
  })));
  for (const index of facets.value.keys()) {
    const row = sdkValue<FacadeResult<"vault.get">>(views,index).value;
    const body = row?.body;
    if (row?.kind === "FACET" && body && typeof body === "object" && "kind" in body && body.kind === "substrate")
      return {world_id:"00000000000000000000000000000001",scope_facet_id:row.id_hex,
        scope_relationship_id:"all",scope_project_id:"00000000000000000000000000000002"};
  }
  throw new Error("Embedded owner has no readable substrate facet");
}
function sdkValue<T>(reply: SdkDriverResult, index = 0): T {
  expect(reply.process.exitCode).toBe(0);
  expect(reply.process.signal).toBeNull();
  const operation = reply.results[index];
  if (!operation) throw new Error("SDK returned no operation result");
  if (!operation.ok) {
    const error = operation.error as { code?: string };
    throw new Error(`SDK operation refused: ${error.code ?? "untyped error"}`);
  }
  return operation.value as T;
}
function sdkRefusal(reply: SdkDriverResult, code: string): void {
  expect(reply.results).toHaveLength(1);
  const operation = reply.results[0];
  if (!operation || operation.ok) throw new Error("Expected an SDK refusal");
  const error = operation.error as { code: string; message: string; suggestions: string[] };
  expect(error.code).toBe(code);
  expect(error.message.length).toBeGreaterThan(0);
  expect(error.suggestions.length).toBeGreaterThan(0);
}
function recalledTurn(pack: Facade.MemoryPack, receipt: Facade.WitnessReceipt, journey: Journey): void {
  const turn = pack.items.find(item => item.short_id === receipt.turn_short_id);
  expect(turn).toBeDefined();
  expect(turn!.value_text).toContain(journey.text);
  expect(turn!.cited_messages).toEqual(expect.arrayContaining([
    expect.objectContaining({ short_id: receipt.message_short_ids[0], value_text: journey.text }),
  ]));
}
function recalledClaim(pack: MemoryPack, receipt: Facade.CommitReceipt, journey: Journey): void {
  const claim = pack.items.find(item => item.shortId === receipt.claim_short_id);
  expect(claim).toBeDefined();
  expect(claim!.predicate).toBe(journey.predicate);
  expect(claim!.valueText).toContain(journey.value.seat);
  expect(claim!.valueText).toContain(journey.marker);
  expect(claim!.provenance.source).toBe("user_stated");
  expect(Array.isArray(claim!.provenance.sourceRevisionIds)).toBe(true);
  expect(Array.isArray(claim!.provenance.evidenceTurnIds)).toBe(true);
  expect(pack.narrowing.applied.denyAll).toBe(false);
}
function claimReceipt(rows: Facade.MemoryReceipt[], commit: Facade.CommitReceipt, principal?: string): Facade.MemoryReceipt {
  const row = rows.find(item => item.receipt_ref === commit.receipt_ref);
  expect(row).toBeDefined();
  expect(row!.outcome).toBe("allow");
  if (principal !== undefined) expect(row!.actor_ref).toBe(principal);
  return row!;
}

// The shared fixture pairs existing principals but does not expose token-agent orchestration.
// This helper uses the documented stopped-vault CLI; the server never shares its writer.
type AgentTier = "read-only" | "propose-only" | "full-access";
async function registerAgents(
  engine: EngineFixture,
  specs: readonly { name: string; tier: AgentTier }[],
): Promise<PairedActor[]> {
  await engine.client.call("vault.receipts", { limit: 1 });
  await engine.kill();
  const principals: string[] = [];
  for (const spec of specs) {
    const result = await engine.cli.run([
      "token", "agent", "--name", spec.name, "--tier", spec.tier,
      "--config", resolve(engine.root, "oneiron.toml"),
      "--out", resolve(engine.root, `${spec.name}.credential`),
    ], undefined, undefined, true);
    expect(result.exitCode).toBe(0);
    const minted = JSON.parse(result.stdout) as { principal_ref: string; actor_class: string };
    expect(minted.actor_class).toBe("agent");
    expect(minted.principal_ref).toMatch(/^[0-9a-f]{32}$/);
    principals.push(minted.principal_ref);
  }
  await engine.restart();
  const actors: PairedActor[] = [];
  for (const [index, spec] of specs.entries()) {
    const scope = spec.tier === "read-only" ? ["core:read"]
      : spec.tier === "propose-only" ? ["core:read", "core:propose"]
      : ["core:read", "core:propose", "core:write"];
    actors.push(await engine.pairActor({ principalRef: principals[index]!, actorClass: "agent", scope }));
  }
  return actors;
}

interface Tool {
  name: string;
  inputSchema: { properties: { schema_version: { const: string } } };
}
interface Tools { surfaceMode: string; tools: Tool[] }
interface McpActor { actor_ref: string; gate_actor_ref: string; actor_class: string; gate_actor_class: string }
interface McpMeta { surface_mode: string; ttlMs: number; cacheScope: string }
interface ToolResult<T> { isError: boolean; structuredContent: T }
interface VerbResult<T> { output: T; actor: McpActor; meta: McpMeta }
function toolArguments(tools: Tools, name: string, fields: Record<string, unknown>): Record<string, unknown> {
  const tool = tools.tools.find(item => item.name === name);
  if (!tool) throw new Error(`Required public MCP tool not registered: ${name}`);
  // The version is a transport binding from tools/list, not an expected outcome.
  return { schema_version: tool.inputSchema.properties.schema_version.const,
    consent: { policy_ref: "policy:boot-session", purpose: "boot public-client journey" }, ...fields };
}
async function mcpVerb<V extends "vault.recall" | "vault.claims.upsert">(
  client: McpClient, tools: Tools, verb: V, input: FacadeInput<V>,
): Promise<VerbResult<FacadeResult<V>>> {
  const reply = await client.callTool(verb, toolArguments(tools, verb, { arguments: { spec: input } })) as ToolResult<VerbResult<FacadeResult<V>>>;
  expect(reply.isError).toBe(false);
  expect(reply.structuredContent).toBeDefined();
  return reply.structuredContent;
}
function mcpRefusal(reply: JsonRpcReply<unknown>, kind: string): void {
  if (!("error" in reply)) throw new Error("Expected an MCP JSON-RPC refusal");
  const data = reply.error.data as { kind: string; error_code: string; recovery_suggestions: string[] };
  expect(data.kind).toBe(kind);
  expect(data.error_code).toBe(kind);
  expect(data.recovery_suggestions.length).toBeGreaterThan(0);
}

suite.test(test, "BOOT-01", "Model-free serve and restart should work", async () => {
  const data = await corpus();
  const journey = data.restart;
  const engine = await EngineFixture.start({ id: "BOOT-01", profile });
  await engine.requireHttpDoor("/api/health", "GET");
  const receipt = await engine.client.call("vault.witness", witness(journey, data.occurredAt));
  expect(receipt.receipt_ref).toStartWith("witness:");
  expect(receipt.message_short_ids).toHaveLength(1);
  const query: FacadeInput<"vault.recall"> = {
    query: journey.marker, effort: "light", limit: 10, as_of: data.occurredAt,
  };
  recalledTurn(await engine.client.call("vault.recall", query), receipt, journey);
  const before = await engine.client.call("vault.neighbors", {
    entity_ref: journey.turnId, opts: { limit: 10 },
  });
  expect(before.value.map(item => item.short_id)).toContain(receipt.message_short_ids[0]!);
  await engine.restart();
  recalledTurn(await engine.client.call("vault.recall", query), receipt, journey);
  const after = await engine.client.call("vault.neighbors", {
    entity_ref: journey.turnId, opts: { limit: 10 },
  });
  expect(after.value.map(item => item.short_id)).toContain(receipt.message_short_ids[0]!);
  const message = await engine.client.call("vault.get", { entity_ref: journey.messageId });
  expect(message.value?.id_hex).toBe(journey.messageId);
  expect(message.value?.body).toEqual(expect.objectContaining({ content: journey.text }));
});

suite.test(test, "BOOT-02", "TypeScript remote memory journey should work", async () => {
  const data = await corpus();
  const journey = data.typescript;
  const engine = await EngineFixture.start({ id: "BOOT-02", profile });
  const actor = await engine.pairActor({ principalRef: engine.pairedActor.principalRef,
    actorClass: "human", scope: ["core:read", "core:write"] });
  const target = { mode: "remote" as const, url: engine.url, credential: actor.credential };
  const scope = await ownerBaseClaimScope(engine.client,engine.pairedActor.principalRef);
  const result = await engine.sdk.run("typescript", target, [
    sdkWitness(journey, data.occurredAt), sdkClaim(journey, data.occurredAt, scope),
    { verb: "recall", query: journey.marker, options: { effort: "light", asOf: data.occurredAt } },
    { verb: "receipts", limit: 100 },
  ]);
  expect(result.results).toHaveLength(4);
  const witnessed = sdkValue<WitnessReceipt>(result, 0);
  const committed = sdkValue<Facade.CommitReceipt>(result, 1);
  expect(witnessed.receiptRef).toStartWith("witness:");
  expect(committed.approval).toBe("auto");
  recalledClaim(sdkValue<MemoryPack>(result, 2), committed, journey);
  expect(claimReceipt(sdkValue<Facade.VaultReceiptsPage>(result, 3).receipts, committed, actor.principalRef).actor_class).toBe("human");
  const saved = await actor.client.call("vault.claims.list", { subject_ref: journey.turnId, limit: 10 });
  expect(saved.value).toEqual(expect.arrayContaining([expect.objectContaining({
    claim_ref: journey.claimId, value: journey.value, source: "user_stated", approval: "auto",
  })]));
  const reader = await engine.pairActor({ principalRef: actor.principalRef, actorClass: "human", scope: ["core:read"] });
  sdkRefusal(await engine.sdk.run("typescript", {
    mode: "remote", url: engine.url, credential: reader.credential,
  }, [sdkClaim({ ...journey, claimId: data.deniedMessageId }, data.occurredAt, scope)]), "FORBIDDEN");
  expect((await engine.client.call("vault.get", { entity_ref: data.deniedMessageId })).value).toBeNull();
});

suite.test(test, "BOOT-03", "Python remote memory journey should work", async () => {
  const data = await corpus();
  const journey = data.python;
  const engine = await EngineFixture.start({ id: "BOOT-03", profile });
  const [actor] = await registerAgents(engine, [{ name: "boot-python", tier: "full-access" }]);
  expect(actor!.principalRef).not.toBe(engine.pairedActor.principalRef);
  const target = { mode: "remote" as const, url: engine.url, credential: actor!.credential };
  const result = await engine.sdk.run("python", target, [
    { verb: "witness", input: { conversation_ref: journey.conversationId, turn_ref: journey.turnId,
      occurred_at: data.occurredAt, messages: [{ id: journey.messageId, author: "user", message_type: "dialogue",
        content: journey.text, order: 0 }] } },
    { verb: "claimUpsert", input: { subject_ref: journey.turnId, predicate: journey.predicate,
      scope: await ownerBaseClaimScope(engine.client,engine.pairedActor.principalRef),
      value: journey.value, confidence: 1, source: "user_stated" } },
    { verb: "recall", query: journey.marker, options: { effort: "light", as_of: data.occurredAt } },
    { verb: "receipts", limit: 100 },
  ]);
  expect(result.results).toHaveLength(4);
  const witnessed = sdkValue<Facade.WitnessReceipt>(result, 0);
  const committed = sdkValue<Facade.CommitReceipt>(result, 1);
  expect(witnessed.receipt_ref).toStartWith("witness:");
  expect(committed.approval).toBe("auto");
  const pack = sdkValue<Facade.MemoryPack>(result, 2);
  const claim = pack.items.find(item => item.short_id === committed.claim_short_id);
  expect(claim).toEqual(expect.objectContaining({ predicate: journey.predicate,
    provenance: expect.objectContaining({ source: "user_stated" }) }));
  expect(claim!.value_text).toContain(journey.value.seat);
  expect(claim!.value_text).toContain(journey.marker);
  expect(pack.narrowing.applied.deny_all).toBe(false);
  const receipts = sdkValue<Facade.VaultReceiptsPage>(result, 3).receipts;
  expect(receipts).toEqual(expect.arrayContaining([expect.objectContaining({
    receipt_ref: committed.receipt_ref, actor_ref: actor!.principalRef, actor_class: "agent", outcome: "allow",
  })]));
  expect(witnessed).not.toHaveProperty("turnShortId");
  expect(pack).not.toHaveProperty("retrievalMeta");
  const writerOnly = await engine.pairActor({ principalRef: actor!.principalRef, actorClass: "agent", scope: ["core:write"] });
  // A valid principal with no read capability must get the SDK's typed refusal, not an empty success.
  sdkRefusal(await engine.sdk.run("python", {
    mode: "remote", url: engine.url, credential: writerOnly.credential,
  }, [{ verb: "recall", query: journey.marker, options: { effort: "light" } }]), "FORBIDDEN");
});

suite.test(test, "BOOT-04", "Native addon memory persistence should work", async () => {
  const data = await corpus();
  const journey = data.native;
  const engine = await EngineFixture.start({ id: "BOOT-04", profile });
  const target = { mode: "embedded" as const, path: resolve(engine.root, "embedded-vault") };
  const scope = await embeddedClaimScope(engine,target);
  const written = await engine.sdk.run("napi", target, [
    sdkWitness(journey, data.occurredAt), sdkClaim(journey, data.occurredAt, scope),
  ]);
  expect(written.results).toHaveLength(2);
  expect(sdkValue<WitnessReceipt>(written, 0).receiptRef).toStartWith("witness:");
  const committed = sdkValue<Facade.CommitReceipt>(written, 1);
  expect(committed.approval).toBe("auto");
  // run() has awaited actual Node process exit before this second host opens the same path.
  const reopened = await engine.sdk.run("napi", target, [
    { verb: "recall", query: journey.marker, options: { effort: "light", asOf: data.occurredAt } },
    { verb: "receipts", limit: 100 },
  ]);
  expect(reopened.results).toHaveLength(2);
  recalledClaim(sdkValue<MemoryPack>(reopened, 0), committed, journey);
  const row = claimReceipt(sdkValue<Facade.VaultReceiptsPage>(reopened, 1).receipts, committed);
  expect(row.actor_class).toBe("human");
  expect(row.actor_ref).toMatch(/^[0-9a-f]{32}$/);
  // The embedded owner PERSON id is pinned (identical in every embedded vault),
  // so cross-vault principal inequality is never asserted; isolation is proven
  // by the foreign-claim/marker absence below plus the receipt checks above.
  const serverRecall = await engine.client.call("vault.recall", { query: journey.marker, effort: "light" });
  expect(serverRecall.items.some(item => item.short_id === committed.claim_short_id)).toBe(false);
  expect(serverRecall.items.some(item => item.value_text.includes(journey.marker))).toBe(false);
  expect(serverRecall.items.some(item => item.value_text.includes(journey.value.seat))).toBe(false);
});

suite.test(test, "BOOT-05", "CLI memory access should work", async () => {
  const data = await corpus();
  const journey = data.cli;
  const engine = await EngineFixture.start({ id: "BOOT-05", profile });
  await engine.client.call("vault.witness", witness(journey, data.occurredAt));
  const actor = await engine.pairActor({ principalRef: engine.pairedActor.principalRef,
    actorClass: "human", scope: ["core:read", "core:write"] });
  const discovered = await engine.cli.json<{ conversations: { id: string }[] }>(["api", "discover"]);
  expect(discovered.conversations.map(item => item.id)).toContain(journey.conversationId);
  const searched = await engine.cli.json<{ items: { id: string }[] }>(["api", "search", journey.marker, "--limit", "10"]);
  const hit = searched.items.find(item => item.id === journey.messageId);
  expect(hit).toBeDefined();
  const got = await engine.cli.run(["api", "get", hit!.id]);
  expect(got.exitCode).toBe(0);
  expect(got.stdout).toContain(journey.text);
  const committed = await actor.cli.call("vault.claims.upsert", {
    scope: await ownerBaseClaimScope(engine.client, engine.pairedActor.principalRef),
    id: journey.claimId, subject_ref: journey.turnId, predicate: journey.predicate,
    value: journey.value, source: "user_stated", confidence: 1,
  });
  expect(committed.approval).toBe("auto");
  const recalled = await actor.cli.call("vault.recall", {
    query: journey.marker, effort: "light", as_of: data.occurredAt,
  });
  const savedClaim = recalled.items.find(item => item.short_id === committed.claim_short_id);
  expect(savedClaim).toBeDefined();
  expect(savedClaim!.value_text).toContain(journey.value.seat);
  expect(savedClaim!.value_text).toContain(journey.marker);
  expect(savedClaim!.provenance.source).toBe("user_stated");
  const receipts = await actor.cli.call("vault.receipts", { limit: 100 });
  expect(receipts.receipts).toEqual(expect.arrayContaining([expect.objectContaining({
    receipt_ref: committed.receipt_ref, actor_ref: actor.principalRef, actor_class: "human", outcome: "allow",
  })]));
  const reader = await engine.pairActor({ principalRef: actor.principalRef, actorClass: "human", scope: ["core:read"] });
  const denied: FacadeInput<"vault.witness"> = {
    conversation_ref: journey.conversationId, turn_ref: data.deniedTurnId, occurred_at: data.occurredAt,
    messages: [{ id: data.deniedMessageId, author: "user", message_type: "dialogue",
      content: data.deniedText, is_visible: true, order: 0 }],
  };
  const refusal = await reader.cli.run(["api", "call", "vault.witness", "--data", "-"], JSON.stringify(denied));
  expect(refusal.exitCode).not.toBe(0);
  const error = JSON.parse(refusal.stdout) as { error: { code: string; message: string; suggestions: string[] } };
  expect(error.error.code).toBe("FORBIDDEN");
  expect(error.error.message.length).toBeGreaterThan(0);
  expect(error.error.suggestions.length).toBeGreaterThan(0);
  expect((await engine.client.call("vault.get", { entity_ref: data.deniedMessageId })).value).toBeNull();
  // Owner recall is ranked, not an exact-match negative lookup: unrelated
  // authorized rows may appear. What must hold is that the denied record
  // itself (ids and text) is absent.
  const deniedRecall = await engine.client.call("vault.recall", { query: data.deniedText, effort: "light" });
  expect(JSON.stringify(deniedRecall.items)).not.toContain(data.deniedMessageId);
  expect(JSON.stringify(deniedRecall.items)).not.toContain(data.deniedTurnId);
  expect(deniedRecall.items.some(item => item.value_text.includes(data.deniedText))).toBe(false);
});

// Canon: ARCH-0044 #part-a and ARCH-0040 #mcp-actor-ceilings, OF-205/246/223.
// The typed execute_code request is {schema_version, consent, run_ref, task, actor?, page?, cache?};
// its result is {structuredContent:{run_ref,run_id,result:{status},actor,steps,results,meta},isError:false}.
// BOOT-06's ordered design and typed read/proposal inputs are pinned in fixtures/boot/execute-mode-design.json.
// execute_code enters at Read (mcp_execute_code_gate) and judges each operation the run makes by its
// own effect, so read-only and propose-only agents run code without core:write. `task` goes to the
// generative_reasoner seat, which writes the program: a scripted loopback provider returns each
// program verbatim. Workflows and the Dreamer are off, so the six programs are the only model calls.
const EXECUTE_CONSENT = {
  policy_ref: "policy:boot-session",
  purpose: "read a witnessed preference and offer a reviewable claim",
} as const;
interface ExecuteStep { seq: number; effect: string; outcome: { kind: string; output?: string; outcome?: string } }
interface ExecuteRun {
  run_ref: string; run_id: string; result: { status: string };
  steps: ExecuteStep[]; actor: McpActor; meta: McpMeta;
}
const executeModels = (providers: ScriptedProviders) => `
[models.providers.boot-code]
kind = "local-openai-compat"
base_url = ${JSON.stringify(providers.urls["boot-code"])}
revision = "boot06-v1"
request_compression = false
capabilities = ["reasoning"]
[models.roles.generative_reasoner]
model = "boot-code:boot-program"
[models.workflows]
enabled = false
[models.dreamer]
enabled = false
[models.code_mode]
prompt_package = ${JSON.stringify(resolve(import.meta.dir, "fixtures/hooks/host/prompts"))}
[models.code_mode.compaction]
enabled = false
[models.code_mode.check]
mode = "off"
`;
/** One scripted program-writing turn: the model's reply is exactly `program`. */
function scriptProgram(providers: ScriptedProviders, id: string, purpose: string, program: string): void {
  providers.enqueue({ id, origin: "boot-code", role: "generative_reasoner", purpose,
    request: { method: "POST", path: "/v1/chat/completions", model: "boot-program" },
    response: openaiText(id, "boot-program", program, { inputTokens: 100, outputTokens: 100 }) });
}
async function executeCode(client: McpClient, tools: Tools, runRef: string, task: string): Promise<ExecuteRun> {
  const reply = await client.callTool("execute_code", toolArguments(tools, "execute_code", {
    consent: EXECUTE_CONSENT, run_ref: runRef, task })) as ToolResult<ExecuteRun>;
  expect(reply.isError).toBe(false);
  expect(reply.structuredContent.run_ref).toBe(runRef);
  expect(reply.structuredContent.run_id).toMatch(/^[0-9a-f]{32}$/);
  expect(reply.structuredContent.result.status).toBe("complete");
  return reply.structuredContent;
}
/** The one recorded verb call of a run: its outcome as the run's caller reads it. */
function onlyVerbStep(run: ExecuteRun): ExecuteStep["outcome"] {
  const verbs = run.steps.filter(step => step.outcome.kind === "agent_verb" || step.outcome.kind === "denied");
  expect(verbs).toHaveLength(1);
  return verbs[0]!.outcome;
}
function deniedWrite(run: ExecuteRun, actor: PairedActor): void {
  const outcome = onlyVerbStep(run);
  expect(outcome.kind).toBe("denied");
  expect(outcome.outcome).toBe("mcp_auth_required");
  expect(run.actor.actor_ref).toBe(actor.principalRef);
  expect(run.actor.gate_actor_class).toBe("agent");
}
suite.test(test, "BOOT-06", "MCP execute-mode session should work", async () => {
  let stage = "fixture and engine setup";
  try {
    const data = await corpus();
    const journey = data.execute;
    const design = await (await loadFixtures()).readJson<{
      readInput: FacadeInput<"vault.recall">;
      proposalInput: { predicate: string; value: Journey["value"]; confidence: number; source: "user_stated" };
    }>("boot-execute-mode-design");
    const providers = await ScriptedProviders.start({ id: "BOOT-06", origins: ["boot-code"], steps: [] });
    const engine = await EngineFixture.start({ id: "BOOT-06", profile, serverConfig: executeModels(providers) });
    stage = "witness and agent credential setup";
    const witnessed = await engine.client.call("vault.witness", witness(journey, data.occurredAt));
    const scope = await ownerBaseClaimScope(engine.client, engine.pairedActor.principalRef);
    const [reader, proposer] = await registerAgents(engine, [
      { name: "boot-execute-reader", tier: "read-only" }, { name: "boot-execute-proposer", tier: "propose-only" },
    ]);
    expect(new Set([reader!.principalRef, proposer!.principalRef, engine.pairedActor.principalRef]).size).toBe(3);
    const readerMcp = new McpClient(reader!.client, "primary");
    const proposerMcp = new McpClient(proposer!.client, "primary");
    stage = "MCP initialization and setup";
    await readerMcp.initialize();
    await proposerMcp.initialize();
    const tools = await readerMcp.request<Tools>("tools/list");
    expect(tools.tools.map(tool => tool.name)).toEqual(expect.arrayContaining(["setup_oneiron", "execute_code", "read_result"]));
    expect(await proposerMcp.request<Tools>("tools/list")).toEqual(tools);
    const setup = await readerMcp.callTool("setup_oneiron", toolArguments(tools, "setup_oneiron", { consent: EXECUTE_CONSENT })) as ToolResult<{
      instructions: string; actor: McpActor; meta: McpMeta;
    }>;
    expect(setup.isError).toBe(false);
    expect(setup.structuredContent.instructions.length).toBeGreaterThan(0);
    expect(setup.structuredContent.actor.actor_ref).toBe(reader!.principalRef);
    expect(setup.structuredContent.meta.ttlMs).toBe(0);
    expect(setup.structuredContent.meta.cacheScope).toBe("private");
    expect(providers.seenFixtureCalls).toHaveLength(0);

    // 1. The read-only agent's program reads the authored preference.
    stage = "step 1 reader recall";
    scriptProgram(providers, "boot06-read", "reader recalls the authored preference",
      `const answer = await vault.recall(${JSON.stringify(design.readInput)});\nfinish("recalled");`);
    const read = await executeCode(readerMcp, tools, "boot-reader", "Read cobalt-execute-preference using vault.recall at light effort.");
    expect(read.actor.actor_ref).toBe(reader!.principalRef);
    expect(read.actor.gate_actor_ref).toBe(reader!.principalRef);
    expect(read.actor.actor_class).toBe("agent");
    expect(read.meta.cacheScope).toBe("private");
    const recall = onlyVerbStep(read);
    expect(recall.kind).toBe("agent_verb");
    const pack = JSON.parse(recall.output!) as Facade.MemoryPack;
    recalledTurn(pack, witnessed, journey);
    // Entering the finished run again replays it: no new program, no new step.
    stage = "step 1 finished-run replay";
    const replay = await executeCode(readerMcp, tools, "boot-reader", "Read cobalt-execute-preference using vault.recall at light effort.");
    expect(replay.run_id).toBe(read.run_id);
    expect(providers.seenFixtureCalls).toHaveLength(1);

    // 2. The propose-only agent's program proposes a claim. The declared user_stated source is
    // false for generated code: the host stamps `generated`, and the write waits for review.
    // A generated claim must name the readable TURN it was made from.
    const proposal = { ...design.proposalInput, scope, subject_ref: journey.turnId,
      evidence_turn_refs: [journey.turnId] };
    stage = "step 2 generated proposal with witnessed TURN evidence";
    scriptProgram(providers, "boot06-proposal", "proposer offers a reviewable claim with a false declared source",
      `const answer = await vault.claims.upsert(${JSON.stringify(proposal)});\nfinish("proposed");`);
    const proposed = await executeCode(proposerMcp, tools, "boot-proposer",
      "Offer a reviewable cobalt-execute-proposal claim about the witnessed preference using vault.claims.upsert.");
    expect(proposed.actor.actor_ref).toBe(proposer!.principalRef);
    expect(proposed.actor.gate_actor_class).toBe("agent");
    const upsert = onlyVerbStep(proposed);
    expect(upsert.kind).toBe("agent_verb");
    const commit = JSON.parse(upsert.output!) as Facade.CommitReceipt;
    expect(commit.approval).toBe("proposed");
    stage = "step 2 proposal and receipt readback";
    const stored = await engine.client.call("vault.claims.list", { subject_ref: journey.turnId, limit: 100 });
    const row = stored.value.find(item => item.short_ref === commit.claim_short_id);
    expect(row).toBeDefined();
    expect(row!.value).toEqual(journey.value);
    expect(row!.source).toBe("generated");
    expect(row!.approval).toBe("proposed");
    const receipts = await engine.client.call("vault.receipts", { limit: 100 });
    expect(receipts.receipts).toEqual(expect.arrayContaining([expect.objectContaining({
      receipt_ref: commit.receipt_ref, outcome: "pending", actor_ref: proposer!.principalRef, actor_class: "agent",
    })]));

    // 3. A caller-supplied actor naming another principal is refused before any program is written.
    stage = "step 3 forged actor refusal";
    mcpRefusal(await readerMcp.rpc("tools/call", { name: "execute_code", arguments: toolArguments(tools, "execute_code", {
      consent: EXECUTE_CONSENT, run_ref: "boot-forged-actor", task: "Read cobalt-execute-preference using vault.recall at light effort.",
      actor: { actor_ref: proposer!.principalRef, gate_actor_ref: proposer!.principalRef,
        actor_class: "agent", gate_actor_class: "agent", scope: {} },
    }) }), "mcp_actor_mismatch");
    expect(providers.seenFixtureCalls).toHaveLength(2);

    // 4. Neither tier exceeds its grant inside a run: the reader cannot propose, and neither
    // agent can make an immediate claim write. A refused verb rejects its promise in the guest,
    // so each program catches it and finishes; the run completes and its write step is denied.
    const deniedProposal = { ...proposal, value: { seat: "aisle", marker: "cobalt-execute-denied-upsert" } };
    stage = "step 4 reader upsert denial";
    scriptProgram(providers, "boot06-reader-upsert", "reader cannot propose a claim",
      `let outcome = "written";\ntry { await vault.claims.upsert(${JSON.stringify(deniedProposal)}); } catch (refusal) { outcome = "refused"; }\nfinish(outcome);`);
    deniedWrite(await executeCode(readerMcp, tools, "boot-reader-upsert",
      "Attempt cobalt-execute-denied-upsert with vault.claims.upsert and report the refusal."), reader!);
    const immediate = (id: string, marker: string) => ({ id, predicate: journey.predicate, subject: journey.turnId,
      value: { seat: "aisle", marker }, confidence: 1 });
    const readerPut = immediate("06424242424242424242424242424242", "cobalt-execute-denied-automatic-reader");
    stage = "step 4 reader immediate-write denial";
    scriptProgram(providers, "boot06-reader-put", "reader cannot write a claim at once",
      `let outcome = "written";\ntry { await vault.claims.put(${JSON.stringify(readerPut)}); } catch (refusal) { outcome = "refused"; }\nfinish(outcome);`);
    deniedWrite(await executeCode(readerMcp, tools, "boot-reader-put",
      "Attempt cobalt-execute-denied-automatic-reader using vault.claims.put and report the refusal."), reader!);
    const proposerPut = immediate("06434343434343434343434343434343", "cobalt-execute-denied-automatic-proposer");
    stage = "step 4 proposer immediate-write denial";
    scriptProgram(providers, "boot06-proposer-put", "proposer cannot write a claim at once",
      `let outcome = "written";\ntry { await vault.claims.put(${JSON.stringify(proposerPut)}); } catch (refusal) { outcome = "refused"; }\nfinish(outcome);`);
    deniedWrite(await executeCode(proposerMcp, tools, "boot-proposer-put",
      "Attempt cobalt-execute-denied-automatic-proposer using vault.claims.put and report the refusal."), proposer!);

    // 5. Public reads confirm the outcome: one generated proposal, no denied write, the original
    // witnessed preference unchanged, and the unapproved proposal outside owner recall.
    stage = "step 5 proposal and denied-write readback";
    const after = await engine.client.call("vault.claims.list", { subject_ref: journey.turnId, limit: 100 });
    expect(after.value.filter(item => JSON.stringify(item.value).includes("cobalt-execute"))).toHaveLength(1);
    expect(JSON.stringify(after.value)).not.toContain("cobalt-execute-denied");
    for (const id of [readerPut.id, proposerPut.id])
      expect((await engine.client.call("vault.get", { entity_ref: id })).value).toBeNull();
    stage = "step 5 witnessed preference and unapproved recall";
    recalledTurn(await engine.client.call("vault.recall", { query: journey.marker, effort: "light", limit: 10 }), witnessed, journey);
    const unapproved = await engine.client.call("vault.recall", {
      query: journey.value.marker, effort: "light", scope: { kinds: ["CLAIM"] },
    });
    expect(unapproved.items.some(item => item.short_id === commit.claim_short_id)).toBe(false);
    stage = "scripted provider call accounting";
    expect(providers.seenFixtureCalls.map(call => call.fixtureId)).toEqual([
      "boot06-read", "boot06-proposal", "boot06-reader-upsert", "boot06-reader-put", "boot06-proposer-put",
    ]);
    stage = "engine cleanup";
    await engine.close();
    stage = "provider cleanup and unexpected-call check";
    await providers.close();
  } catch (error) {
    const failure = error as {
      reply?: { status: number };
      error?: { code: string; message: string; suggestions?: readonly string[] };
      response?: JsonRpcReply<unknown>;
    };
    const rpc = failure.response && "error" in failure.response ? failure.response.error : undefined;
    const detail = rpc?.data as {
      error_code?: string; kind?: string; recovery_suggestions?: readonly string[];
    } | undefined;
    throw new Error(`BOOT-06 ${stage}: status=${failure.reply?.status ?? (rpc ? "2xx" : "<none>")} rpc=${rpc?.code ?? "<none>"} code=${failure.error?.code ?? detail?.error_code ?? detail?.kind ?? "<none>"} message=${failure.error?.message ?? rpc?.message ?? (error instanceof Error ? error.message : String(error))} suggestion=${failure.error?.suggestions?.[0] ?? detail?.recovery_suggestions?.[0] ?? "<none>"}`, { cause: error });
  }
});

suite.test(test, "BOOT-07", "MCP tool-first operator registration should work", async () => {
  const data = await corpus();
  const journey = data.mcp;
  const engine = await EngineFixture.start({ id: "BOOT-07", profile, surface: "tool-first" });
  const witnessed = await engine.client.call("vault.witness", witness(journey, data.occurredAt));
  const [reader, proposer] = await registerAgents(engine, [
    { name: "boot-mcp-reader", tier: "read-only" }, { name: "boot-mcp-proposer", tier: "propose-only" },
  ]);
  const primary = new McpClient(proposer!.client, "primary");
  await primary.initialize();
  await proposer!.mcp.initialize();
  await reader!.mcp.initialize();
  const primaryTools = await primary.request<Tools>("tools/list");
  const tools = await proposer!.mcp.request<Tools>("tools/list");
  expect(primaryTools.surfaceMode).toBe("primary");
  expect(tools.surfaceMode).toBe("tool_first");
  expect(primaryTools.tools.map(tool => tool.name)).toContain("setup_oneiron");
  expect(primaryTools.tools.map(tool => tool.name)).not.toContain("vault.recall");
  expect(tools.tools.map(tool => tool.name)).toEqual(expect.arrayContaining(["vault.recall", "vault.claims.upsert"]));
  expect(tools.tools.map(tool => tool.name)).not.toContain("setup_oneiron");
  expect(await reader!.mcp.request<Tools>("tools/list")).toEqual(tools);
  const setup = await primary.callTool("setup_oneiron", toolArguments(primaryTools, "setup_oneiron", {})) as ToolResult<{
    verb_grammar: { verbs: { name: string; tool_first_tool: string }[] }; instructions: string; actor: McpActor;
  }>;
  expect(setup.isError).toBe(false);
  expect(setup.structuredContent.instructions.length).toBeGreaterThan(0);
  expect(setup.structuredContent.verb_grammar.verbs.length).toBeGreaterThan(0);
  for (const row of setup.structuredContent.verb_grammar.verbs) {
    expect(tools.tools.map(tool => tool.name)).toContain(row.tool_first_tool);
    expect(row.tool_first_tool).toBe(row.name);
  }
  const read = await mcpVerb(reader!.mcp, tools, "vault.recall", {
    query: journey.marker, effort: "light", limit: 10, as_of: data.occurredAt,
  });
  recalledTurn(read.output, witnessed, journey);
  expect(read.actor.gate_actor_ref).toBe(reader!.principalRef);
  expect(read.meta.ttlMs).toBe(0);
  expect(read.meta.cacheScope).toBe("private");
  const proposal: FacadeInput<"vault.claims.upsert"> = {
    scope: await ownerBaseClaimScope(engine.client, engine.pairedActor.principalRef),
    predicate: journey.predicate, subject_ref: journey.turnId,
    value: journey.value, confidence: 1, source: "tool_output",
  };
  const proposed = await mcpVerb(proposer!.mcp, tools, "vault.claims.upsert", proposal);
  expect(proposed.output.approval).toBe("proposed");
  expect(proposed.actor.actor_ref).toBe(proposer!.principalRef);
  expect(proposed.actor.gate_actor_ref).toBe(proposer!.principalRef);
  expect(proposed.actor.gate_actor_class).toBe("agent");
  const stored = await engine.client.call("vault.claims.list", { subject_ref: journey.turnId, limit: 10 });
  expect(stored.value).toEqual(expect.arrayContaining([expect.objectContaining({
    short_ref: proposed.output.claim_short_id, value: journey.value, source: "tool_output", approval: "proposed",
  })]));
  const receipts = await engine.client.call("vault.receipts", { limit: 100 });
  expect(receipts.receipts).toEqual(expect.arrayContaining([expect.objectContaining({
    receipt_ref: proposed.output.receipt_ref, outcome: "pending", actor_ref: proposer!.principalRef, actor_class: "agent",
  })]));
  const unapproved = await engine.client.call("vault.recall", {
    query: journey.marker, effort: "light", scope: { kinds: ["CLAIM"] },
  });
  // Ranked owner recall may return unrelated authorized CLAIMs; the proposed
  // (unapproved) journey claim and its marker must be absent.
  expect(unapproved.items.some(item => item.short_id === proposed.output.claim_short_id)).toBe(false);
  expect(unapproved.items.some(item => item.value_text.includes(journey.marker))).toBe(false);
  mcpRefusal(await reader!.mcp.rpc("tools/call", { name: "vault.claims.upsert",
    arguments: toolArguments(tools, "vault.claims.upsert", { arguments: { spec: proposal } }),
  }), "mcp_auth_required");
  mcpRefusal(await proposer!.mcp.rpc("tools/call", { name: "vault.claims.upsert",
    arguments: toolArguments(tools, "vault.claims.upsert", {
      actor: { actor_ref: engine.pairedActor.principalRef, gate_actor_ref: engine.pairedActor.principalRef,
        actor_class: "human", gate_actor_class: "human", scope: {} }, arguments: { spec: proposal },
    }),
  }), "mcp_actor_mismatch");
  // Endpoint selection belongs to the operator, not to params supplied by an agent.
  expect(await primary.request<Tools>("tools/list", { surface_mode: "tool_first" })).toEqual(primaryTools);
  for (const verb of ["vault.recall", "vault.claims.upsert"] as const) {
    const spec = verb === "vault.recall" ? { query: journey.marker, effort: "light" } : proposal;
    mcpRefusal(await primary.rpc("tools/call", { name: verb,
      arguments: toolArguments(tools, verb, { arguments: { spec }, surface_mode: "tool_first" }),
    }), "unknown_tool");
  }
  expect(await primary.request<Tools>("tools/list")).toEqual(primaryTools);
});

// One Node host holds A and B simultaneously, then reads A/B/A: this exercises client-local
// actor-derived caches as well as two independently authenticated, model-free server processes.
const ISOLATION_CLIENTS = String.raw`
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { join } from 'node:path';
const p = JSON.parse(readFileSync(0, 'utf8'));
const { Oneiron } = await import(pathToFileURL(p.module).href);
const a = Oneiron.connect(p.a.url, p.a.credential);
const b = Oneiron.connect(p.b.url, p.b.credential);
let nextStep=0;
function traced(actor,verb,call) {
  const stepId='isolation-'+nextStep++;
  const record=(phase)=>{mkdirSync(p.traceRoot,{recursive:true,mode:0o700});writeFileSync(join(p.traceRoot,'sdk-'+stepId+'-'+phase+'.json'),
    JSON.stringify({stepId,kind:'sdk',phase,[phase==='start'?'startedAt':'finishedAt']:new Date().toISOString(),method:verb,path:'remote',client:actor})+'\n',{mode:0o600})};
  record('start');try {const value=call();record('complete');return value;} catch(error) {record('error');throw error;}
}
function write(m, j, scope, actor) {
  const witnessed = traced(actor,'witness',()=>m.vault.witness({ conversationRef: j.conversationId, turnRef: j.turnId, occurredAt: p.at,
    messages: [{ id: j.messageId, author: 'user', messageType: 'dialogue', content: j.text, order: 0 }] }));
  const committed = traced(actor,'claimUpsert',()=>m.vault.claims.upsert({ id: j.claimId, subject_ref: j.turnId, predicate: j.predicate, scope,
    value: j.value, confidence: 1, source: 'user_stated', occurred_at: p.at, learned_at: p.at }));
  return { witnessed, committed };
}
const wa = write(a, p.a.journey, p.a.scope, 'a');
const wb = write(b, p.b.journey, p.b.scope, 'b');
const options = { effort: 'light', asOf: p.at };
const firstA = traced('a','recall',()=>a.vault.recall(p.a.journey.marker, options));
const fromB = traced('b','recall',()=>b.vault.recall(p.b.journey.marker, options));
const againA = traced('a','recall',()=>a.vault.recall(p.a.journey.marker, options));
process.stdout.write(JSON.stringify({ wa, wb, firstA, fromB, againA,
  receiptsA: traced('a','receipts',()=>a.vault.receipts()), receiptsB: traced('b','receipts',()=>b.vault.receipts()) }));
`;
interface IsolationReply {
  wa: { witnessed: WitnessReceipt; committed: Facade.CommitReceipt };
  wb: { witnessed: WitnessReceipt; committed: Facade.CommitReceipt };
  firstA: MemoryPack;
  fromB: MemoryPack;
  againA: MemoryPack;
  receiptsA: Facade.VaultReceiptsPage;
  receiptsB: Facade.VaultReceiptsPage;
}
suite.test(test, "BOOT-08", "Vault and client isolation should work", async () => {
  const data = await corpus();
  // BOOT is allocated one slot by the pinned plan. These are two small independent vaults,
  // not EngineFixture sync peers; both processes stay inside that slot's containment budget.
  const a = await EngineFixture.start({ id: "BOOT-08-a", profile });
  const b = await EngineFixture.start({ id: "BOOT-08-b", profile });
  // Both vaults pin the same embedded owner PERSON id by canon, so principal
  // inequality is never asserted; isolation is proven by the cross-vault
  // recall/receipt/get/401 checks below.
  redactor.add(a.pairedActor.credential, b.pairedActor.credential);
  const processResult = await runProcess([
    requireAsset(a.build, "node"), "--input-type=module", "-e", ISOLATION_CLIENTS,
  ], { cwd: a.root, env: a.env, label: "boot-isolation-sdk", privateOutput: true, artifacts: a.artifacts,
    operation: {kind:"sdk",method:"isolation",path:"remote"},
    input: JSON.stringify({ module: requireAsset(a.build, "sdk-js"), at: data.occurredAt, traceRoot:a.artifacts.root,
      a: { url: a.url, credential: a.pairedActor.credential, journey: data.isolationA,
        scope: await ownerBaseClaimScope(a.client,a.pairedActor.principalRef) },
      b: { url: b.url, credential: b.pairedActor.credential, journey: data.isolationB,
        scope: await ownerBaseClaimScope(b.client,b.pairedActor.principalRef) } }),
  });
  expect(processResult.exitCode).toBe(0);
  expect(processResult.signal).toBeNull();
  const result = JSON.parse(processResult.stdout) as IsolationReply;
  expect(result.wa.committed.approval).toBe("auto");
  expect(result.wb.committed.approval).toBe("auto");
  for (const pack of [result.firstA, result.againA]) {
    recalledClaim(pack, result.wa.committed, data.isolationA);
    expect(pack.items.some(item => item.shortId === result.wb.committed.claim_short_id)).toBe(false);
    expect(pack.items.some(item => item.valueText.includes(data.isolationB.value.seat))).toBe(false);
  }
  recalledClaim(result.fromB, result.wb.committed, data.isolationB);
  expect(result.fromB.items.some(item => item.shortId === result.wa.committed.claim_short_id)).toBe(false);
  expect(result.fromB.items.some(item => item.valueText.includes(data.isolationA.value.seat))).toBe(false);
  claimReceipt(result.receiptsA.receipts, result.wa.committed, a.pairedActor.principalRef);
  claimReceipt(result.receiptsB.receipts, result.wb.committed, b.pairedActor.principalRef);
  expect(result.receiptsA.receipts.some(row => row.claim_ref === data.isolationB.claimId)).toBe(false);
  expect(result.receiptsB.receipts.some(row => row.claim_ref === data.isolationA.claimId)).toBe(false);
  const replayed = new PublicHttpClient(b.url, { credential: a.pairedActor.credential, artifacts: b.artifacts });
  const denied = await replayed.raw<{ error: { code: string } }>("POST", "/v1/core/facade/vault.recall", {
    query: data.isolationA.marker, effort: "light",
  } satisfies FacadeInput<"vault.recall">);
  expect(denied.status).toBe(401);
  expect(denied.body.error.code).toBe("UNAUTHORIZED");
  for (const [target, foreign] of [[b, data.isolationA], [a, data.isolationB]] as const) {
    for (const entity_ref of [foreign.turnId, foreign.messageId, foreign.claimId]) {
      expect((await target.client.call("vault.get", { entity_ref })).value).toBeNull();
    }
  }
  const atA = await a.client.call("vault.recall", { query: data.isolationA.marker, effort: "light", as_of: data.occurredAt });
  const atB = await b.client.call("vault.recall", { query: data.isolationB.marker, effort: "light", as_of: data.occurredAt });
  expect(atA.items.some(item => item.value_text.includes(data.isolationA.value.seat))).toBe(true);
  expect(atB.items.some(item => item.value_text.includes(data.isolationB.value.seat))).toBe(true);
  expect(atA.items.some(item => item.value_text.includes(data.isolationB.value.seat))).toBe(false);
  expect(atB.items.some(item => item.value_text.includes(data.isolationA.value.seat))).toBe(false);
  for (const [target, foreignClaim] of [[a, data.isolationB.claimId], [b, data.isolationA.claimId]] as const) {
    expect((await target.client.call("vault.receipts", { limit: 100 })).receipts.some(row => row.claim_ref === foreignClaim)).toBe(false);
  }
});
