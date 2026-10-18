import { afterAll, expect, test } from "bun:test";
import { resolve } from "node:path";
import type { Facade, FacadeInput, FacadeResult } from "@oneiron/client";
import type { CommitReceipt, FacadeReceipt, MemoryPack, WitnessReceipt } from "oneiron";
import { EngineFixture } from "./support/engine.ts";
import type { PairedActor } from "./support/engine.ts";
import { McpClient, PublicHttpClient } from "./support/clients.ts";
import type { JsonRpcReply, SdkDriverResult, SdkOperation } from "./support/clients.ts";
import { loadFixtures, ownerBaseClaimScope, requireAsset } from "./support/fixtures.ts";
import { defineFile, redactor, runProcess } from "./support/run.ts";

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
function sdkClaim(journey: Journey, at: number): SdkOperation {
  return { verb: "claimUpsert", input: {
    id: journey.claimId, subjectRef: journey.turnId, predicate: journey.predicate,
    value: journey.value, confidence: 1, source: "user_stated", occurredAt: at, learnedAt: at,
  } };
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
function recalledClaim(pack: MemoryPack, receipt: CommitReceipt, journey: Journey): void {
  const claim = pack.items.find(item => item.shortId === receipt.claimShortId);
  expect(claim).toBeDefined();
  expect(claim!.predicate).toBe(journey.predicate);
  expect(claim!.valueText).toContain(journey.value.seat);
  expect(claim!.valueText).toContain(journey.marker);
  expect(claim!.provenance.source).toBe("user_stated");
  expect(Array.isArray(claim!.provenance.sourceRevisionIds)).toBe(true);
  expect(Array.isArray(claim!.provenance.evidenceTurnIds)).toBe(true);
  expect(pack.narrowing.applied.denyAll).toBe(false);
}
function claimReceipt(rows: FacadeReceipt[], commit: CommitReceipt, principal?: string): FacadeReceipt {
  const row = rows.find(item => item.receiptRef === commit.receiptRef);
  expect(row).toBeDefined();
  expect(row!.outcome).toBe("allow");
  if (principal !== undefined) expect(row!.actorRef).toBe(principal);
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
  const result = await engine.sdk.run("typescript", target, [
    sdkWitness(journey, data.occurredAt), sdkClaim(journey, data.occurredAt),
    { verb: "recall", query: journey.marker, options: { effort: "light", asOf: data.occurredAt } },
    { verb: "receipts", limit: 100 },
  ]);
  expect(result.results).toHaveLength(4);
  const witnessed = sdkValue<WitnessReceipt>(result, 0);
  const committed = sdkValue<CommitReceipt>(result, 1);
  expect(witnessed.receiptRef).toStartWith("witness:");
  expect(committed.approval).toBe("auto");
  recalledClaim(sdkValue<MemoryPack>(result, 2), committed, journey);
  expect(claimReceipt(sdkValue<FacadeReceipt[]>(result, 3), committed, actor.principalRef).actorClass).toBe("human");
  const saved = await actor.client.call("vault.claims.list", { subject_ref: journey.turnId, limit: 10 });
  expect(saved.value).toEqual(expect.arrayContaining([expect.objectContaining({
    claim_ref: journey.claimId, value: journey.value, source: "user_stated", approval: "auto",
  })]));
  const reader = await engine.pairActor({ principalRef: actor.principalRef, actorClass: "human", scope: ["core:read"] });
  sdkRefusal(await engine.sdk.run("typescript", {
    mode: "remote", url: engine.url, credential: reader.credential,
  }, [sdkClaim({ ...journey, claimId: data.deniedMessageId }, data.occurredAt)]), "FORBIDDEN");
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
  const receipts = sdkValue<Facade.MemoryReceipt[]>(result, 3);
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
  const written = await engine.sdk.run("napi", target, [
    sdkWitness(journey, data.occurredAt), sdkClaim(journey, data.occurredAt),
  ]);
  expect(written.results).toHaveLength(2);
  expect(sdkValue<WitnessReceipt>(written, 0).receiptRef).toStartWith("witness:");
  const committed = sdkValue<CommitReceipt>(written, 1);
  expect(committed.approval).toBe("auto");
  // run() has awaited actual Node process exit before this second host opens the same path.
  const reopened = await engine.sdk.run("napi", target, [
    { verb: "recall", query: journey.marker, options: { effort: "light", asOf: data.occurredAt } },
    { verb: "receipts", limit: 100 },
  ]);
  expect(reopened.results).toHaveLength(2);
  recalledClaim(sdkValue<MemoryPack>(reopened, 0), committed, journey);
  const row = claimReceipt(sdkValue<FacadeReceipt[]>(reopened, 1), committed);
  expect(row.actorClass).toBe("human");
  expect(row.actorRef).toMatch(/^[0-9a-f]{32}$/);
  expect(row.actorRef).not.toBe(engine.pairedActor.principalRef);
  expect((await engine.client.call("vault.recall", { query: journey.marker, effort: "light" })).items).toEqual([]);
});

suite.test(test, "BOOT-05", "CLI memory access should work", async () => {
  const data = await corpus();
  const journey = data.cli;
  const engine = await EngineFixture.start({ id: "BOOT-05", profile });
  await engine.client.call("vault.witness", witness(journey, data.occurredAt));
  const actor = await engine.pairActor({ principalRef: engine.pairedActor.principalRef,
    actorClass: "human", scope: ["core:read", "core:write"] });
  const discovered = await actor.cli.json<{ conversations: { id: string }[] }>(["api", "discover"]);
  expect(discovered.conversations.map(item => item.id)).toContain(journey.conversationId);
  const searched = await actor.cli.json<{ items: { id: string }[] }>(["api", "search", journey.marker, "--limit", "10"]);
  const hit = searched.items.find(item => item.id === journey.messageId);
  expect(hit).toBeDefined();
  const got = await actor.cli.run(["api", "get", hit!.id]);
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
  expect(receipts).toEqual(expect.arrayContaining([expect.objectContaining({
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
  expect((await engine.client.call("vault.recall", { query: data.deniedText, effort: "light" })).items).toEqual([]);
});

// Canon: ARCH-0044 #part-a and ARCH-0040 #mcp-actor-ceilings, OF-205/246/223.
// The typed execute_code request is {schema_version, consent, run_ref, task, actor?, page?, cache?};
// its result is {structuredContent:{result:{status},actor,steps,results,meta},isError:false}.
// BOOT-06's complete ordered design and typed read/proposal inputs are pinned in
// fixtures/boot/execute-mode-design.json. The real runtime, one setup's grammar, the read,
// proposed receipt and forged actor/source assertions must all run when this prerequisite lands.
// mcp_execute_code_gate currently classifies every run as Commits, requiring core:write;
// token agent --tier read-only/propose-only deliberately grants no core:write. Do not widen them.
suite.todo(test, "BOOT-06", "waits on execute_code read-only/propose-only credential admission — MCP execute-mode session should work");

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
  expect(receipts).toEqual(expect.arrayContaining([expect.objectContaining({
    receipt_ref: proposed.output.receipt_ref, outcome: "pending", actor_ref: proposer!.principalRef, actor_class: "agent",
  })]));
  const unapproved = await engine.client.call("vault.recall", {
    query: journey.marker, effort: "light", scope: { kinds: ["CLAIM"] },
  });
  expect(unapproved.items).toEqual([]);
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
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
const p = JSON.parse(readFileSync(0, 'utf8'));
const { Oneiron } = await import(pathToFileURL(p.module).href);
const a = Oneiron.connect(p.a.url, p.a.credential);
const b = Oneiron.connect(p.b.url, p.b.credential);
function write(m, j) {
  const witnessed = m.vault.witness({ conversationRef: j.conversationId, turnRef: j.turnId, occurredAt: p.at,
    messages: [{ id: j.messageId, author: 'user', messageType: 'dialogue', content: j.text, order: 0 }] });
  const committed = m.vault.claims.upsert({ id: j.claimId, subjectRef: j.turnId, predicate: j.predicate,
    value: j.value, confidence: 1, source: 'user_stated', occurredAt: p.at, learnedAt: p.at });
  return { witnessed, committed };
}
const wa = write(a, p.a.journey);
const wb = write(b, p.b.journey);
const options = { effort: 'light', asOf: p.at };
const firstA = a.vault.recall(p.a.journey.marker, options);
const fromB = b.vault.recall(p.b.journey.marker, options);
const againA = a.vault.recall(p.a.journey.marker, options);
process.stdout.write(JSON.stringify({ wa, wb, firstA, fromB, againA,
  receiptsA: a.vault.receipts(), receiptsB: b.vault.receipts() }));
`;
interface IsolationReply {
  wa: { witnessed: WitnessReceipt; committed: CommitReceipt };
  wb: { witnessed: WitnessReceipt; committed: CommitReceipt };
  firstA: MemoryPack;
  fromB: MemoryPack;
  againA: MemoryPack;
  receiptsA: FacadeReceipt[];
  receiptsB: FacadeReceipt[];
}
suite.test(test, "BOOT-08", "Vault and client isolation should work", async () => {
  const data = await corpus();
  // BOOT is allocated one slot by the pinned plan. These are two small independent vaults,
  // not EngineFixture sync peers; both processes stay inside that slot's containment budget.
  const a = await EngineFixture.start({ id: "BOOT-08-a", profile });
  const b = await EngineFixture.start({ id: "BOOT-08-b", profile });
  expect(a.pairedActor.principalRef).not.toBe(b.pairedActor.principalRef);
  redactor.add(a.pairedActor.credential, b.pairedActor.credential);
  const processResult = await runProcess([
    requireAsset(a.build, "node"), "--input-type=module", "-e", ISOLATION_CLIENTS,
  ], { cwd: a.root, env: a.env, label: "boot-isolation-sdk", privateOutput: true,
    input: JSON.stringify({ module: requireAsset(a.build, "sdk-js"), at: data.occurredAt,
      a: { url: a.url, credential: a.pairedActor.credential, journey: data.isolationA },
      b: { url: b.url, credential: b.pairedActor.credential, journey: data.isolationB } }),
  });
  expect(processResult.exitCode).toBe(0);
  expect(processResult.signal).toBeNull();
  const result = JSON.parse(processResult.stdout) as IsolationReply;
  expect(result.wa.committed.approval).toBe("auto");
  expect(result.wb.committed.approval).toBe("auto");
  for (const pack of [result.firstA, result.againA]) {
    recalledClaim(pack, result.wa.committed, data.isolationA);
    expect(pack.items.some(item => item.shortId === result.wb.committed.claimShortId)).toBe(false);
    expect(pack.items.some(item => item.valueText.includes(data.isolationB.value.seat))).toBe(false);
  }
  recalledClaim(result.fromB, result.wb.committed, data.isolationB);
  expect(result.fromB.items.some(item => item.shortId === result.wa.committed.claimShortId)).toBe(false);
  expect(result.fromB.items.some(item => item.valueText.includes(data.isolationA.value.seat))).toBe(false);
  claimReceipt(result.receiptsA, result.wa.committed, a.pairedActor.principalRef);
  claimReceipt(result.receiptsB, result.wb.committed, b.pairedActor.principalRef);
  expect(result.receiptsA.some(row => row.claimRef === data.isolationB.claimId)).toBe(false);
  expect(result.receiptsB.some(row => row.claimRef === data.isolationA.claimId)).toBe(false);
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
    expect((await target.client.call("vault.receipts", { limit: 100 })).some(row => row.claim_ref === foreignClaim)).toBe(false);
  }
});
