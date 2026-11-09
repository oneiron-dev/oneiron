import { afterAll, expect, test } from "bun:test";
import { dirname, resolve } from "node:path";
import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import type { Facade, FacadeInput, FacadeResult, FacadeVerb } from "@oneiron/client";
import { EngineFixture, awaitPublic } from "./support/engine.ts";
import { createPrivateKey, createPublicKey, createHash } from "node:crypto";
import { credentialParts, McpClient, PublicHttpClient, PublicHttpError } from "./support/clients.ts";
import type { JsonRpcReply, WireReply } from "./support/clients.ts";
import { loadFixtures, ownerBaseClaimScope } from "./support/fixtures.ts";
import type { FixtureCatalog } from "./support/fixtures.ts";
import { BlockedDoor, assertFlowActive, defineFile, redactor, secretHex } from "./support/run.ts";
import { blake3 } from "@noble/hashes/blake3";
import { ScriptedProviders, openaiText } from "./support/providers.ts";
import type { ProviderStep } from "./support/providers.ts";

const profile = process.env.E2E_PROFILE === "real-small-model"
  ? "real-small-model" : "deterministic";
const suite = defineFile(import.meta, { profile, slots: 1 });
afterAll(suite.flush);

/*
 * ARCH-0080 #crash-safety/#replay/#verb-outcomes/#host-verbs, OF-579/580/581.
 * Binding read at main 65529b62e07209d8faeb0c0fcde7812e3df9cc46:
 * scripts/sdk/verbs/, both generated SDKs, the server's OpenAPI
 * registration/owner paths, facade host doors, MCP argument/result DTOs and CLI.
 * EngineFixture captures runtime OpenAPI as a binding diagnostic, not an oracle.
 * hooks-scenarios pins canon and independent fixture facts for all seven IDs.
 *
 * The public pack format carries HOOK.md, intent.md and body.js. Those bodies
 * run in serve's checked-in quickjs-hook.wasm, not a JS host or alternate engine.
 * The plan's pack-carried Wasm fixture has no public input; it is on FIX-LIST.
 * No build, server, interpreter CLI, typecheck or test runs in this Mac lane.
 * G01 TODOs below are mandatory BLOCKED rows, never partial passing coverage.
 */

interface Corpus {
  pageBound: number;
  replay: {
    checkpointId: string; anchorId: string; originalId: string; correctionId: string;
    triggerPredicate: string; anchorPredicate: string; outputPredicate: string;
    hookName: string; hookVersion: string; marker: string; anchor: string;
    originalRevision: string; laterRevision: string; packFiles: Record<string, string>;
  };
  redaction: {
    claimId: string; predicate: string; value: { public: string; private: string };
    annotation: string; packFiles: Record<string, string>;
  };
}
interface FactCorpus {
  packName: string; hookName: string; hookVersion: string;
  triggerPredicate: string; otherPredicate: string; outputPredicate: string;
  matchingWorld: string; otherWorld: string; marker: string;
  writes: {
    id: string; match: boolean; axis: "matching" | "predicate" | "world" | "actor_class";
    value: { sequence: number; fact: string };
  }[];
  expected: {
    matchingSequences: number[];
    landedEffects: { marker: string; sequence: number; fact: string }[];
  };
  packFiles: Record<string, string>;
}

async function packInput(catalog: FixtureCatalog, entries: Record<string, string>): Promise<Facade.PackPutRequest> {
  return { files: await Promise.all(Object.entries(entries).map(async ([path, id]) => ({
    path, text: new TextDecoder().decode(await catalog.readArchive(id)),
  }))) };
}

// The shared MCP client intentionally returns protocol bodies. This local
// typed envelope reader supplies no authority, retries, paging or verb fallback.
type HookMcpVerb = "vault.packs.put" | "vault.claims.upsert" | "vault.claims.list"
  | "vault.receipts" | "vault.hooks.replay" | "self.actor" | "vault.scope.ceiling"
  | "vault.skill_hubs.put" | "vault.skill_hubs.publishers.admit" | "vault.skill_hubs.publishers.revoke"
  | "vault.packs.install" | "vault.packs.hooks.qualify" | "vault.packs.hooks.bind"
  | "vault.packs.hooks.list" | "vault.packs.hooks.grant.set" | "vault.packs.hooks.grant.get"
  | "vault.gate.policy.get" | "vault.gate.policy.put" | "vault.secrets.register";
interface ToolCatalog {
  tools: { name: string; inputSchema: { properties: { schema_version: { const: string } } } }[];
}
interface ToolReply<T> {
  isError: boolean;
  structuredContent: { output: T; meta: { end: string } };
}
async function mcpCall<V extends HookMcpVerb>(
  client: McpClient, tools: ToolCatalog, verb: V, input: FacadeInput<V>,
): Promise<FacadeResult<V>> {
  const tool = tools.tools.find(item => item.name === verb);
  if (!tool) throw new Error(`Required typed MCP tool is absent: ${verb}`);
  const reply = await client.callTool(verb, {
    schema_version: tool.inputSchema.properties.schema_version.const,
    consent: { policy_ref: "policy:hooks-e2e", purpose: "runtime hook public journey" },
    arguments: { spec: input },
  }) as ToolReply<FacadeResult<V>>;
  expect(reply.isError).toBe(false);
  expect(reply.structuredContent).toBeDefined();
  // Never claim a truncated before/after snapshot as a complete vault read.
  expect(reply.structuredContent.meta.end).toBe("Complete");
  return reply.structuredContent.output;
}
function receiptField(receipt: Facade.MemoryReceipt, name: string): string {
  const value = receipt.fields?.[name];
  if (value === undefined) throw new Error(`Hook receipt lacks ${name}`);
  return value;
}
function byClaimId(rows: Facade.ClaimView[]): Facade.ClaimView[] {
  return [...rows].sort((a, b) => a.claim_ref.localeCompare(b.claim_ref));
}
function byReceiptId(rows: Facade.MemoryReceipt[]): Facade.MemoryReceipt[] {
  return [...rows].sort((a, b) => a.receipt_ref.localeCompare(b.receipt_ref));
}

async function readHookReceipts(
  read: (input: FacadeInput<"vault.receipts">) => Promise<FacadeResult<"vault.receipts">>,
  limit: number,
): Promise<Facade.MemoryReceipt[]> {
  const rows: Facade.MemoryReceipt[] = [];
  let after: string | undefined;
  for (;;) {
    const page = await read({ kinds: ["hook"], limit, ...(after === undefined ? {} : { after }) });
    expect(page.undecodable).toBe(0);
    rows.push(...page.receipts);
    if (page.next_after == null) return rows;
    after = page.next_after;
  }
}
async function readHookReplay(
  read: (input: FacadeInput<"vault.hooks.replay">) => Promise<FacadeResult<"vault.hooks.replay">>,
  binding: string, since: string, limit: number,
): Promise<Facade.HookReplayRow[]> {
  const rows: Facade.HookReplayRow[] = [];
  let cursor: string | undefined;
  for (;;) {
    const page = await read(cursor === undefined ? { binding, since, limit } : { binding, cursor, limit });
    rows.push(...page.rows);
    if (page.done) {
      expect(page.next_cursor == null).toBe(true);
      return rows;
    }
    if (page.next_cursor == null) throw new Error("Incomplete hook replay lacks its next cursor");
    cursor = page.next_cursor;
  }
}

/* HOOKS-01 — OF-579, ARCH-0080 fact-inputs/fact-sources/crash-safety/hook-grant.
 * Use the public owner grant doors and a NEW independent canonical body.js pack.
 * Trigger actor class is not the observer grant's reader_class. The non-owner
 * writer has a real principal and its own paired credential, not a forged actor.
 * All five source receipts are observed before SIGKILL on the same fixture.
 * Pending work at the instant of the kill is not forced or claimed here.
 */
suite.test(test, "HOOKS-01", "Fact hook commit and restart catchup should work", async () => {
  const catalog = await loadFixtures();
  const data = await catalog.readJson<Corpus>("hooks-scenarios");
  const spec = await catalog.readJson<FactCorpus>("hooks-fact-scenario");
  const engine = await EngineFixture.start({ id: "HOOKS-01", profile });
  const owner = engine.pairedActor.principalRef;

  // Create the agent through the stopped-vault CLI, before the journey's crash.
  await engine.client.call("vault.receipts", { limit: 1 });
  await engine.kill();
  const minted = await engine.cli.run([
    "token", "agent", "--name", "hooks-fact-nonmatch", "--tier", "full-access",
    "--config", resolve(engine.root, "oneiron.toml"),
    "--out", resolve(engine.root, "hooks-fact-nonmatch.credential"),
  ], undefined, undefined, true);
  expect(minted.exitCode).toBe(0);
  const principal = JSON.parse(minted.stdout) as { principal_ref: string; actor_class: string };
  expect(principal.principal_ref).toMatch(/^[a-f0-9]{32}$/);
  expect(principal.actor_class).toBe("agent");
  expect(principal.principal_ref).not.toBe(owner);
  await engine.restart();
  const agent = await engine.pairActor({
    principalRef: principal.principal_ref, actorClass: "agent",
    scope: ["core:read", "core:propose", "core:write"],
  });
  const baseScope = await ownerBaseClaimScope(engine.client, owner);
  const installed = await engine.client.call("vault.packs.put", await packInput(catalog, spec.packFiles));
  expect(installed.outcome).toBe("installed");
  expect(installed.receipt?.pack_name).toBe(spec.packName);
  expect(installed.receipt?.status).toBe("active");
  const bindings = (await engine.client.call("vault.packs.hooks.list", {}))
    .filter(row => row.binding.pack === spec.packName && row.binding.hook === spec.hookName);
  expect(bindings).toHaveLength(1);
  const binding = bindings[0]!;
  expect(binding.binding.owner).toBe(owner);
  expect(binding.binding.author).toEqual({ kind: "owner" });
  expect(binding.binding.enabled).toBe(true);
  expect(binding.binding.selector.phase).toBe("fact");
  expect(binding.binding.selector.verbs).toEqual([`claim.landed:${spec.triggerPredicate}`]);
  expect(binding.binding.selector.actors).toEqual(["human"]);
  expect(binding.binding.selector.scope).toBe(`world:${spec.matchingWorld}`);
  const grant: Facade.HookGrant = {
    reader: owner, reader_class: "human",
    predicates: [spec.triggerPredicate], worlds: [spec.matchingWorld],
  };
  expect(await engine.client.call("vault.packs.hooks.grant.set", { binding: binding.id, grant }))
    .toEqual({ binding: binding.id, grant });
  const readGrant = () => engine.client.call("vault.packs.hooks.grant.get", { binding: binding.id });
  expect(await readGrant()).toEqual({ binding: binding.id, grant });

  const matching = spec.writes.filter(row => row.match);
  expect(matching.map(row => row.value.sequence)).toEqual(spec.expected.matchingSequences);
  expect(spec.writes.filter(row => !row.match).map(row => row.axis))
    .toEqual(["predicate", "world", "actor_class"]);
  const sourceReceipts: Facade.MemoryReceipt[] = [];
  for (const row of spec.writes) {
    const writer = row.axis === "actor_class" ? agent : engine.pairedActor;
    const world = row.axis === "world" ? spec.otherWorld : spec.matchingWorld;
    const committed = await writer.client.call("vault.claims.upsert", {
      id: row.id, subject_ref: owner,
      predicate: row.axis === "predicate" ? spec.otherPredicate : spec.triggerPredicate,
      value: row.value, confidence: 1, source: "user_stated",
      scope: { ...baseScope, world_id: world },
    });
    const page = await engine.client.call("vault.receipts", { limit: data.pageBound });
    expect(page.undecodable).toBe(0);
    expect(page.next_after == null).toBe(true);
    const receipt = page.receipts.find(item => item.receipt_ref === committed.receipt_ref);
    expect(receipt).toBeDefined();
    expect(receipt!.outcome).toBe("allow");
    expect(receipt!.actor_ref).toBe(writer.principalRef);
    sourceReceipts.push(receipt!);
  }
  const hookReceipts = async () => (await readHookReceipts(
    input => engine.client.call("vault.receipts", input), data.pageBound,
  )).filter(row => row.fields?.hook === `${spec.packName}/${spec.hookName}`);
  const readEffects = async () => {
    const page = await engine.client.call("vault.claims.list", {
      subject_ref: owner, predicate: spec.outputPredicate, limit: data.pageBound,
    });
    expect(page.value.length).toBeLessThan(data.pageBound);
    return byClaimId(page.value);
  };
  const beforeKill = await hookReceipts();
  await engine.kill();
  await engine.restart();
  expect(await readGrant()).toEqual({ binding: binding.id, grant });
  const receipts = await awaitPublic(hookReceipts, rows => rows.length >= matching.length,
    { label: "HOOKS-01 durable Hook receipts after SIGKILL" });
  expect(receipts).toHaveLength(matching.length);
  const effects = await awaitPublic(readEffects, rows => rows.length >= matching.length,
    { label: "HOOKS-01 one landed effect per matching envelope" });
  expect(effects).toHaveLength(spec.expected.landedEffects.length);
  const ordered = matching.map(row => {
    const found = receipts.filter(receipt => receipt.fields?.trigger_ref === row.id);
    expect(found).toHaveLength(1);
    return found[0]!;
  });
  const positions = ordered.map(row => receiptField(row, "position"));
  for (const position of positions) expect(position).toMatch(/^[a-f0-9]+$/);
  expect(BigInt(`0x${positions[0]!}`) < BigInt(`0x${positions[1]!}`)).toBe(true);
  const runKeys = ordered.map(row => receiptField(row, "run_key"));
  expect(new Set(runKeys).size).toBe(matching.length);
  for (const key of runKeys) expect(key).toMatch(/^[a-f0-9]{64}$/);
  // Positions prove source order; run clocks may tie. No public unique apply
  // sequence exists, so these reads do not claim strict apply serialization.
  const clocks = ordered.map(row => Number(receiptField(row, "now")));
  expect(clocks.every(Number.isSafeInteger)).toBe(true);
  expect(clocks[0]!).toBeLessThanOrEqual(clocks[1]!);
  expect(ordered[0]!.created_at).toBeLessThanOrEqual(ordered[1]!.created_at);
  for (const [index, receipt] of ordered.entries()) {
    expect(receipt.outcome).toBe("propose");
    expect(receipt.actor_ref).toBe(owner);
    expect(receiptField(receipt, "binding")).toBe(binding.id);
    expect(receiptField(receipt, "source")).toBe("claim_changelog");
    expect(receiptField(receipt, "fact")).toBe("claim.landed");
    expect(receiptField(receipt, "hook_version")).toBe(spec.hookVersion);
    const expected = spec.expected.landedEffects[index]!;
    const landed = effects.filter(row => typeof row.value === "object" && row.value !== null
      && "sequence" in row.value && row.value.sequence === expected.sequence);
    expect(landed).toHaveLength(1);
    expect(landed[0]!.value).toEqual(expected);
    expect(landed[0]!.subject_ref).toBe(owner);
    expect(landed[0]!.source).toBe("generated");
    expect(landed[0]!.approval).toBe("proposed");
    // Author is public on the binding and Hook receipt, not made_by on this
    // worker's Proposed row. Value echo and cardinality correlate the two.
  }
  await engine.artifacts.json("fact-commit-restart.json", {
    sourceReceipts, beforeKill, receipts, effects, grant,
    pendingAtKillForced: false,
  });
  await engine.kill();
  await engine.restart();
  expect(await readGrant()).toEqual({ binding: binding.id, grant });
  expect(await readEffects()).toEqual(effects);
  const afterSecond = await hookReceipts();
  expect(afterSecond.map(row => row.receipt_ref).sort())
    .toEqual(receipts.map(row => row.receipt_ref).sort());
  await engine.artifacts.json("fact-second-restart.json", {
    receipts: afterSecond, effects: await readEffects(),
  });
});

suite.test(test, "HOOKS-02", "Hook replay lands nothing should work", async () => {
  const catalog = await loadFixtures();
  const data = await catalog.readJson<Corpus>("hooks-scenarios");
  const spec = data.replay;
  const engine = await EngineFixture.start({ id: "HOOKS-02", profile });
  await engine.mcp.initialize();
  const tools = await engine.mcp.listTools() as ToolCatalog;
  const call = <V extends HookMcpVerb>(verb: V, input: FacadeInput<V>) =>
    mcpCall(engine.mcp, tools, verb, input);
  const subject = engine.pairedActor.principalRef;
  const scope = await ownerBaseClaimScope(engine.client, subject);
  const upsert = (id: string, predicate: string, value: unknown) => call("vault.claims.upsert", {
    id, subject_ref: subject, predicate, value, confidence: 1, source: "user_stated", scope,
  });
  const readClaims = async () => {
    const reply = await call("vault.claims.list", { subject_ref: subject, limit: data.pageBound });
    expect(reply.value.length).toBeLessThan(data.pageBound);
    return byClaimId(reply.value);
  };
  const hookReceipts = async () => {
    const rows = await readHookReceipts(input => call("vault.receipts", input), data.pageBound);
    expect(rows.length).toBeLessThan(data.pageBound);
    return rows.filter(row => row.fields?.hook === `local/${spec.hookName}`);
  };

  await upsert(spec.anchorId, spec.anchorPredicate, spec.anchor);
  const installed = await call("vault.packs.put", await packInput(catalog, spec.packFiles));
  expect(installed.outcome).toBe("installed");
  expect(installed.receipt?.pack_name).toBe("local");
  expect(installed.receipt?.status).toBe("active");
  // Canon lists hooks as subscription claims on CODE, not a private-store read.
  const subscriptions = await call("vault.claims.list", {
    predicate: "agent.connector_subscription", lifecycle: "active", limit: data.pageBound,
  });
  expect(subscriptions.value.length).toBeLessThan(data.pageBound);
  const bindings = subscriptions.value.filter(row => {
    if (typeof row.value !== "string") return false;
    const binding = JSON.parse(row.value) as { pack?: string; hook?: string };
    return binding.pack === "local" && binding.hook === spec.hookName;
  });
  expect(bindings).toHaveLength(1);
  const binding = bindings[0]!.claim_ref;

  // Obtain a real predecessor cursor; never fabricate a zero cursor or use time.
  await upsert(spec.checkpointId, spec.triggerPredicate, { revision: "checkpoint" });
  const checkpointRows = await awaitPublic(hookReceipts,
    rows => rows.some(row => row.fields?.trigger_ref === spec.checkpointId),
    { label: "HOOKS-02 checkpoint Hook receipt" });
  const checkpoint = checkpointRows.find(row => row.fields?.trigger_ref === spec.checkpointId)!;
  expect(checkpoint.outcome).toBe("nothing");
  expect(receiptField(checkpoint, "source")).toBe("claim_changelog");
  const since = `${receiptField(checkpoint, "source")}:${receiptField(checkpoint, "position")}`;

  const beforeDispatch = Date.now();
  await upsert(spec.originalId, spec.triggerPredicate, {
    revision: spec.originalRevision, anchor: spec.anchorId,
  });
  const recordedRows = await awaitPublic(hookReceipts,
    rows => rows.some(row => row.fields?.trigger_ref === spec.originalId),
    { label: "HOOKS-02 original Hook receipt" });
  const afterDispatch = Date.now();
  const recorded = recordedRows.find(row => row.fields?.trigger_ref === spec.originalId)!;
  expect(recorded.outcome).toBe("propose");
  expect(receiptField(recorded, "hook_version")).toBe(spec.hookVersion);
  expect(Number(receiptField(recorded, "rows_read"))).toBeGreaterThan(0);
  const pinnedNow = Number(receiptField(recorded, "now"));
  expect(Number.isSafeInteger(pinnedNow)).toBe(true);
  expect(pinnedNow).toBeGreaterThanOrEqual(Math.floor(beforeDispatch / 1_000) * 1_000);
  expect(pinnedNow).toBeLessThanOrEqual(afterDispatch);
  const expectedValue = {
    marker: spec.marker, revision: spec.originalRevision, anchor: spec.anchor,
    hook_version: spec.hookVersion, now: pinnedNow, clock: pinnedNow,
  };
  const landed = await awaitPublic(readClaims,
    rows => rows.some(row => row.predicate === spec.outputPredicate),
    { label: "HOOKS-02 original proposed effect" });
  const observations = landed.filter(row => row.predicate === spec.outputPredicate);
  expect(observations).toHaveLength(1);
  expect(observations[0]!.value).toEqual(expectedValue);
  expect(observations[0]!.source).toBe("generated");
  expect(observations[0]!.approval).toBe("proposed");

  // Superseding the triggering source changes its stored lifecycle and value
  // history. The separately read anchor stays intact, so history is retained.
  await upsert(spec.correctionId, spec.triggerPredicate, {
    revision: spec.laterRevision, anchor: spec.anchorId,
  });
  const correctedRows = await awaitPublic(hookReceipts,
    rows => rows.some(row => row.fields?.trigger_ref === spec.correctionId),
    { label: "HOOKS-02 correction Hook receipt" });
  expect(correctedRows.find(row => row.fields?.trigger_ref === spec.correctionId)!.outcome).toBe("nothing");
  const before = await readClaims();
  expect(before.find(row => row.claim_ref === spec.originalId)?.lifecycle).toBe("superseded");
  expect(before.find(row => row.claim_ref === spec.correctionId)?.value).toEqual({
    revision: spec.laterRevision, anchor: spec.anchorId,
  });
  const receiptsBefore = byReceiptId(await hookReceipts());
  expect(receiptsBefore).toHaveLength(3);

  // Repeat the actual dry run. Returned Propose is data, not permission to land.
  for (let replay = 0; replay < 2; replay += 1) {
    const rows = await readHookReplay(input => call("vault.hooks.replay", input), binding, since, data.pageBound);
    expect(rows).toHaveLength(2);
    const original = rows.find(row => row.case.on === "fact" && row.case.entity === spec.originalId);
    expect(original).toBeDefined();
    expect(original!.case).toEqual({
      on: "fact", source: "claim_changelog", kind: "claim.landed", entity: spec.originalId,
      position: `claim_changelog:${receiptField(recorded, "position")}`,
    });
    const result = original!.result;
    if (result.status !== "ran") throw new Error("Retained hook inputs must replay, not lose history");
    expect(result.from_memo).toBe(true);
    expect(result.reads_live).toBe(false);
    expect(result.compare).toBe("same");
    expect(result.outcome).toBe("propose");
    expect(result.recorded).toBe("propose");
    const expectedOutcome = { kind: "propose", claim: {
      subject, predicate: spec.outputPredicate, confidence: 1, value: expectedValue,
    } };
    expect(JSON.parse(result.outcome_json!)).toEqual(expectedOutcome);
    expect(JSON.parse(result.recorded_outcome_json!)).toEqual(expectedOutcome);
    const correction = rows.find(row => row.case.on === "fact" && row.case.entity === spec.correctionId);
    expect(correction?.result).toEqual(expect.objectContaining({
      status: "ran", outcome: "nothing", from_memo: true, reads_live: false, compare: "same",
    }));
    expect(await readClaims()).toEqual(before);
    expect(byReceiptId(await hookReceipts())).toEqual(receiptsBefore);
    await engine.artifacts.json(`replay-${replay}.json`, rows);
  }
});

/* HOOKS-03 — OF-580, ARCH-0080 verb-outcomes/ordering/ask-continuation.
 * ClaimScope is row placement; the support slip's typed Scope is the caller
 * ceiling. The owner issues it to a real CLI-created agent, not to himself.
 * Revoke reduces the SAME saved credential to no authority; attenuation would
 * make another instrument. A task answer supplies no effect authority.
 */
suite.test(test, "HOOKS-03", "Before-hook rewrite and durable ask should work", async () => {
  type Carrier = "HTTP" | "MCP";
  type Mode = "allowed" | "invalid" | "world" | "facet" | "project" | "revoked";
  type Input = FacadeInput<"vault.claims.upsert">;
  type Output = FacadeResult<"vault.claims.upsert">;
  interface Case { mode: Mode; id: string; predicate: string }
  interface Control extends Case { phase: "live" | "revoked"; invocation: string }
  interface RewriteCorpus {
    packName: string; hookVersion: string; rewriteHook: string; askHook: string;
    originalFact: string; rewrittenValue: { marker: string; fact: string };
    question: string; otherWorld: string; otherProject: string;
    cases: Record<Carrier, Case[]>; progressControls: Control[];
    packFiles: Record<string, string>;
  }
  interface ErrorBody {
    error: { code: string; message: string; hook?: Facade.VerbHookStop; receiptRef?: string };
  }
  interface HookToolReply {
    isError: boolean;
    structuredContent: { output?: Output; hook?: Facade.VerbHookStop; meta?: { end: string } };
  }
  type Wire = { carrier: "HTTP"; reply: WireReply<Output | ErrorBody> }
    | { carrier: "MCP"; reply: JsonRpcReply<HookToolReply> };
  type Pending = {
    carrier: Carrier; input: Input; row: Case;
    stop: Extract<Facade.VerbHookStop, { status: "pending" }>;
  };
  const catalog = await loadFixtures();
  const common = await catalog.readJson<Corpus>("hooks-scenarios");
  const spec = await catalog.readJson<RewriteCorpus>("hooks-rewrite-ask-scenario");
  const engine = await EngineFixture.start({ id: "HOOKS-03", profile });
  const owner = engine.pairedActor.principalRef;
  await engine.client.call("vault.receipts", { limit: 1 });
  await engine.kill();
  const minted = await engine.cli.run([
    "token", "agent", "--name", "hooks-rewrite-agent", "--tier", "full-access",
    "--config", resolve(engine.root, "oneiron.toml"),
    "--out", resolve(engine.root, "hooks-rewrite-agent.credential"),
  ], undefined, undefined, true);
  expect(minted.exitCode).toBe(0);
  const principal = JSON.parse(minted.stdout) as { principal_ref: string; actor_class: string };
  expect(principal.principal_ref).toMatch(/^[a-f0-9]{32}$/);
  expect(principal.principal_ref).not.toBe(owner);
  expect(principal.actor_class).toBe("agent");
  await engine.restart();
  const agent = await engine.pairActor({
    principalRef: principal.principal_ref, actorClass: "agent",
    scope: ["core:read", "core:propose", "core:write"],
  });
  const position = await ownerBaseClaimScope(engine.client, owner);
  const facets = () => engine.client.call("vault.neighbors", {
    entity_ref: owner, opts: { edge_kind: "has_facet", limit: common.pageBound },
  });
  const facetsBefore = new Set((await facets()).value.map(row => row.short_id));
  await engine.client.call("vault.identity.facet", {
    entity: owner, facets: [{ label: "Rewrite escape fixture facet" }],
    reassignment_map: [], evidence: { refs: [], rationale: "Independent HOOKS-03 row-position oracle" },
  });
  const added = (await facets()).value.filter(row => !facetsBefore.has(row.short_id));
  expect(added).toHaveLength(1);
  const { value: otherFacet } = await engine.client.call("vault.get", { entity_ref: added[0]!.short_id });
  expect(otherFacet?.kind).toBe("FACET");
  if (!otherFacet) throw new Error("Public facet creation returned no readable FACET");
  expect(otherFacet.id_hex).not.toBe(position.scope_facet_id);
  expect(spec.otherWorld).not.toBe(position.world_id);
  expect(spec.otherProject).not.toBe(position.scope_project_id);

  const { seed } = credentialParts(agent.credential);
  const key = createPrivateKey({
    key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.from(seed, "hex")]),
    format: "der", type: "pkcs8",
  });
  const publicKey = createPublicKey(key).export({ format: "der", type: "spki" }).subarray(-32).toString("hex");
  const ceiling: Facade.Scope = {
    worlds: { kind: "some", values: [position.world_id] },
    facets: { kind: "some", values: [position.scope_facet_id] },
    audience: { kind: "some", values: [position.scope_project_id] },
    bands: { kind: "all" }, verbs: { kind: "some", values: ["write"] },
    sensitivity: { kind: "all" },
  };
  const mintSupport = (purpose: string) => engine.client.call("vault.support_grants.mint", {
    holder: principal.principal_ref, holder_class: "agent", holder_key: publicKey,
    scope: ceiling, records: [], purpose,
  });
  const support = await mintSupport("HOOKS-03 scoped rewrite and saved questions");
  const makeCaller = (slip: string) => {
    expect(slip).toMatch(/^v2\.slip\.[a-f0-9]+$/);
    const credential = `v2.cred.${slip.slice("v2.slip.".length)}.${seed}`;
    redactor.add(slip, slip.slice("v2.slip.".length), credential);
    const http = new PublicHttpClient(engine.url, { credential, artifacts: engine.artifacts });
    return { http, mcp: new McpClient(http) };
  };
  const caller = makeCaller(support.slip);
  expect(support.grant.holder).toBe(principal.principal_ref);
  expect(support.grant.holder_class).toBe("agent");
  const verifyCeiling = (value: Facade.CredentialCeiling) => {
    expect(value.kind).toBe("ceiling");
    expect(value.scope.worlds).toEqual(ceiling.worlds);
    expect(value.scope.facets).toEqual(ceiling.facets);
    expect(value.scope.audience).toEqual(ceiling.audience);
    expect(value.scope.bands).toEqual(ceiling.bands);
    expect(value.scope.sensitivity).toEqual(ceiling.sensitivity);
    expect(value.scope.verbs).toEqual({ kind: "some", values: ["read", "write"] });
  };
  const httpActor = await caller.http.call("self.actor", {});
  expect(httpActor.actor_ref).toBe(principal.principal_ref);
  expect(httpActor.actor_class).toBe("agent");
  verifyCeiling(await caller.http.call("vault.scope.ceiling", {}));
  await caller.mcp.initialize();
  const tools = await caller.mcp.listTools() as ToolCatalog;
  const mcpActor = await mcpCall(caller.mcp, tools, "self.actor", {});
  expect(mcpActor.actor_ref).toBe(principal.principal_ref);
  expect(mcpActor.actor_class).toBe("agent");
  verifyCeiling(await mcpCall(caller.mcp, tools, "vault.scope.ceiling", {}));
  const tool = tools.tools.find(item => item.name === "vault.claims.upsert");
  if (!tool) throw new Error("Required vault.claims.upsert MCP tool is absent");
  const schemaVersion = tool.inputSchema.properties.schema_version.const;
  const installed = await engine.client.call("vault.packs.put", await packInput(catalog, spec.packFiles));
  expect(installed.outcome).toBe("installed");
  expect(installed.receipt?.pack_name).toBe(spec.packName);
  expect(installed.receipt?.status).toBe("active");
  const bindings = (await engine.client.call("vault.packs.hooks.list", {}))
    .filter(row => row.binding.pack === spec.packName);
  expect(bindings).toHaveLength(2);
  for (const [name, priority] of [[spec.rewriteHook, 20], [spec.askHook, 10]] as const) {
    const binding = bindings.find(row => row.binding.hook === name);
    expect(binding?.binding.owner).toBe(owner);
    expect(binding?.binding.author).toEqual({ kind: "owner" });
    expect(binding?.binding.selector).toEqual(expect.objectContaining({
      phase: "pre", actors: ["agent"], verbs: ["vault.claims.upsert"], priority,
    }));
  }

  // Explicit metadata preserves the real stopped call. callTool() would mint
  // another invocation; no credentials, asks or result envelopes are invented.
  const call = async (
    actor: ReturnType<typeof makeCaller>, carrier: Carrier, input: Input, invocation: string, ask?: string,
  ): Promise<Wire> => {
    if (carrier === "HTTP") return { carrier, reply: await actor.http.raw<Output | ErrorBody>(
      "POST", "/v1/core/facade/vault.claims.upsert", input,
      { "x-oneiron-invocation": invocation, ...(ask === undefined ? {} : { "x-oneiron-hook-ask": ask }) },
    ) };
    return { carrier, reply: await actor.mcp.rpc<HookToolReply>("tools/call", {
      name: "vault.claims.upsert",
      arguments: {
        schema_version: schemaVersion,
        consent: { policy_ref: "policy:hooks-e2e", purpose: "runtime hook public journey" },
        arguments: { spec: input },
      },
      _meta: { "oneiron/invocation": invocation, ...(ask === undefined ? {} : { hook_ask: ask }) },
    }) };
  };
  const stopOf = (wire: Wire): Facade.VerbHookStop | undefined => {
    if (wire.carrier === "HTTP") return "error" in wire.reply.body ? wire.reply.body.error.hook : undefined;
    return "result" in wire.reply ? wire.reply.result.structuredContent.hook : undefined;
  };
  const pendingOf = (wire: Wire) => {
    const stop = stopOf(wire);
    if (!stop || stop.status !== "pending") throw new Error("Expected the real typed Pending hook stop");
    if (wire.carrier === "HTTP") expect(wire.reply.status).toBe(202);
    else if ("result" in wire.reply) expect(wire.reply.result.isError).toBe(true);
    return stop;
  };
  const outputOf = (wire: Wire): Output => {
    if (wire.carrier === "HTTP") {
      expect(wire.reply.status).toBe(200);
      if ("error" in wire.reply.body) throw new Error("Saved successful call returned a refusal");
      return wire.reply.body;
    }
    if ("error" in wire.reply) throw new Error("Saved successful MCP call returned a protocol refusal");
    expect(wire.reply.result.isError).toBe(false);
    expect(wire.reply.result.structuredContent.meta?.end).toBe("Complete");
    const output = wire.reply.result.structuredContent.output;
    if (!output) throw new Error("Saved successful MCP call has no typed output");
    return output;
  };
  const refusedOf = (wire: Wire, invocation: string) => {
    const stop = stopOf(wire);
    if (!stop || stop.status !== "completed_with_error") throw new Error("Expected the saved call's typed failure");
    expect(stop.invocation).toBe(invocation);
    expect(stop.code).toBe("FORBIDDEN");
    if (wire.carrier === "HTTP") {
      expect(wire.reply.status).toBe(403);
      expect("error" in wire.reply.body && wire.reply.body.error.code).toBe("FORBIDDEN");
    } else if ("result" in wire.reply) expect(wire.reply.result.isError).toBe(true);
    return { invocation: stop.invocation, code: stop.code, message: stop.message, receipt_ref: stop.receipt_ref };
  };
  const inputFor = (row: Case): Input => ({
    id: row.id, subject_ref: owner, predicate: row.predicate, confidence: 1, source: "user_stated",
    scope: position,
    value: { mode: row.mode, fact: spec.originalFact,
      ...(row.mode === "world" ? { target: spec.otherWorld } : {}),
      ...(row.mode === "facet" ? { target: otherFacet.id_hex } : {}),
      ...(row.mode === "project" ? { target: spec.otherProject } : {}),
    },
  });
  const readClaims = async (row: Case) => {
    const page = await engine.client.call("vault.claims.list", {
      subject_ref: owner, predicate: row.predicate, limit: common.pageBound,
    });
    expect(page.value.length).toBeLessThan(common.pageBound);
    return page.value;
  };
  const hookReceipts = async () => (await readHookReceipts(
    input => engine.client.call("vault.receipts", input), common.pageBound,
  )).filter(row => row.fields?.hook === `${spec.packName}/${spec.rewriteHook}`
    || row.fields?.hook === `${spec.packName}/${spec.askHook}`);
  const answers: { invocation: string; ask: string; answer: FacadeResult<"tasks.answer"> }[] = [];
  const answer = async (pending: Pending) => {
    const result = await engine.client.call("tasks.answer", {
      handle: { group_ref: pending.stop.ask }, word: { result_ref: owner, option: "proceed" },
    });
    answers.push({ invocation: pending.stop.invocation, ask: pending.stop.ask, answer: result });
    return result;
  };
  const stopped: Pending[] = [];
  for (const carrier of ["HTTP", "MCP"] as const) {
    expect(spec.cases[carrier].map(row => row.mode)).toEqual(["allowed", "invalid", "world", "facet", "project", "revoked"]);
    for (const row of spec.cases[carrier]) {
      const input = inputFor(row);
      const initial = await call(caller, carrier, input, row.id);
      const stop = pendingOf(initial);
      expect(stop.invocation).toBe(row.id);
      expect(pendingOf(await call(caller, carrier, input, stop.invocation, stop.ask))).toEqual(stop);
      stopped.push({ carrier, input, row, stop });
      await engine.artifacts.json(`rewrite-${carrier}-${row.mode}-pending.json`, initial);
    }
  }
  const beforeKill = await awaitPublic(hookReceipts, rows => rows.length >= stopped.length * 2,
    { label: "HOOKS-03 durable pre-hook runs before SIGKILL" });
  expect(beforeKill).toHaveLength(stopped.length * 2);
  await engine.kill();
  await engine.restart();
  // The live MCP credential re-registers its same fingerprint before any
  // answer can wake the saved MCP calls; a task answer is not a credential.
  await caller.mcp.initialize();
  for (const pending of stopped) {
    expect(pendingOf(await call(caller, pending.carrier, pending.input,
      pending.stop.invocation, pending.stop.ask))).toEqual(pending.stop);
  }

  const live = stopped.filter(pending => pending.row.mode !== "revoked");
  for (const pending of live) await answer(pending);
  for (const pending of live.filter(item => item.row.mode === "allowed" || item.row.mode === "invalid")) {
    const rows = await awaitPublic(() => readClaims(pending.row), rows => rows.length > 0,
      { label: `HOOKS-03 ${pending.carrier} saved effect` });
    expect(rows).toHaveLength(1);
    expect(rows[0]!.claim_ref).toBe(pending.row.id);
    expect(rows[0]!.value).toEqual(pending.row.mode === "invalid" ? pending.input.value : spec.rewrittenValue);
    expect(rows[0]!.confidence).toBe(1);
  }

  // These independent live calls observe runner progress, not a fabricated
  // revoked-call receipt. Invocation keys sort after all original cases.
  const controlSupport = await mintSupport("HOOKS-03 independent live runner progress controls");
  const controlCaller = makeCaller(controlSupport.slip);
  const controls: Pending[] = [];
  const runControl = async (phase: Control["phase"]) => {
    const row = spec.progressControls.find(item => item.phase === phase);
    if (!row) throw new Error(`Missing independent ${phase} progress-control fixture`);
    for (const pending of stopped) expect(row.invocation > pending.stop.invocation).toBe(true);
    const input = inputFor(row);
    const stop = pendingOf(await call(controlCaller, "HTTP", input, row.invocation));
    const pending: Pending = { carrier: "HTTP", input, row, stop };
    controls.push(pending);
    await answer(pending);
    const claims = await awaitPublic(() => readClaims(row), rows => rows.length > 0,
      { label: `HOOKS-03 ${phase} live runner progress` });
    expect(claims).toHaveLength(1);
    expect(claims[0]!.value).toEqual(spec.rewrittenValue);
    const output = outputOf(await call(controlCaller, "HTTP", input, stop.invocation, stop.ask));
    expect(outputOf(await call(controlCaller, "HTTP", input, stop.invocation, stop.ask))).toEqual(output);
    await engine.artifacts.json(`rewrite-${phase}-progress-control.json`, { stop, claims, output });
  };
  await runControl("live");
  const liveResults: unknown[] = [];
  for (const pending of live) {
    const wire = await call(caller, pending.carrier, pending.input, pending.stop.invocation, pending.stop.ask);
    const repeat = await call(caller, pending.carrier, pending.input, pending.stop.invocation, pending.stop.ask);
    if (pending.row.mode === "allowed" || pending.row.mode === "invalid") {
      expect(outputOf(repeat)).toEqual(outputOf(wire));
      expect(await readClaims(pending.row)).toHaveLength(1);
    } else {
      expect(refusedOf(repeat, pending.stop.invocation)).toEqual(refusedOf(wire, pending.stop.invocation));
      expect(await readClaims(pending.row)).toEqual([]);
    }
    liveResults.push({ carrier: pending.carrier, mode: pending.row.mode, stop: pending.stop, wire, repeat });
  }

  const revoked = stopped.filter(pending => pending.row.mode === "revoked");
  const revoke = await engine.client.call("vault.support_grants.revoke", { grant_ref: support.grant.grant_ref });
  expect(revoke.changed).toBe(true);
  expect(revoke.holder).toBe(principal.principal_ref);
  for (const pending of revoked) await answer(pending);
  await runControl("revoked");
  const revokedReplies: unknown[] = [];
  for (const pending of revoked) {
    const wire = await call(caller, pending.carrier, pending.input, pending.stop.invocation, pending.stop.ask);
    if (wire.carrier === "HTTP") expect(wire.reply.status).toBe(401);
    else {
      if (!("error" in wire.reply)) throw new Error("Revoked MCP credential was admitted");
      expect(wire.reply.error.code).toBe(-32001);
      expect((wire.reply.error.data as { kind: string }).kind).toBe("mcp_credential_revoked");
    }
    expect(await readClaims(pending.row)).toEqual([]);
    revokedReplies.push(wire);
  }
  const all = [...stopped, ...controls];
  const receipts = await awaitPublic(hookReceipts, rows => rows.length >= all.length * 2,
    { label: "HOOKS-03 complete per-invocation pre-hook receipts" });
  expect(receipts).toHaveLength(all.length * 2);
  for (const pending of all) {
    const chain = receipts.filter(row => row.fields?.invocation === pending.stop.invocation);
    expect(chain).toHaveLength(2);
    const rewrite = chain.filter(row => row.fields?.hook === `${spec.packName}/${spec.rewriteHook}`);
    const ask = chain.filter(row => row.fields?.hook === `${spec.packName}/${spec.askHook}`);
    expect(rewrite).toHaveLength(1);
    expect(ask).toHaveLength(1);
    expect(rewrite[0]!.outcome).toBe(pending.row.mode === "invalid" ? "refused" : "rewrite");
    expect(ask[0]!.outcome).toBe("ask");
    if (pending.row.mode === "invalid") expect(receiptField(rewrite[0]!, "reason")).toContain("confidence");
    for (const receipt of chain) {
      expect(receipt.actor_ref).toBe(principal.principal_ref);
      expect(receipt.actor_class).toBe("agent");
      expect(receiptField(receipt, "phase")).toBe("pre");
      expect(receiptField(receipt, "hook_version")).toBe(spec.hookVersion);
    }
  }
  expect(answers).toHaveLength(all.length);
  await engine.artifacts.json("rewrite-ask-results.json", {
    principal: principal.principal_ref, position, otherFacet: otherFacet.id_hex,
    grant: support.grant, revoke, answers, beforeKill, receipts, liveResults, revokedReplies,
    progressControls: controls.map(item => item.stop),
    revokedTerminalReceiptObserved: false,
  });
  await engine.kill();
  // stop() awaited the real server captures. A control is not proof of a
  // healthy pass if a target hit a transient drain failure; do not pass on
  // a truncated log or the tail-only diagnostic ring.
  const captures = (await readdir(engine.artifacts.root))
    .filter(name => name.startsWith("server-") && name.endsWith(".json"));
  expect(captures.length).toBeGreaterThan(0);
  for (const name of captures) {
    const capture = JSON.parse(await readFile(resolve(engine.artifacts.root, name), "utf8")) as {
      stdout: string; stderr: string; stdoutTruncated: boolean; stderrTruncated: boolean;
    };
    if (typeof capture.stdout !== "string" || typeof capture.stderr !== "string"
      || capture.stdoutTruncated !== false || capture.stderrTruncated !== false) {
      throw new BlockedDoor("inconclusive HOOKS-03 progress proof: server diagnostics are missing or truncated");
    }
    const diagnostic = `${capture.stdout}\n${capture.stderr}`;
    if (diagnostic.includes("a settled verb hook ask waits for the next pass")
      || diagnostic.includes("settled verb hook asks wait for the next pass")) {
      throw new BlockedDoor("inconclusive HOOKS-03 progress proof: the runner reported a drain failure");
    }
  }
  await engine.restart();
  for (const pending of stopped) {
    const rows = await readClaims(pending.row);
    expect(rows).toHaveLength(pending.row.mode === "allowed" || pending.row.mode === "invalid" ? 1 : 0);
  }
  expect((await hookReceipts()).map(row => row.receipt_ref).sort())
    .toEqual(receipts.map(row => row.receipt_ref).sort());
});

suite.test(test, "HOOKS-04", "After-hook redaction is monotone should work", async () => {
  const catalog = await loadFixtures();
  const data = await catalog.readJson<Corpus>("hooks-scenarios");
  const spec = data.redaction;
  redactor.add(spec.value.private);
  const engine = await EngineFixture.start({ id: "HOOKS-04", profile });
  const subject = engine.pairedActor.principalRef;
  await engine.client.call("vault.claims.upsert", {
    scope: await ownerBaseClaimScope(engine.client, subject),
    id: spec.claimId, subject_ref: subject, predicate: spec.predicate,
    value: spec.value, confidence: 1, source: "user_stated",
  });
  const rawBefore = await engine.client.call("vault.claims.history", { claim_ref: spec.claimId });
  expect(rawBefore.value).toHaveLength(1);
  expect(rawBefore.value[0]!.value).toEqual(spec.value);
  const installed = await engine.client.call("vault.packs.put", await packInput(catalog, spec.packFiles));
  expect(installed.outcome).toBe("installed");
  expect(installed.receipt?.status).toBe("active");

  const caller = await engine.client.call("vault.claims.list", {
    subject_ref: subject, predicate: spec.predicate, lifecycle: "active", limit: data.pageBound,
  });
  expect(caller.value).toHaveLength(1);
  expect(caller.value[0]!.claim_ref).toBe(spec.claimId);
  expect(caller.value[0]!.value).toEqual({ public: spec.value.public });
  expect(JSON.stringify(caller)).not.toContain(spec.value.private);
  // This second named read is outside the hooked verb; it is still a real
  // authenticated, scoped public read, not a raw store or storage decoder.
  const rawAfter = await engine.client.call("vault.claims.history", { claim_ref: spec.claimId });
  expect(rawAfter.value).toEqual(rawBefore.value);
  expect(rawAfter.value[0]!.value).toEqual(spec.value);

  const rows = await readHookReceipts(input => engine.client.call("vault.receipts", input), data.pageBound);
  expect(rows.length).toBeLessThan(data.pageBound);
  const chain = rows.filter(row => row.fields?.verb === "vault.claims.list");
  expect(chain).toHaveLength(2);
  const redacted = chain.find(row => row.fields?.hook === "local/hide-private")!;
  const annotated = chain.find(row => row.fields?.hook === "local/try-restore")!;
  expect(redacted).toBeDefined();
  expect(annotated).toBeDefined();
  expect(redacted.outcome).toBe("redact");
  expect(annotated.outcome).toBe("annotate");
  expect(receiptField(annotated, "note")).toBe(spec.annotation);
  expect(receiptField(redacted, "invocation")).toBe(receiptField(annotated, "invocation"));
  for (const row of chain) {
    expect(row.actor_ref).toBe(subject);
    expect(receiptField(row, "phase")).toBe("post");
    expect(receiptField(row, "body_hash")).toMatch(/^[a-f0-9]{64}$/);
    expect(Number(receiptField(row, "duration_ms"))).toBeGreaterThanOrEqual(0);
  }
  await engine.artifacts.json("redaction-receipts.json", chain);
});

/* HOOKS-05 — Hook sandbox and author scope should work. OF-579.
 * ARCH-0080 hook-world/authority/foreign-hooks; ARCH-0069 handles.
 * Install a pinned foreign pack through the typed catalog, then prove real
 * replay and live input reads before separate file/network/hydration attempts.
 * Hook read grants are filters, not effect authority. A proposal outside its
 * read predicates remains foreign Generated/Proposed, never owner-authorized
 * activation. Inspect Hook and Gate receipts separately. A matching owner
 * control watches proposal outputs to detect an unwanted cascade.
 * Observe durable foreign Ask before revoking that exact publisher grant,
 * restart before answering, and require current-binding refusals and no new
 * foreign effect while an independent owner control advances. The original
 * owner call retains its own authority; no private terminal getter is assumed.
 */
suite.test(test, "HOOKS-05", "Hook sandbox and author scope should work", async () => {
  interface SandboxAuthorScenario {
    version: number;
    packName: string;
    publisherIdentity: string;
    hubId: string;
    cases: { hook: string; predicate: string; expectedBodyOutcome: string }[];
    pendingPredicate: string;
    outputPredicate: string;
    packFiles: Record<string, string>;
    expected: Record<string, unknown>;
    setupConditions: Record<string, string>;
    sourcePins: { page: string; sha256: string }[];
    controlPackFiles: Record<string, string>;
    controlPredicate: string;
    controlOutputPredicate: string;
  }

  const catalog = await loadFixtures();
  const common = await catalog.readJson<Corpus>("hooks-scenarios");
  const spec = await catalog.readJson<SandboxAuthorScenario>("hooks-sandbox-author-scenario-json");
  expect(spec.version).toBe(1);
  expect(spec.cases.map(row => row.hook)).toEqual(
    ["file-attempt", "network-attempt", "secret-attempt", "kind-escape", "offer-marker"]);
  expect(spec.hubId).toMatch(/^[a-f0-9]{32}$/);

  const engine = await EngineFixture.start({ id: "HOOKS-05", profile });
  const artifactsRoot = engine.artifacts.root;
  let stopSink: (() => void) | undefined;
  try {
    const owner = engine.pairedActor.principalRef;
    const baseScope = await ownerBaseClaimScope(engine.client, owner);
    // The MCP leg proves the previously missing typed catalog doors (hub
    // put/admit/install/qualify/bind/list/grant/policy/secrets/revoke). The
    // HTTP leg carries claims polling, tasks, the control pack, the Pending
    // wire (202 handling) and verification reads.
    await engine.mcp.initialize();
    let tools = await engine.mcp.listTools() as ToolCatalog;
    const call = <V extends HookMcpVerb>(verb: V, input: FacadeInput<V>): Promise<FacadeResult<V>> =>
      mcpCall(engine.mcp, tools, verb, input);
    const reinitMcp = async (): Promise<void> => {
      await engine.mcp.initialize();
      tools = await engine.mcp.listTools() as ToolCatalog;
    };

    // The registered secret enters the redactor BEFORE any request that can
    // log it. Every later absence assertion reads UNREDACTED runtime views,
    // before artifact redaction.
    const secretValue = `hooks05-secret-${secretHex(16)}`;
    const secretB64 = Buffer.from(secretValue, "utf8").toString("base64");
    redactor.add(secretValue, secretB64);
    const expectNoSecret = (label: string, value: unknown): void => {
      const text = JSON.stringify(value);
      expect(text).not.toContain(secretValue);
      expect(text).not.toContain(secretB64);
    };
    // Caller-chosen 32-hex claim ids (a106 test namespace): non-hex upsert
    // ids are a native 400 (id_from_optional_hex). Suffixes: seeds 01-05,
    // live 11-15, outside 21, pendings 31-32, controls 41-43, revoke probe 51, safe-live 61-65.
    const hexId = (suffix: string): string => `a10600000000000000000000000000${suffix}`;
    // LOOKED-UP refs drive every downstream match: list by predicate, find
    // the row by its unique value marker, pin claim_ref against the input
    // hex (passthrough proof), return the looked-up ref.
    const lookupClaimRef = async (
      predicate: string, expected: string, match: (value: unknown) => boolean,
    ): Promise<string> => {
      const found = (await readEffects(predicate)).filter(row => match(row.value));
      expect(found).toHaveLength(1);
      expect(found[0]!.claim_ref).toBe(expected);
      return found[0]!.claim_ref;
    };
    const readAllHookReceipts = (): Promise<Facade.MemoryReceipt[]> => readHookReceipts(
      input => engine.client.call("vault.receipts", input), common.pageBound,
    );
    // The owner control selects the output predicate and both actor classes.
    // A parked proposal must not feed it or any other second-generation hook.
    const expectNoCascade = async (effectRows: Facade.ClaimView[]): Promise<void> => {
      const effectRefs = new Set(effectRows.map(row => row.claim_ref));
      const cascades = (await readAllHookReceipts()).filter(
        receipt => effectRefs.has(receipt.fields?.trigger_ref ?? ""));
      expect(cascades).toHaveLength(0);
    };

    const foreignHook = (hook: string): string => `${spec.packName}/${hook}`;
    const readForeignReceipts = async (): Promise<Facade.MemoryReceipt[]> =>
      (await readAllHookReceipts()).filter(row => (row.fields?.hook ?? "").startsWith(`${spec.packName}/`));
    // Honest reuse, not hook receipts: the same pagination helper with
    // kinds overridden to gate (the gate-decision projector,
    // store/gate_receipt.rs). No support-file edit. Field names below
    // come from that projector + family_receipt, never guessed.
    const readGateReceipts = async (): Promise<Facade.MemoryReceipt[]> => readHookReceipts(
      input => engine.client.call("vault.receipts", { ...input, kinds: ["gate"] }),
      common.pageBound,
    );
    // Gate linkage for one LANDED Generated propose: the gate receipt
    // whose claim_ref is the parked row, stamped on the foreign author.
    // Rejected writes roll gate+claim back together (no phantom gate
    // receipt), so failed/kind legs assert NO gate receipt at all.
    const expectGateLink = async (label: string, parked: Facade.ClaimView): Promise<string> => {
      const found = await awaitPublic(readGateReceipts,
        rows => rows.filter(row => row.claim_ref === parked.claim_ref).length >= 1,
        { label: `HOOKS-05 ${label} gate receipt` });
      const linked = found.filter(row => row.claim_ref === parked.claim_ref);
      expect(linked).toHaveLength(1);
      expect(linked[0]!.kind).toBe("gate");
      expect(linked[0]!.receipt_ref.startsWith("gate:")).toBe(true);
      expect(linked[0]!.actor_ref).toBe(publisher);
      expect(typeof linked[0]!.outcome).toBe("string");
      expect(linked[0]!.outcome.length).toBeGreaterThan(0);
      expect(Array.isArray(linked[0]!.reason_codes)).toBe(true);
      expectNoSecret(`hooks05 ${label} gate receipt`, linked[0]);
      return linked[0]!.receipt_ref;
    };
    const readEffects = async (predicate: string): Promise<Facade.ClaimView[]> => {
      const page = await engine.client.call("vault.claims.list", {
        subject_ref: owner, predicate, limit: common.pageBound,
      });
      expect(page.value.length).toBeLessThan(common.pageBound);
      return byClaimId(page.value);
    };
    // Fleet runtime git only: materialize the pinned local hub from fixture
    // bytes. No Git operation runs on the coordinator Mac for this draft.
    const git = async (args: string[], cwd: string): Promise<string> => {
      assertFlowActive();
      const child = Bun.spawn(["git", ...args], { cwd, stdout: "pipe", stderr: "pipe" });
      const [stdout, stderr, code] = await Promise.all([
        new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited,
      ]);
      if (code !== 0) throw new Error(`git ${args.join(" ")} exited ${code}: ${stderr.slice(0, 2000)}`);
      return stdout;
    };
    // Raw Pending wire (HTTP): the typed call() retains 202 PENDING_ASK as an
    // error, so the saved-call roundtrip stays on explicit wire metadata like
    // HOOKS-03. No credentials, asks or result envelopes are invented.
    interface Hooks05PendingError {
      error: { code: string; message: string; hook?: Facade.VerbHookStop; receiptRef?: string };
    }
    type Hooks05PendingWire = WireReply<FacadeResult<"vault.claims.upsert"> | Hooks05PendingError>;
    const callPending = (
      input: FacadeInput<"vault.claims.upsert">, invocation: string, ask?: string,
    ): Promise<Hooks05PendingWire> => engine.client.raw<
      FacadeResult<"vault.claims.upsert"> | Hooks05PendingError
    >("POST", "/v1/core/facade/vault.claims.upsert", input,
      { "x-oneiron-invocation": invocation, ...(ask === undefined ? {} : { "x-oneiron-hook-ask": ask }) });
    const pendingOf = (
      wire: Hooks05PendingWire, invocation: string,
    ): Extract<Facade.VerbHookStop, { status: "pending" }> => {
      expect(wire.status).toBe(202);
      if (!("error" in wire.body)) throw new Error("Expected the real typed Pending hook stop");
      const stop = wire.body.error.hook;
      if (!stop || stop.status !== "pending") throw new Error("Expected the real typed Pending hook stop");
      expect(stop.invocation).toBe(invocation);
      return stop;
    };
    const outputOf = (wire: Hooks05PendingWire): FacadeResult<"vault.claims.upsert"> => {
      expect(wire.status).toBe(200);
      if ("error" in wire.body) throw new Error("Saved successful call returned a refusal");
      return wire.body;
    };
    // Rust EntityNotFound surfaces on the facade wire as NOT_FOUND (never a
    // hook-outcome refusal): the typed current-authority shape for a revoked
    // binding at grant.get / hooks.replay.
    const expectRevoked = async (label: string, work: () => Promise<unknown>): Promise<void> => {
      try {
        await work();
      } catch (error) {
        expect(error).toBeInstanceOf(PublicHttpError);
        expect((error as PublicHttpError).error?.code).toBe("NOT_FOUND");
        return;
      }
      throw new Error(`${label} admitted a revoked binding`);
    };

    // ---- 1. Real LOCAL git hub, explicit admit, pinned Candidate install. ----
    const hubDir = resolve(engine.root, "hooks05-hub");
    await mkdir(hubDir, { recursive: true });
    for (const [rel, id] of Object.entries(spec.packFiles)) {
      const dest = resolve(hubDir, ...rel.split("/"));
      await mkdir(dirname(dest), { recursive: true });
      await writeFile(dest, await catalog.readArchive(id));
    }
    await git(["init"], hubDir);
    await git(["add", "-A"], hubDir);
    await git(["-c", "user.name=hooks05", "-c", "user.email=hooks05@local",
      "commit", "-m", "hooks05 foreign fixture"], hubDir);
    const commitOid = (await git(["rev-parse", "HEAD"], hubDir)).trim().toLowerCase();
    expect(commitOid).toMatch(/^[a-f0-9]{40}$|^[a-f0-9]{64}$/);
    const hubPut = await call("vault.skill_hubs.put", {
      hub: spec.hubId, kind: "git", endpoint: hubDir,
      trust_tier: "untrusted", sync_policy: "pinned-commit",
    });
    expect(hubPut.hub).toBe(spec.hubId);
    expect(hubPut.consent.outcome).toBe("approved");
    const admission = await call("vault.skill_hubs.publishers.admit", {
      hub: spec.hubId, identity: spec.publisherIdentity,
    });
    expect(admission.hub).toBe(spec.hubId);
    expect(admission.identity).toBe(spec.publisherIdentity);
    expect(admission.grant_ref).toMatch(/^[a-f0-9]+$/);
    const installed = await call("vault.packs.install", {
      hub_ref: { hub_id: spec.hubId, ref_string: ".", pin: { type: "commit", value: commitOid } },
      publisher: spec.publisherIdentity,
    });
    expect(installed.outcome).toBe("candidate");
    expect(installed.receipt?.pack_name).toBe(spec.packName);
    expect(installed.receipt?.status).toBe("candidate");
    expect(installed.receipt?.publisher).toBe(spec.publisherIdentity);
    expect(installed.receipt?.hub_id).toBe(spec.hubId);
    expect(installed.receipt?.pin_type).toBe("commit");
    expect(installed.receipt?.pin_value).toBe(commitOid);
    const sourceId = installed.receipt?.source_id;
    if (!sourceId) throw new Error("Candidate install returned no source id");

    // ---- 2. SAFE seed facts + positive native-sandbox qualify replay. ----
    // The grants are set AFTER this replay. A replay witness can only carry
    // real bodies: each fact hook must Ran with outcome nothing on its own
    // safe seed (never unreplayed:true as executed proof); verb hooks take no
    // fact entries, which labels them unreplayed without holding the pack.
    for (const [index, row] of spec.cases.entries()) {
      const committed = await engine.client.call("vault.claims.upsert", {
        id: hexId(`0${index + 1}`), subject_ref: owner, predicate: row.predicate,
        value: { phase: "safe", hook: row.hook }, confidence: 1,
        source: "user_stated", scope: baseScope,
      });
      expect(committed.receipt_ref.length).toBeGreaterThan(0);
    }
    const qualification = await call("vault.packs.hooks.qualify", { source: sourceId });
    expect(qualification.put.outcome).toBe("installed");
    expect(qualification.put.receipt?.pack_name).toBe(spec.packName);
    expect(qualification.put.receipt?.status).toBe("active");
    for (const row of spec.cases) {
      const replay = qualification.replays.find(entry => entry.hook === row.hook);
      if (!replay) throw new Error(`Qualification replayed no hook ${row.hook}`);
      expect(replay.unreplayed).toBe(false);
      expect(replay.entries).toHaveLength(1);
      for (const entry of replay.entries) {
        if (entry.result.status !== "ran") {
          throw new Error(`Safe seed must run, not ${entry.result.status}`);
        }
        expect(entry.result.outcome).toBe("nothing");
      }
    }
    for (const verbHook of ["saved-question", "after-marker"]) {
      const replay = qualification.replays.find(entry => entry.hook === verbHook);
      if (replay === undefined) continue; // native lists fact replays only here
      expect(replay.unreplayed).toBe(true);
      expect(replay.entries).toHaveLength(0);
    }

    // ---- 3. Owner bind; full foreign-author identity vs owner. ----
    const bound = await call("vault.packs.hooks.bind", { pack: spec.packName });
    expect(bound).toHaveLength(7);
    const bindings = (await call("vault.packs.hooks.list", {}))
      .filter(row => row.binding.pack === spec.packName);
    expect(bindings).toHaveLength(7);
    for (const row of bindings) {
      expect(row.binding.owner).toBe(owner);
      const author = row.binding.author;
      if (author.kind !== "foreign_actor") throw new Error("Foreign pack bound without a foreign author");
      expect(author.actor_kind).toBe("skill_publisher");
      expect(author.identity).toBe(spec.publisherIdentity);
      expect(author.hub).toBe(spec.hubId);
      expect(author.grant).toBe(admission.grant_ref);
      expect(author.actor).toMatch(/^[a-f0-9]{32}$/);
      expect(row.binding.body_hash).toMatch(/^[a-f0-9]{64}$/);
      expect(row.binding.enabled).toBe(true);
    }
    const publisherActors = new Set(bindings.map(row => {
      const author = row.binding.author;
      if (author.kind !== "foreign_actor") throw new Error("unreachable: checked above");
      return author.actor;
    }));
    expect(publisherActors.size).toBe(1);
    const publisher = [...publisherActors][0]!;
    expect(publisher).not.toBe(owner);
    // Selector shapes are the bound contract: fact hooks watch their own
    // claim.landed predicate only; verb hooks run pre/post on upsert.
    for (const row of spec.cases) {
      const binding = bindings.find(item => item.binding.hook === row.hook)!;
      expect(binding.binding.selector.phase).toBe("fact");
      expect(binding.binding.selector.verbs).toEqual([`claim.landed:${row.predicate}`]);
      expect(binding.binding.selector.actors).toEqual(["human"]);
      expect(binding.binding.selector.outcomes).toContain("nothing");
    }
    for (const verbHook of ["saved-question", "after-marker"]) {
      const binding = bindings.find(item => item.binding.hook === verbHook)!;
      expect(binding.binding.selector.phase).toBe(verbHook === "saved-question" ? "pre" : "post");
      expect(binding.binding.selector.verbs).toEqual(["vault.claims.upsert"]);
      expect(binding.binding.selector.actors).toEqual(["human"]);
    }

    // ---- 4. Same-actor owner READ grant + ONE Child witness TASK. ----
    // Typed policy roundtrip: read the DEFAULT manifest, append an Agent Auto
    // ceiling plus a narrow scoped READ grant on the EXACT bound foreign actor_ref
    // (actor_ref = actual binding.author.actor, never the CLI token agent),
    // then put under expected_body_hash CAS and re-read. Preserve all prior
    // decoded fields and rows while appending these two exact-actor entries.
    const policyBefore = await call("vault.gate.policy.get", {});
    const defaultView = policyBefore.manifests
      .find(entry => entry.manifest_ref === policyBefore.default_manifest_ref);
    if (!defaultView) throw new Error("Default policy manifest is absent");
    expect(defaultView.trusted).toBe(true);
    const frontierBefore = policyBefore.read_frontier_hash;
    const ceilingRow: Facade.ActorCeiling = {
      actor_class: "agent", actor_ref: publisher, ceiling: "auto",
    };
    const grantRow: Facade.PolicyScopedGrantRow = {
      actor_ref: publisher, effector: "core:read",
      scope: {
        worlds: { kind: "all" }, facets: { kind: "all" },
        bands: { kind: "all" }, audience: { kind: "all" },
        verbs: { kind: "some", values: ["read", "propose"] },
        sensitivity: { kind: "all" },
      },
      receipt_required: false,
    };
    const manifestNext: Facade.PolicyManifest = {
      ...defaultView.manifest,
      actor_ceilings: [...defaultView.manifest.actor_ceilings, ceilingRow],
      scoped_grants: [...(defaultView.manifest.scoped_grants ?? []), grantRow],
    };
    const policyPut = await call("vault.gate.policy.put", {
      manifest_ref: defaultView.manifest_ref,
      expected_body_hash: defaultView.body_hash, manifest: manifestNext,
    });
    expect(typeof policyPut.receipt_ref).toBe("string");
    expect(policyPut.receipt_ref.length).toBeGreaterThan(0);
    expect(typeof policyPut.read_frontier_hash).toBe("string");
    expect(policyPut.read_frontier_hash).not.toBe(frontierBefore);
    const policyAfter = await call("vault.gate.policy.get", {});
    const defaultAfter = policyAfter.manifests
      .find(entry => entry.manifest_ref === policyAfter.default_manifest_ref);
    if (!defaultAfter) throw new Error("Default policy manifest is absent after put");
    // Whole-manifest equality: every field and row must roundtrip, not a
    // picked subset. This is decoded-view equality (the native encoder
    // preserves the untouched tables); it is not a MessagePack byte proof.
    expect(defaultAfter.manifest).toEqual(manifestNext);
    // A single owner-created Standard TASK (Child assignee) admits the bound
    // publisher as a verified agent principal. Uniqueness is ONE human OWNER
    // principal, not exactly-one-TASK: the witness TASK is safe, and asking
    // refuses only when a second principal is found instead of the owner.
    const witness = await engine.client.call("tasks.create", {
      spec: {
        title: "HOOKS-05 foreign witness",
        description: "Owner-assigned Standard TASK admitting the bound foreign publisher as Agent.",
        lane: "hooks05",
      },
      label: "hooks05-witness",
      assignee: { child: { actor_ref: publisher } },
    });
    expect(witness.task_ref).toBeDefined();
    expect(witness.proposal_ref ?? null).toBeNull();
    expect(witness.approval).toBe("auto");
    expect(witness.effected).toBe(true);
    expect(witness.route).toEqual({ ChildAddressed: { actor_ref: publisher } });

    // ---- 5. Manual per-binding HookGrants: ADDED read filters, not effect authority. ----
    // Read checks require an access grant on the READER and then filter its
    // reads through the HookGrant; the grants below keep the publisher reader
    // narrow (trigger namespaces + base world) and never substitute for the
    // author effect authority asserted at the apply/gate legs.
    const grantPredicates = [...spec.cases.map(row => row.predicate), spec.pendingPredicate];
    const manualGrant: Facade.HookGrant = {
      reader: publisher, reader_class: "agent",
      predicates: grantPredicates, worlds: [baseScope.world_id],
    };
    for (const row of bindings) {
      expect(await call("vault.packs.hooks.grant.set", { binding: row.id, grant: manualGrant }))
        .toEqual({ binding: row.id, grant: manualGrant });
    }
    for (const row of bindings) {
      expect(await call("vault.packs.hooks.grant.get", { binding: row.id }))
        .toEqual({ binding: row.id, grant: manualGrant });
    }

    // ---- 6. Device-bound secret, outside claim, owner-local control. ----
    const registered = await call("vault.secrets.register", {
      name: "hooks05-sandbox-secret", class: "custody-device-bound",
      rung: 2, device_only: true, value_base64: secretB64,
    });
    expect(typeof registered.secret_id).toBe("string");
    expect(registered.secret_id.length).toBeGreaterThan(0);
    expect(registered.device_only).toBe(true);
    expect(registered.name).toBe("hooks05-sandbox-secret");
    expect(registered.class).toBe("custody-device-bound");
    const secretHandle = registered.secret_id;
    // The outside claim is deliberately OUTSIDE the HookGrant predicate set:
    // the offer leg must read it back WITHHELD, proving predicate filtering.
    const outsideHex = hexId("21");
    await engine.client.call("vault.claims.upsert", {
      id: outsideHex, subject_ref: owner, predicate: "hooks05.unrelated",
      value: { note: "outside the hook read grant" }, confidence: 1,
      source: "user_stated", scope: baseScope,
    });
    // The guest read needs the actual entity hex (EntityId::from_hex throws
    // on anything else): look it up, pin it, pass the looked-up ref.
    const outsideRef = await lookupClaimRef("hooks05.unrelated", outsideHex,
      value => (value as { note?: unknown })?.note === "outside the hook read grant");
    // The owner-local control rides plain packs.put (owner authorship) and
    // only proves the runner is alive: before, between and after the revoke.
    const controlPut = await engine.client.call("vault.packs.put", await packInput(catalog, spec.controlPackFiles));
    expect(controlPut.outcome).toBe("installed");
    const controlRows = (await engine.client.call("vault.packs.hooks.list", {}))
      .filter(row => row.binding.hook === "progress-control");
    expect(controlRows).toHaveLength(1);
    expect(controlRows[0]!.binding.pack).toBe("local");
    expect(controlRows[0]!.binding.author).toEqual({ kind: "owner" });
    expect(controlRows[0]!.binding.selector.verbs).toEqual([
      `claim.landed:${spec.controlPredicate}`, `claim.landed:${spec.outputPredicate}`,
    ]);
    expect(controlRows[0]!.binding.selector.actors).toHaveLength(2);
    expect(controlRows[0]!.binding.selector.actors).toEqual(expect.arrayContaining(["human", "agent"]));
    const controlObserved = (): Promise<Facade.ClaimView[]> => readEffects(spec.controlOutputPredicate);
    await engine.client.call("vault.claims.upsert", {
      id: hexId("41"), subject_ref: owner, predicate: spec.controlPredicate,
      value: { phase: "baseline" }, confidence: 1, source: "user_stated", scope: baseScope,
    });
    const baseline = await awaitPublic(controlObserved, rows => rows.length >= 1,
      { label: "HOOKS-05 control baseline progress" });
    expect(baseline).toHaveLength(1);
    expect(baseline[0]!.value).toMatchObject({ marker: "violet-owner-progress", phase: "baseline" });
    expect(baseline[0]!.source).toBe("generated");
    expect(baseline[0]!.approval).toBe("proposed");

    // ---- 6b. Live post-grant readability controls (safe phase, bound hooks). ----
    // AFTER the owner policy read grant + manual HookGrants, five MORE safe
    // facts prove the LIVE publisher inputs are actually readable through
    // the installed grants (per-case Nothing receipt, publisher stamp,
    // correct trigger) BEFORE the malicious branches run. Distinct from
    // the §2 qualify seeds (pre-bind positive replay proof). This is what
    // makes each malicious Failed + nonempty reason meaningful without
    // asserting brittle VM diagnostic tokens.
    const safeLiveHex = new Map(spec.cases.map((row, index) => [row.hook, hexId(`6${index + 1}`)]));
    for (const row of spec.cases) {
      await engine.client.call("vault.claims.upsert", {
        id: safeLiveHex.get(row.hook)!, subject_ref: owner, predicate: row.predicate,
        value: { phase: "safe", hook: row.hook, control: "live-readable" }, confidence: 1,
        source: "user_stated", scope: baseScope,
      });
    }
    const safeLiveTriggerRef = new Map<string, string>();
    for (const row of spec.cases) {
      safeLiveTriggerRef.set(row.hook, await lookupClaimRef(row.predicate, safeLiveHex.get(row.hook)!,
        value => (value as { control?: unknown })?.control === "live-readable"));
    }
    const safeLiveReceipts = await awaitPublic(readForeignReceipts, rows =>
      spec.cases.every(row => rows.some(
        receipt => receipt.fields?.trigger_ref === safeLiveTriggerRef.get(row.hook))),
      { label: "HOOKS-05 live readability receipts" });
    for (const row of spec.cases) {
      const found = safeLiveReceipts.filter(
        receipt => receipt.fields?.trigger_ref === safeLiveTriggerRef.get(row.hook));
      expect(found).toHaveLength(1);
      expect(found[0]!.outcome).toBe("nothing");
      expect(found[0]!.actor_ref).toBe(publisher);
      expect(receiptField(found[0]!, "hook")).toBe(foreignHook(row.hook));
    }

    // ---- 7. Live sandbox attempts, kind refusal and guarded foreign proposal. ----
    // All targets are local/synthetic: a vault-adjacent sentinel file, a
    // loopback sink, and the device-bound handle (never its value).
    const sinkHits: string[] = [];
    assertFlowActive();
    const sink = Bun.serve({
      hostname: "127.0.0.1", port: 0,
      fetch: (request) => { sinkHits.push(request.url); return new Response("hooks05-sink"); },
    });
    stopSink = () => sink.stop(true);
    const sinkPort = sink.port;
    if (sinkPort === undefined || !(sinkPort > 0)) throw new Error("Loopback sink bound no port");
    const sinkUrl = `http://127.0.0.1:${sinkPort}/hook-probe`;
    const sentinelPath = resolve(engine.root, "hooks05-sentinel", "sentinel.txt");
    const sentinelText = "hooks05-sentinel-v1: the hook sandbox must never touch this file.\n";
    await mkdir(dirname(sentinelPath), { recursive: true });
    await writeFile(sentinelPath, sentinelText);
    const liveValues: Record<string, unknown> = {
      "file-attempt": { phase: "live", path: sentinelPath },
      "network-attempt": { phase: "live", url: sinkUrl },
      "secret-attempt": { phase: "live", handle: secretHandle },
      "kind-escape": { phase: "live" },
      "offer-marker": { phase: "live", outsideClaim: outsideRef, handle: secretHandle },
    };
    const liveHex = new Map(spec.cases.map((row, index) => [row.hook, hexId(`1${index + 1}`)]));
    for (const row of spec.cases) {
      await engine.client.call("vault.claims.upsert", {
        id: liveHex.get(row.hook)!, subject_ref: owner, predicate: row.predicate,
        value: liveValues[row.hook], confidence: 1,
        source: "user_stated", scope: baseScope,
      });
    }
    // Receipt matching uses looked-up trigger refs (fact trigger_ref is the
    // trigger claim's entity hex), pinned against the input hex ids.
    const liveTriggerRef = new Map<string, string>();
    for (const row of spec.cases) {
      liveTriggerRef.set(row.hook, await lookupClaimRef(row.predicate, liveHex.get(row.hook)!,
        value => (value as { phase?: unknown })?.phase === "live"));
    }
    const liveReceipts = await awaitPublic(readForeignReceipts, rows =>
      spec.cases.every(row => rows.some(
        receipt => receipt.fields?.trigger_ref === liveTriggerRef.get(row.hook))),
      { label: "HOOKS-05 live fact-hook receipts" });
    const receiptFor = (hook: string): Facade.MemoryReceipt => {
      const found = liveReceipts.filter(
        receipt => receipt.fields?.trigger_ref === liveTriggerRef.get(hook));
      expect(found).toHaveLength(1);
      return found[0]!;
    };
    // Capability legs: each real attempt fails natively inside the sandbox
    // (require/fetch/hydrate are absent globals), stamped on the FOREIGN
    // author, with no effect row, no outbound hit, no file touch and no
    // secret bytes anywhere in the receipt. The reason is asserted
    // NONEMPTY only: exact VM TypeError/ReferenceError text (property
    // names included or not) is not a guaranteed public contract. That
    // these same publisher inputs are genuinely readable is proven
    // positively by the §6b live controls, not by diagnostic wording.
    const failedCase = (hook: string): void => {
      const receipt = receiptFor(hook);
      expect(receipt.outcome).toBe("failed");
      expect(receipt.actor_ref).toBe(publisher);
      expect(receiptField(receipt, "hook")).toBe(foreignHook(hook));
      expect(receiptField(receipt, "hook_version")).toBe("1.0.0");
      expect(receiptField(receipt, "fact")).toBe("claim.landed");
      expect(receiptField(receipt, "source")).toBe("claim_changelog");
      expect(receiptField(receipt, "reason").length).toBeGreaterThan(0);
      expectNoSecret(`hooks05 ${hook} receipt`, receipt);
    };
    failedCase("file-attempt");
    failedCase("network-attempt");
    failedCase("secret-attempt");
    // Leg B (kind-escape): the binding never granted propose, so the outcome
    // kind itself refuses. This is an OUTCOME-KIND check, not author scope.
    const kindReceipt = receiptFor("kind-escape");
    expect(kindReceipt.outcome).toBe("refused");
    expect(kindReceipt.actor_ref).toBe(publisher);
    expect(receiptField(kindReceipt, "hook")).toBe(foreignHook("kind-escape"));
    expect(receiptField(kindReceipt, "reason")).toContain("does not allow propose");
    // The output predicate is outside the hook's read filter. That filter
    // does not grant writes: this valid foreign offer must stay Proposed,
    // carry only the handle and expose none of the withheld claim's body.
    expect(grantPredicates).not.toContain(spec.outputPredicate);
    const offerReceipt = receiptFor("offer-marker");
    expect(offerReceipt.outcome).toBe("propose");
    expect(offerReceipt.actor_ref).toBe(publisher);
    const offers = await awaitPublic(() => readEffects(spec.outputPredicate), rows => rows.length >= 1,
      { label: "HOOKS-05 offer parked proposal" });
    expect(offers).toHaveLength(1);
    expect(offers[0]!.source).toBe("generated");
    expect(offers[0]!.approval).toBe("proposed");
    const offerValue = offers[0]!.value as { marker?: unknown; handle?: unknown; withheld?: unknown };
    expect(offerValue.marker).toBe("violet-author-offer");
    expect(offerValue.handle).toBe(secretHandle);
    expect("withheld" in offerValue).toBe(true);
    expect(offerValue.withheld).toBeNull();
    expectNoSecret("hooks05 offer value", offerValue);
    expectNoSecret("hooks05 offer row", offers[0]);
    // Approval, not lifecycle, distinguishes the parked offer from an
    // authoritative write. The ordinary guarded writer stamps it Generated
    // and Proposed; do not invent a Deny or equate Hook Propose with apply.
    expect(offers.map(row => row.approval)).toEqual(["proposed"]);
    const gateOffer = await expectGateLink("offer parked", offers[0]!);
    await expectNoCascade(offers);
    expect(sinkHits).toHaveLength(0);
    expect(await readFile(sentinelPath, "utf8")).toBe(sentinelText);
    expectNoSecret("hooks05 live receipts", liveReceipts);
    const journeyMeta: Record<string, unknown> = {
      hub: spec.hubId, publisher, grantRef: admission.grant_ref, commit: commitOid,
      qualification: qualification.replays.map(entry => ({
        hook: entry.hook, entries: entry.entries.length, unreplayed: entry.unreplayed,
      })),
      grants: bindings.map(row => ({ binding: row.id, grant: manualGrant })),
      witness: { task: witness.task_ref, approval: witness.approval, route: witness.route },
      liveReceipts: liveReceipts.map(row => row.receipt_ref), safeLive: [...safeLiveTriggerRef.values()],
      offerRef: offers[0]!.claim_ref, gateOffer,
      sinkHits: sinkHits.length, sentinel: "unchanged",
    };
    expectNoSecret("hooks05 journey metadata", journeyMeta);
    await engine.artifacts.json("hooks05-live-attempts.json", journeyMeta);

    // ---- 8. Durable foreign pre-Ask across restart (live authority). ----
    // The upsert asks on the FIRST call, returns the SAME Pending on retry
    // and after restart, resumes exactly once on the owner answer, and stays
    // repeat-stable: the durable-pending oracle with an actual public
    // ordering witness (never a post-revoke trigger as pre-revoke proof).
    const pendingInput = (id: string, invocation: string): FacadeInput<"vault.claims.upsert"> => ({
      id, subject_ref: owner, predicate: spec.pendingPredicate,
      value: { invocation }, confidence: 1, source: "user_stated", scope: baseScope,
    });
    const pendingHex01 = hexId("31");
    const pendingHex02 = hexId("32");
    const invocation01 = "05000000000000000000000000000001";
    const stop01 = pendingOf(await callPending(pendingInput(pendingHex01, invocation01), invocation01), invocation01);
    expect(pendingOf(await callPending(pendingInput(pendingHex01, invocation01), invocation01, stop01.ask), invocation01))
      .toEqual(stop01);
    await engine.restart();
    await reinitMcp();
    expect(pendingOf(await callPending(pendingInput(pendingHex01, invocation01), invocation01, stop01.ask), invocation01))
      .toEqual(stop01);
    const answer01 = await engine.client.call("tasks.answer", {
      handle: { group_ref: stop01.ask }, word: { result_ref: owner, option: "proceed" },
    });
    expect(answer01.task_ref.length).toBeGreaterThan(0);
    const resumed01 = outputOf(await callPending(pendingInput(pendingHex01, invocation01), invocation01, stop01.ask));
    expect(outputOf(await callPending(pendingInput(pendingHex01, invocation01), invocation01, stop01.ask)))
      .toEqual(resumed01);
    const effects01 = await awaitPublic(() => readEffects(spec.outputPredicate),
      rows => rows.some(row => (row.value as { invocation?: unknown })?.invocation === invocation01),
      { label: "HOOKS-05 live post-answer foreign effect" });
    const after01 = effects01.filter(
      row => (row.value as { invocation?: unknown })?.invocation === invocation01);
    expect(after01).toHaveLength(1);
    expect(after01[0]!.source).toBe("generated");
    expect(after01[0]!.approval).toBe("proposed");
    expect(after01[0]!.value).toMatchObject({ marker: "violet-after-answer", invocation: invocation01 });
    expect(effects01.map(row => row.approval)).toEqual(["proposed", "proposed"]);
    const gateAfter01 = await expectGateLink("after-answer parked", after01[0]!);
    await expectNoCascade(effects01);
    const chain01 = await awaitPublic(
      async () => (await readForeignReceipts())
        .filter(row => row.fields?.invocation === invocation01),
      rows => rows.length >= 2, { label: "HOOKS-05 live pending verb receipts" });
    expect(chain01).toHaveLength(2);
    const ask01 = chain01.filter(row => row.fields?.hook === foreignHook("saved-question"));
    const post01 = chain01.filter(row => row.fields?.hook === foreignHook("after-marker"));
    expect(ask01).toHaveLength(1);
    expect(post01).toHaveLength(1);
    expect(ask01[0]!.outcome).toBe("ask");
    expect(post01[0]!.outcome).toBe("propose");
    for (const receipt of chain01) {
      expect(receipt.actor_ref).toBe(publisher);
      expect(receipt.fields?.on_behalf_of).toBe(owner);
      expect(receiptField(receipt, "hook_version")).toBe("1.0.0");
    }
    expect(receiptField(ask01[0]!, "phase")).toBe("pre");
    expect(receiptField(post01[0]!, "phase")).toBe("post");
    await engine.client.call("vault.claims.upsert", {
      id: hexId("42"), subject_ref: owner, predicate: spec.controlPredicate,
      value: { phase: "live-01" }, confidence: 1, source: "user_stated", scope: baseScope,
    });
    await awaitPublic(controlObserved, rows => rows.length >= 2,
      { label: "HOOKS-05 live-phase control progress" });

    // ---- 9. Second Pending BEFORE the exact admit-grant revoke; restart; owner resumes. ----
    // Revoke-then-answer ordering is the durable-pending oracle for the
    // REVOKED leg: the ask predates the revoke, the answer postdates the
    // restart, and current authority rechecks at resume.
    const invocation02 = "05000000000000000000000000000002";
    const stop02 = pendingOf(await callPending(pendingInput(pendingHex02, invocation02), invocation02), invocation02);
    await awaitPublic(
      async () => (await readForeignReceipts())
        .filter(row => row.fields?.invocation === invocation02),
      rows => rows.length >= 1, { label: "HOOKS-05 second ask receipt before revoke" });
    const foreignBeforeRevoke = await readForeignReceipts();
    const effectsBeforeRevoke = await readEffects(spec.outputPredicate);
    const revoke = await call("vault.skill_hubs.publishers.revoke", {
      hub: spec.hubId, identity: spec.publisherIdentity,
    });
    expect(revoke.outcome).toBe("revoked");
    expect(revoke.decision).toMatch(/^[a-f0-9]+$/);
    expect(revoke.grant_ref).toBe(admission.grant_ref);
    await engine.restart();
    await reinitMcp();
    // Current-authority refusals on the KNOWN prior binding ids: the public
    // doors enumerate CURRENT live bindings (an inactive foreign grant drops
    // out even if its manual HookGrant row persists), so grant.get and
    // hooks.replay on a revoked id return Rust EntityNotFound, wire NOT_FOUND.
    // This is a known-prior-binding absence, not a Gate write-Deny and not an
    // exact saved-intent terminal; no further reason code is asserted.
    const liveAfter = await engine.client.call("vault.packs.hooks.list", {});
    expect(liveAfter.filter(row => row.binding.pack === spec.packName)).toHaveLength(0);
    expect(liveAfter.filter(row => row.binding.hook === "progress-control")).toHaveLength(1);
    const revokedBinding = bindings[0]!.id;
    await expectRevoked("grant.get",
      () => engine.client.call("vault.packs.hooks.grant.get", { binding: revokedBinding }));
    await expectRevoked("hooks.replay",
      () => engine.client.call("vault.hooks.replay", { binding: revokedBinding, limit: common.pageBound }));
    // The saved ask is durable across the revoke; the owner answers; the
    // OWNER caller resumes under its own independent authority (no invented
    // cancellation), while the revoked pack proposes nothing further.
    expect(pendingOf(await callPending(pendingInput(pendingHex02, invocation02), invocation02, stop02.ask), invocation02))
      .toEqual(stop02);
    await engine.client.call("tasks.answer", {
      handle: { group_ref: stop02.ask }, word: { result_ref: owner, option: "proceed" },
    });
    const resumed02 = outputOf(await callPending(pendingInput(pendingHex02, invocation02), invocation02, stop02.ask));
    expect(resumed02.claim_short_id.length).toBeGreaterThan(0);
    const pendingRef01 = await lookupClaimRef(spec.pendingPredicate, pendingHex01,
      value => (value as { invocation?: unknown })?.invocation === invocation01);
    const pendingRef02 = await lookupClaimRef(spec.pendingPredicate, pendingHex02,
      value => (value as { invocation?: unknown })?.invocation === invocation02);
    expect([pendingRef01, pendingRef02].sort()).toEqual([pendingHex01, pendingHex02].sort());
    // Binding-liveness exclusion (distinct from the pending oracle above):
    // a trigger on the revoked pack's own offer predicate runs nothing —
    // the apply-time live+enabled+author check has no binding to run —
    // while the control beside it proves the runner is alive.
    const offerPredicate = spec.cases.find(row => row.hook === "offer-marker")!.predicate;
    const probeHex = hexId("51");
    await engine.client.call("vault.claims.upsert", {
      id: probeHex, subject_ref: owner, predicate: offerPredicate,
      value: { phase: "live", probe: "revoked-exclusion", outsideClaim: outsideRef, handle: secretHandle },
      confidence: 1, source: "user_stated", scope: baseScope,
    });
    const probeRef = await lookupClaimRef(offerPredicate, probeHex,
      value => (value as { probe?: unknown })?.probe === "revoked-exclusion");
    // Positive progress under revoked authority comes from the owner-local
    // control: absence of a revoked foreign effect is only meaningful while
    // the runner provably advances something else.
    await engine.client.call("vault.claims.upsert", {
      id: hexId("43"), subject_ref: owner, predicate: spec.controlPredicate,
      value: { phase: "revoked-02" }, confidence: 1, source: "user_stated", scope: baseScope,
    });
    await awaitPublic(controlObserved, rows => rows.length >= 3,
      { label: "HOOKS-05 post-revoke control progress" });
    const foreignAfterProbe = await readForeignReceipts();
    expect(foreignAfterProbe.filter(
      receipt => receipt.fields?.trigger_ref === probeRef)).toHaveLength(0);
    const effectsAfter = await readEffects(spec.outputPredicate);
    expect(effectsAfter.filter(
      row => (row.value as { probe?: unknown })?.probe === "revoked-exclusion")).toHaveLength(0);
    expect(effectsAfter.map(row => row.claim_ref).sort())
      .toEqual(effectsBeforeRevoke.map(row => row.claim_ref).sort());
    expect(effectsAfter.filter(
      row => (row.value as { invocation?: unknown })?.invocation === invocation02)).toHaveLength(0);
    const foreignAfter = await readForeignReceipts();
    expect(foreignAfter.map(row => row.receipt_ref).sort())
      .toEqual(foreignBeforeRevoke.map(row => row.receipt_ref).sort());
    expect(foreignAfter.filter(row =>
      row.fields?.invocation === invocation02 && row.fields?.hook === foreignHook("after-marker")))
      .toHaveLength(0);
    await expectNoCascade(effectsAfter);
    expect(sinkHits).toHaveLength(0);
    expect(await readFile(sentinelPath, "utf8")).toBe(sentinelText);
    expectNoSecret("hooks05 post-revoke views", { effectsAfter, foreignAfter });
    journeyMeta.pending01 = { ask: stop01.ask, answer: answer01.task_ref, effect: after01[0]!.claim_ref, gate: gateAfter01 };
    journeyMeta.pending02 = { ask: stop02.ask, resumed: resumed02.claim_short_id };
    journeyMeta.revoke = { outcome: revoke.outcome, grant_ref: revoke.grant_ref };
    journeyMeta.revokedTerminalReceiptObserved = false;
    expectNoSecret("hooks05 journey metadata", journeyMeta);
    await engine.artifacts.json("hooks05-journey.json", journeyMeta);
  } finally {
    stopSink?.();
    await engine.close();
  }

  // ---- 10. Positive progress is proven only by complete diagnostics. ----
  // Missing/truncated server captures or a drain warning make the run
  // inconclusive (BlockedDoor), never a pass.
  let captureNames: string[];
  try {
    captureNames = (await readdir(artifactsRoot))
      .filter(name => name.startsWith("server-") && name.endsWith(".json"));
  } catch {
    throw new BlockedDoor("inconclusive HOOKS-05 progress proof: server diagnostics are missing");
  }
  if (captureNames.length === 0) {
    throw new BlockedDoor("inconclusive HOOKS-05 progress proof: server diagnostics are missing");
  }
  for (const name of captureNames) {
    const capture = JSON.parse(await readFile(resolve(artifactsRoot, name), "utf8")) as {
      stdout: string; stderr: string; stdoutTruncated: boolean; stderrTruncated: boolean;
    };
    if (typeof capture.stdout !== "string" || typeof capture.stderr !== "string"
      || capture.stdoutTruncated !== false || capture.stderrTruncated !== false) {
      throw new BlockedDoor("inconclusive HOOKS-05 progress proof: server diagnostics are missing or truncated");
    }
    const diagnostic = `${capture.stdout}\n${capture.stderr}`;
    if (diagnostic.trim().length === 0) {
      throw new BlockedDoor("inconclusive HOOKS-05 progress proof: server diagnostics are empty");
    }
    if (diagnostic.includes("a settled verb hook ask waits for the next pass")
      || diagnostic.includes("settled verb hook asks wait for the next pass")) {
      throw new BlockedDoor("inconclusive HOOKS-05 progress proof: the runner reported a drain failure");
    }
  }
});

/* HOOKS-06 — OF-581, ARCH-0080 host-verbs/verb-outcomes.
 * A real public sitting owns three newly witnessed windows. Independent
 * replies exercise the native compaction gate and the native spend meter.
 * The child has a pinned 8000-unit budget; the provider declares 8320 units.
 * These are fixture inputs, not engine defaults or inferred prompt usage.
 */
interface HostHookCorpus {
  packName: string;
  hookNames: { compact: string; wake: string; budget: string };
  conversationId: string;
  oldPin: string;
  addedPin: string;
  quietReason: string;
  pageBound: number;
  tokenCeiling: number;
  budget: { intentKey: string; need: string; prompt: string; capUnits: number;
    inputTokens: number; outputTokens: number; spentUnits: number; taskTitle: string };
  compactCases: { mode: "skip" | "add" | "remove"; turnNumber: number; turnId: string;
    messageId: string; content: string; tokens: number; expectedPins: string[]; expectedSummary: string }[];
  packFiles: Record<string, string>;
  prompts: { packagePath: string; wire: string; compaction: string };
  calls: { chatProvider: string; chatModel: string; compactProvider: string;
    compactModel: string; revision: string };
}

suite.test(test, "HOOKS-06", "Host compaction wake and budget hooks should work", async () => {
  const { ScriptedProviders, openaiText } = await import("./support/providers.ts");
  const catalog = await loadFixtures();
  const spec = await catalog.readJson<HostHookCorpus>("hooks-host-scenario");
  const providers = await ScriptedProviders.start({ id: "hooks06-host", steps: [
    ...spec.compactCases.map(row => ({
      id: `hooks06-compact-${row.mode}`, origin: "compact", role: "checker",
      purpose: `native host compact ${row.mode}`,
      request: { method: "POST" as const, path: "/v1/chat/completions", model: spec.calls.compactModel },
      response: openaiText(`hooks06-compact-${row.mode}`, spec.calls.compactModel,
        JSON.stringify({ from: row.turnNumber, through: row.turnNumber, summary: row.expectedSummary }),
        { inputTokens: 512, outputTokens: spec.tokenCeiling }),
    })),
    {
      id: "hooks06-budget-first", origin: "chat", role: "generative_reasoner",
      purpose: "native child first step charges its declared usage",
      request: { method: "POST", path: "/v1/chat/completions", model: spec.calls.chatModel },
      // The executor's wire is bare JavaScript. This valid no-effect step
      // ends normally; the following admission meets the already-spent cap.
      response: openaiText("hooks06-budget-first", spec.calls.chatModel, "0;", {
        inputTokens: spec.budget.inputTokens, outputTokens: spec.budget.outputTokens,
      }),
    },
  ] });
  const model = `${spec.calls.chatProvider}/${spec.calls.chatModel}@${spec.calls.revision}`;
  const engine = await EngineFixture.start({ id: "HOOKS-06", profile, serverConfig: `
[models]
extraction_egress = true
[models.providers.${spec.calls.chatProvider}]
kind = "openai-compat"
base_url = "${providers.urls.chat}"
revision = "${spec.calls.revision}"
[models.providers.${spec.calls.compactProvider}]
kind = "openai-compat"
base_url = "${providers.urls.compact}"
revision = "${spec.calls.revision}"
[models.providers.hooks06dreamer]
kind = "local-openai-compat"
base_url = "${providers.urls.compact}"
revision = "${spec.calls.revision}"
[models.roles.generative_reasoner]
model = "${spec.calls.chatProvider}:${spec.calls.chatModel}"
[models.roles.checker]
model = "${spec.calls.compactProvider}:${spec.calls.compactModel}"
[models.roles.extraction_teacher]
model = "hooks06dreamer:hooks06-extract"
[models.roles.dreamer_current]
model = "hooks06dreamer:hooks06-summary"
[models.dreamer]
enabled = true
[models.workflows]
enabled = false
[models.code_mode]
prompt_package = ${JSON.stringify(resolve(import.meta.dir, spec.prompts.packagePath))}
[models.code_mode.compaction]
role = "checker"
[[models.planner.seats]]
model = "${model}"
agent = "sys.team_lead"
` });
  try {
    const startedAt = Math.floor(Date.now() / 1_000);
    const bodyOf = (row: Facade.EntityView): Record<string, unknown> => {
      if (row.body === null || typeof row.body !== "object" || Array.isArray(row.body)) {
        throw new Error(`Expected public ${row.kind} body`);
      }
      return row.body as Record<string, unknown>;
    };
    // Temporal search includes container records; default recall intentionally
    // omits SESSION and cannot establish whether this sitting exists.
    const publicViews = async (): Promise<Facade.EntityView[]> => {
      const page = await engine.client.call("vault.search.temporal", {
        start: startedAt, end: Math.floor(Date.now() / 1_000),
        sigma_secs: 0, limit: spec.pageBound,
      });
      expect(page.value.hits.length).toBeLessThan(spec.pageBound);
      const rows: Facade.EntityView[] = [];
      for (const hit of page.value.hits) {
        const row = (await engine.client.call("vault.get", { entity_ref: hit.entity_ref })).value;
        if (row !== null) rows.push(row);
      }
      return rows;
    };
    const hookReceipts = async (hook: string, verb: string, phase: string) =>
      (await readHookReceipts(input => engine.client.call("vault.receipts", input), spec.pageBound))
        .filter(row => row.fields?.hook === `${spec.packName}/${hook}`
          && row.fields?.verb === verb && row.fields?.phase === phase);

    const installed = await engine.client.call("vault.packs.put", await packInput(catalog, spec.packFiles));
    expect(installed.outcome).toBe("installed");
    const bindings = (await engine.client.call("vault.packs.hooks.list", {}))
      .filter(row => row.binding.pack === spec.packName);
    expect(bindings.map(row => row.binding.hook).sort())
      .toEqual(Object.values(spec.hookNames).sort());
    for (const row of bindings) {
      expect(row.binding.enabled).toBe(true);
      expect(row.binding.owner).toBe(engine.pairedActor.principalRef);
    }
    await engine.kill();
    const grant = await engine.cli.run(["dreamer", "grant", "--config",
      resolve(engine.root, "oneiron.toml"), "--extraction-route", "own_server"]);
    expect(grant.exitCode).toBe(0);
    await engine.restart();
    const opened = await engine.client.request("POST", "/v1/ai/session", { event: "open" });
    expect(opened.status).toBe(202);
    const sessions = await awaitPublic(async () => (await publicViews()).filter(row => row.kind === "SESSION"),
      rows => rows.length !== 0, { label: "HOOKS-06 publicly applied open sitting" });
    expect(sessions).toHaveLength(1);
    const session = sessions[0]!;
    await engine.client.call("vault.conversations.create", {
      id: spec.conversationId,
      body: { v: 1, kind: "direct", member_ids: [engine.pairedActor.principalRef], title: "Host hook handover" },
      text: [{ field: "title", value: "Host hook handover" }],
    });
    const compacted: Facade.HostCompactResult[] = [];
    const compactReceipts: Facade.MemoryReceipt[] = [];
    for (const row of spec.compactCases) {
      const witnessed = await engine.client.call("vault.witness", {
        conversation_ref: spec.conversationId, turn_ref: row.turnId,
        occurred_at: Math.floor(Date.now() / 1_000),
        messages: [{ id: row.messageId, author: "user", message_type: "dialogue",
          content: row.content, is_visible: true, order: 0 }],
      });
      expect(witnessed.turn?.id).toBe(row.turnId);
      const previous = await hookReceipts(spec.hookNames.compact, "host.compact", "pre");
      const result = await engine.client.call("host.compact", {
        session_ref: session.id_hex,
        window: [{ message_id: row.messageId, turn_id: row.turnId, content: row.content,
          turn: row.turnNumber, tokens: row.tokens }],
        keep_list: [spec.oldPin], token_ceiling: spec.tokenCeiling,
      });
      expect(result.keep_list).toEqual(row.expectedPins);
      expect(result.text).toBe(row.expectedSummary);
      for (const pin of row.expectedPins) expect(result.text).toContain(pin);
      expect(result.first_turn).toBe(row.turnNumber);
      expect(result.last_turn).toBe(row.turnNumber);
      if (compacted.length !== 0) expect(result.epoch).toBeGreaterThan(compacted.at(-1)!.epoch);
      compacted.push(result);
      const summary = (await engine.client.call("vault.get", { entity_ref: result.summary })).value;
      expect(summary?.kind).toBe("SUMMARY");
      expect(summary).not.toBeNull();
      const summaryBody = bodyOf(summary!);
      expect(summaryBody.text).toBe(row.expectedSummary);
      expect(summaryBody.epoch).toBe(result.epoch);
      expect(summaryBody.turn_start).toBe(row.turnNumber);
      expect(summaryBody.turn_end).toBe(row.turnNumber);
      const receipts = (await hookReceipts(spec.hookNames.compact, "host.compact", "pre"))
        .filter(item => !previous.some(old => old.receipt_ref === item.receipt_ref));
      expect(receipts).toHaveLength(1);
      expect(receipts[0]!.outcome).toBe(row.mode === "add" ? "rewrite" : "refused");
      if (row.mode === "remove") {
        expect(receiptField(receipts[0]!, "reason")).toContain("only adds");
      }
      compactReceipts.push(receipts[0]!);
    }

    const beforeWake = await hookReceipts(spec.hookNames.wake, "host.wake", "pre");
    let wakeRefusal: PublicHttpError | undefined;
    try {
      await engine.client.call("host.wake", { wake_kind: "timer", queue_head: [] });
    } catch (error) {
      if (!(error instanceof PublicHttpError)) throw error;
      wakeRefusal = error;
    }
    expect(wakeRefusal).toBeDefined();
    const wakeRows = (await hookReceipts(spec.hookNames.wake, "host.wake", "pre"))
      .filter(row => !beforeWake.some(previous => previous.receipt_ref === row.receipt_ref));
    expect(wakeRows).toHaveLength(1);
    const wakeReceipt = wakeRows[0]!;
    expect(wakeReceipt.outcome).toBe("skip");
    expect(receiptField(wakeReceipt, "reason")).toBe(spec.quietReason);

    // A current explicit type and fully pinned solo plan need no placement or
    // planning model reply. The real native child, not a private budget tick,
    // owns the paid call and its attempt scope.
    const tree = (await engine.client.call("vault.task_types.get", {})).tree;
    expect(tree).not.toBeNull();
    if (!tree) throw new Error("Fresh vault has no task-type tree");
    expect(tree.nodes.some(row => row.node_id === tree.root.node_id && row.live)).toBe(true);
    const spawned = await engine.client.call("vault.agents.spawn", {
      intent_key: spec.budget.intentKey, prompt: spec.budget.prompt, need: spec.budget.need,
      requested_type: tree.root, care: "light",
      model: { mode: "pin", value: model }, width: { mode: "pin", value: 1 },
      pattern: { mode: "pin", value: "solo" },
      budget_cap_units: { mode: "pin", value: spec.budget.capUnits },
    });
    expect(spawned.phase).toBe("launched");
    expect(spawned.refusal ?? null).toBeNull();
    expect(spawned.root_attempt).toMatch(/^[a-f0-9]{32}$/);
    const seat = spawned.root_attempt!;
    const readLease = () => engine.client.call("vault.budgets.lease", { scope: seat });
    const atCap = await awaitPublic(readLease, value => value.spend.available_units === 0,
      { label: "HOOKS-06 native child spend reaches its pinned cap" });
    expect(atCap.lease.cap_units).toBe(spec.budget.capUnits);
    expect(atCap.lease.hard).toBe(true);
    expect(atCap.lease.parent ?? null).toBeNull();
    expect(atCap.lease.payer ?? null).toBeNull();
    expect(atCap.spend.spent_units).toBe(spec.budget.spentUnits);
    expect(atCap.spend.cap_units).toBe(spec.budget.capUnits);
    expect(atCap.spend.signal?.signal).toBe("at_cap");
    const invocation = secretHex(16);
    const hitInput: FacadeInput<"host.budget.hit"> = { seat, policy: { kind: "suspend" } };
    const hit = (await engine.client.request<FacadeResult<"host.budget.hit">>(
      "POST", "/v1/core/facade/host.budget.hit", hitInput, { "x-oneiron-invocation": invocation },
    )).body;
    expect(hit.seat).toBe(seat);
    expect(hit.policy).toEqual({ kind: "suspend" });
    expect(hit.accounting.line.scope).toBe(atCap.lease.scope);
    expect(hit.accounting.root.scope).toBe(atCap.lease.scope);
    expect(hit.accounting.root.parent ?? null).toBeNull();
    expect(hit.accounting.root.payer ?? null).toBeNull();
    expect(hit.accounting.line.cap_units).toBe(spec.budget.capUnits);
    expect(hit.accounting.root.cap_units).toBe(spec.budget.capUnits);
    expect(hit.accounting.spend.spent_units).toBe(spec.budget.spentUnits);
    expect(hit.accounting.spend.available_units).toBe(0);
    const budgetRows = await awaitPublic(async () =>
      (await hookReceipts(spec.hookNames.budget, "host.budget.hit", "post"))
        .filter(row => row.fields?.invocation === invocation), rows => rows.length !== 0,
      { label: "HOOKS-06 original public budget-hit Hook receipt" });
    expect(budgetRows).toHaveLength(1);
    const budgetReceipt = budgetRows[0]!;
    expect(budgetReceipt.outcome).toBe("enqueue");
    expect(receiptField(budgetReceipt, "run_key")).toMatch(/^[a-f0-9]{64}$/);
    expect(budgetReceipt.receipt_ref).toBe(`hook:${receiptField(budgetReceipt, "run_key")}`);
    const taskRows = await awaitPublic(async () => (await publicViews()).filter(row => {
      if (row.kind !== "TASK") return false;
      const body = bodyOf(row);
      return typeof body.spec === "object" && body.spec !== null && "run_key" in body.spec
        && body.spec.run_key === budgetReceipt.receipt_ref;
    }), rows => rows.length !== 0, { label: "HOOKS-06 publicly landed Enqueue task" });
    expect(taskRows).toHaveLength(1);
    const task = taskRows[0]!;
    const taskSpec = bodyOf(task).spec as Record<string, unknown>;
    expect(taskSpec.title).toBe(spec.budget.taskTitle);
    expect(taskSpec.hook).toBe(receiptField(budgetReceipt, "binding"));
    expect(taskSpec.run_key).toBe(budgetReceipt.receipt_ref);
    expect(typeof taskSpec.body).toBe("string");
    expect(JSON.parse(taskSpec.body as string)).toEqual({ seat, accounting: hit.accounting });
    const afterHit = await readLease();
    expect(afterHit.lease.scope).toBe(atCap.lease.scope);
    expect(afterHit.lease.cap_units).toBe(atCap.lease.cap_units);
    expect(afterHit.lease.parent ?? null).toBe(atCap.lease.parent ?? null);
    expect(afterHit.lease.payer ?? null).toBe(atCap.lease.payer ?? null);
    expect(afterHit.spend.spent_units).toBe(atCap.spend.spent_units);
    expect(afterHit.spend.available_units).toBe(0);
    await engine.artifacts.json("host-compact-wake-budget.json", {
      session, compacted, compactReceipts, wakeRefusal: wakeRefusal!.reply.body,
      wakeReceipt, spawned, atCap, hit, budgetReceipt, task, afterHit,
      payerProof: "owner-root None preserved; not a non-owner payer test",
    });
    await engine.kill();
    await engine.restart();
    const durableWake = (await hookReceipts(spec.hookNames.wake, "host.wake", "pre"))
      .find(row => row.receipt_ref === wakeReceipt.receipt_ref);
    expect(durableWake).toEqual(wakeReceipt);
    expect(receiptField(durableWake!, "reason")).toBe(spec.quietReason);
    expect((await engine.client.call("vault.get", { entity_ref: task.id_hex })).value).toEqual(task);
    const durableLease = await readLease();
    expect(durableLease.lease.cap_units).toBe(spec.budget.capUnits);
    expect(durableLease.spend.spent_units).toBe(spec.budget.spentUnits);
    expect(durableLease.lease.payer ?? null).toBeNull();
    await engine.artifacts.json("host-restart.json", { durableWake, task, durableLease });
  } finally {
    await engine.artifacts.json("host-provider-calls.json", providers.seenFixtureCalls);
    try { await engine.close(); } finally { await providers.close(); }
  }
});

type Hooks07Files = { path: string; text: string }[];

function hooks07BodyHash(text: string): string {
  return Buffer.from(blake3(new TextEncoder().encode(text))).toString("hex");
}

// This is the public tree-hash encoding, over authored inputs only.
function hooks07TreeHash(files: Hooks07Files): string {
  const hash = createHash("sha256").update("oneiron.skill.tree.v1\0");
  const length = (n: number) => {
    const bytes = Buffer.alloc(8);
    bytes.writeBigUInt64BE(BigInt(n));
    hash.update(bytes);
  };
  const sorted = [...files].sort((a, b) => Buffer.compare(Buffer.from(a.path), Buffer.from(b.path)));
  length(sorted.length);
  for (const file of sorted) {
    const path = Buffer.from(file.path);
    const body = Buffer.from(file.text);
    length(path.length); hash.update(path);
    length(body.length); hash.update(body);
  }
  return hash.digest("hex");
}

function hooks07Pack(
  name: string, description: string, version: string, hook: string,
  predicate: string, body: string, outcomes: string[],
): Hooks07Files {
  return [
    { path: "PACK.md", text: `---
name: ${name}
description: ${description}
version: ${version}
license: Apache-2.0
kind: capability
hooks: ["${hook}"]
---
Independent HOOKS-07 inputs.
` },
    { path: `hooks/${hook}/HOOK.md`, text: `---
name: ${hook}
version: ${version}
verbs: ["claim.landed:${predicate}"]
actors: ["human"]
phase: fact
budget_ms: 1000
outcomes: ${JSON.stringify(outcomes)}
---
Observe only the selected claim facts.
` },
    { path: `hooks/${hook}/intent.md`, text: "Observe the selected facts without external effects.\n" },
    { path: `hooks/${hook}/body.js`, text: body },
  ];
}

function hooks07HubSteps(
  id: string, files: Hooks07Files, pin: string, version: string,
): ProviderStep[] {
  return [
    {
      id: `${id}-index`, origin: "hub", role: "skill_hub", purpose: "pinned hook pack fetch",
      request: { method: "GET", path: "/index.json" },
      response: { kind: "json", body: { schema: 1, packages: [{
        name: "hooks07-pinned", description: "Pinned hook consent fixture", version,
        content_hash: pin, ref_string: "hooks07-pinned",
        files: files.map((file, index) => ({ path: file.path, url: `${id}/${index}` })),
      }] } },
    },
    ...files.map((file, index): ProviderStep => ({
      id: `${id}-file-${index}`, origin: "hub", role: "skill_hub", purpose: "authored hook pack bytes",
      request: { method: "GET", path: `/${id}/${index}` },
      response: { kind: "bytes", body: new TextEncoder().encode(file.text), contentType: "text/plain" },
    })),
  ];
}

/* HOOKS-07 — Pinned hook update and block scope should work. OF-581/580.
 * ARCH-0080 updates/regen; ARCH-0053 r4b-hubs. The written subset requires
 * hook-outcome widening to retain the selected pin AND running binding until
 * owner bind, including a repeated sync/qualification without that consent.
 * Separately regenerate a vault-owned hook over saved claim.landed runs:
 * identical eligibility/adoption, owner stamp on diff, revert and blank-body
 * rollback, typed history and restart. Hub hooks are not regenerated.
 * Session-bound board delivery/current-recipient narrowing is not proved:
 * the appendix names no session-bound board-delivery verb behind a read grant.
 * A/B trees and regen bodies below are authored inputs, not engine oracles.
 */
suite.test(test, "HOOKS-07", "Pinned hook widening waits for owner re-consent, and vault-owned regeneration replays, stamps differences, and restores the prior body across restart", async () => {
  const initialBody = 'return {kind:"nothing"};\n';
  const identicalBody = '// identical regenerated body\nreturn {kind:"nothing"};\n';
  const differentBody = 'return {kind:"propose",claim:{subject:input.claim.subject,predicate:"hooks07.regen.output",value:{marker:"hooks07-diff"},confidence:1}};\n';
  const hubBodyA = '// publisher revision A\nreturn {kind:"nothing"};\n';
  const hubBodyB = '// publisher revision B\nreturn {kind:"nothing"};\n';
  const hubA = hooks07Pack("hooks07-pinned", "Pinned hook consent fixture", "1.0.0",
    "pin-observer", "hooks07.pin.input", hubBodyA, ["nothing"]);
  const hubB = hooks07Pack("hooks07-pinned", "Pinned hook consent fixture", "2.0.0",
    "pin-observer", "hooks07.pin.input", hubBodyB, ["nothing", "propose"]);
  const pinA = hooks07TreeHash(hubA);
  const pinB = hooks07TreeHash(hubB);
  const ownerFiles = hooks07Pack("hooks07-regeneration", "Vault-owned hook regeneration fixture", "1.0.0",
    "regen-observer", "hooks07.regen.input", initialBody, ["nothing", "propose"]);
  const agentFiles = hooks07Pack("local", "Agent-owned hook regeneration fixture", "1.0.0",
    "agent-observer", "hooks07.regen.input", initialBody, ["nothing", "propose"]);
  const coachBodies = [
    { id: "hooks07-identical", text: `\`\`\`js\n${identicalBody}\`\`\`` },
    { id: "hooks07-different", text: `\`\`\`js\n${differentBody}\`\`\`` },
    { id: "hooks07-blank", text: "```js\n```" },
    { id: "hooks07-agent-different", text: `\`\`\`js\n${differentBody}\`\`\`` },
  ];
  const steps: ProviderStep[] = [
    ...hooks07HubSteps("hooks07-install-a", hubA, pinA, "1.0.0"),
    ...hooks07HubSteps("hooks07-sync-b-first", hubB, pinB, "2.0.0"),
    ...hooks07HubSteps("hooks07-sync-b-repeat", hubB, pinB, "2.0.0"),
    ...coachBodies.map((row): ProviderStep => ({
      id: row.id, origin: "coach", role: "coach", purpose: "coach_hook_regen",
      request: { method: "POST", path: "/v1/chat/completions", model: "hooks07-regen", fields: { stream: false } },
      response: openaiText(row.id, "hooks07-regen", row.text, { inputTokens: 64, outputTokens: 16 }),
    })),
  ];
  const providers = await ScriptedProviders.start({ id: "hooks07", steps });
  let engine: EngineFixture | undefined;
  try {
    engine = await EngineFixture.start({ id: "HOOKS-07", profile, serverConfig: `
[models.providers.hooks07regen]
kind = "local-openai-compat"
base_url = "${providers.urls.coach}"
revision = "hooks07-fixture-v1"
timeout_secs = 2
[models.roles.coach]
model = "hooks07regen:hooks07-regen"
[models.workflows]
enabled = false
` });
    const fixture = engine;
    const owner = fixture.pairedActor.principalRef;
    const hub = "a1070000000000000000000000000001";
    const publisher = "hooks07-publisher";
    const pageBound = 128;
    // Both real agent principals are created while the server is stopped.
    await fixture.client.call("vault.receipts", { limit: 1 });
    await fixture.kill();
    const principals: string[] = [];
    for (const name of ["hooks07-author", "hooks07-other-agent"]) {
      const minted = await fixture.cli.run([
        "token", "agent", "--name", name, "--tier", "full-access",
        "--config", resolve(fixture.root, "oneiron.toml"),
        "--out", resolve(fixture.root, `${name}.credential`),
      ], undefined, undefined, true);
      expect(minted.exitCode).toBe(0);
      const actor = JSON.parse(minted.stdout) as { principal_ref: string; actor_class: string };
      expect(actor.actor_class).toBe("agent");
      expect(actor.principal_ref).toMatch(/^[a-f0-9]{32}$/);
      expect(actor.principal_ref).not.toBe(owner);
      principals.push(actor.principal_ref);
    }
    expect(new Set(principals).size).toBe(2);
    await fixture.restart();
    const agent = await fixture.pairActor({ principalRef: principals[0]!, actorClass: "agent",
      scope: ["core:read", "core:propose", "core:write"] });
    const otherAgent = await fixture.pairActor({ principalRef: principals[1]!, actorClass: "agent",
      scope: ["core:read", "core:propose", "core:write"] });
    const scope = await ownerBaseClaimScope(fixture.client, owner);
    const claim = (id: string, predicate: string) => fixture.client.call("vault.claims.upsert", {
      id, subject_ref: owner, predicate, value: { marker: id }, confidence: 1, source: "user_stated", scope,
    });
    const enabled = async (pack: string) => (await fixture.client.call("vault.packs.hooks.list", {}))
      .filter(row => row.binding.pack === pack && row.binding.enabled);
    const oneBinding = async (pack: string) => {
      const rows = await enabled(pack);
      expect(rows).toHaveLength(1);
      return rows[0]!;
    };
    const installedPack = async (name: string) => {
      const pack = await fixture.client.call("vault.packs.get", { name });
      if (!pack) throw new Error(`Expected installed fixture pack ${name}`);
      return pack;
    };
    const regen = async (binding: string) => {
      const view = await fixture.client.call("vault.hooks.regen.get", { binding });
      if (!view) throw new Error("Expected the live binding's typed regeneration record");
      return view;
    };
    const history = async (binding: string) => {
      const rows = await fixture.client.call("vault.hooks.regen.history", { binding, limit: pageBound });
      expect(rows.length).toBeLessThan(pageBound);
      return rows;
    };
    const hookReceipts = () => readHookReceipts(input => fixture.client.call("vault.receipts", input), pageBound);
    const outputs = async () => {
      const page = await fixture.client.call("vault.claims.list", {
        subject_ref: owner, predicate: "hooks07.regen.output", limit: pageBound,
      });
      expect(page.value.length).toBeLessThan(pageBound);
      return page.value;
    };
    const refusalReceipts: Facade.CallReceipt[] = [];
    const refuse = async <V extends FacadeVerb>(client: PublicHttpClient, actor: string, actorClass: string,
      verb: V, input: FacadeInput<V>, status: number, code: string): Promise<void> => {
      let refused: PublicHttpError | undefined;
      try { await client.call(verb, input); } catch (error) {
        if (!(error instanceof PublicHttpError)) throw error;
        refused = error;
      }
      if (!refused) throw new Error(`Expected ${verb} refusal`);
      expect(refused.reply.status).toBe(status);
      expect(refused.error?.code).toBe(code);
      const receiptRef = refused.error?.receiptRef;
      expect(typeof receiptRef).toBe("string");
      if (typeof receiptRef !== "string") throw new Error("Authenticated facade refusal lacks receiptRef");
      expect(receiptRef).toMatch(/^call:/);
      const receipt = await fixture.client.call("vault.receipts.get", { receipt_ref: receiptRef });
      expect(receipt).not.toBeNull();
      if (!receipt) throw new Error("Refusal receipt is not publicly readable by owner");
      expect(receipt.receipt_ref).toBe(receiptRef);
      expect(receipt.actor_ref).toBe(actor);
      expect(receipt.actor_class).toBe(actorClass);
      expect(receipt.verb).toBe(`v1/core/facade/${verb}`);
      expect(receipt.outcome).toEqual({ refused: { code } });
      refusalReceipts.push(receipt);
    };

    // A real fact makes qualification execute the authored body, not an empty replay.
    await claim("a1070000000000000000000000000010", "hooks07.pin.input");
    const configured = await fixture.client.call("vault.skill_hubs.put", {
      hub, kind: "http-index", endpoint: `${providers.urls.hub}/index.json`,
      trust_tier: "untrusted", sync_policy: "content-hash-frozen",
    });
    expect(configured.consent.outcome).toBe("approved");
    const hubConfig = await fixture.client.call("vault.skill_hubs.get", { hub });
    expect(hubConfig).toEqual({ kind: "http-index", endpoint: `${providers.urls.hub}/index.json`,
      trust_tier: "untrusted", sync_policy: "content-hash-frozen" });
    const reference = (pin: string): Facade.HubRef => ({ hub_id: hub, ref_string: "hooks07-pinned",
      pin: { type: "content_hash", value: pin } });
    const trackedA = await fixture.client.call("vault.skill_hubs.refs.set", {
      hub_ref: reference(pinA), sync_policy: "content-hash-frozen",
    });
    expect(await fixture.client.call("vault.skill_hubs.refs.get", { hub, ref_string: "hooks07-pinned" }))
      .toEqual(trackedA);
    const first = await fixture.client.call("vault.packs.install", { hub_ref: reference(pinA), publisher });
    expect(first.outcome).toBe("candidate");
    if (!first.receipt) throw new Error("Pinned install lacks a Candidate receipt");
    expect(first.receipt.pin_value).toBe(pinA);
    const qualify = async (source: string) => {
      const result = await fixture.client.call("vault.packs.hooks.qualify", { source });
      expect(result.put.outcome).toBe("installed");
      const replay = result.replays.find(row => row.hook === "pin-observer");
      expect(replay?.unreplayed).toBe(false);
      expect(replay?.entries).toHaveLength(1);
      expect(replay?.entries[0]?.result).toMatchObject({ status: "ran", outcome: "nothing" });
      return result;
    };
    await qualify(first.receipt.source_id);
    expect(await fixture.client.call("vault.packs.hooks.bind", { pack: "hooks07-pinned" })).toHaveLength(1);
    const bindingA = await oneBinding("hooks07-pinned");
    const selectedA = await installedPack("hooks07-pinned");
    expect(selectedA.pin_type).toBe("content_hash");
    expect(selectedA.pin_value).toBe(pinA);
    expect(selectedA.content_hash).toBe(pinA);
    expect(selectedA.hub_id).toBe(hub);
    expect(selectedA.publisher).toBe(publisher);
    expect(bindingA.binding.source).toBe(selectedA.source_id);
    expect(bindingA.binding.body_hash).toBe(hooks07BodyHash(hubBodyA));
    expect(bindingA.binding.author).toMatchObject({ kind: "foreign_actor", identity: publisher, hub });
    expect(bindingA.binding.owner).toBe(owner);

    const trackedB = await fixture.client.call("vault.skill_hubs.refs.set", {
      hub_ref: reference(pinB), sync_policy: "content-hash-frozen",
    });
    // Requested fetch pin and selected installed pin are distinct concepts.
    expect(await fixture.client.call("vault.skill_hubs.refs.get", { hub, ref_string: "hooks07-pinned" }))
      .toEqual(trackedB);
    expect(trackedB.hub_ref).toEqual(reference(pinB));
    const widening = await fixture.client.call("vault.packs.sync", { name: "hooks07-pinned" });
    expect(widening.outcome).toBe("candidate");
    if (!widening.receipt) throw new Error("Widening sync lacks a Candidate receipt");
    expect(widening.receipt.permissions.widening_hooks).toContain("pin-observer/outcome:propose");
    const selectedWhileCandidate = await installedPack("hooks07-pinned");
    const boundWhileCandidate = await enabled("hooks07-pinned");
    await qualify(widening.receipt.source_id);
    const selectedAfterFirst = await installedPack("hooks07-pinned");
    const boundAfterFirst = await enabled("hooks07-pinned");
    // Do not stop at the first hold: no owner bind occurs before the repeat.
    const repeat = await fixture.client.call("vault.packs.sync", { name: "hooks07-pinned" });
    expect(repeat.outcome).toBe("candidate");
    if (!repeat.receipt) throw new Error("Repeated sync lacks a Candidate receipt");
    await qualify(repeat.receipt.source_id);
    const selectedAfterRepeat = await installedPack("hooks07-pinned");
    const boundAfterRepeat = await enabled("hooks07-pinned");
    const trackedBeforeConsent = await fixture.client.call("vault.skill_hubs.refs.get", { hub, ref_string: "hooks07-pinned" });

    // Owner-only doors: valid inputs, a real non-owner, and the actual refusal receipts.
    const nonowner = <V extends FacadeVerb>(verb: V, input: FacadeInput<V>) =>
      refuse(agent.client, agent.principalRef, "agent", verb, input, 403, "FORBIDDEN");
    const validHash = hooks07BodyHash(identicalBody);
    await nonowner("vault.skill_hubs.put", { hub, ...hubConfig });
    await nonowner("vault.skill_hubs.get", { hub });
    await nonowner("vault.skill_hubs.refs.get", { hub, ref_string: "hooks07-pinned" });
    await nonowner("vault.skill_hubs.refs.set", { hub_ref: reference(pinA), sync_policy: "content-hash-frozen" });
    await nonowner("vault.packs.install", { hub_ref: reference(pinA), publisher });
    await nonowner("vault.packs.sync", { name: "hooks07-pinned" });
    await nonowner("vault.packs.hooks.bind", { pack: "hooks07-pinned" });
    await nonowner("vault.packs.hooks.qualify", { source: widening.receipt.source_id });
    await nonowner("vault.hooks.regen.run", { binding: bindingA.id });
    await nonowner("vault.hooks.regen.get", { binding: bindingA.id });
    await nonowner("vault.hooks.regen.adopt", { binding: bindingA.id, candidate_hash: validHash });
    await nonowner("vault.hooks.regen.history", { binding: bindingA.id, limit: pageBound });
    await nonowner("vault.hooks.regen.revert", { binding: bindingA.id, adopted_hash: validHash });
    expect(await installedPack("hooks07-pinned")).toEqual(selectedAfterRepeat);
    expect(await enabled("hooks07-pinned")).toEqual(boundAfterRepeat);
    expect(await fixture.client.call("vault.skill_hubs.get", { hub })).toEqual(hubConfig);
    expect(await fixture.client.call("vault.skill_hubs.refs.get", { hub, ref_string: "hooks07-pinned" }))
      .toEqual(trackedBeforeConsent);

    // Explicit owner re-consent is the only permitted activation step.
    await fixture.client.call("vault.packs.hooks.bind", { pack: "hooks07-pinned" });
    const bindingB = await oneBinding("hooks07-pinned");
    const selectedB = await installedPack("hooks07-pinned");
    expect(selectedB.pin_value).toBe(pinB);
    expect(selectedB.content_hash).toBe(pinB);
    expect(bindingB.binding.source).toBe(selectedB.source_id);
    expect(bindingB.binding.body_hash).toBe(hooks07BodyHash(hubBodyB));
    expect(bindingB.binding.selector.outcomes).toEqual(["nothing", "propose"]);
    expect(bindingB.binding.author).toEqual(bindingA.binding.author);
    await refuse(fixture.client, owner, "human", "vault.hooks.regen.run", { binding: bindingB.id }, 400, "BAD_REQUEST");

    // Vault-owned regeneration uses saved live fact runs, never hub bytes as its oracle.
    expect((await fixture.client.call("vault.packs.put", { files: ownerFiles })).outcome).toBe("installed");
    const original = await oneBinding("hooks07-regeneration");
    expect(original.binding.author).toEqual({ kind: "owner" });
    expect(original.binding.body_hash).toBe(hooks07BodyHash(initialBody));
    const originalRecord = await regen(original.id);
    expect((await agent.client.call("vault.packs.put", { files: agentFiles })).outcome).toBe("installed");
    const agentBinding = await oneBinding("local");
    expect(agentBinding.binding.author).toEqual({ kind: "agent", agent: agent.principalRef });
    // An explicit owner read grant supplies the golden inputs, not effect or stamp authority.
    const agentReadGrant: Facade.HookGrant = { reader: owner, reader_class: "human",
      predicates: ["hooks07.regen.input"], worlds: [scope.world_id] };
    await fixture.client.call("vault.packs.hooks.grant.set", { binding: agentBinding.id, grant: agentReadGrant });
    expect(await fixture.client.call("vault.packs.hooks.grant.get", { binding: agentBinding.id }))
      .toEqual({ binding: agentBinding.id, grant: agentReadGrant });
    const seedIds = ["a1070000000000000000000000000021", "a1070000000000000000000000000022"];
    for (const id of seedIds) await claim(id, "hooks07.regen.input");
    const saved = await awaitPublic(async () => (await hookReceipts())
      .filter(row => row.fields?.binding === original.id && seedIds.includes(row.fields?.trigger_ref ?? "")),
      rows => rows.length >= seedIds.length, { label: "HOOKS-07 saved golden fact runs" });
    expect(saved).toHaveLength(2);
    for (const row of saved) {
      expect(row.outcome).toBe("nothing");
      expect(row.fields?.body_hash).toBe(hooks07BodyHash(initialBody));
    }
    const savedKeys = saved.map(row => receiptField(row, "run_key")).sort();
    const beforeEffects = await outputs();
    expect(beforeEffects).toEqual([]);
    const identical = await fixture.client.call("vault.hooks.regen.run", { binding: original.id });
    expect(await regen(original.id)).toEqual(identical);
    if (!identical || identical.record.pending?.outcome !== "auto_adopt") throw new Error("Nonempty identical golden runs must be auto_adopt eligible");
    expect(identical.candidate_hash).toBe(hooks07BodyHash(identicalBody));
    expect(identical.record.pending.candidate).toBe(identicalBody);
    expect(identical.record.pending.diff).toEqual({ cases: 2, changed: [], execution_failed: [], withheld: [], missing_history: [] });
    expect([...identical.record.pending.golden.runs].sort()).toEqual(savedKeys);
    expect(identical.record.pending.golden.candidate).toEqual(identical.record.pending.golden.last_good);
    expect(Object.keys(identical.record.pending.golden.candidate.cases).sort()).toEqual(savedKeys);
    expect((await oneBinding("hooks07-regeneration")).binding.body_hash).toBe(hooks07BodyHash(initialBody));
    expect(await outputs()).toEqual(beforeEffects);
    await refuse(fixture.client, owner, "human", "vault.hooks.regen.adopt", {
      binding: original.id, candidate_hash: "not-a-body-hash",
    }, 400, "BAD_REQUEST");
    await refuse(fixture.client, owner, "human", "vault.hooks.regen.adopt", {
      binding: original.id, candidate_hash: "0".repeat(64),
    }, 409, "INVALID_STATE");
    expect((await fixture.client.call("vault.hooks.regen.adopt", {
      binding: original.id, candidate_hash: hooks07BodyHash(identicalBody),
    })).outcome).toBe("installed");
    const adoptedIdentical = await oneBinding("hooks07-regeneration");
    const adoptedRecord = await regen(adoptedIdentical.id);
    expect(adoptedRecord.record.body_hash).toBe(hooks07BodyHash(identicalBody));
    expect(adoptedRecord.record.pending ?? null).toBeNull();
    expect(adoptedRecord.record.previous).toEqual({ body: initialBody,
      body_hash: hooks07BodyHash(initialBody), stamp: originalRecord.record.stamp });
    const identicalHistory = await history(adoptedIdentical.id);
    expect(identicalHistory[0]?.event).toEqual(expect.objectContaining({ event: "adopted",
      candidate_hash: hooks07BodyHash(identicalBody), stamped: false, rebound: adoptedIdentical.id }));

    const nextId = "a1070000000000000000000000000023";
    await claim(nextId, "hooks07.regen.input");
    const nextRuns = await awaitPublic(async () => (await hookReceipts())
      .filter(row => row.fields?.binding === adoptedIdentical.id && row.fields?.trigger_ref === nextId),
      rows => rows.length > 0, { label: "HOOKS-07 adopted body's saved fact run" });
    expect(nextRuns).toHaveLength(1);
    expect(nextRuns[0]?.outcome).toBe("nothing");
    const different = await fixture.client.call("vault.hooks.regen.run", { binding: adoptedIdentical.id });
    expect(await regen(adoptedIdentical.id)).toEqual(different);
    if (!different || different.record.pending?.outcome !== "needs_human_stamp") throw new Error("Different golden result must require the owner stamp");
    expect(different.candidate_hash).toBe(hooks07BodyHash(differentBody));
    expect(different.record.pending.candidate).toBe(differentBody);
    expect(different.record.pending.diff.cases).toBe(1);
    expect(different.record.pending.diff.changed).toEqual([receiptField(nextRuns[0]!, "run_key")]);
    expect(different.record.pending.diff.execution_failed).toEqual([]);
    expect(different.record.pending.diff.withheld).toEqual([]);
    expect(different.record.pending.diff.missing_history).toEqual([]);
    expect(await outputs()).toEqual(beforeEffects);
    expect((await oneBinding("hooks07-regeneration")).binding.body_hash).toBe(hooks07BodyHash(identicalBody));
    await nonowner("vault.hooks.regen.adopt", { binding: adoptedIdentical.id, candidate_hash: hooks07BodyHash(differentBody) });
    expect((await fixture.client.call("vault.hooks.regen.adopt", { binding: adoptedIdentical.id,
      candidate_hash: hooks07BodyHash(differentBody) })).outcome).toBe("installed");
    const adoptedDifferent = await oneBinding("hooks07-regeneration");
    expect(adoptedDifferent.binding.body_hash).toBe(hooks07BodyHash(differentBody));
    const diffRecord = await regen(adoptedDifferent.id);
    expect(diffRecord.record.previous?.body).toBe(identicalBody);
    expect(diffRecord.record.previous?.body_hash).toBe(hooks07BodyHash(identicalBody));
    expect((await history(adoptedDifferent.id))[0]?.event).toEqual(expect.objectContaining({ event: "adopted",
      candidate_hash: hooks07BodyHash(differentBody), stamped: true, rebound: adoptedDifferent.id }));
    expect((await fixture.client.call("vault.hooks.regen.revert", { binding: adoptedDifferent.id,
      adopted_hash: hooks07BodyHash(differentBody) })).outcome).toBe("installed");
    const restored = await oneBinding("hooks07-regeneration");
    expect(restored.binding.body_hash).toBe(hooks07BodyHash(identicalBody));
    const restoredRecord = await regen(restored.id);
    expect(restoredRecord.record.body_hash).toBe(hooks07BodyHash(identicalBody));
    expect(restoredRecord.record.previous ?? null).toBeNull();
    expect(restoredRecord.record.pending ?? null).toBeNull();
    expect(restoredRecord.record.declined).toEqual(different.record.pending.target);
    expect((await history(restored.id))[0]?.event).toEqual(expect.objectContaining({ event: "reverted",
      from_hash: hooks07BodyHash(differentBody), to_hash: hooks07BodyHash(identicalBody), rebound: restored.id }));
    const blank = await fixture.client.call("vault.hooks.regen.run", { binding: restored.id });
    expect(await regen(restored.id)).toEqual(blank);
    if (!blank || blank.record.pending?.outcome !== "rolled_back") throw new Error("Blank generated body must roll back");
    expect(blank.record.pending.failure.phase).toBe("validate");
    expect(blank.record.pending.failure.message.length).toBeGreaterThan(0);
    expect(blank.candidate_hash ?? null).toBeNull();
    expect(blank.record.body_hash).toBe(hooks07BodyHash(identicalBody));
    expect((await oneBinding("hooks07-regeneration")).binding.body_hash).toBe(hooks07BodyHash(identicalBody));
    expect(await outputs()).toEqual(beforeEffects);

    // Own-agent doors distinguish actor kind, authorship, and a genuine golden diff.
    const agentRuns = await awaitPublic(async () => (await hookReceipts())
      .filter(row => row.fields?.binding === agentBinding.id
        && [...seedIds, nextId].includes(row.fields?.trigger_ref ?? "")),
      rows => rows.length >= 3, { label: "HOOKS-07 agent-authored golden fact runs" });
    expect(agentRuns).toHaveLength(3);
    for (const row of agentRuns) expect(row.outcome).toBe("nothing");
    const agentDiff = await fixture.client.call("vault.hooks.regen.run", { binding: agentBinding.id });
    expect(await agent.client.call("self.hooks.regen.get", { binding: agentBinding.id })).toEqual(agentDiff);
    if (!agentDiff || agentDiff.record.pending?.outcome !== "needs_human_stamp") throw new Error("A genuine golden diff cannot authorize self-adoption");
    expect(agentDiff.record.pending.diff.cases).toBe(3);
    expect(agentDiff.record.pending.diff.changed).toEqual(agentRuns.map(row => receiptField(row, "run_key")).sort());
    expect(agentDiff.record.pending.diff.execution_failed).toEqual([]);
    expect(agentDiff.record.pending.diff.withheld).toEqual([]);
    expect(agentDiff.record.pending.diff.missing_history).toEqual([]);
    expect(agentDiff.candidate_hash).toBe(hooks07BodyHash(differentBody));
    expect(await outputs()).toEqual(beforeEffects);
    await refuse(agent.client, agent.principalRef, "agent", "self.hooks.regen.adopt", {
      binding: agentBinding.id, candidate_hash: hooks07BodyHash(differentBody),
    }, 409, "INVALID_STATE");
    await refuse(fixture.client, owner, "human", "self.hooks.regen.get", { binding: agentBinding.id }, 403, "FORBIDDEN");
    await refuse(fixture.client, owner, "human", "self.hooks.regen.adopt", {
      binding: agentBinding.id, candidate_hash: validHash,
    }, 403, "FORBIDDEN");
    for (const binding of [restored.id, bindingB.id, agentBinding.id]) {
      await refuse(otherAgent.client, otherAgent.principalRef, "agent", "self.hooks.regen.get", { binding }, 404, "NOT_FOUND");
      await refuse(otherAgent.client, otherAgent.principalRef, "agent", "self.hooks.regen.adopt", {
        binding, candidate_hash: validHash,
      }, 404, "NOT_FOUND");
    }
    expect(await regen(agentBinding.id)).toEqual(agentDiff);
    expect((await oneBinding("local")).binding).toEqual(agentBinding.binding);

    // Withdraw a real credential's write authority, not a HookGrant read filter.
    const { seed } = credentialParts(agent.credential);
    const key = createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"),
      Buffer.from(seed, "hex")]), format: "der", type: "pkcs8" });
    const holderKey = createPublicKey(key).export({ format: "der", type: "spki" }).subarray(-32).toString("hex");
    const all: Facade.Scope = { worlds: { kind: "all" }, facets: { kind: "all" }, bands: { kind: "all" },
      audience: { kind: "all" }, sensitivity: { kind: "all" }, verbs: { kind: "some", values: ["read", "write"] } };
    const support = await fixture.client.call("vault.support_grants.mint", { holder: agent.principalRef,
      holder_class: "agent", holder_key: holderKey, scope: all, records: [], purpose: "HOOKS-07 next-write revocation" });
    const credential = `v2.cred.${support.slip.slice("v2.slip.".length)}.${seed}`;
    redactor.add(support.slip, credential);
    const withdrawn = new PublicHttpClient(fixture.url, { credential, artifacts: fixture.artifacts });
    expect(await withdrawn.call("self.hooks.regen.get", { binding: agentBinding.id })).toEqual(agentDiff);
    await refuse(withdrawn, agent.principalRef, "agent", "self.hooks.regen.adopt", {
      binding: agentBinding.id, candidate_hash: hooks07BodyHash(differentBody),
    }, 409, "INVALID_STATE");
    const revoked = await fixture.client.call("vault.support_grants.revoke", { grant_ref: support.grant.grant_ref });
    expect(revoked.changed).toBe(true);
    expect((await fixture.client.call("vault.support_grants.list", { include_inactive: true, limit: pageBound }))
      .grants.find(row => row.grant_ref === support.grant.grant_ref)?.status).toBe("revoked");
    const revokedWrite = await withdrawn.raw("POST", "/v1/core/facade/self.hooks.regen.adopt", {
      binding: agentBinding.id, candidate_hash: hooks07BodyHash(differentBody),
    });
    // No authenticated caller remains for OF-538 to attribute a receipt to.
    expect(revokedWrite.status).toBe(401);
    expect(await regen(agentBinding.id)).toEqual(agentDiff);

    const regenHistory = await history(restored.id);
    expect(regenHistory.map(row => row.event.event)).toEqual(["decided", "reverted", "adopted", "decided", "adopted", "decided"]);
    for (const row of regenHistory) expect(row.actor).toEqual({ by: "owner", actor: owner });
    expect(regenHistory[0]?.event).toEqual(expect.objectContaining({ event: "decided", decision: "rolled_back",
      failure: expect.objectContaining({ phase: "validate" }) }));
    expect(regenHistory.at(-1)?.event).toEqual(expect.objectContaining({ event: "decided", decision: "auto_adopt",
      golden: identical.record.pending.golden }));
    const agentHistory = await history(agentBinding.id);
    const regenPackBeforeRestart = await installedPack("hooks07-regeneration");
    const trackedFinal = await fixture.client.call("vault.skill_hubs.refs.get", { hub, ref_string: "hooks07-pinned" });
    await fixture.artifacts.json("hooks07-before-restart.json", {
      selectedWhileCandidate, boundWhileCandidate, selectedAfterFirst, boundAfterFirst,
      selectedAfterRepeat, boundAfterRepeat, selectedB, bindingB, identical, different, blank,
      regenHistory, agentDiff, agentHistory, refusalReceipts,
    });
    await fixture.kill();
    await fixture.restart();
    expect(await fixture.client.call("vault.skill_hubs.get", { hub })).toEqual(hubConfig);
    expect(await fixture.client.call("vault.skill_hubs.refs.get", { hub, ref_string: "hooks07-pinned" })).toEqual(trackedFinal);
    expect(await installedPack("hooks07-pinned")).toEqual(selectedB);
    expect(await oneBinding("hooks07-pinned")).toEqual(bindingB);
    expect(await installedPack("hooks07-regeneration")).toEqual(regenPackBeforeRestart);
    expect(await oneBinding("hooks07-regeneration")).toEqual(restored);
    expect(await regen(restored.id)).toEqual(blank);
    expect(await history(restored.id)).toEqual(regenHistory);
    expect(await regen(agentBinding.id)).toEqual(agentDiff);
    expect(await oneBinding("local")).toEqual({ ...agentBinding, grant: agentReadGrant });
    expect(await history(agentBinding.id)).toEqual(agentHistory);
    expect(await outputs()).toEqual(beforeEffects);
    for (const receipt of refusalReceipts) {
      const durable = await fixture.client.call("vault.receipts.get", { receipt_ref: receipt.receipt_ref });
      if (!durable) throw new Error("Refusal receipt did not survive restart");
      // served_records is a current row projection, not the receipt's saved fields.
      const { served_records: beforeProjection, ...before } = receipt;
      const { served_records: afterProjection, ...after } = durable;
      expect(after).toEqual(before);
    }
    expect(providers.seenFixtureCalls.map(row => row.fixtureId)).toEqual(steps.map(row => row.id));
    await fixture.artifacts.json("hooks07-provider-calls.json", providers.seenFixtureCalls);

    // Assert the promise after collecting ALL witnesses, so today's first pin
    // defect cannot prevent the repeated-sync discriminator or regen journey.
    for (const snapshot of [selectedWhileCandidate, selectedAfterFirst, selectedAfterRepeat]) {
      expect(snapshot.pin_type).toBe("content_hash");
      expect(snapshot.pin_value).toBe(pinA);
      expect(snapshot.source_id).toBe(selectedA.source_id);
      expect(snapshot.content_hash).toBe(pinA);
      expect(snapshot.publisher).toBe(publisher);
    }
    for (const snapshot of [boundWhileCandidate, boundAfterFirst, boundAfterRepeat]) {
      expect(snapshot).toEqual([bindingA]);
    }
  } finally {
    try { if (engine) await engine.close(); } finally { await providers.close(); }
  }
});
