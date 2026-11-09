import { afterAll, expect, test } from "bun:test";
import { verify } from "node:crypto";
import { createServer } from "node:net";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { blake3 } from "@noble/hashes/blake3";
import type { FacadeInput, FacadeResult, FacadeVerb } from "@oneiron/client";
import type { LlmRequest, LlmStreamEvent, LlmUsage, ModelBinding, ModelManifest, ModelRole, ModelRoleReceipt,
  ModelSlot, TeacherProbeApproval } from "@oneiron/client/facade-types";
import type * as Models09Facade from "@oneiron/client/facade-types";
import { CliClient, CliError, McpRpcError, PublicHttpClient as Models01HttpClient, PublicHttpError,
  SdkProcessDriver, credentialParts } from "./support/clients.ts";
import type { McpClient, PublicHttpClient, WireReply, WsClient } from "./support/clients.ts";
import { EngineFixture, awaitPublic } from "./support/engine.ts";
import type { PairedActor } from "./support/engine.ts";
import { loadBuildManifest, loadFixtures, ownerBaseClaimScope as models09OwnerBaseClaimScope, requireAsset } from "./support/fixtures.ts";
import type { Profile } from "./support/fixtures.ts";
import { ScriptedProviders, embeddingReply, openaiText } from "./support/providers.ts";
import type { Json, ProviderResponse, ProviderStep, StreamPart } from "./support/providers.ts";
import { Artifacts, LIMITS, ManagedProcess, assertFlowActive, defineFile, isolatedEnv, ownResource,
  redactor, secretHex, tempRoot } from "./support/run.ts";

const profile: Profile = process.env.E2E_PROFILE === "real-small-model"
  ? "real-small-model" : "deterministic";
const suite = defineFile(import.meta, { profile, slots: 1 });
afterAll(suite.flush);

// Non-facade DTOs from the existing OpenAPI UsageEvent/UsageRecordResult/
// UsageRollup schemas (consumer_usage.rs and usage/model.rs). These wire fields
// are camelCase, unlike generated facade DTOs. No model or vault internals run.
type UsageSource = "local" | "byo" | "oneiron_cloud";
interface TokenCounts {
  inputTokens: number;
  outputTokens: number;
  cacheReadTokens: number;
  cacheWriteTokens: number;
}
interface CostRates {
  currency: string;
  priceTableSnapshot: string;
  inputPerMillion: number;
  outputPerMillion: number;
  cacheReadPerMillion: number;
  cacheWritePerMillion: number;
}
interface Money {
  amount: number;
  currency: string;
  priceTableSnapshot: string;
}
interface UsageEvent {
  owner: string;
  vaultId: string;
  idempotencyKey: string;
  source?: UsageSource;
  eventType: "inference" | "cache" | "service";
  role: string;
  occurredAt: number;
  agentId: string;
  model: string;
  service: string;
  tokenCounts: TokenCounts;
  costRates: CostRates;
  serviceAmount: number;
}
interface UsageCounter extends TokenCounts {
  eventCount: number;
  amountsByCurrency: Record<string, number>;
}
interface UsageRollup {
  owner: string;
  vaultId: string;
  counters: UsageCounter;
  agents: Record<string, UsageCounter>;
  models: Record<string, UsageCounter>;
  services: Record<string, UsageCounter>;
}
interface UsageRecordResult {
  recorded: boolean;
  replayed: boolean;
  source: UsageSource;
  cost: Money | null;
  vaultRollup: UsageRollup | null;
}
interface UsageApiError {
  code: string;
  message: string;
  details: { code: string; idempotencyKey?: string | null };
  suggestions: string[];
}
interface UsageModeFixture {
  configMode: "local_free" | "byo_cloud_key" | "oneiron_cloud";
  source: UsageSource;
  recordsBillingFacts: boolean;
}
interface EventFixture extends Omit<UsageEvent, "owner" | "vaultId" | "costRates"> {
  currency: string;
}
interface UsageFacts {
  owner: string;
  vaultId: string;
  otherVaultId: string;
  modes: UsageModeFixture[];
  events: [EventFixture, EventFixture];
  expected: {
    costs: [Money, Money];
    counters: UsageCounter;
    usdCounter: UsageCounter;
    eurCounter: UsageCounter;
    conflictCode: string;
    unmeteredRollupStatus: number;
  };
}
interface PriceTable { revision: string; rates: Record<string, CostRates> }

// Missing from the shared typed client: the existing non-facade usage doors.
// Keep these small wire helpers here; the prerequisite is on the fix list.
function submitUsage(client: PublicHttpClient, event: UsageEvent) {
  return client.raw<UsageRecordResult | UsageApiError>("POST", "/v1/usage/events", event);
}
function readUsage(client: PublicHttpClient, owner: string, vaultId: string) {
  return client.raw<UsageRollup | UsageApiError>("GET",
    `/v1/usage/owners/${encodeURIComponent(owner)}/vaults/${encodeURIComponent(vaultId)}/rollup`);
}
function usageEvent(facts: UsageFacts, event: EventFixture, table: PriceTable): UsageEvent {
  const { currency, ...fields } = event;
  const costRates = table.rates[currency];
  if (!costRates) throw new Error(`Unpriced fixture currency: ${currency}`);
  return { ...fields, owner: facts.owner, vaultId: facts.vaultId, costRates };
}
function expectedRollup(facts: UsageFacts, otherVault = false): UsageRollup {
  const [usd, eur] = facts.events;
  const expected = facts.expected;
  return {
    owner: facts.owner,
    vaultId: otherVault ? facts.otherVaultId : facts.vaultId,
    counters: otherVault ? expected.usdCounter : expected.counters,
    agents: { [usd.agentId]: otherVault ? expected.usdCounter : expected.counters },
    models: otherVault ? { [usd.model]: expected.usdCounter }
      : { [usd.model]: expected.usdCounter, [eur.model]: expected.eurCounter },
    services: otherVault ? { [usd.service]: expected.usdCounter }
      : { [usd.service]: expected.usdCounter, [eur.service]: expected.eurCounter },
  };
}
function expectUnrecorded(reply: WireReply<UsageRecordResult | UsageApiError>, source: UsageSource) {
  expect(reply.status).toBe(200);
  expect(reply.body).toEqual({ recorded: false, replayed: false, source, cost: null, vaultRollup: null });
}

const models01Roles = ["retrieval_embedder", "reranker", "extraction_encoder",
  "extraction_teacher", "generative_reasoner", "local_reasoner", "checker",
  "dreamer_current", "dreamer_target", "asr", "captioner", "doc_parsing",
  "audio_vad", "tts_deferred", "local_vision"] as const satisfies readonly ModelRole[];
const models01Slots = ["llm", "embedder", "oneironer"] as const satisfies readonly ModelSlot[];
const models01Checkpoint = "0123456789abcdef";
const models01Stack = "fedcba9876543210";
const models01Query = "slot independence query";
const models01TagText = "Alice visited Paris.";
const models01AgentRef = "018f0000000070008000000000000a01";

async function models01Manifest(): Promise<ModelManifest> {
  const facts = await (await loadFixtures()).readJson<{
    scenarios: { id: string; contract: { version: number; roleBindings: Record<string, ModelBinding> } }[];
  }>("models-scenarios");
  const scenario = facts.scenarios.find(row => row.id === "MODELS-01");
  if (!scenario) throw new Error("Missing MODELS-01 fixture");
  const roles: Record<string, ModelBinding> = Object.fromEntries(models01Roles.map(role =>
    [role, { model: "alternate/alternate@rev-a", slot: "llm", tier: "fixture-pinned" }]));
  // The four fixture rows are incomplete; host provider names supply the real IDs.
  roles.generative_reasoner = { ...scenario.contract.roleBindings.generative_reasoner!,
    model: "reasoner-a/reasoner@rev-a" };
  roles.local_reasoner = { ...scenario.contract.roleBindings.local_reasoner!,
    model: "alternate/alternate@rev-a" };
  roles.retrieval_embedder = { ...scenario.contract.roleBindings.retrieval_embedder! };
  roles.extraction_encoder = { ...scenario.contract.roleBindings.extraction_encoder!,
    model: `oneironer/endpoint@${models01Checkpoint}` };
  return { version: scenario.contract.version, roles,
    routes: { llm: "own_server", embedder: "on_device", oneironer: "on_device" }, verdict: null };
}

function models01Approval(manifest: ModelManifest): TeacherProbeApproval {
  // Synthetic, owner-authored operator evidence; not a measured quality score.
  // ModelBinding skips empty route_models, absent disposition and false reads_audio.
  const bindingBytes = '{"model":"alternate/alternate@rev-a","slot":"llm","tier":"fixture-pinned"}';
  const policyBytes = '{"probe_id":"oneiron-conll-bio-v1","vault_min_f1_millionths":800000,"min_f1_millionths":800000}';
  expect(manifest.roles.extraction_teacher).toEqual(JSON.parse(bindingBytes));
  const models01Digest = (bytes: string) => Buffer.from(blake3(new TextEncoder().encode(bytes))).toString("hex");
  return { probe_id: "oneiron-conll-bio-v1", model: "alternate/alternate@rev-a",
    binding_hash: models01Digest(bindingBytes), f1_millionths: 1_000_000, policy_hash: models01Digest(policyBytes) };
}

function models01Request(): LlmRequest {
  return { model: "alternate/alternate@rev-a",
    envelope: { purpose: "answer_gen", class: { kind: "best_effort" },
      tier: { global_default: "fixture-pinned" }, response_format: { format: "text" }, locality: "own_server" },
    messages: [{ role: "user", content: [{ kind: "text", text: "slot independence" }] }] };
}

function models01Metadata(): ProviderStep[] {
  return [
    { id: "models01-embedding-list", origin: "embedding", role: "retrieval_embedder",
      purpose: "startup and admission metadata", standing: true,
      request: { method: "GET", path: "/v1/models" },
      response: { kind: "json", body: { data: [{ id: "embedder" }] } } },
    { id: "models01-embedding-probe", origin: "embedding", role: "retrieval_embedder",
      purpose: "startup width probe only", standing: true,
      request: { method: "POST", path: "/v1/embeddings", model: "embedder",
        fields: { input: ["oneiron embedder probe"] } },
      response: embeddingReply("embedder", [[1, 0, 0, 0]], 1) },
    { id: "models01-tagger-card", origin: "tagger", role: "extraction_encoder",
      purpose: "startup and post-extract checkpoint evidence", standing: true,
      request: { method: "GET", path: "/v1/model" }, response: { kind: "json", body: {
        checkpoint_sha16: models01Checkpoint, contract_version: 2, label_count: 1,
        returns: { spans: true, links: true, mood: false }, stack_sha16: models01Stack } } },
  ];
}
function models01EmbedStep(id: string, failed = false): ProviderStep {
  return { id, origin: "embedding", role: "retrieval_embedder", purpose: failed ? "one fast upstream refusal" : "pinned query",
    request: { method: "POST", path: "/v1/embeddings", model: "embedder", fields: { input: [models01Query] } },
    response: failed ? { kind: "json", status: 503, body: { error: { message: "fixture embedder unavailable" } } }
      : embeddingReply("embedder", [[1, 0, 0, 0]], 1) };
}
function models01TagStep(id: string): ProviderStep {
  return { id, origin: "tagger", role: "extraction_encoder", purpose: "pinned live tag call",
    request: { method: "POST", path: "/v1/extract", fields: { messages: [{ text: models01TagText }] } },
    response: { kind: "json", body: { spans: [], links: [], stack_sha16: models01Stack } } };
}
function models01RoundSteps(round: string): ProviderStep[] {
  return [
    { id: `${round}-reasoner`, origin: "reasoner", role: "generative_reasoner", purpose: "pinned reasoner call",
      request: { method: "POST", path: "/v1/chat/completions", model: "reasoner", fields: { stream: false } },
      response: openaiText(`${round}-reasoner`, "reasoner", "Reasoner answer.", { inputTokens: 12, outputTokens: 3 }) },
    { id: `${round}-alternate`, origin: "alternate", role: "local_reasoner", purpose: "independent alternate call",
      request: { method: "POST", path: "/v1/chat/completions", model: "alternate", fields: { stream: false } },
      response: openaiText(`${round}-alternate`, "alternate", "Alternate answer.", { inputTokens: 12, outputTokens: 3 }) },
    models01EmbedStep(`${round}-embed`), models01TagStep(`${round}-tag`),
  ];
}

function models01Config(providers: ScriptedProviders): string {
  return `
[models.providers.reasoner-a]
kind = "local-openai-compat"
base_url = "${providers.urls.reasoner}"
revision = "rev-a"
timeout_secs = 1
request_compression = false
[models.providers.reasoner-b]
kind = "local-openai-compat"
base_url = "${providers.urls.reasoner}"
revision = "rev-b"
timeout_secs = 1
request_compression = false
[models.providers.alternate]
kind = "local-openai-compat"
base_url = "${providers.urls.alternate}"
revision = "rev-a"
timeout_secs = 1
request_compression = false
[models.roles.generative_reasoner]
rungs = [{ model = "reasoner-a:reasoner" }, { model = "reasoner-b:reasoner" }]
[models.roles.local_reasoner]
model = "alternate:alternate"
[models.dreamer]
enabled = false
`;
}

// EngineFixture adds init egress flags even for loopback; public init rejects them.
// Only the public host TOML is read/written. Never open anything inside the vault.
async function models01Start(providers: ScriptedProviders) {
  const build = await loadBuildManifest(profile);
  const root = await tempRoot("MODELS-01");
  const env = isolatedEnv(root, build.environment);
  for (const key of Object.keys(env)) if (key.startsWith("ONEIRON_")) delete env[key];
  env.ONEIRON_AUTH_SECRET = secretHex();
  redactor.add(env.ONEIRON_AUTH_SECRET);
  await mkdir(env.TMPDIR!, { recursive: true, mode: 0o700 });
  const artifacts = new Artifacts(resolve(process.env.E2E_ARTIFACTS_DIR ?? resolve(root, "artifacts"), "MODELS-01"));
  assertFlowActive();
  const reservation = createServer();
  await new Promise<void>((done, reject) => {
    reservation.once("error", reject); reservation.listen(0, "127.0.0.1", done);
  });
  const address = reservation.address();
  if (!address || typeof address === "string") throw new Error("No MODELS-01 port");
  const url = `http://127.0.0.1:${address.port}`;
  let reserved = true;
  const models01Release = async () => {
    if (!reserved) return;
    reserved = false;
    await new Promise<void>((done, reject) => reservation.close(error => error ? reject(error) : done()));
  };
  let server: ManagedProcess | undefined;
  let closed = false;
  let disown: () => void = () => {};
  const models01Close = async () => {
    if (closed) return;
    closed = true; disown();
    try { await server?.stop() }
    finally { await models01Release(); await rm(root, { recursive: true, force: true }) }
  };
  disown = ownResource(models01Close);
  const config = resolve(root, "oneiron.toml");
  const bootstrapCli = new CliClient(requireAsset(build, "cli"), root, env, artifacts);
  const models01Launch = async () => {
    server = await ManagedProcess.start([requireAsset(build, "server"), "serve", "--config", config],
      { cwd: root, env, label: `server-models01-${secretHex(4)}`, artifacts });
    const health = new Models01HttpClient(url, { timeoutMs: 1000, artifacts });
    await awaitPublic(async () => {
      if (!server?.running) throw new Error("MODELS-01 server exited before health");
      return health.raw("GET", "/api/health");
    }, reply => reply.status === 200, { label: "MODELS-01 health", timeoutMs: LIMITS.readyMs, readiness: true });
  };
  try {
    await writeFile(config, `host = "127.0.0.1"
port = ${address.port}
[keystore]
backend = "off"
${models01Config(providers)}`, { mode: 0o600 });
    const initialized = await bootstrapCli.run(["init", resolve(root, "vault"), "--config", config,
      "--embedder", "endpoint", "--embedder-endpoint", `${providers.urls.embedding}/v1`,
      "--embedder-model-key", "embedder", "--embedder-model-id", "models-fixture/embedder@rev-a", "--dimensions", "4",
      "--oneironer", "endpoint", "--oneironer-url", providers.urls.tagger!,
      "--oneironer-checkpoint-sha16", models01Checkpoint, "--oneironer-label-count", "1"],
    undefined, LIMITS.readyMs, true, true);
    if (initialized.exitCode !== 0) throw new CliError(initialized, "models01-init");
    // Init has no timeout/stack flags and rewrites these tables. Set public host policy after it.
    const written = await readFile(config, "utf8");
    expect(written.match(/^\[embedder\]$/gm)).toHaveLength(1);
    expect(written.match(/^\[oneironer\]$/gm)).toHaveLength(1);
    const configured = written.replace(/^\[embedder\]$/m, "[embedder]\ntimeout_ms = 1000")
      .replace(/^\[oneironer\]$/m, `[oneironer]\ntimeout_ms = 1000\nlocality = "on-device"\nstack_sha16 = "${models01Stack}"`);
    const parsed = Bun.TOML.parse(configured) as {
      embedder: { timeout_ms: number }; oneironer: { timeout_ms: number; stack_sha16: string; locality: string };
    };
    expect(parsed.embedder.timeout_ms).toBe(1000);
    expect(parsed.oneironer).toMatchObject({ timeout_ms: 1000, stack_sha16: models01Stack, locality: "on-device" });
    await writeFile(config, configured, { mode: 0o600 });
    const bootstrap = await bootstrapCli.run(["token", "bootstrap", "--url", url, "--config", config],
      undefined, LIMITS.readyMs, true);
    if (bootstrap.exitCode !== 0) throw new CliError(bootstrap, "models01-bootstrap");
    const link = bootstrap.stdout.trim(); redactor.add(link);
    await models01Release(); await models01Launch();
    const sdk = new SdkProcessDriver(build, root, env);
    const paired = await sdk.pair(link);
    const client = new Models01HttpClient(url, { credential: paired.credential, artifacts });
    const { bearer, seed } = credentialParts(paired.credential);
    const cli = new CliClient(requireAsset(build, "cli"), root,
      { ...env, ONEIRON_URL: url, ONEIRON_TOKEN: bearer, ONEIRON_SECRET: bearer, ONEIRON_BINDING_KEY: seed }, artifacts);
    const models01Ready = async () => awaitPublic(() => client.request<{ embedder: { dense: string } }>("GET", "/v1/owner/status"),
      reply => reply.body.embedder.dense === "ready", { label: "MODELS-01 embedder admission" });
    await models01Ready();
    return { client, artifacts, close: models01Close,
      kill: async () => { await server?.stop("SIGKILL") },
      restart: async () => { await server?.stop(); await models01Launch(); await models01Ready() },
      pairActor: async (principalRef: string) => {
        const result = await cli.run(["token", "pair", "--url", url, "--principal-ref", principalRef, "--actor-class", "agent"],
          undefined, LIMITS.requestMs, true);
        if (result.exitCode !== 0) throw new CliError(result, "models01-agent-pair");
        const actorLink = result.stdout.trim(); redactor.add(actorLink);
        const actor = await sdk.pair(actorLink);
        return new Models01HttpClient(url, { credential: actor.credential, artifacts, label: "models01-non-owner" });
      } };
  } catch (error) { await models01Close(); throw error }
}

async function models01State(client: Models01HttpClient) {
  const [manifest, routes, roles] = await Promise.all([
    client.call("vault.models.manifest.read", {}),
    Promise.all(models01Slots.map(slot => client.call("vault.models.routes.read", { slot }))),
    Promise.all(models01Roles.map(role => client.call("vault.models.roles.read", { role }))),
  ]);
  return { manifest, routes, roles };
}
async function models01Unchanged(client: Models01HttpClient, state: Awaited<ReturnType<typeof models01State>>) {
  const [manifest, routes] = await Promise.all([
    client.call("vault.models.manifest.read", {}),
    Promise.all(models01Slots.map(slot => client.call("vault.models.routes.read", { slot }))),
  ]);
  expect(manifest).toEqual(state.manifest);
  expect(routes).toEqual(state.routes);
}
async function models01Refused(action: () => Promise<unknown>, status: number, code: string): Promise<PublicHttpError> {
  try { await action() } catch (error) {
    if (!(error instanceof PublicHttpError)) throw error;
    expect(error.reply.status).toBe(status);
    expect(error.error?.code).toBe(code);
    return error;
  }
  throw new Error(`Expected ${status} ${code}, but the public call succeeded`);
}
async function models01RefusalReceipt(client: Models01HttpClient, error: PublicHttpError,
  verb: string, actorRef?: string) {
  const ref = error.error?.receiptRef;
  expect(typeof ref).toBe("string");
  if (typeof ref !== "string") throw new Error("Refusal has no receiptRef");
  expect(ref).toMatch(/^call:[a-f0-9]{32}$/);
  expect(error.reply.headers.get("x-oneiron-receipt-ref")).toBe(ref);
  const receipt = await client.call("vault.receipts.get", { receipt_ref: ref });
  expect(receipt).toMatchObject({ receipt_ref: ref, verb: `v1/core/facade/${verb}`,
    outcome: { refused: { code: error.error!.code } }, ...(actorRef ? { actor_ref: actorRef, actor_class: "agent" } : {}) });
  return ref;
}

async function models01Round(client: Models01HttpClient, providers: ScriptedProviders, round: string,
  reasoner: "a" | "b") {
  const expected = [
    { role: "generative_reasoner", model: `reasoner-${reasoner}/reasoner@rev-${reasoner}`, revision: `rev-${reasoner}`,
      provider: `reasoner-${reasoner}`, slot: "llm", route: "own_server", text: "Reasoner answer." },
    { role: "local_reasoner", model: "alternate/alternate@rev-a", revision: "rev-a", provider: "alternate",
      slot: "llm", route: "own_server", text: "Alternate answer." },
    { role: "retrieval_embedder", model: "models-fixture/embedder@rev-a", revision: "rev-a", provider: "endpoint",
      slot: "embedder", route: "on_device" },
    { role: "extraction_encoder", model: `oneironer/endpoint@${models01Checkpoint}`, revision: models01Checkpoint,
      provider: "endpoint", slot: "oneironer", route: "on_device" },
  ] as const;
  const receipts: ModelRoleReceipt[] = [];
  for (const row of expected) {
    const input: FacadeInput<"vault.models.roles.invoke"> = { role: row.role,
      input: row.role === "retrieval_embedder" ? { kind: "embed", text: models01Query }
        : row.role === "extraction_encoder" ? { kind: "tag", text: models01TagText }
        : { kind: "generate", request: models01Request() } };
    const { receipt, output } = await client.call("vault.models.roles.invoke", input);
    const { text, ...identity } = { ...row, text: "text" in row ? row.text : undefined };
    expect(receipt).toMatchObject({ ...identity, tier: "fixture-pinned" });
    const read = await client.call("vault.models.roles.read", { role: row.role });
    // Binding reads name the model's provider; invoke names the actual endpoint adapter.
    expect({ ...receipt, provider: read.provider }).toEqual(read);
    if (output.kind === "generated") {
      expect(output.response.message.role).toBe("assistant");
      expect(output.response.message.content).toContainEqual({ kind: "text", text });
    } else if (output.kind === "embedded") expect(output.vector).toEqual([1, 0, 0, 0]);
    else {
      expect(output.output).toMatchObject({ spans: [], links: [], stack_sha16: models01Stack });
      if (output.execution) expect(output.execution).toMatchObject({ runtime: "endpoint", compute: "opaque" });
    }
    expect(output.kind).toBe(row.role === "retrieval_embedder" ? "embedded"
      : row.role === "extraction_encoder" ? "tagged" : "generated");
    receipts.push(receipt);
  }
  const calls = providers.seenFixtureCalls.filter(call => call.fixtureId?.startsWith(`${round}-`));
  expect(calls.map(call => call.fixtureId)).toEqual([`${round}-reasoner`, `${round}-alternate`, `${round}-embed`, `${round}-tag`]);
  expect(new Set(calls.map(call => call.origin)).size).toBe(4);
  return receipts;
}

/* MODELS-01 Independent model slots and role bindings should work.
 * Canon: ARCH-0036 #inference-slots, #model-line, #roles; OF-126/129/131/132/133/134/138.
 * Partial: separate generate/embed/tag origins, real embedder route narrowing,
 * a reasoner-only rebind preserving all other rows and resident routes, and
 * restart durability. Invalid manifests, owner-only calls and one embedder
 * outage are refused without changing bindings. Fixture: scenarios.json.
 * Operator teacher approval is synthetic owner evidence, not model quality.
 * No off-device tagger, generative outage exhaustion or fallback receipt is
 * claimed. The two known identity/slot defects run only in the red variant.
 */
suite.test(test, "MODELS-01", "Independent slot routes and revision-pinned role calls survive a reasoner-only rebind and restart; invalid manifests and non-owner callers are refused", async () => {
  const providers = await ScriptedProviders.start({ id: "MODELS-01", steps: [
    ...models01Metadata(), ...models01RoundSteps("models01-initial"),
    models01EmbedStep("models01-narrow-embed"), ...models01RoundSteps("models01-rebound"),
    models01EmbedStep("models01-upstream-failure", true), ...models01RoundSteps("models01-restarted"),
  ] });
  try {
    const engine = await models01Start(providers);
    try {
      const client = engine.client;
      const manifest = await models01Manifest();
      const approval = models01Approval(manifest);
      expect(await client.call("vault.models.manifest.read", {})).toBeNull();
      for (const slot of models01Slots) expect(await client.call("vault.models.routes.read", { slot }))
        .toEqual({ slot, pin: null, route: null });
      await models01Refused(() => client.call("vault.models.manifest.replace", { manifest }), 400, "BAD_REQUEST");
      expect(await client.call("vault.models.manifest.read", {})).toBeNull();
      await models01Refused(() => client.call("vault.models.manifest.replace", {
        manifest, teacher_approval: { ...approval, binding_hash: "0".repeat(64) },
      }), 400, "BAD_REQUEST");
      expect(await client.call("vault.models.manifest.read", {})).toBeNull();
      expect(await client.call("vault.models.manifest.replace", { manifest, teacher_approval: approval })).toEqual(manifest);
      const initial = await models01State(client);
      expect(initial.manifest).toEqual(manifest);
      expect(initial.routes).toEqual(models01Slots.map(slot => ({ slot, pin: manifest.routes[slot], route: manifest.routes[slot] })));
      for (const row of initial.roles) {
        const binding = manifest.roles[row.role]!;
        expect(row).toMatchObject({ role: row.role, model: binding.model,
          revision: binding.model.split("@")[1], provider: binding.model.split("/")[0],
          slot: binding.slot, tier: binding.tier, route: manifest.routes[binding.slot] });
      }
      const firstCalls = await models01Round(client, providers, "models01-initial", "a");

      // A wider embedder pin declares a distinct local alternative; it is not failover.
      const widenedManifest = structuredClone(initial.manifest!);
      widenedManifest.routes.embedder = "own_server";
      widenedManifest.roles.retrieval_embedder = { ...widenedManifest.roles.retrieval_embedder!,
        model: "models-fixture/embedder-remote@rev-a", route_models: { on_device: "models-fixture/embedder@rev-a" } };
      expect(await client.call("vault.models.manifest.replace", { manifest: widenedManifest })).toEqual(widenedManifest);
      const widened = await models01State(client);
      expect(widened.manifest).toEqual(widenedManifest);
      expect(widened.routes).toEqual(initial.routes.map(view => view.slot === "embedder"
        ? { slot: "embedder", pin: "own_server", route: "own_server" } : view));
      expect(widened.roles.filter(row => row.role !== "retrieval_embedder"))
        .toEqual(initial.roles.filter(row => row.role !== "retrieval_embedder"));
      const beforeMismatch = providers.seenFixtureCalls.filter(call => !call.standing).length;
      const mismatch = await models01Refused(() => client.call("vault.models.roles.invoke", {
        role: "retrieval_embedder", input: { kind: "embed", text: models01Query },
      }), 503, "MODEL_UNAVAILABLE");
      expect(mismatch.error?.message).toBe("the retrieval embedder does not serve the pinned model and route");
      expect(providers.seenFixtureCalls.filter(call => !call.standing)).toHaveLength(beforeMismatch);
      await models01Unchanged(client, widened);
      expect(await client.call("vault.models.routes.replace", { slot: "embedder", route: "on_device" }))
        .toEqual({ slot: "embedder", pin: "own_server", route: "on_device" });
      const narrowed = await models01State(client);
      expect(narrowed.manifest).toEqual(widenedManifest);
      expect(narrowed.routes).toEqual(widened.routes.map(view => view.slot === "embedder" ? { ...view, route: "on_device" } : view));
      expect(narrowed.roles).toEqual(initial.roles);
      const narrowCall = await client.call("vault.models.roles.invoke", {
        role: "retrieval_embedder", input: { kind: "embed", text: models01Query },
      });
      expect(narrowCall).toMatchObject({ receipt: { model: "models-fixture/embedder@rev-a", route: "on_device" },
        output: { kind: "embedded", vector: [1, 0, 0, 0] } });

      // Copy the public read, and alter exactly one row's model.
      const reboundManifest = structuredClone(narrowed.manifest!);
      reboundManifest.roles.generative_reasoner!.model = "reasoner-b/reasoner@rev-b";
      expect(await client.call("vault.models.manifest.replace", { manifest: reboundManifest })).toEqual(reboundManifest);
      const rebound = await models01State(client);
      expect(rebound.manifest).toEqual(reboundManifest);
      expect(rebound.routes).toEqual(narrowed.routes);
      expect(rebound.manifest!.routes).toEqual(narrowed.manifest!.routes);
      for (const role of models01Roles) if (role !== "generative_reasoner") {
        expect(rebound.manifest!.roles[role]).toEqual(narrowed.manifest!.roles[role]);
        expect(rebound.roles.find(row => row.role === role)).toEqual(narrowed.roles.find(row => row.role === role));
      }
      const reboundCalls = await models01Round(client, providers, "models01-rebound", "b");
      expect(reboundCalls.slice(1)).toEqual(firstCalls.slice(1));

      const invalidManifests: ModelManifest[] = [];
      const unknownRole = structuredClone(reboundManifest);
      unknownRole.roles.unknown_role = { ...unknownRole.roles.local_reasoner! };
      invalidManifests.push(unknownRole);
      const encoderWrongSlot = structuredClone(reboundManifest);
      encoderWrongSlot.roles.extraction_encoder!.slot = "llm";
      invalidManifests.push(encoderWrongSlot);
      const missingRole = structuredClone(reboundManifest);
      delete missingRole.roles.local_reasoner;
      invalidManifests.push(missingRole);
      const missingRoute = structuredClone(reboundManifest);
      delete missingRoute.routes.oneironer;
      invalidManifests.push(missingRoute);
      const wrongVersion = structuredClone(reboundManifest);
      wrongVersion.version = 1;
      invalidManifests.push(wrongVersion);
      for (const invalid of invalidManifests) {
        await models01Refused(() => client.call("vault.models.manifest.replace", { manifest: invalid }), 400, "BAD_REQUEST");
        await models01Unchanged(client, rebound);
      }
      await models01Refused(() => client.call("vault.models.manifest.replace", {
        manifest: reboundManifest, teacher_approval: { ...approval, policy_hash: "0".repeat(64) },
      }), 400, "BAD_REQUEST");
      await models01Unchanged(client, rebound);
      await models01Refused(() => client.call("vault.models.routes.replace", { slot: "llm", route: "third_party" }), 400, "BAD_REQUEST");
      await models01Unchanged(client, rebound);
      await models01Refused(() => client.call("vault.models.roles.invoke", {
        role: "retrieval_embedder", input: { kind: "generate", request: models01Request() },
      }), 400, "BAD_REQUEST");
      await models01Unchanged(client, rebound);

      await client.call("vault.agents.create", { agent_def_ref: models01AgentRef,
        definition: { agent_id: "models01-observer", display_name: "MODELS-01 observer",
          desc: "Inert non-owner model observer", version: "1" } });
      expect(await client.call("vault.agents.get", { agent_def_ref: models01AgentRef }))
        .toMatchObject({ agent_def_ref: models01AgentRef, definition: { agent_id: "models01-observer", version: "1" } });
      const agent = await engine.pairActor(models01AgentRef);
      expect(await agent.call("self.actor", {})).toMatchObject({ actor_ref: models01AgentRef, actor_class: "agent" });
      const models01AgentRefusal = async <V extends FacadeVerb>(verb: V, input: FacadeInput<V>) => {
        const error = await models01Refused(() => agent.call(verb, input), 403, "FORBIDDEN");
        expect(error.error?.message).toBe(`${verb} is the vault owner's`);
        expect(error.error?.suggestions).toEqual(["Present the owner's own verified, unattenuated credential."]);
        await models01RefusalReceipt(client, error, verb, models01AgentRef);
      };
      const beforeAgent = providers.seenFixtureCalls.filter(call => !call.standing).length;
      await models01AgentRefusal("vault.models.manifest.read", {});
      await models01AgentRefusal("vault.models.manifest.replace", { manifest: reboundManifest });
      await models01AgentRefusal("vault.models.routes.read", { slot: "embedder" });
      await models01AgentRefusal("vault.models.routes.replace", { slot: "embedder", route: "on_device" });
      await models01AgentRefusal("vault.models.roles.read", { role: "generative_reasoner" });
      await models01AgentRefusal("vault.models.roles.invoke", { role: "generative_reasoner",
        input: { kind: "generate", request: models01Request() } });
      expect(providers.seenFixtureCalls.filter(call => !call.standing)).toHaveLength(beforeAgent);
      await models01Unchanged(client, rebound);

      const beforeFailure = providers.seenFixtureCalls.filter(call => !call.standing).length;
      const failure = await models01Refused(() => client.call("vault.models.roles.invoke", {
        role: "retrieval_embedder", input: { kind: "embed", text: models01Query },
      }), 503, "MODEL_UNAVAILABLE");
      expect(failure.error?.message).toBe("the retrieval embedder could not answer");
      expect(failure.reply.body).not.toHaveProperty("output");
      expect(providers.seenFixtureCalls.filter(call => !call.standing)).toHaveLength(beforeFailure + 1);
      const failureReceipt = await models01RefusalReceipt(client, failure, "vault.models.roles.invoke");
      await models01Unchanged(client, rebound);

      await engine.kill(); await engine.restart();
      expect(await models01State(client)).toEqual(rebound);
      expect(await client.call("vault.receipts.get", { receipt_ref: failureReceipt }))
        .toMatchObject({ receipt_ref: failureReceipt, outcome: { refused: { code: "MODEL_UNAVAILABLE" } } });
      const restartedCalls = await models01Round(client, providers, "models01-restarted", "b");
      expect(restartedCalls).toEqual(reboundCalls);
      await engine.artifacts.json("models01-observations.json", { initial, narrowed, rebound,
        firstCalls, reboundCalls, restartedCalls, failureReceipt, providerCalls: providers.seenFixtureCalls });
    } finally { await engine.close() }
  } finally { await providers.close() }
});

interface Models02Scenario {
  id: string;
  contract: { events: LlmStreamEvent[] };
  expected: { producerCalls: number; usage: LlmUsage };
}
function models02Chunk(id: string, delta: Json, barrier?: string): StreamPart {
  return { id, data: `data: ${JSON.stringify({ model: "test-model",
    choices: [{ index: 0, delta, finish_reason: null }] })}\n\n`,
    ...(barrier ? { barrier } : {}) };
}
function models02Step(origin: string, parts: StreamPart[]): ProviderStep {
  return { id: `models02-${origin}`, origin, role: "generative_reasoner",
    purpose: `models02-${origin}`, request: { method: "POST", path: "/v1/chat/completions",
      model: "test-model", fields: { stream: true, stream_options: { include_usage: true } } },
    response: { kind: "stream", contentType: "text/event-stream", parts } };
}
// One silent 16-bit mono sample at 8 kHz, encoded as a complete RIFF/WAVE clip.
function models02Wav(): string {
  const bytes = Buffer.alloc(46);
  bytes.write("RIFF", 0); bytes.writeUInt32LE(38, 4); bytes.write("WAVEfmt ", 8);
  bytes.writeUInt32LE(16, 16); bytes.writeUInt16LE(1, 20); bytes.writeUInt16LE(1, 22);
  bytes.writeUInt32LE(8000, 24); bytes.writeUInt32LE(16000, 28);
  bytes.writeUInt16LE(2, 32); bytes.writeUInt16LE(16, 34);
  bytes.write("data", 36); bytes.writeUInt32LE(2, 40);
  return bytes.toString("base64");
}
function models02Request(provider: string, text: string): LlmRequest {
  return { model: `${provider}/test-model@rev-a`, envelope: { purpose: "answer_gen",
    class: { kind: "best_effort" }, tier: { global_default: "fixture-pinned" },
    response_format: { format: "text" }, locality: "own_server" },
    messages: [{ role: "user", content: [{ kind: "text", text }] }] };
}
async function models02PollEvents(
  read: () => Promise<FacadeResult<"ai.streams.events">>,
  events: LlmStreamEvent[],
  ready: (page: FacadeResult<"ai.streams.events">, all: LlmStreamEvent[]) => boolean,
  label: string,
) {
  return awaitPublic(async () => {
    const page = await read();
    events.push(...page.events);
    return page;
  }, page => ready(page, events), { label });
}
async function models02HttpRefusal<V extends FacadeVerb>(
  engine: EngineFixture, client: PublicHttpClient, verb: V, input: FacadeInput<V>,
  status: number, code: string,
) {
  let failure: unknown;
  try { await client.call(verb, input); } catch (error) { failure = error; }
  if (!(failure instanceof PublicHttpError)) throw new Error(`Expected public refusal for ${verb}`);
  expect(failure.reply.status).toBe(status);
  expect(failure.error?.code).toBe(code);
  const receiptRef = failure.error?.receiptRef;
  expect(receiptRef).toEqual(expect.stringMatching(/^call:[a-f0-9]{32}$/));
  if (typeof receiptRef !== "string") throw new Error(`Missing refusal receipt for ${verb}`);
  expect(failure.reply.headers.get("x-oneiron-receipt-ref")).toBe(receiptRef);
  const receipt = await awaitPublic(
    () => engine.client.call("vault.receipts.get", { receipt_ref: receiptRef }),
    value => value !== null, { label: `models02 refusal receipt ${verb}` });
  expect(receipt).toMatchObject({ receipt_ref: receiptRef, transport: "http_facade",
    verb: `v1/core/facade/${verb}`, outcome: { refused: { code } } });
  return { failure, receipt };
}

/* MODELS-02 Typed multimodal streaming should work.
 * Canon: ARCH-0036 #model-line, ARCH-0026 #run-tree; OF-126/136.
 * Partial: one multimodal-input producer fans correlated reasoning/text to
 * HTTP and WS RPC polls. Detach loses only the slow handle; abort retains
 * delivered parts. A post-delta stall fails within its provider budget.
 * Finished terminals survive restart without another provider request;
 * release clears transient handles/replay, not the durable terminal.
 * waits on an image-output-capable provider adapter behind owner-authorized
 * ai.streams.open, with image events/ContentPart through events/terminal.
 * WS push remains unproved: ai.streams.events is RPC polling, not push.
 * Audio is input evidence, never an invented audio_* event. scenarios.json
 * supplies content and numeric usage; the chat decoder supplies part IDs.
 */
suite.test(test, "MODELS-02", "Shared multimodal-input text/reasoning stream reaches HTTP and WS subscribers, detaches one, and retains its terminal across restart", async () => {
  const catalog = await loadFixtures();
  const document = await catalog.readJson<{ scenarios: Models02Scenario[] }>("models-scenarios");
  const facts = document.scenarios.find(row => row.id === "MODELS-02");
  if (!facts) throw new Error("Missing MODELS-02 fixture");
  const fixtureDone = facts.contract.events.find(event => event.event === "done");
  const fixtureImage = facts.contract.events.find(event => event.event === "image_end");
  if (!fixtureDone || fixtureDone.event !== "done" || !fixtureImage || fixtureImage.event !== "image_end"
      || fixtureImage.image.source !== "base64")
    throw new Error("MODELS-02 needs authored content and image evidence");
  const imageData = fixtureImage.image.data;
  const expectedContent = fixtureDone.message.content.filter(part => part.kind === "reasoning" || part.kind === "text");
  const reasoning = expectedContent.find(part => part.kind === "reasoning");
  const answer = expectedContent.find(part => part.kind === "text");
  if (!reasoning || reasoning.kind !== "reasoning" || !answer || answer.kind !== "text")
    throw new Error("MODELS-02 needs reasoning and text facts");
  expect(reasoning.text).toBe("Read fixture evidence.");
  expect(answer.text).toBe("Fixture answer.");
  const request = models02Request("chat", reasoning.text);
  request.messages[0]!.content.push(
    { kind: "image", media_type: fixtureImage.media_type, image: fixtureImage.image },
    { kind: "audio", media_type: "audio/wav", data: models02Wav() },
  );
  const sharedKey = "models02-shared";
  const cancelKey = "models02-cancel";
  const slowKey = "models02-slow";
  const cancelRequest = models02Request("cancel", "Cancel after delivered parts.");
  const slowRequest = models02Request("slow", "Stop waiting after the first delta.");
  const providers = await ScriptedProviders.start({ id: "MODELS-02", steps: [
    models02Step("chat", [
      models02Chunk("models02-reason-first", { reasoning_content: "Read fixture " }),
      models02Chunk("models02-text-first", { content: "Fixture " }, "models02-first-part"),
      models02Chunk("models02-reason-last", { reasoning_content: "evidence." }),
      models02Chunk("models02-text-last", { content: "answer." }),
      { id: "models02-stop", barrier: "models02-before-done", data:
        'data: {"model":"test-model","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}\n\n' },
      { id: "models02-usage", data: `data: ${JSON.stringify({ model: "test-model", choices: [], usage: {
        prompt_tokens: facts.expected.usage.input.total, completion_tokens: facts.expected.usage.output.total,
        prompt_tokens_details: { cached_tokens: facts.expected.usage.input.cache_read },
        completion_tokens_details: { reasoning_tokens: facts.expected.usage.output.reasoning },
      } })}\n\n` },
      { id: "models02-done", data: "data: [DONE]\n\n" },
    ]),
    models02Step("cancel", [
      models02Chunk("models02-cancel-reason", { reasoning_content: "Cancellation evidence." }),
      models02Chunk("models02-cancel-text", { content: "Delivered partial." }),
      models02Chunk("models02-cancel-undelivered", { content: " Must not be delivered." }, "models02-cancel-held"),
    ]),
    models02Step("slow", [
      models02Chunk("models02-slow-text", { content: "Before timeout." }),
      models02Chunk("models02-slow-undelivered", { content: " Must not be delivered." }, "models02-slow-held"),
    ]),
  ] });
  let engine: EngineFixture | undefined;
  let ws: WsClient | undefined;
  try {
    engine = await EngineFixture.start({ id: "MODELS-02", profile, serverConfig: `
[models]
default = "chat:test-model"
[models.providers.chat]
kind = "local-openai-compat"
base_url = "${providers.urls.chat}"
revision = "rev-a"
request_compression = false
timeout_secs = 10
capabilities = ["streaming", "json_response", "reasoning", "image_input", "audio_input"]
[models.providers.cancel]
kind = "local-openai-compat"
base_url = "${providers.urls.cancel}"
revision = "rev-a"
request_compression = false
timeout_secs = 10
[models.providers.slow]
kind = "local-openai-compat"
base_url = "${providers.urls.slow}"
revision = "rev-a"
request_compression = false
timeout_secs = 1
[models.roles.local_reasoner]
model = "cancel:test-model"
[models.roles.checker]
model = "slow:test-model"
[models.dreamer]
enabled = false
` });
    const owner = engine.client;
    ws = await engine.websocket();
    const fast = await owner.call("ai.streams.subscribe", { stream_key: sharedKey });
    const slow = (await ws.call("ai.streams.subscribe", { stream_key: sharedKey })).value;
    expect(fast.status).toBe("pending");
    expect(slow).toMatchObject({ stream_ref: fast.stream_ref, stream_key: sharedKey, status: "pending" });
    expect(slow.handle).not.toBe(fast.handle);
    expect(providers.seenFixtureCalls).toHaveLength(0);
    const opened = await owner.call("ai.streams.open", { stream_key: sharedKey, request });
    expect(opened).toEqual({ stream_ref: fast.stream_ref, stream_key: sharedKey,
      model: request.model, status: "live" });
    await providers.awaitBarrier("models02-first-part");
    const fastEvents: LlmStreamEvent[] = [];
    const fastRead = () => owner.call("ai.streams.events", { stream_key: sharedKey, handle: fast.handle, limit: 512 });
    await models02PollEvents(fastRead, fastEvents,
      (_page, all) => all.some(event => event.event === "reasoning_delta"), "models02 first HTTP reasoning");
    const slowEvents: LlmStreamEvent[] = [];
    await models02PollEvents(async () => (await ws!.call("ai.streams.events", {
      stream_key: sharedKey, handle: slow.handle, limit: 512 })).value, slowEvents,
      (_page, all) => all.some(event => event.event === "reasoning_delta"), "models02 first WS reasoning");
    expect(slowEvents).toEqual(fastEvents);
    expect(fastEvents.map(event => event.event)).toEqual(["reasoning_start", "reasoning_delta"]);
    expect(await owner.call("ai.streams.open", { stream_key: sharedKey, request })).toEqual(opened);
    expect(providers.seenFixtureCalls).toHaveLength(facts.expected.producerCalls);
    expect((await ws.call("ai.streams.detach", { stream_key: sharedKey, handle: slow.handle })).value)
      .toEqual({ stream_ref: fast.stream_ref, stream_key: sharedKey, handle: slow.handle, detached: true });
    // Read through HTTP after the WS mutation; the other handle remains usable.
    await models02HttpRefusal(engine, owner, "ai.streams.events", {
      stream_key: sharedKey, handle: slow.handle }, 404, "NOT_FOUND");
    providers.releaseBarrier("models02-first-part");
    await providers.awaitBarrier("models02-before-done");
    await models02PollEvents(fastRead, fastEvents, (_page, all) =>
      all.filter(event => event.event === "text_delta").length === 2
      && all.filter(event => event.event === "reasoning_delta").length === 2, "models02 continued HTTP delivery");
    expect((await fastRead()).closed).toBe(false);
    providers.releaseBarrier("models02-before-done");
    const closed = await models02PollEvents(fastRead, fastEvents, page => page.closed, "models02 successful close");
    expect(closed.status).toBe("finished");
    expect(fastEvents.map(event => event.event)).toEqual([
      "reasoning_start", "reasoning_delta", "text_start", "text_delta", "reasoning_delta", "text_delta",
      "reasoning_end", "text_end", "done",
    ]);
    for (const event of fastEvents) {
      if (event.event.startsWith("reasoning_") && "part_id" in event) expect(event.part_id).toBe("reasoning-0");
      if (event.event.startsWith("text_") && "part_id" in event) expect(event.part_id).toBe("text-0");
    }
    expect(fastEvents.filter(event => event.event === "reasoning_delta").map(event => event.text))
      .toEqual(["Read fixture ", "evidence."]);
    expect(fastEvents.filter(event => event.event === "text_delta").map(event => event.text))
      .toEqual(["Fixture ", "answer."]);
    const done = fastEvents.find(event => event.event === "done");
    if (!done || done.event !== "done") throw new Error("Missing typed Done");
    expect(done.message.role).toBe("assistant");
    expect(done.message.content).toHaveLength(2);
    expect(done.message.content).toMatchObject(expectedContent);
    expect(done.finish_reason).toBe("stop");
    expect(done.usage.input).toEqual(facts.expected.usage.input);
    expect(done.usage.output).toEqual(facts.expected.usage.output);
    const terminal = await owner.call("ai.streams.terminal", { stream_key: sharedKey });
    expect(terminal).toMatchObject({ stream_ref: fast.stream_ref, stream_key: sharedKey,
      model: request.model, status: "finished", response: {
        message: done.message, usage: done.usage, finish_reason: done.finish_reason } });
    expect(terminal.failure ?? null).toBeNull();
    expect(providers.seenFixtureCalls).toHaveLength(1);
    const providerBody = providers.seenFixtureCalls[0]!.body;
    expect(providerBody).toMatchObject({ model: "test-model", stream: true,
      stream_options: { include_usage: true }, messages: [{ role: "user", content: [
        { type: "text", text: reasoning.text },
        { type: "image_url", image_url: { url: `data:image/png;base64,${imageData}` } },
        { type: "input_audio", input_audio: { data: models02Wav(), format: "wav" } },
      ] }] });

    const agentRef = "b202b202b202b202b202b202b202b202";
    await owner.call("vault.agents.create", { agent_def_ref: agentRef, definition: {
      agent_id: "models02-non-owner", display_name: "Models stream non-owner",
      desc: "Inert principal for owner-only stream refusals", version: "1" } });
    expect((await owner.call("vault.get", { entity_ref: agentRef })).value?.kind).toBe("AGENT_DEF");
    const agent = await engine.pairActor({ principalRef: agentRef, actorClass: "agent" });
    expect(await agent.client.call("self.actor", {})).toMatchObject({ actor_ref: agentRef, actor_class: "agent" });
    const cancelUsage: LlmUsage = { input: { total: 0, cache_read: 0, cache_write: 0 },
      output: { total: 0, text: 0, reasoning: 0 }, raw_provider: { fixture: "models02-cancel" } };
    const models02RefuseOwner = async <V extends FacadeVerb>(verb: V, input: FacadeInput<V>) => {
      const { failure, receipt } = await models02HttpRefusal(engine!, agent.client, verb, input, 403, "FORBIDDEN");
      expect(failure.error?.message).toBe(`${verb} is the vault owner's`);
      expect(receipt).toMatchObject({ actor_ref: agentRef, actor_class: "agent" });
    };
    await models02RefuseOwner("ai.streams.open", { stream_key: sharedKey, request });
    await models02RefuseOwner("ai.streams.subscribe", { stream_key: sharedKey });
    await models02RefuseOwner("ai.streams.events", { stream_key: sharedKey, handle: fast.handle });
    await models02RefuseOwner("ai.streams.detach", { stream_key: sharedKey, handle: fast.handle });
    await models02RefuseOwner("ai.streams.abort", { stream_key: sharedKey, usage: cancelUsage });
    await models02RefuseOwner("ai.streams.terminal", { stream_key: sharedKey });
    await models02RefuseOwner("ai.streams.release", { stream_key: sharedKey });
    expect(await owner.call("ai.streams.terminal", { stream_key: sharedKey })).toEqual(terminal);
    expect(await fastRead()).toMatchObject({ events: [], closed: true, status: "finished" });
    expect(providers.seenFixtureCalls).toHaveLength(1);

    const cancelSub = await owner.call("ai.streams.subscribe", { stream_key: cancelKey });
    await owner.call("ai.streams.open", { stream_key: cancelKey, request: cancelRequest });
    await providers.awaitBarrier("models02-cancel-held");
    const cancelEvents: LlmStreamEvent[] = [];
    const cancelRead = () => owner.call("ai.streams.events", { stream_key: cancelKey, handle: cancelSub.handle });
    await models02PollEvents(cancelRead, cancelEvents, (_page, all) =>
      all.some(event => event.event === "text_delta"), "models02 delivered before abort");
    const cancelled = await owner.call("ai.streams.abort", { stream_key: cancelKey, usage: cancelUsage });
    expect(cancelled).toMatchObject({ status: "finished", response: { finish_reason: "cancelled",
      message: { role: "assistant", content: [
        { kind: "reasoning", text: "Cancellation evidence." }, { kind: "text", text: "Delivered partial." },
      ] }, usage: cancelUsage } });
    expect(cancelled.response?.message.content).toHaveLength(2);
    expect(await owner.call("ai.streams.terminal", { stream_key: cancelKey })).toEqual(cancelled);
    await models02PollEvents(cancelRead, cancelEvents, page => page.closed, "models02 cancelled subscriber close");
    const cancelledDone = cancelEvents.find(event => event.event === "done");
    if (!cancelledDone || cancelledDone.event !== "done") throw new Error("Abort omitted Done");
    expect(cancelledDone.message).toEqual(cancelled.response?.message);
    expect(cancelledDone.finish_reason).toBe("cancelled");
    expect(cancelledDone.usage).toEqual(cancelUsage);
    expect(cancelEvents.filter(event => event.event === "done")).toHaveLength(1);
    providers.releaseBarrier("models02-cancel-held");
    expect(await owner.call("ai.streams.open", { stream_key: cancelKey, request: cancelRequest }))
      .toMatchObject({ stream_ref: cancelSub.stream_ref, status: "finished" });
    expect(await owner.call("ai.streams.terminal", { stream_key: cancelKey })).toEqual(cancelled);
    expect(providers.seenFixtureCalls.filter(call => call.origin === "cancel")).toHaveLength(1);

    const slowSub = await owner.call("ai.streams.subscribe", { stream_key: slowKey });
    await owner.call("ai.streams.open", { stream_key: slowKey, request: slowRequest });
    await providers.awaitBarrier("models02-slow-held");
    const slowFailureEvents: LlmStreamEvent[] = [];
    const slowRead = () => owner.call("ai.streams.events", { stream_key: slowKey, handle: slowSub.handle });
    await models02PollEvents(slowRead, slowFailureEvents, (_page, all) =>
      all.some(event => event.event === "text_delta"), "models02 delivered before timeout");
    await models02PollEvents(slowRead, slowFailureEvents, page => page.closed, "models02 provider timeout closes bus");
    const failed = await awaitPublic(() => owner.call("ai.streams.terminal", { stream_key: slowKey }),
      value => value.status === "failed", { label: "models02 durable timeout failure" });
    expect(failed).toMatchObject({ stream_ref: slowSub.stream_ref, model: slowRequest.model, status: "failed" });
    expect(failed.response ?? null).toBeNull();
    expect(failed.failure).toEqual(expect.any(String));
    expect(failed.failure!.length).toBeGreaterThan(0);
    expect(slowFailureEvents.map(event => event.event)).toEqual(["text_start", "text_delta"]);
    expect(slowFailureEvents[1]).toMatchObject({ part_id: "text-0", text: "Before timeout." });
    providers.releaseBarrier("models02-slow-held");
    expect(providers.seenFixtureCalls.filter(call => call.origin === "slow")).toHaveLength(1);

    ws.close(); ws = undefined;
    await engine.kill();
    await engine.restart();
    expect(await owner.call("ai.streams.terminal", { stream_key: sharedKey })).toEqual(terminal);
    expect(await owner.call("ai.streams.terminal", { stream_key: cancelKey })).toEqual(cancelled);
    expect(await owner.call("ai.streams.terminal", { stream_key: slowKey })).toEqual(failed);
    await models02HttpRefusal(engine, owner, "ai.streams.events", {
      stream_key: sharedKey, handle: fast.handle }, 404, "NOT_FOUND");
    const retained = await owner.call("ai.streams.subscribe", { stream_key: sharedKey });
    expect(retained).toMatchObject({ stream_ref: terminal.stream_ref, status: "finished" });
    expect(await owner.call("ai.streams.events", { stream_key: sharedKey, handle: retained.handle }))
      .toMatchObject({ events: [], closed: true, status: "finished" });
    expect(await owner.call("ai.streams.release", { stream_key: sharedKey }))
      .toEqual({ stream_ref: terminal.stream_ref, stream_key: sharedKey, status: "finished", released: true });
    await models02HttpRefusal(engine, owner, "ai.streams.events", {
      stream_key: sharedKey, handle: retained.handle }, 404, "NOT_FOUND");
    expect(await owner.call("ai.streams.terminal", { stream_key: sharedKey })).toEqual(terminal);
    const afterRelease = await owner.call("ai.streams.subscribe", { stream_key: sharedKey });
    expect(await owner.call("ai.streams.events", { stream_key: sharedKey, handle: afterRelease.handle }))
      .toMatchObject({ stream_ref: terminal.stream_ref, events: [], closed: true, status: "finished" });
    expect(await owner.call("ai.streams.open", { stream_key: sharedKey, request }))
      .toMatchObject({ stream_ref: terminal.stream_ref, status: "finished" });
    expect(providers.seenFixtureCalls.map(call => call.fixtureId)).toEqual([
      "models02-chat", "models02-cancel", "models02-slow",
    ]);
  } finally {
    for (const barrier of ["models02-first-part", "models02-before-done", "models02-cancel-held", "models02-slow-held"])
      providers.releaseBarrier(barrier);
    ws?.close();
    try { await engine?.close(); } finally { await providers.close(); }
  }
});

type ModelSubmit = FacadeInput<"ai.steps.submit">;
type ModelReceipt = FacadeResult<"ai.steps.receipt">;
type ModelFailure = Extract<NonNullable<ModelReceipt["result"]>, { status: "failed" }>["failure"];
type ModelStepVerb = "ai.steps.submit" | "ai.steps.receipt";
interface ModelTerminal { input: ModelSubmit; receipt: ModelReceipt }
interface ModelOffer { name: string; url: string; nativeJson: boolean }
interface ModelFailureScenario {
  id: string;
  sequences: {
    fatalWithoutFallback: { status: number; body: Json }[];
    fatalWithDeclaredFallback: { status: number; body: Json }[];
  };
  expected: { fatalAttempts: number; fallbackValue: { outcome: string; reason: string } };
}
async function modelScenario<T extends { id: string }>(id: string): Promise<T> {
  const catalog = await loadFixtures();
  const data = await catalog.readJson<{ scenarios: T[] }>("models-scenarios");
  const selected = data.scenarios.find(row => row.id === id);
  if (!selected) throw new Error(`Missing model scenario ${id}`);
  return selected;
}
function modelStepConfig(offers: readonly ModelOffer[]): string {
  return `[models.dreamer]\nenabled = false\n` + offers.map(offer => `
[models.providers.${offer.name}]
kind = "local-openai-compat"
base_url = ${JSON.stringify(offer.url)}
revision = "rev-a"
timeout_secs = 1
request_compression = false
capabilities = ${offer.nativeJson ? '["json_response"]' : '[]'}
`).join("") + `\n[models.roles.generative_reasoner]\nrungs = [\n` +
    offers.map(offer => `  { model = "${offer.name}:reasoner" }`).join(",\n") + "\n]\n";
}
function modelStepInput(step_key: string, provider: string,
  response_format: ModelSubmit["request"]["envelope"]["response_format"] = { format: "text" },
  callClass: ModelSubmit["request"]["envelope"]["class"] = { kind: "best_effort" },
  max_attempts = 1): ModelSubmit {
  return {
    step_key, retry: { max_attempts },
    request: {
      model: `${provider}/reasoner@rev-a`,
      envelope: { purpose: "answer_gen", class: callClass,
        tier: { global_default: "fixture" }, response_format, locality: "own_server" },
      messages: [{ role: "user", content: [{ kind: "text", text: "Return the fixture result." }] }],
      params: { temperature: 0, max_tokens: 32 },
    },
  };
}
function modelProviderStep(origin: string, id: string, response: ProviderResponse,
  fields: Record<string, Json> = {}, barrier?: string): ProviderStep {
  return { id, origin, role: "generative_reasoner", purpose: "answer_gen",
    request: { method: "POST", path: "/v1/chat/completions", model: "reasoner",
      fields: { stream: false, temperature: 0, max_tokens: 32, ...fields } },
    response, ...(barrier === undefined ? {} : { barrier }) };
}
function modelCallCount(providers: ScriptedProviders, origin: string): number {
  return providers.seenFixtureCalls.filter(call => call.origin === origin).length;
}
function expectModelIdentity(receipt: ModelReceipt, input: ModelSubmit): void {
  expect(receipt.step_ref).toMatch(/^[a-f0-9]{32}$/);
  expect(receipt.step_hash).toMatch(/^[a-f0-9]{64}$/);
  expect(receipt.model).toBe(input.request.model);
  expect(receipt.retry).toEqual(input.retry);
}
function expectModelFinished(receipt: ModelReceipt, json: unknown) {
  expect(receipt.progression).toBe("finished");
  expect(receipt.result?.status).toBe("finished");
  if (receipt.result?.status !== "finished") throw new Error("Model step did not finish");
  const result = receipt.result;
  expect(result.json ?? null).toEqual(json);
  expect(result.claim_ref).toMatch(/^[a-f0-9]{32}$/);
  expect(result.response.message.role).toBe("assistant");
  const text = result.response.message.content.flatMap(part => part.kind === "text" ? [part.text] : []).join("");
  expect(text.trim().length).toBeGreaterThan(0);
  return result;
}
function expectModelFailed(receipt: ModelReceipt, failureClass: ModelFailure["class"],
  llm?: NonNullable<ModelFailure["llm"]>): ModelFailure {
  expect(receipt.result?.status).toBe("failed");
  if (receipt.result?.status !== "failed") throw new Error("Expected a failed model-step receipt");
  const result = receipt.result;
  expect(result.failure.class).toBe(failureClass);
  expect(result.failure.message.trim().length).toBeGreaterThan(0);
  if (llm !== undefined) expect(result.failure.llm).toMatchObject(llm);
  expect(result).not.toHaveProperty("response");
  expect(result).not.toHaveProperty("json");
  expect(result).not.toHaveProperty("fallback_source");
  return result.failure;
}
function expectModelReplay(original: ModelReceipt, current: ModelReceipt, submitted = false): void {
  if (original.result?.status === "finished") {
    expect(current).toEqual({ ...original, result: { ...original.result,
      memoized: submitted ? true : original.result.memoized } });
  } else {
    expect(current).toEqual(original);
  }
}
async function observeModelTerminal(engine: EngineFixture, input: ModelSubmit,
  receipt: ModelReceipt): Promise<ModelTerminal> {
  expectModelIdentity(receipt, input);
  expect(["finished", "failed"]).toContain(receipt.result?.status);
  const stored = await engine.client.call("ai.steps.receipt", { step_key: input.step_key });
  expectModelReplay(receipt, stored);
  return { input, receipt: stored };
}
async function modelRefusalAgent(engine: EngineFixture, id: string): Promise<PairedActor> {
  const created = await engine.client.call("vault.agents.create", {
    agent_def_ref: id,
    definition: { agent_id: "models-non-owner", display_name: "Models non-owner",
      desc: "Inert model-step refusal principal", version: "1" },
  });
  expect(created.agent_def_ref).toBe(id);
  const entity = await engine.client.call("vault.get", { entity_ref: id });
  expect(entity.value?.kind).toBe("AGENT_DEF");
  const actor = await engine.pairActor({ principalRef: id, actorClass: "agent" });
  const identity = await actor.client.call("self.actor", {});
  expect(identity.actor_ref).toBe(id);
  expect(identity.actor_class).toBe("agent");
  return actor;
}
async function modelHttpError(operation: () => Promise<unknown>, status: number,
  code: string, message: string): Promise<PublicHttpError> {
  let caught: unknown;
  try { await operation(); } catch (error) { caught = error; }
  expect(caught).toBeInstanceOf(PublicHttpError);
  if (!(caught instanceof PublicHttpError)) throw new Error("Expected a public HTTP refusal");
  expect(caught.reply.status).toBe(status);
  expect(caught.error?.code).toBe(code);
  expect(caught.error?.message).toBe(message);
  return caught;
}
async function observeModelCallRefusal(engine: EngineFixture, receiptRef: unknown,
  actor: PairedActor, transport: "http_facade" | "mcp", code: string): Promise<void> {
  expect(typeof receiptRef).toBe("string");
  if (typeof receiptRef !== "string") throw new Error("Refusal omitted its call receipt");
  expect(receiptRef).toMatch(/^call:[a-f0-9]{32}$/);
  // Call receipts commit asynchronously; only this public read is repeated.
  const receipt = await awaitPublic(
    () => engine.client.call("vault.receipts.get", { receipt_ref: receiptRef }),
    value => value !== null, { label: "model-step refusal call receipt" });
  expect(receipt).toMatchObject({ receipt_ref: receiptRef, transport,
    actor_ref: actor.principalRef, actor_class: "agent", outcome: { refused: { code } } });
}
async function expectModelOwnerRefusals(engine: EngineFixture, actor: PairedActor,
  existing: ModelSubmit): Promise<void> {
  const refusedInput = { ...existing, step_key: `${existing.step_key}-agent-refused` };
  const operations: { verb: ModelStepVerb; call: () => Promise<unknown> }[] = [
    { verb: "ai.steps.submit", call: () => actor.client.call("ai.steps.submit", refusedInput) },
    { verb: "ai.steps.receipt", call: () => actor.client.call("ai.steps.receipt", { step_key: existing.step_key }) },
  ];
  for (const operation of operations) {
    const error = await modelHttpError(operation.call, 403, "FORBIDDEN", `${operation.verb} is the vault owner's`);
    expect(error.error?.suggestions).toContain("Present the owner's own verified, unattenuated credential.");
    await observeModelCallRefusal(engine, error.error?.receiptRef, actor, "http_facade", "FORBIDDEN");
  }
}
async function refusedModelOrigin(): Promise<string> {
  const server = createServer();
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  try {
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("No reserved loopback port");
    return `http://127.0.0.1:${address.port}`;
  } finally {
    await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  }
}

/* MODELS-03 One retry authority and explicit failure should work.
 * Canon: ARCH-0026 #run-tree, ARCH-0036 #model-line; OF-130/140.
 * Partial: fatal/no fallback, declared deterministic fallback, four isolated
 * provider faults, Started serialization, owner refusal and terminal replay.
 * 503 recovery and exhaustion stay unproved under FIX 11226: health/probation
 * rest must park the durable step without spending a declared attempt; the
 * public receipt must expose that park and resume it when the offer is due.
 * Only Started and terminal Finished are observed, not checkpoint history.
 */
suite.test(test, "MODELS-03", "Fatal model failure is explicit, declared deterministic fallback and terminal replay survive restart", async () => {
  const facts = await modelScenario<ModelFailureScenario>("MODELS-03");
  const fatal = facts.sequences.fatalWithoutFallback[0]!;
  const fallbackFatal = facts.sequences.fatalWithDeclaredFallback[0]!;
  const providers = await ScriptedProviders.start({ id: "MODELS-03", steps: [
    modelProviderStep("m03-fatal", "m03-fatal-400", { kind: "json", status: fatal.status, body: fatal.body }),
    modelProviderStep("m03-fallback", "m03-fallback-400", { kind: "json", status: fallbackFatal.status, body: fallbackFatal.body }),
    modelProviderStep("m03-slow", "m03-timeout", openaiText("m03-late", "reasoner", "Too late", { inputTokens: 4, outputTokens: 2 }), {}, "m03-timeout-reply"),
    modelProviderStep("m03-garbage", "m03-not-json", { kind: "bytes", contentType: "text/plain", body: new TextEncoder().encode("not-json") }),
    modelProviderStep("m03-empty", "m03-empty-choices", { kind: "json", body: { choices: [] } }),
    modelProviderStep("m03-started", "m03-started-answer", openaiText("m03-started", "reasoner", "completed", { inputTokens: 4, outputTokens: 2 }), {}, "m03-started-reply"),
  ] });
  try {
    const origin = await refusedModelOrigin();
    const offers: ModelOffer[] = Object.entries(providers.urls).map(([name, url]) => ({ name, url, nativeJson: name === "m03-fallback" }));
    offers.push({ name: "m03-refused", url: origin, nativeJson: false });
    const engine = await EngineFixture.start({ id: "MODELS-03", profile, serverConfig: modelStepConfig(offers) });
    try {
      const terminals: ModelTerminal[] = [];
      const fatalDetail = { InvalidRequestDetail: { message: "fixture fatal" } };
      const fatalInput = modelStepInput("MODELS-03-fatal-v1", "m03-fatal", { format: "text" }, { kind: "best_effort" }, 3);
      const fatalReceipt = await engine.client.call("ai.steps.submit", fatalInput);
      expectModelFailed(fatalReceipt, "fatal", { Fatal: fatalDetail });
      expect(modelCallCount(providers, "m03-fatal")).toBe(facts.expected.fatalAttempts);
      terminals.push(await observeModelTerminal(engine, fatalInput, fatalReceipt));

      const value = facts.expected.fallbackValue;
      const fallbackSchema: Json = { type: "object", properties: {
        outcome: { type: "string", const: value.outcome }, reason: { type: "string", const: value.reason },
      }, required: ["outcome", "reason"], additionalProperties: false };
      const fallbackInput = modelStepInput("MODELS-03-fallback-v1", "m03-fallback", { format: "json", schema: fallbackSchema },
        { kind: "durable", fallback: { name: "json_rules_v1", config: {
          version: 1, rows: [{ failure: "invalid_request", value }],
        } } }, 3);
      const fallbackReceipt = await engine.client.call("ai.steps.submit", fallbackInput);
      const fallback = expectModelFinished(fallbackReceipt, value);
      expect(fallback.memoized).toBe(false);
      expect(fallback.fallback_source).toMatchObject(fatalDetail);
      expect(modelCallCount(providers, "m03-fallback")).toBe(facts.expected.fatalAttempts);
      terminals.push(await observeModelTerminal(engine, fallbackInput, fallbackReceipt));

      const refusedInput = modelStepInput("MODELS-03-refused-v1", "m03-refused");
      const callsBeforeConnectionFault = providers.seenFixtureCalls;
      const refusedReceipt = await engine.client.call("ai.steps.submit", refusedInput);
      expectModelFailed(refusedReceipt, "retryable", { Retryable: "StreamCut" });
      expect(providers.seenFixtureCalls).toEqual(callsBeforeConnectionFault);
      terminals.push(await observeModelTerminal(engine, refusedInput, refusedReceipt));

      const slowInput = modelStepInput("MODELS-03-timeout-v1", "m03-slow");
      const pendingSlow = engine.client.call("ai.steps.submit", slowInput);
      void pendingSlow.catch(() => {});
      try {
        await providers.awaitBarrier("m03-timeout-reply");
        // Keep the reply held until the real provider timeout has returned.
        const receipt = await pendingSlow;
        expectModelFailed(receipt, "retryable", { Retryable: "Timeout" });
        expect(modelCallCount(providers, "m03-slow")).toBe(1);
        terminals.push(await observeModelTerminal(engine, slowInput, receipt));
      } finally {
        providers.releaseBarrier("m03-timeout-reply");
        await pendingSlow.catch(() => {});
      }
      for (const fault of [
        { name: "garbage", provider: "m03-garbage", failureClass: "retryable", llm: { Retryable: "ServerError" } },
        { name: "empty", provider: "m03-empty", failureClass: "fatal", llm: { Fatal: "EmptyResponse" } },
      ] satisfies { name: string; provider: string; failureClass: ModelFailure["class"]; llm: NonNullable<ModelFailure["llm"]> }[]) {
        const input = modelStepInput(`MODELS-03-${fault.name}-v1`, fault.provider);
        const receipt = await engine.client.call("ai.steps.submit", input);
        expectModelFailed(receipt, fault.failureClass, fault.llm);
        expect(modelCallCount(providers, fault.provider)).toBe(1);
        terminals.push(await observeModelTerminal(engine, input, receipt));
      }

      const agent = await modelRefusalAgent(engine, "03030303030303030303030303030303");
      const callsBeforeRefusal = providers.seenFixtureCalls;
      await expectModelOwnerRefusals(engine, agent, fatalInput);
      expect(providers.seenFixtureCalls).toEqual(callsBeforeRefusal);

      const startedInput = modelStepInput("MODELS-03-started-v1", "m03-started");
      const pendingStarted = engine.client.call("ai.steps.submit", startedInput);
      void pendingStarted.catch(() => {});
      try {
        await providers.awaitBarrier("m03-started-reply");
        const started = await engine.client.call("ai.steps.receipt", { step_key: startedInput.step_key });
        expectModelIdentity(started, startedInput);
        expect(started.progression).toBe("started");
        expect(started.result).toBeNull();
        const busy = await engine.client.call("ai.steps.submit", startedInput);
        expect(busy).toEqual(started);
        expect(modelCallCount(providers, "m03-started")).toBe(1);
      } finally {
        providers.releaseBarrier("m03-started-reply");
        await pendingStarted.catch(() => {});
      }
      const completed = await pendingStarted;
      const completedResult = expectModelFinished(completed, null);
      expect(completedResult.fallback_source ?? null).toBeNull();
      expect(completedResult.memoized).toBe(false);
      expect(completedResult.response.message.content).toEqual([{ kind: "text", text: "completed" }]);
      terminals.push(await observeModelTerminal(engine, startedInput, completed));
      expect(providers.seenFixtureCalls).toHaveLength(6);
      expect(providers.seenFixtureCalls.every(call => call.fixtureId !== null)).toBe(true);

      const callsBeforeReplay = providers.seenFixtureCalls;
      for (const terminal of terminals) {
        const replay = await engine.client.call("ai.steps.submit", terminal.input);
        expectModelReplay(terminal.receipt, replay, true);
      }
      expect(providers.seenFixtureCalls).toEqual(callsBeforeReplay);
      // Terminal reads above, rather than provider arrival, establish durability.
      await engine.kill();
      await engine.restart();
      for (const terminal of terminals) {
        const stored = await engine.client.call("ai.steps.receipt", { step_key: terminal.input.step_key });
        expectModelReplay(terminal.receipt, stored);
        const replay = await engine.client.call("ai.steps.submit", terminal.input);
        expectModelReplay(terminal.receipt, replay, true);
      }
      expect(providers.seenFixtureCalls).toEqual(callsBeforeReplay);
    } finally { await engine.close(); }
  } finally {
    providers.releaseBarrier("m03-timeout-reply");
    providers.releaseBarrier("m03-started-reply");
    await providers.close();
  }
});

// Shared model-step helpers and imports are supplied by MODELS-03.ts.
interface ModelSchemaScenario {
  id: string;
  contract: { responseFormat: { format: "json"; schema: Json }; validValue: { count: number } };
  sequences: { native: string[]; shim: string[]; exhausted: string[] };
  expected: { nativeAttempts: number; shimAttempts: number; exhaustedAttempts: number };
}
function modelSchemaSteps(origin: string, texts: readonly string[], schema: Json,
  native: boolean): ProviderStep[] {
  return texts.map((text, index) => {
    const roles = ["system", "user", ...Array.from({ length: index }, () => ["assistant", "user"]).flat()];
    const fields: Record<string, Json> = native
      ? { response_format: { type: "json_schema", json_schema: { name: "oneiron_response", schema } } }
      : { messages: roles.map(role => ({ role })) };
    return modelProviderStep(origin, `${origin}-${index + 1}`,
      openaiText(`${origin}-answer-${index + 1}`, "reasoner", text, { inputTokens: 4, outputTokens: 2 }), fields);
  });
}
function expectModelCorrectionFeedback(providers: ScriptedProviders, origin: string,
  expectedAttempts: number, schema: Json): void {
  const calls = providers.seenFixtureCalls.filter(call => call.origin === origin);
  expect(calls).toHaveLength(expectedAttempts);
  for (const call of calls.slice(1)) {
    // Inspect the engine's output wire, not generated diagnostic prose.
    const body = call.body as { messages: { role: string; content: unknown }[] };
    const last = body.messages.at(-1);
    expect(last?.role).toBe("user");
    expect(typeof last?.content).toBe("string");
    if (typeof last?.content !== "string") throw new Error("Correction has no JSON feedback string");
    const feedback = JSON.parse(last.content) as { required_schema: unknown; schema_validation_errors: unknown };
    expect(feedback.required_schema).toEqual(schema);
    expect(Array.isArray(feedback.schema_validation_errors)).toBe(true);
    if (!Array.isArray(feedback.schema_validation_errors)) throw new Error("Correction omitted validation errors");
    expect(feedback.schema_validation_errors.length).toBeGreaterThan(0);
  }
}
async function modelMcpSchemas(mcp: McpClient): Promise<Map<string, string>> {
  await mcp.initialize();
  const listed = await mcp.request<{ tools: {
    name: string; inputSchema: { properties: { schema_version: { const: string } } };
  }[] }>("tools/list");
  const versions = new Map(listed.tools.map(tool => [tool.name, tool.inputSchema.properties.schema_version.const]));
  for (const verb of ["ai.steps.submit", "ai.steps.receipt"]) {
    expect(typeof versions.get(verb)).toBe("string");
    expect(versions.get(verb)!.length).toBeGreaterThan(0);
  }
  return versions;
}
function modelMcpArguments<V extends ModelStepVerb>(versions: Map<string, string>, verb: V,
  input: FacadeInput<V>) {
  const schemaVersion = versions.get(verb);
  if (!schemaVersion) throw new Error(`Required public MCP tool not listed: ${verb}`);
  return { schema_version: schemaVersion,
    consent: { policy_ref: "policy:models-e2e", purpose: "structured model-step journey" },
    arguments: { spec: input } };
}
async function modelMcpTool<V extends ModelStepVerb>(mcp: McpClient, versions: Map<string, string>,
  verb: V, input: FacadeInput<V>): Promise<FacadeResult<V>> {
  const reply = await mcp.callTool(verb, modelMcpArguments(versions, verb, input)) as {
    isError: boolean; structuredContent: { tool: string; output: FacadeResult<V> };
  };
  expect(reply.isError).toBe(false);
  expect(reply.structuredContent.tool).toBe(verb);
  return reply.structuredContent.output;
}
async function expectModelMcpRefusal(engine: EngineFixture, actor: PairedActor,
  operation: () => Promise<unknown>, verb: ModelStepVerb): Promise<void> {
  let caught: unknown;
  try { await operation(); } catch (error) { caught = error; }
  expect(caught).toBeInstanceOf(McpRpcError);
  if (!(caught instanceof McpRpcError) || !("error" in caught.response)) throw new Error("Expected an MCP owner refusal");
  expect(caught.response).not.toHaveProperty("result");
  expect(caught.response.error).toMatchObject({ code: -32020, data: {
    kind: "facade_error", error_code: "facade_error", human_message: `${verb} is the vault owner's`,
  } });
  const data = caught.response.error.data as { receipt_ref?: unknown };
  await observeModelCallRefusal(engine, data.receipt_ref, actor, "mcp", "facade_error");
}

/* MODELS-04 Structured output retries and refusal should work.
 * Canon: ARCH-0036 #model-line, runtime #mint:S4; OF-436.
 * Native JSON takes one send; the engine shim corrects once or fails after
 * three replies. Correction feedback is parsed from the actual provider wire.
 * Invalid schema sends nothing; zero attempts and non-owner actors are refused.
 * Fresh MCP execution and cross-transport replay use the listed tool envelope.
 * Receipt reads and identical submits retain every terminal after SIGKILL.
 */
suite.test(test, "MODELS-04", "Structured output retries and refusal should work", async () => {
  const facts = await modelScenario<ModelSchemaScenario>("MODELS-04");
  const format = facts.contract.responseFormat;
  const providers = await ScriptedProviders.start({ id: "MODELS-04",
    origins: ["m04-invalid-schema", "m04-zero-attempts"], steps: [
      ...modelSchemaSteps("m04-native", facts.sequences.native, format.schema, true),
      ...modelSchemaSteps("m04-shim", facts.sequences.shim, format.schema, false),
      ...modelSchemaSteps("m04-exhausted", facts.sequences.exhausted, format.schema, false),
      ...modelSchemaSteps("m04-mcp", facts.sequences.native, format.schema, true),
    ] });
  try {
    const offers: ModelOffer[] = Object.entries(providers.urls).map(([name, url]) => ({ name, url,
      nativeJson: name !== "m04-shim" && name !== "m04-exhausted" }));
    const engine = await EngineFixture.start({ id: "MODELS-04", profile, surface: "tool-first",
      serverConfig: modelStepConfig(offers) });
    try {
      const terminals: ModelTerminal[] = [];
      const nativeInput = modelStepInput("MODELS-04-native-v1", "m04-native", format, { kind: "best_effort" }, 3);
      const nativeReceipt = await engine.client.call("ai.steps.submit", nativeInput);
      const native = expectModelFinished(nativeReceipt, facts.contract.validValue);
      expect(native.memoized).toBe(false);
      expect(native.fallback_source ?? null).toBeNull();
      expect(modelCallCount(providers, "m04-native")).toBe(facts.expected.nativeAttempts);
      terminals.push(await observeModelTerminal(engine, nativeInput, nativeReceipt));

      const shimInput = modelStepInput("MODELS-04-shim-v1", "m04-shim", format, { kind: "best_effort" }, 3);
      const shimReceipt = await engine.client.call("ai.steps.submit", shimInput);
      const shim = expectModelFinished(shimReceipt, facts.contract.validValue);
      expect(shim.memoized).toBe(false);
      expect(shim.fallback_source ?? null).toBeNull();
      expectModelCorrectionFeedback(providers, "m04-shim", facts.expected.shimAttempts, format.schema);
      terminals.push(await observeModelTerminal(engine, shimInput, shimReceipt));

      const exhaustedInput = modelStepInput("MODELS-04-exhausted-v1", "m04-exhausted", format, { kind: "best_effort" }, 3);
      const exhaustedReceipt = await engine.client.call("ai.steps.submit", exhaustedInput);
      const exhausted = expectModelFailed(exhaustedReceipt, "schema_validation");
      expect(exhausted.validation_attempts).toBe(facts.expected.exhaustedAttempts);
      expect(exhausted.validation_errors.length).toBeGreaterThan(0);
      expectModelCorrectionFeedback(providers, "m04-exhausted", facts.expected.exhaustedAttempts, format.schema);
      terminals.push(await observeModelTerminal(engine, exhaustedInput, exhaustedReceipt));

      const callsBeforeInvalid = providers.seenFixtureCalls;
      const invalidInput = modelStepInput("MODELS-04-invalid-schema-v1", "m04-invalid-schema",
        { format: "json", schema: { type: 17 } }, { kind: "best_effort" }, 3);
      const invalidReceipt = await engine.client.call("ai.steps.submit", invalidInput);
      const invalid = expectModelFailed(invalidReceipt, "schema_validation");
      expect(invalid.validation_attempts).toBe(0);
      expect(invalid.validation_errors.length).toBeGreaterThan(0);
      terminals.push(await observeModelTerminal(engine, invalidInput, invalidReceipt));
      const zeroInput = modelStepInput("MODELS-04-zero-attempts-v1", "m04-zero-attempts", format, { kind: "best_effort" }, 0);
      await modelHttpError(() => engine.client.call("ai.steps.submit", zeroInput), 400,
        "BAD_REQUEST", "max_attempts must be at least one");
      let missing: unknown;
      try { await engine.client.call("ai.steps.receipt", { step_key: zeroInput.step_key }); }
      catch (error) { missing = error; }
      expect(missing).toBeInstanceOf(PublicHttpError);
      if (!(missing instanceof PublicHttpError)) throw new Error("Zero attempts admitted a model step");
      expect(missing.reply.status).toBe(404);
      expect(missing.error?.code).toBe("NOT_FOUND");
      expect(providers.seenFixtureCalls).toEqual(callsBeforeInvalid);

      const versions = await modelMcpSchemas(engine.mcp);
      const mcpInput = modelStepInput("MODELS-04-mcp-fresh-v1", "m04-mcp", format, { kind: "best_effort" }, 3);
      const mcpReceipt = await modelMcpTool(engine.mcp, versions, "ai.steps.submit", mcpInput);
      const mcpResult = expectModelFinished(mcpReceipt, facts.contract.validValue);
      expect(mcpResult.memoized).toBe(false);
      expect(mcpResult.fallback_source ?? null).toBeNull();
      expect(modelCallCount(providers, "m04-mcp")).toBe(facts.expected.nativeAttempts);
      terminals.push(await observeModelTerminal(engine, mcpInput, mcpReceipt));
      const callsBeforeReplay = providers.seenFixtureCalls;
      const mcpRead = await modelMcpTool(engine.mcp, versions, "ai.steps.receipt", { step_key: nativeInput.step_key });
      expectModelReplay(nativeReceipt, mcpRead);
      const mcpReplay = await modelMcpTool(engine.mcp, versions, "ai.steps.submit", nativeInput);
      expectModelReplay(nativeReceipt, mcpReplay, true);
      expect(providers.seenFixtureCalls).toEqual(callsBeforeReplay);

      const agent = await modelRefusalAgent(engine, "04040404040404040404040404040404");
      await expectModelOwnerRefusals(engine, agent, nativeInput);
      await agent.mcp.initialize();
      const refusedInput = { ...nativeInput, step_key: "MODELS-04-mcp-agent-refused" };
      await expectModelMcpRefusal(engine, agent,
        () => agent.mcp.callTool("ai.steps.submit", modelMcpArguments(versions, "ai.steps.submit", refusedInput)), "ai.steps.submit");
      await expectModelMcpRefusal(engine, agent,
        () => agent.mcp.callTool("ai.steps.receipt", modelMcpArguments(versions, "ai.steps.receipt", { step_key: nativeInput.step_key })), "ai.steps.receipt");
      expect(providers.seenFixtureCalls).toEqual(callsBeforeReplay);
      expect(providers.seenFixtureCalls).toHaveLength(7);
      expect(providers.seenFixtureCalls.every(call => call.fixtureId !== null)).toBe(true);

      for (const terminal of terminals) {
        const replay = await engine.client.call("ai.steps.submit", terminal.input);
        expectModelReplay(terminal.receipt, replay, true);
      }
      expect(providers.seenFixtureCalls).toEqual(callsBeforeReplay);
      await engine.kill();
      await engine.restart();
      for (const terminal of terminals) {
        const stored = await engine.client.call("ai.steps.receipt", { step_key: terminal.input.step_key });
        expectModelReplay(terminal.receipt, stored);
        const replay = await engine.client.call("ai.steps.submit", terminal.input);
        expectModelReplay(terminal.receipt, replay, true);
      }
      const restartedVersions = await modelMcpSchemas(engine.mcp);
      const restartedMcpReplay = await modelMcpTool(engine.mcp, restartedVersions, "ai.steps.submit", nativeInput);
      expectModelReplay(nativeReceipt, restartedMcpReplay, true);
      expect(providers.seenFixtureCalls).toEqual(callsBeforeReplay);
    } finally { await engine.close(); }
  } finally { await providers.close(); }
});

/* MODELS-05 Budget reserve settle and cached resume should work.
 * Canon: ARCH-0026 #run-tree, runtime #charge-rule; OF-076/127/286/290/319.
 * Preserve reserve->lease->settle: an authorized in-flight call can finish,
 * a settled logical step returns its cached terminal on resume, and usage
 * settles once. A no-usage answer pays its reservation; every failed rung
 * that went out pays its own reservation, even when all rungs fail.
 * scenarios.json pins monetary amounts, concurrency barrier and call count.
 * The lease doors (vault.budgets.lease.open/lease/top_up/settlements) and
 * ai.steps.submit/receipt are real owner doors, but nothing joins them:
 * ModelStepSubmit has no spend-lease binding (it denies unknown fields), a
 * step's sends are metered on the process-local raw-inference meter, and
 * settlements of a fresh served run are not correlated to a step. The
 * cached-resume promise alone (settled terminal, restart, identical submit,
 * no new provider call) is proved in MODELS-03; a copy here would add a
 * case without adding a promise.
 */
suite.todo(test, "MODELS-05", "waits on an owner-authorized spend-lease binding on ai.steps.submit with priced per-rung reservations, and vault.budgets.settlements metering correlated to the step's run");

/* MODELS-06 Graceful budget wrap and hold should work.
 * Canon: ARCH-0079 #work/#budget, ARCH-0026 #run-tree; OF-271/419/496/532.
 * Budget read/notice must expose remaining allowance, PLAN/LAND pressure,
 * checkpoint and partial results. The fixture declares a 10% landing
 * reserve; ordinary work cannot spend it. Top up the held lease and resume
 * the same model and work, never silently choose a cheaper one. A soft
 * share is not a pinned cap, and a hold is neither Done nor abandonment.
 * self.budget/self.budget.land and vault.budgets.hold/hold.resume/top_up are
 * real doors, but no public dispatch spends a model budget to a hold on a
 * fresh vault: self.budget is a dispatched attempt's own read, the workflow
 * claim never dials the landing reserve, self.budget.land needs the worker's
 * lease fence that no read exposes, and BudgetGuard's PLAN/LAND steering is
 * not on any public read. An owner-only hold/top-up/resume round trip or an
 * absent-hold read keeps no wrap-and-hold promise.
 */
suite.todo(test, "MODELS-06", "waits on grant-authorized metered task/workflow dispatch bound to an owned lease with a deterministic budget hold, a worker lease-fence read for self.budget.land, and self.budget PLAN/LAND pressure plus a dialed landing reserve over HTTP and MCP");

suite.test(test, "MODELS-07", "Inference mode and usage attribution should work", async () => {
  const catalog = await loadFixtures();
  const facts = await catalog.readJson<UsageFacts>("models-usage");
  const tableBytes = await catalog.readArchive("models-price-table");
  const publicKey = await catalog.readArchive("models-price-table-public-key");
  const signature = await catalog.readArchive("models-price-table-signature");
  // This signs the external fixture oracle, not an invented server request
  // field. POST /v1/usage/events accepts costRates plus priceTableSnapshot.
  expect(verify(null, tableBytes, Buffer.from(publicKey), signature)).toBe(true);
  const table = JSON.parse(new TextDecoder().decode(tableBytes)) as PriceTable;
  const [usdFixture, eurFixture] = facts.events;
  const usd = usageEvent(facts, usdFixture, table);
  const eur = usageEvent(facts, eurFixture, table);
  const otherVault = { ...usd, vaultId: facts.otherVaultId };
  const changedFacts: UsageEvent[] = [
    { ...usd, tokenCounts: { ...usd.tokenCounts, inputTokens: 1001 } },
    { ...usd, model: "models-fixture/other@rev-c" },
    { ...usd, service: "models-fixture-other-service" },
    { ...usd, costRates: { ...usd.costRates, priceTableSnapshot: "models-fixture-prices-v2" } },
    { ...usd, costRates: { ...usd.costRates, currency: "EUR" } },
    { ...usd, serviceAmount: 625001 },
  ];
  const observations = [];
  // Three fresh real vault processes, sequential in this one-slot file. No
  // inference/key is needed to submit externally authored usage facts.
  for (const mode of facts.modes) {
    const engine = await EngineFixture.start({
      id: `MODELS-07-${mode.configMode}`, profile,
      serverConfig: `[runtime]\nmode = "${mode.configMode}"\n`,
    });
    try {
      await engine.requireHttpDoor("/v1/usage/events", "POST");
      await engine.requireHttpDoor("/v1/usage/owners/{owner}/vaults/{vault_id}/rollup", "GET");
      const first = await submitUsage(engine.client, usd);
      const replay = await submitUsage(engine.client, usd);
      const conflicts = [];
      for (const changed of changedFacts) conflicts.push(await submitUsage(engine.client, changed));
      const second = await submitUsage(engine.client, eur);
      const separate = await submitUsage(engine.client, otherVault);
      const rollup = await readUsage(engine.client, facts.owner, facts.vaultId);
      const otherRollup = await readUsage(engine.client, facts.owner, facts.otherVaultId);
      const absent = await readUsage(engine.client, facts.owner, "models-fixture-vault-empty");
      // Attribution comes from host configuration, not a caller's source label.
      const forgedSource = await submitUsage(engine.client, {
        ...usd, idempotencyKey: "models-source-label-probe", source: "oneiron_cloud",
        vaultId: "models-fixture-source-probe",
      });
      const sourceRollup = await readUsage(engine.client, facts.owner, "models-fixture-source-probe");
      if (mode.recordsBillingFacts) await engine.restart();
      const afterRestart = await submitUsage(engine.client, usd);
      const finalRollup = await readUsage(engine.client, facts.owner, facts.vaultId);
      const seen = { mode, first, replay, conflicts, second, separate, rollup, otherRollup,
        absent, forgedSource, sourceRollup, afterRestart, finalRollup };
      await engine.artifacts.json("usage-observations.json", seen);
      observations.push(seen);
    } finally {
      await engine.close();
    }
  }
  // Collect all modes before assertions: a Local/BYO regression must not
  // prevent the hosted sequence from reaching its idempotency/isolation checks.
  for (const seen of observations) {
    const { mode } = seen;
    expect(seen.absent.status).toBe(404);
    if (!mode.recordsBillingFacts) {
      for (const reply of [seen.first, seen.replay, seen.second, seen.separate,
        seen.afterRestart, seen.forgedSource, ...seen.conflicts]) expectUnrecorded(reply, mode.source);
      for (const reply of [seen.rollup, seen.otherRollup, seen.sourceRollup, seen.finalRollup]) {
        expect(reply.status).toBe(facts.expected.unmeteredRollupStatus);
        expect(reply.body).toMatchObject({ code: "NOT_FOUND" });
      }
      continue;
    }
    expect(seen.first.status).toBe(200);
    expect(seen.first.body).toMatchObject({ recorded: true, replayed: false,
      source: mode.source, cost: facts.expected.costs[0] });
    expect(seen.second.status).toBe(200);
    expect(seen.second.body).toMatchObject({ recorded: true, replayed: false,
      source: mode.source, cost: facts.expected.costs[1], vaultRollup: expectedRollup(facts) });
    for (const reply of [seen.replay, seen.afterRestart]) {
      expect(reply.status).toBe(200);
      expect(reply.body).toMatchObject({ recorded: false, replayed: true,
        source: mode.source, cost: facts.expected.costs[0] });
    }
    for (const reply of seen.conflicts) {
      expect(reply.status).toBe(409);
      expect(reply.body).toMatchObject({ code: facts.expected.conflictCode,
        details: { code: facts.expected.conflictCode } });
    }
    expect(seen.separate.status).toBe(200);
    expect(seen.separate.body).toMatchObject({ recorded: true, replayed: false,
      source: mode.source, cost: facts.expected.costs[0], vaultRollup: expectedRollup(facts, true) });
    for (const reply of [seen.rollup, seen.finalRollup]) {
      expect(reply.status).toBe(200);
      expect(reply.body).toEqual(expectedRollup(facts));
    }
    expect(seen.otherRollup.status).toBe(200);
    expect(seen.otherRollup.body).toEqual(expectedRollup(facts, true));
    expect(seen.forgedSource.status).toBe(200);
    expect(seen.forgedSource.body).toMatchObject({ source: mode.source,
      recorded: true, replayed: false, cost: facts.expected.costs[0] });
    expect(seen.sourceRollup.status).toBe(200);
    expect(seen.sourceRollup.body).toEqual({ ...expectedRollup(facts, true),
      vaultId: "models-fixture-source-probe" });
  }
}, 60_000);

/* MODELS-08 Official subscription login boundary should work.
 * Canon: ARCH-0036 #model-line, ARCH-0069 #handles; OF-137/375.
 * A seat has vendor/account/machine/login-store/plan-window metadata, never
 * credential bytes in a model result or control-plane transfer. Complete
 * official login at a loopback fixture issuer, call the seat, exhaust its
 * window, inspect the typed wait/reset and declared fallback choices, then
 * logout and prove the old seat no longer works. A configured paid fallback
 * is permitted; login alone permits none. scenarios.json pins the boundary.
 * `seat login-plan` only prints the plan; it has no callback/token exchange
 * or logout. No real vendor credential, scraped store or client identity
 * may be used as a substitute for this missing official public login flow.
 */
suite.todo(test, "MODELS-08", "waits on documented official subscription login/callback/logout and typed credential-free seat status with configurable issuer");

interface Models09Facts {
  id: string;
  catalogs: { revision: string; offers: { id: string; model: string; priceNanoUsd: number; externalScore: number }[] }[];
  heldOutLabels: { item: string; label: "yes" | "no" }[];
  expected: { trialCostNanoUsd: number; approval: string; beforeBinding: string; afterBinding: string;
    receiptCatalogRevision: string; autoAuthorizedSwap: boolean };
}

function models09HashJson(value: unknown): string {
  return Buffer.from(blake3(new TextEncoder().encode(JSON.stringify(value)))).toString("hex");
}

function models09TeacherApproval(
  binding: Models09Facade.ModelBinding, floor: Models09Facade.TeacherProbePolicy,
): Models09Facade.TeacherProbeApproval {
  // Rust ModelBinding field order; empty route_models, None disposition and false reads_audio are omitted.
  const bindingJson = { model: binding.model, slot: binding.slot, tier: binding.tier };
  // Rust resolved TeacherProbePolicy field order; holder_ref=None is omitted, not null.
  const policyJson = { probe_id: floor.probe_id, vault_min_f1_millionths: floor.min_f1_millionths,
    min_f1_millionths: floor.min_f1_millionths };
  return { probe_id: floor.probe_id, model: binding.model, binding_hash: models09HashJson(bindingJson),
    f1_millionths: 1_000_000, policy_hash: models09HashJson(policyJson) };
}

function models09InitialManifest(incumbent: string): Models09Facade.ModelManifest {
  const required = ["retrieval_embedder", "reranker", "extraction_encoder", "extraction_teacher",
    "generative_reasoner", "local_reasoner", "checker", "dreamer_current", "dreamer_target",
    "asr", "captioner", "doc_parsing", "audio_vad", "tts_deferred", "local_vision"];
  const roles: Record<string, Models09Facade.ModelBinding> = {};
  for (const role of required) roles[role] = { model: incumbent, slot: "llm", tier: "fixture-role" };
  roles.retrieval_embedder = { model: "models-fixture/embedder@rev-a", slot: "embedder", tier: "fixture-embedder" };
  roles.extraction_encoder = { model: "models-fixture/encoder@rev-a", slot: "oneironer", tier: "fixture-encoder" };
  roles.extraction_teacher = { model: "models-fixture/teacher@rev-a", slot: "llm", tier: "fixture-teacher" };
  return { version: 2, roles, routes: { llm: "own_server", embedder: "own_server", oneironer: "own_server" } };
}

function models09BackendPin(model: string): Models09Facade.ModelBackendPin {
  return { model, backend: "models-fixture", serving_revision: "fixture-serving-1",
    quantization: null, context_window_tokens: 1_048_576 };
}

function models09RegistryRow(model: string, nanoUsdPerMillion: number): Models09Facade.ModelRegistryRow {
  // The scenario leaves the price denominator unstated. This fixture uses nano-USD per million tokens.
  const rate = (nanoUsdPerMillion / 1_000_000_000).toFixed(9);
  const price: Models09Facade.LlmCatalogCost = { input_per_million: rate, output_per_million: rate,
    cache_read_per_million: "0", cache_write_per_million: "0", currency: "USD" };
  return { version: 1, wire: "openai-compat", catalog: { model, display_name: model,
    locality: "own_server", context_window_tokens: 1_048_576, max_output_tokens: 64,
    cost: price, capabilities: ["json_response"], metadata: { description: {},
      backends: [{ pin: models09BackendPin(model), price }] } }, scores: {}, fetched_at: {} };
}

function models09CatalogImport(
  facts: Models09Facts, index: number,
): FacadeInput<"vault.models.catalog.refresh"> {
  const revision = facts.catalogs[index]!;
  const offer = revision.offers[0]!;
  return { revision: revision.revision, expected_revision: index === 0 ? null : facts.catalogs[index - 1]!.revision,
    catalog: { version: 1, rows: [models09RegistryRow(facts.expected.beforeBinding, 10),
      models09RegistryRow(offer.model, offer.priceNanoUsd)] },
    scores: [{ source: "fixture-rank", fetched_at: 1001 + index,
      observations: [{ model: offer.model, benchmark: "fixture-yes-no", score: offer.externalScore }] }] };
}

function models09CandidateRow(revision: Models09Facade.ModelCatalogRevision, model: string) {
  const row = revision.rows.find(value => value.catalog.model === model);
  if (!row) throw new Error("MODELS-09 catalog lacks candidate row");
  return row;
}

function models09PaidArm(id: string, model: string, answer: boolean, probability: number): ProviderStep {
  return { id, origin: "models-fixture", role: "held-out-trial", purpose: "measured-model-comparison",
    request: { method: "POST", path: "/v1/chat/completions", model, fields: { stream: false } },
    response: openaiText(id, model, JSON.stringify({ answer, probability }),
      { inputTokens: 499_998, outputTokens: 2 }) };
}

async function models09Refused(
  engine: EngineFixture, act: () => Promise<unknown>, verb: string,
  status: number, code: string, actorRef: string, message?: string,
) {
  let failure: unknown;
  try { await act(); } catch (error) { failure = error; }
  if (!(failure instanceof PublicHttpError)) throw new Error(`MODELS-09 expected public HTTP refusal: ${verb}`);
  expect(failure.reply.status).toBe(status);
  expect(failure.error?.code).toBe(code);
  if (message) expect(failure.error?.message).toContain(message);
  const receiptRef = failure.error?.receiptRef;
  // Authenticated facade refusals carry OF-538 call receipts, including owner preflight refusals.
  expect(receiptRef).toMatch(/^call:[a-f0-9]{32}$/);
  if (typeof receiptRef !== "string") throw new Error("MODELS-09 refusal lacks receiptRef");
  const receipt = await engine.client.call("vault.receipts.get", { receipt_ref: receiptRef });
  expect(receipt).toMatchObject({ receipt_ref: receiptRef, verb, actor_ref: actorRef,
    outcome: { refused: { code } } });
  return receiptRef;
}

/* MODELS-09 Model registry offers are evidence not permission should work.
 * Canon: ARCH-0036 #model-line, ARCH-0003 #learning; OF-512.
 * Imported catalog revisions pin prices and external scores. Public historical
 * answers and independent authored outcomes feed a priced held-out trial.
 * Only owner approval admits spend; a completed proposal is denied, survives
 * restart and leaves both the role receipt and incumbent wire route unchanged.
 * A candidate 503 retains an interrupted unknown arm, not a binding proposal.
 * Unproved: registry fetching, real teacher quality, inferred confidence
 * intervals, certified family independence and settlement without token usage.
 * Full-case TODO: waits on owner-gated vault.models.catalog.refresh fetching
 * a configured registry origin with a documented response schema and bounded
 * typed failure that preserves the incumbent binding.
 */
suite.test(test, "MODELS-09", "Owner denial preserves incumbent routing after a measured held-out model trial", async () => {
  const catalog = await loadFixtures();
  const document = await catalog.readJson<{ scenarios: Models09Facts[] }>("models-scenarios");
  const facts = document.scenarios.find(value => value.id === "MODELS-09");
  if (!facts) throw new Error("MODELS-09 fixture is absent");
  expect(facts.catalogs).toHaveLength(2);
  expect(facts.heldOutLabels.map(value => value.label)).toEqual(["yes", "no"]);
  expect(facts.expected.approval).toBe("deny");
  expect(facts.expected.autoAuthorizedSwap).toBe(false);
  const candidate = facts.catalogs[1]!.offers[0]!.model;
  expect(candidate).toBe("models-fixture/candidate@rev-a");
  expect(facts.expected.beforeBinding).toBe("models-fixture/incumbent@rev-a");
  expect(facts.expected.afterBinding).toBe(facts.expected.beforeBinding);
  const providers = await ScriptedProviders.start({ id: "MODELS-09", steps: [
    models09PaidArm("models09-trial-1-incumbent", "incumbent", true, 0.8),
    models09PaidArm("models09-trial-1-candidate", "candidate", true, 0.9),
    models09PaidArm("models09-trial-2-incumbent", "incumbent", false, 0.2),
    models09PaidArm("models09-trial-2-candidate", "candidate", false, 0.1),
    { id: "models09-denial-probe", origin: "models-fixture", role: "generative_reasoner", purpose: "incumbent-after-denial",
      request: { method: "POST", path: "/v1/chat/completions", model: "incumbent", fields: { stream: false } },
      response: openaiText("models09-denial-probe", "incumbent", "incumbent-after-denial",
        { inputTokens: 10, outputTokens: 2 }) },
  ] });
  let engine: EngineFixture | undefined;
  try {
    engine = await EngineFixture.start({ id: "MODELS-09", profile, serverConfig: `
[models]
raw_budget_units = 10000000
[models.providers.models-fixture]
kind = "local-openai-compat"
base_url = ${JSON.stringify(providers.urls["models-fixture"])}
revision = "rev-a"
timeout_secs = 1
request_compression = false
context_tokens = 1048576
max_output_tokens = 64
[models.roles.generative_reasoner]
model = "models-fixture:incumbent"
[models.roles.checker]
model = "models-fixture:candidate"
[models.decisions.big]
role = "generative_reasoner"
version = "fixture-big-v1"
wording = "Answer the fixture yes/no question with its probability."
reply = "json"
budget_units = 10000000
[models.dreamer]
enabled = false
` });
    const owner = engine.client;
    const ownerRef = engine.pairedActor.principalRef;
    const policy = await owner.call("vault.gate.policy.get", {});
    const defaultPolicy = policy.manifests.find(value => value.manifest_ref === policy.default_manifest_ref);
    expect(defaultPolicy?.trusted).toBe(true);
    expect(defaultPolicy?.quarantined).toBe(false);
    const floor = defaultPolicy?.manifest.teacher_probe;
    if (!floor) throw new Error("MODELS-09 trusted teacher-probe policy is absent");
    expect(floor).toMatchObject({ probe_id: "oneiron-conll-bio-v1", min_f1_millionths: 800_000 });
    expect(floor.holders ?? []).toEqual([]);
    const manifest = models09InitialManifest(facts.expected.beforeBinding);
    // External operator fixture evidence, not a teacher benchmark run or a signature.
    await owner.call("vault.models.manifest.replace", { manifest,
      teacher_approval: models09TeacherApproval(manifest.roles.extraction_teacher!, floor) });
    expect(await owner.call("vault.models.manifest.read", {})).toMatchObject(manifest);
    const before = await owner.call("vault.models.bindings.read", { role: "generative_reasoner" });
    expect(before).toEqual(manifest.roles.generative_reasoner!);

    const agentRef = "09000000000000000000000000000001";
    await owner.call("vault.agents.create", { agent_def_ref: agentRef, definition: {
      agent_id: "models09-observer", desc: "Model catalog observer without owner authority", version: "1",
    } });
    expect((await owner.call("vault.get", { entity_ref: agentRef })).value?.kind).toBe("AGENT_DEF");
    const agent = await engine.pairActor({ principalRef: agentRef, actorClass: "agent",
      scope: ["core:read", "core:write", "core:propose"] });
    expect(await agent.client.call("self.actor", {})).toMatchObject({ actor_ref: agentRef, actor_class: "agent" });

    const importA = models09CatalogImport(facts, 0);
    const importB = models09CatalogImport(facts, 1);
    await owner.call("vault.models.catalog.refresh", importA);
    const revisionA = await owner.call("vault.models.catalog.get", { revision: importA.revision });
    expect(revisionA.revision).toBe(importA.revision);
    const rowA = models09CandidateRow(revisionA, candidate);
    expect(rowA.catalog.cost).toEqual(importA.catalog.rows[1]!.catalog.cost);
    expect(rowA.catalog.metadata?.backends).toEqual(importA.catalog.rows[1]!.catalog.metadata?.backends);
    expect(rowA.scores?.["fixture-rank"]?.["fixture-yes-no"]).toBe(facts.catalogs[0]!.offers[0]!.externalScore);
    expect(rowA.fetched_at?.["fixture-rank"]).toBe(1001);
    await models09Refused(engine, () => agent.client.call("vault.models.catalog.refresh", importB),
      "vault.models.catalog.refresh", 403, "FORBIDDEN", agentRef, "is the vault owner's");
    expect((await owner.call("vault.models.catalog.get", {})).revision).toBe(importA.revision);
    expect(await owner.call("vault.models.bindings.read", { role: "generative_reasoner" })).toEqual(before);
    await owner.call("vault.models.catalog.refresh", importB);
    const revisionB = await owner.call("vault.models.catalog.get", { revision: importB.revision });
    expect(revisionB.previous_revision).toBe(importA.revision);
    expect(revisionB.score_diffs).toEqual([{ model: candidate, source: "fixture-rank", benchmark: "fixture-yes-no",
      previous: facts.catalogs[0]!.offers[0]!.externalScore, score: facts.catalogs[1]!.offers[0]!.externalScore, fetched_at: 1002 }]);
    const rowB = models09CandidateRow(revisionB, candidate);
    expect(rowB.catalog.cost).toEqual(importB.catalog.rows[1]!.catalog.cost);
    expect(rowB.catalog.metadata?.backends).toEqual(importB.catalog.rows[1]!.catalog.metadata?.backends);
    expect(rowB.scores?.["fixture-rank"]?.["fixture-yes-no"]).toBe(facts.catalogs[1]!.offers[0]!.externalScore);
    expect(rowB.fetched_at?.["fixture-rank"]).toBe(1002);
    expect(await owner.call("vault.models.catalog.diff", { from: importA.revision, to: importB.revision }))
      .toEqual({ from: importA.revision, to: importB.revision, changes: [{ model: candidate, previous: rowA, current: rowB }] });
    expect(await owner.call("vault.models.catalog.get", { revision: importA.revision })).toEqual(revisionA);
    expect((await owner.call("vault.models.catalog.get", {})).revision).toBe(importB.revision);
    const roleBefore = await owner.call("vault.models.roles.read", { role: "generative_reasoner" });
    expect(roleBefore).toMatchObject({ model: before.model, provider: "models-fixture", revision: "rev-a",
      route: "own_server", slot: "llm", tier: before.tier });

    const scope = await models09OwnerBaseClaimScope(owner, ownerRef);
    const witness = await owner.call("vault.witness", { conversation_ref: "models09-history", occurred_at: 1_800_000_000,
      messages: [{ author: "user", message_type: "dialogue", content: "Two independent model evaluation items.",
        is_visible: true, order: 0 }] });
    const turn = (await owner.call("vault.get", { entity_ref: witness.turn_short_id })).value;
    if (!turn) throw new Error("MODELS-09 witnessed turn is not readable");
    expect(turn.kind).toBe("TURN");
    const units = ["09000000000000000000000000000002", "09000000000000000000000000000003"];
    for (const [index, unit] of units.entries()) {
      const claim = await owner.call("vault.claims.upsert", { id: unit, subject_ref: turn.id_hex,
        predicate: `fixture.item.${index === 0 ? "a" : "b"}`, value: facts.heldOutLabels[index]!.item,
        confidence: 1, source: "user_stated", scope, occurred_at: 1_800_000_000 });
      expect(claim.approval).toBe("auto");
      expect((await owner.call("vault.get", { entity_ref: claim.claim_short_id })).value?.id_hex).toBe(unit);
    }
    const question = await owner.call("vault.questions.create", { definition: {
      question: { text: "Will this fixture item resolve yes?", class: "judgment", contract: { kind: "noul" }, accept_type: false },
      adapter: "graph", units, recipe: "explicit", profile: "fixture",
      dial: { first: "big", ceiling: "big", band: { low: 0.35, high: 0.65 } },
      activation: "standing", refresh: { on_arrival: false, every_seconds: null }, delivery: "fixture",
      learning: true, deadline_ms: 2000, binding: { source: { kind: "claim", predicate: "fixture.outcome" },
        horizon: 315_360_000, mapping: { yes: true, no: false }, noise_weight: 1 },
    } });
    const questionId = question.definition.question.id;
    expect(question.definition.question.version).toBe(1);
    expect(question.principal).toBe(ownerRef);
    expect(await owner.call("vault.questions.read", { id: questionId })).toEqual(question);
    const answers: Models09Facade.AnswerRecord[] = [];
    const heldOut: Models09Facade.HeldOutSelection[] = [];
    for (const [index, unit] of units.entries()) {
      const input = { unit, evidence: [] };
      const prepared = await owner.call("vault.questions.prepare", { id: questionId, expected_version: 1, input });
      expect(prepared.sources.map(value => value.id)).toEqual([unit]);
      const answer = await owner.call("vault.questions.admit", { id: questionId, expected_version: 1, input,
        source_frontier: prepared.source_frontier,
        // Authored historical prediction; the paid comparison below must still call both real wire arms.
        decision: { answer: { kind: "noul", value: true }, probability: 0.7, evidence: [], in_band: false,
          receipt: { question: questionId, question_version: 1, principal: prepared.principal,
            providers: [{ rung: "big", model: "fixture-provider/fixture-model", version: "fixture-v1" }],
            band: { low: 0.35, high: 0.65 }, evidence_versions: prepared.sources.map(source => ({
              id: source.id, body_hash: Buffer.from(source.hash).toString("hex"),
            })) } } });
      answers.push(answer);
      const factId = index === 0 ? "09000000000000000000000000000004" : "09000000000000000000000000000005";
      const fact = await owner.call("vault.claims.upsert", { id: factId, subject_ref: unit,
        predicate: "fixture.outcome", value: facts.heldOutLabels[index]!.label,
        confidence: 1, source: "user_stated", scope, occurred_at: answer.answered_at });
      expect(fact.approval).toBe("auto");
      const factRead = (await owner.call("vault.get", { entity_ref: fact.claim_short_id })).value;
      expect(factRead?.id_hex).toBe(factId);
      heldOut.push({ answer: answer.claim, fact: factRead!.id_hex, source_family: facts.heldOutLabels[index]!.item });
    }
    const answerRead = await owner.call("vault.questions.answers", { id: questionId });
    const answerRows = Array.isArray(answerRead) ? answerRead : answerRead.answers;
    expect(answerRows).toHaveLength(2);
    for (const answer of answers) expect(answerRows).toContainEqual({ ...answer, kind: "graph" });
    await owner.call("vault.questions.outcomes.project", { id: questionId });
    const outcomes = await owner.call("vault.questions.outcomes", { id: questionId });
    expect(outcomes.calibration).toHaveLength(2);
    for (const [index, selection] of heldOut.entries()) {
      expect(outcomes.calibration).toContainEqual(expect.objectContaining({ question_version: 1,
        outcome: expect.objectContaining({ answer: selection.answer, fact: selection.fact,
          label: facts.heldOutLabels[index]!.label === "yes", noise_weight: 1 }) }));
    }
    expect(providers.seenFixtureCalls).toEqual([]);
    const usage: Models09Facade.LlmUsage = { input: { total: 499_998, cache_read: 0, cache_write: 0 },
      output: { total: 2, text: 2, reasoning: 0 }, raw_provider: {} };
    const set = { id: "models-held-out", version: 1, rubric_version: "models-yes-no-v1" };
    const nominate: FacadeInput<"vault.models.trials.nominate"> = { catalog_revision: importB.revision,
      request: { principal: ownerRef, question: questionId, question_version: 1, goal: ownerRef,
        incumbent: models09BackendPin(before.model), candidate: models09BackendPin(candidate),
        source: "fixture-rank", benchmark: "fixture-yes-no", set, held_out: heldOut,
        incumbent_usage_bound: usage, candidate_usage_bound: usage, future_units: 1000,
        policy: { exploration_remaining: 0, vault_cost_cap: 0.00003, project_cost_cap: 0.00003,
          auto_approve: false, candidate_needs_download: false } } };
    const nominated = await owner.call("vault.models.trials.nominate", nominate);
    const ref = { question: questionId, trial: nominated.id };
    expect(await owner.call("vault.models.trials.get", ref)).toEqual(nominated);
    expect(nominated).toMatchObject({ admission: "ask_exploration", execution: "not_started", arms_total: 4,
      arms_completed: 0, arms_unknown: 0, catalog_revision: importB.revision, nominated_score: 0.99, score_fetched_at: 1002 });
    expect(nominated.request).toEqual(nominate.request);
    expect(nominated.incumbent).toEqual({ pin: nominate.request.incumbent, price: importB.catalog.rows[0]!.catalog.cost });
    expect(nominated.candidate).toEqual({ pin: nominate.request.candidate, price: importB.catalog.rows[1]!.catalog.cost });
    const expectedCost = facts.expected.trialCostNanoUsd / 1_000_000_000;
    expect(nominated.estimated_cost).toBeCloseTo(expectedCost, 15);
    for (const [index, trialCase] of nominated.cases.entries()) {
      const label = outcomes.calibration.find(value => value.outcome.answer === heldOut[index]!.answer)!.outcome;
      expect(trialCase).toMatchObject({ selection: heldOut[index], unit: units[index], label: label.label,
        fact_value_hash: label.fact_value_hash, noise_weight: 1, source_frontier: answers[index]!.frontier });
    }
    const proposedBinding = { ...before, model: candidate };
    await models09Refused(engine, () => owner.call("vault.models.bindings.propose", {
      ...ref, role: "generative_reasoner", binding: proposedBinding,
    }), "vault.models.bindings.propose", 400, "BAD_REQUEST", ownerRef, "completed held-out trial offer");
    expect(await owner.call("vault.models.trials.get", ref)).toEqual(nominated);
    expect(await owner.call("vault.models.trials.run", ref)).toEqual(nominated);
    expect(providers.seenFixtureCalls).toEqual([]);
    await models09Refused(engine, () => agent.client.call("vault.models.trials.approve", ref),
      "vault.models.trials.approve", 403, "FORBIDDEN", agentRef, "is the vault owner's");
    expect((await owner.call("vault.models.trials.get", ref)).admission).toBe("ask_exploration");
    await owner.call("vault.models.trials.approve", ref);
    expect((await owner.call("vault.models.trials.get", ref)).admission).toBe("ready");
    expect(await owner.call("vault.models.bindings.read", { role: "generative_reasoner" })).toEqual(before);
    expect(providers.seenFixtureCalls).toEqual([]);
    await owner.call("vault.models.trials.run", ref);
    const measured = await owner.call("vault.models.trials.get", ref);
    expect(measured).toMatchObject({ execution: "measured", arms_total: 4, arms_completed: 4, arms_unknown: 0,
      evidence: { independent_families: 2, unknown_arms: 0, resent_unknown_arms: 0 } });
    expect(providers.seenFixtureCalls.map(value => value.fixtureId)).toEqual([
      "models09-trial-1-incumbent", "models09-trial-1-candidate", "models09-trial-2-incumbent", "models09-trial-2-candidate",
    ]);
    const evidence = measured.evidence;
    if (!evidence) throw new Error("MODELS-09 measured trial lacks evidence");
    expect(evidence.measurements_hash).toHaveLength(32);
    expect(evidence.incumbent_loss!).toBeCloseTo(0.04, 12);
    expect(evidence.candidate_loss!).toBeCloseTo(0.01, 12);
    expect(evidence.trial_cost).toBeCloseTo(expectedCost, 15);
    expect(evidence.incumbent_cost_per_thousand).toBeCloseTo(0.000005, 15);
    expect(evidence.candidate_cost_per_thousand).toBeCloseTo(0.00002, 15);
    await owner.call("vault.models.trials.complete", { ...ref, assessment: { set,
      measurements_hash: evidence.measurements_hash, paired_gain: { low: 0.02, high: 0.04 }, retest_noise: 0.01,
      stricter_margin: null, required_families: 2, rare_slices_sufficient: true, versions_match: true, canary_diverged: false } });
    const completed = await owner.call("vault.models.trials.get", ref);
    expect(completed.receipt).toMatchObject({ quality: "better", action: "offer",
      assessment: { set, measurements_hash: evidence.measurements_hash } });
    expect(completed.evidence).toEqual(evidence);
    expect(await owner.call("vault.models.roles.read", { role: "generative_reasoner" })).toEqual(roleBefore);
    const proposal = await owner.call("vault.models.bindings.propose", { ...ref,
      role: "generative_reasoner", binding: proposedBinding });
    const proposalRef = { proposal: proposal.id };
    const proposalRead = await owner.call("vault.models.bindings.get", proposalRef);
    expect(proposalRead).toEqual(proposal);
    expect(proposalRead).toMatchObject({ status: "proposed", previous: before, proposed: proposedBinding,
      trial: { catalog_revision: facts.expected.receiptCatalogRevision, evidence, receipt: completed.receipt } });
    expect(proposalRead.trial.evidence!.trial_cost).toBeCloseTo(expectedCost, 15);
    await models09Refused(engine, () => agent.client.call("vault.models.bindings.accept", proposalRef),
      "vault.models.bindings.accept", 403, "FORBIDDEN", agentRef, "is the vault owner's");
    expect(await owner.call("vault.models.bindings.get", proposalRef)).toEqual(proposalRead);
    expect(await owner.call("vault.models.bindings.read", { role: "generative_reasoner" })).toEqual(before);
    await owner.call("vault.models.bindings.deny", proposalRef);
    const denied = await owner.call("vault.models.bindings.get", proposalRef);
    expect(denied).toMatchObject({ status: "denied", previous: before, proposed: proposedBinding, trial: proposalRead.trial });
    expect(denied.settled_at).toBeNumber();
    expect(await owner.call("vault.models.bindings.read", { role: "generative_reasoner" })).toEqual(before);
    expect(await owner.call("vault.models.roles.read", { role: "generative_reasoner" })).toEqual(roleBefore);
    await engine.restart();
    expect(await owner.call("vault.models.bindings.get", proposalRef)).toEqual(denied);
    expect(await owner.call("vault.models.trials.get", ref)).toEqual(completed);
    expect(await owner.call("vault.models.bindings.read", { role: "generative_reasoner" })).toEqual(before);
    expect(await owner.call("vault.models.roles.read", { role: "generative_reasoner" })).toEqual(roleBefore);
    expect(providers.seenFixtureCalls).toHaveLength(4);
    const invocation = await owner.call("vault.models.roles.invoke", { role: "generative_reasoner",
      input: { kind: "generate", request: { model: before.model,
        envelope: { purpose: "eval", class: { kind: "best_effort" }, tier: { global_default: before.tier },
          response_format: { format: "text" }, locality: "own_server" },
        messages: [{ role: "user", content: [{ kind: "text", text: "incumbent denial probe" }] }],
        tools: [], params: {}, provider_options: {} } } });
    expect(invocation.receipt).toEqual(roleBefore);
    expect(invocation.output.kind).toBe("generated");
    if (invocation.output.kind !== "generated") throw new Error("MODELS-09 role did not generate");
    expect(invocation.output.response.message.content).toContainEqual({ kind: "text", text: "incumbent-after-denial" });
    expect(providers.seenFixtureCalls.map(value => value.fixtureId)).toEqual([
      "models09-trial-1-incumbent", "models09-trial-1-candidate", "models09-trial-2-incumbent", "models09-trial-2-candidate", "models09-denial-probe",
    ]);
    expect(providers.seenFixtureCalls.slice(4).map(value => value.body)).toEqual([
      expect.objectContaining({ model: "incumbent", stream: false }),
    ]);

    // New set version, same public history; fail last so candidate cooldown cannot mask the clean trial.
    providers.enqueue(models09PaidArm("models09-fault-incumbent", "incumbent", true, 0.8));
    providers.enqueue({ id: "models09-fault-candidate", origin: "models-fixture", role: "held-out-trial",
      purpose: "candidate-unavailable", request: { method: "POST", path: "/v1/chat/completions", model: "candidate", fields: { stream: false } },
      response: { kind: "json", status: 503, body: { error: { type: "server_error", message: "fixture candidate down" } } } });
    const interrupted = await owner.call("vault.models.trials.nominate", { ...nominate,
      request: { ...nominate.request, set: { ...set, version: 2 } } });
    const failedRef = { question: questionId, trial: interrupted.id };
    expect((await owner.call("vault.models.trials.get", failedRef)).admission).toBe("ask_exploration");
    await owner.call("vault.models.trials.approve", failedRef);
    expect((await owner.call("vault.models.trials.get", failedRef)).admission).toBe("ready");
    await models09Refused(engine, () => owner.call("vault.models.trials.run", failedRef),
      "vault.models.trials.run", 400, "BAD_REQUEST", ownerRef);
    const failureRead = await owner.call("vault.models.trials.get", failedRef);
    expect(failureRead).toMatchObject({ execution: "interrupted", arms_completed: 1, arms_unknown: 1, arms_total: 4,
      unknown_arms: [{ answer: heldOut[0]!.answer, arm: "candidate" }] });
    expect(failureRead.evidence ?? null).toBeNull();
    expect(failureRead.receipt ?? null).toBeNull();
    await models09Refused(engine, () => owner.call("vault.models.bindings.propose", {
      ...failedRef, role: "generative_reasoner", binding: proposedBinding,
    }), "vault.models.bindings.propose", 400, "BAD_REQUEST", ownerRef, "completed held-out trial offer");
    expect(await owner.call("vault.models.bindings.get", proposalRef)).toEqual(denied);
    expect(await owner.call("vault.models.bindings.read", { role: "generative_reasoner" })).toEqual(before);
    expect(await owner.call("vault.models.roles.read", { role: "generative_reasoner" })).toEqual(roleBefore);
    expect(providers.seenFixtureCalls.map(value => value.fixtureId)).toEqual([
      "models09-trial-1-incumbent", "models09-trial-1-candidate", "models09-trial-2-incumbent", "models09-trial-2-candidate",
      "models09-denial-probe", "models09-fault-incumbent", "models09-fault-candidate",
    ]);
    await engine.artifacts.json("models09-evidence.json", { revisionA, revisionB, outcomes, measured, completed,
      denied, invocation, failureRead, providerCalls: providers.seenFixtureCalls });
  } finally {
    try { await engine?.close(); } finally { await providers.close(); }
  }
});
