import { afterAll, expect, test } from "bun:test";
import { createServer } from "node:net";
import { createHash } from "node:crypto";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import type { FacadeInput, FacadeResult, FacadeVerb } from "@oneiron/client";
import type { SpaceMove, WitnessReceipt, TranscriptPage } from "@oneiron/client/facade-types";
import { CliClient, CliError, PublicHttpClient, SdkProcessDriver, credentialParts, PublicHttpError } from "./support/clients.ts";
import { EngineFixture, awaitPublic } from "./support/engine.ts";
import { loadBuildManifest, loadFixtures, requireAsset } from "./support/fixtures.ts";
import { ScriptedProviders, embeddingReply } from "./support/providers.ts";
import type { ProviderStep } from "./support/providers.ts";
import { Artifacts, LIMITS, ManagedProcess, assertFlowActive, defineFile, isolatedEnv, ownResource, redactor, secretHex, tempRoot } from "./support/run.ts";
import type { PairedActor } from "./support/engine.ts";

const profile = process.env.E2E_PROFILE === "real-small-model"
  ? "real-small-model" : "deterministic";
const suite = defineFile(import.meta, { profile, slots: 1 });
afterAll(suite.flush);

/* Canon: ARCH-0036 #inference-slots/#oneironer, ARCH-0019 #storage-invariants,
 * ARCH-0004 #rrf-pipeline/#swap-check-ruling, ARCH-0003 #claim-type,
 * ARCH-0069 #handles; G06=A also binds ARCH-0053 #not-worse.
 * Binding: generated HTTP/SDK facade DTOs, OpenAPI registration/owner paths,
 * api/search.rs and cli.rs at the worktree head. All relevant production files
 * were identical to origin/main at readback. Area manifest pins source facts.
 * Stubs prove adapter routing and durability, not learned model quality.
 */
interface Row {
  id: string; turn: string; text: string; keyword: string; vector: number[];
  policy: "allow" | "deny" | "undecided";
}
interface Scenarios {
  space: { modelKey: string; modelId: string; wrongRevision: string; dimensions: number };
  occurredAt: number;
  runtimePolicy: { leaseMs: number; idleIntervalMs: number; batchSize: number };
  firstRun: { text: string; keyword: string; vector: number[] };
  durability: { text: string; keyword: string; query: string; vector: number[];
    conversation: string; turn: string; message: string };
  egress: Row[];
  swap: { bad: string; good: string; targetTurn: string; distractorTurn: string;
    targetText: string; distractorText: string;
    vectors: { target: number[]; distractor: number[]; incumbentQuery: number[]; badQuery: number[]; goodQuery: number[] };
    probes: { query: string; family: string; targets: string[]; author: string }[] };
}
interface OwnerStatus {
  embedder: {
    configured: { provider: string; model_id: string; dimensions: number } | null;
    persisted: { model_id: string | null; dimensions: number | null } | null;
    dense: string;
  };
}
interface SearchPage {
  items: { id: string; score: number }[];
  embedder?: { provider: string; modelId: string; dimensions: number } | { space: string };
}
async function fixtures(): Promise<Scenarios> {
  return (await loadFixtures()).readJson<Scenarios>("embeddings-scenarios");
}

/* The shared endpoint launcher unconditionally supplies egress flags, which
 * public init rejects for a loopback primary. It also cannot select a remote
 * rung plus its same-space primary. Keep this public-CLI-only helper local;
 * the FIX-LIST names it. Processes, pairing, HTTP, ownership and deadlines are
 * still the shared helpers. No privileged records or vault files are touched.
 */
async function startEndpointEngine(id: string, data: Scenarios, endpoint: string,
  remote?: { endpoint: string; allow: string[]; deny: string[] }, modelConfig = "") {
  const build = await loadBuildManifest(profile);
  const root = await tempRoot(id);
  const env = isolatedEnv(root, build.environment);
  for (const key of Object.keys(env)) if (key.startsWith("ONEIRON_")) delete env[key];
  env.ONEIRON_AUTH_SECRET = secretHex();
  redactor.add(env.ONEIRON_AUTH_SECRET);
  await mkdir(env.TMPDIR!, { recursive: true, mode: 0o700 });
  const artifacts = new Artifacts(resolve(process.env.E2E_ARTIFACTS_DIR ?? resolve(root, "artifacts"), id));
  assertFlowActive();
  const reservation = createServer();
  await new Promise<void>((done, reject) => {
    reservation.once("error", reject);
    reservation.listen(0, "127.0.0.1", done);
  });
  const address = reservation.address();
  if (!address || typeof address === "string") throw new Error("No endpoint fixture port");
  const url = `http://127.0.0.1:${address.port}`;
  let reserved = true;
  const release = async () => {
    if (!reserved) return;
    reserved = false;
    await new Promise<void>((done, reject) => reservation.close(error => error ? reject(error) : done()));
  };
  const config = resolve(root, "oneiron.toml");
  let server: ManagedProcess | undefined;
  let closed = false;
  let disown: () => void = () => {};
  const close = async () => {
    if (closed) return;
    closed = true;
    disown();
    try { await server?.stop() }
    finally { await release(); await rm(root, { recursive: true, force: true }) }
  };
  disown = ownResource(close);
  const bootstrapCli = new CliClient(requireAsset(build, "cli"), root, env, artifacts);
  const launch = async () => {
    server = await ManagedProcess.start([requireAsset(build, "server"), "serve", "--config", config],
      { cwd: root, env, label: `server-${id}-${secretHex(4)}`, artifacts });
    const health = new PublicHttpClient(url, { timeoutMs: 1000 });
    await awaitPublic(async () => {
      if (!server?.running) throw new Error("Owned endpoint fixture exited before health");
      return health.raw("GET", "/api/health");
    }, reply => reply.status === 200,
    { label: "endpoint fixture health", timeoutMs: LIMITS.readyMs, readiness: true });
  };
  try {
    await writeFile(config, `host = "127.0.0.1"\nport = ${address.port}\n\n[keystore]\nbackend = "off"\n${modelConfig}`, { mode: 0o600 });
    const args = ["init", resolve(root, "vault"), "--config", config, "--oneironer", "none",
      "--embedder", "endpoint", "--embedder-endpoint", remote?.endpoint ?? endpoint,
      "--embedder-model-key", data.space.modelKey, "--embedder-model-id", data.space.modelId,
      "--dimensions", String(data.space.dimensions),
      ...(remote ? ["--embedder-locality", "third-party", "--embedder-fallback-endpoint", endpoint,
        "--embedder-egress-allow", remote.allow.join(",")] : [])];
    const initialized = await bootstrapCli.run(args, undefined, LIMITS.readyMs, true);
    if (initialized.exitCode !== 0) throw new CliError(initialized);
    // Public host configuration, not private queue ticks. These explicit
    // fixture policies leave the product's 30s lease and 15s idle defaults alone.
    const configured = await readFile(config, "utf8");
    let configuredPolicy = configured.replace("[embedder]", `[embedder]\nlease_ms = ${data.runtimePolicy.leaseMs}\nidle_interval_ms = ${data.runtimePolicy.idleIntervalMs}\nbatch_size = ${data.runtimePolicy.batchSize}`);
    if (remote) configuredPolicy = configuredPolicy.replace("[embedder.remote.egress]",
      `[embedder.remote.egress]\ndeny = ${JSON.stringify(remote.deny)}`);
    const parsed = Bun.TOML.parse(configuredPolicy) as {
      embedder: { lease_ms: number; idle_interval_ms: number; remote?: { egress: { deny: string[] } } };
    };
    expect(parsed.embedder.lease_ms).toBe(data.runtimePolicy.leaseMs);
    expect(parsed.embedder.idle_interval_ms).toBe(data.runtimePolicy.idleIntervalMs);
    if (remote) expect(parsed.embedder.remote?.egress.deny).toEqual(remote.deny);
    await writeFile(config, configuredPolicy, { mode: 0o600 });
    const bootstrap = await bootstrapCli.run(["token", "bootstrap", "--url", url, "--config", config],
      undefined, LIMITS.readyMs, true);
    if (bootstrap.exitCode !== 0) throw new CliError(bootstrap);
    const link = bootstrap.stdout.trim();
    redactor.add(link);
    await release();
    await launch();
    const sdk = new SdkProcessDriver(build, root, env);
    const paired = await sdk.pair(link);
    const client = new PublicHttpClient(url, { credential: paired.credential, artifacts });
    const { bearer, seed } = credentialParts(paired.credential);
    const cli = new CliClient(requireAsset(build, "cli"), root,
      { ...env, ONEIRON_URL: url, ONEIRON_TOKEN: bearer, ONEIRON_SECRET: bearer, ONEIRON_BINDING_KEY: seed }, artifacts);
    const schema = await client.request<{ readonly paths?: Readonly<Record<string, unknown>> }>("GET", "/api/openapi.json");
    await artifacts.json("public-schema.json", {
      sha256: createHash("sha256").update(schema.bytes).digest("hex"),
      bytes: schema.bytes.byteLength, pathCount: Object.keys(schema.body.paths ?? {}).length,
    });
    await artifacts.json("launch.json", { buildHead: build.head, profile,
      config: redactor.text(configuredPolicy), runtimePolicy: data.runtimePolicy });
    const ready = async () => awaitPublic(() => client.request<OwnerStatus>("GET", "/v1/owner/status"),
      reply => reply.body.embedder.dense === "ready", { label: "endpoint embedder admitted" });
    await ready();
    return { root, url, client, cli, artifacts, close,
      kill: async () => { await server?.stop("SIGKILL") },
      restart: async () => { await server?.stop(); await launch(); await ready() } };
  } catch (error) { await close(); throw error }
}

function listing(origin: string, id: string, data: Scenarios): ProviderStep {
  return { id, origin, role: "embedder", purpose: "model identity metadata",
    request: { method: "GET", path: "/v1/models" },
    response: { kind: "json", body: { data: [{ id: data.space.modelKey }] } } };
}
function startup(origin: string, id: string, data: Scenarios, worker: boolean): ProviderStep[] {
  return [listing(origin, `${id}-listing`, data),
    { id: `${id}-probe`, origin, role: "embedder", purpose: "configured width probe",
      request: { method: "POST", path: "/v1/embeddings", model: data.space.modelKey },
      response: embeddingReply(data.space.modelKey, [[1, 0, 0, 0]], 8) },
    ...(worker ? [listing(origin, `${id}-admission`, data)] : [])];
}
function documentStep(origin: string, id: string, data: Scenarios, text: string,
  vector: number[], barrier?: string): ProviderStep {
  return { id, origin, role: "embedder", purpose: "fixture document fill",
    request: { method: "POST", path: "/v1/embeddings", model: data.space.modelKey, fields: { input: [text] } },
    response: embeddingReply(data.space.modelKey, [vector], 8), ...(barrier ? { barrier } : {}) };
}
function witness(client: PublicHttpClient, data: Scenarios, text: string,
  refs: { conversation?: string; turn?: string; message?: string } = {}): Promise<WitnessReceipt> {
  const input: FacadeInput<"vault.witness"> = {
    conversation_ref: refs.conversation ?? "018f0000000070008000000000000100",
    ...(refs.turn ? { turn_ref: refs.turn } : {}), occurred_at: data.occurredAt,
    messages: [{ ...(refs.message ? { id: refs.message } : {}), author: "user",
      message_type: "dialogue", content: text, is_visible: true, order: 0 }],
  };
  return client.call("vault.witness", input);
}
async function lexical(client: PublicHttpClient, keyword: string, receipt: WitnessReceipt) {
  const hits = await client.call("vault.search.bm25", { query: keyword, limit: 100 });
  expect(hits.value.some(hit => receipt.message_short_ids.includes(hit.short_id) || hit.short_id === receipt.turn_short_id)).toBe(true);
  const recalled = await client.call("vault.recall", { query: keyword, effort: "light", limit: 10 });
  expect(recalled.items.some(item => item.value_text.includes(keyword))).toBe(true);
}
async function vectorPage(client: PublicHttpClient, vector: number[]): Promise<SearchPage> {
  const query = new URLSearchParams({ query: vector.join(","), view: "standard", limit: "100" });
  return (await client.request<SearchPage>("GET", `/api/search/vector?${query}`)).body;
}
async function filled(client: PublicHttpClient, vector: number[], turn: string) {
  const page = await awaitPublic(() => vectorPage(client, vector),
    value => value.items.some(item => item.id === turn), { label: "acknowledged turn's vector is searchable" });
  expect(page.items.filter(item => item.id === turn)).toHaveLength(1);
}

suite.test(test, "EMBEDDINGS-01", "First-run embedder choice should work", async () => {
  const data = await fixtures();
  const none = await EngineFixture.start({ id: "EMBEDDINGS-01-none", profile });
  const health = await new PublicHttpClient(none.url).request<{ status: string }>("GET", "/api/health");
  expect(health.body.status).toBe("ok");
  const saved = await witness(none.client, data, data.firstRun.text);
  await lexical(none.client, data.firstRun.keyword, saved);
  const noModel = await none.client.request<OwnerStatus>("GET", "/v1/owner/status");
  expect(noModel.body.embedder.configured).toBeNull();
  expect(noModel.body.embedder.dense).toBe("not_configured");
  await none.restart();
  await lexical(none.client, data.firstRun.keyword, saved);
  expect((await none.client.request<OwnerStatus>("GET", "/v1/owner/status")).body.embedder.configured).toBeNull();
  await none.close();

  const providers = await ScriptedProviders.start({ id: "EMBEDDINGS-01", steps: [
    ...startup("primary", "init", data, false), ...startup("primary", "serve", data, true),
    documentStep("primary", "first-run-document", data, data.firstRun.text, data.firstRun.vector),
    ...startup("primary", "restart", data, true),
  ] });
  const engine = await startEndpointEngine("EMBEDDINGS-01-endpoint", data, `${providers.urls.primary!}/v1`);
  expect((await new PublicHttpClient(engine.url).request<{ status: string }>("GET", "/api/health")).body.status).toBe("ok");
  const endpointTurn = "018f0000000070008000000000000110";
  const endpointSaved = await witness(engine.client, data, data.firstRun.text, { turn: endpointTurn });
  await lexical(engine.client, data.firstRun.keyword, endpointSaved);
  await filled(engine.client, data.firstRun.vector, endpointTurn);
  await engine.restart();
  const owner = (await engine.client.request<OwnerStatus>("GET", "/v1/owner/status")).body.embedder;
  expect(owner.configured).toMatchObject({ provider: "endpoint", model_id: data.space.modelId, dimensions: data.space.dimensions });
  expect(owner.persisted).toEqual({ model_id: data.space.modelId, dimensions: data.space.dimensions });
  await filled(engine.client, data.firstRun.vector, endpointTurn);

  const sent = providers.seenFixtureCalls.length;
  const deniedConfig = resolve(engine.root, "no-consent.toml");
  const deniedVault = resolve(engine.root, "no-consent-vault");
  const denied = await engine.cli.run(["init", deniedVault, "--config", deniedConfig,
    "--oneironer", "none", "--embedder", "endpoint",
    "--embedder-endpoint", "https://no-egress.example.invalid/v1",
    "--embedder-fallback-endpoint", `${providers.urls.primary!}/v1`,
    "--embedder-model-key", data.space.modelKey, "--embedder-model-id", data.space.modelId,
    "--dimensions", String(data.space.dimensions)]);
  expect(denied.exitCode).not.toBe(0);
  expect(await Bun.file(deniedConfig).exists()).toBe(false);
  expect(providers.seenFixtureCalls).toHaveLength(sent);
  await engine.artifacts.json("providers.json", providers.seenFixtureCalls);
  // No local model is required or downloaded: this flow selects none/endpoint.
});

suite.test(test, "EMBEDDINGS-02", "Async embedding durability should work", async () => {
  const data = await fixtures();
  const row = data.durability;
  const query = (id: string) => documentStep("primary", id, data, row.query, row.vector);
  const providers = await ScriptedProviders.start({ id: "EMBEDDINGS-02", steps: [
    ...startup("primary", "init", data, false), ...startup("primary", "serve", data, true),
    documentStep("primary", "interrupted-fill", data, row.text, row.vector, "before-fill"),
    ...startup("primary", "recovery", data, true),
    documentStep("primary", "successful-fill", data, row.text, row.vector, "recovered-fill"), query("semantic-before-restart"),
    ...startup("primary", "durable-restart", data, true), query("semantic-after-restart"),
  ] });
  const engine = await startEndpointEngine("EMBEDDINGS-02", data, `${providers.urls.primary!}/v1`);
  // This acknowledgment resolves while the model response remains held.
  const saved = await witness(engine.client, data, row.text, row);
  await providers.awaitBarrier("before-fill");
  await lexical(engine.client, row.keyword, saved);
  const neighbors = await engine.client.call("vault.neighbors", { entity_ref: saved.turn_short_id, opts: { limit: 100 } });
  for (const message of saved.message_short_ids) expect(neighbors.value.some(hit => hit.short_id === message)).toBe(true);
  expect((await vectorPage(engine.client, row.vector)).items.some(item => item.id === row.turn)).toBe(false);
  // A real write receipt plus the external barrier is the crash boundary.
  expect(saved.receipt_ref.length).toBeGreaterThan(0);
  await engine.kill();
  await engine.restart();
  await providers.awaitBarrier("recovered-fill");
  await lexical(engine.client, row.keyword, saved);
  providers.releaseBarrier("before-fill");
  providers.releaseBarrier("recovered-fill");
  await filled(engine.client, row.vector, row.turn);
  const semantic = async () => (await engine.client.request<SearchPage>("POST", "/api/search/semantic",
    { text: row.query, view: "standard", limit: 10, depth: "light" })).body;
  const recalled = await semantic();
  expect(recalled.embedder).toEqual({ provider: "endpoint", modelId: data.space.modelId, dimensions: data.space.dimensions });
  expect(recalled.items.filter(item => item.id === row.turn)).toHaveLength(1);
  await engine.restart();
  expect((await semantic()).items.filter(item => item.id === row.turn)).toHaveLength(1);
  expect(providers.seenFixtureCalls.filter(call => call.fixtureId === "successful-fill")).toHaveLength(1);
  // Two attempts are intentional: do not turn crash-safe fill into an
  // unsupported exactly-once upstream-dispatch promise.
  await engine.artifacts.json("providers.json", providers.seenFixtureCalls);
});

/* OF-114/035; G06=A. Same-width revision mismatch must fail before use.
 * Checked moves fill beside the serving text index. A single-family probe set
 * is unknown; full owned probes distinguish worse from not_worse. No old-format
 * reader, migration fixture or owner move_approve stands in for automatic swap.
 */
suite.test(test, "EMBEDDINGS-03", "Exact embedding identity and checked swap should work", async () => {
  const data = await fixtures();
  const swap = data.swap;
  const vectors = swap.vectors;
  const first = swap.probes[0];
  if (!first) throw new Error("Missing owned retrieval probes");
  const probeStep = (origin: string, id: string, vector: number[]): ProviderStep => ({
    id, origin, role: "embedder", purpose: "owned retrieval probe",
    request: { method: "POST", path: "/v1/embeddings", model: origin === "primary" ? data.space.modelKey : "model" },
    response: embeddingReply(origin === "primary" ? data.space.modelKey : "model", [vector], 8),
  });
  const paired = (phase: string, count: number, repeats: number) => Array.from({ length: count * repeats },
    (_, i) => probeStep("primary", `${phase}-incumbent-${i}`, vectors.incumbentQuery));
  const mediaDocument = (origin: string, id: string, text: string, vector: number[], barrier?: string): ProviderStep => ({
    ...documentStep(origin, id, data, text, vector, barrier),
    request: { method: "POST", path: "/v1/embeddings", model: "model", fields: { input: [text] } },
    response: embeddingReply("model", [vector], 8),
  });
  const providers = await ScriptedProviders.start({ id: "EMBEDDINGS-03", steps: [
    ...startup("primary", "init", data, false), ...startup("primary", "serve", data, true),
    documentStep("primary", "target", data, swap.targetText, vectors.target),
    documentStep("primary", "distractor", data, swap.distractorText, vectors.distractor),
    ...startup("primary", "after-refusal", data, true),
    documentStep("primary", "while-bad-fills", data, first.query, vectors.incumbentQuery),
    ...paired("unknown", 1, 2), ...paired("bad", swap.probes.length, 2),
    documentStep("primary", "while-good-fills", data, first.query, vectors.incumbentQuery),
    ...paired("good", swap.probes.length, 2),
    mediaDocument("bad", "bad-target", swap.targetText, vectors.target, "bad-filling"),
    mediaDocument("bad", "bad-distractor", swap.distractorText, vectors.distractor),
    probeStep("bad", "unknown-candidate", vectors.badQuery),
    ...swap.probes.map((_, i) => probeStep("bad", `bad-candidate-${i}`, vectors.badQuery)),
    mediaDocument("good", "good-target", swap.targetText, vectors.target, "good-filling"),
    mediaDocument("good", "good-distractor", swap.distractorText, vectors.distractor),
    ...swap.probes.map((_, i) => probeStep("good", `good-candidate-${i}`, vectors.goodQuery)),
    probeStep("good", "after-automatic-swap", vectors.goodQuery),
  ] });
  const modelConfig = ["bad", "good"].map(origin => `
[models.providers.${origin}]
kind = "local-openai-compat"
base_url = "${providers.urls[origin]!}"
revision = "${origin === "bad" ? "2222222222222222222222222222222222222222" : "3333333333333333333333333333333333333333"}"
request_compression = false
`).join("") + `
[models.media.embed]
rungs = ["bad:model", "good:model"]
inputs = ["text"]
`;
  const engine = await startEndpointEngine("EMBEDDINGS-03", data, `${providers.urls.primary!}/v1`, undefined, modelConfig);
  await witness(engine.client, data, swap.targetText, { turn: swap.targetTurn });
  await filled(engine.client, vectors.incumbentQuery, swap.targetTurn);
  await witness(engine.client, data, swap.distractorText, { turn: swap.distractorTurn });
  await filled(engine.client, vectors.distractor, swap.distractorTurn);
  // Unmanaged serve opens the vault before constructing its embedder adapter.
  // A populated A space therefore refuses same-width revision B before send.
  await engine.client.call("vault.receipts", { limit: 1 });
  await engine.kill();
  const beforeWrongRevision = providers.seenFixtureCalls.length;
  const refused = await engine.cli.run(["serve", "--config", resolve(engine.root, "oneiron.toml"),
    "--embedder-model-id", data.space.wrongRevision]);
  expect(refused.exitCode).not.toBe(0);
  expect(providers.seenFixtureCalls).toHaveLength(beforeWrongRevision);
  await engine.restart();
  await filled(engine.client, vectors.incumbentQuery, swap.targetTurn);

  for (const id of [swap.bad, swap.good]) await engine.client.call("vault.embedding_spaces.declare", {
    id, dimensions: data.space.dimensions, accepts: ["text"], query_towers: ["text"], evidence: { floor: 0.7, strong: 0.9 },
  });
  const putProbe = (probe: Scenarios["swap"]["probes"][number]) => engine.client.call("vault.embedding_spaces.probes.put", {
    kind: "text", query: probe.query, family: probe.family, targets: probe.targets, author: probe.author,
  });
  await putProbe(first);
  await engine.client.call("vault.embedding_spaces.move", { candidate: swap.bad });
  await providers.awaitBarrier("bad-filling");
  const semantic = async () => (await engine.client.request<SearchPage>("POST", "/api/search/semantic",
    { text: first.query, view: "standard", limit: 1, depth: "light" })).body;
  expect((await semantic()).items.map(item => item.id)).toEqual([swap.targetTurn]);
  expect((await engine.client.call("vault.embedding_spaces.list", {})).slots.text).toBeUndefined();
  providers.releaseBarrier("bad-filling");
  const moves = () => engine.client.call("vault.embedding_spaces.list", {});
  const insufficient = await awaitPublic(moves,
    view => view.moves.some(move => move.candidate === swap.bad && move.last_check?.verdict === "unknown"),
    { label: "insufficient probes block automatic swap" });
  expect(insufficient.moves.find(move => move.candidate === swap.bad)?.state).toBe("open");
  expect(insufficient.slots.text).toBeUndefined();
  for (const probe of swap.probes.slice(1)) await putProbe(probe);
  const probes = await engine.client.call("vault.embedding_spaces.probes.list", {});
  expect(probes.probes).toHaveLength(swap.probes.length);
  expect(new Set(probes.probes.map(probe => probe.author))).toEqual(new Set(swap.probes.map(probe => probe.author)));
  const bad = await engine.client.call("vault.embedding_spaces.move_check", { candidate: swap.bad });
  expect(bad.outcome).toBe("kept");
  expect(bad.check?.verdict).toBe("worse");
  expect((await moves()).slots.text).toBeUndefined();

  await engine.client.call("vault.embedding_spaces.move", { candidate: swap.good });
  await providers.awaitBarrier("good-filling");
  expect((await semantic()).items.map(item => item.id)).toEqual([swap.targetTurn]);
  providers.releaseBarrier("good-filling");
  const swapped = await awaitPublic(moves, view => view.slots.text === swap.good,
    { label: "good paired probes automatically swap the kind slot" });
  const move: SpaceMove | undefined = swapped.moves.find(move => move.candidate === swap.good);
  expect(move?.state).toMatchObject({ swapped_in: { by_owner: false } });
  expect(move?.last_check?.verdict).toBe("not_worse");
  expect(move?.last_check?.kinds.map(kind => kind.kind)).toEqual(["text"]);
  for (const kind of move?.last_check?.kinds ?? []) {
    expect(kind.verdict).toBe("not_worse");
    expect(kind.difference).not.toBeNull();
    expect(kind.tolerance).not.toBeNull();
    expect(kind.difference!.low).toBeGreaterThanOrEqual(-kind.tolerance!);
  }
  const after = await semantic();
  expect(after.embedder).toEqual({ space: swap.good });
  expect(after.items.map(item => item.id)).toEqual([swap.targetTurn]);
  const inbox = await engine.client.call("self.inbox.list", { limit: 100 });
  // Match the revisioned space identity in typed source metadata, never the
  // English summary. The public note is the notification, not a log line.
  const notes = inbox.rows.filter(row => row.source.event.includes(swap.good));
  expect(notes).toHaveLength(1);
  expect(notes[0]!.source.result?.length).toBeGreaterThan(0);
  const authored = new Set(swap.probes.map(probe => probe.query));
  const probeCalls = providers.seenFixtureCalls.filter(call => call.purpose === "owned retrieval probe");
  for (const call of probeCalls) {
    const body = call.body as { input: string[] };
    expect(body.input).toHaveLength(1);
    expect(authored.has(body.input[0]!)).toBe(true);
  }
  for (const probe of swap.probes) for (const origin of ["primary", "bad", "good"]) {
    const calls = probeCalls.filter(call => call.origin === origin &&
      (call.body as { input: string[] }).input[0] === probe.query);
    // Two incumbent measurements per check, one candidate measurement;
    // the first query also has the unknown check / post-swap public read.
    expect(calls).toHaveLength((origin === "primary" ? 4 : 1) +
      (probe.query === first.query ? (origin === "primary" ? 2 : 1) : 0));
  }
  await engine.artifacts.json("providers.json", providers.seenFixtureCalls);
});

type MediaEmb04Kind = FacadeInput<"vault.assets.ingest">["embedding_kind"];
type MediaEmb04Fields = NonNullable<ProviderStep["request"]["fields"]>;
interface MediaEmb04Scenarios {
  occurredAt: number;
  media: {
    text: { content: string; vector: number[] };
    image: { asset: string; vector: number[] };
    audio: { asset: string; vector: number[] };
    queries: { kind: MediaEmb04Kind; text: string; vector: number[]; target: MediaEmb04Kind }[];
    unrelated: number[];
    floors: Record<MediaEmb04Kind, { floor: number; strong: number }>;
  };
}
interface MediaEmb04Asset {
  kind: MediaEmb04Kind; assetRef: string; space: string; mime: string;
  bytes: Uint8Array; text: string; vector: number[];
}
interface MediaEmb04Query {
  id: string; target: MediaEmb04Kind; queryKind: MediaEmb04Kind;
  input: FacadeInput<"vault.recall">;
  fields?: MediaEmb04Fields;
}
interface MediaEmb04Status {
  models: { seats: { role: string; rungs: {
    provider: string; engine_model?: string; health?: { state: string };
  }[] }[] };
}
function mediaEmb04Fields(kind: MediaEmb04Kind, mime: string, bytes: Uint8Array): MediaEmb04Fields {
  const encoded = Buffer.from(bytes).toString("base64");
  if (kind === "text") return { input: [new TextDecoder().decode(bytes)], encoding_format: "float" };
  if (kind === "image") return { messages: [{ role: "user", content: [
    { type: "image_url", image_url: { url: `data:${mime};base64,${encoded}` } },
  ] }], encoding_format: "float" };
  return { messages: [{ role: "user", content: [
    { type: "input_audio", input_audio: { data: encoded, format: "wav" } },
  ] }], encoding_format: "float" };
}
function mediaEmb04Step(origin: string, id: string, fields: MediaEmb04Fields,
  vector: number[], barrier?: string): ProviderStep {
  return { id, origin, role: "media.embed", purpose: id.startsWith("media-emb04-fill-")
      ? "typed ASSET fill" : "authored recall query",
    request: { method: "POST", path: "/v1/embeddings", model: "model", fields },
    response: embeddingReply("model", [vector], 8), ...(barrier ? { barrier } : {}) };
}
async function mediaEmb04Error(action: () => Promise<unknown>, status: number, code: string) {
  try { await action() } catch (error) {
    if (!(error instanceof PublicHttpError)) throw error;
    expect(error.reply.status).toBe(status);
    expect(error.error?.code).toBe(code);
    return error;
  }
  throw new Error(`Expected HTTP ${status} ${code}`);
}
async function mediaEmb04RefusalReceipt(engine: EngineFixture, error: PublicHttpError,
  verb: string, actorRef: string, actorClass: string) {
  const receiptRef = error.error?.receiptRef;
  expect(typeof receiptRef).toBe("string");
  if (typeof receiptRef !== "string") throw new Error("Facade refusal omitted its call receipt");
  expect(receiptRef).toMatch(/^call:[a-f0-9]{32}$/);
  expect(error.reply.headers.get("x-oneiron-receipt-ref")).toBe(receiptRef);
  const receipt = await engine.client.call("vault.receipts.get", { receipt_ref: receiptRef });
  expect(receipt).not.toBeNull();
  expect(receipt).toMatchObject({ receipt_ref: receiptRef, verb, actor_ref: actorRef,
    actor_class: actorClass, outcome: { refused: { code: error.error!.code } } });
  return receiptRef;
}
async function mediaEmb04Filled(client: PublicHttpClient, asset: MediaEmb04Asset) {
  const query = new URLSearchParams({ space: asset.space, queryKind: asset.kind,
    query: asset.vector.join(","), limit: "100", view: "standard", depth: "light" });
  const page = await awaitPublic(async () => (await client.request<SearchPage>("GET", `/api/search/vector?${query}`)).body,
    value => value.items.some(item => item.id === asset.assetRef),
    { label: `media ${asset.kind} vector is searchable` });
  expect(new Set(page.items.map(item => item.id))).toEqual(new Set([asset.assetRef]));
}
function mediaEmb04Matches(pack: FacadeResult<"vault.recall">, plan: MediaEmb04Query,
  assets: Record<MediaEmb04Kind, MediaEmb04Asset>, data: MediaEmb04Scenarios) {
  const matched = new Map<string, Set<string>>();
  for (const item of pack.items) {
    expect(item.kind).toBe("ASSET");
    for (const evidence of item.embedding_matches ?? []) {
      const asset = Object.values(assets).find(row => row.space === evidence.space);
      if (!asset) throw new Error("Recall exposed an undeclared fixture space");
      expect(item.asset_ref).toBe(asset.assetRef);
      expect(evidence.embedding_kind).toBe(asset.kind);
      expect(evidence.query_kind).toBe(asset.kind === "text" ? "text" : plan.queryKind);
      expect(evidence.floor).toBeCloseTo(data.media.floors[asset.kind].floor, 6);
      expect(evidence.strong).toBeCloseTo(data.media.floors[asset.kind].strong, 6);
      expect(Number.isFinite(evidence.score)).toBe(true);
      expect(evidence.matched).toBe(evidence.score >= evidence.floor);
      if (evidence.matched) {
        const refs = matched.get(evidence.space) ?? new Set<string>();
        refs.add(item.asset_ref!); matched.set(evidence.space, refs);
      }
    }
  }
  for (const asset of Object.values(assets)) {
    expect(matched.get(asset.space) ?? new Set<string>()).toEqual(
      new Set(asset.kind === plan.target ? [asset.assetRef] : []));
  }
  const asset = assets[plan.target];
  const hits = pack.items.filter(item => item.asset_ref === asset.assetRef &&
    item.embedding_matches?.some(match => match.space === asset.space &&
      match.embedding_kind === asset.kind && match.query_kind === plan.queryKind && match.matched));
  expect(hits).toHaveLength(1);
  return hits[0]!.asset_ref!;
}
async function mediaEmb04Resolve(client: PublicHttpClient, asset: MediaEmb04Asset,
  receipt: FacadeResult<"vault.assets.ingest">, bytes: boolean) {
  const result = await client.call("vault.assets.resolve", { asset_ref: asset.assetRef,
    image_input: bytes && asset.kind === "image", audio_input: bytes && asset.kind === "audio",
    room_bytes: 1_048_576 });
  expect(result.narrowing).toBeDefined();
  expect(result.value.asset_ref).toBe(asset.assetRef);
  const form = bytes && asset.kind !== "text" ? asset.kind : "asset_text";
  expect(result.value.form).toBe(form);
  if (form === "asset_text") {
    expect(result.value.text).toBe(asset.text);
    expect(result.value.asset_text_ref).toBe(receipt.asset_text_ref);
    expect(result.value.bytes_b64).toBeNull();
    expect(result.value.mime_type).toBeNull();
  } else {
    expect(result.value.mime_type).toBe(asset.mime);
    expect(result.value.bytes_b64).toBe(Buffer.from(asset.bytes).toString("base64"));
    expect(result.value.handle?.length).toBeGreaterThan(0);
  }
  expect(result.value.receipt_refs).toHaveLength(1);
  expect(result.value.receipt_refs[0]!).toMatch(/^served_form:[a-f0-9]{32}$/);
  return { receiptRef: result.value.receipt_refs[0]!, assetRef: asset.assetRef,
    form: form === "asset_text" ? "text" : form,
    ...(form === "asset_text" ? { assetTextRef: receipt.asset_text_ref! } : {}) };
}

/* EMBEDDINGS-04 — Text and media space search should work. OF-370, OF-329.
 * Partial: typed text/image/audio ASSETs fill separate declared spaces;
 * native and text towers return per-space match evidence and authored floors.
 * Resolve serves pinned bytes while the image fill is held, or saved text to
 * a text-only reader, with served-form receipts read through vault.receipts.
 * A holder binds a slot to its own declared model and it lands; a non-holder
 * agent's declare/bind and read-only ingest refusals carry call receipts and
 * change no bindings. In this personal vault the Owner is the only holder. A fourth
 * offered, declared but unbound rung receives one query and fails explicitly.
 * Restart retains bindings, match evidence, bytes, text and earlier receipts
 * without another document fill. Orthogonal queries abstain in all three spaces.
 * No learned-quality, retry/recovery, per-ASSET fill-state, erasure, thumbnail
 * budget ladder or live content-grant withdrawal claim is made here.
 */
suite.test(test, "EMBEDDINGS-04", "Typed text, image and audio assets fill declared spaces, recall with match evidence, resolve to the reader's form across restart, a holder binds a slot to its own model while a non-holder is refused, and an unavailable media rung refuses its query", async () => {
  const catalog = await loadFixtures();
  const data = await catalog.readJson<MediaEmb04Scenarios>("embeddings-scenarios");
  const imageQuery = data.media.queries.find(query => query.kind === "text" && query.target === "image");
  const audioQuery = data.media.queries.find(query => query.kind === "audio" && query.target === "audio");
  if (!imageQuery || !audioQuery) throw new Error("Missing authored media queries");
  const revision = "1111111111111111111111111111111111111111";
  const mediaEmb04Space = (origin: string) => `${origin}/model@${revision}@${origin}`;
  const assets: Record<MediaEmb04Kind, MediaEmb04Asset> = {
    text: { kind: "text", assetRef: "018f0000000070008000000000000401", space: mediaEmb04Space("text"),
      mime: "text/plain", bytes: Buffer.from(data.media.text.content), text: data.media.text.content,
      vector: data.media.text.vector },
    image: { kind: "image", assetRef: "018f0000000070008000000000000402", space: mediaEmb04Space("image"),
      mime: "image/png", bytes: await catalog.readArchive(data.media.image.asset),
      text: data.media.text.content, vector: data.media.image.vector },
    audio: { kind: "audio", assetRef: "018f0000000070008000000000000403", space: mediaEmb04Space("audio"),
      mime: "audio/wav", bytes: await catalog.readArchive(data.media.audio.asset),
      text: audioQuery.text, vector: data.media.audio.vector },
  };
  const mediaEmb04Declaration = (origin: MediaEmb04Kind | "down"): FacadeInput<"vault.embedding_spaces.declare"> => {
    const kind = origin === "down" ? "image" : origin;
    return { id: mediaEmb04Space(origin), dimensions: 4, accepts: [kind],
      query_towers: kind === "text" ? ["text"] : ["text", kind], evidence: data.media.floors[kind] };
  };
  const mediaEmb04QueryPlan = (id: string, target: "image" | "audio", queryKind: MediaEmb04Kind,
    query: string, mime: string, bytes: Uint8Array): MediaEmb04Query => ({
    id, target, queryKind, fields: mediaEmb04Fields(queryKind, mime, bytes),
    input: { query, effort: "medium", scope: { kinds: ["ASSET"] }, limit: 10,
      media: { space: assets[target].space, mime, bytes_b64: Buffer.from(bytes).toString("base64"), kinds: [target] } },
  });
  const plans: MediaEmb04Query[] = [
    { id: "text", target: "text", queryKind: "text",
      input: { query: imageQuery.text, effort: "medium", scope: { kinds: ["ASSET"] }, limit: 10 } },
    mediaEmb04QueryPlan("image-text", "image", "text", imageQuery.text, "text/plain", Buffer.from(imageQuery.text)),
    mediaEmb04QueryPlan("image-native", "image", "image", imageQuery.text, assets.image.mime, assets.image.bytes),
    mediaEmb04QueryPlan("audio-native", "audio", "audio", audioQuery.text, assets.audio.mime, assets.audio.bytes),
    mediaEmb04QueryPlan("audio-text", "audio", "text", audioQuery.text, "text/plain", Buffer.from(audioQuery.text)),
  ];
  const unrelated = "unrelated quartz orbit";
  const noMatchPlans: MediaEmb04Query[] = [
    { id: "no-match-text", target: "text", queryKind: "text",
      input: { query: unrelated, effort: "medium", scope: { kinds: ["ASSET"] }, limit: 10 } },
    mediaEmb04QueryPlan("no-match-image", "image", "text", unrelated, "text/plain", Buffer.from(unrelated)),
    mediaEmb04QueryPlan("no-match-audio", "audio", "text", unrelated, "text/plain", Buffer.from(unrelated)),
  ];
  const failedQuery = "unavailable cobalt prism";
  const steps: ProviderStep[] = Object.values(assets).map(asset => mediaEmb04Step(asset.kind,
    `media-emb04-fill-${asset.kind}`, mediaEmb04Fields(asset.kind, asset.mime, asset.bytes), asset.vector,
    asset.kind === "image" ? "media-emb04-image-held" : undefined));
  steps.push(mediaEmb04Step("text", "media-emb04-down-normal",
    mediaEmb04Fields("text", "text/plain", Buffer.from(failedQuery)), data.media.unrelated));
  steps.push({ ...mediaEmb04Step("down", "media-emb04-down-query",
    mediaEmb04Fields("text", "text/plain", Buffer.from(failedQuery)), data.media.unrelated),
    response: { kind: "json", status: 503,
      body: { error: { type: "unavailable", message: "fixture provider unavailable" } } } });
  const mediaEmb04AddQueries = (phase: string, queries: MediaEmb04Query[], abstain: boolean) => {
    for (const plan of queries) {
      steps.push(mediaEmb04Step("text", `media-emb04-${phase}-${plan.id}-normal`,
        mediaEmb04Fields("text", "text/plain", Buffer.from(plan.input.query)),
        !abstain && plan.target === "text" ? imageQuery.vector : data.media.unrelated));
      if (plan.fields) steps.push(mediaEmb04Step(plan.target, `media-emb04-${phase}-${plan.id}-media`,
        plan.fields, abstain ? data.media.unrelated : plan.queryKind === "text"
          ? (plan.target === "image" ? imageQuery.vector : audioQuery.vector) : assets[plan.target].vector));
    }
  };
  mediaEmb04AddQueries("before", plans, false);
  mediaEmb04AddQueries("abstain", noMatchPlans, true);
  mediaEmb04AddQueries("after", plans, false);
  const providers = await ScriptedProviders.start({ id: "EMBEDDINGS-04", origins: ["holder"], steps });
  const serverConfig = ["text", "image", "audio", "down", "holder"].map(origin => `
[models.providers.${origin}]
kind = "local-openai-compat"
base_url = "${providers.urls[origin]!}"
revision = "${revision}"
request_compression = false
timeout_secs = ${origin === "down" ? 1 : 5}
`).join("") + `
[models.media.embed]
rungs = ["text:model", "image:model", "audio:model", "down:model", "holder:model"]
inputs = ["text", "image", "audio"]
`;
  const engine = await EngineFixture.start({ id: "EMBEDDINGS-04", profile, serverConfig });
  for (const origin of ["text", "image", "audio", "down"] as const)
    await engine.client.call("vault.embedding_spaces.declare", mediaEmb04Declaration(origin));
  const setup = await engine.client.call("vault.embedding_spaces.list", {});
  for (const origin of ["text", "image", "audio", "down"] as const)
    expect(setup.spaces.find(row => row.id === mediaEmb04Space(origin))).toEqual(mediaEmb04Declaration(origin));
  expect(Object.values(setup.slots)).not.toContain(mediaEmb04Space("down"));

  // Holder row (ARCH-0019 #default-bindings; DEC-0005): "A holder may also
  // bind any slot to their own model." Holders are the vault's Owners, and
  // any Admin or Delegate whose Grant includes the policy power; in this
  // personal vault the Owner alone holds it, and no typed door mints such
  // a Grant, so the paired Owner (`engine.client`) is the holder. It
  // declares a space on its own "holder" model origin, binds the image
  // slot to it, and the binding lands, read back through list. The case's
  // working image binding is then restored through the same holder and
  // read back, so the legs below keep the bindings they already assert.
  const mediaEmb04HolderDeclaration = { ...mediaEmb04Declaration("image"), id: mediaEmb04Space("holder") };
  const mediaEmb04HolderRestoredImageSpace = assets.image.space;
  await engine.client.call("vault.embedding_spaces.declare", mediaEmb04HolderDeclaration);
  await engine.client.call("vault.embedding_spaces.bind", { kind: "image", space: mediaEmb04Space("holder") });
  const holderSetup = await engine.client.call("vault.embedding_spaces.list", {});
  expect(holderSetup.spaces.find(row => row.id === mediaEmb04Space("holder"))).toEqual(mediaEmb04HolderDeclaration);
  expect(holderSetup.slots.image).toBe(mediaEmb04Space("holder"));
  await engine.client.call("vault.embedding_spaces.bind", { kind: "image", space: mediaEmb04HolderRestoredImageSpace });
  const restoredSetup = await engine.client.call("vault.embedding_spaces.list", {});
  expect(restoredSetup.slots.image).toBe(mediaEmb04HolderRestoredImageSpace);
  expect(Object.values(restoredSetup.slots)).not.toContain(mediaEmb04Space("holder"));

  // Non-holder row: the paired agent holds core:read/core:write and no
  // policy power, so its declare/bind are refused and change no bindings.
  const agentRef = "018f0000000070008000000000000404";
  const agentInput: FacadeInput<"vault.agents.create"> = { agent_def_ref: agentRef,
    definition: { agent_id: "media-emb04-reader", desc: "Inert media-space refusal principal", version: "1" } };
  await engine.client.call("vault.agents.create", agentInput);
  expect((await engine.client.call("vault.agents.get", { agent_def_ref: agentRef })).definition).toMatchObject(agentInput.definition);
  const agent = await engine.pairActor({ principalRef: agentRef, actorClass: "agent", scope: ["core:read", "core:write"] });
  expect(await agent.client.call("self.actor", {})).toMatchObject({ actor_ref: agentRef, actor_class: "agent" });
  const refusedDeclaration = { ...mediaEmb04Declaration("image"), id: `${mediaEmb04Space("image")}-refused` };
  const declareRefusal = await mediaEmb04Error(() => agent.client.call("vault.embedding_spaces.declare", refusedDeclaration), 403, "FORBIDDEN");
  const bindRefusal = await mediaEmb04Error(() => agent.client.call("vault.embedding_spaces.bind", { kind: "image", space: mediaEmb04Space("down") }), 403, "FORBIDDEN");
  const refusalRefs = [
    await mediaEmb04RefusalReceipt(engine, declareRefusal, "vault.embedding_spaces.declare", agentRef, "agent"),
    await mediaEmb04RefusalReceipt(engine, bindRefusal, "vault.embedding_spaces.bind", agentRef, "agent"),
  ];
  const refusedSetup = await engine.client.call("vault.embedding_spaces.list", {});
  expect(refusedSetup.spaces).toEqual(restoredSetup.spaces);
  expect(refusedSetup.slots).toEqual(restoredSetup.slots);
  const readOnly = await engine.pairActor({ principalRef: agentRef, actorClass: "agent", scope: ["core:read"] });
  const deniedAssetRef = "018f0000000070008000000000000405";
  const ingestRefusal = await mediaEmb04Error(() => readOnly.client.call("vault.assets.ingest", {
    asset_ref: deniedAssetRef, embedding_kind: "text", mime_type: "text/plain",
    bytes_b64: Buffer.from(data.media.text.content).toString("base64"), occurred_at: data.occurredAt,
  }), 403, "FORBIDDEN");
  refusalRefs.push(await mediaEmb04RefusalReceipt(engine, ingestRefusal, "vault.assets.ingest", agentRef, "agent"));
  await mediaEmb04Error(() => engine.client.call("vault.assets.resolve", { asset_ref: deniedAssetRef }), 404, "NOT_FOUND");
  expect(providers.seenFixtureCalls).toHaveLength(0);

  const ingested = {} as Record<MediaEmb04Kind, FacadeResult<"vault.assets.ingest">>;
  const served: { receiptRef: string; assetRef: string; form: string; assetTextRef?: string }[] = [];
  for (const asset of Object.values(assets)) {
    await engine.client.call("vault.embedding_spaces.bind", { kind: asset.kind, space: asset.space });
    ingested[asset.kind] = await engine.client.call("vault.assets.ingest", {
      asset_ref: asset.assetRef, embedding_kind: asset.kind, mime_type: asset.mime,
      bytes_b64: Buffer.from(asset.bytes).toString("base64"), text: asset.text, occurred_at: data.occurredAt,
    });
    expect(ingested[asset.kind]).toMatchObject({ asset_ref: asset.assetRef, embedding_kind: asset.kind,
      mime_type: asset.mime, byte_size: asset.bytes.byteLength });
    expect(ingested[asset.kind].blake3).toMatch(/^[a-f0-9]{64}$/);
    expect(ingested[asset.kind].asset_text_ref).toMatch(/^[a-f0-9]{32}$/);
    if (asset.kind === "image") {
      await providers.awaitBarrier("media-emb04-image-held");
      // Resolve is independent of the still-held embedding response.
      served.push(await mediaEmb04Resolve(engine.client, asset, ingested.image, true));
      const held = new URLSearchParams({ space: asset.space, queryKind: "image",
        query: asset.vector.join(","), limit: "100", view: "standard", depth: "light" });
      expect((await engine.client.request<SearchPage>("GET", `/api/search/vector?${held}`)).body.items).toEqual([]);
      providers.releaseBarrier("media-emb04-image-held");
    }
    await mediaEmb04Filled(engine.client, asset);
    served.push(await mediaEmb04Resolve(engine.client, asset, ingested[asset.kind], true));
    served.push(await mediaEmb04Resolve(engine.client, asset, ingested[asset.kind], false));
  }
  const mediaEmb04CheckSetup = async () => {
    const view = await engine.client.call("vault.embedding_spaces.list", {});
    for (const asset of Object.values(assets)) {
      expect(view.slots[asset.kind]).toBe(asset.space);
      expect(view.spaces.find(row => row.id === asset.space)).toEqual(mediaEmb04Declaration(asset.kind));
    }
    expect(view.spaces.find(row => row.id === mediaEmb04Space("down"))).toEqual(mediaEmb04Declaration("down"));
    expect(Object.values(view.slots)).not.toContain(mediaEmb04Space("down"));
  };
  await mediaEmb04CheckSetup();
  const down = await mediaEmb04Error(() => engine.client.call("vault.recall", {
    query: failedQuery, effort: "medium", scope: { kinds: ["ASSET"] }, limit: 10,
    media: { space: mediaEmb04Space("down"), mime: "text/plain",
      bytes_b64: Buffer.from(failedQuery).toString("base64"), kinds: ["image"] },
  }), 503, "MODEL_UNAVAILABLE");
  const status = (await engine.client.request<MediaEmb04Status>("GET", "/v1/ai/status")).body;
  const downRung = status.models.seats.find(seat => seat.role === "media.embed")?.rungs
    .find(rung => rung.provider === "down" && rung.engine_model === `down/model@${revision}`);
  expect(downRung?.health?.state).toBe("down");
  refusalRefs.push(await mediaEmb04RefusalReceipt(engine, down, "vault.recall", engine.pairedActor.principalRef, "human"));
  expect(providers.seenFixtureCalls.filter(call => call.origin === "down").map(call => call.fixtureId))
    .toEqual(["media-emb04-down-query"]);

  const mediaEmb04RecallPlans = async () => {
    for (const plan of plans) {
      const pack = await engine.client.call("vault.recall", plan.input);
      const returnedRef = mediaEmb04Matches(pack, plan, assets, data);
      served.push(await mediaEmb04Resolve(engine.client, { ...assets[plan.target], assetRef: returnedRef }, ingested[plan.target], true));
    }
  };
  await mediaEmb04RecallPlans();
  for (const plan of noMatchPlans) {
    const pack = await engine.client.call("vault.recall", plan.input);
    expect(pack.items).toEqual([]);
  }
  const mediaEmb04CheckServedReceipts = async () => {
    const page = await engine.client.call("vault.receipts", { kinds: ["served_form"], limit: 100 });
    for (const expected of served) {
      const receipt = page.receipts.find(row => row.receipt_ref === expected.receiptRef);
      expect(receipt).toMatchObject({ kind: "served_form", outcome: "served", actor_class: "human",
        actor_ref: engine.pairedActor.principalRef,
        fields: { asset_ref: expected.assetRef, form: expected.form,
          ...(expected.assetTextRef ? { asset_text_ref: expected.assetTextRef } : {}) } });
    }
  };
  await mediaEmb04CheckServedReceipts();
  const fillCalls = providers.seenFixtureCalls.filter(call => call.purpose === "typed ASSET fill");
  expect(fillCalls.map(call => call.fixtureId)).toEqual([
    "media-emb04-fill-text", "media-emb04-fill-image", "media-emb04-fill-audio",
  ]);
  const beforeRestart = providers.seenFixtureCalls.length;
  await engine.restart();
  expect((await engine.client.call("vault.embedding_spaces.list", {})).slots.image).toBe(mediaEmb04HolderRestoredImageSpace);
  await mediaEmb04CheckSetup();
  await mediaEmb04RecallPlans();
  for (const asset of Object.values(assets))
    served.push(await mediaEmb04Resolve(engine.client, asset, ingested[asset.kind], false));
  await mediaEmb04CheckServedReceipts();
  for (const receiptRef of refusalRefs)
    expect((await engine.client.call("vault.receipts.get", { receipt_ref: receiptRef }))?.receipt_ref).toBe(receiptRef);
  expect(providers.seenFixtureCalls.slice(beforeRestart).some(call => call.purpose === "typed ASSET fill")).toBe(false);
  expect(providers.seenFixtureCalls.filter(call => call.purpose === "typed ASSET fill")).toEqual(fillCalls);
  for (const origin of ["text", "image", "audio", "down"]) {
    const calls = providers.seenFixtureCalls.filter(call => call.origin === origin);
    const expected = steps.filter(step => step.origin === origin);
    expect(calls.map(call => call.fixtureId)).toEqual(expected.map(step => step.id));
    for (let index = 0; index < expected.length; index++) {
      expect(calls[index]).toMatchObject({ method: "POST", path: "/v1/embeddings", origin, role: "media.embed" });
      expect(calls[index]!.body).toEqual({ model: "model", ...expected[index]!.request.fields });
    }
  }
  await engine.artifacts.json("providers.json", providers.seenFixtureCalls);
});

suite.test(test, "EMBEDDINGS-05", "Remote egress deny falls back locally should work", async () => {
  const data = await fixtures();
  const [allowed, denied, undecided, failure, tail] = data.egress;
  if (!allowed || !denied || !undecided || !failure || !tail) throw new Error("Incomplete authored egress fixture");
  const failedStep: ProviderStep = {
    ...documentStep("remote", "remote-failure", data, failure.text, failure.vector),
    response: { kind: "json", status: 503, body: { error: { type: "unavailable", message: "fixture provider unavailable" } } },
  };
  const providers = await ScriptedProviders.start({ id: "EMBEDDINGS-05", steps: [
    ...startup("primary", "local-init", data, false), ...startup("primary", "local-serve", data, true),
    documentStep("primary", "denied-local", data, denied.text, denied.vector),
    documentStep("primary", "undecided-local", data, undecided.text, undecided.vector),
    documentStep("primary", "failed-remote-local", data, failure.text, failure.vector),
    documentStep("primary", "tail-local", data, tail.text, tail.vector),
    ...startup("remote", "remote-init", data, false), ...startup("remote", "remote-serve", data, false),
    listing("remote", "remote-rung-listing", data),
    documentStep("remote", "allowed-remote", data, allowed.text, allowed.vector), failedStep,
  ] });
  // "third-party" is the real adapter's locality policy, not a trusted-model
  // exemption. The recording origin is loopback for the network-isolated run;
  // this proves per-row routing, not Internet/TLS infrastructure.
  const engine = await startEndpointEngine("EMBEDDINGS-05", data, `${providers.urls.primary!}/v1`, {
    endpoint: `${providers.urls.remote!}/v1`,
    allow: data.egress.filter(row => row.policy === "allow").map(row => row.turn),
    deny: data.egress.filter(row => row.policy === "deny").map(row => row.turn),
  });
  for (const row of data.egress) {
    const saved = await witness(engine.client, data, row.text, { turn: row.turn });
    await lexical(engine.client, row.keyword, saved);
    // Observe each row before adding the next, so provider batches never
    // rely on incidental arrival order. This is a GET, not a mutation retry.
    await filled(engine.client, row.vector, row.turn);
  }
  const remoteCalls = providers.seenFixtureCalls.filter(call => call.origin === "remote");
  const documentCalls = remoteCalls.filter(call => call.purpose === "fixture document fill");
  expect(documentCalls.map(call => call.fixtureId)).toEqual(["allowed-remote", "remote-failure"]);
  for (const row of [denied, undecided, tail])
    expect(remoteCalls.every(call => !JSON.stringify(call.body).includes(row.keyword))).toBe(true);
  const localIds = providers.seenFixtureCalls.filter(call => call.origin === "primary" && call.purpose === "fixture document fill")
    .map(call => call.fixtureId);
  expect(localIds).toEqual(["denied-local", "undecided-local", "failed-remote-local", "tail-local"]);
  const recalled = await engine.client.call("vault.recall", { query: tail.keyword, effort: "light", limit: 10 });
  expect(recalled.items.some(item => item.value_text.includes(tail.keyword))).toBe(true);
  await engine.artifacts.json("providers.json", providers.seenFixtureCalls);
});

interface TaggerFixtures {
  occurredAt: number;
  tagger: {
    checkpointSha16: string; stackSha16: string; labelCount: number; text: string;
    modelCard: { checkpoint_sha16: string; stack_sha16: string; contract_version: number;
      label_count: number; returns: { spans: boolean; links: boolean; mood: boolean } };
    output: {
      spans: { message: number; start: number; end: number; label: string; confidence: number }[];
      links: { span: number; antecedent: number; confidence: number }[];
      vad: { valence: number; arousal: number; dominance: number }; stack_sha16: string;
    };
    expected: { mentions: string[]; claimsAuthored: number; dreamerCalls: number;
      rawTurnSurvivesDelay: boolean };
  };
}
interface TaggerTurnRefs { conversation: string; turn: string; message: string }
function taggerCard(data: TaggerFixtures): ProviderStep {
  // Probes race successful-answer vouch reads. Only extraction is FIFO.
  return { id: "tagger-card", origin: "tagger", role: "oneironer", purpose: "configured model card",
    standing: true, request: { method: "GET", path: "/v1/model" },
    response: { kind: "json", body: data.tagger.modelCard } };
}
function taggerExtract(id: string, refs: TaggerTurnRefs, text: string,
  response: ProviderStep["response"], barrier?: string): ProviderStep {
  return { id, origin: "tagger", role: "oneironer", purpose: "witnessed turn extraction",
    request: { method: "POST", path: "/v1/extract", fields: {
      turn: refs.turn, messages: [{ id: refs.message, text }], context: [],
    } }, response, ...(barrier ? { barrier } : {}) };
}
function taggerEngine(id: string, data: TaggerFixtures, providers: ScriptedProviders) {
  return EngineFixture.start({ id, profile,
    oneironer: { url: providers.urls.tagger!, checkpointSha16: data.tagger.checkpointSha16,
      labelCount: data.tagger.labelCount, mode: "save" },
    // Init carries labels forward into its own [oneironer] table.
    serverConfig: `
[oneironer.labels]
PERSON = "PERSON"
[models.providers.dreamer]
kind = "local-openai-compat"
base_url = "${providers.urls.dreamer!}"
revision = "e2e-tagger-only-v1"
request_compression = false
[models.roles.dreamer_current]
model = "dreamer:unused"
[models.dreamer]
enabled = false
`,
  });
}
async function taggerAgent(engine: EngineFixture, principalRef: string, scope: string[]) {
  const created = await engine.client.call("vault.agents.create", {
    agent_def_ref: principalRef,
    definition: { agent_id: "tagging-refusal-agent", display_name: "Tagging refusal agent",
      desc: "Inert principal for public-door refusal checks", version: "1" },
  });
  expect(created.agent_def_ref).toBe(principalRef);
  const stored = await engine.client.call("vault.agents.get", { agent_def_ref: principalRef });
  expect(stored).toEqual(created);
  const actor = await engine.pairActor({ principalRef, actorClass: "agent", scope });
  // The write-only actor cannot call self.actor, which requires core:read.
  return actor;
}
async function taggerRefusal<V extends FacadeVerb>(engine: EngineFixture, actor: PairedActor,
  verb: V, input: FacadeInput<V>, reason: "scope" | "owner") {
  let refusal: PublicHttpError | undefined;
  try { await actor.client.call(verb, input) }
  catch (error) {
    if (!(error instanceof PublicHttpError)) throw error;
    refusal = error;
  }
  if (!refusal) throw new Error(`Expected refusal from ${verb}`);
  expect(refusal.reply.status).toBe(403);
  expect(refusal.error).toMatchObject({ code: "FORBIDDEN",
    message: reason === "owner" ? `${verb} is the vault owner's` : "request does not have the required scope",
    suggestions: [reason === "owner" ? "Present the owner's own verified, unattenuated credential."
      : "Request a token with the required Oneiron core scope and retry."],
  });
  expect(typeof refusal.error?.requestId).toBe("string");
  const receiptRef = refusal.error?.receiptRef;
  if (typeof receiptRef !== "string") throw new Error("Authenticated facade refusal lacks its call receipt");
  expect(receiptRef).toMatch(/^call:[a-f0-9]{32}$/);
  expect(refusal.reply.headers.get("x-oneiron-receipt-ref")).toBe(receiptRef);
  const receipt = await awaitPublic(() => engine.client.call("vault.receipts.get", { receipt_ref: receiptRef }),
    value => value !== null, { label: `${verb} refusal receipt` });
  expect(receipt).toMatchObject({ receipt_ref: receiptRef, transport: "http_facade",
    verb, actor_ref: actor.principalRef, actor_class: "agent",
    outcome: { refused: { code: "FORBIDDEN" } }, served: [],
  });
}
async function taggerReadable(client: PublicHttpClient, refs: TaggerTurnRefs, text: string, query: string) {
  const transcript = await client.request<TranscriptPage>("GET",
    `/v1/core/conversations/${refs.conversation}/transcript?limit=10`);
  expect(transcript.body.conversation).toBe(refs.conversation);
  const turn = transcript.body.turns.find(row => row.id === refs.turn);
  expect(turn?.messages.map(message => ({ id: message.id, text: message.text })))
    .toEqual([{ id: refs.message, text }]);
  const recalled = await client.call("vault.recall", { query, effort: "light", limit: 10 });
  expect(recalled.items.some(item => item.value_text.includes(text))).toBe(true);
}
function taggerExtractionIds(providers: ScriptedProviders) {
  return providers.seenFixtureCalls.filter(call => call.origin === "tagger" && call.path === "/v1/extract")
    .map(call => call.fixtureId);
}
function taggerOnlyCalls(providers: ScriptedProviders, expectedDreamerCalls: number) {
  expect(providers.seenFixtureCalls.filter(call => call.origin === "dreamer")).toHaveLength(expectedDreamerCalls);
  expect(providers.seenFixtureCalls.every(call => call.origin === "tagger" &&
    ((call.method === "GET" && call.path === "/v1/model") ||
     (call.method === "POST" && call.path === "/v1/extract")))).toBe(true);
}

/* EMBEDDINGS-06 — Oneironer tags without authoring beliefs should work.
 * OF-119/128/135/138/539. Contract-v2 fixture spans, coreference and VAD
 * survive a transient 500, a successful retry and a settled restart.
 * The acknowledged text stays readable and recallable while tagging waits.
 * Saved tags and reverse mentions are read through separate public doors;
 * claims stay unchanged, and the disabled Dreamer origin receives no call.
 * R5-server-oneironer-001 and R5-server-oneironer-007 are asserted here.
 * This checks the adapter and persistence, not learned tagging quality.
 */
suite.test(test, "EMBEDDINGS-06", "Oneironer saves faithful tags without beliefs, retries a transient failure, and preserves them after restart", async () => {
  const data = await (await loadFixtures()).readJson<TaggerFixtures>("embeddings-scenarios");
  const refs: TaggerTurnRefs = { conversation: "018f0000000070008000000000000600",
    turn: "018f0000000070008000000000000601", message: "018f0000000070008000000000000602" };
  const providers = await ScriptedProviders.start({ id: "EMBEDDINGS-06", origins: ["tagger", "dreamer"], steps: [
    taggerCard(data),
    taggerExtract("extract-failure", refs, data.tagger.text,
      { kind: "json", status: 500, body: { error: "fixture transient failure" } }, "tagger-first"),
    taggerExtract("extract-retry", refs, data.tagger.text,
      { kind: "json", body: data.tagger.output }, "tagger-retry"),
  ] });
  const engine = await taggerEngine("EMBEDDINGS-06", data, providers);
  const agent = await taggerAgent(engine, "018f00000000700080000000000006f0", ["core:write"]);
  const claimsBefore = (await engine.client.call("vault.claims.list", { limit: 1000 })).value;
  expect(claimsBefore.length).toBeLessThan(1000);
  const saved = await engine.client.call("vault.witness", {
    conversation_ref: refs.conversation, turn_ref: refs.turn, occurred_at: data.occurredAt,
    messages: [{ id: refs.message, author: "user", message_type: "dialogue", content: data.tagger.text,
      is_visible: true, order: 0 }],
  });
  expect(saved.turn_id).toBe(refs.turn);
  expect(saved.message_short_ids).toHaveLength(1);
  expect(saved.receipt_ref.length).toBeGreaterThan(0);
  const turnInput = { turn_ref: saved.turn_short_id };
  const status = () => engine.client.call("vault.tagging.status", turnInput);
  const tags = () => engine.client.call("vault.tagging.tags", turnInput);
  const history = () => engine.client.call("vault.tagging.history", turnInput);
  const unchangedClaims = async () => {
    const current = (await engine.client.call("vault.claims.list", { limit: 1000 })).value;
    expect(current).toEqual(claimsBefore);
    expect(current.length - claimsBefore.length).toBe(data.tagger.expected.claimsAuthored);
  };
  await providers.awaitBarrier("tagger-first");
  expect((await status()).value).toMatchObject({ turn_ref: refs.turn, state: "pending", configured: true,
    checkpoint: data.tagger.checkpointSha16, mode: "save", has_tags: false, failure: null });
  expect((await tags()).value.tags).toBeNull();
  expect((await history()).value.traces).toEqual([]);
  await taggerReadable(engine.client, refs, data.tagger.text, "Mira");
  await unchangedClaims();
  providers.releaseBarrier("tagger-first");
  await awaitPublic(history, value => value.value.traces.some(trace => trace.outcome.outcome === "failed"),
    { label: "first tagger failure recorded" });
  // Hold the successor so the retry state cannot race a successful save.
  await providers.awaitBarrier("tagger-retry");
  const retrying = (await status()).value;
  expect(retrying).toMatchObject({ state: "retrying", configured: true, has_tags: false, try_number: 1,
    checkpoint: data.tagger.checkpointSha16, model: `oneironer/endpoint@${data.tagger.checkpointSha16}`,
    failure: { class: "call", code: "tagger extract returned HTTP 500", refusal: null },
  });
  expect(retrying.marker?.retry_of).toMatch(/^[a-f0-9]{32}$/);
  expect(retrying.retry_at).toEqual(expect.any(Number));
  expect(retrying.last_trace?.outcome).toMatchObject({ outcome: "failed", retry_at: retrying.retry_at });
  expect((await tags()).value.tags).toBeNull();
  const failedHistory = (await history()).value.traces;
  expect(failedHistory).toHaveLength(1);
  expect(failedHistory[0]?.try_number).toBe(1);
  await taggerReadable(engine.client, refs, data.tagger.text, "Mira");
  await unchangedClaims();
  providers.releaseBarrier("tagger-retry");
  const settled = await awaitPublic(status, value => value.value.state === "settled" && value.value.has_tags,
    { label: "valid retry saves the turn annotations" });
  expect(settled.value).toMatchObject({ marker: null, failure: null, try_number: 2,
    checkpoint: data.tagger.checkpointSha16, model: `oneironer/endpoint@${data.tagger.checkpointSha16}`,
    freshness: { stale: false, pending_retag: false } });
  const savedTags = (await tags()).value.tags;
  if (!savedTags) throw new Error("Settled tagger has no saved annotations");
  expect(savedTags.turn_ref).toBe(refs.turn);
  expect(savedTags.message_refs).toEqual([refs.message]);
  expect(savedTags.mentions).toHaveLength(data.tagger.output.spans.length);
  for (const [index, span] of data.tagger.output.spans.entries()) {
    const mention = savedTags.mentions[index]!;
    expect(mention).toMatchObject({ index, message_ref: refs.message, start: span.start, end: span.end, label: span.label });
    expect(mention.confidence).toBeCloseTo(span.confidence, 6);
    expect(data.tagger.text.slice(mention.start, mention.end)).toBe(data.tagger.expected.mentions[index]);
  }
  const [mira, she, email] = savedTags.mentions;
  if (!mira || !she || !email || mira.link.link !== "minted") throw new Error("Expected Mira's provisional identity link");
  expect(mira.antecedent).toBeNull();
  expect(she.link).toEqual(mira.link);
  expect(she.antecedent).toBe(0);
  expect(she.link_confidence!).toBeCloseTo(data.tagger.output.links[0]!.confidence, 6);
  expect(email.link).toEqual({ link: "tag" });
  expect(email.antecedent).toBeNull();
  expect(savedTags.merge_evidence).toEqual([]);
  expect(savedTags.mood?.valence!).toBeCloseTo(data.tagger.output.vad.valence, 6);
  expect(savedTags.mood?.arousal!).toBeCloseTo(data.tagger.output.vad.arousal, 6);
  expect(savedTags.mood?.dominance!).toBeCloseTo(data.tagger.output.vad.dominance, 6);
  expect(savedTags.mood_freshness).toEqual({ stale: false, pending_retag: false });
  expect(savedTags.mood_parts).toEqual([]);
  expect(savedTags.freshness).toEqual({ stale: false, pending_retag: false });
  expect(savedTags.envelope).toMatchObject({
    model_id: `oneironer/endpoint@${data.tagger.checkpointSha16}@${data.tagger.checkpointSha16}`,
    stack: data.tagger.stackSha16, version: "oneiron.tagging.save.v2",
  });
  expect(savedTags.envelope.content_hash).toMatch(/^[a-f0-9]{64}$/);
  expect(savedTags.envelope.params_hash).toMatch(/^[a-f0-9]{64}$/);
  expect(savedTags.saved_at).toEqual(expect.any(Number));
  const mentionInput = { entity_ref: mira.link.entity_ref, limit: 10 };
  const reverse = (await engine.client.call("vault.tagging.mentions", mentionInput)).value;
  expect(reverse.entity_ref).toBe(mira.link.entity_ref);
  expect(reverse.mentions).toEqual([mira, she].map((mention, index) => ({ turn_ref: refs.turn, index,
    mention, freshness: { stale: false, pending_retag: false } })));
  const savedHistory = (await history()).value;
  expect(savedHistory.traces.map(trace => trace.outcome.outcome)).toEqual(["failed", "saved"]);
  expect(savedHistory.traces.map(trace => trace.try_number)).toEqual([1, 2]);
  expect(savedHistory.traces[1]?.outcome).toMatchObject({ outcome: "saved", spans: 3, links: 1, mood: true });
  await taggerRefusal(engine, agent, "vault.tagging.status", turnInput, "scope");
  await taggerRefusal(engine, agent, "vault.tagging.tags", turnInput, "scope");
  await taggerRefusal(engine, agent, "vault.tagging.history", turnInput, "scope");
  await taggerRefusal(engine, agent, "vault.tagging.mentions", mentionInput, "scope");
  expect((await tags()).value.tags).toEqual(savedTags);
  await unchangedClaims();
  expect(taggerExtractionIds(providers)).toEqual(["extract-failure", "extract-retry"]);
  await engine.restart();
  expect((await status()).value).toMatchObject({ state: "settled", has_tags: true, marker: null, failure: null });
  expect((await tags()).value.tags).toEqual(savedTags);
  expect((await history()).value).toEqual(savedHistory);
  expect((await engine.client.call("vault.tagging.mentions", mentionInput)).value).toEqual(reverse);
  await taggerReadable(engine.client, refs, data.tagger.text, "Mira");
  await unchangedClaims();
  expect(taggerExtractionIds(providers)).toEqual(["extract-failure", "extract-retry"]);
  taggerOnlyCalls(providers, data.tagger.expected.dreamerCalls);
  await engine.artifacts.json("providers.json", providers.seenFixtureCalls);
  await engine.close();
  taggerOnlyCalls(providers, data.tagger.expected.dreamerCalls);
  await providers.close();
});

interface IdentityFixtures extends TaggerFixtures {
  identity: {
    people: { label: string; name: string; identityEvidence: { email: string; organisation: string } }[];
    ambiguousMention: string; ownerEvidence: string;
    expected: { ambiguousMerges: number; distinctPeople: number; resolvedPerson: string;
      retainMentionAndOwnerEvidence: boolean };
  };
}
async function identityEvidence(engine: EngineFixture, content: string) {
  // Diary notes do not enqueue witnessed-turn tagging markers.
  const receipt = await engine.client.call("self.memory.diary", { content });
  expect(receipt.entry_id).toMatch(/^[a-f0-9]{32}$/);
  const stored = await engine.client.call("vault.get", { entity_ref: receipt.entry_id });
  expect(stored.value).toMatchObject({ id_hex: receipt.entry_id, kind: "NOTE", body: { markdown: content } });
  return { receipt, stored: stored.value };
}

/* EMBEDDINGS-07 — Conservative entity resolution should work. OF-443.
 * Two owner-created namesakes retain their own contact/organisation evidence.
 * Name-only lookup and an ambiguous saved mention keep both candidates.
 * A non-owner agent cannot create, inspect owner identity doors, or answer;
 * the refusal's receipt and unchanged owner projection are read back.
 * The owner's evidence-backed answer selects north without merging south.
 * Original suggestion, owner provenance and saved resolution survive restart
 * without another extraction. No learned evidence scoring is claimed.
 */
suite.test(test, "EMBEDDINGS-07", "Same-name people stay distinct until an evidence-backed owner answer resolves the mention and survives restart", async () => {
  const data = await (await loadFixtures()).readJson<IdentityFixtures>("embeddings-scenarios");
  const northFixture = data.identity.people.find(person => person.label === "mira-north");
  const southFixture = data.identity.people.find(person => person.label === "mira-south");
  if (!northFixture || !southFixture) throw new Error("Missing authored namesakes");
  const refs: TaggerTurnRefs = { conversation: "018f0000000070008000000000000700",
    turn: "018f0000000070008000000000000701", message: "018f0000000070008000000000000702" };
  // This text has its own nine-byte name span, not the other case's spans.
  const nameEnd = 9;
  expect(data.identity.ambiguousMention.slice(0, nameEnd)).toBe(northFixture.name);
  expect(southFixture.name).toBe(northFixture.name);
  const providers = await ScriptedProviders.start({ id: "EMBEDDINGS-07", origins: ["tagger", "dreamer"], steps: [
    taggerCard(data),
    taggerExtract("ambiguous-person", refs, data.identity.ambiguousMention, { kind: "json", body: {
      spans: [{ message: 0, start: 0, end: nameEnd, label: "PERSON", confidence: 0.99 }],
      links: [], stack_sha16: data.tagger.stackSha16,
    } }),
  ] });
  const engine = await taggerEngine("EMBEDDINGS-07", data, providers);
  const agent = await taggerAgent(engine, "018f00000000700080000000000007f0", ["core:read", "core:write"]);
  const agentIdentity = await agent.client.call("self.actor", {});
  expect(agentIdentity).toMatchObject({ actor_ref: agent.principalRef, actor_class: "agent" });
  const evidenceText = (person: IdentityFixtures["identity"]["people"][number]) =>
    `${person.name}: ${person.identityEvidence.email}; organisation ${person.identityEvidence.organisation}.`;
  const northEvidence = await identityEvidence(engine, evidenceText(northFixture));
  const southEvidence = await identityEvidence(engine, evidenceText(southFixture));
  const personInput = (person: IdentityFixtures["identity"]["people"][number], evidence: string): FacadeInput<"vault.people.create"> => ({
    identity: { name: person.name, contact_handle: [person.identityEvidence.email] },
    identity_evidence_refs: [evidence], occurred_at: data.occurredAt,
  });
  const northInput = personInput(northFixture, northEvidence.receipt.entry_id);
  const southInput = personInput(southFixture, southEvidence.receipt.entry_id);
  const north = await engine.client.call("vault.people.create", northInput);
  const south = await engine.client.call("vault.people.create", southInput);
  expect(north.person.id_hex).not.toBe(south.person.id_hex);
  expect(north.prior_candidate_refs).toEqual([]);
  expect(south.prior_candidate_refs).toEqual([north.person.id_hex]);
  for (const [created, input] of [[north, northInput], [south, southInput]] as const) {
    expect(created.identity).toMatchObject(input.identity);
    expect(created.identity_evidence_refs).toEqual(input.identity_evidence_refs);
    expect(created.owner_ref).toBe(engine.pairedActor.principalRef);
    expect(created.recorded_at).toEqual(expect.any(Number));
    const person = await engine.client.call("vault.get", { entity_ref: created.person.id_hex });
    expect(person.value).toMatchObject({ id_hex: created.person.id_hex, kind: "PERSON", body: {
      name: input.identity.name, contact_handle: input.identity.contact_handle,
      identity_evidence_refs: input.identity_evidence_refs, identity_owner_ref: engine.pairedActor.principalRef,
    } });
  }
  const candidateRefs = [north.person.id_hex, south.person.id_hex].sort();
  const lookupInput: FacadeInput<"vault.entities.look_before_mint"> = { kind: "PERSON", identity: { name: northFixture.name } };
  const lookup = () => engine.client.call("vault.entities.look_before_mint", lookupInput);
  const candidates = await lookup();
  expect(candidates.kind).toBe("PERSON");
  expect(candidates.candidates).toHaveLength(data.identity.expected.distinctPeople);
  expect(candidates.candidates.map(candidate => candidate.entity_ref).sort()).toEqual(candidateRefs);
  expect(candidates.waterfall).toMatchObject({ ranked: [], selected: null, claims_suppressed: 0,
    route: "provisional_entity", requires_async_verification: false });
  for (const created of [north, south]) {
    const candidate = candidates.candidates.find(row => row.entity_ref === created.person.id_hex);
    expect(candidate).toMatchObject({ identity_evidence_refs: created.identity_evidence_refs,
      identity_owner_ref: engine.pairedActor.principalRef, identity_recorded_at: created.recorded_at,
      mention_evidence: [] });
    expect(candidate?.matched_hints).toEqual([northFixture.name.toLowerCase()]);
    expect(candidate?.made_by).not.toBeNull();
    expect(candidate?.made_by).toBeDefined();
  }
  await taggerRefusal(engine, agent, "vault.people.create", northInput, "owner");
  await taggerRefusal(engine, agent, "vault.entities.look_before_mint", lookupInput, "owner");
  expect(await lookup()).toEqual(candidates);

  const saved = await engine.client.call("vault.witness", {
    conversation_ref: refs.conversation, turn_ref: refs.turn, occurred_at: data.occurredAt,
    messages: [{ id: refs.message, author: "user", message_type: "dialogue", content: data.identity.ambiguousMention,
      is_visible: true, order: 0 }],
  });
  expect(saved.turn_id).toBe(refs.turn);
  const turnInput = { turn_ref: saved.turn_short_id };
  const status = () => engine.client.call("vault.tagging.status", turnInput);
  await awaitPublic(status, reply => reply.value.state === "settled" && reply.value.has_tags,
    { label: "ambiguous mention saved without choosing a person" });
  await taggerReadable(engine.client, refs, data.identity.ambiguousMention, northFixture.name);
  const originalTags = (await engine.client.call("vault.tagging.tags", turnInput)).value.tags;
  if (!originalTags) throw new Error("Missing saved ambiguous tags");
  expect(originalTags.mentions).toHaveLength(1);
  const suggested = originalTags.mentions[0]!;
  expect(suggested).toMatchObject({ index: 0, message_ref: refs.message, start: 0, end: nameEnd, label: "PERSON" });
  expect(suggested.confidence).toBeCloseTo(0.99, 6);
  if (suggested.link.link !== "candidates") throw new Error("Name-only tagging chose or minted an identity");
  expect([...suggested.link.entity_refs].sort()).toEqual(candidateRefs);
  const mentionInput: FacadeInput<"vault.identity.mention"> = {
    turn: refs.turn, message: refs.message, start: 0, end: nameEnd,
  };
  const mention = () => engine.client.call("vault.identity.mention", mentionInput);
  const before = await mention();
  expect(before).toMatchObject({ mention: mentionInput, name: northFixture.name, state: "candidates",
    target_ref: null, resolution: null });
  expect([...before.candidate_refs].sort()).toEqual(candidateRefs);
  expect(before.current).toEqual(suggested);
  expect(before.provenance).toEqual(originalTags.envelope);
  const decision = await engine.client.call("self.identity.settle", {
    name: northFixture.name, conversation: refs.conversation, effect: "send",
    prompt: "Which Mira Chen should receive the note?", someone_new: "Someone new",
  });
  if (decision.state !== "deciding") throw new Error("An ambiguous name must open an owner-answerable choice");
  expect(decision.ask).toMatch(/^[a-f0-9]{64}$/);
  expect(await mention()).toEqual(before);
  const ownerEvidence = await identityEvidence(engine, data.identity.ownerEvidence);
  const answerInput: FacadeInput<"self.identity.answer"> = { ask: decision.ask,
    choice: `is:${north.person.id_hex}`, evidence_refs: [ownerEvidence.receipt.entry_id] };
  await taggerRefusal(engine, agent, "vault.identity.mention", mentionInput, "owner");
  await taggerRefusal(engine, agent, "self.identity.answer", answerInput, "owner");
  // Refusing the agent neither consumes the choice nor changes its suggestion.
  expect(await mention()).toEqual(before);
  expect((await engine.client.call("vault.tagging.tags", turnInput)).value.tags).toEqual(originalTags);
  expect(await lookup()).toEqual(candidates);
  const answered = await engine.client.call("self.identity.answer", answerInput);
  expect(answered).toEqual({ ask: decision.ask, entity: north.person.id_hex });
  expect(data.identity.expected.resolvedPerson).toBe(northFixture.label);
  const resolved = await mention();
  expect(resolved).toMatchObject({ name: northFixture.name, state: "resolved", target_ref: north.person.id_hex,
    candidate_refs: [north.person.id_hex], mention: mentionInput,
    resolution: { ask: decision.ask, target_ref: north.person.id_hex, source: "user_stated",
      owner_ref: engine.pairedActor.principalRef, owner_evidence_refs: [ownerEvidence.receipt.entry_id] },
  });
  expect(resolved.resolution?.resolved_at).toEqual(expect.any(Number));
  expect(resolved.resolution?.original).toEqual(before.current);
  expect(resolved.resolution?.original_provenance).toEqual(before.provenance);
  expect(resolved.provenance).toEqual(before.provenance);
  expect(resolved.current).toEqual({ ...before.current,
    link: { link: "candidates", kind: suggested.link.kind, entity_refs: [north.person.id_hex] } });
  const resolvedTags = (await engine.client.call("vault.tagging.tags", turnInput)).value.tags;
  expect(resolvedTags?.mentions).toEqual([resolved.current]);
  expect(resolvedTags?.envelope).toEqual(originalTags.envelope);
  expect(await lookup()).toEqual(candidates);
  const northMentions = (await engine.client.call("vault.tagging.mentions", { entity_ref: north.person.id_hex, limit: 10 })).value;
  const southMentions = (await engine.client.call("vault.tagging.mentions", { entity_ref: south.person.id_hex, limit: 10 })).value;
  expect(northMentions.mentions).toEqual([{ turn_ref: refs.turn, index: 0, mention: resolved.current,
    freshness: { stale: false, pending_retag: false } }]);
  expect(southMentions.mentions).toEqual([]);
  expect(taggerExtractionIds(providers)).toEqual(["ambiguous-person"]);

  // The restart is the failure leg: durable evidence, not a fresh extraction.
  await engine.restart();
  expect((await status()).value).toMatchObject({ state: "settled", has_tags: true, marker: null });
  expect(await mention()).toEqual(resolved);
  expect((await engine.client.call("vault.tagging.tags", turnInput)).value.tags).toEqual(resolvedTags);
  expect(await lookup()).toEqual(candidates);
  expect((await engine.client.call("vault.get", { entity_ref: ownerEvidence.receipt.entry_id })).value).toEqual(ownerEvidence.stored);
  expect((await engine.client.call("vault.get", { entity_ref: northEvidence.receipt.entry_id })).value).toEqual(northEvidence.stored);
  expect((await engine.client.call("vault.get", { entity_ref: southEvidence.receipt.entry_id })).value).toEqual(southEvidence.stored);
  expect((await engine.client.call("vault.tagging.mentions", { entity_ref: north.person.id_hex, limit: 10 })).value).toEqual(northMentions);
  expect((await engine.client.call("vault.tagging.mentions", { entity_ref: south.person.id_hex, limit: 10 })).value).toEqual(southMentions);
  await taggerReadable(engine.client, refs, data.identity.ambiguousMention, northFixture.name);
  expect(taggerExtractionIds(providers)).toEqual(["ambiguous-person"]);
  taggerOnlyCalls(providers, data.tagger.expected.dreamerCalls);
  await engine.artifacts.json("providers.json", providers.seenFixtureCalls);
  await engine.close();
  taggerOnlyCalls(providers, data.tagger.expected.dreamerCalls);
  await providers.close();
});
