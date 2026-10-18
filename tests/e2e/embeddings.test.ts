import { afterAll, expect, test } from "bun:test";
import { createServer } from "node:net";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import type { FacadeInput } from "@oneiron/client";
import type { SpaceMove, WitnessReceipt } from "@oneiron/client/facade-types";
import { CliClient, CliError, PublicHttpClient, SdkProcessDriver, credentialParts } from "./support/clients.ts";
import { EngineFixture, awaitPublic } from "./support/engine.ts";
import { loadBuildManifest, loadFixtures, requireAsset } from "./support/fixtures.ts";
import { ScriptedProviders, embeddingReply } from "./support/providers.ts";
import type { ProviderStep } from "./support/providers.ts";
import { Artifacts, LIMITS, ManagedProcess, defineFile, isolatedEnv, ownResource, redactor, secretHex, tempRoot } from "./support/run.ts";

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
    await artifacts.json("public-schema.json", (await client.request("GET", "/api/openapi.json")).body);
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

/* EMBEDDINGS-04 — Text and media space search should work. OF-370, OF-329.
 * Oracle: scenarios.media plus the pinned red-triangle PNG/three-pulse WAV.
 * Existing declare/bind inputs above; bind({kind: text|image|audio,space}) ->
 * EmbeddingSpacesView. recall({query,effort:'medium',media?:
 *   {space,mime,bytes_b64,kinds?: (text|image|audio)[]}}) -> MemoryPack;
 * GET search/vector takes space,queryKind,query,limit,view. Each declared
 * space pins its revision, width, accepted inputs, towers and own floor.
 * Required typed ingest: asset ref + MIME + content/byte ref + embedding kind;
 * required hit evidence: asset ref, embedding kind, declared space/version,
 * per-space match evidence and selected bytes/text/handle form with receipt.
 * Upload text/photo/audio through that door, hold fills independently, and
 * verify routing by the separate provider origins and authored fixture ids.
 * Query each kind and cross-modality with the declared text/media towers.
 * Orthogonal no-match queries must abstain at EACH kind's authored floor;
 * compare kind/target sets, not cross-space raw scores. Read the metadata and
 * resolver receipt to prove the chosen space and reader's declared form.
 * Current ArtifactCreateRequest writes BLOB_ARTIFACT, not the image/audio
 * ASSETs this backfill scans. structural.put({kind:'asset',body:unknown}) is
 * not a typed media-ingest door. MemoryItem also lacks the required typed
 * space/kind evidence. Never seed binary ASSET bodies through a generic put.
 */
suite.todo(test, "EMBEDDINGS-04", "waits on typed media ASSET ingest and per-kind space/evidence result metadata");

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

/* EMBEDDINGS-06 — Oneironer tags without authoring beliefs should work.
 * OF-119/128/135/138/539. Oracle: scenarios.tagger (contract-v2 model card,
 * PERSON/EMAIL spans, coreference link and VAD); no teacher-training claim.
 * Public setup: witness(WitnessTurn) -> WitnessReceipt; claims.list
 * ({subject_ref?,predicate?,lifecycle?,limit}) -> ScopedReadResult<ClaimView[]>.
 * EngineFixture.oneironer configures the real GET /v1/model and POST
 * /v1/extract adapter. Script the startup card, then hold the extract request;
 * assert witness ACK, raw conversation transcript and light recall while
 * held. Required typed read: turn ref -> pending/retrying/settled tagging
 * marker + configured model/checkpoint + failure reason; settled tags ->
 * mention refs/spans/targets, coreference, affect, PII labels and provenance.
 * Release the fixed output, read those saved annotations, and recall by its
 * mention. Compare claims before/after (empty), with every Dreamer generation
 * origin scripted for zero calls. Repeat with a missing/delayed tagger: a
 * visible retry state and raw turn, not a write failure or invented beliefs.
 * No typed HTTP+SDK marker/tag/mention-history reads exist. TURN/entity reads
 * return an opaque entity body, not the tag side-table contract. Affect-only
 * /turns/annotate cannot certify NER/coreference/PII/tagging completion.
 */
suite.todo(test, "EMBEDDINGS-06", "waits on typed tagging marker/status and saved mention/coreference/PII annotation reads");

/* EMBEDDINGS-07 — Conservative entity resolution should work. OF-443.
 * Oracle: scenarios.identity. Two distinct Mira Chen people have independent
 * contact/organisation evidence; the name alone must not merge them.
 * Existing self.identity.settle({name,conversation?,effect,prompt,someone_new})
 * -> {state:'settled',entity} | {state:'unknown'} |
 *    {state:'deciding',ask} | {state:'needs_person',ask,card:unknown};
 * self.identity.answer({ask,choice}) -> {ask,entity}; people.list/get exist.
 * Required typed setup/search: create person with identity-evidence refs;
 * look-before-mint(kind,declared identity hints,mention evidence) -> N
 * candidates with evidence/provenance, never a derived identity id. Required
 * read: mention -> unresolved/candidates/resolved target + resolving owner
 * evidence and provenance. First search, then import the ambiguous mention
 * through witness/tagger. The two people remain distinct, with neither
 * silently selected by a name hint. Supply the later owner evidence through
 * the typed identity decision, choose only the returned matching person,
 * and assert original mention plus owner resolution provenance survives.
 * No typed person-with-evidence creation, look-before-mint query or resolved
 * mention provenance projection exists in HTTP+SDK. The existing owner choice
 * verbs are not missing, but opaque structural PERSON bodies, a generic get
 * or refs.resolve's handle lookup are not the missing identity contracts.
 */
suite.todo(test, "EMBEDDINGS-07", "waits on typed person identity-evidence setup, look-before-mint and resolved-mention provenance reads");
