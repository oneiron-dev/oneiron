import { afterAll, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import type { Facade, FacadeInput, FacadeResult } from "@oneiron/client";
import { EngineFixture, awaitPublic } from "./support/engine.ts";
import { PublicHttpClient, credentialParts } from "./support/clients.ts";
import { loadFixtures, ownerBaseClaimScope } from "./support/fixtures.ts";
import { ScriptedProviders } from "./support/providers.ts";
import { assertFlowActive, defineFile, ownResource, recordStart, redactor } from "./support/run.ts";

const profile = process.env.E2E_PROFILE === "real-small-model"
  ? "real-small-model" : "deterministic";
const suite = defineFile(import.meta, { profile, slots: 1 });
afterAll(suite.flush);

function errorText(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/* Source-only proposal against the current public catalog. Canon expectations
 * and authored inputs come from retrieval-scenarios and retrieval-evidence.
 * A fresh authenticated vault per flow, one slot, no engine imports, private
 * clocks, mutation retries, model downloads, or stored output snapshots.
 * Manifest TODO metadata is historical; registration below is authoritative.
 * The proposal has not been executed or type-checked on this Mac.
 */
type ReadReceipt = FacadeResult<"vault.claims.list">["narrowing"];
type ClaimRow = FacadeResult<"vault.claims.list">["value"][number];
interface Probe { readonly query: string; readonly vector: number[] }
interface EvidenceClaim {
  readonly label: string; readonly predicate: string;
  readonly value: string; readonly vector: number[];
}
interface EvidenceFixture {
  readonly embedder: {
    readonly modelKey: string; readonly modelId: string; readonly dimensions: number;
    readonly probeText: string; readonly probeVector: number[]; readonly usageInputTokens: number;
  };
  readonly confidence: number; readonly salience: number;
  readonly occurredAt: number; readonly learnedAt: number;
  readonly claims: EvidenceClaim[];
  readonly weak: Probe;
  readonly anomalous: (Probe & { readonly label: string })[];
  readonly strong: Probe & { readonly requiredLabels: string[] };
  readonly expectations: {
    readonly storedSource: string; readonly storedApproval: string;
    readonly storedLifecycle: string; readonly storedStale: boolean;
  };
  readonly constants: { readonly tokenBudget: number; readonly resultLimit: number };
}
// Existing OpenAPI context-pack and legacy vector-search DTO subsets. The
// facade calls below use generated input/output types, not hand-made DTOs.
interface ContextPackRequest {
  readonly query: string; readonly query_vector: number[];
  readonly limit: number; readonly edge_hop: number; readonly view: "full";
  readonly budget: { readonly token_budget: number };
}
interface ContextPackReply {
  readonly results: { readonly id: string }[];
  readonly neighbors: { readonly id: string }[];
  readonly state: {
    readonly kind: "ok" | "missing_data" | "low_confidence" | "skipped";
    readonly reason?: string;
  };
  readonly evidence: { readonly result_ids: string[]; readonly scores: unknown[] };
  readonly narrowing: ReadReceipt;
}
interface VectorPage {
  readonly items: { readonly id: string; readonly score: number }[];
  readonly narrowing: ReadReceipt[];
}
interface ScenarioBook {
  readonly scenarios: { readonly id: string; readonly inputs: unknown }[];
}
async function scenario<T>(id: string): Promise<T> {
  const catalog = await loadFixtures();
  const book = await catalog.readJson<ScenarioBook>("retrieval-scenarios");
  const row = book.scenarios.find(row => row.id === id);
  if (!row) throw new Error(`Missing authored scenario ${id}`);
  return row.inputs as T;
}
const utc = (value: string) => Date.parse(value) / 1000;
const sorted = (values: readonly string[]) => [...values].sort();
const blend: Facade.RetrievalBlendWeights = {
  relevance: 1, recency: 0, salience: 0, confidence: 0, gravity: 0,
};
function readReceipt(receipt: ReadReceipt) {
  expect(receipt.requested).toBeDefined();
  expect(receipt.actor_ceiling).toBeDefined();
  expect(receipt.applied).toBeDefined();
  expect(Array.isArray(receipt.narrowed_axes)).toBe(true);
  expect(Array.isArray(receipt.replan_hint)).toBe(true);
}
async function claim(engine: EngineFixture, scope: Facade.ClaimScope,
  input: Omit<FacadeInput<"vault.claims.upsert">, "scope" | "subject_ref" | "source" | "confidence"> & {
    readonly subject_ref?: string; readonly confidence?: number;
  }) {
  const receipt = await engine.client.call("vault.claims.upsert", {
    ...input, scope, subject_ref: input.subject_ref ?? engine.pairedActor.principalRef,
    source: "user_stated", confidence: input.confidence ?? 0.875,
  });
  expect(["auto", "approved"]).toContain(receipt.approval);
  await engine.awaitReceipt(receipt.receipt_ref);
  const read = await engine.client.call("vault.hydrate", { refs: [receipt.claim_short_id] });
  readReceipt(read.narrowing);
  expect(read.value).toHaveLength(1);
  return { receipt, entity: read.value[0]!, ref: receipt.claim_short_id, id: read.value[0]!.id_hex };
}
async function claimSet(engine: EngineFixture) {
  const read = await engine.client.call("vault.claims.list", {
    subject_ref: engine.pairedActor.principalRef, limit: 1000,
  });
  readReceipt(read.narrowing);
  return [...read.value].sort((a, b) => a.claim_ref.localeCompare(b.claim_ref));
}
async function task(engine: EngineFixture, title: string, occurredAt: number,
  edges: Facade.StructuralEdgeSpec[] = [], name?: string) {
  return engine.client.call("vault.structural.put", {
    // TASK bodies require the existing TaskRole::Task byte (role 1).
    kind: "TASK", body: { title, role: 1, ...(name ? { name } : {}) },
    text_fields: [{ field: "content", value: title }],
    edges, occurred_at: occurredAt, learned_at: occurredAt,
  });
}
async function witnessedText(engine: EngineFixture, text: string, occurredAt: number) {
  const conversation = await engine.client.call("vault.conversations.create", {
    body: {}, occurred_start: occurredAt, occurred_end: occurredAt, learned_at: occurredAt,
  });
  const witnessed = await engine.client.call("vault.witness", {
    conversation_ref: conversation.id, occurred_at: occurredAt,
    messages: [{ author: "user", message_type: "text", content: text, is_visible: true, order: 0 }],
  });
  expect(witnessed.message_short_ids).toHaveLength(1);
  const message = await engine.client.call("vault.get", { entity_ref: witnessed.message_short_ids[0]! });
  expect(message.value).not.toBeNull();
  expect(message.value!.body).toMatchObject({ content: text });
  return { conversation, witnessed, message: message.value! };
}
// The fixture supplies egress authorization, so init needs an explicit remote
// locality and the same pinned model as its on-device fallback. Both URLs are
// loopback fixtures, not a remote service or a model download.
const endpointInitArgs = (endpoint: string) => [
  "--embedder-locality", "owner-server", "--embedder-fallback-endpoint", endpoint,
];
async function recordBoundReader(engine: EngineFixture, ids: readonly string[]) {
  const { seed } = credentialParts(engine.pairedActor.credential);
  const narrowed = await engine.client.call("self.credential.attenuate", {
    holder_seed: [...Buffer.from(seed, "hex")], caveat: { records: [...ids] },
  });
  if (!narrowed.token.startsWith("v2.slip.")) throw new Error("Expected public attenuated slip");
  const credential = `v2.cred.${narrowed.token.slice(8)}.${seed}`;
  return new PublicHttpClient(engine.url, { credential, artifacts: engine.artifacts });
}
const rerankConfig = (endpoint: string) => `
[models.providers.retrieval_fixture]
kind = "local-openai-compat"
base_url = "${endpoint}"
revision = "e2e-v1"
[models.roles.reranker]
model = "retrieval_fixture:retrieval-reranker"
`;
function rerankStep(id: string, barrier?: string) {
  return {
    id, origin: "reranker", role: "reranker", purpose: "retrieval-ranking",
    request: { method: "POST" as const, path: "/v1/rerank", model: "retrieval-reranker" },
    response: { kind: "json" as const, body: {
      results: [{ index: 0, relevance_score: 0.9 }, { index: 1, relevance_score: 0.8 }],
      usage: { total_tokens: 16 },
    } }, ...(barrier ? { barrier } : {}),
  };
}
async function effortCorpus(engine: EngineFixture) {
  const scope = await ownerBaseClaimScope(engine.client, engine.pairedActor.principalRef);
  const rows: Awaited<ReturnType<typeof claim>>[] = [];
  for (const [index, value] of [
    "retrievaleffortlantern: The calibration sheet is in the north drawer.",
    "retrievaleffortlantern: The spare lens is in the south drawer.",
  ].entries()) rows.push(await claim(engine, scope, {
    predicate: `profile.retrieval_effort_${index}`, value,
    occurred_at: utc("2026-08-01T00:00:00Z"), learned_at: utc("2026-08-01T00:00:00Z"),
  }));
  await awaitPublic(() => engine.client.call("vault.search.bm25", { query: "retrievaleffortlantern", limit: 10 }),
    read => rows.every(row => read.value.some(hit => hit.short_id === row.ref || hit.record?.id === row.id)),
    { label: "published effort corpus" });
  return rows;
}
/** External OpenAI-compatible embedder only; it never reads or fakes a vault.
 * Shared ScriptedProviders has ordered replies, but no exact text-table lookup
 * for the reconciler's variable batches. This fixture accepts only declared
 * canonical claim strings, explicit structural texts, the startup probe, and
 * the observed production-reconciliation background corpus below. Unknown input
 * fails the flow; no default vector, prompt echo or engine-derived answer.
 */
// G8 source-mapped background corpus (FIX21902 closure, Engine 12:03; FIX21914 adds observed agent-health-review). 28
// pinned literals from production-reconciliation batches (R22 32-input batch
// before first test write, 8-input batches after; egress.allowAll on a fresh
// vault legitimately seeds bootstrap data): 1 startup literal 'model', 7
// opaque 32-hex rows (exact producing rows UNKNOWN per rootcause, pinned as
// literals, never a live any-32hex pattern which would silently accept
// unplanned inputs), 13 skill hub_provenance CLAIMs (5 bootstrap hubId
// eba40381... + 8 pack hubId 0f8ccc77..., all clock-free verbatim; producer
// skill_hub/index.rs:257-266 ClaimBody PREDICATE_SKILL_HUB_PROVENANCE with
// {contentHash, hubRef}, embedded via embed.rs:136-145 payload_text and
// eligibility.rs:116-123 ClaimBody), 5 bootstrap scan_verdict shapes
// (scannedAt normalized to 0 here; live run-clock values recognized by
// backgroundScanVerdict below; producer skill_hub/verdict.rs:254-287 with
// {contentHash, provider oneiron.static.v1, scannedAt, verdict unknown,
// riskLevel none, completeness complete, governance recommended,
// staticInputHash hex64}), and 2 skill-description rows (goal-intake + agent-health-review prose).
// Fresh-run legitimacy is observed in-test via provider.seen (see R06 check)
// plus 10s awaitPublic server-provided lists (/api/search/vector per-row
// probes, vault.claims.list), not assumed from R22 snapshots. No fixture
// oracle change (evidence.json/scenarios.json untouched).
const BACKGROUND_LITERALS: readonly string[] = [
  'model',
  'a4c287a77f1c843ba4b81ebc08ca586b',
  'aaa8b40c792382e1aa3914d6c815dcea',
  '19e703985adb802e98a70319a12d492d',
  'b6bde9dd17f281f6ad9ea8c99abdb3b7',
  '5ec8a51826f0872f94ac79683df7655b',
  'd8ed7af830d287e4b7411071dcfb3585',
  'd923dd245bce8350821638df84613dc0',
  '{"contentHash": "6aaf0a1c744bc7eebd62970aa2089b3822dec8055558f5855a69d33ff1bfde2e", "hubRef": {"hubId": "eba40381816289359d577401be27f01f", "refString": "skill-optimize", "pin": {"type": "content_hash", "value": "6aaf0a1c744bc7eebd62970aa2089b3822dec8055558f5855a69d33ff1bfde2e"}}}',
  '{"contentHash": "6aaf0a1c744bc7eebd62970aa2089b3822dec8055558f5855a69d33ff1bfde2e", "provider": "oneiron.static.v1", "scannedAt": 0, "verdict": "unknown", "riskLevel": "none", "completeness": "complete", "governance": "recommended", "staticInputHash": "9f976250cbb5ec53a19be22b10a294c02ffeb58ecf1df6942babca6f17aab321"}',
  '{"contentHash": "d5ad33a464e4c5bf48254121a0c3fc9a600e7104d46a1359057ec8369ac25a4d", "hubRef": {"hubId": "eba40381816289359d577401be27f01f", "refString": "judge", "pin": {"type": "content_hash", "value": "d5ad33a464e4c5bf48254121a0c3fc9a600e7104d46a1359057ec8369ac25a4d"}}}',
  '{"contentHash": "d5ad33a464e4c5bf48254121a0c3fc9a600e7104d46a1359057ec8369ac25a4d", "provider": "oneiron.static.v1", "scannedAt": 0, "verdict": "unknown", "riskLevel": "none", "completeness": "complete", "governance": "recommended", "staticInputHash": "da909150abaf0d3c0a3d561aa5fb4ee014ef4a3a5cf91852e7ebbcffa3196181"}',
  '{"contentHash": "4a4b957ac57ad162aba6bf04f857aea09dc9134a120e167175eef70e1f462040", "hubRef": {"hubId": "eba40381816289359d577401be27f01f", "refString": "goal-intake", "pin": {"type": "content_hash", "value": "4a4b957ac57ad162aba6bf04f857aea09dc9134a120e167175eef70e1f462040"}}}',
  '{"contentHash": "4a4b957ac57ad162aba6bf04f857aea09dc9134a120e167175eef70e1f462040", "provider": "oneiron.static.v1", "scannedAt": 0, "verdict": "unknown", "riskLevel": "none", "completeness": "complete", "governance": "recommended", "staticInputHash": "8211f1a1b1da05e2ae2ad8bc9e68875d29c0c1e1d115c4a8119200e196e7b965"}',
  '{"contentHash": "680595164edaf97e42280f9f6f6ef6283d0167eb0c63d3e6f25fc7339049508d", "hubRef": {"hubId": "eba40381816289359d577401be27f01f", "refString": "wake", "pin": {"type": "content_hash", "value": "680595164edaf97e42280f9f6f6ef6283d0167eb0c63d3e6f25fc7339049508d"}}}',
  '{"contentHash": "680595164edaf97e42280f9f6f6ef6283d0167eb0c63d3e6f25fc7339049508d", "provider": "oneiron.static.v1", "scannedAt": 0, "verdict": "unknown", "riskLevel": "none", "completeness": "complete", "governance": "recommended", "staticInputHash": "b9641ba28169ecc42be2009f72932c5b47cf076b8cb40ad6c83601cd3c4dcf91"}',
  '{"contentHash": "73278f055a5c12348058a87f0918afdb900e9a84c629259b28820ab5960350ea", "hubRef": {"hubId": "eba40381816289359d577401be27f01f", "refString": "agent-health-review", "pin": {"type": "content_hash", "value": "73278f055a5c12348058a87f0918afdb900e9a84c629259b28820ab5960350ea"}}}',
  '{"contentHash": "73278f055a5c12348058a87f0918afdb900e9a84c629259b28820ab5960350ea", "provider": "oneiron.static.v1", "scannedAt": 0, "verdict": "unknown", "riskLevel": "none", "completeness": "complete", "governance": "recommended", "staticInputHash": "0786ddfe9ba6dd6affd8c5b2df48ca2af6908505bb246192f7b6f22232105ebc"}',
  '{"contentHash": "fff8ad74327606acd8335424de87dc954dfd99792b2213e9793fc0bebe329b69", "hubRef": {"hubId": "0f8ccc77298089c9b670f3bac7ae8f07", "refString": "pack-skill:243cedb7325752bc213efb71a493d3cb5b721d760d146e4ca1aea88ccd8251de", "pin": {"type": "content_hash", "value": "fff8ad74327606acd8335424de87dc954dfd99792b2213e9793fc0bebe329b69"}}}',
  '{"contentHash": "b97d7d780db236973912a26553c2759b368104a4a903419d51309aa0338691d3", "hubRef": {"hubId": "0f8ccc77298089c9b670f3bac7ae8f07", "refString": "pack-skill:70739f85288954f06ed60a33f8fa231f91dcce525d92651259e64c02ab7ad466", "pin": {"type": "content_hash", "value": "b97d7d780db236973912a26553c2759b368104a4a903419d51309aa0338691d3"}}}',
  '{"contentHash": "8e6ef3e2ed38e1232b50027cb16f9e1bd097aad921f7ec0efd4b6e36a9fe5a37", "hubRef": {"hubId": "0f8ccc77298089c9b670f3bac7ae8f07", "refString": "pack-skill:55e17435fce176ce59f24206d72978b371df9d3ba7c3bce4e9aa4f3b85db9bae", "pin": {"type": "content_hash", "value": "8e6ef3e2ed38e1232b50027cb16f9e1bd097aad921f7ec0efd4b6e36a9fe5a37"}}}',
  '{"contentHash": "77bc3c46d1125077de84efa9472cbe00b40294c0bd5d8f8c45fc63d4ebf8da78", "hubRef": {"hubId": "0f8ccc77298089c9b670f3bac7ae8f07", "refString": "pack-skill:d6b1f4b7b53b8a0c2e6532a278eec0d8d0e111cc103b486b1008cc6c32fb2d47", "pin": {"type": "content_hash", "value": "77bc3c46d1125077de84efa9472cbe00b40294c0bd5d8f8c45fc63d4ebf8da78"}}}',
  '{"contentHash": "1bb662bb3d352973c375c2e2884979ae868c32d0b496666a0a908babb77977f7", "hubRef": {"hubId": "0f8ccc77298089c9b670f3bac7ae8f07", "refString": "pack-skill:3a019fa1ec338bfc492ca92ce0fabd18d25966195dbe454ae394ef845c2d0e77", "pin": {"type": "content_hash", "value": "1bb662bb3d352973c375c2e2884979ae868c32d0b496666a0a908babb77977f7"}}}',
  '{"contentHash": "bdea3a9b9ff4c63804e89de60815957fdae35f9e7ed99963b5b0532999db1f59", "hubRef": {"hubId": "0f8ccc77298089c9b670f3bac7ae8f07", "refString": "pack-skill:81ffcb82eb5ff17e543684ad7ef119b5b6d30b1f5e47a18158a023317c8aeb60", "pin": {"type": "content_hash", "value": "bdea3a9b9ff4c63804e89de60815957fdae35f9e7ed99963b5b0532999db1f59"}}}',
  '{"contentHash": "f661e275a80d44bfc5ac4cd3cb200f45010a9c41aa15289f47d699849e460c2a", "hubRef": {"hubId": "0f8ccc77298089c9b670f3bac7ae8f07", "refString": "pack-skill:79ba63d22e2a88e88be173d0db70c37d962899d50769a861be5ade0a729577c9", "pin": {"type": "content_hash", "value": "f661e275a80d44bfc5ac4cd3cb200f45010a9c41aa15289f47d699849e460c2a"}}}',
  '{"contentHash": "237cec53997e8d4b4bc642b34913249a2d86672def3fc1d5948679aa75ac7e0c", "hubRef": {"hubId": "0f8ccc77298089c9b670f3bac7ae8f07", "refString": "pack-skill:08da204ede76e8749a0d4866bebbf5d21d3396475f6005f1c4fb68f3431021f8", "pin": {"type": "content_hash", "value": "237cec53997e8d4b4bc642b34913249a2d86672def3fc1d5948679aa75ac7e0c"}}}',
  'Interview a human for a typed project goal record and commit it via authenticated intake.',
  'Judge agent health from receipts with closed-form detectors and seeded dials.',
];
// contentHashes of the 13 observed skill rows (5 bootstrap + 8 pack).
const BACKGROUND_SKILL_HASHES: ReadonlySet<string> = new Set([
  '1bb662bb3d352973c375c2e2884979ae868c32d0b496666a0a908babb77977f7',
  '237cec53997e8d4b4bc642b34913249a2d86672def3fc1d5948679aa75ac7e0c',
  '4a4b957ac57ad162aba6bf04f857aea09dc9134a120e167175eef70e1f462040',
  '680595164edaf97e42280f9f6f6ef6283d0167eb0c63d3e6f25fc7339049508d',
  '6aaf0a1c744bc7eebd62970aa2089b3822dec8055558f5855a69d33ff1bfde2e',
  '73278f055a5c12348058a87f0918afdb900e9a84c629259b28820ab5960350ea',
  '77bc3c46d1125077de84efa9472cbe00b40294c0bd5d8f8c45fc63d4ebf8da78',
  '8e6ef3e2ed38e1232b50027cb16f9e1bd097aad921f7ec0efd4b6e36a9fe5a37',
  'b97d7d780db236973912a26553c2759b368104a4a903419d51309aa0338691d3',
  'bdea3a9b9ff4c63804e89de60815957fdae35f9e7ed99963b5b0532999db1f59',
  'd5ad33a464e4c5bf48254121a0c3fc9a600e7104d46a1359057ec8369ac25a4d',
  'f661e275a80d44bfc5ac4cd3cb200f45010a9c41aa15289f47d699849e460c2a',
  'fff8ad74327606acd8335424de87dc954dfd99792b2213e9793fc0bebe329b69',
]);
const HEX64 = /^[0-9a-f]{64}$/;
// Timestamp-aware scan-verdict recognition: exact schema plus pinned
// non-clock fields. scannedAt is run clock and the only accepted variance;
// an unknown skill hash or shape still fails the flow.
function backgroundScanVerdict(text: string): boolean {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    return false;
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const row = value as Record<string, unknown>;
  return typeof row.contentHash === "string" && BACKGROUND_SKILL_HASHES.has(row.contentHash)
    && row.provider === "oneiron.static.v1"
    && typeof row.scannedAt === "number" && Number.isFinite(row.scannedAt) && row.scannedAt >= 0
    && row.verdict === "unknown" && row.riskLevel === "none"
    && row.completeness === "complete" && row.governance === "recommended"
    && typeof row.staticInputHash === "string" && HEX64.test(row.staticInputHash);
}
function startVectorTable(fixture: EvidenceFixture, extraVectors: readonly (readonly [string, number[]])[] = []) {
  const vectors = new Map<string, number[]>([
    [fixture.embedder.probeText, fixture.embedder.probeVector],
    ...fixture.claims.map(row => [row.value, row.vector] as [string, number[]]),
    ...extraVectors,
  ]);
  // Authored background vector: the all-ones diagonal, dimension-generic.
  // Geometry non-contamination proof (4-dim; R06/R01/R12 all use 4): cosine
  // to any axis probe is 1/sqrt(4)=0.5, to self 1.0. R06 weak probe [1,0,0,0]
  // vs weak-observation [0.125,1,0,0] cosine ~0.124, vs background 0.5, vs
  // self 1.0 for per-row top-1 (limit 1) so fixture rows still win; strong
  // probe [0,0,1,0] vs strong-a 1.0, strong-b ~0.9999, background 0.5, weak
  // 0.0, so required strong ids rank first. R01 query [1,0,0,0] vs
  // all-evidence 1.0, background 0.5, unrelated [0,0,0,1] 0.0, so
  // all-evidence before unrelated holds; containment checks only gain
  // unrelated rows. R12 ordinary query [1,0,1,0] vs right-tail 1.0,
  // background 0.707, wrong-tail 0.0, so right before wrong holds; voice
  // presence-only checks unaffected. Background rows carry their own entity
  // ids, so they can neither satisfy an expected-id probe (per-row probes
  // require exact fixture ids via 10s awaitPublic server lists) nor hide a
  // missing fixture record (a missing row's probe would return background,
  // failing the id match loudly). No 32hex fallback; unknown inputs still
  // refuse with recorded rejectedInputs.
  const backgroundVector = Array.from({ length: fixture.embedder.dimensions }, () => 1);
  for (const text of BACKGROUND_LITERALS) {
    if (!vectors.has(text)) vectors.set(text, backgroundVector);
  }
  const vectorFor = (text: string): number[] | undefined =>
    vectors.get(text) ?? (backgroundScanVerdict(text) ? backgroundVector : undefined);
  const seen = new Set<string>();
  const violations: string[] = [];
  let closed = false;
  let disown = () => {};
  assertFlowActive();
  const server = Bun.serve({
    hostname: "127.0.0.1", port: 0,
    async fetch(request) {
      const path = new URL(request.url).pathname;
      try {
        if (request.method === "GET" && path === "/v1/models") {
          return Response.json({ object: "list", data: [{ id: fixture.embedder.modelKey, object: "model" }] });
        }
        if (request.method !== "POST" || path !== "/v1/embeddings") {
          throw new Error(`Unexpected vector fixture route: ${request.method} ${path}`);
        }
        const body = await request.json() as { model?: unknown; input?: unknown };
        if (body.model !== fixture.embedder.modelKey || !Array.isArray(body.input) || body.input.length === 0) {
          throw new Error("Vector fixture needs its declared model and a nonempty input array");
        }
        const unexpected = body.input.filter((text: unknown) => typeof text !== "string" || vectorFor(text) === undefined);
        if (unexpected.length) await recordStart("fixture", {method:"POST",path:"/v1/embeddings",model:body.model,
          rejectedInputs:unexpected.map((text:unknown) => typeof text === "string"
            ? {sha256:createHash("sha256").update(text).digest("hex"),text:redactor.text(text)} : {type:typeof text})});
        const data = body.input.map((text: unknown, index: number) => {
          const embedding = typeof text === "string" ? vectorFor(text) : undefined;
          if (typeof text !== "string" || embedding === undefined) {
            throw new Error("Unexpected canonical text sent to vector fixture");
          }
          seen.add(text);
          return { object: "embedding", index, embedding };
        });
        return Response.json({ object: "list", model: fixture.embedder.modelKey, data,
          usage: { prompt_tokens: fixture.embedder.usageInputTokens, total_tokens: fixture.embedder.usageInputTokens } });
      } catch (error) {
        violations.push(error instanceof Error ? error.message : String(error));
        return Response.json({ error: { type: "invalid_request_error", message: "Vector fixture request refused" } }, { status: 400 });
      }
    },
  });
  const close = async () => {
    if (closed) return;
    closed = true;
    disown();
    await server.stop(true);
    if (violations.length) throw new Error(violations.join("; "));
  };
  disown = ownResource(close);
  return { endpoint: `http://127.0.0.1:${server.port}/v1`, seen, close };
}

/* RETRIEVAL-01: explicit five-channel inputs and direct per-hit evidence. */
suite.test(test, "RETRIEVAL-01", "Five-channel recall and stable rank should work", async () => {
  const fixture = await scenario<{
    query: string; queryVector: number[]; anchorUtc: string; seedLabels: string[];
    corpus: { label: string; text: string; name?: string; vector: number[]; occurredUtc?: string }[];
    edges: { from: string; kind: string; to: string }[];
    expected: { relevantLabels: string[]; before: string[][]; traceSignals: Facade.RetrievalSignal[] };
  }>("RETRIEVAL-01");
  const catalog = await loadFixtures();
  const vectorFixture = await catalog.readJson<EvidenceFixture>("retrieval-evidence");
  const provider = startVectorTable({ ...vectorFixture, claims: [] }, [
    ...fixture.corpus.map(row => [row.text, row.vector] as const),
    ["Calibration graph seed", [0, 0, 0, 1]],
  ]);
  const engine = await EngineFixture.start({ id: "RETRIEVAL-01", profile,
    initArgs: endpointInitArgs(provider.endpoint), embedder: {
      endpoint: provider.endpoint, modelKey: vectorFixture.embedder.modelKey,
      modelId: vectorFixture.embedder.modelId, dimensions: fixture.queryVector.length, egress: { allowAll: true },
    } });
  let primaryFailed: boolean = false;
  let primary: unknown;
  try {
    const records = new Map<string, Facade.EntityRefReceipt>();
    for (const row of fixture.corpus) {
      const record = await task(engine, row.text, utc(row.occurredUtc ?? fixture.anchorUtc), [], row.name);
      records.set(row.label, record);
      const put = await engine.client.call("vault.vectors.put", { entity_ref: record.entity_ref, vector: row.vector });
      expect(put.dimensions).toBe(fixture.queryVector.length);
    }
    for (const label of fixture.seedLabels) {
      const edges = fixture.edges.filter(edge => edge.from === label).map(edge => ({
        edge_kind: edge.kind, target_ref: records.get(edge.to)!.entity_ref,
      }));
      const seed = await task(engine, "Calibration graph seed", utc(fixture.anchorUtc), edges);
      records.set(label, seed);
      await engine.client.call("vault.vectors.put", { entity_ref: seed.entity_ref, vector: [0, 0, 0, 1] });
    }
    // G-TOPK (FIX21914): isolate the authored ranking corpus from bootstrap
    // top-k occupancy via the existing record-bound reader, admitting every
    // intended corpus record and its real PPR seed. Ranking reads use this
    // scoped reader; writes and pinned revision gets stay on the owner.
    const reader = await recordBoundReader(engine, [...records.values()].map(record => record.id_hex));
    for (const [label, record] of records) {
      const vector = fixture.corpus.find(row => row.label === label)?.vector ?? [0, 0, 0, 1];
      await awaitPublic(() => reader.call("vault.search.vector", { query: vector, limit: 20 }),
        read => read.value.hits.some(hit => hit.entity_ref === record.id_hex),
        { label: `published vector: ${label}` });
    }
    // Mira and Meera share the standard English Soundex M600 code. Codes are
    // authored query input; none are planted into an index or claimed learned.
    const input: FacadeInput<"vault.search.hybrid"> = {
      query: fixture.query, query_vector: fixture.queryVector,
      phonetic_codes: ["en:soundex:M600"],
      ppr: { seeds: fixture.seedLabels.map(label => records.get(label)!.entity_ref), depth: 2 },
      temporal: { start: utc(fixture.anchorUtc), end: utc(fixture.anchorUtc) },
      replay: { now: utc(fixture.anchorUtc), blend_weights: blend }, limit: 20,
    };
    const first = await awaitPublic(() => reader.call("vault.search.hybrid", input),
      read => fixture.expected.relevantLabels.every(label =>
        read.value.some(hit => hit.entity_ref === records.get(label)!.id_hex)),
      { label: "published five-channel authored corpus" });
    const repeated = await reader.call("vault.search.hybrid", input);
    for (const read of [first, repeated]) readReceipt(read.narrowing);
    const ids = first.value.map(hit => hit.entity_ref);
    expect(repeated.value.map(hit => hit.entity_ref)).toEqual(ids);
    for (const label of fixture.expected.relevantLabels) expect(ids).toContain(records.get(label)!.id_hex);
    for (const [earlier, later] of fixture.expected.before) {
      expect(ids).toContain(records.get(later!)!.id_hex);
      expect(ids.indexOf(records.get(earlier!)!.id_hex)).toBeLessThan(ids.indexOf(records.get(later!)!.id_hex));
    }
    const signals = new Set(first.value.flatMap(hit => hit.components.map(component => component.signal)));
    for (const signal of fixture.expected.traceSignals) expect(signals.has(signal)).toBe(true);
    for (const [label, signal] of [
      ["lexical", "text"], ["vector", "vector"], ["graph", "ppr"],
      ["temporal", "temporal"], ["phonetic", "phonetic"],
    ] as const) {
      const hit = first.value.find(hit => hit.entity_ref === records.get(label)!.id_hex)!;
      expect(hit.components.some(component => component.signal === signal)).toBe(true);
      expect(hit.source_revision_ref).toBeTruthy();
      const stored = await engine.client.call("vault.get", { entity_ref: `${hit.entity_ref}@${hit.source_revision_ref!}` });
      expect(stored.value?.body).toMatchObject({ title: fixture.corpus.find(row => row.label === label)!.text });
    }
    await engine.artifacts.json("retrieval-five-channel.json", { input, first, repeated });
  } catch (error) {
    primaryFailed = true;
    primary = error;
  } finally {
    const cleanups: string[] = [];
    try { await engine.close(); } catch (error) { cleanups.push(errorText(error)); }
    try { await provider.close(); } catch (error) { cleanups.push(errorText(error)); }
    if (primaryFailed) {
      if (cleanups.length) throw new Error(`${errorText(primary)}; cleanup: ${cleanups.join("; ")}`);
      throw primary;
    }
    if (cleanups.length) throw new Error(`cleanup: ${cleanups.join("; ")}`);
  }
});

/* RETRIEVAL-02: lexical originals and explicit phonetic query codes. */
suite.test(test, "RETRIEVAL-02", "Multilingual lexical retrieval should work", async () => {
  const fixture = await scenario<{
    texts: { label: string; text: string; queries: string[] }[];
    names: { label: string; name: string; queries: string[] }[];
  }>("RETRIEVAL-02");
  const engine = await EngineFixture.start({ id: "RETRIEVAL-02", profile });
  let primaryFailed: boolean = false;
  let primary: unknown;
  try {
    const at = utc("2026-08-01T00:00:00Z");
    const originals = new Map<string, Awaited<ReturnType<typeof witnessedText>>>();
    for (const row of fixture.texts) originals.set(row.label, await witnessedText(engine, row.text, at));
    const observations = [];
    for (const row of fixture.texts) for (const query of row.queries) {
      const expected = originals.get(row.label)!;
      const found = await awaitPublic(() => engine.client.call("vault.search.bm25", { query, limit: 20 }),
        read => read.value.some(hit => hit.short_id === expected.witnessed.message_short_ids[0] || hit.record?.id === expected.message.id_hex),
        { label: `published lexical text: ${row.label}/${query}` });
      readReceipt(found.narrowing);
      expect(found.value.some(hit => hit.record?.id === originals.get("distractor")!.message.id_hex || hit.short_id === originals.get("distractor")!.witnessed.message_short_ids[0])).toBe(false);
      const hit = found.value.find(hit => hit.short_id === expected.witnessed.message_short_ids[0] || hit.record?.id === expected.message.id_hex)!;
      const citation = await engine.client.call("vault.refs.resolve", { reference: hit.short_id });
      expect(citation.value.record.id).toBe(expected.message.id_hex);
      expect(citation.value.revision).toBeTruthy();
      // LexicalHit.short_id is already pinned as <ref>@<revision>; append no
      // second pin. One identity plus one revision reads the cited original.
      const stored = await engine.client.call("vault.get", { entity_ref: `${citation.value.record.id}@${citation.value.revision!}` });
      expect(stored.value!.body).toEqual(expected.message.body);
      expect(stored.value!.body).toMatchObject({ content: row.text });
      observations.push({ query, found });
    }
    // Cuomo's Japanese reading is クオモ, encoded by the public v1 romaji
    // key; Rupert and Robert share the standard English Soundex R163.
    const codes: Record<string, string[]> = {
      "cross-script": ["romaji:kuomo"], "misheard": ["en:soundex:R163"],
    };
    for (const row of fixture.names) {
      const person = await engine.client.call("vault.people.create", {
        identity: { name: row.name }, identity_evidence_refs: [], occurred_at: at, learned_at: at,
      });
      for (const query of row.queries) {
        const lexical = await engine.client.call("vault.search.bm25", { query, limit: 20 });
        expect(lexical.value.some(hit => hit.record?.id === person.person.id_hex || hit.short_id === person.person.entity_ref)).toBe(false);
        const found = await awaitPublic(() => engine.client.call("vault.search.hybrid", {
          query, phonetic_codes: codes[row.label]!, replay: { now: at, blend_weights: blend }, limit: 20,
        }), read => read.value.some(hit => hit.entity_ref === person.person.id_hex),
        { label: `published phonetic name: ${row.label}` });
        readReceipt(found.narrowing);
        const hit = found.value.find(hit => hit.entity_ref === person.person.id_hex)!;
        expect(hit.components.some(component => component.signal === "phonetic")).toBe(true);
        expect(hit.source_revision_ref).toBeTruthy();
        const stored = await engine.client.call("vault.get", { entity_ref: `${hit.entity_ref}@${hit.source_revision_ref!}` });
        expect(stored.value?.body).toMatchObject({ name: row.name });
        observations.push({ query, found });
      }
    }
    for (const row of fixture.texts) {
      const read = await engine.client.call("vault.get", { entity_ref: originals.get(row.label)!.message.id_hex });
      expect(read.value!.body).toEqual(originals.get(row.label)!.message.body);
    }
    await engine.artifacts.json("retrieval-multilingual.json", observations);
  } catch (error) {
    primaryFailed = true;
    primary = error;
  } finally {
    const cleanups: string[] = [];
    try { await engine.close(); } catch (error) { cleanups.push(errorText(error)); }
    if (primaryFailed) {
      if (cleanups.length) throw new Error(`${errorText(primary)}; cleanup: ${cleanups.join("; ")}`);
      throw primary;
    }
    if (cleanups.length) throw new Error(`cleanup: ${cleanups.join("; ")}`);
  }
});

/* RETRIEVAL-03: real stored dates, independent occurrence/learning axes. */
suite.test(test, "RETRIEVAL-03", "Bitemporal widening should work", async () => {
  const fixture = await scenario<{
    ingestionOrder: string[]; corpus: { label: string; occurredUtc: string; learnedUtc: string }[];
    narrowUtc: string[]; wideningOuterUtc: string[];
    expected: { occurredMatch: string; learnedMatch: string; widenedOccurredMatch: string; maximumAdaptiveRounds: number };
  }>("RETRIEVAL-03");
  const engine = await EngineFixture.start({ id: "RETRIEVAL-03", profile });
  let primaryFailed: boolean = false;
  let primary: unknown;
  try {
    const scope = await ownerBaseClaimScope(engine.client, engine.pairedActor.principalRef);
    const records = new Map<string, Awaited<ReturnType<typeof claim>>>();
    for (const label of fixture.ingestionOrder) {
      const row = fixture.corpus.find(row => row.label === label)!;
      records.set(label, await claim(engine, scope, {
        predicate: `profile.retrieval_temporal_${label.replaceAll("-", "_")}`, value: label,
        occurred_at: utc(row.occurredUtc), learned_at: utc(row.learnedUtc),
      }));
    }
    const narrow = { start: utc(fixture.narrowUtc[0]!), end: utc(fixture.narrowUtc[1]!) };
    const outer = { start: utc(fixture.wideningOuterUtc[0]!), end: utc(fixture.wideningOuterUtc[1]!) };
    const observations: FacadeResult<"vault.search.temporal">[] = [];
    async function search(input: FacadeInput<"vault.search.temporal">, labels: string[]) {
      const read = await engine.client.call("vault.search.temporal", input);
      readReceipt(read.narrowing);
      expect(sorted(read.value.hits.map(hit => hit.entity_ref))).toEqual(sorted(labels.map(label => records.get(label)!.id)));
      for (const hit of read.value.hits) {
        const row = fixture.corpus.find(row => records.get(row.label)!.id === hit.entity_ref)!;
        expect(hit.occurred_start).toBe(utc(row.occurredUtc));
        expect(hit.occurred_end).toBe(utc(row.occurredUtc));
        expect(hit.learned_at).toBe(utc(row.learnedUtc));
        expect(hit.source_revision_ref).toBeTruthy();
      }
      expect(read.value.widening).toBeTruthy();
      expect(read.value.widening!.rounds).toBeLessThanOrEqual(fixture.expected.maximumAdaptiveRounds);
      observations.push(read);
      return read;
    }
    await search({ ...narrow, sigma_secs: 3600, adaptive: false, anchor_mode: "occurred",
      occurred_range: narrow, limit: 10 }, [fixture.expected.occurredMatch]);
    await search({ ...narrow, sigma_secs: 3600, adaptive: false, anchor_mode: "learned",
      learned_range: narrow, limit: 10 }, [fixture.expected.learnedMatch]);
    const learned = { start: utc("2026-08-19T23:00:00Z"), end: utc("2026-08-20T01:00:00Z") };
    await search({ ...narrow, sigma_secs: 3600, adaptive: false, anchor_mode: "both",
      learned_start: learned.start, learned_end: learned.end,
      occurred_range: narrow, learned_range: learned, limit: 10 }, [fixture.expected.occurredMatch]);
    const request: FacadeInput<"vault.search.temporal"> = {
      ...narrow, sigma_secs: 86400, anchor_mode: "occurred", occurred_range: outer, limit: 10,
    };
    // Fixed mode scores Gaussian proximity within its collection window; it
    // does not hard-filter to the anchor. Both in-range candidates are admitted.
    const fixed = await search({ ...request, adaptive: false },
      [fixture.expected.occurredMatch, fixture.expected.widenedOccurredMatch]);
    const widened = await search({ ...request, adaptive: true },
      [fixture.expected.occurredMatch, fixture.expected.widenedOccurredMatch]);
    expect(widened.value.widening!.rounds).toBeGreaterThan(fixed.value.widening!.rounds);
    expect(widened.value.widening!.sigma_secs).toBeGreaterThan(fixed.value.widening!.sigma_secs);
    for (const hit of widened.value.hits) {
      expect(hit.occurred_start).toBeGreaterThanOrEqual(outer.start);
      expect(hit.occurred_end).toBeLessThanOrEqual(outer.end);
    }
    await engine.artifacts.json("retrieval-bitemporal.json", observations);
  } catch (error) {
    primaryFailed = true;
    primary = error;
  } finally {
    const cleanups: string[] = [];
    try { await engine.close(); } catch (error) { cleanups.push(errorText(error)); }
    if (primaryFailed) {
      if (cleanups.length) throw new Error(`${errorText(primary)}; cleanup: ${cleanups.join("; ")}`);
      throw primary;
    }
    if (cleanups.length) throw new Error(`cleanup: ${cleanups.join("; ")}`);
  }
});

/* The stale producer and filtered claim reads exist. They do not provide the
 * complete caller-filter journey across recall/hydrate/neighbors/search. */
suite.skip(test, "RETRIEVAL-04", "waits on caller ReadFilterInput bindings on recall, hydrate, neighbors and every search/read door; demote and list_filtered alone do not cover this ID [FIX 3977; qualif 17779]");

/* RETRIEVAL-05: real reranker traffic and a held public HyDE work item. */
suite.test(test, "RETRIEVAL-05", "Retrieval effort and deadline should work", async () => {
  const fixture = await scenario<{
    efforts: Facade.RecallEffort[]; deadlineMs: number; lateAnswer: string;
    expected: { noRerankerReason: Facade.RerankSkip; lightMediumModelLeases: number };
  }>("RETRIEVAL-05");
  // Unconfigured is a separate fresh vault, not an error hidden by a fallback.
  const plain = await EngineFixture.start({ id: "RETRIEVAL-05-unconfigured", profile });
  let plainPrimaryFailed: boolean = false;
  let plainPrimary: unknown;
  try {
    const rows = await effortCorpus(plain);
    const reader = await recordBoundReader(plain, [plain.pairedActor.principalRef, ...rows.map(row => row.id)]);
    for (const effort of fixture.efforts) {
      const read = await reader.call("vault.recall", {
        query: "retrievaleffortlantern", effort, scope: { kinds: ["CLAIM"] }, limit: 10,
      });
      readReceipt(read.narrowing);
      for (const row of rows) expect(read.items.some(item => item.short_id === row.ref)).toBe(true);
      if (["high", "xhigh", "max"].includes(effort)) {
        expect(read.retrieval_meta.rerank).toEqual({ status: "skipped", reason: fixture.expected.noRerankerReason });
      }
    }
  } catch (error) {
    plainPrimaryFailed = true;
    plainPrimary = error;
  } finally {
    const cleanups: string[] = [];
    try { await plain.close(); } catch (error) { cleanups.push(errorText(error)); }
    if (plainPrimaryFailed) {
      if (cleanups.length) throw new Error(`${errorText(plainPrimary)}; cleanup: ${cleanups.join("; ")}`);
      throw plainPrimary;
    }
    if (cleanups.length) throw new Error(`cleanup: ${cleanups.join("; ")}`);
  }
  const providers = await ScriptedProviders.start({ id: "retrieval-effort",
    steps: [rerankStep("high"), rerankStep("xhigh"), rerankStep("max"), rerankStep("deadline-base")] });
  const engine = await EngineFixture.start({ id: "RETRIEVAL-05", profile,
    initArgs: ["--dimensions", "4"], serverConfig: rerankConfig(providers.urls.reranker!) });
  let primaryFailed: boolean = false;
  let primary: unknown;
  try {
    const rows = await effortCorpus(engine);
    const reader = await recordBoundReader(engine, [engine.pairedActor.principalRef, ...rows.map(row => row.id)]);
    const role = await engine.client.call("vault.models.roles.read", { role: "reranker" });
    expect(role.provider).toBe("retrieval_fixture");
    const observations = [];
    for (const effort of fixture.efforts) {
      const beforeCalls = providers.seenFixtureCalls.length;
      const read = await reader.call("vault.recall", {
        query: "retrievaleffortlantern", effort, scope: { kinds: ["CLAIM"] }, limit: 10,
      });
      readReceipt(read.narrowing);
      expect(sorted(read.items.map(item => item.short_id))).toEqual(sorted(rows.map(row => row.ref)));
      if (effort === "light" || effort === "medium") {
        // No other model role or HyDE host is configured. These reads must
        // make no model call, not merely skip one selected model stage.
        expect(providers.seenFixtureCalls.length - beforeCalls).toBe(fixture.expected.lightMediumModelLeases);
      } else {
        expect(read.retrieval_meta.rerank?.status).toBe("applied");
        if (read.retrieval_meta.rerank?.status !== "applied") throw new Error("Expected applied reranker");
        expect(read.retrieval_meta.rerank.model).toBe("retrieval_fixture:retrieval-reranker");
        expect(read.retrieval_meta.rerank.candidates).toBe(rows.length);
        expect(read.retrieval_meta.rerank.calls).toBeGreaterThan(0);
        expect(providers.seenFixtureCalls.length).toBeGreaterThan(beforeCalls);
      }
      observations.push({ effort, read });
    }
    const binding: FacadeInput<"vault.retrieval.hyde.configure"> = { binding: {
      expander: "retrieval-e2e-host", grounding: { bindings: {} },
      options: { channel_limit: 4, retry_once: false },
    } };
    expect(await engine.client.call("vault.retrieval.hyde.configure", binding)).toEqual(binding);
    expect(await engine.client.call("vault.retrieval.hyde.get", {})).toEqual(binding);
    const beforeClaims = await claimSet(engine);
    const request: FacadeInput<"vault.recall"> = {
      query: "retrievaleffortlantern", effort: "high", scope: { kinds: ["CLAIM"] },
      limit: 10, deadline_ms: fixture.deadlineMs,
    };
    const delivery = reader.request<FacadeResult<"vault.recall">>(
      "POST", "/v1/core/facade/vault.recall", request);
    void delivery.catch(() => {}); // The main await below still propagates transport failure.
    // Observe real work, but do not complete it until after delivery. The
    // engine owns the clock, timeout and pending receipt throughout.
    const work = await awaitPublic(() => reader.call("vault.retrieval.hyde.pending", { limit: 10 }),
      pending => pending.some(row => row.input.stage === "expansion"),
      { label: "public expansion-response-held work item" });
    const held = work.find(row => row.input.stage === "expansion")!;
    if (held.input.stage !== "expansion") throw new Error("Expected expansion work");
    expect(held.input.request.query).toBe(request.query);
    const reply = await delivery;
    readReceipt(reply.body.narrowing);
    expect(reply.body.retrieval_meta.partial).toBe(true);
    expect(sorted(reply.body.items.map(item => item.short_id))).toEqual(sorted(rows.map(row => row.ref)));
    expect(reply.raw).not.toContain(fixture.lateAnswer);
    const bytes = new Uint8Array(reply.bytes);
    const delivered = JSON.stringify(reply.body);
    const completion = await reader.call("vault.retrieval.hyde.complete", {
      request_id: held.request_id, answer: { stage: "expansion", expansion: {
        grounded_query: held.input.request.query, hypothetical_answer: fixture.lateAnswer,
        embedding: [1, 0, 0, 0], subqueries: ["unrelated garden"],
      } },
    });
    expect(completion.status).toBe("discarded_deadline");
    expect(completion.received_bytes).toBeGreaterThan(0);
    expect(completion.completed_at_ms!).toBeGreaterThanOrEqual(completion.deadline_at_ms!);
    expect(await reader.call("vault.retrieval.hyde.receipt", { request_id: held.request_id })).toEqual(completion);
    expect(reply.bytes).toEqual(bytes);
    expect(new TextDecoder().decode(reply.bytes)).toBe(reply.raw);
    expect(JSON.stringify(reply.body)).toBe(delivered);
    expect(await claimSet(engine)).toEqual(beforeClaims);
    await engine.client.call("vault.retrieval.hyde.configure", { binding: null });
    const after = await reader.call("vault.recall", {
      query: "retrievaleffortlantern", effort: "light", scope: { kinds: ["CLAIM"] }, limit: 10,
    });
    expect(sorted(after.items.map(item => item.short_id))).toEqual(sorted(rows.map(row => row.ref)));
    expect(after.items.some(item => item.value_text.includes(fixture.lateAnswer))).toBe(false);
    expect(await claimSet(engine)).toEqual(beforeClaims);
    expect(providers.seenFixtureCalls.every(call => call.role === "reranker" && call.path === "/v1/rerank")).toBe(true);
    await engine.artifacts.json("retrieval-effort-deadline.json", { observations, held, completion, delivered: reply.body,
      providerCalls: providers.seenFixtureCalls });
  } catch (error) {
    primaryFailed = true;
    primary = error;
  } finally {
    const cleanups: string[] = [];
    try { await engine.close(); } catch (error) { cleanups.push(errorText(error)); }
    try { await providers.close(); } catch (error) { cleanups.push(errorText(error)); }
    if (primaryFailed) {
      if (cleanups.length) throw new Error(`${errorText(primary)}; cleanup: ${cleanups.join("; ")}`);
      throw primary;
    }
    if (cleanups.length) throw new Error(`cleanup: ${cleanups.join("; ")}`);
  }
});

/* RETRIEVAL-06 — Evidence abstention not invented recall should work.
 * OF-085/104/090; ARCH-0004 #pre-assembly/#evidence-floors-endpoint.
 * Generic endpoint profile, explicit fixture vectors, no generator/HyDE role.
 * Weak vectors are near-orthogonal to the weak probe. The two strong vectors
 * are almost parallel, so a tiny gap alone must not reject them. Anomalous
 * control bytes/repetition withhold evidence, not saved facts. Empty packs
 * must explain themselves with typed state, never silently look successful.
 */
suite.test(test, "RETRIEVAL-06", "Evidence abstention not invented recall should work", async () => {
  const catalog = await loadFixtures();
  const fixture = await catalog.readJson<EvidenceFixture>("retrieval-evidence");
  const provider = startVectorTable(fixture);
  const engine = await EngineFixture.start({ id: "RETRIEVAL-06", profile,
    initArgs: endpointInitArgs(provider.endpoint),
    embedder: { endpoint: provider.endpoint, modelKey: fixture.embedder.modelKey,
      modelId: fixture.embedder.modelId, dimensions: fixture.embedder.dimensions,
      egress: { allowAll: true } } });
  let primaryFailed: boolean = false;
  let primary: unknown;
  try {
    await engine.requireHttpDoor("/v1/core/context-pack", "POST");
    await engine.requireHttpDoor("/api/search/vector", "GET");
    const scope = await ownerBaseClaimScope(engine.client, engine.pairedActor.principalRef);
    const identities = new Map<string, { id: string; ref: string }>();
    for (const row of fixture.claims) {
      const input: FacadeInput<"vault.claims.upsert"> = {
        scope,
        predicate: row.predicate, subject_ref: engine.pairedActor.principalRef,
        value: row.value, confidence: fixture.confidence,
        source: fixture.expectations.storedSource, salience: fixture.salience,
        occurred_at: fixture.occurredAt, learned_at: fixture.learnedAt,
      };
      const receipt = await engine.client.call("vault.claims.upsert", input);
      expect(receipt.approval).toBe(fixture.expectations.storedApproval);
      await engine.awaitReceipt(receipt.receipt_ref);
      const read = await engine.client.call("vault.hydrate", { refs: [receipt.claim_short_id] });
      expect(read.value).toHaveLength(1);
      const entity = read.value[0]!;
      expect(entity.occurred_start).toBe(fixture.occurredAt);
      expect(entity.occurred_end).toBe(fixture.occurredAt);
      expect(entity.learned_at).toBe(fixture.learnedAt);
      identities.set(row.label, { id: entity.id_hex, ref: receipt.claim_short_id });
    }

    // Observe each row through its own positive public probe. A provider
    // request alone does not prove its fill was admitted/persisted, and weak
    // rows need not survive a different probe's evidence floor.
    for (const row of fixture.claims) {
      const params = new URLSearchParams({ query: row.vector.join(","),
        limit: "1", view: "standard", countMode: "none" });
      const expectedId = identities.get(row.label)!.id;
      await awaitPublic(async () => (await engine.client.request<VectorPage>("GET", `/api/search/vector?${params}`)).body,
        page => page.items.some(hit => hit.id === expectedId),
        { label: `fixture embedding visible through public vector search: ${row.label} id ${expectedId}` });
      expect(provider.seen.has(row.value)).toBe(true);
    }
    const filter: FacadeInput<"vault.claims.list"> = { subject_ref: engine.pairedActor.principalRef, limit: 1000 };
    const before = await engine.client.call("vault.claims.list", filter);
    for (const row of fixture.claims) {
      const matching = before.value.filter(claim => claim.predicate === row.predicate);
      expect(matching).toHaveLength(1);
      expect(matching[0]).toMatchObject({ value: row.value, confidence: fixture.confidence,
        source: fixture.expectations.storedSource, approval: fixture.expectations.storedApproval,
        lifecycle: fixture.expectations.storedLifecycle, stale: fixture.expectations.storedStale });
    }

    const requestPack = async (probe: Probe): Promise<ContextPackReply> => {
      const request: ContextPackRequest = { query: probe.query, query_vector: probe.vector,
        limit: fixture.constants.resultLimit, edge_hop: 0, view: "full",
        budget: { token_budget: fixture.constants.tokenBudget } };
      return (await engine.client.request<ContextPackReply>("POST", "/v1/core/context-pack", request)).body;
    };
    const observed: { label: string; state: ContextPackReply["state"]; ids: string[] }[] = [];
    // G8 safe R06 failure ids: expected empty only for weak/anomalous. Any
    // non-empty results here (fixture or background ids) fail immediately via
    // the empty expects below; background cannot silently satisfy them.
    for (const probe of [{ ...fixture.weak, label: "weak-no-keywords" }, ...fixture.anomalous]) {
      // A positive weak-evidence check needs to prove the lexical channel
      // cannot rescue it; a bare empty-vault or vector-only query is not it.
      const keywords = await engine.client.call("vault.search.bm25", { query: probe.query, limit: 10 });
      expect(keywords.value).toEqual([]);
      const pack = await requestPack(probe);
      expect(pack.results).toEqual([]);
      expect(pack.neighbors).toEqual([]);
      expect(["missing_data", "low_confidence"]).toContain(pack.state.kind);
      expect(typeof pack.state.reason).toBe("string");
      expect(pack.state.reason!.length).toBeGreaterThan(0);
      expect(pack.evidence.result_ids).toEqual([]);
      expect(pack.evidence.scores).toEqual([]);
      observed.push({ label: probe.label, state: pack.state, ids: [] });
    }
    const strongKeywords = await engine.client.call("vault.search.bm25", { query: fixture.strong.query, limit: 10 });
    expect(strongKeywords.value).toEqual([]);
    // G8 safe strong failure: any missing required id or any non-fixture id
    // in strong results fails immediately below; background ids would fail
    // the every-hit check loudly, not hide a missing record. No oracle change.
    const strong = await requestPack(fixture.strong);
    expect(strong.state.kind).toBe("ok");
    const requiredIds = fixture.strong.requiredLabels.map(label => identities.get(label)!.id).sort();
    expect(strong.results.slice(0, requiredIds.length).map(row => row.id).sort()).toEqual(requiredIds);
    expect(strong.results.every(hit => [...identities.values()].some(row => row.id === hit.id))).toBe(true);
    observed.push({ label: "strong-near-tie", state: strong.state, ids: strong.results.map(row => row.id) });

    // Independent expected bodies above, plus the read-only invariant over
    // all owner claims, including any bootstrap rows (not just these four).
    const after = await engine.client.call("vault.claims.list", filter);
    const byRef = (a: ClaimRow, b: ClaimRow) => a.claim_ref.localeCompare(b.claim_ref);
    expect([...after.value].sort(byRef)).toEqual([...before.value].sort(byRef));
    for (const row of fixture.claims) {
      const read = await engine.client.call("vault.hydrate", { refs: [identities.get(row.label)!.ref] });
      expect(read.value).toHaveLength(1);
      expect(read.value[0]).toMatchObject({ occurred_start: fixture.occurredAt,
        occurred_end: fixture.occurredAt, learned_at: fixture.learnedAt });
    }
    await engine.artifacts.json("retrieval-evidence.json", { fixtureId: "retrieval-evidence", observed });
  } catch (error) {
    primaryFailed = true;
    primary = error;
  } finally {
    const cleanups: string[] = [];
    try { await engine.close(); } catch (error) { cleanups.push(errorText(error)); }
    try { await provider.close(); } catch (error) { cleanups.push(errorText(error)); }
    if (primaryFailed) {
      if (cleanups.length) throw new Error(`${errorText(primary)}; cleanup: ${cleanups.join("; ")}`);
      throw primary;
    }
    if (cleanups.length) throw new Error(`cleanup: ${cleanups.join("; ")}`);
  }
});

/* RETRIEVAL-07: class-level read-side aging, not confidence rewriting. */
suite.test(test, "RETRIEVAL-07", "Freshness does not rewrite confidence should work", async () => {
  const fixture = await scenario<{
    confidence: number; classes: string[]; oldUtc: string; newUtc: string; timeAnchorsUtc: string[];
    oldValue: string; newValue: string;
  }>("RETRIEVAL-07");
  const engine = await EngineFixture.start({ id: "RETRIEVAL-07", profile });
  let primaryFailed: boolean = false;
  let primary: unknown;
  try {
    const current = await engine.client.call("vault.retrieval.aging.get", {});
    const profiles: Facade.ClaimAgingProfiles = {
      durable: { half_life_secs: 365 * 86400, floor: 0.0001 },
      standard: { half_life_secs: 90 * 86400, floor: 0.0001 },
      ephemeral: { half_life_secs: 14 * 86400, floor: 0.0001 },
    };
    const configured = await engine.client.call("vault.retrieval.aging.configure", {
      expected_body_hash: current.body_hash, profiles,
    });
    await engine.awaitReceipt(configured.receipt_ref);
    // G-PRECISION (FIX21914): f32-backed floors compare with tight tolerance;
    // profile keys and integer half-lives stay exact.
    const readback = (await engine.client.call("vault.retrieval.aging.get", {})).profiles;
    expect(Object.keys(readback).sort()).toEqual(Object.keys(profiles).sort());
    for (const key of Object.keys(profiles) as (keyof typeof profiles)[]) {
      expect(readback[key]!.half_life_secs).toBe(profiles[key]!.half_life_secs);
      expect(readback[key]!.floor).toBeCloseTo(0.0001, 10);
    }
    const scope = await ownerBaseClaimScope(engine.client, engine.pairedActor.principalRef);
    const records = new Map<string, Awaited<ReturnType<typeof claim>>>();
    // Memory classes are not writable top-level kind strings. These ordinary
    // roots bind the fixture's semantic and working facts to standard and
    // ephemeral aging without manufacturing a memoryClass body field.
    const roots: Record<string, string> = { semantic: "profile", working: "status" };
    for (const kind of fixture.classes) for (const age of ["old", "new"] as const) {
      const at = utc(age === "old" ? fixture.oldUtc : fixture.newUtc);
      records.set(`${kind}-${age}`, await claim(engine, scope, {
        predicate: `${roots[kind]!}.retrieval_aging_${kind}_${age}`,
        value: age === "old" ? fixture.oldValue : fixture.newValue, confidence: fixture.confidence,
        occurred_at: at, learned_at: at, salience: 0.5,
      }));
    }
    const before = await claimSet(engine);
    const observations = [];
    const factors = new Map<string, number[]>();
    for (const anchor of fixture.timeAnchorsUtc) {
      const input: FacadeInput<"vault.search.hybrid"> = {
        query: "field kit locker", replay: { now: utc(anchor), blend_weights: blend }, limit: 20,
      };
      const read = await engine.client.call("vault.search.hybrid", input);
      readReceipt(read.narrowing);
      const again = await engine.client.call("vault.search.hybrid", input);
      expect(again.value.map(hit => hit.entity_ref)).toEqual(read.value.map(hit => hit.entity_ref));
      for (const [label, record] of records) {
        const hit = read.value.find(hit => hit.entity_ref === record.id);
        expect(hit).toBeDefined();
        expect(typeof hit!.access_factor).toBe("number");
        expect(hit!.access_factor!).toBeGreaterThan(0);
        expect(hit!.access_factor!).toBeLessThanOrEqual(1);
        factors.set(label, [...(factors.get(label) ?? []), hit!.access_factor!]);
      }
      expect(await claimSet(engine)).toEqual(before);
      observations.push({ anchor, read });
    }
    for (const values of factors.values()) expect(values[1]!).toBeLessThanOrEqual(values[0]!);
    expect(factors.get("semantic-new")![1]!).toBeGreaterThan(factors.get("working-new")![1]!);
    expect(factors.get("semantic-new")![0]!).toBeGreaterThan(factors.get("semantic-old")![0]!);
    const original = records.get("semantic-old")!;
    const replacement = await claim(engine, scope, {
      predicate: "profile.retrieval_aging_semantic_old", value: fixture.newValue,
      confidence: fixture.confidence, occurred_at: utc(fixture.newUtc), learned_at: utc(fixture.newUtc), salience: 0.5,
    });
    expect(replacement.receipt.superseded_short_id).toBe(original.ref);
    const present = await engine.client.call("vault.search.hybrid", {
      query: "field kit locker", replay: { now: utc(fixture.timeAnchorsUtc[1]!), blend_weights: blend }, limit: 20,
    });
    expect(present.value.some(hit => hit.entity_ref === original.id)).toBe(false);
    expect(present.value.some(hit => hit.entity_ref === replacement.id)).toBe(true);
    const history = await engine.client.call("vault.claims.history", { claim_ref: replacement.ref });
    readReceipt(history.narrowing);
    const old = history.value.find(row => row.claim_ref === original.id || row.short_ref === original.ref);
    const newest = history.value.find(row => row.claim_ref === replacement.id || row.short_ref === replacement.ref);
    expect(old).toMatchObject({ value: fixture.oldValue, confidence: fixture.confidence, lifecycle: "superseded" });
    expect(newest).toMatchObject({ value: fixture.newValue, confidence: fixture.confidence, lifecycle: "active" });
    for (const row of history.value) expect(row.confidence).toBe(fixture.confidence);
    await engine.artifacts.json("retrieval-aging.json", { configured, observations, factors: Object.fromEntries(factors), present, history });
  } catch (error) {
    primaryFailed = true;
    primary = error;
  } finally {
    const cleanups: string[] = [];
    try { await engine.close(); } catch (error) { cleanups.push(errorText(error)); }
    if (primaryFailed) {
      if (cleanups.length) throw new Error(`${errorText(primary)}; cleanup: ${cleanups.join("; ")}`);
      throw primary;
    }
    if (cleanups.length) throw new Error(`cleanup: ${cleanups.join("; ")}`);
  }
});

/* RETRIEVAL-08: the real journaled rerank wait permits in-process SLIM. */
suite.test(test, "RETRIEVAL-08", "Warm and rebuilt graph parity should work", async () => {
  const fixture = await scenario<{
    seed: string; allowedNeighborhood: string[]; privateNode: string;
    edges: { from: string; kind: string; to: string }[];
  }>("RETRIEVAL-08");
  const providers = await ScriptedProviders.start({ id: "retrieval-slim", steps: [rerankStep("slim-wait", "journaled-rerank-held")] });
  const engine = await EngineFixture.start({ id: "RETRIEVAL-08", profile, serverConfig: rerankConfig(providers.urls.reranker!) });
  let pending: Promise<FacadeResult<"vault.recall">> | undefined;
  let primaryFailed: boolean = false;
  let primary: unknown;
  try {
    const rows = await effortCorpus(engine);
    const at = utc("2026-08-01T00:00:00Z");
    const records = new Map<string, Facade.EntityRefReceipt>();
    // The fixture is a DAG. Create each real target before its parent.
    for (const label of [fixture.privateNode, ...[...fixture.allowedNeighborhood].reverse()]) {
      const edges = fixture.edges.filter(edge => edge.from === label).map(edge => ({
        edge_kind: edge.kind, target_ref: records.get(edge.to)!.entity_ref,
      }));
      records.set(label, await task(engine, `retrieval graph ${label}`, at, edges));
    }
    const reader = await recordBoundReader(engine, fixture.allowedNeighborhood.map(label => records.get(label)!.id_hex));
    const withheld = records.get(fixture.privateNode)!;
    expect((await engine.client.call("vault.get", { entity_ref: withheld.entity_ref })).value).not.toBeNull();
    expect((await reader.call("vault.get", { entity_ref: withheld.entity_ref })).value).toBeNull();
    const input: FacadeInput<"vault.search.hybrid"> = {
      ppr: { seeds: [records.get(fixture.seed)!.entity_ref], depth: 3 },
      replay: { now: at, blend_weights: blend }, limit: 20,
    };
    const observe = async () => {
      const read = await reader.call("vault.search.hybrid", input);
      readReceipt(read.narrowing);
      expect(sorted(read.value.map(hit => hit.entity_ref))).toEqual(sorted(fixture.allowedNeighborhood.map(label => records.get(label)!.id_hex)));
      expect(JSON.stringify(read.value)).not.toContain(withheld.id_hex);
      expect(JSON.stringify(read.value)).not.toContain(withheld.entity_ref);
      return read;
    };
    const semantics = (read: FacadeResult<"vault.search.hybrid">) => read.value.map(hit => ({
      id: hit.entity_ref, revision: hit.source_revision_ref,
      signals: sorted(hit.components.map(component => component.signal)),
    }));
    const cold = await observe();
    const warm = await observe();
    expect(semantics(warm)).toEqual(semantics(cold));
    const before = await engine.client.call("vault.slim.state", {});
    expect(before.state.residency).toBe("full");
    // This public recall creates its own run, lease and model checkpoint.
    // A provider barrier proves the outbound call exists. No run id, lease,
    // outbound intent or elapsed wait is fabricated for the drop request.
    const recallReader = await recordBoundReader(engine, [engine.pairedActor.principalRef, ...rows.map(row => row.id)]);
    pending = recallReader.call("vault.recall", {
      query: "retrievaleffortlantern", effort: "high", scope: { kinds: ["CLAIM"] }, limit: 10,
    });
    void pending.catch(() => {}); // Still awaited and asserted after releasing the barrier.
    await providers.awaitBarrier("journaled-rerank-held");
    // G-SLIM-WAIT (FIX21914): observe a full positive second while the real
    // provider barrier remains held, using the normal bounded wait. The
    // measured whole seconds are passed; never a fabricated 1.
    const slimWaitStarted = Date.now();
    await awaitPublic(async () => Date.now() - slimWaitStarted,
      elapsed => elapsed >= 1000,
      { label: "observed positive barrier-held wait" });
    const waitedSecs = Math.floor((Date.now() - slimWaitStarted) / 1000);
    expect(waitedSecs).toBeGreaterThanOrEqual(1);
    const dropped = await engine.cli.call("vault.slim.drop_heavy", { cause: "memory_pressure", waited_secs: waitedSecs });
    expect(dropped.process_id).toBe(before.process_id);
    expect(dropped.outcome.status).toBe("entered");
    if (dropped.outcome.status !== "entered") throw new Error("Expected a completed in-process SLIM transition");
    const slim = await engine.client.call("vault.slim.state", {});
    expect(slim.process_id).toBe(before.process_id);
    expect(slim.state.residency).toBe("slim");
    if (slim.state.residency !== "slim") throw new Error("Expected SLIM state");
    expect(slim.state.residue.step).toEqual(dropped.outcome.residue.step);
    const step = slim.state.residue.step;
    expect(step.kind).toBe("model");
    if (step.kind !== "model") throw new Error("Expected the held rerank model checkpoint");
    const saved = await engine.client.call("vault.slim.resume_step", {
      kind: "model", attempt_id: step.attempt_id, step_hash: step.step_hash,
    });
    expect(saved.kind).toBe("model");
    const resumed = await engine.cli.call("vault.slim.resume", {});
    expect(resumed.process_id).toBe(before.process_id);
    expect(resumed.outcome.status).toBe("resumed");
    const rebuilt = await observe();
    const rewarm = await observe();
    expect(semantics(rebuilt)).toEqual(semantics(cold));
    expect(semantics(rewarm)).toEqual(semantics(cold));
    const full = await engine.client.call("vault.slim.state", {});
    expect(full).toEqual(before);
    expect(providers.seenFixtureCalls).toHaveLength(1);
    providers.releaseBarrier("journaled-rerank-held");
    const delivered = await pending;
    expect(sorted(delivered.items.map(item => item.short_id))).toEqual(sorted(rows.map(row => row.ref)));
    expect(providers.seenFixtureCalls).toHaveLength(1);
    await engine.artifacts.json("retrieval-slim-parity.json", { cold, warm, before, dropped, slim, saved, resumed, rebuilt, rewarm, full });
  } catch (error) {
    primaryFailed = true;
    primary = error;
  } finally {
    providers.releaseBarrier("journaled-rerank-held");
    // Settle the owned request before stopping its server on assertion failure.
    await pending?.catch(() => {});
    const cleanups: string[] = [];
    try { await engine.close(); } catch (error) { cleanups.push(errorText(error)); }
    try { await providers.close(); } catch (error) { cleanups.push(errorText(error)); }
    if (primaryFailed) {
      if (cleanups.length) throw new Error(`${errorText(primary)}; cleanup: ${cleanups.join("; ")}`);
      throw primary;
    }
    if (cleanups.length) throw new Error(`cleanup: ${cleanups.join("; ")}`);
  }
});

/* RETRIEVAL-09: authored TURN self-reports, optional priors, real read ceiling. */
suite.test(test, "RETRIEVAL-09", "Optional affect and community priors should work", async () => {
  const fixture = await scenario<{
    rows: { label: string; vad?: Facade.QueryAffect; confidence: number }[];
    queryAffect: Facade.QueryAffect;
  }>("RETRIEVAL-09");
  const engine = await EngineFixture.start({ id: "RETRIEVAL-09", profile });
  let primaryFailed: boolean = false;
  let primary: unknown;
  try {
    const zero: Facade.RetrievalWeights = { affect: 0, arousal: 0, community: 0, vad: 0 };
    expect((await engine.client.call("vault.retrieval.weights.get", {})).weights).toEqual(zero);
    const scope = await ownerBaseClaimScope(engine.client, engine.pairedActor.principalRef);
    const at = utc("2026-08-01T00:00:00Z");
    const records = new Map<string, Awaited<ReturnType<typeof claim>>>();
    const allowed = [engine.pairedActor.principalRef, scope.world_id, scope.scope_facet_id, scope.scope_project_id];
    for (const [index, row] of fixture.rows.entries()) {
      let evidence: string[] = [];
      if (row.vad) {
        const turn = await witnessedText(engine, `retrievalpriors ${row.label} self-report`, at);
        const annotation = await engine.client.call("vault.affect.annotations.put", {
          turn_ref: turn.witnessed.turn_short_id, vad: row.vad,
          source: "user_self_report", annotated_at: at, scope,
        });
        await engine.awaitReceipt(annotation.receipt_ref);
        evidence = [turn.witnessed.turn_short_id];
        const hydrated = await engine.client.call("vault.hydrate", {
          refs: [turn.witnessed.turn_short_id, annotation.claim_short_id],
        });
        allowed.push(turn.conversation.id, turn.message.id_hex, ...hydrated.value.map(entity => entity.id_hex));
      }
      const saved = await claim(engine, scope, {
        predicate: `profile.retrieval_priors_${index}`, value: `retrievalpriors ${row.label}`,
        confidence: row.confidence, evidence_turn_refs: evidence, occurred_at: at, learned_at: at,
      });
      records.set(row.label, saved);
      if (row.label !== "private-community") allowed.push(saved.id);
      if (row.vad) {
        const consolidated = await engine.client.call("vault.affect.claims.consolidate", { claim_ref: saved.ref });
        // G-PRECISION (FIX21914): f32 VAD coordinates compare with tight tolerance.
        expect(consolidated.vad.valence).toBeCloseTo(row.vad.valence, 7);
        expect(consolidated.vad.arousal).toBeCloseTo(row.vad.arousal, 7);
        expect(consolidated.vad.dominance).toBeCloseTo(row.vad.dominance, 7);
        expect(consolidated.evidence_turns.length).toBeGreaterThan(0);
      }
    }
    // A dense, publicly written task neighborhood supplies the community
    // candidate. No community id, snapshot, membership or model tag is seeded.
    const hubs: Facade.EntityRefReceipt[] = [];
    for (let index = 0; index < 5; index++) {
      const hub = await task(engine, `retrievalpriors neighborhood ${index}`, at, [
        { edge_kind: "about", target_ref: records.get("community-neighbor")!.ref },
        ...hubs.map(other => ({ edge_kind: "about", target_ref: other.entity_ref })),
      ]);
      hubs.push(hub); allowed.push(hub.id_hex);
    }
    const reader = await recordBoundReader(engine, allowed);
    const privateRow = records.get("private-community")!;
    expect((await reader.call("vault.get", { entity_ref: privateRow.ref })).value).toBeNull();
    const before = await claimSet(engine);
    const snapshots: {
      pack: FacadeResult<"vault.recall">; evidence: FacadeResult<"vault.retrieval.run">;
      intenseDelta: number; communityDelta: number;
    }[] = [];
    async function read() {
      const pack = await reader.call("vault.recall", {
        query: "retrievalpriors", effort: "medium", limit: 50,
        query_affect: fixture.queryAffect, telemetry: { capture_trace: true },
      });
      readReceipt(pack.narrowing);
      for (const label of ["calm", "intense", "community-neighbor"]) {
        expect(pack.items.some(item => item.short_id === records.get(label)!.ref)).toBe(true);
      }
      expect(pack.items.some(item => item.short_id === privateRow.ref)).toBe(false);
      expect(JSON.stringify(pack.items)).not.toContain("private-community");
      expect(pack.retrieval_run_id).toBeTruthy();
      const evidence = await engine.client.call("vault.retrieval.run", { run_id: pack.retrieval_run_id! });
      expect(evidence).not.toBeNull();
      expect(evidence!.run.trace).toBeTruthy();
      const score = (label: string) => {
        const hit = evidence!.run.score_breakdown.find(hit => Buffer.from(hit.result_id).toString("hex") === records.get(label)!.id);
        expect(hit).toBeDefined();
        return hit!.final_score;
      };
      const snapshot = { pack, evidence, intenseDelta: score("intense") - score("calm"),
        communityDelta: score("community-neighbor") - score("calm") };
      snapshots.push(snapshot);
      return snapshot;
    }
    async function configure(weights: Facade.RetrievalWeights) {
      const current = await engine.client.call("vault.retrieval.weights.get", {});
      const receipt = await engine.client.call("vault.retrieval.weights.configure", {
        expected_body_hash: current.body_hash, weights,
      });
      await engine.awaitReceipt(receipt.receipt_ref);
      expect((await engine.client.call("vault.retrieval.weights.get", {})).weights).toEqual(weights);
    }
    const baseline = await read();
    const rowOrder = (snapshot: Awaited<ReturnType<typeof read>>) => snapshot.pack.items
      .map(item => item.short_id).filter(ref => [...records.values()].some(row => row.ref === ref));
    for (const [axis, value, favored] of [
      ["affect", 0.4, "intense"], ["arousal", 4, "intense"], ["community", 0.25, "community-neighbor"],
    ] as const) {
      await configure({ ...zero, [axis]: value });
      const enabled = await read();
      const refs = rowOrder(enabled);
      expect(refs.indexOf(records.get(favored)!.ref)).toBeLessThan(refs.indexOf(records.get("calm")!.ref));
      if (axis === "community") expect(enabled.communityDelta).toBeGreaterThan(baseline.communityDelta);
      else expect(enabled.intenseDelta).toBeGreaterThan(baseline.intenseDelta);
      expect(await claimSet(engine)).toEqual(before);
      await configure(zero);
      const off = await read();
      expect(rowOrder(off)).toEqual(rowOrder(baseline));
      expect(await claimSet(engine)).toEqual(before);
    }
    for (const row of fixture.rows) {
      const stored = (await engine.client.call("vault.claims.list", { subject_ref: engine.pairedActor.principalRef, limit: 1000 }))
        .value.find(claim => claim.short_ref === records.get(row.label)!.ref || claim.claim_ref === records.get(row.label)!.id)!;
      expect(stored.confidence).toBe(row.confidence);
      expect(stored.approval).toBe(records.get(row.label)!.receipt.approval);
    }
    await engine.artifacts.json("retrieval-optional-priors.json", snapshots);
  } catch (error) {
    primaryFailed = true;
    primary = error;
  } finally {
    const cleanups: string[] = [];
    try { await engine.close(); } catch (error) { cleanups.push(errorText(error)); }
    if (primaryFailed) {
      if (cleanups.length) throw new Error(`${errorText(primary)}; cleanup: ${cleanups.join("; ")}`);
      throw primary;
    }
    if (cleanups.length) throw new Error(`cleanup: ${cleanups.join("; ")}`);
  }
});

type ClusterVerb = "vault.cluster" | "vault.cluster.propose" | "vault.cluster.proposal" | "vault.cluster.resolve_proposal";
// The tool-first envelope is the advertised schema: schema_version bound from
// tools/list, consent, and the verb input nested under arguments.spec. A bare
// top-level spec is refused as tool_args_invalid.
async function clusterTool<V extends ClusterVerb>(engine: EngineFixture, verb: V, input: FacadeInput<V>): Promise<FacadeResult<V>> {
  const listed = await engine.mcp.request<{ tools: {
    name: string; inputSchema: { properties: { schema_version: { const: string } } };
  }[] }>("tools/list");
  const tool = listed.tools.find(item => item.name === verb);
  if (!tool) throw new Error(`Required public MCP tool not registered: ${verb}`);
  const reply = await engine.mcp.callTool(verb, {
    schema_version: tool.inputSchema.properties.schema_version.const,
    consent: { policy_ref: "policy:retrieval-session", purpose: "retrieval clustering journey" },
    arguments: { spec: input },
  }) as { isError: boolean; structuredContent: { tool: string; output: FacadeResult<V> } };
  expect(reply.isError).toBe(false);
  expect(reply.structuredContent.tool).toBe(verb);
  return reply.structuredContent.output;
}

/* RETRIEVAL-10: MCP cohorts, rejected judgments, then receipted merge/split. */
suite.test(test, "RETRIEVAL-10", "Clustering produces proposals not truth should work", async () => {
  const fixture = await scenario<{
    clusters: Record<string, string[]>; ambiguousBridge: string;
  }>("RETRIEVAL-10");
  const engine = await EngineFixture.start({ id: "RETRIEVAL-10", profile, surface: "tool-first" });
  let primaryFailed: boolean = false;
  let primary: unknown;
  try {
    await engine.mcp.initialize();
    const listed = await engine.mcp.request<{ tools: { name: string }[] }>("tools/list");
    for (const verb of ["vault.cluster", "vault.cluster.propose", "vault.cluster.proposal", "vault.cluster.resolve_proposal"]) {
      expect(listed.tools.some(tool => tool.name === verb)).toBe(true);
    }
    const scope = await ownerBaseClaimScope(engine.client, engine.pairedActor.principalRef);
    const records = new Map<string, Awaited<ReturnType<typeof claim>>>();
    const vectors: Record<string, number[]> = {
      slate: [1, 0, 0, 0], shingle: [1, 0.01, 0, 0],
      lens: [0, 1, 0, 0], mirror: [0.01, 1, 0, 0],
      [fixture.ambiguousBridge]: [1, 1, 0, 0],
    };
    const labels = [...Object.values(fixture.clusters).flat(), fixture.ambiguousBridge];
    for (const [index, label] of labels.entries()) records.set(label, await claim(engine, scope, {
      predicate: `profile.retrieval_cluster_${index}`, value: label,
      occurred_at: utc("2026-08-01T00:00:00Z"), learned_at: utc("2026-08-01T00:00:00Z"),
    }));
    const before = await claimSet(engine);
    const proposed = await clusterTool(engine, "vault.cluster", {
      claims: labels.map(label => ({ claim_ref: records.get(label)!.ref, embedding: vectors[label]! })),
      cohesion_threshold: 0.9,
    });
    readReceipt(proposed.narrowing);
    const memberships = proposed.value.cohorts.map(cohort => sorted(cohort.member_refs)).sort((a, b) => a.join().localeCompare(b.join()));
    const expected = [...Object.values(fixture.clusters), [fixture.ambiguousBridge]]
      .map(group => sorted(group.map(label => records.get(label)!.ref))).sort((a, b) => a.join().localeCompare(b.join()));
    expect(memberships).toEqual(expected);
    for (const cohort of proposed.value.cohorts) {
      expect(cohort.partition.predicate_root).toBe("profile");
      const subject = await engine.client.call("vault.get", { entity_ref: cohort.partition.subject_ref });
      expect(subject.value?.id_hex).toBe(engine.pairedActor.principalRef);
      // G-CLUSTER-BASE (FIX21914): null is the documented base cohort; the
      // reserved base id is a scope member, never an entity row, so no vault.get.
      expect(cohort.partition.world_ref).toBeNull();
      expect(cohort.partition.facet_ref).toBeTruthy();
      const facet = await engine.client.call("vault.get", { entity_ref: cohort.partition.facet_ref! });
      expect(facet.value?.id_hex).toBe(scope.scope_facet_id);
      expect(cohort.cohesion).toBeGreaterThanOrEqual(0.9);
    }
    expect(await claimSet(engine)).toEqual(before);
    // Real structural task records are topology participants, not forged
    // actors or raw claims. The owner judges a task-identity grouping.
    const at = utc("2026-08-01T00:00:00Z");
    const source = await task(engine, "Glass roof panel inspection", at);
    const survivor = await task(engine, "Glass roof panel inspection master", at);
    const roofHead = await task(engine, "Roof inspection task", at);
    const opticsHead = await task(engine, "Optics inspection task", at);
    const graphInput: FacadeInput<"vault.search.hybrid"> = {
      ppr: { seeds: [source.entity_ref], depth: 3 }, replay: { now: at, blend_weights: blend }, limit: 20,
    };
    const graph = async () => (await engine.client.call("vault.search.hybrid", graphInput)).value.map(hit => hit.entity_ref);
    const originalRecall = await graph();
    expect(originalRecall).toContain(source.id_hex);
    expect(originalRecall).not.toContain(survivor.id_hex);
    const merge: Facade.ClusterOperation = { kind: "merge", sources: [source.entity_ref], survivor: survivor.entity_ref,
      survivorship_plan: "read_through", evidence: { refs: labels.map(label => records.get(label)!.ref),
        rationale: "Owner judges the inspection records to describe one task; cohorts alone decided nothing." } };
    const parked = await clusterTool(engine, "vault.cluster.propose", { operation: merge });
    expect(parked.outcome).toBe("proposed");
    expect(parked.proposal_ref).toBeTruthy();
    expect(await graph()).toEqual(originalRecall);
    const inspected = await clusterTool(engine, "vault.cluster.proposal", { proposal_ref: parked.proposal_ref! });
    const refused = await clusterTool(engine, "vault.cluster.resolve_proposal", {
      proposal_ref: inspected.value.proposal_ref, seen: inspected.value.seen, ruling: { verdict: "reject" },
    });
    expect(refused.outcome).toBe("rejected");
    expect(refused.receipt_ref).toBeTruthy();
    expect(await graph()).toEqual(originalRecall);
    expect(await claimSet(engine)).toEqual(before);
    const parkedAgain = await clusterTool(engine, "vault.cluster.propose", { operation: merge });
    const seenAgain = await clusterTool(engine, "vault.cluster.proposal", { proposal_ref: parkedAgain.proposal_ref! });
    const accepted = await clusterTool(engine, "vault.cluster.resolve_proposal", {
      proposal_ref: seenAgain.value.proposal_ref, seen: seenAgain.value.seen, ruling: { verdict: "approve" },
    });
    expect(accepted.outcome).toBe("approved_untouched");
    expect(accepted.receipt_ref).toBeTruthy();
    const mergedRecall = await graph();
    expect(mergedRecall).toContain(survivor.id_hex);
    const redirect = await engine.client.call("vault.neighbors", { entity_ref: source.entity_ref, opts: { edge_kind: "merged_into", limit: 10 } });
    expect(redirect.value.some(row => row.record?.id === survivor.id_hex || row.short_id === survivor.entity_ref)).toBe(true);
    const split: Facade.ClusterOperation = { kind: "split", entity: survivor.entity_ref,
      heads: [roofHead.entity_ref, opticsHead.entity_ref], reassignment_map: [],
      evidence: { refs: [records.get(fixture.ambiguousBridge)!.ref], rationale: "Owner separates roof and optics inspection tasks." } };
    const parkedSplit = await clusterTool(engine, "vault.cluster.propose", { operation: split });
    expect(await graph()).toEqual(mergedRecall);
    const splitView = await clusterTool(engine, "vault.cluster.proposal", { proposal_ref: parkedSplit.proposal_ref! });
    const acceptedSplit = await clusterTool(engine, "vault.cluster.resolve_proposal", {
      proposal_ref: splitView.value.proposal_ref, seen: splitView.value.seen, ruling: { verdict: "approve" },
    });
    expect(acceptedSplit.outcome).toBe("approved_untouched");
    expect(acceptedSplit.receipt_ref).toBeTruthy();
    const splitRecall = await graph();
    expect(splitRecall).toContain(roofHead.id_hex);
    expect(splitRecall).toContain(opticsHead.id_hex);
    // Ledger judgments may add their own typed events. None may mint, vet,
    // change or move the original semantic facts as a cosine side effect.
    const after = await claimSet(engine);
    for (const row of before) expect(after.find(other => other.claim_ref === row.claim_ref)).toEqual(row);
    await engine.artifacts.json("retrieval-clustering.json", { proposed, parked, refused, accepted, acceptedSplit,
      originalRecall, mergedRecall, splitRecall });
  } catch (error) {
    primaryFailed = true;
    primary = error;
  } finally {
    const cleanups: string[] = [];
    try { await engine.close(); } catch (error) { cleanups.push(errorText(error)); }
    if (primaryFailed) {
      if (cleanups.length) throw new Error(`${errorText(primary)}; cleanup: ${cleanups.join("; ")}`);
      throw primary;
    }
    if (cleanups.length) throw new Error(`cleanup: ${cleanups.join("; ")}`);
  }
});

/* RETRIEVAL-11: evidence inspection and vetting exist; the complete
 * Generated/Auto + pending-critical production producers are still owed.
 * Engine 2026-11-07 07:12 JST confirms agents.spawn -> genuine agent holder
 * pairing -> agents.spawn.get leased -> self.run.attach. That composition is
 * built; this is not a request for another lease/registration API.
 * The fixture must retain the actual caller-owned lease for its production
 * writes. Attach consumes that state; a queue receipt alone does not grant
 * the paired human owner an agent's run. Deterministic fixture timing and
 * host-stamped producer setup remain to be qualified, not forged or inferred
 * from an evidence read. No source:"generated" upsert or fabricated run is
 * a positive control. Keep the complete original pending-critical oracle.
 */
suite.skip(test, "RETRIEVAL-11", "waits on merged complete production Generated/Auto and pending-critical producers and qualification of the genuine caller-owned leased-run fixture; spawn/agent-pair/leased-get/attach composition exists, while evidence inspection is not a producer [FIX 3983]");

/* RETRIEVAL-12 replacement section. Drop-in for retrieval.test.ts: delete the
 * RETRIEVAL-12 suite.todo block and paste this whole section in its place.
 * Uses existing helpers only (scenario, utc, readReceipt,
 * task, endpointInitArgs, startVectorTable, EvidenceFixture, profile, suite);
 * the r12*-named additions below are new and collide with nothing.
 * Requires the EngineOptions.fastDims support edit from retrieval12-setup.md
 * (root applies): until then `fastDims` below does not type-check. Source-only
 * proposal; not executed or type-checked on this Mac.
 *
 * Two sequential fresh endpoint-backed vaults, one lane each, each with
 * independently authored vector geometry. Separation is deliberate: each
 * vault's corpus is authored for its lane, so no row or ranking leaks across
 * lanes. Shape {dimensions 4, fast_dims 2} is fixed at each vault's first
 * open and read back through vault.search.vector.config in-test.
 * No speed claim anywhere (scenario millionRowSpeedClaim is false).
 */
interface R12Scenario {
  readonly dimensions: number; readonly fastDims: number;
  readonly query: number[];
  readonly vectors: { readonly label: string; readonly value: number[] }[];
  readonly expected: {
    readonly normalBefore: string[][]; readonly voiceMode: string;
    readonly voiceTieOrderNotPinned: boolean; readonly millionRowSpeedClaim: boolean;
  };
}
/* Independently authored voice-vault geometry. Same invariant shape as the
 * scenario (identical 2-wide prefix, tails separate), different axis, query
 * and labels: nothing is copied from the ordinary vault's rows. */
const r12VoiceGeometry = {
  query: [0, 1, 0, 1],
  rows: [
    { label: "decoy-tail", vector: [0, 1, 0, -1] },
    { label: "match-tail", vector: [0, 1, 0, 1] },
  ],
} as const;
/* Candidate citation: the hit's source revision pins the stored TASK body. */
async function r12PinnedTitle(engine: EngineFixture, hit: { readonly entity_ref: string; readonly source_revision_ref?: string | null }) {
  expect(hit.source_revision_ref).toBeTruthy();
  const stored = await engine.client.call("vault.get", { entity_ref: `${hit.entity_ref}@${hit.source_revision_ref!}` });
  expect(stored.value).not.toBeNull();
  return (stored.value!.body as { title?: unknown }).title;
}

/* RETRIEVAL-12: ordinary full-dimension rescore vs declared voice_hot prefix. */
suite.test(test, "RETRIEVAL-12", "Vector prefix candidates get full-dimension refinement should work", async () => {
  const fixture = await scenario<R12Scenario>("RETRIEVAL-12");
  expect(fixture.dimensions).toBe(4);
  expect(fixture.fastDims).toBe(2);
  expect(fixture.expected.voiceMode).toBe("declared-prefix-only");
  expect(fixture.expected.voiceTieOrderNotPinned).toBe(true);
  expect(fixture.expected.millionRowSpeedClaim).toBe(false);
  const catalog = await loadFixtures();
  const vectorFixture = await catalog.readJson<EvidenceFixture>("retrieval-evidence");
  const at = utc("2026-08-01T00:00:00Z");
  const embedderOf = (endpoint: string) => ({
    endpoint, modelKey: vectorFixture.embedder.modelKey,
    modelId: vectorFixture.embedder.modelId, dimensions: fixture.dimensions,
    egress: { allowAll: true as const },
  });

  /* Vault 1: ordinary lane on the scenario geometry verbatim. */
  const ordinaryProvider = startVectorTable({ ...vectorFixture, claims: [] },
    fixture.vectors.map(row => [`R12 ordinary ${row.label}`, row.value] as const));
  const ordinary = await EngineFixture.start({ id: "RETRIEVAL-12-ordinary", profile,
    fastDims: fixture.fastDims, initArgs: endpointInitArgs(ordinaryProvider.endpoint),
    embedder: embedderOf(ordinaryProvider.endpoint) });
  let ordinaryPrimaryFailed: boolean = false;
  let ordinaryPrimary: unknown;
  try {
    const config = await ordinary.client.call("vault.search.vector.config", {});
    readReceipt(config.narrowing);
    expect(config.value.dimensions).toBe(4);
    expect(config.value.fast_dims).toBe(2);
    const records = new Map<string, string>();
    for (const row of fixture.vectors) {
      const record = await task(ordinary, `R12 ordinary ${row.label}`, at);
      const put = await ordinary.client.call("vault.vectors.put", { entity_ref: record.entity_ref, vector: row.value });
      expect(put.dimensions).toBe(4);
      records.set(row.label, record.id_hex);
    }
    // G-TOPK (FIX21914): isolate the intended ordinary corpus via the existing
    // record-bound reader; observe publication with each row's own positive
    // probe, not the deliberately poor common-query rank.
    const ordinaryReader = await recordBoundReader(ordinary, [...records.values()]);
    for (const row of fixture.vectors) {
      const id = records.get(row.label)!;
      await awaitPublic(() => ordinaryReader.call("vault.search.vector", { query: row.value, limit: 10 }),
        read => read.value.hits.some(hit => hit.entity_ref === id),
        { label: `published vector: ordinary/${row.label}` });
    }
    const first = await ordinaryReader.call("vault.search.vector", { query: fixture.query, limit: 10 });
    readReceipt(first.narrowing);
    expect(first.value.lane).toBe("ordinary");
    expect(first.value.effective_limit).toBe(10);
    expect(first.value.limit_clamped).toBe(false);
    expect(first.value.refinement).toMatchObject({ stored_dimensions: 4,
      candidate_dimensions: 2, query_dimensions: 4, score_dimensions: 4,
      full_dimension_rescore: true });
    const ids = first.value.hits.map(hit => hit.entity_ref);
    const [earlier, later] = fixture.expected.normalBefore[0]!;
    expect(ids).toContain(records.get(earlier!)!);
    expect(ids).toContain(records.get(later!)!);
    expect(ids.indexOf(records.get(earlier!)!)).toBeLessThan(ids.indexOf(records.get(later!)!));
    const repeated = await ordinaryReader.call("vault.search.vector", { query: fixture.query, limit: 10 });
    expect(repeated.value.hits.map(hit => hit.entity_ref)).toEqual(ids);
    for (const hit of first.value.hits) {
      expect(Array.isArray(hit.embedding_matches)).toBe(true);
      expect(String(await r12PinnedTitle(ordinary, hit))).toMatch(/^R12 ordinary /);
    }
    await ordinary.artifacts.json("retrieval-mrl-ordinary.json", { query: fixture.query, first, repeated });
  } catch (error) {
    ordinaryPrimaryFailed = true;
    ordinaryPrimary = error;
  } finally {
    const cleanups: string[] = [];
    try { await ordinary.close(); } catch (error) { cleanups.push(errorText(error)); }
    try { await ordinaryProvider.close(); } catch (error) { cleanups.push(errorText(error)); }
    if (ordinaryPrimaryFailed) {
      if (cleanups.length) throw new Error(`${errorText(ordinaryPrimary)}; cleanup: ${cleanups.join("; ")}`);
      throw ordinaryPrimary;
    }
    if (cleanups.length) throw new Error(`cleanup: ${cleanups.join("; ")}`);
  }

  /* Vault 2: voice_hot lane on the independently authored geometry. Prefix
   * scores tie by construction, so the tie order stays unpinned: presence
   * plus prefix-only refinement evidence is the whole voice assertion. */
  const voiceProvider = startVectorTable({ ...vectorFixture, claims: [] },
    r12VoiceGeometry.rows.map(row => [`R12 voice ${row.label}`, [...row.vector]] as const));
  const voice = await EngineFixture.start({ id: "RETRIEVAL-12-voice", profile,
    fastDims: fixture.fastDims, initArgs: endpointInitArgs(voiceProvider.endpoint),
    embedder: embedderOf(voiceProvider.endpoint) });
  let voicePrimaryFailed: boolean = false;
  let voicePrimary: unknown;
  try {
    const config = await voice.client.call("vault.search.vector.config", {});
    readReceipt(config.narrowing);
    expect(config.value.dimensions).toBe(4);
    expect(config.value.fast_dims).toBe(2);
    const records = new Map<string, string>();
    for (const row of r12VoiceGeometry.rows) {
      const record = await task(voice, `R12 voice ${row.label}`, at);
      const put = await voice.client.call("vault.vectors.put", { entity_ref: record.entity_ref, vector: [...row.vector] });
      expect(put.dimensions).toBe(4);
      records.set(row.label, record.id_hex);
    }
    // G-TOPK (FIX21914): same scoped-reader isolation for the voice lane;
    // per-row positive probes keep the prefix-only geometry intact.
    const voiceReader = await recordBoundReader(voice, [...records.values()]);
    for (const row of r12VoiceGeometry.rows) {
      const id = records.get(row.label)!;
      await awaitPublic(() => voiceReader.call("vault.search.vector",
          { query: [...row.vector], limit: 8, lane: "voice_hot" }),
        read => read.value.hits.some(hit => hit.entity_ref === id),
        { label: `published vector: voice/${row.label}` });
    }
    const first = await voiceReader.call("vault.search.vector",
      { query: [...r12VoiceGeometry.query], limit: 8, lane: "voice_hot" });
    readReceipt(first.narrowing);
    expect(first.value.lane).toBe("voice_hot");
    expect(first.value.effective_limit).toBe(8);
    expect(first.value.limit_clamped).toBe(false);
    expect(first.value.refinement).toMatchObject({ stored_dimensions: 4,
      candidate_dimensions: 2, query_dimensions: 4, score_dimensions: 2,
      full_dimension_rescore: false });
    const ids = first.value.hits.map(hit => hit.entity_ref);
    for (const row of r12VoiceGeometry.rows) expect(ids).toContain(records.get(row.label)!);
    const repeated = await voiceReader.call("vault.search.vector",
      { query: [...r12VoiceGeometry.query], limit: 8, lane: "voice_hot" });
    expect(repeated.value.refinement).toMatchObject({ score_dimensions: 2, full_dimension_rescore: false });
    for (const hit of first.value.hits) {
      expect(Array.isArray(hit.embedding_matches)).toBe(true);
      expect(String(await r12PinnedTitle(voice, hit))).toMatch(/^R12 voice /);
    }
    await voice.artifacts.json("retrieval-mrl-voice.json", { query: [...r12VoiceGeometry.query], first, repeated });
  } catch (error) {
    voicePrimaryFailed = true;
    voicePrimary = error;
  } finally {
    const cleanups: string[] = [];
    try { await voice.close(); } catch (error) { cleanups.push(errorText(error)); }
    try { await voiceProvider.close(); } catch (error) { cleanups.push(errorText(error)); }
    if (voicePrimaryFailed) {
      if (cleanups.length) throw new Error(`${errorText(voicePrimary)}; cleanup: ${cleanups.join("; ")}`);
      throw voicePrimary;
    }
    if (cleanups.length) throw new Error(`cleanup: ${cleanups.join("; ")}`);
  }
});
