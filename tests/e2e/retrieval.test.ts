import { afterAll, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { decode } from "@msgpack/msgpack";
import type { Facade, FacadeInput, FacadeResult, FacadeVerb } from "@oneiron/client";
import { EngineFixture, awaitPublic } from "./support/engine.ts";
import type { PairedActor } from "./support/engine.ts";
import { PublicHttpClient, PublicHttpError, WsClient, WsRpcError, credentialParts } from "./support/clients.ts";
import { loadFixtures, ownerBaseClaimScope } from "./support/fixtures.ts";
import { ScriptedProviders, openaiText } from "./support/providers.ts";
import { assertFlowActive, defineFile, ownResource, recordStart, redactor, secretHex } from "./support/run.ts";

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
// One exact configured chat model for a durable owner model step. The
// checker role arms no Dreamer, workflow or code-mode seat, so the vault
// holds no other journaled step.
const slimStepConfig = (endpoint: string) => `
[models.providers.slim]
kind = "local-openai-compat"
base_url = "${endpoint}"
revision = "e2e-v1"
[models.roles.checker]
model = "slim:slim-chat"
`;
const SLIM_STEP_TEXT = "Hold this durable step while the vault sheds its heavy state.";
const slimStep = {
  id: "slim-durable-step", origin: "slim", role: "checker", purpose: "durable owner model step held for SLIM",
  request: { method: "POST" as const, path: "/v1/chat/completions", model: "slim-chat" },
  barrier: "durable-step-held",
  response: openaiText("slim-durable-step", "slim-chat", "Held step answered.", { inputTokens: 16, outputTokens: 4 }),
};
const slimSubmit: FacadeInput<"ai.steps.submit"> = {
  step_key: "retrieval-08-slim-wait",
  request: {
    model: "slim/slim-chat@e2e-v1",
    envelope: { purpose: "answer_gen", class: { kind: "best_effort" }, tier: { global_default: "answer" },
      response_format: { format: "text" }, locality: "own_server" },
    messages: [{ role: "user", content: [{ kind: "text", text: SLIM_STEP_TEXT }] }],
  },
  retry: { max_attempts: 1 },
};
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
// G8 source-mapped background corpus (FIX21902 closure, Engine 12:03; FIX21914 adds observed agent-health-review;
// FIX22118 adds the observed weave-lens text; FIX22313 adds judge). 33 pinned literals from production-reconciliation batches
// (R22 32-input batch before first test write, 8-input batches after; R41 supplied the weave-lens text;
// egress.allowAll on a fresh
// vault legitimately seeds bootstrap data): 1 startup literal 'model', 7
// opaque 32-hex rows (exact producing rows UNKNOWN per rootcause, pinned as
// literals, never a live any-32hex pattern which would silently accept
// unplanned inputs), 14 skill hub_provenance CLAIMs (5 bootstrap hubId
// eba40381... + 9 pack hubId 0f8ccc77..., all clock-free verbatim; producer
// skill_hub/index.rs:257-266 ClaimBody PREDICATE_SKILL_HUB_PROVENANCE with
// {contentHash, hubRef}, embedded via embed.rs:136-145 payload_text and
// eligibility.rs:116-123 ClaimBody), 5 bootstrap scan_verdict shapes
// (scannedAt normalized to 0 here; live run-clock values recognized by
// backgroundScanVerdict below; producer skill_hub/verdict.rs:254-287 with
// {contentHash, provider oneiron.static.v1, scannedAt, verdict unknown,
// riskLevel none, completeness complete, governance recommended,
// staticInputHash hex64}), and 6 prose rows (the five bootstrap skills and the reader weave lens).
// Fresh-run legitimacy is observed in-test via provider.seen (see R06 check)
// plus 10s awaitPublic server-provided lists (/api/search/vector per-row
// probes, vault.claims.list), not assumed from R22 snapshots. No fixture
// oracle change (evidence.json/scenarios.json untouched).
// The goal-intake rows pin skills/goal-intake/SKILL.md as of ed396f61a5c
// (12 Nov); a later edit of a bootstrap SKILL.md changes its two literals.
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
  '{"contentHash": "11fbb5c56b35347a041964c8fb654d637ccf08e446eeb18f7dc9dde7dc1eefc8", "hubRef": {"hubId": "eba40381816289359d577401be27f01f", "refString": "goal-intake", "pin": {"type": "content_hash", "value": "11fbb5c56b35347a041964c8fb654d637ccf08e446eeb18f7dc9dde7dc1eefc8"}}}',
  '{"contentHash": "11fbb5c56b35347a041964c8fb654d637ccf08e446eeb18f7dc9dde7dc1eefc8", "provider": "oneiron.static.v1", "scannedAt": 0, "verdict": "unknown", "riskLevel": "none", "completeness": "complete", "governance": "recommended", "staticInputHash": "e1e56f9fabbb5c0c58c6a67c420d99b356f429f6a0f2fbc4e1c07dd9db9de08b"}',
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
  '{"contentHash": "c3e4241a880307b1003b9c962eded7e7bfd9a2433a417dd17e90efef3b52616c", "hubRef": {"hubId": "0f8ccc77298089c9b670f3bac7ae8f07", "refString": "pack-skill:15ab715ae6fc567ee6217ddd3232b4e6513a2b180fcca469d6bfdaac7e8efd9d", "pin": {"type": "content_hash", "value": "c3e4241a880307b1003b9c962eded7e7bfd9a2433a417dd17e90efef3b52616c"}}}',
  'Interview a human for a typed project goal record and commit it via authenticated intake.',
  'Judge agent health from receipts with closed-form detectors and seeded dials.',
  'Compare skill revisions against a fixed rubric using held-out cases.',
  "Render one reader's weave report as a short, readable lens over the items their own read admitted.",
  'Improve a standard skill from observed failures and held-out evidence.',
  'Resume useful work from durable tasks and receipts without repeating effects.',
];
// contentHashes of the 14 observed skill rows (5 bootstrap + 9 pack).
const BACKGROUND_SKILL_HASHES: ReadonlySet<string> = new Set([
  '11fbb5c56b35347a041964c8fb654d637ccf08e446eeb18f7dc9dde7dc1eefc8',
  '1bb662bb3d352973c375c2e2884979ae868c32d0b496666a0a908babb77977f7',
  '237cec53997e8d4b4bc642b34913249a2d86672def3fc1d5948679aa75ac7e0c',
  '680595164edaf97e42280f9f6f6ef6283d0167eb0c63d3e6f25fc7339049508d',
  '6aaf0a1c744bc7eebd62970aa2089b3822dec8055558f5855a69d33ff1bfde2e',
  '73278f055a5c12348058a87f0918afdb900e9a84c629259b28820ab5960350ea',
  '77bc3c46d1125077de84efa9472cbe00b40294c0bd5d8f8c45fc63d4ebf8da78',
  '8e6ef3e2ed38e1232b50027cb16f9e1bd097aad921f7ec0efd4b6e36a9fe5a37',
  'b97d7d780db236973912a26553c2759b368104a4a903419d51309aa0338691d3',
  'bdea3a9b9ff4c63804e89de60815957fdae35f9e7ed99963b5b0532999db1f59',
  'c3e4241a880307b1003b9c962eded7e7bfd9a2433a417dd17e90efef3b52616c',
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
function startVectorTable(fixture: EvidenceFixture, extraVectors: readonly (readonly [string, number[]])[] = [],
  backgroundVector?: number[]) {
  const vectors = new Map<string, number[]>([
    [fixture.embedder.probeText, fixture.embedder.probeVector],
    ...fixture.claims.map(row => [row.value, row.vector] as [string, number[]]),
    ...extraVectors,
  ]);
  // Default authored background vector: the all-ones diagonal, dimension-generic.
  // R01 query [1,0,0,0] vs all-evidence 1.0, background 0.5, unrelated
  // [0,0,0,1] 0.0, so all-evidence before unrelated holds. R12 ordinary query
  // [1,0,1,0] vs right-tail 1.0, background 0.707, wrong-tail 0.0, so right
  // before wrong holds; voice presence-only checks are unaffected. R06 passes
  // a fourth-axis background below, orthogonal to its weak and strong probes.
  // Background rows carry their own entity ids, so they cannot satisfy an
  // expected-id probe or hide a missing fixture record: per-row probes require
  // exact fixture ids via 10s awaitPublic server lists. No 32hex fallback;
  // unknown inputs still refuse with recorded rejectedInputs.
  const background = backgroundVector ?? Array.from({ length: fixture.embedder.dimensions }, () => 1);
  for (const text of BACKGROUND_LITERALS) {
    if (!vectors.has(text)) vectors.set(text, background);
  }
  const vectorFor = (text: string): number[] | undefined =>
    vectors.get(text) ?? (backgroundScanVerdict(text) ? background : undefined);
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
    names: { label: string; name: string; queries: string[]; evidence: string }[];
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
      // A name alone is not identity evidence: each person cites its own
      // witnessed statement, as memory.test.ts's person() does.
      const evidence = await witnessedText(engine, row.evidence, at);
      const person = await engine.client.call("vault.people.create", {
        identity: { name: row.name }, identity_evidence_refs: [evidence.message.id_hex], occurred_at: at, learned_at: at,
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

/* RETRIEVAL-04 (partial): one world-limited reader, every facade read door it may use. */
function retrieval04Receipt(receipt: ReadReceipt) {
  readReceipt(receipt);
  expect(receipt.requested.include_stale).toBe(true);
  expect(receipt.actor_ceiling.include_stale).toBe(false);
  expect(receipt.applied.include_stale).toBe(false);
  expect(receipt.narrowed_axes).toContain("include_stale");
  expect(receipt.replan_hint).toContain("include_stale");
  expect(receipt.replan_hint).toContain("grant_scope");
  expect(receipt.suppressed_count).toBe(0);
}
function retrieval04Absent(output: unknown, forbidden: readonly string[]) {
  const serialized = JSON.stringify(output);
  for (const value of forbidden) expect(serialized).not.toContain(value);
}
interface Retrieval04Pack extends ContextPackReply {
  readonly stats: {
    readonly candidates_considered: number; readonly entities_hydrated: number;
    readonly neighbors_hydrated: number; readonly claims_suppressed: number;
  };
  readonly l2_base?: { readonly content_hash: string; readonly body: string } | null;
  readonly disclosure?: { readonly mode: string } | null;
  readonly interlocutors?: readonly { readonly speaker: string; readonly class: string }[] | null;
}
interface Retrieval04L2Row {
  readonly id: string; readonly subj: string; readonly pred: string | null;
  readonly val: unknown; readonly world: string | null;
}
// A pack serves each claim about an L2 subject (the vault owner, and the
// reader's own PERSON) once, as an l2_base row, and drops it from results and
// neighbors (serialize/pack_preparation.rs prepare_entities skips
// l2_base.evidence_ids). The visible stats are set before that cut
// (api/context_pack/response_limits.rs scrub_context_pack_visible_stats), so
// they count the served l2_base rows as well.
function retrieval04L2Rows(pack: Retrieval04Pack): Retrieval04L2Row[] {
  return pack.l2_base ? JSON.parse(pack.l2_base.body) as Retrieval04L2Row[] : [];
}
interface Retrieval04QueryPage {
  readonly items: { readonly id: string }[];
  readonly meta: { readonly total: number; readonly countMode: string };
  readonly narrowing: ReadReceipt;
}
interface Retrieval04HydrateBatch {
  readonly narrowing: ReadReceipt;
  readonly results: {
    readonly ref: string; readonly outcome: string;
    readonly result?: { readonly id?: string; readonly narrowing: ReadReceipt };
    readonly error?: { readonly kind: string };
  }[];
}
interface Retrieval04Refusal {
  readonly error: { readonly code: string; readonly message: string; readonly receiptRef?: string };
  readonly narrowing?: ReadReceipt;
  readonly value?: unknown;
}

// Promise: A world-limited reader stays clamped across restart on claim recall, point and lexical reads and on graph reads from a readable TASK anchor, gets honest read receipts without hidden-claim counts, and cannot write into the hidden world.
// Doors: owner facade claim writes and structural TASK/about-edge setup; reader facade recall/get/hydrate/BM25/neighbors, HTTP query/context-pack/batch hydrate; owner hydration, neighbor/pack controls and refusal-receipt read-back; restart.
// Unproved: legacy vector/entity/edges row clamps need grant-admitting legacy read doors; MCP caveated-reader parity needs registered caveated-reader admission; proposed/stale/deleted/superseded lifecycle rows remain unexercised (producers exist); a world axis on receipts needs a public receipt field, not an invented narrowed_axes value.
suite.test(test, "RETRIEVAL-04", "A world-limited reader stays clamped across restart on claim recall, point and lexical reads and on graph reads from a readable TASK anchor, gets honest read receipts without hidden-claim counts, and cannot write into the hidden world", async () => {
  const fixture = await scenario<{
    rows: { label: string }[];
    edges: { from: string; kind: string; to: string }[];
    expected: { bothEndpointsReadable: boolean; neverWidens: boolean;
      everyNarrowingExplained: boolean; unreadableNamesAndCountsAbsent: boolean };
  }>("RETRIEVAL-04");
  expect(fixture.rows.some(row => row.label === "readable")).toBe(true);
  expect(fixture.rows.some(row => row.label === "private")).toBe(true);
  expect(fixture.expected).toMatchObject({ bothEndpointsReadable: true, neverWidens: true,
    everyNarrowingExplained: true, unreadableNamesAndCountsAbsent: true });
  const edge = fixture.edges.find(row => row.from === "readable" && row.to === "private");
  if (!edge) throw new Error("RETRIEVAL-04 requires the authored readable-to-private edge");
  expect(edge.kind).toBe("about");
  const engine = await EngineFixture.start({ id: "RETRIEVAL-04", profile });
  let primaryFailed: boolean = false;
  let primary: unknown;
  try {
    const at = utc("2026-02-01T12:00:00Z");
    const scope = await ownerBaseClaimScope(engine.client, engine.pairedActor.principalRef);
    const evidence = await witnessedText(engine, "This distinct person is Retrieval clamp reader.", at);
    const person = await engine.client.call("vault.people.create", {
      identity: { name: "Retrieval clamp reader" }, identity_evidence_refs: [evidence.message.id_hex],
      occurred_at: at,
    });
    const guestId = person.person.id_hex;
    expect(guestId).not.toBe(engine.pairedActor.principalRef);
    const guest = await engine.pairActor({ principalRef: guestId, actorClass: "human", scope: ["core:read"] });
    expect((await guest.client.call("self.actor", {})).actor_ref).toBe(guestId);
    const { seed } = credentialParts(guest.credential);
    const attenuated = await guest.client.call("self.credential.attenuate", {
      holder_seed: [...Buffer.from(seed, "hex")], caveat: { scope: { kind: "ceiling", scope: {
        worlds: { kind: "some", values: [scope.world_id] }, facets: { kind: "all" },
        bands: { kind: "all" }, audience: { kind: "all" },
        verbs: { kind: "some", values: ["core:read"] }, sensitivity: { kind: "all" },
      } } },
    });
    expect(attenuated.token.startsWith("v2.slip.")).toBe(true);
    // No holder transfer: binding_key is public, so retain the paired holder's seed.
    const reader = new PublicHttpClient(engine.url, {
      credential: `v2.cred.${attenuated.token.slice(8)}.${seed}`, artifacts: engine.artifacts,
    });
    const hiddenWorldName = "Retrieval private partition";
    const hiddenWorld = await engine.client.call("vault.structural.put", {
      kind: "WORLD", body: { name: hiddenWorldName, kind: "dream" }, occurred_at: at, learned_at: at,
    });
    const worldRead = await engine.client.call("vault.get", { entity_ref: hiddenWorld.id_hex });
    expect(worldRead.value?.body).toMatchObject({ name: hiddenWorldName, kind: "dream" });
    const token = "retrievalclampquartz";
    const graphToken = "retrievalgraphquartz";
    const readableText = `${token} ${graphToken} readable`;
    const graphText = `${graphToken} readable graph anchor`;
    const hiddenText = `${token} private`;
    // claim() observes each commit receipt and hydrates the write as owner.
    // Public synthetic values isolate the world ceiling from model-channel name projection.
    // Even a Public claim in the hidden world must remain unreadable.
    async function retrieval04FixtureClaim(label: string, claimScope: Facade.ClaimScope, value: string) {
      try {
        return await claim(engine, claimScope, {
          predicate: "profile.name", value, sensitivity: 0, occurred_at: at, learned_at: at,
        });
      } catch (error) {
        if (error instanceof PublicHttpError) {
          throw new Error(
            `RETRIEVAL-04 owner ${label} fixture claim: status=${error.reply.status}; code=${error.error?.code ?? "absent"}; message=${error.error?.message ?? errorText(error)}; first_suggestion=${error.error?.suggestions?.[0] ?? "absent"}`,
            { cause: error },
          );
        }
        throw new Error(
          `RETRIEVAL-04 owner ${label} Public user_stated fixture did not pass claim()'s auto/approved landing/readback guard (FIX-LIST [CLAIM-SENSITIVITY-STAMP-FORCES-PROPOSED] was fixed by #7269); world=${claimScope.world_id}; ${errorText(error)}`,
          { cause: error },
        );
      }
    }
    const readable = await retrieval04FixtureClaim("readable base-world", scope, readableText);
    const hidden = await retrieval04FixtureClaim("hidden-world", { ...scope, world_id: hiddenWorld.id_hex }, hiddenText);
    expect(readable.entity.body).toMatchObject({ val: readableText, life: "active" });
    expect(hidden.entity.body).toMatchObject({ val: hiddenText, life: "active" });
    expect(hidden.id).not.toBe(readable.id);
    expect(readable.ref).toMatch(/^[^:]+:[a-f0-9]{2}$/);
    expect(hidden.ref).toMatch(/^[^:]+:[a-f0-9]{2}$/);
    const forbidden = [hiddenText, hidden.id, hidden.ref, hidden.ref.split(":")[0]!, hiddenWorld.id_hex, hiddenWorldName];
    // The structural door atomically writes an indexed base-world TASK and its about edge.
    // The readable CLAIM also matches the graph token, retaining a base CLAIM for the pack world-share cap.
    const graphAnchor = await task(engine, graphText, at, [
      { edge_kind: edge.kind, target_ref: hidden.id, weight: 0.5 },
    ]);
    const ownerAnchor = await engine.client.call("vault.get", { entity_ref: graphAnchor.id_hex });
    expect(ownerAnchor.value?.id_hex).toBe(graphAnchor.id_hex);
    expect(ownerAnchor.value?.body).toMatchObject({ title: graphText, role: 1 });
    const neighborInput: FacadeInput<"vault.neighbors"> = {
      entity_ref: graphAnchor.id_hex, opts: { edge_kind: edge.kind, limit: 20 }, filter: { include_stale: true },
    };
    const ownerEdges = await engine.client.call("vault.neighbors", neighborInput);
    expect(ownerEdges.value.some(row => row.record?.id === hidden.id
      && row.edge_kind === edge.kind && row.direction === "out")).toBe(true);
    const ownerLexical = await engine.client.call("vault.search.bm25", { query: token, limit: 20 });
    expect(sorted(ownerLexical.value.map(hit => hit.record!.id))).toEqual(sorted([readable.id, hidden.id]));
    const recallInput: FacadeInput<"vault.recall"> = {
      query: token, effort: "medium", limit: 20, format: "md", token_budget: 8192,
      scope: { worlds: { kind: "all" }, kinds: ["CLAIM"] }, filter: { include_stale: true },
    };
    async function checkReader() {
      const recalled = await reader.call("vault.recall", recallInput).catch((error: unknown) => {
        if (error instanceof PublicHttpError) {
          throw new Error(
            `RETRIEVAL-04 vault.recall: HTTP ${error.reply.status}; code=${error.error?.code ?? "absent"}; message=${error.error?.message ?? errorText(error)}; first_suggestion=${error.error?.suggestions?.[0] ?? "absent"}`,
            { cause: error },
          );
        }
        throw new Error(`RETRIEVAL-04 vault.recall: ${errorText(error)}`, { cause: error });
      });
      // Medium recall also returns the fresh vault's own seeded base-world claims; the promise is
      // that the readable claim is there and nothing of the hidden world is (retrieval04Absent below).
      const recalledReadable = recalled.items.find(item => item.short_id === readable.ref);
      if (!recalledReadable) {
        throw new Error(
          `RETRIEVAL-04 medium vault.recall omitted readable CLAIM ${readable.ref}; returned_short_ids=${JSON.stringify(recalled.items.map(item => item.short_id))}`,
        );
      }
      // Require the authored claim's identity and its Public value, not just a matching string elsewhere.
      expect(recalledReadable.predicate).toBe("profile.name");
      expect(recalledReadable.value_text).toBe(readableText);
      expect(recalled.items.map(item => item.value_text)).toContain(readableText);
      expect(recalled.rendered).toBeTruthy();
      retrieval04Receipt(recalled.narrowing);
      retrieval04Absent(recalled, forbidden);
      const visible = await reader.call("vault.get", { entity_ref: readable.id, filter: { include_stale: true } });
      expect(visible.value?.id_hex).toBe(readable.id);
      expect(visible.value?.body).toMatchObject({ val: readableText });
      retrieval04Receipt(visible.narrowing);
      retrieval04Absent(visible, forbidden);
      const absent = await reader.call("vault.get", { entity_ref: hidden.id, filter: { include_stale: true } });
      expect(absent.value).toBeNull();
      retrieval04Receipt(absent.narrowing);
      retrieval04Absent(absent, forbidden);
      const lexical = await reader.call("vault.search.bm25", { query: token, limit: 20, filter: { include_stale: true } });
      expect(lexical.value.map(hit => hit.record?.id)).toEqual([readable.id]);
      retrieval04Receipt(lexical.narrowing);
      retrieval04Absent(lexical, forbidden);
      const anchor = await reader.call("vault.get", {
        entity_ref: graphAnchor.id_hex, filter: { include_stale: true },
      });
      expect(anchor.value?.id_hex).toBe(graphAnchor.id_hex);
      expect(anchor.value?.body).toMatchObject({ title: graphText, role: 1 });
      retrieval04Receipt(anchor.narrowing);
      retrieval04Absent(anchor, forbidden);
      const neighbors = await reader.call("vault.neighbors", neighborInput);
      expect(neighbors.value).toEqual([]);
      retrieval04Receipt(neighbors.narrowing);
      retrieval04Absent(neighbors, forbidden);
      return { recalled, visible, absent, lexical, anchor, neighbors };
    }
    const before = await checkReader();
    const visibleHydrate = await reader.call("vault.hydrate", { refs: [readable.ref], filter: { include_stale: true } });
    expect(visibleHydrate.value.map(row => row.id_hex)).toEqual([readable.id]);
    expect(visibleHydrate.value[0]!.body).toMatchObject({ val: readableText });
    retrieval04Receipt(visibleHydrate.narrowing);
    retrieval04Absent(visibleHydrate, forbidden);
    const withheld = await reader.raw<Retrieval04Refusal>("POST", "/v1/core/facade/vault.hydrate", {
      refs: [readable.ref, hidden.ref], filter: { include_stale: true },
    } satisfies FacadeInput<"vault.hydrate">);
    expect(withheld.status).toBe(404);
    expect(withheld.body.error.code).toBe("NOT_FOUND");
    expect(withheld.body.value).toBeUndefined();
    expect(withheld.body.narrowing).toBeDefined();
    retrieval04Receipt(withheld.body.narrowing!);
    // A hydrate error may echo the supplied ref; only server-discovered payload is forbidden here.
    retrieval04Absent(withheld.body, [hiddenText, hiddenWorldName, hiddenWorld.id_hex]);
    const quality = await reader.call("vault.get", { entity_ref: readable.id, filter: { min_confidence: 1 } });
    expect(quality.value).toBeNull();
    readReceipt(quality.narrowing);
    expect(quality.narrowing.requested.min_confidence).toBe(1);
    expect(quality.narrowing.applied.min_confidence).toBe(1);
    expect(quality.narrowing.replan_hint).toContain("grant_scope");
    // This receipt can count the permitted claim removed by the quality filter, not the hidden world.
    const query = await reader.raw<Retrieval04QueryPage>("POST", "/v1/core/query", {
      query: token, limit: 20, view: "full", countMode: "exact", filter: { include_stale: true },
    });
    expect(query.status).toBe(200);
    expect(query.body.items.map(row => row.id)).toEqual([readable.id]);
    expect(query.body.meta.total).toBe(1);
    expect(query.body.meta.countMode).toBe("estimate");
    retrieval04Receipt(query.body.narrowing);
    retrieval04Absent(query.body, forbidden);
    const batch = await reader.raw<Retrieval04HydrateBatch>("POST", "/v1/core/batch/shortId/hydrate", {
      refs: [readable.ref, hidden.ref], view: "full", filter: { include_stale: true },
    });
    expect(batch.status).toBe(200);
    expect(batch.body.results).toHaveLength(2);
    expect(batch.body.results[0]!.ref).toBe(readable.ref);
    expect(batch.body.results[0]!.outcome).toBe("live");
    expect(batch.body.results[0]!.result?.id).toBe(readable.id);
    expect(batch.body.results[1]!.ref).toBe(hidden.ref);
    expect(batch.body.results[1]!.outcome).toBe("not_found");
    expect(batch.body.results[1]!.error?.kind).toBe("not_found");
    expect(batch.body.results[1]!.result).toBeUndefined();
    retrieval04Receipt(batch.body.narrowing);
    retrieval04Receipt(batch.body.results[0]!.result!.narrowing);
    // Batch refs are required echoes of caller inputs, not disclosed identifiers.
    retrieval04Absent(batch.body.results.map(row => row.result), forbidden);
    const packInput = { query: graphToken, limit: 20, hydrate: true, include_edges: true,
      edge_hop: 1, max_neighbors: 20, view: "full", budget: { token_budget: 8192 },
      filter: { include_stale: true } };
    // Both fixture claims are about the owner, an L2 subject of every pack
    // here. The L2 prefix holds the owner's base-reality claims only
    // (pipeline/l2_evidence.rs), so the readable claim is an l2_base row and
    // the hidden dream-world claim is a delta row (a result or neighbor).
    const packShape = (reply: Retrieval04Pack, rows: readonly Retrieval04L2Row[]) => JSON.stringify({
      results: reply.results.map(row => row.id), neighbors: reply.neighbors.map(row => row.id),
      l2_rows: rows.map(row => ({ id: row.id, pred: row.pred, world: row.world,
        matches_query: typeof row.val === "string" && row.val.includes(graphToken) })),
      stats: reply.stats, disclosure: reply.disclosure?.mode ?? null,
      interlocutors: reply.interlocutors?.map(stamp => stamp.class) ?? null,
    });
    async function retrieval04CheckPacks() {
      const ownerPack = await engine.client.raw<Retrieval04Pack>("POST", "/v1/core/context-pack", packInput);
      expect(ownerPack.status).toBe(200);
      const ownerL2 = retrieval04L2Rows(ownerPack.body);
      try {
        // Control: the owner's pack reaches the TASK anchor and both claims:
        // the readable base claim in the L2 prefix, the hidden-world claim
        // outside it, as a delta row of the TASK anchor's walk.
        expect(ownerPack.body.disclosure?.mode ?? null).not.toBe("absence_clamp");
        expect(ownerPack.body.results.map(row => row.id)).toContain(graphAnchor.id_hex);
        expect(ownerL2.map(row => row.val)).toContain(readableText);
        expect(ownerL2.map(row => row.val)).not.toContain(hiddenText);
        expect([...ownerPack.body.results, ...ownerPack.body.neighbors].map(row => row.id)).toContain(hidden.id);
      } catch (error) {
        throw new Error(`RETRIEVAL-04 owner context-pack control: ${errorText(error)}; pack=${packShape(ownerPack.body, ownerL2)}`,
          { cause: error });
      }
      const pack = await reader.raw<Retrieval04Pack>("POST", "/v1/core/context-pack", packInput);
      expect(pack.status).toBe(200);
      const readerL2 = retrieval04L2Rows(pack.body);
      try {
        // P7 (ILDF2, one-1592 :34 "Unknown contact -> empty clearance -> public-only"):
        // the reader is a principal-scoped core:read token with no interlocutors
        // block, an Unknown party, so its pack assembles under the absence clamp
        // and only positively Public rows take a candidate slot
        // (pipeline/filters.rs, disclosure/disclosable_set.rs admits). The TASK is
        // born Sensitive (federation/record_scope.rs default_stamp), so the pack
        // withholds it although the reader's point read above admits it; the
        // Public readable claim is served as an l2_base row.
        expect(pack.body.disclosure?.mode).toBe("absence_clamp");
        expect(pack.body.interlocutors?.some(stamp => stamp.class === "unknown")).toBe(true);
        expect(pack.body.results.map(row => row.id)).not.toContain(graphAnchor.id_hex);
        expect(pack.body.neighbors.map(row => row.id)).not.toContain(graphAnchor.id_hex);
        expect(readerL2.map(row => row.val)).toContain(readableText);
        expect(pack.body.neighbors.map(row => row.id)).not.toContain(hidden.id);
        retrieval04Receipt(pack.body.narrowing);
        retrieval04Absent(pack.body, forbidden);
        // Honest counts: every counted row is one the reader was served, as a
        // result, a neighbor or an l2_base row; the hidden claim is never one.
        const servedQueryRows = readerL2.filter(row => typeof row.val === "string" && row.val.includes(graphToken)).length;
        expect(servedQueryRows).toBe(1);
        expect(pack.body.stats.claims_suppressed).toBe(0);
        for (const counted of [pack.body.stats.candidates_considered, pack.body.stats.entities_hydrated]) {
          expect(counted).toBeGreaterThanOrEqual(pack.body.results.length + servedQueryRows);
          expect(counted).toBeLessThanOrEqual(pack.body.results.length + readerL2.length);
        }
        expect(pack.body.stats.neighbors_hydrated).toBeGreaterThanOrEqual(pack.body.neighbors.length);
        expect(pack.body.stats.neighbors_hydrated).toBeLessThanOrEqual(pack.body.neighbors.length + readerL2.length);
      } catch (error) {
        throw new Error(`RETRIEVAL-04 reader context-pack: ${errorText(error)}; pack=${packShape(pack.body, readerL2)}`,
          { cause: error });
      }
      return { ownerPack, pack };
    }
    const { ownerPack, pack } = await retrieval04CheckPacks();
    const refused = await reader.raw<Retrieval04Refusal>("POST", "/v1/core/facade/vault.claims.upsert", {
      subject_ref: engine.pairedActor.principalRef, predicate: "profile.retrieval_forbidden",
      value: "retrievalforbiddenquartz", confidence: 0.875, source: "user_stated",
      scope: { ...scope, world_id: hiddenWorld.id_hex }, occurred_at: at, learned_at: at,
    } satisfies FacadeInput<"vault.claims.upsert">);
    expect(refused.status).toBe(403);
    expect(refused.body.error.code).toBe("FORBIDDEN");
    expect(refused.body.narrowing).toBeUndefined();
    expect(refused.body.error.receiptRef).toMatch(/^call:[a-f0-9]{32}$/);
    expect(refused.headers.get("x-oneiron-receipt-ref")).toBe(refused.body.error.receiptRef!);
    const refusedReceipt = await engine.client.call("vault.receipts.get", {
      receipt_ref: refused.body.error.receiptRef!,
    });
    expect(refusedReceipt).not.toBeNull();
    expect(refusedReceipt!.receipt_ref).toBe(refused.body.error.receiptRef!);
    expect(refusedReceipt!.actor_ref).toBe(guestId);
    expect(refusedReceipt!.actor_class).toBe("human");
    expect(refusedReceipt!.transport).toBe("http_facade");
    expect(refusedReceipt!.outcome).toEqual({ refused: { code: "FORBIDDEN" } });
    await engine.restart();
    // Reuse the exact reader and credential; do not re-pair or re-attenuate after restart.
    const after = await checkReader();
    const afterPacks = await retrieval04CheckPacks();
    const durable = await engine.client.call("vault.hydrate", { refs: [readable.ref, hidden.ref] });
    expect(durable.value.map(row => row.id_hex)).toEqual([readable.id, hidden.id]);
    expect(durable.value[0]!.body).toMatchObject({ val: readableText, life: "active" });
    expect(durable.value[1]!.body).toMatchObject({ val: hiddenText, life: "active" });
    const durableEdges = await engine.client.call("vault.neighbors", neighborInput);
    expect(durableEdges.value.some(row => row.record?.id === hidden.id
      && row.edge_kind === edge.kind && row.direction === "out")).toBe(true);
    const claimsAfterRefusal = await claimSet(engine);
    expect(claimsAfterRefusal.map(row => row.claim_ref)).toContain(readable.id);
    expect(claimsAfterRefusal.map(row => row.claim_ref)).toContain(hidden.id);
    expect(claimsAfterRefusal.some(row => row.predicate === "profile.retrieval_forbidden")).toBe(false);
    await engine.artifacts.json("retrieval-world-clamp.json", { before, after, visibleHydrate,
      withheld: withheld.body, query: query.body, batch: batch.body, ownerPack: ownerPack.body,
      pack: pack.body, afterPacks: { ownerPack: afterPacks.ownerPack.body, pack: afterPacks.pack.body },
      graphAnchor, ownerAnchor, refused: refused.body, refusedReceipt, durable, durableEdges, claimsAfterRefusal });
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
    // The deadline leg never reaches the rerank stage (HyDE is cut first), so it has no rerank step.
    steps: [rerankStep("high"), rerankStep("xhigh"), rerankStep("max")] });
  const engine = await EngineFixture.start({ id: "RETRIEVAL-05", profile,
    initArgs: ["--dimensions", "4"], serverConfig: rerankConfig(providers.urls.reranker!) });
  let primaryFailed: boolean = false;
  let primary: unknown;
  try {
    const rows = await effortCorpus(engine);
    const reader = await recordBoundReader(engine, [engine.pairedActor.principalRef, ...rows.map(row => row.id)]);
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
    const delivery = engine.client.request<FacadeResult<"vault.recall">>(
      "POST", "/v1/core/facade/vault.recall", request);
    void delivery.catch(() => {}); // The main await below still propagates transport failure.
    // The whole HyDE leg uses one unrestricted owner credential: pending work
    // is filtered by the same caller key that started the deadline recall.
    // Observe real work, but do not complete it until after delivery. The
    // engine owns the clock, timeout and pending receipt throughout.
    const work = await awaitPublic(() => engine.client.call("vault.retrieval.hyde.pending", { limit: 10 }),
      pending => pending.some(row => row.input.stage === "expansion"),
      { label: "public expansion-response-held work item" });
    const held = work.find(row => row.input.stage === "expansion")!;
    if (held.input.stage !== "expansion") throw new Error("Expected expansion work");
    expect(held.input.request.query).toBe(request.query);
    const reply = await delivery;
    readReceipt(reply.body.narrowing);
    expect(reply.body.retrieval_meta.partial).toBe(true);
    // The deadline pack is the best admitted owner pack (P-RECALL-006), so other admitted claims may
    // fill the limit; the authored rows must be present and lead it (FIX 22300).
    const deliveredRefs = reply.body.items.map(item => item.short_id);
    for (const row of rows) expect(deliveredRefs).toContain(row.ref);
    expect(deliveredRefs.slice(0, rows.length).sort()).toEqual(sorted(rows.map(row => row.ref)));
    expect(reply.raw).not.toContain(fixture.lateAnswer);
    const bytes = new Uint8Array(reply.bytes);
    const delivered = JSON.stringify(reply.body);
    const completion = await engine.client.call("vault.retrieval.hyde.complete", {
      request_id: held.request_id, answer: { stage: "expansion", expansion: {
        grounded_query: held.input.request.query, hypothetical_answer: fixture.lateAnswer,
        embedding: [1, 0, 0, 0], subqueries: ["unrelated garden"],
      } },
    });
    expect(completion.status).toBe("discarded_deadline");
    expect(completion.received_bytes).toBeGreaterThan(0);
    expect(completion.completed_at_ms!).toBeGreaterThanOrEqual(completion.deadline_at_ms!);
    expect(await engine.client.call("vault.retrieval.hyde.receipt", { request_id: held.request_id })).toEqual(completion);
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
  // Keep background off the weak first-axis and strong third-axis probes;
  // exact per-row positive id probes and all evidence vectors stay unchanged.
  const provider = startVectorTable(fixture, [], [0, 0, 0, 1]);
  const engine = await EngineFixture.start({ id: "RETRIEVAL-06", profile,
    initArgs: endpointInitArgs(provider.endpoint),
    // Explicit reconciler cadence: an empty pass sleeps 500 ms, not the
    // 15 s default, so a row written after a partial pass is filled
    // inside the unchanged readiness budget.
    embedderIdleIntervalMs: 500,
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
      try {
        return (await engine.client.request<ContextPackReply>("POST", "/v1/core/context-pack", request)).body;
      } catch (error) {
        if (!(error instanceof PublicHttpError)) throw error;
        throw new Error(
          `RETRIEVAL-06 context-pack query=${JSON.stringify(probe.query)}: status=${error.reply.status}; code=${error.error?.code ?? "absent"}; message=${error.error?.message ?? errorText(error)}; first_suggestion=${error.error?.suggestions?.[0] ?? "absent"}`,
          { cause: error },
        );
      }
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
      try {
        expect(["missing_data", "low_confidence"]).toContain(pack.state.kind);
      } catch (error) {
        throw new Error(
          `RETRIEVAL-06 ENGINE DEFECT 2026-11-11: FIX 22309/22313 empty abstained retrieval reports ${pack.state.kind}; probe=${probe.label}; state=${JSON.stringify(pack.state)}; ${errorText(error)}`,
          { cause: error },
        );
      }
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
    // FIX 22041: the owner's own correction of a claim the owner authored
    // lands at once, through the fresh-claim oracle, and closes the prior in
    // the same write. No proposal opens; the receipt names the prior.
    const replacement = await claim(engine, scope, {
      predicate: "profile.retrieval_aging_semantic_old", value: fixture.newValue,
      confidence: fixture.confidence, occurred_at: utc(fixture.newUtc), learned_at: utc(fixture.newUtc), salience: 0.5,
    });
    expect(replacement.id).not.toBe(original.id);
    expect(replacement.receipt.superseded?.id).toBe(original.id);
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

/* RETRIEVAL-08: a held durable owner model step permits in-process SLIM. */
suite.test(test, "RETRIEVAL-08", "Warm and rebuilt graph parity should work", async () => {
  const fixture = await scenario<{
    seed: string; allowedNeighborhood: string[]; privateNode: string;
    edges: { from: string; kind: string; to: string }[];
  }>("RETRIEVAL-08");
  const providers = await ScriptedProviders.start({ id: "retrieval-slim", steps: [slimStep] });
  const engine = await EngineFixture.start({ id: "RETRIEVAL-08", profile, serverConfig: slimStepConfig(providers.urls.slim!) });
  let pending: Promise<FacadeResult<"ai.steps.submit">> | undefined;
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
    // The owner's durable model step writes its Started row, then its provider
    // call waits on the barrier: the one journaled outbound step SLIM selects.
    // No run id, lease, step id or elapsed wait is fabricated.
    pending = engine.client.call("ai.steps.submit", slimSubmit);
    void pending.catch(() => {}); // Still awaited and asserted after releasing the barrier.
    await providers.awaitBarrier("durable-step-held");
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
    if (step.kind !== "model") throw new Error("Expected the held durable model step");
    const saved = await engine.client.call("vault.slim.resume_step", {
      kind: "model", attempt_id: step.attempt_id, step_hash: step.step_hash,
    });
    expect(saved.kind).toBe("model");
    expect(saved).toMatchObject({ kind: "model", attempt_id: step.attempt_id, step_hash: step.step_hash,
      checkpoint: { progression: "started" } });
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
    providers.releaseBarrier("durable-step-held");
    const delivered = await pending;
    expect(delivered.step_ref).toBe(step.attempt_id);
    expect(delivered.step_hash).toBe(step.step_hash);
    expect(delivered.result?.status).toBe("finished");
    expect(providers.seenFixtureCalls).toHaveLength(1);
    await engine.artifacts.json("retrieval-slim-parity.json", { cold, warm, before, dropped, slim, saved, resumed, rebuilt, rewarm, full });
  } catch (error) {
    primaryFailed = true;
    primary = error;
  } finally {
    providers.releaseBarrier("durable-step-held");
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

// Readable filler claims RETRIEVAL-09 adds beside its six-row task clique: the
// reader's walk admits about 9-17 fixture rows, so 56 more keep the clique at
// or under 10% of the admitted graph (FIX-LIST [RETRIEVAL-09-FIXTURE-BELOW-COMMUNITY-CAP]).
const retrieval09FillerCount = 56;

/* RETRIEVAL-09: authored TURN self-reports, optional priors, real read ceiling. */
/* RETRIEVAL-09 is a budget case: the 56 fillers take about 10 s (E2E job 20, nelly) and three
 * axes read, configure and restore in turn, so the flow passed the 30 s cap. Its stated bound
 * is 60 s; it belongs to the nightly tier. */
suite.test(test, "RETRIEVAL-09", "Optional affect and community priors should work", async () => {
  const fixture = await scenario<{
    rows: { label: string; vad?: Facade.QueryAffect; confidence: number }[];
    queryAffect: Facade.QueryAffect;
  }>("RETRIEVAL-09");
  // RET-TRACE-1 is a default-off measurement lane: this case opts its
  // served vault in (FIX 21998) so a capture_trace recall returns a run id.
  const engine = await EngineFixture.start({ id: "RETRIEVAL-09", profile,
    serverConfig: "[recall]\nretrieval_telemetry_capture = true\n" });
  let primaryFailed: boolean = false;
  let primary: unknown;
  type PriorRead = {
    phase: string; effort: Facade.RecallEffort;
    pack: FacadeResult<"vault.recall">; evidence: FacadeResult<"vault.retrieval.run"> | null;
    rows: Record<string, Facade.RetrievalScoreBreakdown | null>;
  };
  const records = new Map<string, Awaited<ReturnType<typeof claim>>>();
  const reads: PriorRead[] = [];
  async function retrieval09Diagnose<T>(label: string, act: () => Promise<T>): Promise<T> {
    try { return await act(); } catch (error) {
      if (!(error instanceof PublicHttpError)) throw error;
      throw new Error(
        `RETRIEVAL-09 ${label}: status=${error.reply.status}; code=${error.error?.code ?? "absent"}; message=${error.error?.message ?? errorText(error)}; first_suggestion=${error.error?.suggestions?.[0] ?? "absent"}`,
        { cause: error },
      );
    }
  }
  try {
    const zero: Facade.RetrievalWeights = { affect: 0, arousal: 0, community: 0, vad: 0 };
    expect((await engine.client.call("vault.retrieval.weights.get", {})).weights).toEqual(zero);
    const scope = await ownerBaseClaimScope(engine.client, engine.pairedActor.principalRef);
    const at = utc("2026-08-01T00:00:00Z");
    // Every row's words share one length and carry no label (FIX 22309, R50):
    // text BM25 follows text length, so "calm" vs "intense" alone gave calm a
    // 2.16x baseline that the priors under test then had to overcome.
    const rowText = (index: number) => `retrievalpriors row${index}`;
    const privateIndex = fixture.rows.findIndex(row => row.label === "private-community");
    const allowed = [engine.pairedActor.principalRef, scope.world_id, scope.scope_facet_id, scope.scope_project_id];
    for (const [index, row] of fixture.rows.entries()) {
      let evidence: string[] = [];
      if (row.vad) {
        const turn = await witnessedText(engine, `${rowText(index)} self-report`, at);
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
        predicate: `profile.retrieval_priors_${index}`, value: rowText(index),
        confidence: row.confidence, evidence_turn_refs: evidence, occurred_at: at, learned_at: at,
      });
      records.set(row.label, saved);
      if (row.label !== "private-community") allowed.push(saved.id);
      if (row.vad) {
        const consolidated = await engine.client.call("vault.affect.claims.consolidate", { claim_ref: saved.ref });
        if (consolidated.vad == null) throw new Error("Expected consolidated VAD for authored affect evidence");
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
    // FIX-LIST [RETRIEVAL-09-FIXTURE-BELOW-COMMUNITY-CAP]: since #7272 the
    // reader's narrowed walk takes its community prior from the rows it admits
    // alone, and a fine community over 10% of them takes none (6 x 10 > ~20
    // rows). Readable filler claims about the owner share no query word and
    // sit two hops from every claim seed (claim -> owner -> filler; the walk
    // follows ClaimOf both ways), so the walk admits them as singletons: the
    // admitted graph passes 60 rows and the six-row task clique stays one
    // community. They are written before `before`, and none is hidden.
    // One read-back of the owner's claim list proves every filler landed. A
    // receipt wait per filler reads the whole vault.receipts page, which grows
    // with the vault: 1.2-1.7 s per filler, so 56 of them passed the 30 s cap.
    const fillerRefs: string[] = [];
    for (let start = 0; start < retrieval09FillerCount; start += 8) {
      const receipts = await Promise.all(Array.from(
        { length: Math.min(8, retrieval09FillerCount - start) },
        (_, offset) => engine.client.call("vault.claims.upsert", {
          predicate: `profile.retrieval_filler_${start + offset}`,
          subject_ref: engine.pairedActor.principalRef, value: `quiet ledger line ${start + offset}`,
          confidence: 0.875, source: "user_stated", scope, occurred_at: at, learned_at: at,
        }),
      ));
      for (const receipt of receipts) {
        expect(["auto", "approved"]).toContain(receipt.approval);
        fillerRefs.push(receipt.claim_short_id);
      }
    }
    await awaitPublic(
      () => engine.client.call("vault.claims.list", { subject_ref: engine.pairedActor.principalRef, limit: 1000 }),
      page => page.value.filter(row => row.predicate.startsWith("profile.retrieval_filler_")).length === retrieval09FillerCount,
      { label: "RETRIEVAL-09 filler claims landed" },
    );
    const fillers = await engine.client.call("vault.hydrate", { refs: fillerRefs });
    expect(fillers.value).toHaveLength(retrieval09FillerCount);
    allowed.push(...fillers.value.map(entity => entity.id_hex));
    const reader = await recordBoundReader(engine, allowed);
    const privateRow = records.get("private-community")!;
    expect((await reader.call("vault.get", { entity_ref: privateRow.ref })).value).toBeNull();
    const before = await claimSet(engine);
    // One judged-at second for every read, set after all claims exist: baseline, enabled and off then differ
    // only in the configured prior, not in elapsed decay between wall-clock reads (as_of is Unix seconds).
    const readAt = Math.ceil(Date.now() / 1000) + 1;
    const scored = ["calm", "intense", "community-neighbor"] as const;
    async function read(phase: string, effort: Facade.RecallEffort) {
      const pack = await retrieval09Diagnose(`${phase} vault.recall effort=${effort}`, () => reader.call("vault.recall", {
        query: "retrievalpriors", effort, limit: 50, as_of: readAt,
        query_affect: fixture.queryAffect, telemetry: { capture_trace: true },
      }));
      const runId = pack.retrieval_run_id;
      const evidence = runId
        ? await retrieval09Diagnose(`${phase} vault.retrieval.run`, () => engine.client.call("vault.retrieval.run", { run_id: runId }))
        : null;
      const rows = Object.fromEntries(scored.map(label => [label, evidence?.run.score_breakdown
        .find(hit => Buffer.from(hit.result_id).toString("hex") === records.get(label)!.id) ?? null]));
      const saved: PriorRead = { phase, effort, pack, evidence, rows };
      reads.push(saved);
      readReceipt(pack.narrowing);
      for (const label of scored) {
        expect(pack.items.some(item => item.short_id === records.get(label)!.ref)).toBe(true);
      }
      expect(pack.items.some(item => item.short_id === privateRow.ref)).toBe(false);
      expect(JSON.stringify(pack.items)).not.toContain(rowText(privateIndex));
      expect(pack.retrieval_run_id).toBeTruthy();
      expect(evidence).not.toBeNull();
      expect(evidence!.run.trace).toBeTruthy();
      const score = (label: typeof scored[number]) => {
        const hit = rows[label];
        expect(hit).not.toBeNull();
        return hit!.final_score;
      };
      return { ...saved, intenseDelta: score("intense") - score("calm"),
        communityDelta: score("community-neighbor") - score("calm") };
    }
    async function configure(weights: Facade.RetrievalWeights) {
      const setting = JSON.stringify(weights);
      const current = await retrieval09Diagnose(`weights.get before ${setting}`, () => engine.client.call("vault.retrieval.weights.get", {}));
      const receipt = await retrieval09Diagnose(`weights.configure ${setting}`, () => engine.client.call("vault.retrieval.weights.configure", {
        expected_body_hash: current.body_hash, weights,
      }));
      expect(receipt.receipt_ref).toBeTruthy();
      // The setting is read back through weights.get, not a receipt wait:
      // awaitReceipt reads the whole vault.receipts page, which took 5.1 s
      // after the fillers (E2E job 20), and this case configures six times.
      const keys = Object.keys(weights) as (keyof Facade.RetrievalWeights)[];
      const configured = (await retrieval09Diagnose(`weights.get after ${setting}`, () => awaitPublic(
        () => engine.client.call("vault.retrieval.weights.get", {}),
        read => Object.keys(read.weights).length === keys.length
          && keys.every(key => Math.abs(read.weights[key] - weights[key]) < 5e-8),
        { label: `RETRIEVAL-09 weights ${setting} read back` },
      ))).weights;
      expect(Object.keys(configured).sort()).toEqual(Object.keys(weights).sort());
      // Every coordinate is f32-backed; preserve the numeric setting across
      // the wire round trip without requiring the original decimal spelling.
      for (const key of Object.keys(weights) as (keyof Facade.RetrievalWeights)[]) {
        expect(configured[key]).toBeCloseTo(weights[key], 7);
      }
    }
    const baselines = new Map<Facade.RecallEffort, Awaited<ReturnType<typeof read>>>();
    baselines.set("medium", await read("baseline-medium", "medium"));
    const rowOrder = (snapshot: Awaited<ReturnType<typeof read>>) => snapshot.pack.items
      .map(item => item.short_id).filter(ref => [...records.values()].some(row => row.ref === ref));
    for (const [axis, value, favored, effort] of [
      ["affect", 0.4, "intense", "medium"], ["arousal", 4, "intense", "medium"],
      // ARCH-0004 #effort: the community prior (expand_ppr) runs at high and above only.
      ["community", 0.25, "community-neighbor", "high"],
    ] as const) {
      if (!baselines.has(effort)) baselines.set(effort, await read(`baseline-${effort}`, effort));
      const baseline = baselines.get(effort)!;
      await configure({ ...zero, [axis]: value });
      const enabled = await read(`${axis}-enabled`, effort);
      const refs = rowOrder(enabled);
      try {
        expect(refs.indexOf(records.get(favored)!.ref)).toBeLessThan(refs.indexOf(records.get("calm")!.ref));
        if (axis === "community") expect(enabled.communityDelta).toBeGreaterThan(baseline.communityDelta);
        else expect(enabled.intenseDelta).toBeGreaterThan(baseline.intenseDelta);
      } catch (error) {
        throw new Error(
          `RETRIEVAL-09 ENGINE DEFECT 2026-11-11: configured ${axis} prior did not improve the favored-vs-calm ranking/delta; effort=${effort}; baselineIntenseDelta=${baseline.intenseDelta}; enabledIntenseDelta=${enabled.intenseDelta}; baselineCommunityDelta=${baseline.communityDelta}; enabledCommunityDelta=${enabled.communityDelta}; as_of=${readAt}; ${errorText(error)}`,
          { cause: error },
        );
      }
      expect(await claimSet(engine)).toEqual(before);
      await configure(zero);
      const off = await read(`${axis}-off`, effort);
      expect(rowOrder(off)).toEqual(rowOrder(baseline));
      expect(await claimSet(engine)).toEqual(before);
    }
    const storedClaims = (await engine.client.call("vault.claims.list", { subject_ref: engine.pairedActor.principalRef, limit: 1000 })).value;
    for (const row of fixture.rows) {
      const stored = storedClaims
        .find(claim => claim.short_ref === records.get(row.label)!.ref || claim.claim_ref === records.get(row.label)!.id)!;
      expect(stored.confidence).toBe(row.confidence);
      expect(stored.approval).toBe(records.get(row.label)!.receipt.approval);
    }
  } catch (error) {
    primaryFailed = true;
    primary = error;
  } finally {
    const cleanups: string[] = [];
    try {
      await engine.artifacts.json("retrieval-optional-priors.json", {
        labels: Object.fromEntries([...records].map(([label, row]) => [label, { ref: row.ref, id: row.id }])),
        reads,
      });
    } catch (error) { cleanups.push(errorText(error)); }
    try { await engine.close(); } catch (error) { cleanups.push(errorText(error)); }
    if (primaryFailed) {
      if (cleanups.length) throw new Error(`${errorText(primary)}; cleanup: ${cleanups.join("; ")}`);
      throw primary;
    }
    if (cleanups.length) throw new Error(`cleanup: ${cleanups.join("; ")}`);
  }
}, 60_000);

type ClusterVerb = "vault.cluster" | "vault.cluster.propose" | "vault.cluster.proposal" | "vault.cluster.resolve_proposal";
// One tools/list per initialized MCP session: the server advertises
// tools.listChanged = false, so the bound schema versions hold for it.
const clusterSchemas = new WeakMap<object, Map<string, string>>();
async function clusterSchemaVersion(engine: EngineFixture, verb: ClusterVerb): Promise<string> {
  let bound = clusterSchemas.get(engine.mcp);
  if (!bound) {
    const listed = await engine.mcp.request<{ tools: {
      name: string; inputSchema: { properties: { schema_version: { const: string } } };
    }[] }>("tools/list");
    bound = new Map(listed.tools.map(item => [item.name, item.inputSchema.properties.schema_version.const]));
    clusterSchemas.set(engine.mcp, bound);
  }
  const version = bound.get(verb);
  if (!version) throw new Error(`Required public MCP tool not registered: ${verb}`);
  return version;
}
// The tool-first envelope is the advertised schema: schema_version bound from
// tools/list, consent, and the verb input nested under arguments.spec. A bare
// top-level spec is refused as tool_args_invalid.
async function clusterTool<V extends ClusterVerb>(engine: EngineFixture, verb: V, input: FacadeInput<V>): Promise<FacadeResult<V>> {
  const schemaVersion = await clusterSchemaVersion(engine, verb);
  const reply = await engine.mcp.callTool(verb, {
    schema_version: schemaVersion,
    consent: { policy_ref: "policy:retrieval-session", purpose: "retrieval clustering journey" },
    arguments: { spec: input },
  }) as { isError: boolean; structuredContent: { tool: string; output: FacadeResult<V> } };
  expect(reply.isError).toBe(false);
  expect(reply.structuredContent.tool).toBe(verb);
  return reply.structuredContent.output;
}

/* RETRIEVAL-10: MCP cohorts, rejected judgments, then receipted merge/split. */
/* RETRIEVAL-10 is a budget case: its full judgment journey (five claims, four structural puts, ten
 * MCP tool calls) exceeded the 30 s flow on gce-ci-2 (job 3, 10 Nov). Its stated bound is 90 s
 * until it is measured; it belongs to the nightly tier. */
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
}, 90_000);

async function retrieval11OwnerRefusal(engine: EngineFixture, client: PublicHttpClient,
  verb: "vault.claims.review" | "vault.claims.settle" | "vault.consolidation.evidence",
  input: unknown, actorRef: string, actorClass: "agent" | "human") {
  const reply = await client.raw<{ error: { code: string; message: string; receiptRef?: string } }>(
    "POST", `/v1/core/facade/${verb}`, input);
  expect(reply.status).toBe(403);
  expect(reply.body.error.code).toBe("FORBIDDEN");
  expect(reply.body.error.message).toBe(`${verb} is the vault owner's`);
  expect(reply.body.error.receiptRef).toMatch(/^call:[a-f0-9]{32}$/);
  expect(reply.headers.get("x-oneiron-receipt-ref")).toBe(reply.body.error.receiptRef!);
  const receipt = await engine.client.call("vault.receipts.get", {
    receipt_ref: reply.body.error.receiptRef!,
  });
  expect(receipt).not.toBeNull();
  expect(receipt!.receipt_ref).toBe(reply.body.error.receiptRef!);
  expect(receipt!.actor_ref).toBe(actorRef);
  expect(receipt!.actor_class).toBe(actorClass);
  expect(receipt!.transport).toBe("http_facade");
  expect(receipt!.outcome).toEqual({ refused: { code: "FORBIDDEN" } });
}

/* RETRIEVAL-11
 * Promise: An external agent's Generated claim becomes recall-visible after owner approval but remains ineligible as corroboration; an owner-stated human control is corroboration-eligible, an unapproved ToolOutput proposal is neither recall-visible nor admissible evidence, and these evidence decisions require the owner's own unattenuated credential.
 * Doors: agent upsert -> owner review/settle -> claims.list/evidence; review/settle/evidence refuse the agent, evidence refuses an attenuated owner, restart preserves the matrix, recall runs last.
 * Unproved: host-stamped Generated/Auto needs a genuine Dreamer run through vault.agents.spawn -> owned leased vault.agents.spawn.get -> self.run.attach -> vault.consolidation.promote, with its Auto grant/checker; a declared external source is not that producer.
 * Unproved: pending-critical Generated/Proposed needs a qualified public producer and vault.writes.critical_confirm.pending binding; Proposed alone is not an attached confirmation.
 * Unproved: consuming promotion/root accounting needs vault.consolidation.promote output evidence or vault.consolidation.pin/frontier/accounting under its grant; this case inspects eligibility only.
 * Unproved: outbound authority from prose needs vault.policy.outbound.decide and the consuming connector.call consent/grant door; effector_evidence_eligible is not permission to send.
 */
suite.test(test, "RETRIEVAL-11", "An external agent's Generated claim becomes recall-visible after owner approval but remains ineligible as corroboration; an owner-stated human control is corroboration-eligible, an unapproved ToolOutput proposal is neither recall-visible nor admissible evidence, and these evidence decisions require the owner's own unattenuated credential.", async () => {
  const fixture = await scenario<{
    readonly sources: { readonly label: string; readonly source: string }[];
  }>("RETRIEVAL-11");
  const toolSource = fixture.sources.find(row => row.label === "foreign-tool");
  expect(toolSource?.source).toBe("tool_output");
  const engine = await EngineFixture.start({ id: "RETRIEVAL-11", profile,
    serverConfig: "[models.dreamer]\nenabled = false\n[models.workflows]\nenabled = false\n" });
  let primaryFailed: boolean = false;
  let primary: unknown;
  try {
    const ownerRef = engine.pairedActor.principalRef;
    const scope = await ownerBaseClaimScope(engine.client, ownerRef);
    const created = await engine.client.call("vault.agents.create", {
      agent_def_ref: "10000000000000000000000000000012",
      definition: { agent_id: "r11_claim_author", display_name: "R11 claim author",
        desc: "External claim author for source-trust inspection", version: "1", ceiling: "auto" },
    });
    const agent = await engine.pairActor({ principalRef: created.agent_def_ref,
      actorClass: "agent", scope: ["core:read", "core:write"] });
    const identity = await agent.client.call("self.actor", {});
    expect(identity.actor_ref).toBe(created.agent_def_ref);
    expect(identity.actor_class).toBe("agent");
    const prompt = await witnessedText(engine,
      "Propose a short generated statement for source-trust inspection.", utc("2026-08-01T00:00:00Z"));
    // Fixed external-agent output, not a host-run model or a Generated/Auto fixture.
    const generated = await agent.client.call("vault.claims.upsert", {
      predicate: "profile.r11_generated", subject_ref: ownerRef,
      value: "r11marker amber generated assertion", confidence: 0.875,
      source: "generated", scope, sensitivity: 0,
      evidence_turn_refs: [prompt.witnessed.turn_short_id],
    });
    const tool = await agent.client.call("vault.claims.upsert", {
      predicate: "profile.r11_tool", subject_ref: ownerRef,
      value: "r11marker amber tool observation", confidence: 0.875,
      source: toolSource!.source, scope, sensitivity: 0, evidence_turn_refs: [],
    });
    expect(generated.approval).toBe("proposed");
    expect(tool.approval).toBe("proposed");
    expect(generated.claim).toBeTruthy();
    expect(tool.claim).toBeTruthy();
    const generatedId = generated.claim!.id;
    const toolId = tool.claim!.id;
    const gates = await engine.client.call("vault.receipts", { limit: 1000 });
    for (const [write, reasons] of [
      [generated, ["gate.pending.actor_ceiling", "gate.pending.source_trust"]],
      [tool, ["gate.pending.actor_ceiling"]],
    ] as const) {
      const gate = gates.receipts.find(row => row.receipt_ref === write.receipt_ref);
      expect(gate).toBeDefined();
      expect(gate!.outcome).toBe("pending");
      expect(gate!.actor_class).toBe("agent");
      expect(gate!.actor_ref).toBe(created.agent_def_ref);
      expect(gate!.claim_ref).toBe(write.claim!.id);
      expect(sorted(gate!.reason_codes)).toEqual(sorted(reasons));
    }
    const control = await claim(engine, scope, { predicate: "profile.r11_control",
      value: "r11marker amber owner statement", evidence_turn_refs: [] });
    expect(control.receipt.approval).toBe("auto");
    const retrieval11ReadClaims = async (generatedApproval: "proposed" | "approved") => {
      const rows = await claimSet(engine);
      for (const expected of [
        { claim_ref: generatedId, predicate: "profile.r11_generated", source: "generated",
          approval: generatedApproval, value: "r11marker amber generated assertion" },
        { claim_ref: toolId, predicate: "profile.r11_tool", source: "tool_output",
          approval: "proposed", value: "r11marker amber tool observation" },
        { claim_ref: control.id, predicate: "profile.r11_control", source: "user_stated",
          approval: "auto", value: "r11marker amber owner statement" },
      ]) {
        expect(rows.find(row => row.claim_ref === expected.claim_ref)).toMatchObject({
          ...expected, subject_ref: ownerRef, claim_scope: scope, confidence: 0.875,
          lifecycle: "active", stale: false,
        });
      }
    };
    const review = await engine.client.call("vault.claims.review", { claim_ref: generated.claim_short_id });
    expect(review.proposal_ref).toBe(generatedId);
    expect(review.opener_ref).toBe(created.agent_def_ref);
    expect(review.claim).toMatchObject({ claim_ref: generatedId, source: "generated", approval: "proposed" });
    await retrieval11OwnerRefusal(engine, agent.client, "vault.claims.review",
      { claim_ref: generated.claim_short_id }, created.agent_def_ref, "agent");
    const settlementInput: FacadeInput<"vault.claims.settle"> = {
      claim_ref: review.proposal_ref, review_id: review.review_id, decision: "approve",
    };
    await retrieval11OwnerRefusal(engine, agent.client, "vault.claims.settle",
      settlementInput, created.agent_def_ref, "agent");
    await retrieval11ReadClaims("proposed");
    const approved = await engine.client.call("vault.claims.settle", settlementInput);
    expect(approved.verdict).toBe("landed");
    expect(approved.reason).toBe("gate.claim.settle.approved");
    expect(approved.proposal_ref).toBe(generatedId);
    expect(approved.review_id).toBe(review.review_id);
    expect(approved.answered_by).toEqual({ kind: "word", person_ref: ownerRef });
    expect(approved.claim).toMatchObject({ claim_ref: generatedId, source: "generated",
      approval: "approved", lifecycle: "active", stale: false });
    await retrieval11ReadClaims("approved");
    const evidenceInput: FacadeInput<"vault.consolidation.evidence"> = {
      source_refs: [generatedId, toolId, control.id],
    };
    const retrieval11ReadEvidence = async () => {
      const read = await engine.client.call("vault.consolidation.evidence", evidenceInput);
      readReceipt(read.narrowing);
      expect(read.value).toHaveLength(3);
      for (const expected of [
        { source_ref: generatedId, source: "generated", approval: "approved", generated_origin: true,
          writer_ref: created.agent_def_ref, consolidation_eligible: true, corroboration_eligible: false,
          first_party_corroboration: false, effector_evidence_eligible: true, refusal: "generated_origin" },
        { source_ref: toolId, source: "tool_output", approval: "proposed", generated_origin: false,
          writer_ref: created.agent_def_ref, consolidation_eligible: false, corroboration_eligible: false,
          first_party_corroboration: false, effector_evidence_eligible: false, refusal: "not_surfaceable" },
        { source_ref: control.id, source: "user_stated", approval: "auto", generated_origin: false,
          writer_ref: ownerRef, consolidation_eligible: true, corroboration_eligible: true,
          first_party_corroboration: true, effector_evidence_eligible: true, refusal: null },
      ]) {
        expect(read.value.find(row => row.source_ref === expected.source_ref)).toMatchObject({
          ...expected, lifecycle: "active", evidence_taint: null, foreign_world_ref: null,
        });
      }
    };
    await retrieval11ReadEvidence();
    await retrieval11OwnerRefusal(engine, agent.client, "vault.consolidation.evidence",
      evidenceInput, created.agent_def_ref, "agent");
    const { seed } = credentialParts(engine.pairedActor.credential);
    const narrowed = await engine.client.call("self.credential.attenuate", {
      holder_seed: [...Buffer.from(seed, "hex")],
      caveat: { scope: { kind: "ceiling", scope: {
        worlds: { kind: "all" }, facets: { kind: "all" }, bands: { kind: "all" },
        audience: { kind: "all" }, verbs: { kind: "some", values: ["core:read"] },
        sensitivity: { kind: "all" },
      } } },
    });
    expect(narrowed.token.startsWith("v2.slip.")).toBe(true);
    const attenuatedOwner = new PublicHttpClient(engine.url, {
      credential: `v2.cred.${narrowed.token.slice(8)}.${seed}`, artifacts: engine.artifacts,
    });
    const narrowedIdentity = await attenuatedOwner.call("self.actor", {});
    expect(narrowedIdentity.actor_ref).toBe(ownerRef);
    expect(narrowedIdentity.actor_class).toBe("human");
    await retrieval11OwnerRefusal(engine, attenuatedOwner, "vault.consolidation.evidence",
      evidenceInput, ownerRef, "human");
    await engine.restart();
    await retrieval11ReadClaims("approved");
    await retrieval11ReadEvidence();

    // Last door: assert the promise despite the no-embedder publication defect (2026-11-10).
    const recallInput: FacadeInput<"vault.recall"> = {
      query: "r11marker amber", effort: "light", limit: 100, format: "md", token_budget: 8192,
      scope: { kinds: ["CLAIM"], worlds: { kind: "base" } },
    };
    const retrieval11Matches = (item: Facade.MemoryItem, id: string, shortRef: string) =>
      item.record?.id === id || item.short_id === shortRef;
    // The owner-stated control is lexically indexed at its own write, so it must be visible first;
    // only then is the approved Generated claim awaited, so a red names the right claim.
    await awaitPublic(() => engine.client.call("vault.recall", recallInput),
      value => value.items.some(item => retrieval11Matches(item, control.id, control.ref)),
      { timeoutMs: 5000, label: "owner-stated control visible in recall" });
    let pack: FacadeResult<"vault.recall">;
    const recallLabel = "approved Generated claim visible in recall";
    try {
      pack = await awaitPublic(() => engine.client.call("vault.recall", recallInput),
        value => value.items.some(item => retrieval11Matches(item, generatedId, generated.claim_short_id))
          && value.items.some(item => retrieval11Matches(item, control.id, control.ref)),
        { timeoutMs: 5000, label: recallLabel });
    } catch (error) {
      if (errorText(error).startsWith(`${recallLabel} deadline after 5000ms poll budget;`)) {
        throw new Error("approved Generated claim visible in recall: not published within 5000ms [DEFECT 2026-11-10]", { cause: error });
      }
      throw error;
    }
    readReceipt(pack.narrowing);
    expect(pack.items.find(item => retrieval11Matches(item, generatedId, generated.claim_short_id))!.provenance.source).toBe("generated");
    expect(pack.items.find(item => retrieval11Matches(item, control.id, control.ref))!.provenance.source).toBe("user_stated");
    expect(pack.items.some(item => retrieval11Matches(item, toolId, tool.claim_short_id))).toBe(false);
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

// Muse recall legs use the same public audit pager and WS refusal read-back.
type MuseRecallAuditRow = FacadeResult<"vault.authority.audit">["rows"][number];

async function museRecallAuditRows(client: PublicHttpClient): Promise<MuseRecallAuditRow[]> {
  const rows: MuseRecallAuditRow[] = [];
  let after: string | undefined;
  for (;;) {
    const page = await client.call("vault.authority.audit", {
      limit: 500, ...(after ? { after } : {}),
    });
    rows.push(...page.rows);
    if (!page.next_after) return rows;
    after = page.next_after;
  }
}

async function museRecallReadSetup(engine: EngineFixture, entityRef: string, kind: string): Promise<void> {
  const read = await engine.client.call("vault.get", { entity_ref: entityRef });
  expect(read.value?.kind).toBe(kind);
}

async function museRecallRefusalReceipt<V extends FacadeVerb>(
  engine: EngineFixture,
  actor: PairedActor,
  verb: V,
  input: FacadeInput<V>,
): Promise<void> {
  const socket = await engine.websocket(actor);
  let refused: WsRpcError | undefined;
  try {
    await socket.call(verb, input);
  } catch (error) {
    if (!(error instanceof WsRpcError)) throw error;
    refused = error;
  } finally {
    socket.close();
  }
  if (!refused) throw new Error("Wrong actor was not refused over WS");
  const receiptRef = refused.frames.map(frame => frame.envelope.receipt_ref)
    .find((ref): ref is string => typeof ref === "string" && ref.length > 0);
  if (!receiptRef) throw new Error("WS refusal carried no call receipt reference");
  const receipt = await awaitPublic(
    () => engine.client.call("vault.receipts.get", { receipt_ref: receiptRef }),
    value => value !== null,
    { label: "wrong-actor refusal call receipt" },
  );
  if (!receipt || receipt.outcome === "ok") throw new Error("Call receipt did not record the refusal");
  expect(receipt.verb).toBe(verb);
  expect(receipt.outcome.refused.code.length).toBeGreaterThan(0);
}

// A scoped actor's authenticated HTTP refusal states its call receipt in the
// error envelope and the x-oneiron-receipt-ref header (api/call_receipt.rs,
// OF-538). Read that receipt back as owner through vault.receipts.get; the
// HTTP reply is the refusal under test.
async function museRecallHttpRefusalReceipt(
  engine: EngineFixture,
  label: string,
  reply: { readonly status: number; readonly headers: Headers; readonly body: unknown },
  verb: FacadeVerb,
): Promise<void> {
  const wire = reply.body as {
    readonly error?: { readonly code?: unknown; readonly message?: unknown; readonly receiptRef?: unknown };
  };
  const errorCode = wire.error?.code;
  const code = typeof errorCode === "string" ? errorCode : "<none>";
  const errorMessage = wire.error?.message;
  const message = typeof errorMessage === "string" ? errorMessage : "<none>";
  const receiptRefValue = wire.error?.receiptRef;
  const receiptRef = typeof receiptRefValue === "string" && receiptRefValue.length > 0
    ? receiptRefValue : undefined;
  if (!receiptRef) {
    throw new Error(`${label} ${verb} HTTP refusal missing call receipt: status=${reply.status} code=${code} message=${message}`);
  }
  const header = reply.headers.get("x-oneiron-receipt-ref");
  if (header !== receiptRef) {
    throw new Error(`${label} ${verb} refusal receipt mismatch: status=${reply.status} code=${code} header=${header ?? "<none>"} receiptRef=${receiptRef}`);
  }
  const receipt = await awaitPublic(
    () => engine.client.call("vault.receipts.get", { receipt_ref: receiptRef }),
    value => value !== null,
    { label: `${label} ${verb} refusal call receipt ${receiptRef}` },
  );
  if (!receipt || receipt.outcome === "ok") {
    throw new Error(`${label} call receipt did not record the ${verb} refusal: status=${reply.status} code=${code} receiptRef=${receiptRef}`);
  }
  expect(receipt.verb).toBe(verb);
  expect(receipt.outcome.refused.code.length).toBeGreaterThan(0);
}

// MUSE-RECALL-01 — P-RECALL-001, P-RECALL-016 (drivable subset).
// Claims are seeded proposed, settled by the owner, retracted, marked stale,
// and superseded; list/history/filter read them back before recall and restart.
// Unproved P-RECALL-002: as_of anchors query time words, not a snapshot.
// No public historical recall pin or native claim-review Grant mint exists.
// Audit drops remove recall exclusion assertions; list_filtered still checks
// the state filter. Confidence/provenance and the versioned pack stay checked.

type MuseRecall01Client = EngineFixture["client"];
type MuseRecall01Scope = Awaited<ReturnType<typeof ownerBaseClaimScope>>;
type MuseRecall01ClaimView = FacadeResult<"vault.claims.list">["value"][number];
type MuseRecall01Pack = FacadeResult<"vault.recall">;
type MuseRecall01Item = MuseRecall01Pack["items"][number];

function museRecall01ClaimInput(
  scope: MuseRecall01Scope,
  subjectRef: string,
  predicate: string,
  sentinel: string,
  confidence: number,
  at: number,
): FacadeInput<"vault.claims.upsert"> {
  return {
    predicate,
    subject_ref: subjectRef,
    value: sentinel,
    confidence,
    source: "user_stated",
    scope,
    valid_from: at,
    occurred_at: at,
    learned_at: at,
  };
}

async function museRecall01Claims(
  client: MuseRecall01Client,
  subjectRef: string,
  predicate: string,
  lifecycle?: string,
): Promise<MuseRecall01ClaimView[]> {
  const page = await client.call("vault.claims.list", {
    subject_ref: subjectRef,
    predicate,
    limit: 100,
    ...(lifecycle ? { lifecycle } : {}),
  });
  return page.value;
}

function museRecall01Claim(
  claims: readonly MuseRecall01ClaimView[],
  sentinel: string,
): MuseRecall01ClaimView {
  const claim = claims.find((row) => row.value === sentinel);
  if (!claim) throw new Error(`MUSE-RECALL-01 claim not read back for ${sentinel}`);
  return claim;
}

function museRecall01HasClaim(
  claims: readonly MuseRecall01ClaimView[],
  sentinel: string,
): boolean {
  return claims.some((row) => row.value === sentinel);
}

function museRecall01ExpectClaimState(
  claim: MuseRecall01ClaimView,
  approval: string,
  lifecycle: string,
  stale: boolean,
  confidence: number,
): void {
  expect(claim.approval).toBe(approval);
  expect(claim.lifecycle).toBe(lifecycle);
  expect(claim.stale).toBe(stale);
  expect(Math.abs(claim.confidence - confidence) < 0.00001).toBe(true);
  expect(claim.source ?? "").toBe("user_stated");
}

function museRecall01Item(
  pack: MuseRecall01Pack,
  sentinel: string,
): MuseRecall01Item | undefined {
  return pack.items.find((item) => item.value_text.includes(sentinel));
}

function museRecall01ExpectItem(
  pack: MuseRecall01Pack,
  sentinel: string,
  confidence: number,
): MuseRecall01Item {
  const item = museRecall01Item(pack, sentinel)!;
  expect(Math.abs(item.confidence - confidence) < 0.00001).toBe(true);
  expect(item.confidence >= 0 && item.confidence <= 1).toBe(true);
  expect(item.provenance.source).toBe("user_stated");
  expect(Array.isArray(item.provenance.source_revision_ids)).toBe(true);
  expect(Array.isArray(item.provenance.evidence_turn_ids)).toBe(true);
  return item;
}

function museRecall01ExpectPackShape(pack: MuseRecall01Pack): void {
  expect(Number.isInteger(pack.pack_version)).toBe(true);
  expect(pack.pack_version).toBeGreaterThan(0);
  for (const item of pack.items) {
    expect(item.confidence >= 0 && item.confidence <= 1).toBe(true);
    expect(item.provenance.source.length).toBeGreaterThan(0);
    expect(Array.isArray(item.provenance.source_revision_ids)).toBe(true);
    expect(Array.isArray(item.provenance.evidence_turn_ids)).toBe(true);
  }
}

async function museRecall01AwaitPack(
  client: MuseRecall01Client,
  input: FacadeInput<"vault.recall">,
  included: readonly { readonly slot: string; readonly sentinel: string }[],
  label: string,
): Promise<MuseRecall01Pack> {
  const claimPublicationDeadlineMs = 3000;
  const pollLabel = `MUSE-RECALL-01 approved claim lexical publication (FIX 22964, fixed by #7032); ${label}`;
  const observed = await awaitPublic(
    async () => {
      let pack: MuseRecall01Pack;
      try {
        pack = await client.call("vault.recall", input);
      } catch (error) {
        if (!(error instanceof PublicHttpError)) throw error;
        const detail = error.error;
        throw new Error(
          `MUSE-RECALL-01 ${label} vault.recall: status=${error.reply.status} code=${detail?.code ?? "<none>"} message=${detail?.message ?? "<none>"} suggestion=${detail?.suggestions?.[0] ?? "<none>"}`,
          { cause: error },
        );
      }
      return {
        presence: included.map(({ slot, sentinel }) => ({
          slot, present: museRecall01Item(pack, sentinel) !== undefined,
        })),
        itemCount: pack.items.length,
        pack,
      };
    },
    value => value.presence.every(row => row.present),
    { timeoutMs: claimPublicationDeadlineMs, label: pollLabel },
  );
  return observed.pack;
}

function museRecall01Landed(
  row: FacadeResult<"vault.claims.seed">[number] | undefined,
): FacadeResult<"vault.claims.upsert"> {
  if (!row || row.outcome !== "landed") {
    throw new Error("MUSE-RECALL-01 seeded claim did not land");
  }
  return row;
}

async function museRecall01Upsert(
  engine: EngineFixture,
  input: FacadeInput<"vault.claims.upsert">,
): Promise<FacadeResult<"vault.claims.upsert">> {
  const receipt = await engine.client.call("vault.claims.upsert", input);
  expect(receipt.approval).toBe("auto");
  expect(receipt.claim_short_id.length).toBeGreaterThan(0);
  expect(receipt.receipt_ref.length).toBeGreaterThan(0);
  await engine.awaitReceipt(receipt.receipt_ref);
  return receipt;
}

async function museRecall01ExpectSettleRefused(
  engine: EngineFixture,
  client: MuseRecall01Client,
  input: FacadeInput<"vault.claims.settle">,
): Promise<string> {
  const reply = await client.raw<{ error: { code: string; message: string; receiptRef?: string } }>(
    "POST", "/v1/core/facade/vault.claims.settle", input,
  );
  expect(reply.status).toBe(403);
  expect(reply.body.error.code.length).toBeGreaterThan(0);
  expect(reply.body.error.message.length).toBeGreaterThan(0);
  const receiptRef = reply.body.error.receiptRef;
  if (!receiptRef) throw new Error("Settle refusal left no call receipt reference");
  const receipt = await awaitPublic(
    () => engine.client.call("vault.receipts.get", { receipt_ref: receiptRef }),
    value => value !== null,
    { label: "settle refusal call receipt" },
  );
  if (!receipt || receipt.outcome === "ok") throw new Error("Settle refusal receipt is not refused");
  expect(receipt.verb).toBe("vault.claims.settle");
  expect(receipt.outcome.refused.code.length).toBeGreaterThan(0);
  return receiptRef;
}

suite.test(test, "MUSE-RECALL-01", "Ordinary recall serves auto and approved active claims, the surfaceable claim list holds back proposed, rejected, retracted, stale and superseded ones, and the pack is versioned with confidence and provenance by default", async () => {
  const occurred = 1769947200;
  const food = "preference.food";
  const seedFood = "profile.food";
  const namePredicate = "profile.name";
  const query = "quokkafern";
  const autoSentinel = "quokkafern autoalpha";
  const approvedSentinel = "quokkafern approvedbeta";
  const proposedSentinel = "quokkafern proposedgamma";
  const rejectedSentinel = "quokkafern rejecteddelta";
  const retractedSentinel = "quokkafern retractedepsilon";
  const staleSentinel = "quokkafern stalezeta";
  const oldNameSentinel = "quokkafern oldeta";
  const newNameSentinel = "quokkafern newtheta";
  redactor.add(
    query, autoSentinel, approvedSentinel, proposedSentinel, rejectedSentinel,
    retractedSentinel, staleSentinel, oldNameSentinel, newNameSentinel,
  );

  const engine = await EngineFixture.start({ id: "MUSE-RECALL-01", profile });
  try {
    const ownerRef = engine.pairedActor.principalRef;
    const scope = await ownerBaseClaimScope(engine.client, ownerRef);
    const settle = async (
      label: string, input: FacadeInput<"vault.claims.settle">,
    ): Promise<FacadeResult<"vault.claims.settle">> => {
      try {
        return await engine.client.call("vault.claims.settle", input);
      } catch (error) {
        if (!(error instanceof PublicHttpError)) throw error;
        const detail = error.error;
        throw new Error(
          `MUSE-RECALL-01 owner settle ${label} actor=${ownerRef} predicate=${seedFood}: status=${error.reply.status} code=${detail?.code ?? "<none>"} message=${detail?.message ?? "<none>"} suggestion=${detail?.suggestions?.[0] ?? "<none>"} receiptRef=${typeof detail?.receiptRef === "string" ? detail.receiptRef : "<none>"}`,
          { cause: error },
        );
      }
    };

    const agentRecord = await engine.client.call("vault.structural.put", {
      kind: "PERSON",
      body: { name: "Muse Recall 01 agent" },
      occurred_at: occurred,
    } satisfies FacadeInput<"vault.structural.put">);
    await museRecallReadSetup(engine, agentRecord.entity_ref, "PERSON");
    const agent = await engine.pairActor({
      principalRef: agentRecord.id_hex,
      actorClass: "agent",
      scope: ["core:read", "core:write"],
    });

    // A different actor opens the proposals: an opener never settles its own.
    // Seed does not supersede; profile.* is Normal-labelled for owner approval.
    // The distinct auto/retracted/stale upserts below keep the set-valued food key.
    const seeded = await agent.client.call("vault.claims.seed", {
      claims: [
        museRecall01ClaimInput(scope, ownerRef, seedFood, approvedSentinel, 0.82, occurred),
        museRecall01ClaimInput(scope, ownerRef, seedFood, proposedSentinel, 0.73, occurred),
        museRecall01ClaimInput(scope, ownerRef, seedFood, rejectedSentinel, 0.64, occurred),
      ],
    } satisfies FacadeInput<"vault.claims.seed">);
    expect(seeded).toHaveLength(3);
    const approvedSeed = museRecall01Landed(seeded[0]);
    const proposedSeed = museRecall01Landed(seeded[1]);
    const rejectedSeed = museRecall01Landed(seeded[2]);
    for (const receipt of [approvedSeed, proposedSeed, rejectedSeed]) {
      expect(receipt.approval).toBe("proposed");
      await engine.awaitReceipt(receipt.receipt_ref);
    }

    // Observe the writes back through claims.list and the pending queue.
    let foodClaims = await museRecall01Claims(engine.client, ownerRef, seedFood);
    const approvedView0 = museRecall01Claim(foodClaims, approvedSentinel);
    museRecall01ExpectClaimState(approvedView0, "proposed", "active", false, 0.82);
    const proposedView0 = museRecall01Claim(foodClaims, proposedSentinel);
    museRecall01ExpectClaimState(proposedView0, "proposed", "active", false, 0.73);
    const rejectedView0 = museRecall01Claim(foodClaims, rejectedSentinel);
    museRecall01ExpectClaimState(rejectedView0, "proposed", "active", false, 0.64);
    const pending0 = await engine.client.call("vault.writes.pending", { limit: 100 });
    for (const [view, receipt] of [
      [approvedView0, approvedSeed],
      [proposedView0, proposedSeed],
      [rejectedView0, rejectedSeed],
    ] as const) {
      const candidates = [view.claim_ref, view.short_ref ?? "", receipt.claim_short_id];
      expect(pending0.some((row) => candidates.includes(row.claim_ref))).toBe(true);
    }

    // Wrong actor: an agent with no claim-settle grant is refused, and the
    // refusal leaves a call receipt independently readable by the owner.
    const approvedOwnerReview = await engine.client.call("vault.claims.review", {
      claim_ref: approvedView0.claim_ref,
    } satisfies FacadeInput<"vault.claims.review">);
    expect(approvedOwnerReview.review_id.length).toBeGreaterThan(0);
    expect(approvedOwnerReview.claim.value).toBe(approvedSentinel);
    expect(approvedOwnerReview.claim.approval).toBe("proposed");
    const refusalReceiptRef = await museRecall01ExpectSettleRefused(
      engine, agent.client,
      {
        claim_ref: approvedView0.claim_ref,
        review_id: approvedOwnerReview.review_id,
        decision: "approve",
      },
    );
    foodClaims = await museRecall01Claims(engine.client, ownerRef, seedFood);
    museRecall01ExpectClaimState(
      museRecall01Claim(foodClaims, approvedSentinel), "proposed", "active", false, 0.82,
    );

    // The owner's public review/settle door can approve the proposed claim.
    const approvedSettlement = await settle("approve proposed active claim", {
      claim_ref: approvedView0.claim_ref,
      review_id: approvedOwnerReview.review_id,
      decision: "approve",
    });
    expect(approvedSettlement.verdict).toBe("landed");
    expect(approvedSettlement.claim.approval).toBe("approved");
    await engine.awaitReceipt(approvedSettlement.receipt_ref);
    foodClaims = await museRecall01Claims(engine.client, ownerRef, seedFood);
    const approvedView = museRecall01Claim(foodClaims, approvedSentinel);
    museRecall01ExpectClaimState(approvedView, "approved", "active", false, 0.82);

    // The owner rejects the third proposed claim.
    const rejectedOwnerReview = await engine.client.call("vault.claims.review", {
      claim_ref: rejectedView0.claim_ref,
    } satisfies FacadeInput<"vault.claims.review">);
    const rejectedSettlement = await settle("reject proposed active claim", {
      claim_ref: rejectedView0.claim_ref,
      review_id: rejectedOwnerReview.review_id,
      decision: "reject",
    } satisfies FacadeInput<"vault.claims.settle">);
    expect(rejectedSettlement.verdict).toBe("rejected");
    expect(rejectedSettlement.claim.approval).toBe("rejected");
    await engine.awaitReceipt(rejectedSettlement.receipt_ref);
    const rejectedHistory = await engine.client.call("vault.claims.history", {
      claim_ref: rejectedView0.claim_ref,
    } satisfies FacadeInput<"vault.claims.history">);
    expect(museRecall01Claim(rejectedHistory.value, rejectedSentinel).approval).toBe("rejected");

    // Act: auto, retracted, stale and superseded claims.
    await museRecall01Upsert(
      engine, museRecall01ClaimInput(scope, ownerRef, food, autoSentinel, 0.91, occurred),
    );
    const retractedReceipt = await museRecall01Upsert(
      engine, museRecall01ClaimInput(scope, ownerRef, food, retractedSentinel, 0.95, occurred),
    );
    const staleReceipt = await museRecall01Upsert(
      engine, museRecall01ClaimInput(scope, ownerRef, food, staleSentinel, 0.86, occurred),
    );
    expect(retractedReceipt.claim_short_id.length).toBeGreaterThan(0);
    expect(staleReceipt.claim_short_id.length).toBeGreaterThan(0);
    foodClaims = await museRecall01Claims(engine.client, ownerRef, food);
    const autoView = museRecall01Claim(foodClaims, autoSentinel);
    museRecall01ExpectClaimState(autoView, "auto", "active", false, 0.91);
    const retractedView0 = museRecall01Claim(foodClaims, retractedSentinel);
    museRecall01ExpectClaimState(retractedView0, "auto", "active", false, 0.95);
    const staleView0 = museRecall01Claim(foodClaims, staleSentinel);
    museRecall01ExpectClaimState(staleView0, "auto", "active", false, 0.86);

    const retractReceipt = await engine.client.call("vault.claims.retract", {
      claim_ref: retractedView0.claim_ref,
    } satisfies FacadeInput<"vault.claims.retract">);
    expect(retractReceipt.receipt_ref.length).toBeGreaterThan(0);
    await engine.awaitReceipt(retractReceipt.receipt_ref);
    const retractedClaims = await museRecall01Claims(engine.client, ownerRef, food, "retracted");
    museRecall01ExpectClaimState(
      museRecall01Claim(retractedClaims, retractedSentinel), "auto", "retracted", false, 0.95,
    );

    const demoted = await engine.client.call("vault.claims.demote", {
      claim_ref: staleView0.claim_ref,
      action: { kind: "stale" },
    } satisfies FacadeInput<"vault.claims.demote">);
    expect(demoted.stale).toBe(true);
    await engine.awaitReceipt(demoted.receipt_ref);
    foodClaims = await museRecall01Claims(engine.client, ownerRef, food);
    museRecall01ExpectClaimState(
      museRecall01Claim(foodClaims, staleSentinel), "auto", "active", true, 0.86,
    );

    await museRecall01Upsert(
      engine, museRecall01ClaimInput(scope, ownerRef, namePredicate, oldNameSentinel, 0.77, occurred),
    );
    await museRecall01Upsert(
      engine,
      museRecall01ClaimInput(scope, ownerRef, namePredicate, newNameSentinel, 0.88, occurred + 60),
    );
    const nameClaims = await museRecall01Claims(engine.client, ownerRef, namePredicate);
    const newNameView = museRecall01Claim(nameClaims, newNameSentinel);
    museRecall01ExpectClaimState(newNameView, "auto", "active", false, 0.88);
    const nameHistory = await engine.client.call("vault.claims.history", {
      claim_ref: newNameView.claim_ref,
    } satisfies FacadeInput<"vault.claims.history">);
    museRecall01ExpectClaimState(
      museRecall01Claim(nameHistory.value, oldNameSentinel), "auto", "superseded", false, 0.77,
    );

    // Second door: the surfaceable-claims list admits exactly the states
    // ordinary recall may show, claim by claim.
    const surfaceableSeedFood = await engine.client.call("vault.claims.list_filtered", {
      subject_ref: ownerRef, predicate: seedFood, limit: 100,
    } satisfies FacadeInput<"vault.claims.list_filtered">);
    expect(museRecall01HasClaim(surfaceableSeedFood.value, approvedSentinel)).toBe(true);
    for (const sentinel of [proposedSentinel, rejectedSentinel]) {
      expect(museRecall01HasClaim(surfaceableSeedFood.value, sentinel)).toBe(false);
    }
    const surfaceableFood = await engine.client.call("vault.claims.list_filtered", {
      subject_ref: ownerRef,
      predicate: food,
      limit: 100,
    } satisfies FacadeInput<"vault.claims.list_filtered">);
    expect(museRecall01HasClaim(surfaceableFood.value, autoSentinel)).toBe(true);
    for (const sentinel of [retractedSentinel, staleSentinel]) {
      expect(museRecall01HasClaim(surfaceableFood.value, sentinel)).toBe(false);
    }
    const surfaceableNames = await engine.client.call("vault.claims.list_filtered", {
      subject_ref: ownerRef,
      predicate: namePredicate,
      limit: 100,
    } satisfies FacadeInput<"vault.claims.list_filtered">);
    expect(museRecall01HasClaim(surfaceableNames.value, newNameSentinel)).toBe(true);
    expect(museRecall01HasClaim(surfaceableNames.value, oldNameSentinel)).toBe(false);

    // P-RECALL-001 + P-RECALL-016: ordinary recall by default (no format and
    // no provenance/confidence flags exist to ask with).
    const liveInput: FacadeInput<"vault.recall"> = { query, effort: "light", limit: 50 };
    const included: readonly (readonly [string, string, number])[] = [
      [autoSentinel, food, 0.91],
      [approvedSentinel, seedFood, 0.82],
      [newNameSentinel, namePredicate, 0.88],
    ];
    const livePack = await museRecall01AwaitPack(
      engine.client, liveInput, included.map(([sentinel, predicate]) => ({ slot: predicate, sentinel })),
      "ordinary pack",
    );
    museRecall01ExpectPackShape(livePack);
    for (const [sentinel, predicate, confidence] of included) {
      museRecall01ExpectItem(livePack, sentinel, confidence);
    }
    // Survive a restart, then read every state again.
    await engine.restart();
    const livePackAfter = await museRecall01AwaitPack(
      engine.client, liveInput, included.map(([sentinel, predicate]) => ({ slot: predicate, sentinel })),
      "ordinary pack after restart",
    );
    museRecall01ExpectPackShape(livePackAfter);
    expect(livePackAfter.pack_version).toBe(livePack.pack_version);
    for (const [sentinel, predicate, confidence] of included) {
      museRecall01ExpectItem(livePackAfter, sentinel, confidence);
    }
    foodClaims = await museRecall01Claims(engine.client, ownerRef, food);
    museRecall01ExpectClaimState(
      museRecall01Claim(foodClaims, autoSentinel), "auto", "active", false, 0.91,
    );
    const seedFoodAfterRestart = await museRecall01Claims(engine.client, ownerRef, seedFood);
    museRecall01ExpectClaimState(
      museRecall01Claim(seedFoodAfterRestart, approvedSentinel), "approved", "active", false, 0.82,
    );
    museRecall01ExpectClaimState(
      museRecall01Claim(foodClaims, staleSentinel), "auto", "active", true, 0.86,
    );
    const refusalAfterRestart = await engine.client.call("vault.receipts.get", {
      receipt_ref: refusalReceiptRef,
    });
    if (!refusalAfterRestart || refusalAfterRestart.outcome === "ok") {
      throw new Error("Settle refusal was not durable across restart");
    }
    expect(refusalAfterRestart.outcome.refused.code.length).toBeGreaterThan(0);

    // Second surface: the same recall verb over the held socket.
    const socket = await engine.websocket();
    try {
      const socketPack = (await socket.call("vault.recall", liveInput)).value;
      museRecall01ExpectPackShape(socketPack);
      expect(socketPack.pack_version).toBe(livePack.pack_version);
      museRecall01ExpectItem(socketPack, autoSentinel, 0.91);
      museRecall01ExpectItem(socketPack, approvedSentinel, 0.82);
    } finally {
      socket.close();
    }

    await engine.artifacts.json("muse-recall01.json", {
      packVersion: livePack.pack_version,
      autoClaimRef: autoView.claim_ref,
      approvedClaimRef: approvedView.claim_ref,
      refusalReceiptRef,
    });
  } finally {
    await engine.close();
  }
});

// MUSE-RECALL-02 — promises P-RECALL-004..007 (all MUST), door: recall.
//   P-RECALL-004  Recall accepts light, medium, high, xhigh and max.
//   P-RECALL-005  Light recall makes no model call and requires no budget lease.
//   P-RECALL-006  At its deadline, recall returns the best pack ready so far.
//   P-RECALL-007  FIX 56 supersedes the old 1,000 clamp: limit=1,001
//                 is served whole over HTTP, WS and after restart, without
//                 limit_clamped=true (engine-20261111-e2e4-recall-contract 1=A).
//                 requested_result_rows=1_048_576; only above it, ask and serve.
// Doors used (public only): vault.structural.put + pairActor (agent setup),
// vault.conversations.create, vault.witness, vault.batch (1,002 PERSON memories),
// vault.get + vault.hydrate (second-door read-backs), vault.recall (HTTP and WS),
// vault.retrieval.hyde.pending (second door for "no model work queued"),
// vault.authority.audit + POST /v1/core/slips/revoke (grant loss + its
// audit receipt), engine.restart().
// Finished through existing doors: configured ScriptedProviders zero-call
// light control, and an unanswered HyDE host item forcing a deadline pack.
// Unproved: internal recall lease accounting (no retrieval-run lease field),
// full populated delivery above 1,048,576 (09 covers the cheap ask), and ranking quality.
// The enlarged flow has a stated 60 s bound and belongs to the nightly tier;
// The accompanying report gives the source-only timing estimate.

type MuseRecall02Pack = FacadeResult<"vault.recall">;
type MuseRecall02AuditRow = FacadeResult<"vault.authority.audit">["rows"][number];

const museRecall02OtherEfforts = ["medium", "high", "xhigh", "max"] as const;

function museRecall02Object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Expected a public JSON object (body withheld)");
  }
  return value as Record<string, unknown>;
}

function museRecall02Contains(pack: MuseRecall02Pack, token: string): boolean {
  return pack.items.some(item => item.value_text.includes(token)
    || Boolean(item.cited_messages?.some(message => message.value_text.includes(token))));
}

function museRecall02ExpectErrorEnvelope(body: unknown): void {
  const root = museRecall02Object(body);
  const error = museRecall02Object(root.error ?? root);
  expect(typeof error.code).toBe("string");
  expect(String(error.code).length).toBeGreaterThan(0);
  expect(typeof error.message).toBe("string");
  expect(String(error.message).length).toBeGreaterThan(0);
}

function museRecall02MintedSlip(
  before: readonly MuseRecall02AuditRow[],
  after: readonly MuseRecall02AuditRow[],
  holder: string,
): string {
  const existing = new Set(before.map(row => row.entry_hash));
  const minted = after.filter(row => !existing.has(row.entry_hash)
    && row.source_op === "slip_mint" && row.holder_ref === holder);
  expect(minted).toHaveLength(1);
  const slipId = minted[0]!.subject_ref;
  if (!slipId || !/^[a-f0-9]{64}$/.test(slipId)) {
    throw new Error("Minted slip audit row lacks a slip id");
  }
  return slipId;
}

suite.test(test, "MUSE-RECALL-02", "Recall takes the five effort levels, light makes no model call, a deadline returns the best pack so far, and a limit of 1,001 is served whole with no clamp flag", async () => {
  const providers = await ScriptedProviders.start({
    id: "muse-recall-02", origins: ["reranker"], steps: [],
  });
  let engine: EngineFixture | undefined;
  try {
    engine = await EngineFixture.start({ id: "MUSE-RECALL-02", profile,
      initArgs: ["--dimensions", "4"], serverConfig: rerankConfig(providers.urls.reranker!) });
    await museRecall02Flow(engine, providers);
  } catch (error) {
    if (!(error instanceof PublicHttpError)) throw error;
    const detail = error.error;
    throw new Error(
      `MUSE-RECALL-02 public flow: status=${error.reply.status} code=${detail?.code ?? "<none>"} message=${detail?.message ?? "<none>"} suggestion=${detail?.suggestions?.[0] ?? "<none>"}`,
      { cause: error },
    );
  } finally {
    try { await engine?.close(); } finally { await providers.close(); }
  }
}, 60_000);

function museRecall02ExpectBoolean(
  label: string,
  actual: boolean | undefined,
  expected: boolean,
  observation: unknown = null,
): void {
  try {
    expect(actual).toBe(expected);
  } catch (error) {
    throw new Error(
      `MUSE-RECALL-02 ${label}: expected=${expected} actual=${String(actual)} observation=${redactor.text(JSON.stringify(observation) ?? "<none>")}; ${errorText(error)}`,
      { cause: error },
    );
  }
}

function museRecall02ExpectWholePack(
  surface: string,
  requestedLimit: number,
  pack: MuseRecall02Pack,
): void {
  try {
    expect(pack.items.length).toBe(requestedLimit);
    expect(pack.retrieval_meta.limit_clamped).not.toBe(true);
    expect(new Set(pack.items.map(item => item.record?.id ?? item.short_id)).size).toBe(requestedLimit);
  } catch (error) {
    throw new Error(
      `MUSE-RECALL-02 full requested delivery (FIX 56; ruling engine-20261111-e2e4-recall-contract 1=A): surface=${surface} requested_limit=${requestedLimit} item_count=${pack.items.length} limit_clamped=${String(pack.retrieval_meta.limit_clamped)} retrieval_meta=${redactor.text(JSON.stringify(pack.retrieval_meta) ?? "<missing>")}; ${errorText(error)}`,
      { cause: error },
    );
  }
}

async function museRecall02Flow(engine: EngineFixture, providers: ScriptedProviders): Promise<void> {
  const occurred = 1769947200;
  // Generated sentinels only. The query carries queryToken alone, so a
  // refusal body may echo the query, but must never carry contentToken,
  // which exists only inside the witnessed content.
  const queryToken = `qorathil${secretHex(6)}`;
  const contentToken = `velunari${secretHex(6)}`;
  redactor.add(queryToken, contentToken);
  const seededContent = `The ${queryToken} marker mentions ${contentToken} once.`;

  // Agents first: the slip-mint audit diff needs a before snapshot.
  const auditBeforePairing = await museRecallAuditRows(engine.client);
  const readerRecord = await engine.client.call("vault.structural.put", {
    kind: "PERSON", body: { name: "Recall Reader Agent" }, occurred_at: occurred,
  });
  await museRecallReadSetup(engine, readerRecord.entity_ref, "PERSON");
  const reader = await engine.pairActor({
    principalRef: readerRecord.id_hex, actorClass: "agent",
    scope: ["core:read", "core:write"],
  });
  const writerRecord = await engine.client.call("vault.structural.put", {
    kind: "PERSON", body: { name: "Recall Writer Agent" }, occurred_at: occurred,
  });
  await museRecallReadSetup(engine, writerRecord.entity_ref, "PERSON");
  const writer = await engine.pairActor({
    principalRef: writerRecord.id_hex, actorClass: "agent",
    scope: ["core:write"],
  });
  const readerSlipId = museRecall02MintedSlip(
    auditBeforePairing,
    await museRecallAuditRows(engine.client),
    reader.principalRef,
  );

  // Act: seed one memory through the public witness door.
  const conversation = await engine.client.call("vault.conversations.create", {
    body: { members: [engine.pairedActor.principalRef, reader.principalRef, writer.principalRef] },
    occurred_start: occurred, occurred_end: occurred,
  });
  await museRecallReadSetup(engine, conversation.id, "CONVERSATION");
  const witnessed = await engine.client.call("vault.witness", {
    conversation_ref: conversation.id,
    occurred_at: occurred,
    messages: [{ author: "user", message_type: "text", is_visible: true, order: 0,
      content: seededContent }],
  } satisfies FacadeInput<"vault.witness">);

  expect(witnessed.message_short_ids.length).toBe(1);
  const messageRef = witnessed.message_short_ids[0];
  if (!messageRef) throw new Error("Witness returned no message reference");

  // Observe through a second door: read the write back with vault.get.
  const saved = await engine.client.call("vault.get", { entity_ref: messageRef });
  if (!saved.value) throw new Error("Witnessed message is not publicly readable");
  expect(museRecall02Object(saved.value.body).content).toBe(seededContent);

  // P-RECALL-005 (light, checked first so the HyDE queue diff is clean):
  // A reranker is configured, but its strict origin has no steps. No
  // budget lease was opened, and light must not contact that origin. awaitPublic repeats reads only, while
  // the indexed frontier catches up with the fresh witness write.
  const pendingBeforeLight = await engine.client.call("vault.retrieval.hyde.pending", {});
  const pendingBeforeLightIds = new Set(pendingBeforeLight.map(work => work.request_id));
  const lightPack = await awaitPublic(
    () => engine.client.call("vault.recall", {
      query: queryToken, effort: "light", limit: 10,
    } satisfies FacadeInput<"vault.recall">),
    pack => museRecall02Contains(pack, queryToken),
    { label: "MUSE-RECALL-02 witnessed memory present at light effort" },
  );
  museRecall02ExpectBoolean("owner light pack contains witnessed query token",
    museRecall02Contains(lightPack, queryToken), true,
    { itemCount: lightPack.items.length, partial: lightPack.retrieval_meta.partial ?? null });
  expect(lightPack.retrieval_meta.rerank?.status).not.toBe("applied");
  museRecall02ExpectBoolean("owner light limit=10 is not clamped",
    lightPack.retrieval_meta.limit_clamped ?? false, false);
  expect(providers.seenFixtureCalls).toHaveLength(0);
  // Paid efforts may use this one declared protocol after the zero-call check.
  // The transport requests every document's score, in batches of at most 50.
  // Bootstrap candidates can join the witness; one matching memory is not one document.
  const maxRerankBatchDocuments = 50;
  for (let documentCount = 1; documentCount <= maxRerankBatchDocuments; documentCount++) {
    providers.enqueue({
      id: `muse-recall-02-rerank-${documentCount}`, origin: "reranker", role: "reranker",
      purpose: "recall effort acceptance", standing: true,
      request: { method: "POST", path: "/v1/rerank", model: "retrieval-reranker",
        fields: { query: queryToken, top_n: documentCount } },
      response: { kind: "json", body: {
        results: Array.from({ length: documentCount }, (_, index) => ({ index, relevance_score: 0.9 })),
        usage: { total_tokens: 16 },
      } },
    });
  }
  const pendingAfterLight = await engine.client.call("vault.retrieval.hyde.pending", {});
  museRecall02ExpectBoolean("light recall enqueued no new HyDE work",
    pendingAfterLight.every(work => pendingBeforeLightIds.has(work.request_id)), true,
    { beforeCount: pendingBeforeLightIds.size, afterCount: pendingAfterLight.length,
      newWorkCount: pendingAfterLight.filter(work => !pendingBeforeLightIds.has(work.request_id)).length });

  // P-RECALL-004: every other level on the one dial is accepted and the
  // sole seeded match is still served. Containment of the only matching
  // memory at limit 10 is plumbing, not a ranking-quality claim.
  for (const effort of museRecall02OtherEfforts) {
    // Paid recall has no default engine deadline; stay below the 10s HTTP budget.
    const deadlineMs = 1500;
    let pack: MuseRecall02Pack;
    try {
      pack = await engine.client.call("vault.recall", {
        query: queryToken, effort, limit: 10, deadline_ms: deadlineMs,
      } satisfies FacadeInput<"vault.recall">);
    } catch (error) {
      if (error instanceof PublicHttpError) {
        const detail = error.error;
        throw new Error(
          `MUSE-RECALL-02 effort=${effort} deadline_ms=${deadlineMs} client_default_ms=10000: status=${error.reply.status} code=${detail?.code ?? "<none>"} message=${detail?.message ?? "<none>"} suggestion=${detail?.suggestions?.[0] ?? "<none>"}`,
          { cause: error },
        );
      }
      throw new Error(
        `MUSE-RECALL-02 effort=${effort} deadline_ms=${deadlineMs} client_default_ms=10000: ${error instanceof Error ? error.name : "unknown"}: ${errorText(error)}`,
        { cause: error },
      );
    }
    museRecall02ExpectBoolean(
      `effort=${effort} deadline_ms=${deadlineMs} pack contains witnessed query token`,
      museRecall02Contains(pack, queryToken), true,
      { itemCount: pack.items.length, partial: pack.retrieval_meta.partial ?? null,
        rerank: pack.retrieval_meta.rerank ?? null, fixtureCalls: providers.seenFixtureCalls.length,
        batches: providers.seenFixtureCalls.map(call => ({
          fixtureId: call.fixtureId,
          topN: call.body !== null && typeof call.body === "object"
            ? (call.body as { readonly top_n?: unknown }).top_n ?? null : null,
        })) });
  }

  // P-RECALL-005 for an agent: the reader holds a read slip but was never
  // given an agent grant or a spend lease; light still answers it.
  const callsBeforeReaderLight = providers.seenFixtureCalls.length;
  const readerPack = await reader.client.call("vault.recall", {
    query: queryToken, effort: "light", limit: 10,
  });
  museRecall02ExpectBoolean("read-scoped agent light pack contains witnessed query token",
    museRecall02Contains(readerPack, queryToken), true,
    { itemCount: readerPack.items.length, partial: readerPack.retrieval_meta.partial ?? null });
  expect(providers.seenFixtureCalls.length).toBe(callsBeforeReaderLight);

  // P-RECALL-006: hold a real public expansion work item until recall's
  // deadline. No sleep or private clock decides when the deadline lands.
  const binding: FacadeInput<"vault.retrieval.hyde.configure"> = { binding: {
    expander: "muse-recall-02-host", grounding: { bindings: {} },
    options: { channel_limit: 4, retry_once: false },
  } };
  await engine.client.call("vault.retrieval.hyde.configure", binding);
  expect(await engine.client.call("vault.retrieval.hyde.get", {})).toEqual(binding);
  const delivery = engine.client.call("vault.recall", {
    query: queryToken, effort: "high", limit: 10, deadline_ms: 1000,
  }).catch((error: unknown): never => {
    if (error instanceof PublicHttpError) {
      const detail = error.error;
      throw new Error(
        `MUSE-RECALL-02 held HyDE effort=high deadline_ms=1000 client_default_ms=10000: status=${error.reply.status} code=${detail?.code ?? "<none>"} message=${detail?.message ?? "<none>"} suggestion=${detail?.suggestions?.[0] ?? "<none>"}`,
        { cause: error },
      );
    }
    throw new Error(
      `MUSE-RECALL-02 held HyDE effort=high deadline_ms=1000 client_default_ms=10000: ${error instanceof Error ? error.name : "unknown"}: ${errorText(error)}`,
      { cause: error },
    );
  });
  void delivery.catch(() => {});
  const pending = await awaitPublic(
    () => engine.client.call("vault.retrieval.hyde.pending", { limit: 10 }),
    rows => rows.some(row => row.input.stage === "expansion"),
    { label: "MUSE-RECALL-02 expansion work pending at public HyDE host door" },
  );
  const held = pending.find(row => row.input.stage === "expansion")!;
  const deadlinePack = await delivery;
  museRecall02ExpectBoolean("held HyDE high deadline_ms=1000 pack reports partial",
    deadlinePack.retrieval_meta.partial, true,
    { itemCount: deadlinePack.items.length, rerank: deadlinePack.retrieval_meta.rerank ?? null });
  museRecall02ExpectBoolean("held HyDE deadline pack contains witnessed query token",
    museRecall02Contains(deadlinePack, queryToken), true,
    { itemCount: deadlinePack.items.length, partial: deadlinePack.retrieval_meta.partial ?? null });
  const lateAnswer = `${contentToken} late expansion`;
  const completion = await engine.client.call("vault.retrieval.hyde.complete", {
    request_id: held.request_id,
    answer: { stage: "expansion", expansion: {
      grounded_query: queryToken, hypothetical_answer: lateAnswer,
      embedding: [1, 0, 0, 0], subqueries: [queryToken],
    } },
  });
  expect(completion.status).toBe("discarded_deadline");
  expect(await engine.client.call("vault.retrieval.hyde.receipt", {
    request_id: held.request_id,
  })).toEqual(completion);
  await engine.client.call("vault.retrieval.hyde.configure", { binding: null });
  expect(await engine.client.call("vault.retrieval.hyde.get", {})).toEqual({ binding: null });

  // Wrong actor: a write-only credential cannot recall. Read its refused
  // call's receipt back as owner through vault.receipts.get.
  const writerInput: FacadeInput<"vault.recall"> = {
    query: queryToken, effort: "light", limit: 10,
  };
  const writerReply = await writer.client.raw("POST", "/v1/core/facade/vault.recall", writerInput);
  expect(writerReply.status).toBe(403);
  museRecall02ExpectErrorEnvelope(writerReply.body);
  museRecall02ExpectBoolean("write-only recall refusal does not leak witnessed content token",
    writerReply.raw.includes(contentToken), false, { status: writerReply.status });
  await museRecallHttpRefusalReceipt(engine, "MUSE-RECALL-02", writerReply, "vault.recall");
  // An unauthenticated caller is refused outright, with the envelope.
  const anonymous = new PublicHttpClient(engine.url, {
    artifacts: engine.artifacts, label: "muse-recall-02-anonymous",
  });
  const anonymousReply = await anonymous.raw("POST", "/v1/core/facade/vault.recall", {
    query: queryToken, effort: "light", limit: 10,
  });
  expect(anonymousReply.status).toBe(401);
  museRecall02ExpectErrorEnvelope(anonymousReply.body);
  museRecall02ExpectBoolean("anonymous recall refusal does not leak witnessed content token",
    anonymousReply.raw.includes(contentToken), false, { status: anonymousReply.status });

  // Lose the grant mid-flow: the owner revokes the reader's slip through
  // the public door; the reader's next recall is refused, the revoke is
  // read back in the authority audit, and the owner still recalls.
  await engine.requireHttpDoor("/v1/core/slips/revoke", "POST");
  const revoked = await engine.client.request<{ revoked: boolean }>("POST", "/v1/core/slips/revoke", {
    slip_id: Array.from(Buffer.from(readerSlipId, "hex")),
  });
  expect(revoked.status).toBe(200);
  museRecall02ExpectBoolean("owner revoke reply reports revoked",
    revoked.body.revoked, true, { status: revoked.status });
  const auditAfterRevoke = await museRecallAuditRows(engine.client);
  museRecall02ExpectBoolean("authority audit has fold-valid slip_revoke for reader slip",
    auditAfterRevoke.some(row => row.source_op === "slip_revoke"
      && row.subject_ref === readerSlipId && row.fold_valid), true,
    { auditRowCount: auditAfterRevoke.length });
  const revokedReaderReply = await reader.client.raw("POST", "/v1/core/facade/vault.recall", {
    query: queryToken, effort: "light", limit: 10,
  });
  expect(revokedReaderReply.status).toBe(401);
  museRecall02ExpectErrorEnvelope(revokedReaderReply.body);
  museRecall02ExpectBoolean("revoked reader recall refusal does not leak witnessed content token",
    revokedReaderReply.raw.includes(contentToken), false, { status: revokedReaderReply.status });
  const ownerControl = await engine.client.call("vault.recall", {
    query: queryToken, effort: "light", limit: 10,
  });
  museRecall02ExpectBoolean("owner light control after reader revoke contains witnessed query token",
    museRecall02Contains(ownerControl, queryToken), true);

  // One atomic public batch, not 1,002 witness turns or structural calls.
  // PERSON is a content kind: each distinct row becomes its own pack item,
  // without the MESSAGE-to-TURN fold. Keep paid/deadline probes on the small
  // corpus above; only the whole-limit light probes need this larger corpus.
  const corpusItemCount = 1002;
  const corpusTexts = Array.from({ length: corpusItemCount }, (_, index) =>
    `${queryToken} ${contentToken} corpus ${String(index).padStart(4, "0")}`);
  const corpusReceipt = await engine.client.call("vault.batch", {
    entities: corpusTexts.map(content => ({
      entity_type: 10, // PERSON, pinned registry type byte.
      occurred_start: occurred, occurred_end: occurred, learned_at: occurred,
      body: { name: content }, text: [{ field: "body", value: content }],
    })),
  } satisfies FacadeInput<"vault.batch">);
  expect(corpusReceipt.count).toBe(corpusItemCount);
  expect(corpusReceipt.entities).toHaveLength(corpusItemCount);
  const corpusIds = corpusReceipt.entities.map(entity => entity.id);
  // The write receipt is not proof: a separate public list read must return
  // every seeded row, its distinct id, and its exact indexed matching text.
  const corpusRead = await engine.client.call("vault.hydrate", { refs: corpusIds });
  expect(corpusRead.value).toHaveLength(corpusItemCount);
  expect(corpusRead.value.map(view => view.id_hex)).toEqual(corpusIds);
  expect(new Set(corpusRead.value.map(view => view.id_hex)).size).toBe(corpusItemCount);
  expect(corpusRead.value.every(view => view.kind === "PERSON")).toBe(true);
  expect(corpusRead.value.map(view => museRecall02Object(view.body).name)).toEqual(corpusTexts);

  // FIX 56 / ruling 1=A: isolate the row limit from the optional token budget.
  // token_budget=0 is the public uncut setting, not a changed engine default.
  const atLimitPack = await engine.client.call("vault.recall", {
    query: queryToken, effort: "light", limit: 1000, token_budget: 0,
  });
  museRecall02ExpectWholePack("HTTP vault.recall control", 1000, atLimitPack);
  const wholePack = await engine.client.call("vault.recall", {
    query: queryToken, effort: "light", limit: 1001, token_budget: 0,
  });
  museRecall02ExpectWholePack("HTTP vault.recall", 1001, wholePack);
  museRecall02ExpectBoolean("HTTP whole pack contains witnessed query token",
    museRecall02Contains(wholePack, queryToken), true);
  const socket = await engine.websocket();
  try {
    const wholeOverWs = (await socket.call("vault.recall", {
      query: queryToken, effort: "light", limit: 1001, token_budget: 0,
    })).value;
    museRecall02ExpectWholePack("WS vault.recall", 1001, wholeOverWs);
    museRecall02ExpectBoolean("WS whole pack contains witnessed query token",
      museRecall02Contains(wholeOverWs, queryToken), true);
  } finally { socket.close() }

  await engine.artifacts.json("muse-recall-02.json", {
    witnessReceipt: witnessed.receipt_ref,
    efforts: ["light", ...museRecall02OtherEfforts],
    lightRerank: lightPack.retrieval_meta.rerank ?? null,
    clampedAt1000: atLimitPack.retrieval_meta.limit_clamped ?? false,
    clampedAt1001: wholePack.retrieval_meta.limit_clamped ?? false,
    seededCorpusItems: corpusRead.value.length,
    servedAt1000: atLimitPack.items.length,
    servedAt1001: wholePack.items.length,
    deadlinePartial: deadlinePack.retrieval_meta.partial ?? null,
    deadlineHeldSeed: museRecall02Contains(deadlinePack, queryToken),
  });

  // Survive a restart: the memory, whole-limit delivery and the revocation all
  // read the same afterwards.
  await engine.restart();
  const callsBeforeRestartLight = providers.seenFixtureCalls.length;
  const savedAfterRestart = await engine.client.call("vault.get", { entity_ref: messageRef });
  if (!savedAfterRestart.value) throw new Error("Witnessed message is not publicly readable after restart");
  expect(museRecall02Object(savedAfterRestart.value.body).content).toBe(seededContent);
  const afterRestartPack = await awaitPublic(
    () => engine.client.call("vault.recall", {
      query: queryToken, effort: "light", limit: 10,
    } satisfies FacadeInput<"vault.recall">),
    pack => museRecall02Contains(pack, queryToken),
    { label: "MUSE-RECALL-02 witnessed memory present after restart" },
  );
  museRecall02ExpectBoolean("owner light pack after restart contains witnessed query token",
    museRecall02Contains(afterRestartPack, queryToken), true);
  const wholeAfterRestart = await engine.client.call("vault.recall", {
    query: queryToken, effort: "light", limit: 1001, token_budget: 0,
  });
  museRecall02ExpectWholePack("HTTP vault.recall after restart", 1001, wholeAfterRestart);
  expect(providers.seenFixtureCalls.length).toBe(callsBeforeRestartLight);
  const stillRevokedReply = await reader.client.raw("POST", "/v1/core/facade/vault.recall", {
    query: queryToken, effort: "light", limit: 10,
  });
  expect(stillRevokedReply.status).toBe(401);
  museRecall02ExpectErrorEnvelope(stillRevokedReply.body);
}

// MUSE-RECALL-09 — FIX 56, engine-20261111-e2e4-recall-contract 1=A.
// A sparse corpus suffices to cross requested_result_rows: the input count,
// not a million stored rows, raises the observation-only question. Read it
// through GET /v1/owner/wire-health, never a private telemetry/store read.
// The worker folds crossings every 15 s; the 60 s nightly bound covers that
// public read-only wait, setup, the refusal receipt, and restart.
// Unproved: delivery of 1,048,577 populated items and a human's answer to the ask.
interface MuseRecall09HealthChecks {
  readonly checks: readonly {
    readonly subject: string;
    readonly first_raised: number;
    readonly source: string;
    readonly crossing: Readonly<Record<string, unknown>>;
  }[];
}

suite.test(test, "MUSE-RECALL-09", "Recall above 1,048,576 records a limit question while serving available memories, refuses a write-only agent, and keeps the question and memory after restart", async () => {
  const providers = await ScriptedProviders.start({
    id: "muse-recall-09", origins: ["reranker"], steps: [],
  });
  let engine: EngineFixture | undefined;
  try {
    const activeEngine = await EngineFixture.start({ id: "MUSE-RECALL-09", profile,
      initArgs: ["--dimensions", "4"], serverConfig: rerankConfig(providers.urls.reranker!) });
    engine = activeEngine;
    const occurredAt = 1769947200;
    const requestedLimit = 1_048_577;
    const questionSubject = "limit:limits.requested_result_rows";
    const queryToken = `recallthreshold${secretHex(6)}`;
    const contentToken = `thresholdmemory${secretHex(6)}`;
    const content = `${queryToken} ${contentToken}`;
    redactor.add(queryToken, contentToken);
    await activeEngine.requireHttpDoor("/v1/owner/wire-health", "GET");
    const readHealth = async (): Promise<MuseRecall09HealthChecks> =>
      (await activeEngine.client.request<MuseRecall09HealthChecks>("GET", "/v1/owner/wire-health")).body;
    const before = await readHealth();
    expect(before.checks.some(check => check.subject === questionSubject)).toBe(false);

    const seeded = await activeEngine.client.call("vault.structural.put", {
      kind: "PERSON", body: { name: content },
      text_fields: [{ field: "body", value: content }], occurred_at: occurredAt,
    } satisfies FacadeInput<"vault.structural.put">);
    const saved = await activeEngine.client.call("vault.get", { entity_ref: seeded.entity_ref });
    if (!saved.value) throw new Error("MUSE-RECALL-09 seeded PERSON is not publicly readable");
    expect((saved.value.body as { readonly name?: unknown }).name).toBe(content);

    const writerRecord = await activeEngine.client.call("vault.structural.put", {
      kind: "PERSON", body: { name: "Recall Threshold Writer Agent" }, occurred_at: occurredAt,
    });
    await museRecallReadSetup(activeEngine, writerRecord.entity_ref, "PERSON");
    const writer = await activeEngine.pairActor({
      principalRef: writerRecord.id_hex, actorClass: "agent", scope: ["core:write"],
    });
    const request = {
      query: queryToken, effort: "light", limit: requestedLimit, token_budget: 0,
    } satisfies FacadeInput<"vault.recall">;
    const refusal = await writer.client.raw<{
      readonly error: { readonly code: string; readonly message: string };
    }>("POST", "/v1/core/facade/vault.recall", request);
    expect(refusal.status).toBe(403);
    expect(refusal.body.error.code.length).toBeGreaterThan(0);
    expect(refusal.body.error.message.length).toBeGreaterThan(0);
    expect(refusal.raw.includes(contentToken)).toBe(false);
    await museRecallHttpRefusalReceipt(activeEngine, "MUSE-RECALL-09", refusal, "vault.recall");

    // Act once above the threshold. A sparse result is not a count clamp:
    // retain the request count in the independent crossing read-back below.
    const pack = await activeEngine.client.call("vault.recall", request);
    try {
      expect(pack.items.some(item => item.value_text.includes(content))).toBe(true);
      expect(pack.retrieval_meta.limit_clamped).not.toBe(true);
    } catch (error) {
      throw new Error(
        `MUSE-RECALL-09 HTTP vault.recall requested_limit=${requestedLimit} item_count=${pack.items.length} limit_clamped=${String(pack.retrieval_meta.limit_clamped)} retrieval_meta=${redactor.text(JSON.stringify(pack.retrieval_meta))}; ${errorText(error)}`,
        { cause: error },
      );
    }
    const observed = await awaitPublic(
      readHealth,
      value => value.checks.some(check => check.subject === questionSubject
        && check.source === "limit"
        && check.crossing.row === "limits.requested_result_rows"
        && check.crossing.bound === 1_048_576
        && typeof check.crossing.observed === "number"
        && check.crossing.observed === requestedLimit),
      { timeoutMs: 25_000,
        label: `MUSE-RECALL-09 requested_limit=${requestedLimit} must serve and publish ${questionSubject} bound=1048576 observed=1048577` },
    );
    const question = observed.checks.find(check => check.subject === questionSubject);
    if (!question) throw new Error("MUSE-RECALL-09 observed limit question disappeared");
    expect(providers.seenFixtureCalls).toHaveLength(0);

    await activeEngine.restart();
    const savedAfterRestart = await activeEngine.client.call("vault.get", { entity_ref: seeded.entity_ref });
    if (!savedAfterRestart.value) throw new Error("MUSE-RECALL-09 seeded PERSON is absent after restart");
    expect((savedAfterRestart.value.body as { readonly name?: unknown }).name).toBe(content);
    const recalledAfterRestart = await activeEngine.client.call("vault.recall", {
      query: queryToken, effort: "light", limit: 10,
    });
    expect(recalledAfterRestart.items.some(item => item.value_text.includes(content))).toBe(true);
    // Do not cross the threshold again: this must be the durable earlier ask.
    const healthAfterRestart = await readHealth();
    const questionAfterRestart = healthAfterRestart.checks.find(check => check.subject === questionSubject);
    expect(questionAfterRestart?.source).toBe("limit");
    expect(questionAfterRestart?.first_raised).toBe(question.first_raised);
    expect(questionAfterRestart?.crossing.row).toBe("limits.requested_result_rows");
    expect(questionAfterRestart?.crossing.bound).toBe(1_048_576);
    expect(questionAfterRestart?.crossing.observed).toBe(question.crossing.observed);
    expect(providers.seenFixtureCalls).toHaveLength(0);
  } catch (error) {
    if (!(error instanceof PublicHttpError)) throw error;
    throw new Error(
      `MUSE-RECALL-09 requested_limit=1048577 public threshold/health/receipt flow: status=${error.reply.status} code=${error.error?.code ?? "<none>"} message=${error.error?.message ?? "<none>"} suggestion=${error.error?.suggestions?.[0] ?? "<none>"}`,
      { cause: error },
    );
  } finally {
    try { await engine?.close(); } finally { await providers.close(); }
  }
}, 60_000);

// MUSE-RECALL-03 (PARTIAL) — promises, doors, and what stays unproved.
// Promises (promise register wording, with the canon source for each):
// - P-RECALL-009: "A non-local search remains limited by the caller's Grants
//   at the home node." Source: retrieval.md#policy. NOT proved as written:
//   this case has one served vault and no second machine, so there is no
//   non-local leg. It proves the same grant limit locally (a reader without
//   the read scope is refused, and a reader who loses its credential is
//   refused at the next recall).
// - P-RECALL-010: "Results from different vaults are not blended into a
//   single top-k list." Source: ARCH-0004#world-scope. NOT proved across
//   vaults (no cross-vault door in this file; see the report). It proves the
//   partition mechanism that canon says also labels vaults: base and story
//   world hits are never interleaved unlabeled in one list.
// - P-RECALL-011: "World sections are labeled and presented base-first
//   within their budgets." Source: ARCH-0004#world-scope. Proved in the
//   typed pack (per-item world label, base group first) and in the rendered
//   pack: the claims are all about the vault owner, whose L2 prefix holds
//   the base claims only, and the story rows render after it as delta rows
//   labeled with the story world; the out-of-scope world is absent. The
//   story claims are written first, so claim-id order alone would put them
//   ahead (FIX-LIST [RECALL-L2-PREFIX-WORLDS-UNPARTITIONED], Engine ruling
//   E2E4-L2-WORLD-PARTITION = C). The
//   exact non-base budget fraction is not asserted: no typed door read here
//   lets the owner set or read that fraction. The fixture holds three base
//   claims beside the three story claims, so the default non-base share
//   (0.5) admits every story claim; the two extra base claims are longer
//   than the base sentinel claim, so the sentinel ranks first in base.
// - P-RECALL-014: "Owner-excluded worlds are omitted entirely from the
//   Context Board." Source: ARCH-0067#what. NOT proved: no typed owner
//   world-access grant/exclude door and no board render read for a paired
//   actor without a live run were found in the facade surface read here.
// - P-RECALL-017: "Recall distinguishes out-of-scope worlds from an absence
//   of memories." Source: ARCH-0044#s6-title. Proved for the requested
//   scope and a credential world ceiling: a base-only recall whose only match sits in the second story
//   world returns no such item and names that world in scope_honesty,
//   while an all-worlds recall for a token stored nowhere names none.
// Doors used, all public: vault.structural.put (act: mint WORLD/PERSON),
// vault.claims.upsert (act: scoped claims), vault.get and vault.claims.list
// (observe through a second door), vault.recall over HTTP and over WS,
// engine.pairActor (token pair), POST /v1/core/slips/revoke (owner revoke),
// vault.authority.audit and vault.receipts.get (refusal/revoke read-back),
// engine.restart (survival).
type museRecall03Pack = FacadeResult<"vault.recall">;
type museRecall03Item = museRecall03Pack["items"][number];
type museRecall03AuditRow = FacadeResult<"vault.authority.audit">["rows"][number];
type museRecall03ClaimRow = FacadeResult<"vault.claims.list">["value"][number];
interface museRecall03ErrorBody {
  readonly error?: {
    readonly code?: unknown;
    readonly message?: unknown;
    readonly suggestions?: unknown;
  };
}

const museRecall03Occurred = 1769947200;
const museRecall03Predicate = "decision.practical";

function museRecall03ItemsWith(pack: museRecall03Pack, token: string): museRecall03Item[] {
  return pack.items.filter((item) => item.value_text.includes(token));
}

function museRecall03HasSentinel(pack: museRecall03Pack, sentinel: string): boolean {
  return pack.items.some((item) => item.value_text.includes(sentinel));
}

function museRecall03NoSentinels(value: unknown, sentinels: readonly string[]): void {
  const text = JSON.stringify(value) ?? "";
  // Boolean form keeps sentinel text out of assertion diagnostics.
  expect(sentinels.every((sentinel) => !text.includes(sentinel))).toBe(true);
}

// A rendered toon pack's l2_base rows. serialize/l2_prefix.rs with_l2_prefix
// writes the first line as `l2_base: <JSON string of {content_hash, body}>`;
// body is the row array context_pack/l2_base.rs render_l2_rows_with_handles
// writes ({id, subj, pred, val, world}). A pack with no prefix has no rows.
function museRecall03RenderedL2Rows(rendered: string): Retrieval04L2Row[] {
  const tag = "l2_base: ";
  const head = rendered.split("\n", 1)[0] ?? "";
  if (!head.startsWith(tag)) return [];
  const summary = JSON.parse(JSON.parse(head.slice(tag.length)) as string) as { readonly body: string };
  return JSON.parse(summary.body) as Retrieval04L2Row[];
}

// The spellings an l2_base row's `world` takes for a WORLD: its short handle
// (the entity_ref before its ":<hash>"), or its id hex where no short handle
// resolves (l2_base.rs read_l2_handle).
function museRecall03WorldHandles(world: { readonly entity_ref: string; readonly id_hex: string }): string[] {
  const colon = world.entity_ref.lastIndexOf(":");
  return [colon > 0 ? world.entity_ref.slice(0, colon) : world.entity_ref, world.id_hex];
}

function museRecall03NamesWorld(
  listed: readonly string[],
  candidates: readonly string[],
): boolean {
  return listed.some((entry) => candidates.some(
    (candidate) => entry === candidate || entry.includes(candidate),
  ));
}

function museRecall03AssertBaseFirst(
  pack: museRecall03Pack,
  tokenCommon: string,
  baseSentinel: string,
  storySentinels: readonly string[],
): void {
  const hits = museRecall03ItemsWith(pack, tokenCommon);
  const baseIndex = hits.findIndex((item) => item.value_text.includes(baseSentinel));
  expect(baseIndex).toBeGreaterThanOrEqual(0);
  if (baseIndex < 0) throw new Error("Base sentinel claim missing from recall pack");
  for (const item of hits) {
    expect(typeof item.world).toBe("string");
    expect((item.world ?? "").length).toBeGreaterThan(0);
  }
  const baseLabel = hits[baseIndex]!.world;
  const storyLabels = new Set<string>();
  for (const sentinel of storySentinels) {
    const storyIndex = hits.findIndex((item) => item.value_text.includes(sentinel));
    if (storyIndex < 0) throw new Error("Story sentinel claim missing from recall pack");
    if (storyIndex < baseIndex) {
      // Slot order only: which world each matching item carries, never its text.
      const order = hits.map((item) => (item.value_text.includes(baseSentinel) ? "base" : item.world === baseLabel ? "base-world" : "story"));
      // FIX [RECALL-WORLD-PARTITION-ALL-SCOPE-ONLY], fixed by #7216.
      throw new Error(
        `MUSE-RECALL-03 P-RECALL-011 base section first (ARCH-0004 #world-scope): a story claim ranks before the base claim in a {story, include_base} recall; base_index=${baseIndex} story_index=${storyIndex} order=${JSON.stringify(order)}`,
      );
    }
    expect(storyIndex).toBeGreaterThan(baseIndex);
    const label = hits[storyIndex]!.world;
    expect(label === baseLabel).toBe(false);
    storyLabels.add(label ?? "");
  }
}

async function museRecall03OurClaimRows(
  client: PublicHttpClient,
  subjectRef: string,
  expectedWorldByValue: ReadonlyMap<string, string>,
): Promise<museRecall03ClaimRow[]> {
  const listed = await client.call("vault.claims.list", {
    subject_ref: subjectRef, predicate: museRecall03Predicate, limit: 50,
  } satisfies FacadeInput<"vault.claims.list">);
  return listed.value.filter((row) => {
    const value = row.value;
    return typeof value === "string" && expectedWorldByValue.has(value);
  });
}

function museRecall03ExpectClaimWorlds(
  rows: readonly museRecall03ClaimRow[],
  expectedWorldByValue: ReadonlyMap<string, string>,
): void {
  expect(rows).toHaveLength(expectedWorldByValue.size);
  for (const row of rows) {
    const value = row.value;
    if (typeof value !== "string") throw new Error("Read-back claim value is not text");
    const expectedWorld = expectedWorldByValue.get(value);
    if (expectedWorld === undefined) throw new Error(`Read-back claim value ${value} was not seeded`);
    expect(row.claim_scope.world_id).toBe(expectedWorld);
  }
}

suite.test(test, "MUSE-RECALL-03", "Recall partitions worlds base-first with labels, names an out-of-scope world instead of calling it empty, and refuses readers without or after losing read access", async () => {
  const engine = await EngineFixture.start({ id: "MUSE-RECALL-03", profile });
  try {
    const ownerRef = engine.pairedActor.principalRef;
    const tokenCommon = `lantern${secretHex(3)}`;
    const tokenOtherWorld = `quiet${secretHex(3)}`;
    const tokenNowhere = `nowhere${secretHex(3)}`;
    const baseSentinel = `base${secretHex(3)}`;
    const baseExtraSentinels = [`basex${secretHex(3)}`, `basey${secretHex(3)}`];
    const storySentinels = [`storya${secretHex(3)}`, `storyb${secretHex(3)}`, `storyc${secretHex(3)}`];
    const otherSentinel = `other${secretHex(3)}`;
    const storyWorldName = `Lantern Story ${secretHex(2)}`;
    const otherWorldName = `Quiet Story ${secretHex(2)}`;
    const readerName = `Recall Reader ${secretHex(2)}`;
    const writerName = `Recall Writer ${secretHex(2)}`;
    const sentinels = [
      tokenCommon, tokenOtherWorld, tokenNowhere, baseSentinel, ...baseExtraSentinels,
      ...storySentinels, otherSentinel, storyWorldName, otherWorldName,
      readerName, writerName,
    ];
    redactor.add(...sentinels);

    const baseScope = await ownerBaseClaimScope(engine.client, ownerRef);
    const storyWorld = await engine.client.call("vault.structural.put", {
      kind: "WORLD", body: { name: storyWorldName, kind: "fictional" },
      occurred_at: museRecall03Occurred,
    } satisfies FacadeInput<"vault.structural.put">);
    const otherWorld = await engine.client.call("vault.structural.put", {
      kind: "WORLD", body: { name: otherWorldName, kind: "fictional" },
      occurred_at: museRecall03Occurred,
    } satisfies FacadeInput<"vault.structural.put">);
    for (const world of [storyWorld, otherWorld]) {
      const readBack = await engine.client.call("vault.get", {
        entity_ref: world.entity_ref,
      } satisfies FacadeInput<"vault.get">);
      expect(readBack.value?.kind).toBe("WORLD");
      expect(readBack.value?.id_hex).toBe(world.id_hex);
    }

    const baseValue = `real harbor note ${tokenCommon} ${baseSentinel}`;
    const baseExtraValues = baseExtraSentinels.map(
      (sentinel) => `real harbor note kept beside the quay through a long grey evening ${tokenCommon} ${sentinel}`,
    );
    const storyValues = storySentinels.map(
      (sentinel) => `story harbor note ${tokenCommon} ${tokenCommon} ${sentinel}`,
    );
    const otherValue = `quiet harbor note ${tokenOtherWorld} ${otherSentinel}`;
    const expectedWorldByValue = new Map<string, string>([
      [baseValue, baseScope.world_id],
      ...baseExtraValues.map((value): [string, string] => [value, baseScope.world_id]),
      ...storyValues.map((value): [string, string] => [value, storyWorld.id_hex]),
      [otherValue, otherWorld.id_hex],
    ]);
    // Story claims first: their claim ids (clock-ordered) sort before the
    // base claims', so only the world partition renders the base rows first.
    const claimInputs: FacadeInput<"vault.claims.upsert">[] = [
      ...storyValues.map((value): FacadeInput<"vault.claims.upsert"> => ({
        predicate: museRecall03Predicate, subject_ref: ownerRef, value,
        confidence: 1, source: "user_stated",
        scope: { ...baseScope, world_id: storyWorld.id_hex },
        occurred_at: museRecall03Occurred,
      })),
      ...[baseValue, ...baseExtraValues].map((value): FacadeInput<"vault.claims.upsert"> => ({
        predicate: museRecall03Predicate, subject_ref: ownerRef, value,
        confidence: 1, source: "user_stated", scope: baseScope,
        occurred_at: museRecall03Occurred,
      })),
      {
        predicate: museRecall03Predicate, subject_ref: ownerRef, value: otherValue,
        confidence: 1, source: "user_stated",
        scope: { ...baseScope, world_id: otherWorld.id_hex },
        occurred_at: museRecall03Occurred,
      },
    ];
    const claimShortIds: string[] = [];
    for (const input of claimInputs) {
      const receipt = await engine.client.call("vault.claims.upsert", input);
      expect(receipt.claim_short_id.length).toBeGreaterThan(0);
      claimShortIds.push(receipt.claim_short_id);
      await engine.awaitReceipt(receipt.receipt_ref);
    }
    const seededRows = await museRecall03OurClaimRows(engine.client, ownerRef, expectedWorldByValue);
    museRecall03ExpectClaimWorlds(seededRows, expectedWorldByValue);
    const seededStates = [baseValue, ...storyValues, otherValue].map((value, index) => {
      const row = seededRows.find(candidate => candidate.value === value);
      return { slot: index === 0 ? "base" : index === storyValues.length + 1 ? "other" : `story${index - 1}`,
        approval: row?.approval ?? null, lifecycle: row?.lifecycle ?? null,
        stale: row?.stale ?? null, world: row?.claim_scope.world_id ?? null };
    });
    const supersededStories = seededStates.filter(row => row.slot.startsWith("story")
      && row.lifecycle === "superseded");
    const recall = async (input: FacadeInput<"vault.recall">): Promise<museRecall03Pack> => {
      try {
        return await engine.client.call("vault.recall", input);
      } catch (error) {
        if (!(error instanceof PublicHttpError)) throw error;
        const detail = error.error;
        throw new Error(
          `MUSE-RECALL-03 vault.recall: status=${error.reply.status} code=${detail?.code ?? "<none>"} message=${detail?.message ?? "<none>"} suggestion=${detail?.suggestions?.[0] ?? "<none>"}`,
          { cause: error },
        );
      }
    };

    const partitionInput: FacadeInput<"vault.recall"> = {
      query: tokenCommon, effort: "light", limit: 10,
      scope: {
        worlds: { kind: "worlds", world_refs: [storyWorld.id_hex], include_base: true },
      },
    };
    const awaitPartition = async (label: string): Promise<museRecall03Pack> => {
      let lastPresence: { basePresent: boolean; storyPresent: boolean[]; itemCount: number } | null = null;
      try {
        const observed = await awaitPublic(
          async () => {
            const pack = await recall(partitionInput);
            const presence = {
              basePresent: museRecall03HasSentinel(pack, baseSentinel),
              storyPresent: storySentinels.map(sentinel => museRecall03HasSentinel(pack, sentinel)),
              itemCount: pack.items.length,
            };
            lastPresence = presence;
            return { presence, pack };
          },
          value => value.presence.basePresent && value.presence.storyPresent.every(Boolean),
          { label },
        );
        return observed.pack;
      } catch (error) {
        const prefix = supersededStories.length > 0
          ? "MUSE-RECALL-03 canon-multi decision.practical was auto-superseded again (FIX 8794 residual, fixed by #7055)"
          : "MUSE-RECALL-03 partition recall";
        throw new Error(
          `${prefix}; last presence=${JSON.stringify(lastPresence)}; seeded states=${JSON.stringify(seededStates)}; ${errorText(error)}`,
          { cause: error },
        );
      }
    };
    const httpPack = await awaitPartition("MUSE-RECALL-03 indexed base and story claims");
    museRecall03AssertBaseFirst(httpPack, tokenCommon, baseSentinel, storySentinels);
    expect(museRecall03HasSentinel(httpPack, otherSentinel)).toBe(false);

    const ownerSocket = await engine.websocket();
    try {
      const wsPack = (await ownerSocket.call("vault.recall", partitionInput)).value;
      museRecall03AssertBaseFirst(wsPack, tokenCommon, baseSentinel, storySentinels);
    } finally {
      ownerSocket.close();
    }

    const limitedPack = await recall({
      ...partitionInput, limit: 2,
    });
    expect(museRecall03HasSentinel(limitedPack, baseSentinel)).toBe(true);

    const renderedPack = await recall({
      ...partitionInput, format: "toon",
    });
    expect(typeof renderedPack.rendered).toBe("string");
    const rendered = renderedPack.rendered ?? "";
    // P-RECALL-011 in the rendered pack. Every claim here is about the vault
    // owner, an L2 subject. The L2 prefix (the toon pack's first line,
    // serialize/l2_prefix.rs) is the owner's base-reality profile: it holds
    // the base claims and no claim of a named world (pipeline/l2_evidence.rs).
    // The story claims are delta rows, which the pack partitions base-first
    // and labels with their world (#7304: `world_section`, the story world's
    // id hex). So each story row renders after the last base row, with the
    // story world named between them.
    const l2Rows = museRecall03RenderedL2Rows(rendered);
    const l2RowWith = (sentinel: string) => l2Rows.find(
      (row) => (JSON.stringify(row.val) ?? "").includes(sentinel),
    );
    const storyWorldHandles = museRecall03WorldHandles(storyWorld);
    const renderedBaseSentinels = [baseSentinel, ...baseExtraSentinels];
    const basePositions = renderedBaseSentinels.map((sentinel) => rendered.indexOf(sentinel));
    const storyPositions = storySentinels.map((sentinel) => rendered.indexOf(sentinel));
    const lastBase = Math.max(...basePositions);
    const storyLabelled = storyPositions.map((at) => at > lastBase
      && storyWorldHandles.some((handle) => rendered.slice(lastBase, at).includes(handle)));
    const l2BaseRows = renderedBaseSentinels.filter((sentinel) => l2RowWith(sentinel) !== undefined).length;
    const l2StoryRows = storySentinels.filter((sentinel) => l2RowWith(sentinel) !== undefined).length;
    const l2WorldRows = l2Rows.filter((row) => row.world !== null).length;
    const renderedPartitioned = l2BaseRows === renderedBaseSentinels.length
      && l2StoryRows === 0 && l2WorldRows === 0
      && basePositions.every((at) => at >= 0)
      && storyLabelled.every(Boolean);
    if (!renderedPartitioned) {
      // Positions and counts only, never text: rows carry redacted sentinels.
      throw new Error(`MUSE-RECALL-03 the rendered recall pack (format=toon) does not render the owner's base claims first, in its L2 prefix, with the story rows labeled after them; rendered_head=${JSON.stringify(rendered.slice(0, 12))} l2_rows=${l2Rows.length} l2_base_rows=${l2BaseRows} l2_story_rows=${l2StoryRows} l2_world_rows=${l2WorldRows} base_positions=${JSON.stringify(basePositions)} story_positions=${JSON.stringify(storyPositions)} story_labelled=${JSON.stringify(storyLabelled)} rendered_chars=${rendered.length}`);
    }
    // The out-of-scope world's claim is in no part of the rendered pack.
    expect(rendered.includes(otherSentinel)).toBe(false);

    const otherOnlyInput: FacadeInput<"vault.recall"> = {
      query: tokenOtherWorld, effort: "light", limit: 10,
      scope: {
        worlds: { kind: "world", world_ref: otherWorld.id_hex, include_base: false },
      },
    };
    const otherPack = await awaitPublic(
      () => engine.client.call("vault.recall", otherOnlyInput),
      (pack) => museRecall03HasSentinel(pack, otherSentinel),
      { label: "MUSE-RECALL-03 indexed other-world claim" },
    );
    expect(museRecall03HasSentinel(otherPack, otherSentinel)).toBe(true);

    const baseOnlyPack = await recall({
      query: tokenOtherWorld, effort: "light", limit: 10,
      scope: { worlds: { kind: "base" } },
    } satisfies FacadeInput<"vault.recall">);
    expect(museRecall03HasSentinel(baseOnlyPack, otherSentinel)).toBe(false);
    expect(museRecall03NamesWorld(
      baseOnlyPack.scope_honesty.out_of_scope_worlds,
      [otherWorld.id_hex, otherWorld.entity_ref, otherWorldName],
    )).toBe(true);

    const { seed } = credentialParts(engine.pairedActor.credential);
    const narrowed = await engine.client.call("self.credential.attenuate", {
      holder_seed: [...Buffer.from(seed, "hex")],
      caveat: { scope: { kind: "ceiling", scope: {
        worlds: { kind: "some", values: [baseScope.world_id] },
        facets: { kind: "all" }, bands: { kind: "all" }, audience: { kind: "all" },
        verbs: { kind: "some", values: ["core:read"] }, sensitivity: { kind: "all" },
      } } },
    });
    if (!narrowed.token.startsWith("v2.slip.")) throw new Error("Expected an attenuated public slip");
    const ceilingReader = new PublicHttpClient(engine.url, {
      credential: `v2.cred.${narrowed.token.slice(8)}.${seed}`, artifacts: engine.artifacts,
    });
    const ceilingInput: FacadeInput<"vault.recall"> = {
      query: tokenOtherWorld, effort: "light", limit: 10, scope: { worlds: { kind: "all" } },
    };
    const ceilingPack = await ceilingReader.call("vault.recall", ceilingInput);
    expect(museRecall03HasSentinel(ceilingPack, otherSentinel)).toBe(false);
    expect(museRecall03NamesWorld(ceilingPack.scope_honesty.out_of_scope_worlds,
      [otherWorld.id_hex, otherWorld.entity_ref, otherWorldName])).toBe(false);
    const ceilingBase = await ceilingReader.call("vault.recall", {
      query: tokenCommon, effort: "light", limit: 10,
    });
    expect(museRecall03HasSentinel(ceilingBase, baseSentinel)).toBe(true);

    const nowherePack = await recall({
      query: tokenNowhere, effort: "light", limit: 10,
      scope: { worlds: { kind: "all" } },
    } satisfies FacadeInput<"vault.recall">);
    expect(museRecall03ItemsWith(nowherePack, tokenNowhere)).toHaveLength(0);
    expect(nowherePack.scope_honesty.out_of_scope_worlds).toHaveLength(0);

    const auditBeforeReader = await museRecallAuditRows(engine.client);
    const readerRecord = await engine.client.call("vault.structural.put", {
      kind: "PERSON", body: { name: readerName },
      occurred_at: museRecall03Occurred,
    } satisfies FacadeInput<"vault.structural.put">);
    await museRecallReadSetup(engine, readerRecord.entity_ref, "PERSON");
    const reader: PairedActor = await engine.pairActor({
      principalRef: readerRecord.id_hex, actorClass: "agent", scope: ["core:read"],
    });
    const auditAfterReader = await museRecallAuditRows(engine.client);
    const knownEntries = new Set(auditBeforeReader.map((row) => row.entry_hash));
    const readerMints = auditAfterReader.filter((row) => !knownEntries.has(row.entry_hash)
      && row.source_op === "slip_mint" && row.holder_ref === reader.principalRef);
    expect(readerMints).toHaveLength(1);
    const readerSlip = readerMints[0]!.subject_ref;
    if (typeof readerSlip !== "string" || !/^[a-f0-9]{64}$/.test(readerSlip)) {
      throw new Error("Reader slip mint carries no slip reference");
    }

    const readerPack = await reader.client.call("vault.recall", {
      query: tokenCommon, effort: "light", limit: 10,
    } satisfies FacadeInput<"vault.recall">);
    expect(museRecall03HasSentinel(readerPack, baseSentinel)).toBe(true);

    const writerRecord = await engine.client.call("vault.structural.put", {
      kind: "PERSON", body: { name: writerName },
      occurred_at: museRecall03Occurred,
    } satisfies FacadeInput<"vault.structural.put">);
    await museRecallReadSetup(engine, writerRecord.entity_ref, "PERSON");
    const writeOnly: PairedActor = await engine.pairActor({
      principalRef: writerRecord.id_hex, actorClass: "agent", scope: ["core:write"],
    });
    const refusedInput: FacadeInput<"vault.recall"> = {
      query: tokenCommon, effort: "light", limit: 10,
    };
    const refusedHttp = await writeOnly.client.raw<museRecall03ErrorBody>(
      "POST", "/v1/core/facade/vault.recall", refusedInput,
    );
    expect(refusedHttp.status).toBe(403);
    expect(typeof refusedHttp.body.error?.code).toBe("string");
    expect(typeof refusedHttp.body.error?.message).toBe("string");
    museRecall03NoSentinels(refusedHttp.body, sentinels);

    let refusalReceiptRef: string | undefined;
    const writerSocket = await WsClient.connect(engine.url, writeOnly.credential);
    try {
      await writerSocket.call("vault.recall", refusedInput);
      throw new Error("Write-only agent recall over WS was not refused");
    } catch (error) {
      if (!(error instanceof WsRpcError)) throw error;
      for (const frame of error.frames) {
        const ref = frame.envelope.receipt_ref;
        if (typeof ref === "string" && ref.length > 0) {
          refusalReceiptRef = ref;
          break;
        }
      }
    } finally {
      writerSocket.close();
    }
    if (!refusalReceiptRef) throw new Error("WS recall refusal carried no receipt reference");
    const refusalReceipt = await awaitPublic(
      () => engine.client.call("vault.receipts.get", { receipt_ref: refusalReceiptRef! }),
      value => value !== null,
      { label: "recall refusal call receipt" },
    );
    if (!refusalReceipt) throw new Error("Refused recall left no readable call receipt");
    const refusalOutcome = refusalReceipt.outcome;
    if (refusalOutcome === "ok") {
      throw new Error("Refused recall call receipt does not record a refusal");
    }
    expect(refusalOutcome.refused.code.length).toBeGreaterThan(0);
    expect(refusalReceipt.served).toHaveLength(0);

    const revoked = await engine.client.request<{ revoked: boolean }>(
      "POST", "/v1/core/slips/revoke",
      { slip_id: Array.from(Buffer.from(readerSlip, "hex")) },
    );
    expect(revoked.status).toBe(200);
    expect(revoked.body.revoked).toBe(true);
    const readerAfterRevoke = await reader.client.raw<museRecall03ErrorBody>(
      "POST", "/v1/core/facade/vault.recall", refusedInput,
    );
    expect(readerAfterRevoke.status).toBe(401);
    expect(typeof readerAfterRevoke.body.error?.code).toBe("string");
    museRecall03NoSentinels(readerAfterRevoke.body, sentinels);
    const auditAfterRevoke = await museRecallAuditRows(engine.client);
    expect(auditAfterRevoke.some((row) => row.source_op === "slip_revoke"
      && row.subject_ref === readerSlip && row.fold_valid)).toBe(true);

    await engine.restart();

    museRecall03ExpectClaimWorlds(
      await museRecall03OurClaimRows(engine.client, ownerRef, expectedWorldByValue),
      expectedWorldByValue,
    );
    const afterRestartPack = await awaitPartition("MUSE-RECALL-03 post-restart partitioned recall");
    museRecall03AssertBaseFirst(
      afterRestartPack, tokenCommon, baseSentinel, storySentinels,
    );
    const ceilingAfterRestart = await ceilingReader.call("vault.recall", ceilingInput);
    expect(museRecall03HasSentinel(ceilingAfterRestart, otherSentinel)).toBe(false);
    expect(museRecall03NamesWorld(ceilingAfterRestart.scope_honesty.out_of_scope_worlds,
      [otherWorld.id_hex, otherWorld.entity_ref, otherWorldName])).toBe(false);
    const readerAfterRestart = await reader.client.raw<museRecall03ErrorBody>(
      "POST", "/v1/core/facade/vault.recall", refusedInput,
    );
    expect(readerAfterRestart.status).toBe(401);
    museRecall03NoSentinels(readerAfterRestart.body, sentinels);

    await engine.artifacts.json("muse-recall-03.json", {
      worlds: { story: storyWorld.id_hex, other: otherWorld.id_hex },
      claimShortIds,
      refusalReceiptRef,
      readerSlip,
    });
  } finally {
    await engine.close();
  }
});

type MuseRecall04Pack = FacadeResult<"vault.recall">;
type MuseRecall04RunEvidence = FacadeResult<"vault.retrieval.runs">[number];
type MuseRecall04AuditRow = FacadeResult<"vault.authority.audit">["rows"][number];

interface MuseRecall04Refusal {
  error?: { code?: unknown; message?: unknown };
}

function museRecall04PackHas(pack: MuseRecall04Pack, marker: string): boolean {
  return pack.items.some((item) => item.value_text.includes(marker));
}

// Trace capture is owner-enabled below; only this pack's run is evidence.
async function museRecall04RunForPack(
  engine: EngineFixture,
  pack: MuseRecall04Pack,
  _wantEmpty: boolean,
): Promise<MuseRecall04RunEvidence | null> {
  if (!pack.retrieval_run_id) return null;
  return engine.client.call("vault.retrieval.run", { run_id: pack.retrieval_run_id });
}

function museRecall04MintedSlip(
  before: readonly MuseRecall04AuditRow[],
  after: readonly MuseRecall04AuditRow[],
  holder: string,
): string {
  const existing = new Set(before.map((row) => row.entry_hash));
  const minted = after.filter((row) => !existing.has(row.entry_hash)
    && row.source_op === "slip_mint" && row.holder_ref === holder);
  expect(minted).toHaveLength(1);
  const row = minted[0]!;
  expect(row.fold_valid).toBe(true);
  if (!row.subject_ref) throw new Error("Minted slip audit row has no subject reference");
  return row.subject_ref;
}

function museRecall04ExpectRefusal(
  reply: { readonly status: number; readonly body: MuseRecall04Refusal },
  expectedStatus: number,
): void {
  expect(reply.status).toBe(expectedStatus);
  const code = reply.body?.error?.code;
  const message = reply.body?.error?.message;
  expect(typeof code === "string" && code.length > 0).toBe(true);
  expect(typeof message === "string" && message.length > 0).toBe(true);
}

// MUSE-RECALL-04 — PARTIAL case for three promises:
//   P-RECALL-012 (MUST): an insufficient-evidence recall returns no memory
//     structurally rather than prompting the model to pretend.
//   P-RECALL-013 (MUST): search with explain enabled reports each retrieval
//     signal's score contribution.
//   P-RECALL-003 (MUST): capability hits are displayed as skills rather than
//     spending the memory budget.
// Doors used: vault.recall (act), vault.search.bm25 / vault.search.hybrid /
// vault.claims.list / vault.agents.get / vault.retrieval.run /
// vault.retrieval.runs / vault.authority.audit (second-door reads),
// vault.claims.upsert / vault.conversations.create / vault.structural.put /
// vault.agents.create (setup writes), POST /v1/core/slips/revoke (owner
// revoke, as in AUTHORITY-05), unauthenticated and non-owner raw facade calls
// (refusals), engine.restart().
// Stays unproved: the positive Context Board SKILLS `found` display of a
// capability hit (no typed board render/read verb exists in the generated
// facade; self.board.* only edits layout for the next turn), and a literal
// search(explain=true) toggle (no generated search input carries an explain
// field; vault.search.hybrid always returns per-hit score components). The
// case therefore proves that a capability hit spends no memory slot and never
// appears as a memory row, not that it is rendered as a SKILLS found row.
suite.test(test, "MUSE-RECALL-04", "Thin evidence returns no memory, search reports each signal's share, and a capability hit spends no memory slot", async () => {
  const engine = await EngineFixture.start({ id: "MUSE-RECALL-04", profile,
    serverConfig: "[recall]\nretrieval_telemetry_capture = true\n" });
  const recall = async (input: FacadeInput<"vault.recall">): Promise<MuseRecall04Pack> => {
    try {
      return await engine.client.call("vault.recall", input);
    } catch (error) {
      if (!(error instanceof PublicHttpError)) throw error;
      const detail = error.error;
      throw new Error(
        `MUSE-RECALL-04 vault.recall effort=${input.effort ?? "default"}: status=${error.reply.status} code=${detail?.code ?? "<none>"} message=${detail?.message ?? "<none>"} suggestion=${detail?.suggestions?.[0] ?? "<none>"}`,
        { cause: error },
      );
    }
  };
  const expectThin = (pack: MuseRecall04Pack): void => {
    try {
      expect(pack.items).toHaveLength(0);
      expect(pack.retrieval_meta.claims_returned).toBe(0);
    } catch (error) {
      const rows = pack.items.map(item => ({
        short_id: item.short_id, kind: item.kind, predicate: item.predicate ?? null,
        value_text: redactor.text(item.value_text).slice(0, 120),
      }));
      throw new Error(
        `MUSE-RECALL-04 ENGINE DEFECT 2026-11-11: P-RECALL-012 zero-match lexical recall surfaced ${pack.items.length} memory items (claims=${pack.retrieval_meta.claims_returned}); default temporal effort anchor is not query evidence; rows=${JSON.stringify(rows)}; ${errorText(error)}`,
        { cause: error },
      );
    }
  };
  try {
    const occurred = 1769947200;
    const phrase = "lantern quokka timetable";
    const thinQuery = "violet anvil semaphore picnic";
    const markerOne = `${phrase} marker one prefers the north gate at dawn`;
    const markerTwo = `${phrase} marker two prefers the south pier at dusk`;
    const markers = [markerOne, markerTwo];
    const capabilityName = "lantern-quokka-timetable-helper";
    const agentDefRef = secretHex(16);
    const readerName = "Muse Recall Reader";
    redactor.add(phrase, thinQuery, markerOne, markerTwo, capabilityName, agentDefRef, readerName);

    // P-RECALL-012: a query with no evidence in a fresh vault returns a
    // structurally empty pack, not a dressed-up hint.
    const thinPack = await recall({
      query: thinQuery, effort: "light", telemetry: { capture_trace: true }, limit: 10,
    } satisfies FacadeInput<"vault.recall">);
    expectThin(thinPack);
    const thinRun = await awaitPublic(
      () => museRecall04RunForPack(engine, thinPack, true),
      (value) => value !== null,
      { label: "thin-evidence retrieval run" },
    );
    if (!thinRun) throw new Error("Thin-evidence recall left no finalized retrieval run");
    expect(thinRun.run.result_ids).toHaveLength(0);
    expect(thinRun.run.score_breakdown).toHaveLength(0);
    const thinBm25 = await engine.client.call("vault.search.bm25", {
      query: thinQuery, limit: 10,
    } satisfies FacadeInput<"vault.search.bm25">);
    expect(thinBm25.value).toHaveLength(0);

    // A paired reader agent for the wrong-actor and lost-grant legs. Its slip
    // is found from the authority audit diff, exactly as in AUTHORITY-05.
    const readerPerson = await engine.client.call("vault.structural.put", {
      kind: "PERSON", body: { name: readerName }, occurred_at: occurred,
    } satisfies FacadeInput<"vault.structural.put">);
    await museRecallReadSetup(engine, readerPerson.entity_ref, "PERSON");
    const auditBeforePair = await museRecallAuditRows(engine.client);
    const reader = await engine.pairActor({
      principalRef: readerPerson.id_hex, actorClass: "agent", scope: ["core:read", "core:write"],
    });
    const readerSlipId = museRecall04MintedSlip(
      auditBeforePair, await museRecallAuditRows(engine.client), reader.principalRef,
    );

    // Seed two owner memories, each read back through vault.claims.list.
    const scope = await ownerBaseClaimScope(engine.client, engine.pairedActor.principalRef);
    // A public predicate has at least two dot-joined segments (D17 grammar);
    // a bare "preference" is refused 400 before anything is stored.
    const seedPredicate = "preference.meeting_place";
    const seededClaims: { readonly id: string | null; readonly shortId: string }[] = [];
    for (const marker of markers) {
      const conversation = await engine.client.call("vault.conversations.create", {
        body: { members: [engine.pairedActor.principalRef, reader.principalRef] },
        occurred_start: occurred, occurred_end: occurred,
      } satisfies FacadeInput<"vault.conversations.create">);
      await museRecallReadSetup(engine, conversation.id, "CONVERSATION");
      let claim: FacadeResult<"vault.claims.upsert">;
      try {
        claim = await engine.client.call("vault.claims.upsert", {
          scope, predicate: seedPredicate, subject_ref: conversation.id,
          value: marker, source: "user_stated", confidence: 1, occurred_at: occurred,
        } satisfies FacadeInput<"vault.claims.upsert">);
      } catch (error) {
        if (!(error instanceof PublicHttpError)) throw error;
        const detail = error.error;
        throw new Error(
          `MUSE-RECALL-04 seed vault.claims.upsert predicate=${seedPredicate} subject=CONVERSATION: status=${error.reply.status} code=${detail?.code ?? "<none>"} message=${detail?.message ?? "<none>"} suggestion=${detail?.suggestions?.[0] ?? "<none>"}`,
          { cause: error },
        );
      }
      seededClaims.push({ id: claim.claim?.id ?? null, shortId: claim.claim_short_id });
      await engine.awaitReceipt(claim.receipt_ref);
      const listed = await engine.client.call("vault.claims.list", {
        subject_ref: conversation.id, predicate: seedPredicate, limit: 10,
      } satisfies FacadeInput<"vault.claims.list">);
      expect(listed.value).toHaveLength(1);
      expect(listed.value[0]!.value).toBe(marker);
    }

    // Second-door visibility of the seeds, then the positive recall control.
    // A CLAIM hit carries no snippet (memory/reads.rs LexicalHit: a preview
    // only when the body has a `content` field), so each seeded claim is
    // found by its record id or its short id.
    const bm25FindsEverySeed = (page: FacadeResult<"vault.search.bm25">): boolean =>
      seededClaims.every((seed) => page.value.some((hit) =>
        (seed.id !== null && hit.record?.id === seed.id)
        || hit.short_id.split("@")[0] === seed.shortId.split("@")[0]));
    const bm25 = await awaitPublic(
      () => engine.client.call("vault.search.bm25", {
        query: phrase, limit: 10,
      } satisfies FacadeInput<"vault.search.bm25">),
      bm25FindsEverySeed,
      { label: "seeded claims in BM25 search" },
    );
    expect(seededClaims).toHaveLength(markers.length);
    expect(bm25FindsEverySeed(bm25)).toBe(true);
    const pack = await awaitPublic(
      () => recall({
        query: phrase, effort: "light", telemetry: { capture_trace: true }, limit: 10,
      } satisfies FacadeInput<"vault.recall">),
      (value) => markers.every((marker) => museRecall04PackHas(value, marker)),
      { label: "seeded memories in recall" },
    );
    expect(pack.items.length).toBeGreaterThanOrEqual(2);
    expect(pack.retrieval_meta.claims_returned).toBeGreaterThanOrEqual(2);
    expect(pack.items.every((item) => item.kind !== "SKILL" && item.kind !== "AGENT_DEF")).toBe(true);

    // P-RECALL-013: hybrid search reports a per-signal score component for
    // every hit, and the finalized run keeps the same score breakdown.
    const hybrid = await engine.client.call("vault.search.hybrid", {
      query: phrase, limit: 10,
    } satisfies FacadeInput<"vault.search.hybrid">);
    expect(hybrid.value.length).toBeGreaterThan(0);
    for (const hit of hybrid.value) {
      expect(hit.components.length).toBeGreaterThan(0);
      for (const component of hit.components) {
        expect(Number.isFinite(component.score)).toBe(true);
      }
    }
    const explainedRun = await awaitPublic(
      () => museRecall04RunForPack(engine, pack, false),
      (value) => value !== null,
      { label: "positive retrieval run" },
    );
    if (!explainedRun) throw new Error("Positive recall left no finalized retrieval run");
    expect(explainedRun.run.score_breakdown.length).toBeGreaterThan(0);
    for (const row of explainedRun.run.score_breakdown) {
      expect(row.components.length).toBeGreaterThan(0);
      for (const component of row.components) {
        expect(Number.isFinite(component.score)).toBe(true);
      }
    }

    // P-RECALL-003 (budget half): an agent definition whose name and text
    // match the same query must not take a memory slot at the cut and must
    // never appear as a memory row.
    const createdAgent = await engine.client.call("vault.agents.create", {
      agent_def_ref: agentDefRef,
      definition: {
        agent_id: capabilityName,
        desc: `Spawnable helper for ${phrase} questions`,
        version: "1.0.0",
        display_name: capabilityName,
        instructions: `Help with ${phrase} questions.`,
        enabled: true,
      },
    } satisfies FacadeInput<"vault.agents.create">);
    expect(createdAgent.definition.agent_id).toBe(capabilityName);
    expect(createdAgent.lifecycle_status).toBe("active");
    const agentReadBack = await engine.client.call("vault.agents.get", {
      agent_def_ref: createdAgent.agent_def_ref,
    } satisfies FacadeInput<"vault.agents.get">);
    expect(agentReadBack.definition.agent_id).toBe(capabilityName);
    expect(agentReadBack.lifecycle_status).toBe("active");

    const cappedPack = await recall({
      query: phrase, effort: "light", telemetry: { capture_trace: true }, limit: markers.length,
    } satisfies FacadeInput<"vault.recall">);
    expect(cappedPack.items.length).toBeLessThanOrEqual(markers.length);
    expect(markers.every((marker) => museRecall04PackHas(cappedPack, marker))).toBe(true);
    expect(cappedPack.items.every((item) => item.kind !== "SKILL" && item.kind !== "AGENT_DEF")).toBe(true);
    expect(cappedPack.items.some((item) => item.value_text.includes(capabilityName))).toBe(false);
    // Wrong actors: no credential at all, and a paired agent at the
    // owner-only retrieval-telemetry door. The reader first proves its own
    // credential works at the agent-facing recall door.
    const anonymous = new PublicHttpClient(engine.url);
    museRecall04ExpectRefusal(await anonymous.raw<MuseRecall04Refusal>(
      "POST", "/v1/core/facade/vault.recall", { query: phrase, effort: "light", telemetry: { capture_trace: true }, limit: 1 },
    ), 401);
    const readerPack = await reader.client.call("vault.recall", {
      query: phrase, effort: "light", telemetry: { capture_trace: true }, limit: 10,
    } satisfies FacadeInput<"vault.recall">);
    expect(Array.isArray(readerPack.items)).toBe(true);
    const readerRunsReply = await reader.client.raw<MuseRecall04Refusal>(
      "POST", "/v1/core/facade/vault.retrieval.runs", { limit: 1 },
    );
    museRecall04ExpectRefusal(readerRunsReply, 403);
    await museRecallHttpRefusalReceipt(engine, "MUSE-RECALL-04", readerRunsReply, "vault.retrieval.runs");
    await engine.client.call("vault.retrieval.runs", {
      limit: 1,
    } satisfies FacadeInput<"vault.retrieval.runs">);

    // Lost grant: the owner revokes the reader's slip through the public
    // door; the reader's next recall is refused, and the revoke is read
    // back from the authority audit.
    const revoked = await engine.client.request<{ revoked: boolean }>("POST", "/v1/core/slips/revoke", {
      slip_id: Array.from(Buffer.from(readerSlipId, "hex")),
    });
    expect(revoked.status).toBe(200);
    expect(revoked.body.revoked).toBe(true);
    museRecall04ExpectRefusal(await reader.client.raw<MuseRecall04Refusal>(
      "POST", "/v1/core/facade/vault.recall", { query: phrase, effort: "light", telemetry: { capture_trace: true }, limit: 1 },
    ), 401);
    const auditAfterRevoke = await museRecallAuditRows(engine.client);
    expect(auditAfterRevoke.some((row) => row.source_op === "slip_revoke"
      && row.subject_ref === readerSlipId && row.fold_valid)).toBe(true);

    // Restart: memories, the thin-evidence abstention, the capability row
    // and the revocation all survive.
    await engine.restart();
    const afterRestart = await awaitPublic(
      () => recall({
        query: phrase, effort: "light", telemetry: { capture_trace: true }, limit: 10,
      } satisfies FacadeInput<"vault.recall">),
      (value) => markers.every((marker) => museRecall04PackHas(value, marker)),
      { label: "seeded memories in recall after restart" },
    );
    expect(markers.every((marker) => museRecall04PackHas(afterRestart, marker))).toBe(true);
    const thinAfterRestart = await recall({
      query: thinQuery, effort: "light", telemetry: { capture_trace: true }, limit: 10,
    } satisfies FacadeInput<"vault.recall">);
    expectThin(thinAfterRestart);
    await engine.client.call("vault.agents.get", {
      agent_def_ref: createdAgent.agent_def_ref,
    } satisfies FacadeInput<"vault.agents.get">);
    const cappedAfterRestart = await recall({
      query: phrase, effort: "light", limit: markers.length,
    });
    expect(markers.every(marker => museRecall04PackHas(cappedAfterRestart, marker))).toBe(true);
    expect(cappedAfterRestart.items.every(item => item.kind !== "SKILL" && item.kind !== "AGENT_DEF")).toBe(true);
    museRecall04ExpectRefusal(await reader.client.raw<MuseRecall04Refusal>(
      "POST", "/v1/core/facade/vault.recall", { query: phrase, effort: "light", telemetry: { capture_trace: true }, limit: 1 },
    ), 401);
  } finally {
    await engine.close();
  }
});

// MUSE-RECALL-05 (PARTIAL)
// Promises: P-RECALL-008 (owner-excluded paths are absent and uncounted in
// the filesystem view) is exercised below for a world the owner keeps
// outside an agent's minted grant. P-RECALL-015 (foreign content on the
// Context Board remains fenced as data) stays UNPROVED: the typed facade
// has no Context Board render/read verb a paired agent can call (canon
// board.refresh; facade self.focus.refresh is LiveRun-bound) and no typed
// guest claim write (vault.guests.propose takes opaque update bytes), so
// foreign content cannot be put on a board and read back through a door
// this case may call. See the report for the candidate missing doors.
// Doors used: vault.structural.put, vault.agents.grants.mint/revoke,
// token pair (pairActor), mount, graph_fs.readdir/ls/grep,
// vault.claims.upsert/list, vault.get, vault.recall, vault.receipts.get,
// HTTP raw facade calls and their call receipts for refusals.

type museRecall05Mount = FacadeInput<"graph_fs.readdir">["mount"];
type museRecall05WorldView = FacadeResult<"graph_fs.readdir">;

function museRecall05Text(value: unknown): string {
  return JSON.stringify(value ?? null) ?? "";
}

function museRecall05Field(value: unknown, key: string): unknown {
  return typeof value === "object" && value !== null && key in value
    ? (value as Record<string, unknown>)[key]
    : undefined;
}

function museRecall05WireError(body: unknown): { code: string; message: string } | undefined {
  const payload = museRecall05Field(body, "error") ?? body;
  const code = museRecall05Field(payload, "code");
  const message = museRecall05Field(payload, "message");
  return typeof code === "string" && typeof message === "string" ? { code, message } : undefined;
}

async function museRecall05WorldEntries(
  client: PublicHttpClient,
  mount: museRecall05Mount,
): Promise<{ names: string[]; suppressed: (number | null)[] }> {
  const names: string[] = [];
  const suppressed: (number | null)[] = [];
  const cursors = new Set<string>();
  let cursor: string | undefined;
  for (;;) {
    const input: FacadeInput<"graph_fs.readdir"> = cursor
      ? { mount, path: "/worlds/", cursor }
      : { mount, path: "/worlds/" };
    const view: museRecall05WorldView = await client.call("graph_fs.readdir", input);
    for (const entry of view.entries) {
      if (entry.kind !== "cursor") names.push(entry.name);
    }
    suppressed.push(view.read_receipt ? view.read_receipt.suppressed_count : null);
    const next = view.next_cursor;
    if (!next) return { names: names.sort(), suppressed };
    expect(cursors.has(next)).toBe(false);
    cursors.add(next);
    cursor = next;
  }
}

async function museRecall05GrepAll(
  client: PublicHttpClient,
  mount: museRecall05Mount,
  pattern: string,
): Promise<string> {
  let output = "";
  const cursors = new Set<string>();
  let cursor: string | undefined;
  for (;;) {
    const input: FacadeInput<"graph_fs.grep"> = cursor
      ? { mount, path: "/claims/", pattern, recursive: true, cursor }
      : { mount, path: "/claims/", pattern, recursive: true };
    const page = await client.call("graph_fs.grep", input);
    output += page.output;
    const nextPage = page.next_cursor;
    if (!nextPage) return output;
    expect(cursors.has(nextPage)).toBe(false);
    cursors.add(nextPage);
    cursor = nextPage;
  }
}

suite.test(test, "MUSE-RECALL-05", "A world outside an agent's owner-minted grant stays absent and uncounted in the filesystem view", async () => {
  const occurred = 1769947200; // Fixed public setup time; never wall clock.
  const token = `muse05w${secretHex(8)}`;
  const hiddenValue = `${token} hidden world note`;
  const worldName = `Muse05 Hidden World ${secretHex(4)}`;
  const predicate = "profile.preference";
  redactor.add(token, hiddenValue, worldName);

  const engine = await EngineFixture.start({ id: "MUSE-RECALL-05", profile });
  try {
    const ownerRef = engine.pairedActor.principalRef;
    const baseScope = await ownerBaseClaimScope(engine.client, ownerRef);

    // The reader agent: an AGENT_DEF the owner creates, grants base-world-only
    // authority, then pairs. The mint is the owner's exclusion act: any world
    // not named in the grant's worlds axis is owner-excluded for this agent.
    const readerRef = secretHex(16);
    redactor.add(readerRef);
    const readerRecord = await engine.client.call("vault.agents.create", {
      agent_def_ref: readerRef,
      definition: { agent_id: "muse_recall05_reader", desc: "Filesystem scope reader",
        version: "1.0.0", ceiling: "auto" },
    });
    const readerSaved = await engine.client.call("vault.agents.get", { agent_def_ref: readerRef });
    expect(readerSaved.agent_def_ref).toBe(readerRecord.agent_def_ref);
    const minted = await engine.client.call("vault.agents.grants.mint", {
      agent: readerRecord.agent_def_ref,
      authority_scope: {
        worlds: { kind: "some", values: [baseScope.world_id] },
        facets: { kind: "all" }, bands: { kind: "all" }, audience: { kind: "all" },
        verbs: { kind: "some", values: ["read"] }, sensitivity: { kind: "all" },
      },
    });
    expect(minted.grant.agent).toBe(readerRecord.agent_def_ref);
    expect(minted.grant.authority_scope.worlds).toEqual({ kind: "some", values: [baseScope.world_id] });
    const registry = await engine.client.call("vault.consent.registry", { limit: 100 });
    expect(registry.rows.some(row => row.grant_ref === minted.grant.grant_ref)).toBe(true);
    const reader = await engine.pairActor({
      principalRef: readerRecord.agent_def_ref, actorClass: "agent", scope: ["core:read", "core:write"],
    });

    const mounted = await engine.client.call("mount", {
      ref: { kind: "live_head" },
    } satisfies FacadeInput<"mount">);
    const mount = mounted.mount;

    // Baselines before the hidden world exists (naming-agnostic diff below).
    const ownerBaseline = await museRecall05WorldEntries(engine.client, mount);
    // Each actor is compared with its own baseline: the grant may already
    // exclude a pre-existing non-base world from the reader, and that is the
    // promised behaviour, not a baseline mismatch.
    const readerBaseline = await museRecall05WorldEntries(reader.client, mount);

    // Act: the owner creates a world outside the reader's grant and writes a
    // claim in it. Every write is read back through a different door.
    const world = await engine.client.call("vault.structural.put", {
      kind: "WORLD", body: { name: worldName, kind: "fictional" }, occurred_at: occurred,
    } satisfies FacadeInput<"vault.structural.put">);

    const worldRead = await engine.client.call("vault.get", {
      entity_ref: world.entity_ref,
    } satisfies FacadeInput<"vault.get">);
    expect(worldRead.value?.kind).toBe("WORLD");

    const claim = await (async () => {
      try {
        return await engine.client.call("vault.claims.upsert", {
          predicate, subject_ref: ownerRef, value: hiddenValue, confidence: 1,
          source: "user_stated", scope: { ...baseScope, world_id: world.id_hex },
          occurred_at: occurred,
        } satisfies FacadeInput<"vault.claims.upsert">);
      } catch (error) {
        if (!(error instanceof PublicHttpError)) throw error;
        const detail = error.error;
        const firstSuggestion = detail?.suggestions?.[0] ?? "<none>";
        throw new Error(
          `MUSE-RECALL-05 vault.claims.upsert: status=${error.reply.status} code=${detail?.code ?? "<none>"} message=${detail?.message ?? "<none>"} suggestion=${firstSuggestion}`,
          { cause: error },
        );
      }
    })();
    await engine.awaitReceipt(claim.receipt_ref);
    const ownerClaims = await engine.client.call("vault.claims.list", {
      subject_ref: ownerRef, predicate, limit: 100,
    } satisfies FacadeInput<"vault.claims.list">);
    expect(ownerClaims.value.some((row) => row.value === hiddenValue
      && row.claim_scope.world_id === world.id_hex)).toBe(true);

    // The owner sees exactly one new world path; that entry names the segment.
    const ownerAfter = await museRecall05WorldEntries(engine.client, mount);
    const added = ownerAfter.names.filter((name) => !ownerBaseline.names.includes(name));
    expect(added).toHaveLength(1);
    const segment = added[0];
    if (!segment) throw new Error("Owner filesystem view gained no world path for the new world");
    const worldPath = `/worlds/${segment}`;
    const ownerLs = await engine.client.call("graph_fs.ls", {
      mount, path: "/worlds/",
    } satisfies FacadeInput<"graph_fs.ls">);
    expect(ownerLs.output.includes(segment)).toBe(true);
    const ownerPack = await awaitPublic(
      () => engine.client.call("vault.recall", {
        query: token, effort: "light", limit: 10,
        scope: { worlds: { kind: "worlds", world_refs: [world.id_hex], include_base: true } },
      } satisfies FacadeInput<"vault.recall">),
      (pack) => pack.items.some((item) => item.value_text.includes(hiddenValue)),
      { label: "owner recall finds the hidden-world claim" },
    );
    expect(ownerPack.items.some((item) => item.value_text.includes(hiddenValue))).toBe(true);
    const ownerGrep = await awaitPublic(
      () => museRecall05GrepAll(engine.client, mount, token),
      (output) => output.includes(token),
      { label: "owner graph_fs grep finds the hidden-world claim" },
    );
    expect(ownerGrep.includes(token)).toBe(true);

    // P-RECALL-008: for the excluded reader the world path is absent and
    // uncounted — same listing as before it existed, no name, no count.
    const expectReaderBlind = async (): Promise<void> => {
      const listing = await (async () => {
        let seenNames: readonly string[] | undefined;
        try {
          const listing = await museRecall05WorldEntries(reader.client, mount);
          seenNames = listing.names;
          expect(listing.names).toEqual(readerBaseline.names);
          expect(listing.names.includes(segment)).toBe(false);
          return listing;
        } catch (error) {
          const extraNames = seenNames?.filter((name) => !readerBaseline.names.includes(name));
          const detail = error instanceof PublicHttpError
            ? `status=${error.reply.status} code=${error.error?.code ?? "<none>"} message=${error.error?.message ?? "<none>"} suggestion=${error.error?.suggestions?.[0] ?? "<none>"}`
            : errorText(error);
          throw new Error(
            `MUSE-RECALL-05 the graph_fs walk is not clamped by the agent grant (ARCH-0051:84, :97; FIX [AGENT-GRAPHFS-GRANT-WORLDS], fixed by #7044); actor=reader agent ${reader.principalRef}; grant.worlds=${JSON.stringify(minted.grant.authority_scope.worlds)}; graph_fs.readdir /worlds/ extra_names=${JSON.stringify(extraNames ?? "<unavailable>")} baseline=${JSON.stringify(readerBaseline.names)} seen=${JSON.stringify(seenNames ?? "<unavailable>")}; ${detail}`,
            { cause: error },
          );
        }
      })();
      // Uncounted, stated as a diff: the hidden world must not move any
      // suppressed_count from the reader's own pre-world baseline. (An
      // absolute zero would over-claim: a receipt may count rows this
      // reader can read that the request itself excluded.)
      expect(listing.suppressed).toEqual(readerBaseline.suppressed);
      const ls = await reader.client.call("graph_fs.ls", {
        mount, path: "/worlds/",
      } satisfies FacadeInput<"graph_fs.ls">);
      expect(ls.output.includes(segment)).toBe(false);
      expect(ls.output.includes(worldName)).toBe(false);
      const grep = await museRecall05GrepAll(reader.client, mount, token);
      expect(grep.includes(token)).toBe(false);
      const pack = await reader.client.call("vault.recall", {
        query: token, effort: "light", limit: 10,
        scope: { worlds: { kind: "all" } },
      } satisfies FacadeInput<"vault.recall">);
      expect(pack.scope_honesty.out_of_scope_worlds.includes(world.id_hex)).toBe(false);
    };
    await expectReaderBlind();

    // A direct walk at the excluded path is not a 403 and answers exactly as
    // a world id the vault never assigned: absent means indistinguishable
    // from never having existed. readdir serves the same fixed
    // claims/backlinks/scope skeleton for every well-formed world id, so the
    // control is a never-assigned id, not an empty listing; the hidden
    // world's claims directory must then list what the never-assigned one
    // lists (nothing), with no name and no count.
    const neverAssignedPath = `/worlds/${secretHex(16)}`;
    const readdirAt = (path: string) => reader.client.raw("POST", "/v1/core/facade/graph_fs.readdir", {
      mount, path,
    } satisfies FacadeInput<"graph_fs.readdir">);
    const entryNames = (body: unknown): string[] | null => {
      const entries = museRecall05Field(body, "entries");
      if (!Array.isArray(entries)) return null;
      return entries
        .filter((entry) => museRecall05Field(entry, "kind") !== "cursor")
        .map((entry) => String(museRecall05Field(entry, "name")))
        .sort();
    };
    for (const [hiddenPath, controlPath] of [
      [worldPath, neverAssignedPath],
      [`${worldPath}/claims`, `${neverAssignedPath}/claims`],
    ] as const) {
      const direct = await readdirAt(hiddenPath);
      const control = await readdirAt(controlPath);
      const directText = museRecall05Text(direct.body);
      expect(direct.status).not.toBe(403);
      expect(directText.includes(token)).toBe(false);
      if (segment !== worldName) expect(directText.includes(worldName)).toBe(false);
      const hiddenLeaf = hiddenPath.slice(worldPath.length) || "/";
      const seen = { status: direct.status, names: entryNames(direct.body) };
      const expected = { status: control.status, names: entryNames(control.body) };
      if (JSON.stringify(seen) !== JSON.stringify(expected)) {
        throw new Error(
          `MUSE-RECALL-05 direct readdir of the hidden world${hiddenLeaf} differs from a never-assigned world id; actor=reader agent ${reader.principalRef}; hidden=${JSON.stringify(seen)} never_assigned=${JSON.stringify(expected)}`,
        );
      }
      if (direct.status < 200 || direct.status >= 300) {
        expect(museRecall05WireError(direct.body)).toBeDefined();
      }
    }

    // The exclusion survives a restart; the owner still sees the world.
    await engine.restart();
    const ownerAfterRestart = await museRecall05WorldEntries(engine.client, mount);
    expect(ownerAfterRestart.names).toEqual(ownerAfter.names);
    await expectReaderBlind();

    // Wrong actor kind: the agent tries to widen its own grant to all worlds.
    // Self-widening the allowed set is an owner-tier act, never the agent's.
    const widen: FacadeInput<"vault.agents.grants.mint"> = {
      agent: readerRecord.agent_def_ref,
      authority_scope: { ...minted.grant.authority_scope, worlds: { kind: "all" } },
    };
    const widenReply = await reader.client.raw("POST", "/v1/core/facade/vault.agents.grants.mint", widen);
    expect(widenReply.status >= 400).toBe(true);
    const widenError = museRecall05WireError(widenReply.body);
    if (!widenError) throw new Error("Agent self-widen was not refused with the standard error envelope");
    expect(widenError.code.length).toBeGreaterThan(0);
    expect(widenError.message.length).toBeGreaterThan(0);
    // The refusal's call receipt, read back as owner: the HTTP reply's
    // receipt is the one under test.
    await museRecallHttpRefusalReceipt(engine, "MUSE-RECALL-05", widenReply, "vault.agents.grants.mint");
    // The refused widen changed nothing, read back through the listing.
    const afterWiden = await museRecall05WorldEntries(reader.client, mount);
    try {
      expect(afterWiden.names).toEqual(readerBaseline.names);
    } catch (error) {
      const extraNames = afterWiden.names.filter((name) => !readerBaseline.names.includes(name));
      throw new Error(
        `MUSE-RECALL-05 the graph_fs walk is not clamped by the agent grant (ARCH-0051:84, :97; FIX [AGENT-GRAPHFS-GRANT-WORLDS], fixed by #7044); actor=reader agent ${reader.principalRef}; grant.worlds=${JSON.stringify(minted.grant.authority_scope.worlds)}; graph_fs.readdir /worlds/ after refused self-widen extra_names=${JSON.stringify(extraNames)} baseline=${JSON.stringify(readerBaseline.names)} seen=${JSON.stringify(afterWiden.names)}; ${errorText(error)}`,
        { cause: error },
      );
    }

    // An agent paired without the read scope is refused at the same door.
    const noReadRecord = await engine.client.call("vault.structural.put", {
      kind: "PERSON", body: { name: "Muse Recall05 NoRead" }, occurred_at: occurred,
    } satisfies FacadeInput<"vault.structural.put">);
    await museRecallReadSetup(engine, noReadRecord.entity_ref, "PERSON");

    const noRead = await engine.pairActor({
      principalRef: noReadRecord.id_hex, actorClass: "agent", scope: ["core:write"],
    });
    const noReadReply = await noRead.client.raw("POST", "/v1/core/facade/graph_fs.readdir", {
      mount, path: "/worlds/",
    } satisfies FacadeInput<"graph_fs.readdir">);
    expect(noReadReply.status >= 400).toBe(true);
    expect(museRecall05WireError(noReadReply.body)).toBeDefined();
    expect(museRecall05Text(noReadReply.body).includes(token)).toBe(false);

    // Losing the grant mid-flow: the owner revokes it, and the reader's next
    // filesystem use no longer serves even its baseline worlds.
    const revoked = await engine.client.call("vault.agents.grants.revoke", {
      grant_ref: minted.grant.grant_ref,
    } satisfies FacadeInput<"vault.agents.grants.revoke">);
    expect(revoked.changed).toBe(true);
    expect(revoked.grant_ref).toBe(minted.grant.grant_ref);
    const revokedRegistry = await engine.client.call("vault.consent.registry", {
      include_revoked: true, limit: 100,
    });
    expect(revokedRegistry.rows.some(row => row.grant_ref === minted.grant.grant_ref)).toBe(true);
    const afterRevoke = await reader.client.raw("POST", "/v1/core/facade/graph_fs.readdir", {
      mount, path: "/worlds/",
    } satisfies FacadeInput<"graph_fs.readdir">);
    if (afterRevoke.status >= 200 && afterRevoke.status < 300) {
      const entries = museRecall05Field(afterRevoke.body, "entries");
      expect(Array.isArray(entries) ? entries.length : -1).toBe(0);
    } else {
      expect(museRecall05WireError(afterRevoke.body)).toBeDefined();
    }
    expect(museRecall05Text(afterRevoke.body).includes(segment)).toBe(false);
    expect(museRecall05Text(afterRevoke.body).includes(token)).toBe(false);

    // The owner's view is untouched by all of the above.
    const ownerFinal = await museRecall05WorldEntries(engine.client, mount);
    await engine.artifacts.json("muse-recall05-summary.json", {
      ownerWorlds: ownerFinal.names.length,
      readerBaselineWorlds: readerBaseline.names.length,
      addedWorldsForOwner: added.length,
    });
  } finally {
    await engine.close();
  }
});

// MUSE-RECALL-06 — PARTIAL for P-RECALL-018, P-RECALL-019, P-RECALL-020.
// P-RECALL-018 (MUST): subscriptions deliver an initial snapshot and EOSE
//   marker before live scoped updates.
// P-RECALL-019 (MUST): a reconnect catches up from the last cursor or
//   performs a full resync if that cursor is too old.
// P-RECALL-020 (MUST): active subscriptions are replayed after reconnect.
// Doors: raw tag-31 sub.open/sub.ack through WsClient.send/next, HTTP
// witness/get/recall, call receipts for the equivalent refused recall,
// authority audit/slip revoke, restart. The cursor is the exact public
// {document, versionVector, batch} object, not a fabricated byte string.
// Unproved: too-old retention/full-resync, production-client auto-replay
// P-RECALL-020, and a receipt for sub.err itself (the wire stamps none).

// The public tag-31 protocol is driven locally; support/ remains unchanged.
type MuseRecall06Cursor = { document: string; versionVector: Uint8Array; batch: number };
type MuseRecall06Event =
  | { kind: "snapshot" | "data"; cursor: MuseRecall06Cursor; value: unknown }
  | { kind: "eose" | "gap"; cursor: MuseRecall06Cursor }
  | { kind: "error"; code: string; message: string };
interface MuseRecall06Subscription {
  readonly id: number;
  next(): Promise<MuseRecall06Event>;
  ack(cursor: MuseRecall06Cursor): void;
}

function museRecall06Subscribe(
  socket: WsClient,
  query: string,
  resume?: { subscriptionId: number; cursor: MuseRecall06Cursor },
): MuseRecall06Subscription {
  // This case holds one subscription per socket and makes no RPC on it.
  const id = resume?.subscriptionId ?? 7;
  socket.send(31, { type: "sub.open", id, seq: 0, last: true, payload: {
    scopedView: { query, filter: { kind: "MESSAGE" } },
    ...(resume ? { cursor: resume.cursor } : {}),
  } });
  return {
    id,
    ack(cursor) {
      socket.send(31, { type: "sub.ack", id, seq: 0, last: true, payload: { cursor } });
    },
    async next() {
      const chunks: Uint8Array[] = [];
      let kind: string | undefined;
      let nextSequence: number | undefined;
      for (;;) {
        const frame = await socket.next();
        const envelope = frame.envelope;
        if (frame.tag !== 31 || envelope.id !== id) throw new Error("Unexpected subscription frame");
        if (envelope.type === "sub.err") {
          const error = envelope.payload as { code: string; message: string };
          return { kind: "error", code: error.code, message: error.message };
        }
        if (kind !== undefined && (kind !== envelope.type || envelope.seq !== nextSequence)) {
          throw new Error("Subscription chunks are out of order");
        }
        kind = envelope.type;
        nextSequence = envelope.seq + 1;
        const payload = envelope.payload as { cursor: MuseRecall06Cursor; data?: Uint8Array };
        const cursor = payload.cursor;
        if (!(cursor.versionVector instanceof Uint8Array)) throw new Error("Subscription cursor lost its binary version vector");
        if (payload.data !== undefined) {
          if (!(payload.data instanceof Uint8Array)) throw new Error("Subscription data is not binary");
          chunks.push(payload.data);
        }
        if (!envelope.last) continue;
        if (kind === "sub.eose") return { kind: "eose", cursor };
        if (kind === "sub.gap") return { kind: "gap", cursor };
        if (kind !== "sub.snapshot" && kind !== "sub.data") throw new Error("Unknown subscription event");
        const bytes = new Uint8Array(chunks.reduce((length, chunk) => length + chunk.length, 0));
        let offset = 0;
        for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
        return { kind: kind === "sub.snapshot" ? "snapshot" : "data", cursor, value: decode(bytes) };
      }
    },
  };
}

type museRecall06AuditRow = FacadeResult<"vault.authority.audit">["rows"][number];
type museRecall06Actor = Awaited<ReturnType<EngineFixture["pairActor"]>>;
type museRecall06Mention = {
  readonly token: string;
  readonly refs: readonly string[];
};

function museRecall06EventText(event: MuseRecall06Event): string {
  if (event.kind === "error") return `${event.code} ${event.message}`;
  if (event.kind !== "snapshot" && event.kind !== "data") return "";
  const value: unknown = event.value;
  if (typeof value === "string") return value;
  if (value instanceof Uint8Array) return new TextDecoder().decode(value);
  return JSON.stringify(value) ?? "";
}

function museRecall06CursorOf(event: MuseRecall06Event): MuseRecall06Cursor {
  if (event.kind === "error") {
    throw new Error(`Subscription error has no cursor: ${event.code}`);
  }
  return event.cursor;
}

function museRecall06CursorKey(cursor: MuseRecall06Cursor): string {
  return `${cursor.document}:${Buffer.from(cursor.versionVector).toString("hex")}:${cursor.batch}`;
}

function museRecall06Mentions(text: string, mention: museRecall06Mention): boolean {
  if (text.includes(mention.token)) return true;
  return mention.refs.some(ref => ref.length > 0 && text.includes(ref));
}

function museRecall06EventMentions(
  event: MuseRecall06Event,
  mention: museRecall06Mention,
): boolean {
  return museRecall06Mentions(museRecall06EventText(event), mention);
}

async function museRecall06CollectUntil(
  subscription: MuseRecall06Subscription,
  ready: (events: readonly MuseRecall06Event[]) => boolean,
  maxEvents: number,
): Promise<MuseRecall06Event[]> {
  const events: MuseRecall06Event[] = [];
  for (let index = 0; index < maxEvents; index++) {
    let event: MuseRecall06Event;
    try {
      event = await subscription.next();
    } catch (error) {
      throw new Error(
        `MUSE-RECALL-06 subscription ${subscription.id} frame wait failed; last public events=${events.map(value => value.kind).join(",") || "<none>"}; ${errorText(error)}`,
        { cause: error },
      );
    }
    if (event.kind === "error") {
      throw new Error(`MUSE-RECALL-06 subscription ${subscription.id} error ${event.code}: ${event.message}; last public events=${events.map(value => value.kind).join(",") || "<none>"}`);
    }
    events.push(event);
    if (ready(events)) return events;
  }
  throw new Error(
    `MUSE-RECALL-06 subscription ${subscription.id} did not reach the expected event within ${maxEvents} events; last public events= ${events.map(event => event.kind).join(",")}`,
  );
}

async function museRecall06RecallMentions(
  client: PublicHttpClient,
  query: string,
  token: string,
): Promise<boolean> {
  const pack = await awaitPublic(
    () => client.call("vault.recall", { query, effort: "light", limit: 10 }),
    value => value.items.some(item => item.value_text.includes(token)
      || item.cited_messages?.some(message => message.value_text.includes(token))),
    { label: "MUSE-RECALL-06 subscription write visible through recall" },
  );
  return pack.items.some(item => item.value_text.includes(token)
    || item.cited_messages?.some(message => message.value_text.includes(token)));
}

async function museRecall06Witness(
  engine: EngineFixture,
  client: PublicHttpClient,
  conversationRef: string,
  content: string,
  occurredAt: number,
): Promise<FacadeResult<"vault.witness">> {
  const receipt = await client.call("vault.witness", {
    conversation_ref: conversationRef,
    occurred_at: occurredAt,
    messages: [{
      author: "user", message_type: "text", is_visible: true, order: 0, content,
    }],
  } satisfies FacadeInput<"vault.witness">);

  const got = await engine.client.call("vault.get", {
    entity_ref: receipt.turn_short_id,
  } satisfies FacadeInput<"vault.get">);
  expect(got.value?.kind).toBe("TURN");
  for (const ref of receipt.message_short_ids) {
    const message = await engine.client.call("vault.get", { entity_ref: ref });
    expect((message.value?.body as { content?: string } | undefined)?.content).toBe(content);
  }
  return receipt;
}

function museRecall06MentionOf(
  token: string,
  receipt: FacadeResult<"vault.witness">,
): museRecall06Mention {
  return {
    token,
    refs: [receipt.turn_short_id, receipt.turn_id, ...receipt.message_short_ids],
  };
}

function museRecall06WireError(
  body: unknown,
): { code: string; message: string } | undefined {
  if (!body || typeof body !== "object") return undefined;
  const payload = "error" in body ? (body as { error: unknown }).error : body;
  if (!payload || typeof payload !== "object") return undefined;
  const fields = payload as Record<string, unknown>;
  if (typeof fields.code !== "string" || typeof fields.message !== "string") {
    return undefined;
  }
  return { code: fields.code, message: fields.message };
}

async function museRecall06ConnectFails(
  engine: EngineFixture,
  actor: museRecall06Actor,
): Promise<boolean> {
  try {
    const socket = await engine.websocket(actor);
    socket.close();
    return false;
  } catch {
    return true;
  }
}

suite.test(test, "MUSE-RECALL-06", "A recall subscription sends a snapshot then EOSE before live updates, and a reconnect with its last cursor catches up and resumes live updates", async () => {
  const engine = await EngineFixture.start({ id: "MUSE-RECALL-06", profile });
  let stage = "public setup and HTTP recall control";
  try {
    const hex = secretHex(6);
    const common = `lantern${hex}`;
    const alphaToken = `alpha${hex}`;
    const bravoToken = `bravo${hex}`;
    const charlieToken = `charlie${hex}`;
    const deltaToken = `delta${hex}`;
    const readerName = `Muse 06 Reader ${hex}`;
    const writerName = `Muse 06 Writer ${hex}`;
    redactor.add(
      hex, common, alphaToken, bravoToken, charlieToken, deltaToken,
      readerName, writerName,
    );
    const occurred = 1769947200;

    const auditBefore = await museRecallAuditRows(engine.client);
    const readerRecord = await engine.client.call("vault.structural.put", {
      kind: "PERSON", body: { name: readerName }, occurred_at: occurred,
    } satisfies FacadeInput<"vault.structural.put">);
    await museRecallReadSetup(engine, readerRecord.entity_ref, "PERSON");
    const writerRecord = await engine.client.call("vault.structural.put", {
      kind: "PERSON", body: { name: writerName }, occurred_at: occurred,
    } satisfies FacadeInput<"vault.structural.put">);
    await museRecallReadSetup(engine, writerRecord.entity_ref, "PERSON");
    const reader = await engine.pairActor({
      principalRef: readerRecord.id_hex, actorClass: "agent",
      scope: ["core:read", "core:write"],
    });
    const writer = await engine.pairActor({
      principalRef: writerRecord.id_hex, actorClass: "agent",
      scope: ["core:write"],
    });
    const conversation = await engine.client.call("vault.conversations.create", {
      body: {
        members: [
          engine.pairedActor.principalRef, reader.principalRef, writer.principalRef,
        ],
      },
      occurred_start: occurred, occurred_end: occurred,
    } satisfies FacadeInput<"vault.conversations.create">);
    await museRecallReadSetup(engine, conversation.id, "CONVERSATION");

    // Pre-existing matching record, read back through a second door
    // (vault.get inside the witness helper, then vault.recall over HTTP).
    const alpha = await museRecall06Witness(
      engine, engine.client, conversation.id,
      `${common} ${alphaToken} first lantern entry`, occurred,
    );
    const alphaMention = museRecall06MentionOf(alphaToken, alpha);
    expect(await museRecall06RecallMentions(engine.client, common, alphaToken)).toBe(true);

    // P-RECALL-018, act: open the recall subscription on the held socket.
    // Snapshot frames come first, then EOSE, and no live data precedes EOSE.
    let subscriptionId = -1;
    let lastCursor: MuseRecall06Cursor | undefined;
    stage = "owner human initial sub.snapshot then sub.eose";
    const socket = await engine.websocket();
    try {
      const subscription = museRecall06Subscribe(socket, common);
      subscriptionId = subscription.id;
      const untilEose = await museRecall06CollectUntil(
        subscription,
        events => events.some(event => event.kind === "eose"),
        20,
      );
      const eoseIndex = untilEose.findIndex(event => event.kind === "eose");
      expect(eoseIndex).toBeGreaterThan(0);
      const snapshotEvents = untilEose.slice(0, eoseIndex);
      expect(snapshotEvents.length).toBeGreaterThan(0);
      expect(snapshotEvents.every(event => event.kind === "snapshot")).toBe(true);
      expect(snapshotEvents.some(event => museRecall06EventMentions(event, alphaMention))).toBe(true);
      expect(snapshotEvents.some(event => museRecall06EventText(event).includes(bravoToken))).toBe(false);
      const eoseCursor = museRecall06CursorOf(untilEose[eoseIndex]!);
      expect(eoseCursor.versionVector.byteLength).toBeGreaterThan(0);
      subscription.ack(eoseCursor);
      stage = "owner human live bravo sub.data";

      // Live scoped update: written over HTTP after EOSE, pushed as data.
      const bravo = await museRecall06Witness(
        engine, engine.client, conversation.id,
        `${common} ${bravoToken} second lantern entry`, occurred + 60,
      );
      const bravoMention = museRecall06MentionOf(bravoToken, bravo);
      expect(await museRecall06RecallMentions(engine.client, common, bravoToken)).toBe(true);
      const liveEvents = await museRecall06CollectUntil(
        subscription,
        events => events.some(event => event.kind === "data"
          && museRecall06EventMentions(event, bravoMention)),
        20,
      );
      const bravoEvent = liveEvents.find(event => event.kind === "data"
        && museRecall06EventMentions(event, bravoMention))!;
      lastCursor = museRecall06CursorOf(bravoEvent);
      expect(lastCursor.versionVector.byteLength).toBeGreaterThan(0);
      expect(museRecall06CursorKey(lastCursor))
        .not.toBe(museRecall06CursorKey(eoseCursor));
      subscription.ack(lastCursor);
    } finally {
      socket.close();
    }
    expect(subscriptionId).toBeGreaterThanOrEqual(0);
    if (!lastCursor) throw new Error("Live subscription delivered no resume cursor");
    expect(lastCursor.versionVector.byteLength).toBeGreaterThan(0);

    // P-RECALL-019/-020, reconnect subset: an update lands while no socket
    // is held. Re-opening the same subscription on a fresh socket with the
    // last cursor delivers that missed update, then live updates resume.
    const charlie = await museRecall06Witness(
      engine, engine.client, conversation.id,
      `${common} ${charlieToken} third lantern entry`, occurred + 120,
    );
    const charlieMention = museRecall06MentionOf(charlieToken, charlie);
    expect(await museRecall06RecallMentions(engine.client, common, charlieToken)).toBe(true);

    let deltaMention: museRecall06Mention = { token: deltaToken, refs: [] };
    stage = "owner human cursor-resume subscription awaiting charlie";
    const resumedSocket = await engine.websocket();
    try {
      const resumed = museRecall06Subscribe(
        resumedSocket, common,
        { subscriptionId, cursor: lastCursor },
      );
      expect(resumed.id).toBe(subscriptionId);
      const caughtUp = await museRecall06CollectUntil(
        resumed,
        events => events.some(event => (event.kind === "data"
          || event.kind === "snapshot")
          && museRecall06EventMentions(event, charlieMention)),
        20,
      );
      expect(caughtUp.some(event => event.kind === "gap")).toBe(false);
      const charlieEvent = caughtUp.find(event => (event.kind === "data"
        || event.kind === "snapshot")
        && museRecall06EventMentions(event, charlieMention))!;
      const charlieCursor = museRecall06CursorOf(charlieEvent);
      expect(charlieCursor.versionVector.byteLength).toBeGreaterThan(0);
      resumed.ack(charlieCursor);
      stage = "owner human resumed live delta sub.data";

      const delta = await museRecall06Witness(
        engine, engine.client, conversation.id,
        `${common} ${deltaToken} fourth lantern entry`, occurred + 180,
      );
      deltaMention = museRecall06MentionOf(deltaToken, delta);
      expect(await museRecall06RecallMentions(engine.client, common, deltaToken)).toBe(true);
      const liveAfterResume = await museRecall06CollectUntil(
        resumed,
        events => events.some(event => event.kind === "data"
          && museRecall06EventMentions(event, deltaMention)),
        20,
      );
      expect(liveAfterResume.some(event => event.kind === "data"
        && museRecall06EventMentions(event, deltaMention))).toBe(true);
    } finally {
      resumedSocket.close();
    }

    // A read-scoped agent reads the same record back over HTTP before it
    // loses that scope below. It queries the entry's own token: a light pack
    // at limit 10 keeps at most two TURNs (ContextPackRetrievalBudget::from_limit
    // plus one surplus slot), so after four entries share the common word the
    // first one is cut for any caller.
    stage = "read-scoped agent HTTP recall read-back";
    expect(await museRecall06RecallMentions(reader.client, alphaToken, alphaToken)).toBe(true);

    // Wrong actor kind: a write-only agent is refused the read. The HTTP
    // refusal carries the standard typed error envelope and no record text.
    const writerRecall = await writer.client.raw(
      "POST", "/v1/core/facade/vault.recall",
      { query: common, effort: "light", limit: 10 },
    );
    expect([401, 403]).toContain(writerRecall.status);
    const writerError = museRecall06WireError(writerRecall.body);
    expect(writerError?.code.length ?? 0).toBeGreaterThan(0);
    expect(writerError?.message.length ?? 0).toBeGreaterThan(0);
    expect((JSON.stringify(writerRecall.body) ?? "").includes(alphaToken)).toBe(false);

    // Its subscription attempt is refused too. sub.err is unstamped;
    // only the equivalent RPC recall has a public call receipt.
    stage = "write-only agent subscription";
    const writerSocket = await engine.websocket(writer);
    try {
      const writerSubscription = museRecall06Subscribe(writerSocket, common);
      const refused = await writerSubscription.next();
      expect(refused.kind).toBe("error");
      if (refused.kind !== "error") {
        throw new Error("Write-only subscription was not refused");
      }
      expect(refused.code.length).toBeGreaterThan(0);
      expect(refused.message.length).toBeGreaterThan(0);
      expect(`${refused.code} ${refused.message}`.includes(alphaToken)).toBe(false);
    } finally {
      writerSocket.close();
    }

    stage = "write-only agent RPC refusal receipt";
    await museRecallRefusalReceipt(engine, writer, "vault.recall", {
      query: common, effort: "light", limit: 10,
    });

    // Losing its scope mid-flow: the owner revokes the reader agent's
    // paired slip through the public slip door. Its next read and its
    // next socket are refused, and the revoke reads back in the audit log.
    stage = "reader grant revocation";
    const auditAfterPair = await museRecallAuditRows(engine.client);
    const beforeHashes = new Set(auditBefore.map(row => row.entry_hash));
    const readerMints = auditAfterPair.filter(row => !beforeHashes.has(row.entry_hash)
      && row.source_op === "slip_mint" && row.holder_ref === reader.principalRef);
    expect(readerMints).toHaveLength(1);
    const slipId = readerMints[0]!.subject_ref;
    if (typeof slipId !== "string" || slipId.length === 0) {
      throw new Error("Reader agent slip mint has no slip reference");
    }
    const revoked = await engine.client.request<{ revoked: boolean }>(
      "POST", "/v1/core/slips/revoke",
      { slip_id: Array.from(Buffer.from(slipId, "hex")) },
    );
    expect(revoked.status).toBe(200);
    expect(revoked.body.revoked).toBe(true);
    const readerAfterRevoke = await reader.client.raw(
      "POST", "/v1/core/facade/vault.recall",
      { query: common, effort: "light", limit: 10 },
    );
    expect(readerAfterRevoke.status).toBe(401);
    expect(await museRecall06ConnectFails(engine, reader)).toBe(true);
    const auditFinal = await museRecallAuditRows(engine.client);
    expect(auditFinal.some(row => row.source_op === "slip_revoke"
      && row.subject_ref === slipId && row.fold_valid)).toBe(true);

    // Survive a restart: the records read back over HTTP again, a fresh
    // subscription again sends a snapshot holding them before EOSE, and
    // the revoked reader is still refused.
    stage = "owner human restart snapshot then EOSE readback";
    await engine.restart();
    expect(await museRecall06RecallMentions(engine.client, common, deltaToken)).toBe(true);
    const restartedSocket = await engine.websocket();
    try {
      const restarted = museRecall06Subscribe(restartedSocket, common);
      const untilEoseAfterRestart = await museRecall06CollectUntil(
        restarted,
        events => events.some(event => event.kind === "eose"),
        20,
      );
      const eoseIndexAfterRestart = untilEoseAfterRestart
        .findIndex(event => event.kind === "eose");
      expect(eoseIndexAfterRestart).toBeGreaterThan(0);
      const snapshotAfterRestart = untilEoseAfterRestart.slice(0, eoseIndexAfterRestart);
      expect(snapshotAfterRestart.every(event => event.kind === "snapshot")).toBe(true);
      expect(snapshotAfterRestart.some(event => museRecall06EventMentions(event, alphaMention))).toBe(true);
      expect(snapshotAfterRestart.some(event => museRecall06EventMentions(event, deltaMention))).toBe(true);
    } finally {
      restartedSocket.close();
    }
    const readerAfterRestart = await reader.client.raw(
      "POST", "/v1/core/facade/vault.recall",
      { query: common, effort: "light", limit: 10 },
    );
    expect(readerAfterRestart.status).toBe(401);
  } catch (error) {
    if (error instanceof PublicHttpError) {
      throw new Error(
        `MUSE-RECALL-06 ${stage}: status=${error.reply.status} code=${error.error?.code ?? "<none>"} message=${error.error?.message ?? "<none>"} suggestion=${error.error?.suggestions?.[0] ?? "<none>"}`,
        { cause: error },
      );
    }
    const message = errorText(error);
    if (stage === "owner human live bravo sub.data" && message.includes("WS frame exceeded")) {
      throw new Error(
        `MUSE-RECALL-06 ENGINE DEFECT 2026-11-11: subscription 7 received snapshot and EOSE, then no live sub.data for HTTP-visible bravo; actor=owner human; auth.bind completed; channel=view filter.kind=MESSAGE; expected=live sub.data mentioning bravo; ${stage}; ${message}`,
        { cause: error },
      );
    }
    if (message.includes("WS closed 4008")) {
      throw new Error(
        `MUSE-RECALL-06 bound-principal admission refused at use; the run's 934e2510aee WsClient helper already performs auth.bind; ${stage}; ${message}`,
        { cause: error },
      );
    }
    throw new Error(`MUSE-RECALL-06 ${stage}: ${message}`, { cause: error });
  } finally {
    await engine.close();
  }
});

interface MuseRecall07BatchReply {
  readonly narrowing: ReadReceipt;
  readonly results: readonly {
    readonly ref: string;
    readonly outcome: "live" | "deleted" | "malformed_short_id" | "not_found" | "use_restricted";
    readonly result?: { readonly id?: string; readonly status: "live" | "deleted" };
    readonly error?: { readonly kind: "malformed_short_id" | "not_found" | "use_restricted"; readonly message: string };
  }[];
}
async function museRecall07BatchHydrate(client: PublicHttpClient, refs: readonly string[]): Promise<MuseRecall07BatchReply> {
  const reply = await client.request<MuseRecall07BatchReply>("POST", "/v1/core/batch/shortId/hydrate", {
    refs: [...refs], view: "full",
  });
  expect(reply.status).toBe(200);
  return reply.body;
}

type MuseRecall07EntityView = NonNullable<FacadeResult<"vault.get">["value"]>;
type MuseRecall07AuditRow = FacadeResult<"vault.authority.audit">["rows"][number];

interface MuseRecall07Person {
  readonly view: MuseRecall07EntityView;
  readonly shortId: string | null;
  readonly shortRef: string;
}

interface MuseRecall07ErrorBody {
  readonly error: { readonly code: string; readonly message: string };
}

function museRecall07BodyField(body: unknown, field: string): unknown {
  if (!body || typeof body !== "object" || Array.isArray(body)) return undefined;
  return (body as Record<string, unknown>)[field];
}

async function museRecall07Get(
  client: PublicHttpClient,
  entityRef: string,
): Promise<MuseRecall07EntityView> {
  const read = await client.call("vault.get", {
    entity_ref: entityRef,
  } satisfies FacadeInput<"vault.get">);
  if (!read.value) throw new Error(`Expected a public entity view for ${entityRef}`);
  return read.value;
}

async function museRecall07Hydrate(
  client: PublicHttpClient,
  refs: readonly string[],
): Promise<FacadeResult<"vault.hydrate">> {
  return client.call("vault.hydrate", {
    refs: [...refs],
  } satisfies FacadeInput<"vault.hydrate">);
}

async function museRecall07CreatePerson(
  engine: EngineFixture,
  name: string,
  occurredAt: number,
): Promise<MuseRecall07Person> {
  const created = await engine.client.call("vault.structural.put", {
    kind: "PERSON",
    body: { name },
    occurred_at: occurredAt,
  } satisfies FacadeInput<"vault.structural.put">);
  const view = await museRecall07Get(engine.client, created.entity_ref);
  expect(view.id_hex).toBe(created.id_hex);
  expect(view.kind).toBe("PERSON");
  return { view, shortId: (created.record?.short_id ?? view.short_ref)?.split(":")[0] ?? null, shortRef: created.entity_ref };
}

function museRecall07RequirePersonShortId(person: MuseRecall07Person): string {
  const shortId = person.shortId;
  if (!shortId) throw new Error("Expected a public short id for the created PERSON");
  return shortId;
}

async function museRecall07WitnessMessage(
  engine: EngineFixture,
  conversationRef: string,
  content: string,
  occurredAt: number,
): Promise<string> {
  const witnessed = await engine.client.call("vault.witness", {
    conversation_ref: conversationRef,
    occurred_at: occurredAt,
    messages: [{
      author: "user",
      message_type: "text",
      content,
      is_visible: true,
      order: 0,
    }],
  } satisfies FacadeInput<"vault.witness">);

  expect(witnessed.message_short_ids).toHaveLength(1);
  const shortId = witnessed.message_short_ids[0];
  if (!shortId) throw new Error("Witness returned no message short id");
  const saved = await museRecall07Get(engine.client, shortId);
  expect(museRecall07BodyField(saved.body, "content")).toBe(content);
  return shortId;
}

function museRecall07MintedSlipId(
  before: readonly MuseRecall07AuditRow[],
  after: readonly MuseRecall07AuditRow[],
  holderRef: string,
): string {
  const existing = new Set(before.map((row) => row.entry_hash));
  const minted = after.filter((row) => !existing.has(row.entry_hash)
    && row.source_op === "slip_mint" && row.holder_ref === holderRef);
  expect(minted).toHaveLength(1);
  const row = minted[0];
  if (!row) throw new Error("Expected one minted slip audit row");
  const slipId = row.subject_ref;
  if (!slipId || !/^[a-f0-9]{64}$/.test(slipId)) {
    throw new Error("Minted slip audit row has no hex subject ref");
  }
  return slipId;
}

async function museRecall07ExpectRawRefusal(
  client: PublicHttpClient,
  path: string,
  body: unknown,
  status: number,
) {
  const reply = await client.raw<MuseRecall07ErrorBody>("POST", path, body);
  expect(reply.status).toBe(status);
  expect(typeof reply.body.error.code).toBe("string");
  expect(reply.body.error.code.length).toBeGreaterThan(0);
  expect(typeof reply.body.error.message).toBe("string");
  expect(reply.body.error.message.length).toBeGreaterThan(0);
  return reply;
}

/*
 * MUSE-RECALL-07 (PARTIAL)
 * Promises: P-RECALL-022, P-RECALL-023, P-RECALL-024 and P-RECALL-025.
 * Doors used: vault.structural.put, vault.conversations.create, vault.witness,
 * vault.get, vault.hydrate, vault.delete, vault.authority.audit, the public
 * token-pair pairing in EngineFixture.pairActor, and POST /v1/core/slips/revoke.
 * Proved here: a short id hydrates to the same entity that vault.get reads for
 * the owner and for a core:read agent; an agent without core:read is refused;
 * a read agent whose slip is revoked is refused at its next use; a
 * hard-erased PERSON answers not_found without a result; a soft-deleted
 * PERSON answers deleted; neither bare pr short id is given to later PERSON
 * records, including after restart (engine-20261111-e2e4-recall-contract 2=A).
 * One 50-ref native batch returns live rows beside hard-erased, soft-deleted
 * and never-assigned refs.
 * Finished P-RECALL-025 through POST /v1/core/batch/shortId/hydrate:
 * 50 qualified refs return per-input live/deleted/not_found rows; a denied
 * live row is hidden as not_found while its readable neighbor succeeds.
 * P-RECALL-024, ruled subset: HardErase removes the mapping (not_found),
 * while user_delete keeps a deleted shell (deleted), also after restart.
 * Unproved: the single-door HTTP 404 distinction; native hydration uses 200.
 * Explicit access_denied reporting is also absent, not invented here.
 */
suite.test(test, "MUSE-RECALL-07", "A short id hydrates for read-granted callers, hard-erased and soft-deleted persons' short ids are not reused, and a 50-ref hydrate returns live rows despite erased, deleted and never-assigned refs", async () => {
  const engine = await EngineFixture.start({ id: "MUSE-RECALL-07", profile });
  try {
    const occurredAt = 1769947200;
    const liveText = "muse recall 07 live harbour lantern stays readable";
    redactor.add(liveText);

    const readerPerson = await museRecall07CreatePerson(
      engine, "Muse Recall 07 Reader Agent", occurredAt,
    );
    const writerPerson = await museRecall07CreatePerson(
      engine, "Muse Recall 07 Writer Agent", occurredAt,
    );
    const auditBeforePairing = await museRecallAuditRows(engine.client);
    const reader = await engine.pairActor({
      principalRef: readerPerson.view.id_hex,
      actorClass: "agent",
      scope: ["core:read"],
    });
    const writer = await engine.pairActor({
      principalRef: writerPerson.view.id_hex,
      actorClass: "agent",
      scope: ["core:write"],
    });

    const conversation = await engine.client.call("vault.conversations.create", {
      body: {
        members: [
          engine.pairedActor.principalRef,
          reader.principalRef,
          writer.principalRef,
        ],
      },
      occurred_start: occurredAt,
      occurred_end: occurredAt,
      learned_at: occurredAt,
    } satisfies FacadeInput<"vault.conversations.create">);
    await museRecallReadSetup(engine, conversation.id, "CONVERSATION");
    const liveShortId = await museRecall07WitnessMessage(
      engine, conversation.id, liveText, occurredAt,
    );
    const liveView = await museRecall07Get(engine.client, liveShortId);
    expect(liveView.kind).toBe("MESSAGE");
    expect(museRecall07BodyField(liveView.body, "content")).toBe(liveText);

    const ownerHydrated = await museRecall07Hydrate(engine.client, [liveShortId]);
    expect(ownerHydrated.value).toHaveLength(1);
    expect(ownerHydrated.value[0]?.id_hex).toBe(liveView.id_hex);
    expect(ownerHydrated.value[0]?.kind).toBe("MESSAGE");
    expect(museRecall07BodyField(ownerHydrated.value[0]?.body, "content")).toBe(liveText);

    const readerView = await museRecall07Get(reader.client, liveShortId);
    expect(readerView.id_hex).toBe(liveView.id_hex);
    const readerHydrated = await museRecall07Hydrate(reader.client, [liveShortId]);
    expect(readerHydrated.value).toHaveLength(1);
    expect(readerHydrated.value[0]?.id_hex).toBe(liveView.id_hex);
    expect(museRecall07BodyField(readerHydrated.value[0]?.body, "content")).toBe(liveText);

    // These authenticated HTTP refusals carry a call receipt. Read it back as
    // owner through vault.receipts.get.
    const readRefusalReceipt = async (
      reply: { readonly status: number; readonly headers: Headers; readonly body: unknown },
      verb: "vault.hydrate" | "vault.delete",
      receiptFrom: "body" | "header" = "body",
    ): Promise<void> => {
      const wire = reply.body as {
        readonly error?: {
          readonly code?: unknown; readonly message?: unknown;
          readonly suggestions?: unknown; readonly receiptRef?: unknown;
        };
      };
      const errorCode = wire.error?.code;
      const code = typeof errorCode === "string" ? errorCode : "<none>";
      const errorMessage = wire.error?.message;
      const message = typeof errorMessage === "string" ? errorMessage : "<none>";
      const errorSuggestions = wire.error?.suggestions;
      const firstSuggestion = Array.isArray(errorSuggestions) ? errorSuggestions[0] : undefined;
      const suggestion = typeof firstSuggestion === "string" ? firstSuggestion : "<none>";
      const receiptRefValue = wire.error?.receiptRef;
      const bodyRef = typeof receiptRefValue === "string" && receiptRefValue.length > 0
        ? receiptRefValue : undefined;
      // Pre-auth refusals have a connection receipt in the header only.
      const header = reply.headers.get("x-oneiron-receipt-ref");
      const headerRef = header && header !== "none; no-record" ? header : undefined;
      const receiptRef = receiptFrom === "header" ? headerRef : bodyRef;
      if (!receiptRef) {
        throw new Error(
          `MUSE-RECALL-07 ${verb} HTTP refusal missing call receipt: status=${reply.status} code=${code} message=${message} suggestion=${suggestion}`,
        );
      }
      if (receiptFrom === "body" && header !== receiptRef) {
        throw new Error(
          `MUSE-RECALL-07 ${verb} refusal receipt mismatch: status=${reply.status} code=${code} message=${message} suggestion=${suggestion} header=${header ?? "<none>"} receiptRef=${receiptRef}`,
        );
      }
      const receipt = await awaitPublic(
        () => engine.client.call("vault.receipts.get", { receipt_ref: receiptRef }),
        (value) => value !== null,
        { label: `MUSE-RECALL-07 ${verb} refusal call receipt ${receiptRef}` },
      );
      if (!receipt || receipt.outcome === "ok") {
        throw new Error(
          `MUSE-RECALL-07 call receipt did not record the ${verb} refusal: status=${reply.status} code=${code} message=${message} suggestion=${suggestion} receiptRef=${receiptRef}`,
        );
      }
      expect(receipt.verb).toBe(verb);
      expect(receipt.outcome.refused.code.length).toBeGreaterThan(0);
    };
    const writerDenied = await museRecall07ExpectRawRefusal(
      writer.client,
      "/v1/core/facade/vault.hydrate",
      { refs: [liveShortId] } satisfies FacadeInput<"vault.hydrate">,
      403,
    );
    expect(JSON.stringify(writerDenied.body).includes(liveText)).toBe(false);
    await readRefusalReceipt(writerDenied, "vault.hydrate");

    const readerSlipId = museRecall07MintedSlipId(
      auditBeforePairing,
      await museRecallAuditRows(engine.client),
      reader.principalRef,
    );
    const revoked = await engine.client.request<{ revoked: boolean }>(
      "POST",
      "/v1/core/slips/revoke",
      { slip_id: Array.from(Buffer.from(readerSlipId, "hex")) },
    );
    expect(revoked.status).toBe(200);
    expect(revoked.body.revoked).toBe(true);
    const readerRevoked = await museRecall07ExpectRawRefusal(
      reader.client,
      "/v1/core/facade/vault.hydrate",
      { refs: [liveShortId] } satisfies FacadeInput<"vault.hydrate">,
      401,
    );
    await readRefusalReceipt(readerRevoked, "vault.hydrate", "header");

    const retiredPerson = await museRecall07CreatePerson(
      engine, "Muse Recall 07 Retired Person", occurredAt,
    );
    const retiredShortId = museRecall07RequirePersonShortId(retiredPerson);
    const expectRetiredRow = (
      batch: MuseRecall07BatchReply,
      index: number,
      stage: string,
    ): void => {
      const row = batch.results[index];
      try {
        expect(row?.outcome).toBe("not_found");
        expect(row?.result).toBeUndefined();
      } catch (error) {
        throw new Error(
          `MUSE-RECALL-07 HardErase answers not_found (ruling engine-20261111-e2e4-recall-contract 2=A): ref=${retiredPerson.shortRef} expected=not_found,no_result outcome=${row?.outcome ?? "<missing>"} result_status=${row?.result?.status ?? "<missing>"} row=${redactor.text(JSON.stringify(row) ?? "<missing>")}; ${stage}; ${errorText(error)}`,
          { cause: error },
        );
      }
    };
    const retiredHydrated = await museRecall07Hydrate(engine.client, [retiredPerson.shortRef]);
    expect(retiredHydrated.value).toHaveLength(1);
    expect(retiredHydrated.value[0]?.id_hex).toBe(retiredPerson.view.id_hex);
    expect(retiredHydrated.value[0]?.kind).toBe("PERSON");

    const deleteDenied = await museRecall07ExpectRawRefusal(
      writer.client,
      "/v1/core/facade/vault.delete",
      {
        entity_ref: retiredPerson.view.id_hex,
        reason: "user_hard_delete",
      } satisfies FacadeInput<"vault.delete">,
      403,
    );
    await readRefusalReceipt(deleteDenied, "vault.delete");
    const stillLive = await museRecall07Get(engine.client, retiredPerson.shortRef);
    expect(stillLive.id_hex).toBe(retiredPerson.view.id_hex);

    const deleted = await engine.client.call("vault.delete", {
      entity_ref: retiredPerson.view.id_hex,
      reason: "user_hard_delete",
    } satisfies FacadeInput<"vault.delete">);
    expect(deleted.existed).toBe(true);
    if (!deleted.receipt_ref) throw new Error("Hard delete returned no deletion receipt ref");

    const retiredRead = await awaitPublic(
      () => engine.client.call("vault.get", {
        entity_ref: retiredPerson.shortRef,
      } satisfies FacadeInput<"vault.get">),
      (read) => read.value === null,
      { label: `MUSE-RECALL-07 hard-deleted PERSON ref=${retiredPerson.shortRef} reads absent through vault.get` },
    );
    expect(retiredRead.value).toBeNull();
    await engine.requireHttpDoor("/v1/core/batch/shortId/hydrate", "POST");
    const retiredBatch = await museRecall07BatchHydrate(engine.client, [retiredPerson.shortRef]);
    expectRetiredRow(retiredBatch, 0, "owner batch hydrate after hard delete");

    // user_delete is the public soft delete: keep its resolvable shell,
    // unlike HardErase. Refuse the write-only agent and read the refusal
    // receipt and the still-live PERSON back before the owner deletes it.
    const softDeletedPerson = await museRecall07CreatePerson(
      engine, "Muse Recall 07 Soft Deleted Person", occurredAt,
    );
    const softDeletedShortId = museRecall07RequirePersonShortId(softDeletedPerson);
    const softDeleteDenied = await museRecall07ExpectRawRefusal(
      writer.client,
      "/v1/core/facade/vault.delete",
      {
        entity_ref: softDeletedPerson.view.id_hex, reason: "user_delete",
      } satisfies FacadeInput<"vault.delete">,
      403,
    );
    await readRefusalReceipt(softDeleteDenied, "vault.delete");
    expect((await museRecall07Get(engine.client, softDeletedPerson.shortRef)).id_hex)
      .toBe(softDeletedPerson.view.id_hex);
    const softDeleted = await engine.client.call("vault.delete", {
      entity_ref: softDeletedPerson.view.id_hex, reason: "user_delete",
    } satisfies FacadeInput<"vault.delete">);
    expect(softDeleted.existed).toBe(true);
    const softDeletedRead = await awaitPublic(
      () => engine.client.call("vault.get", { entity_ref: softDeletedPerson.shortRef }),
      read => read.value === null,
      { label: `MUSE-RECALL-07 soft-deleted PERSON ref=${softDeletedPerson.shortRef} reads absent through vault.get` },
    );
    expect(softDeletedRead.value).toBeNull();
    const expectSoftDeletedRow = (
      batch: MuseRecall07BatchReply,
      index: number,
      stage: string,
    ): void => {
      const row = batch.results[index];
      try {
        expect(row?.outcome).toBe("deleted");
        expect(row?.result?.status).toBe("deleted");
        expect(row?.result?.id).toBe(softDeletedPerson.view.id_hex);
      } catch (error) {
        throw new Error(
          `MUSE-RECALL-07 soft delete answers deleted (ruling engine-20261111-e2e4-recall-contract 2=A): ref=${softDeletedPerson.shortRef} expected=deleted outcome=${row?.outcome ?? "<missing>"} row=${redactor.text(JSON.stringify(row) ?? "<missing>")}; ${stage}; ${errorText(error)}`,
          { cause: error },
        );
      }
    };
    const softDeletedBatch = await museRecall07BatchHydrate(engine.client, [softDeletedPerson.shortRef]);
    expectSoftDeletedRow(softDeletedBatch, 0, "owner batch hydrate after soft delete");

    const replacementPersons: MuseRecall07Person[] = [];
    for (const name of [
      "Muse Recall 07 Replacement One",
      "Muse Recall 07 Replacement Two",
      "Muse Recall 07 Replacement Three",
    ]) {
      replacementPersons.push(await museRecall07CreatePerson(engine, name, occurredAt));
    }
    const replacementShortIds = replacementPersons.map(museRecall07RequirePersonShortId);
    expect(replacementShortIds.includes(retiredShortId)).toBe(false);
    expect(replacementShortIds.includes(softDeletedShortId)).toBe(false);
    const firstReplacement = replacementPersons[0];
    if (!firstReplacement) throw new Error("Expected a replacement PERSON");

    const neverAssignedRefs = Array.from(
      { length: 45 },
      (_unused, index) => `pr${900000 + index}:00`,
    );
    const batchRefs = [
      liveShortId,
      firstReplacement.shortRef,
      retiredPerson.shortRef,
      softDeletedPerson.shortRef,
      "ms999999:00",
      ...neverAssignedRefs,
    ];
    expect(batchRefs).toHaveLength(50);
    expect(new Set(batchRefs).size).toBe(50);
    const batch = await museRecall07BatchHydrate(engine.client, batchRefs);
    expect(batch.results.map(row => row.ref)).toEqual(batchRefs);
    const batchIds = new Set(batch.results.flatMap(row => row.result?.id ? [row.result.id] : []));
    expect(batch.results[0]?.outcome).toBe("live");
    expect(batch.results[0]?.result?.id).toBe(liveView.id_hex);
    expect(batch.results[1]?.outcome).toBe("live");
    expect(batch.results[1]?.result?.id).toBe(firstReplacement.view.id_hex);
    expectRetiredRow(batch, 2, "owner mixed 50-ref batch hydrate");
    expectSoftDeletedRow(batch, 3, "owner mixed 50-ref batch hydrate");
    for (const row of batch.results.slice(4)) {
      expect(row.outcome).toBe("not_found");
      expect(row.error?.kind).toBe("not_found");
    }
    // A named but unreadable live row reports no body without failing its
    // readable neighbor. The wire hides denial as not_found, not access_denied.
    const deniedPerson = replacementPersons[1]!;
    const limited = await recordBoundReader(engine, [liveView.id_hex]);
    const deniedBatch = await museRecall07BatchHydrate(limited, [liveShortId, deniedPerson.shortRef]);
    expect(deniedBatch.results[0]?.outcome).toBe("live");
    expect(deniedBatch.results[1]?.outcome).toBe("not_found");
    expect(deniedBatch.results[1]?.result).toBeUndefined();
    const ownerDeniedControl = await museRecall07Get(engine.client, deniedPerson.shortRef);
    expect(ownerDeniedControl.id_hex).toBe(deniedPerson.view.id_hex);

    await engine.restart();

    const liveAfterRestart = await museRecall07Get(engine.client, liveShortId);
    expect(liveAfterRestart.id_hex).toBe(liveView.id_hex);
    expect(museRecall07BodyField(liveAfterRestart.body, "content")).toBe(liveText);
    const hydratedAfterRestart = await museRecall07BatchHydrate(engine.client, [
      liveShortId, retiredPerson.shortRef, softDeletedPerson.shortRef, "ms999999:00",
    ]);
    try {
      expect(hydratedAfterRestart.results.map(row => row.outcome)).toEqual(["live", "not_found", "deleted", "not_found"]);
    } catch (error) {
      throw new Error(
        `MUSE-RECALL-07 HardErase answers not_found (ruling engine-20261111-e2e4-recall-contract 2=A); soft delete answers deleted; batch outcomes after restart: retired_ref=${retiredPerson.shortRef} soft_deleted_ref=${softDeletedPerson.shortRef} expected=live,not_found,deleted,not_found rows=${redactor.text(JSON.stringify(hydratedAfterRestart.results) ?? "<missing>")}; ${errorText(error)}`,
        { cause: error },
      );
    }
    expect(hydratedAfterRestart.results[0]?.result?.id).toBe(liveView.id_hex);
    expectRetiredRow(hydratedAfterRestart, 1, "owner batch hydrate after restart");
    expectSoftDeletedRow(hydratedAfterRestart, 2, "owner batch hydrate after restart");
    const retiredAfterRestart = await engine.client.call("vault.get", {
      entity_ref: retiredPerson.shortRef,
    } satisfies FacadeInput<"vault.get">);
    expect(retiredAfterRestart.value).toBeNull();
    const softDeletedAfterRestart = await engine.client.call("vault.get", {
      entity_ref: softDeletedPerson.shortRef,
    });
    expect(softDeletedAfterRestart.value).toBeNull();

    const postRestartPerson = await museRecall07CreatePerson(
      engine, "Muse Recall 07 Post Restart Person", occurredAt,
    );
    const postRestartShortId = museRecall07RequirePersonShortId(postRestartPerson);
    expect(postRestartShortId === retiredShortId).toBe(false);
    expect(postRestartShortId === softDeletedShortId).toBe(false);
    const postRestartHydrated = await museRecall07Hydrate(
      engine.client, [postRestartPerson.shortRef],
    );
    expect(postRestartHydrated.value).toHaveLength(1);
    expect(postRestartHydrated.value[0]?.id_hex).toBe(postRestartPerson.view.id_hex);

    const readerRevokedAfterRestart = await museRecall07ExpectRawRefusal(
      reader.client,
      "/v1/core/facade/vault.hydrate",
      { refs: [liveShortId] } satisfies FacadeInput<"vault.hydrate">,
      401,
    );
    await readRefusalReceipt(readerRevokedAfterRestart, "vault.hydrate", "header");

    await engine.artifacts.json("muse-recall-07.json", {
      liveShortId,
      liveIdHex: liveView.id_hex,
      retiredShortId,
      retiredIdHex: retiredPerson.view.id_hex,
      softDeletedShortId,
      softDeletedIdHex: softDeletedPerson.view.id_hex,
      deleteReceiptRef: deleted.receipt_ref,
      replacementShortIds,
      postRestartShortId,
      batchLiveIds: [...batchIds],
    });
  } catch (error) {
    if (!(error instanceof PublicHttpError)) throw error;
    throw new Error(
      `MUSE-RECALL-07 public setup/hydrate/receipt readback: status=${error.reply.status} code=${error.error?.code ?? "<none>"} message=${error.error?.message ?? "<none>"} suggestion=${error.error?.suggestions?.[0] ?? "<none>"}`,
      { cause: error },
    );
  } finally {
    await engine.close();
  }
});

// MUSE-RECALL-08 — P-RECALL-021 (MUST): Recall supports TOON, Markdown,
// JSON, YAML, and plaintext serialization.
// Canon: ARCH-0044 S6 says recall exposes query/effort/scope/limit/format;
// C4 names the five wire spellings one serializer writes: toon, md, json,
// yaml, txt (plaintext). Doors used: vault.witness (act), vault.get (second-door
// read-back), vault.recall over HTTP and WS with each format (the serialized
// pack is MemoryPack.rendered), vault.authority.audit plus POST
// /v1/core/slips/revoke for the loses-its-grant leg, vault.receipts.get for
// the refusal receipt, and engine.restart().
// Unproved here: TOON/YAML grammar validity is not parsed (no parser door is
// known to this suite; JSON is parsed, the rest must be pairwise-distinct
// renderings carrying the same item), the default format when format is
// omitted, first-mention name-plus-id rendering (canon says it is missing),
// and rejection of an unknown format string (the promise names only the
// five supported formats).

type museRecall08Pack = FacadeResult<"vault.recall">;
type museRecall08AuditRow = FacadeResult<"vault.authority.audit">["rows"][number];
type museRecall08ItemSignatureRow = {
  short_id: string;
  kind: string;
  value_text: string;
  predicate: string | null;
};

const museRecall08Formats = ["toon", "md", "json", "yaml", "txt"] as const;
const museRecall08OccurredAt = 1769947200;

function museRecall08Object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Expected a public JSON object (body withheld)");
  }
  return value as Record<string, unknown>;
}

function museRecall08PackHas(pack: museRecall08Pack, sentinel: string): boolean {
  return pack.items.some(item => item.value_text.includes(sentinel)
    || (item.cited_messages?.some(message => message.value_text.includes(sentinel)) ?? false));
}

function museRecall08Rendered(pack: museRecall08Pack): string {
  const rendered = pack.rendered;
  expect(typeof rendered).toBe("string");
  if (typeof rendered !== "string" || rendered.length === 0) {
    throw new Error("Recall with a format returned no rendered pack");
  }
  return rendered;
}

function museRecall08ItemSignature(pack: museRecall08Pack): museRecall08ItemSignatureRow[] {
  return pack.items.map(item => ({
    short_id: item.short_id,
    kind: item.kind,
    value_text: item.value_text,
    predicate: item.predicate ?? null,
  }));
}

function museRecall08JsonContains(value: unknown, needle: string): boolean {
  if (typeof value === "string") return value.includes(needle);
  if (Array.isArray(value)) return value.some(entry => museRecall08JsonContains(entry, needle));
  if (value && typeof value === "object") {
    return Object.entries(value as Record<string, unknown>)
      .some(([key, entry]) => key.includes(needle) || museRecall08JsonContains(entry, needle));
  }
  return false;
}

async function museRecall08RecallAllFormats(
  client: EngineFixture["client"],
  query: string,
): Promise<Map<string, museRecall08Pack>> {
  const packs = new Map<string, museRecall08Pack>();
  for (const format of museRecall08Formats) {
    try {
      packs.set(format, await client.call("vault.recall", {
        query, effort: "light", limit: 10, format,
      }));
    } catch (error) {
      if (!(error instanceof PublicHttpError)) throw error;
      throw new Error(
        `MUSE-RECALL-08 vault.recall format=${format}: status=${error.reply.status} code=${error.error?.code ?? "<none>"} message=${error.error?.message ?? "<none>"} suggestion=${error.error?.suggestions?.[0] ?? "<none>"}`,
        { cause: error },
      );
    }
  }
  return packs;
}

function museRecall08PackFor(
  packs: ReadonlyMap<string, museRecall08Pack>,
  format: string,
): museRecall08Pack {
  const pack = packs.get(format);
  if (!pack) throw new Error("Missing recall pack for a requested format (name withheld)");
  return pack;
}

function museRecall08AssertSamePackAllFormats(
  packs: ReadonlyMap<string, museRecall08Pack>,
  sentinel: string,
): museRecall08ItemSignatureRow[] {
  expect(packs.size).toBe(museRecall08Formats.length);
  const reference = museRecall08PackFor(packs, "toon");
  const referenceSignature = museRecall08ItemSignature(reference);
  expect(referenceSignature.length).toBeGreaterThan(0);
  expect(new Set([...packs.values()].map(pack => pack.pack_version)).size).toBe(1);
  const renderings: string[] = [];
  for (const format of museRecall08Formats) {
    const pack = museRecall08PackFor(packs, format);
    // The format changes the serialization, never the pack it serializes.
    expect(museRecall08ItemSignature(pack)).toEqual(referenceSignature);
    expect(museRecall08PackHas(pack, sentinel)).toBe(true);
    const rendered = museRecall08Rendered(pack);
    try {
      expect(rendered.includes(sentinel)).toBe(true);
    } catch (error) {
      throw new Error(
        `MUSE-RECALL-08 ENGINE DEFECT 2026-11-11: light recall drops message text from rendered pack; format=${format} item_has_sentinel=${museRecall08PackHas(pack, sentinel)} rendered_has_sentinel=${rendered.includes(sentinel)} rendered_chars=${rendered.length}; recall/mod.rs:849-853 disables hydration before serialize/pack_preparation.rs:287`,
        { cause: error },
      );
    }
    renderings.push(rendered);
  }
  // Five formats means five serializations, not one default repeated.
  expect(new Set(renderings).size).toBe(museRecall08Formats.length);
  const jsonPack = museRecall08PackFor(packs, "json");
  const first = jsonPack.items[0];
  if (!first) throw new Error("JSON recall pack returned no item");
  const parsedJson: unknown = JSON.parse(museRecall08Rendered(jsonPack));
  expect(museRecall08JsonContains(parsedJson, sentinel)).toBe(true);
  expect(museRecall08JsonContains(parsedJson, first.short_id)).toBe(true);
  return referenceSignature;
}

function museRecall08MintedSlipId(
  rowsBefore: readonly museRecall08AuditRow[],
  rowsAfter: readonly museRecall08AuditRow[],
  holder: string,
): string {
  const existing = new Set(rowsBefore.map(row => row.entry_hash));
  const minted = rowsAfter.filter(row => !existing.has(row.entry_hash)
    && row.source_op === "slip_mint" && row.holder_ref === holder);
  expect(minted).toHaveLength(1);
  const row = minted[0]!;
  const slipId = row.subject_ref;
  if (!slipId) throw new Error("Minted slip row has no subject reference");
  return slipId;
}

suite.test(test, "MUSE-RECALL-08", "Recall serializes the same pack in all five formats", async () => {
  const sentinel = `quokkalantern${secretHex(4)}`;
  redactor.add(sentinel);
  const content = `The ${sentinel} marker says the observatory notebook stays on the blue shelf.`;
  const nameSuffix = secretHex(4);
  redactor.add(nameSuffix);
  const readerName = `MuseRecall08 Reader ${nameSuffix}`;
  const writerName = `MuseRecall08 Writer ${nameSuffix}`;
  redactor.add(readerName, writerName);
  const jsonRecall: FacadeInput<"vault.recall"> = {
    query: sentinel, effort: "light", limit: 10, format: "json",
  };

  const engine = await EngineFixture.start({ id: "MUSE-RECALL-08", profile });
  try {
    // Two agents on real pairing scopes: one may read, one may only write.
    const readerRecord = await engine.client.call("vault.structural.put", {
      kind: "PERSON", body: { name: readerName }, occurred_at: museRecall08OccurredAt,
    });
    await museRecallReadSetup(engine, readerRecord.entity_ref, "PERSON");
    const writerRecord = await engine.client.call("vault.structural.put", {
      kind: "PERSON", body: { name: writerName }, occurred_at: museRecall08OccurredAt,
    });
    await museRecallReadSetup(engine, writerRecord.entity_ref, "PERSON");
    const auditBeforeReader = await museRecallAuditRows(engine.client);
    const reader = await engine.pairActor({
      principalRef: readerRecord.id_hex, actorClass: "agent", scope: ["core:read"],
    });
    const readerSlipId = museRecall08MintedSlipId(
      auditBeforeReader, await museRecallAuditRows(engine.client), reader.principalRef,
    );
    const writer = await engine.pairActor({
      principalRef: writerRecord.id_hex, actorClass: "agent", scope: ["core:write"],
    });

    // Act: witness one turn through the owner, in a conversation all three
    // actors belong to, so the agents differ only in their pairing scope.
    const conversation = await engine.client.call("vault.conversations.create", {
      body: { members: [engine.pairedActor.principalRef, reader.principalRef, writer.principalRef] },
      occurred_start: museRecall08OccurredAt, occurred_end: museRecall08OccurredAt,
    } satisfies FacadeInput<"vault.conversations.create">);
    await museRecallReadSetup(engine, conversation.id, "CONVERSATION");
    const witnessed = await engine.client.call("vault.witness", {
      conversation_ref: conversation.id,
      occurred_at: museRecall08OccurredAt,
      messages: [{
        author: "user", message_type: "text", is_visible: true, order: 0, content,
      }],
    } satisfies FacadeInput<"vault.witness">);

    expect(witnessed.message_short_ids).toHaveLength(1);
    const messageRef = witnessed.message_short_ids[0];
    if (!messageRef) throw new Error("Witness returned no message reference");

    // Observe through a second door: the witnessed message reads back exact
    // through vault.get, and recall finds it before any format is asked for.
    const saved = await engine.client.call("vault.get", { entity_ref: messageRef });
    if (!saved.value) throw new Error("Witnessed message is not publicly readable");
    expect(museRecall08Object(saved.value.body).content).toBe(content);
    const baseline = await awaitPublic(
      () => engine.client.call("vault.recall", { query: sentinel, effort: "light", limit: 10 }),
      pack => museRecall08PackHas(pack, sentinel),
      { label: "MUSE-RECALL-08 baseline recall finds the witnessed sentinel turn" },
    );
    expect(museRecall08ItemSignature(baseline).length).toBeGreaterThan(0);

    // The promise: the same pack, serialized in each of the five formats.
    const packs = await museRecall08RecallAllFormats(engine.client, sentinel);
    const signature = museRecall08AssertSamePackAllFormats(packs, sentinel);

    // Second surface: the same JSON serialization is served over the WS door,
    // for the same pack and with the sentinel item inside its parsed JSON.
    const ownerSocket = await engine.websocket();
    try {
      const viaSocket = await ownerSocket.call("vault.recall", jsonRecall);
      expect(museRecall08ItemSignature(viaSocket.value)).toEqual(signature);
      const socketRendered = museRecall08Rendered(viaSocket.value);
      expect(socketRendered.includes(sentinel)).toBe(true);
      const parsedSocketJson: unknown = JSON.parse(socketRendered);
      expect(museRecall08JsonContains(parsedSocketJson, sentinel)).toBe(true);
    } finally {
      ownerSocket.close();
    }

    // Wrong actor: an authenticated agent without the read scope is refused
    // with the standard envelope over HTTP and leaks no recalled content.
    const writerDenied = await writer.client
      .raw<{ error?: { code?: string; message?: string } }>(
        "POST", "/v1/core/facade/vault.recall", jsonRecall,
      );
    expect(writerDenied.status).toBe(403);
    expect(typeof writerDenied.body.error?.code).toBe("string");
    expect((writerDenied.body.error?.code ?? "").length).toBeGreaterThan(0);
    expect(typeof writerDenied.body.error?.message).toBe("string");
    expect((writerDenied.body.error?.message ?? "").length).toBeGreaterThan(0);
    expect((JSON.stringify(writerDenied.body) ?? "").includes(sentinel)).toBe(false);

    // The same refusal over WS leaves a call receipt the owner can read back.
    const writerSocket = await engine.websocket(writer);
    let wsRefusal: unknown = undefined;
    try {
      await writerSocket.call("vault.recall", jsonRecall);
    } catch (error) {
      wsRefusal = error;
    } finally {
      writerSocket.close();
    }
    expect(wsRefusal instanceof WsRpcError).toBe(true);
    if (!(wsRefusal instanceof WsRpcError)) {
      throw new Error("Write-only agent recall over WS was not refused");
    }
    const errFrame = wsRefusal.frames.find(frame => frame.envelope.type === "rpc.err");
    expect(errFrame).toBeDefined();
    const refusalReceiptRef = errFrame?.envelope.receipt_ref;
    expect(typeof refusalReceiptRef).toBe("string");
    if (!refusalReceiptRef) throw new Error("WS recall refusal carries no receipt reference");
    const refusalReceipt = await awaitPublic(
      () => engine.client.call("vault.receipts.get", { receipt_ref: refusalReceiptRef }),
      receipt => receipt !== null,
      { label: "MUSE-RECALL-08 write-only agent recall refusal call receipt" },
    );
    if (!refusalReceipt) throw new Error("Recall refusal left no readable call receipt");
    expect(refusalReceipt.verb).toBe("vault.recall");
    expect(refusalReceipt.actor_class).toBe("agent");
    expect(refusalReceipt.outcome).not.toBe("ok");
    if (refusalReceipt.outcome === "ok") throw new Error("Refused recall was receipted as ok");
    expect(refusalReceipt.outcome.refused.code.length).toBeGreaterThan(0);

    // The reader agent holds the read scope and recalls the pack in JSON.
    const readerPack = await reader.client.call("vault.recall", jsonRecall);
    expect(museRecall08PackHas(readerPack, sentinel)).toBe(true);
    expect(museRecall08Rendered(readerPack).includes(sentinel)).toBe(true);

    // Loses the grant mid-flow: the owner revokes the reader's slip through
    // the public door, its next recall is refused, and the audit shows why.
    const revoked = await engine.client.request<{ revoked: boolean }>(
      "POST", "/v1/core/slips/revoke", {
        slip_id: Array.from(Buffer.from(readerSlipId, "hex")),
      },
    );
    expect(revoked.status).toBe(200);
    expect(revoked.body.revoked).toBe(true);
    const readerAfterRevoke = await reader.client
      .raw<{ error?: { code?: string; message?: string } }>(
        "POST", "/v1/core/facade/vault.recall", jsonRecall,
      );
    expect(readerAfterRevoke.status).toBe(401);
    expect(readerAfterRevoke.body.error?.code).toBe("UNAUTHORIZED");
    expect((JSON.stringify(readerAfterRevoke.body) ?? "").includes(sentinel)).toBe(false);
    const auditAfterRevoke = await museRecallAuditRows(engine.client);
    expect(auditAfterRevoke.some(row => row.source_op === "slip_revoke"
      && row.subject_ref === readerSlipId && row.fold_valid)).toBe(true);

    // Survive a restart: the same pack still serializes in all five formats,
    // the revoked reader is still refused, and the revoke is still on record.
    await engine.restart();
    const packsAfterRestart = await museRecall08RecallAllFormats(engine.client, sentinel);
    const signatureAfterRestart = museRecall08AssertSamePackAllFormats(packsAfterRestart, sentinel);
    expect(signatureAfterRestart).toEqual(signature);
    const readerAfterRestart = await reader.client
      .raw<{ error?: { code?: string; message?: string } }>(
        "POST", "/v1/core/facade/vault.recall", jsonRecall,
      );
    expect(readerAfterRestart.status).toBe(401);
    expect(readerAfterRestart.body.error?.code).toBe("UNAUTHORIZED");
    const auditAfterRestart = await museRecallAuditRows(engine.client);
    expect(auditAfterRestart.some(row => row.source_op === "slip_revoke"
      && row.subject_ref === readerSlipId && row.fold_valid)).toBe(true);
  } catch (error) {
    if (!(error instanceof PublicHttpError)) throw error;
    throw new Error(
      `MUSE-RECALL-08 public setup/readback: status=${error.reply.status} code=${error.error?.code ?? "<none>"} message=${error.error?.message ?? "<none>"} suggestion=${error.error?.suggestions?.[0] ?? "<none>"}`,
      { cause: error },
    );
  } finally {
    await engine.close();
  }
});
