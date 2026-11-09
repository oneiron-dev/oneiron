import { afterAll, expect, test } from "bun:test";
import { inflateRawSync } from "node:zlib";
import { blake3 } from "@noble/hashes/blake3";
import type { FacadeInput, FacadeResult, FacadeVerb } from "@oneiron/client";
import { EngineFixture, awaitPublic, type PairedActor } from "./support/engine.ts";
import { PublicHttpClient } from "./support/clients.ts";
import { loadFixtures, ownerBaseClaimScope } from "./support/fixtures.ts";
import { defineFile, redactor } from "./support/run.ts";
import { ScriptedProviders, openaiText, type ProviderStep } from "./support/providers.ts";

const profile = process.env.E2E_PROFILE === "real-small-model"
  ? "real-small-model" : "deterministic";
const suite = defineFile(import.meta, { profile, slots: 1 });
afterAll(suite.flush);

/*
 * Secret custody and policy. Binding read at main
 * 5ecd5af5bea2c70e25760f0583f276790f49fba4, not the older canon build notes.
 * Oracle: ARCH-0069 #handles/#reveal-check/#ladder/#rotation/#result-bodies;
 * ARCH-0038 #secret-scan-target; ARCH-0047 #door/#receipt; registry OF-061,
 * OF-067, OF-333, OF-422, OF-425, OF-431, OF-453, OF-527, OF-559, OF-560,
 * OF-597. G04=A is settled: a structured field keeps a custody handle too.
 * Binary-file scanning is not inferred from that ruling.
 *
 * Existing owner routes below have Rust DTOs but no generated owner client.
 * Their small wire mirrors stay here, not in the shared harness. Designed
 * doors without a typed public call remain registered TODOs under G01.
 */
interface MaskFixture {
  occurredAt: number;
  agentName: string;
  prefix: string;
  suffix: string;
  textHandleTemplate: string;
  credential: string;
  fieldCredential: string;
  fieldNote: string;
  fieldTail: string;
  predicate: string;
  query: string;
  agentReason: string;
  ownerReason: string;
}
interface OwnerRevealInput { handle: string; reason: string }
interface OwnerRevealReceipt {
  reveal: string;
  handle: string;
  class: string;
  why: string;
  reader: string;
  connection: string | null;
  answered_by: string | null;
  receipt_ref: string | null;
  delivered_at: number | null;
}
interface OwnerRevealAsk extends OwnerRevealReceipt {
  state: string;
  expected_digest: string | null;
}
interface OwnerRevealAnswerInput {
  reveal: string;
  expected_digest: string;
  outcome: "once" | "standing" | "deny";
}
interface OwnerRevealAnswered {
  reveal: string;
  outcome: string;
  receipt_ref: string;
  grant_ref: string | null;
}
interface OwnerRevealed { value_base64: string; receipt: OwnerRevealReceipt }
interface ScanChange {
  receipt_id: string;
  revision: number;
  author: string;
  mode: "on" | "off";
  previous: "on" | "off";
  at: number;
}
interface ScanState { mode: "on" | "off"; changes: ScanChange[] }

function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Expected a public JSON object (body withheld)");
  }
  return value as Record<string, unknown>;
}
function noValues(value: unknown, secrets: readonly string[]): void {
  const text = JSON.stringify(value) ?? "";
  // Boolean assertions keep credential bytes out of assertion diagnostics.
  expect(secrets.every(secret => !text.includes(secret)
    && !text.includes(Buffer.from(secret).toString("base64")))).toBe(true);
}
function secretHandle(value: unknown): string {
  expect(typeof value).toBe("string");
  const handle = String(value);
  expect(/^sc[0-9]+$/.test(handle)).toBe(true);
  return handle;
}
function member(files: ReadonlyMap<string, Buffer>, path: string): Buffer {
  const bytes = files.get(path);
  if (!bytes) throw new Error(`Public archive is missing ${path}`);
  return bytes;
}

/** Reads the public ZIP response, not a vault or a fabricated export fixture.
 * This tiny fixture needs ordinary single-disk ZIP, stored or deflated members.
 * There is no filesystem extraction, subprocess or engine codec here.
 */
function publicZip(encoded: string): Map<string, Buffer> {
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

suite.test(test, "SECRETS-01", "Mask-on-write and reveal should work", async () => {
  const catalog = await loadFixtures();
  const fixture = await catalog.readJson<MaskFixture>("secrets-mask-on-write");
  const secrets = [fixture.credential, fixture.fieldCredential];
  for (const secret of secrets) redactor.add(secret, Buffer.from(secret).toString("base64"));
  // Two real owners, sequential servers: this one-slot file never runs a
  // peer vault concurrently or fabricates another issuer's credential.
  const otherVault = await EngineFixture.start({ id: "SECRETS-01-other-owner", profile });
  const otherOwnerCredential = otherVault.pairedActor.credential;
  await otherVault.close();
  const engine = await EngineFixture.start({ id: "SECRETS-01", profile });
  try {
    const scan = await engine.client.request<ScanState>("GET", "/v1/owner/secret-scan");
    expect(scan.status).toBe(200);
    expect(scan.body.mode).toBe("on");

    // This is the existing owner-gated public PERSON create operation. It
    // creates no credential or authority; token pair supplies the real scope.
    const agentRecord = await engine.client.call("vault.structural.put", {
      kind: "PERSON", body: { name: fixture.agentName }, occurred_at: fixture.occurredAt,
    });
    const agent = await engine.pairActor({
      principalRef: agentRecord.id_hex, actorClass: "agent", scope: ["core:read", "core:write"],
    });
    const conversation = await engine.client.call("vault.conversations.create", {
      body: { members: [engine.pairedActor.principalRef, agent.principalRef] },
      occurred_start: fixture.occurredAt, occurred_end: fixture.occurredAt,
    });
    const witnessed = await engine.client.call("vault.witness", {
      conversation_ref: conversation.id,
      occurred_at: fixture.occurredAt,
      messages: [{ author: "user", message_type: "text", is_visible: true, order: 0,
        content: fixture.prefix + fixture.credential + fixture.suffix }],
    } satisfies FacadeInput<"vault.witness">);
    await engine.awaitReceipt(witnessed.receipt_ref);
    expect(witnessed.message_short_ids.length).toBe(1);
    const messageRef = witnessed.message_short_ids[0];
    if (!messageRef) throw new Error("Witness returned no message reference");
    const saved = await engine.client.call("vault.get", { entity_ref: messageRef });
    if (!saved.value) throw new Error("Witnessed message is not publicly readable");
    const content = object(saved.value.body).content;
    expect(typeof content).toBe("string");
    const found = String(content).match(/\bsc[0-9]+\b/g) ?? [];
    expect(found.length).toBe(1);
    const handle = secretHandle(found[0]);
    const masked = fixture.prefix + fixture.textHandleTemplate.replace("{handle}", handle) + fixture.suffix;
    expect(content).toBe(masked); // Exactly the secret span changed; ordinary text survives.
    noValues(saved, secrets);

    const recall = async (): Promise<FacadeResult<"vault.recall">> => agent.client.call("vault.recall", {
      query: fixture.query, effort: "light", limit: 10,
    });
    const recalled = await recall();
    noValues(recalled, secrets);
    expect(recalled.items.some(item => item.value_text.includes(masked)
      || item.cited_messages?.some(message => message.value_text.includes(masked)))).toBe(true);

    // G04: a value in a structured field is kept by reference, not rejected.
    const claim = await engine.client.call("vault.claims.upsert", {
      scope: await ownerBaseClaimScope(engine.client, engine.pairedActor.principalRef),
      predicate: fixture.predicate, subject_ref: conversation.id,
      value: { note: fixture.fieldNote, access: fixture.fieldCredential, tail: fixture.fieldTail },
      source: "user_stated", confidence: 1, occurred_at: fixture.occurredAt,
    });
    await engine.awaitReceipt(claim.receipt_ref);
    const claims = await engine.client.call("vault.claims.list", {
      subject_ref: conversation.id, predicate: fixture.predicate, limit: 10,
    });
    expect(claims.value.length).toBe(1);
    const fieldValue = object(claims.value[0]?.value);
    expect(fieldValue.note).toBe(fixture.fieldNote);
    expect(fieldValue.tail).toBe(fixture.fieldTail);
    const fieldMatch = String(fieldValue.access).match(/^\[secret (sc[0-9]+)\]$/);
    const fieldHandle = secretHandle(fieldMatch?.[1]);
    expect(fieldValue.access).toBe(fixture.textHandleTemplate.replace("{handle}", fieldHandle));
    noValues(claims, secrets);

    const card = await agent.client.call("reveal.describe", { handle });
    expect(card).toMatchObject({ handle, class: "custody-portable", status: "active",
      band: "restricted", reveal: "asks", provenance: { record: saved.value.id_hex } });
    const fieldCard = await agent.client.call("reveal.describe", { handle: fieldHandle });
    expect(fieldCard).toMatchObject({ handle: fieldHandle, band: "restricted", status: "active" });
    noValues([card, fieldCard], secrets);

    const otherOwner = new PublicHttpClient(engine.url, { credential: otherOwnerCredential });
    const wrongVault = await otherOwner.raw("POST", "/v1/owner/secrets/reveal", {
      handle, reason: fixture.ownerReason,
    } satisfies OwnerRevealInput);
    expect(wrongVault.status).toBe(401);
    noValues(wrongVault.body, secrets);
    // A scoped agent cannot use the owner's direct reveal door either.
    const unauthorized = await agent.client.raw("POST", "/v1/owner/secrets/reveal", {
      handle, reason: fixture.agentReason,
    } satisfies OwnerRevealInput);
    expect(unauthorized.status).toBe(403);
    noValues(unauthorized.body, secrets);
    const pending = await agent.client.call("reveal", { handle, why: fixture.agentReason });
    const waiting = await agent.client.call("reveal.wait", pending);
    expect(waiting.decision).toBe("pending");
    expect(waiting.value == null && waiting.value_base64 == null).toBe(true);
    const asks = await engine.client.request<OwnerRevealAsk[]>("GET", "/v1/owner/secrets/reveals?pending=true");
    noValues(asks.body, secrets);
    const ask = asks.body.find(row => row.reveal === pending.reveal);
    if (!ask?.expected_digest) throw new Error("Public pending reveal lacks its consent digest");
    expect(ask).toMatchObject({ state: "asked", handle, why: fixture.agentReason });
    const denied = await engine.client.request<OwnerRevealAnswered>("POST", "/v1/owner/secrets/reveals/answer", {
      reveal: pending.reveal, expected_digest: ask.expected_digest, outcome: "deny",
    } satisfies OwnerRevealAnswerInput);
    expect(denied.body.outcome).toBe("deny");
    await engine.awaitReceipt(denied.body.receipt_ref);
    const deniedView = await agent.client.call("reveal.wait", pending);
    expect(deniedView.decision).toBe("denied");
    expect(deniedView.value == null && deniedView.value_base64 == null).toBe(true);
    expect(deniedView.receipt).toMatchObject({ handle, why: fixture.agentReason });
    noValues(deniedView, secrets);

    const revealed = await engine.client.request<OwnerRevealed>("POST", "/v1/owner/secrets/reveal", {
      handle, reason: fixture.ownerReason,
    } satisfies OwnerRevealInput);
    expect(revealed.status).toBe(200);
    expect(revealed.body.value_base64 === Buffer.from(fixture.credential).toString("base64")).toBe(true);
    expect(revealed.body.receipt).toMatchObject({ handle, why: fixture.ownerReason,
      class: "custody-portable", answered_by: `owner:${engine.pairedActor.principalRef}` });
    expect(revealed.body.receipt.delivered_at).not.toBeNull();
    noValues(revealed.body.receipt, secrets);
    if (!revealed.body.receipt.receipt_ref) throw new Error("Owner reveal lacks its Gate receipt");
    await engine.awaitReceipt(revealed.body.receipt.receipt_ref);
    const receipts = await engine.client.request<OwnerRevealAsk[]>("GET", "/v1/owner/secrets/reveals");
    expect(receipts.body.some(row => row.reveal === revealed.body.receipt.reveal
      && row.handle === handle && row.why === fixture.ownerReason && row.delivered_at != null)).toBe(true);
    noValues(receipts.body, secrets);

    // The full owner archive now defaults to including custody for recovery.
    // This case explicitly requests the value-stripped ordinary export, not
    // an encrypted backup or the owner's complete custody-transfer archive.
    const exported = await engine.client.call("vault.export", {
      format: "archive", include_secrets: false, delivery: "inline",
    });
    if (!("archive" in exported)) throw new Error("Unexpected export transfer for inline request");
    const archive = Buffer.from(exported.archive, "base64");
    expect(Buffer.from(blake3(archive)).toString("hex")).toBe(exported.digest);
    const files = publicZip(exported.archive);
    const manifest = object(JSON.parse(member(files, "manifest.json").toString("utf8")));
    expect(manifest.secrets_included).toBe(false);
    expect(manifest.secrets_nulled).toBe(true);
    expect(member(files, "records/entity/message.jsonl").toString("utf8").includes(masked)).toBe(true);
    expect(member(files, "records/entity/claim.jsonl").toString("utf8").includes(fieldHandle)).toBe(true);
    const custodyRows = member(files, "records/secret_custody.jsonl").toString("utf8")
      .split("\n").filter(Boolean).map(line => object(JSON.parse(line)));
    for (const expectedHandle of [handle, fieldHandle]) {
      expect(custodyRows.some(row => row.handle === expectedHandle && row.body === null)).toBe(true);
    }
    for (const bytes of files.values()) noValues(bytes.toString("utf8"), secrets);
    noValues(await recall(), secrets); // A reveal never promotes its value into ordinary memory.
    const savedAfterReveal = await engine.client.call("vault.get", { entity_ref: messageRef });
    expect(object(savedAfterReveal.value?.body).content).toBe(masked);
    noValues(savedAfterReveal, secrets);
    await engine.artifacts.json("custody-receipts.json", {
      write: witnessed.receipt_ref, fieldWrite: claim.receipt_ref,
      denied: denied.body.receipt_ref, ownerReveal: revealed.body.receipt,
      archiveDigest: exported.digest,
    });
  } finally {
    await engine.close();
  }
});

// SECRETS-02 — Owner-only scanner switch should work (OF-559).
// Existing wire: GET /v1/owner/secret-scan -> ScanState; POST {mode:"off"|"on"}
// -> ScanChange. The agent's POST must be 403 without changing mode/history.
// Owner off/on must append distinct ordered receipt IDs, the paired owner's
// author, and previous:on/off. The benchmark result/report must disclose the
// actual scan mode on EVERY row, not a mode copied into a test artifact.
// No typed benchmark report read is in main's HTTP/SDK catalog or CLI; do not
// substitute vault.research.record_benchmark (which authors archive metadata).
// Full request order and independent facts: secrets-blocked-scenarios.
suite.todo(test, "SECRETS-02", "waits on typed benchmark result/report read with secret-scan mode metadata");

// No additional imports; the merged test file already imports every dependency.

interface secrets03Scenario {
  "SECRETS-03": {
    rungs: { tier_ceiling: number; valuePlacement: string }[];
    expected: { providerReceivesCredential: boolean; modelReceivesCredential: boolean;
      deniedRevealContainsValue: boolean; nextLeaseGeneration: number };
  };
}
interface secrets03Bound {
  secret_id: string; handle: string; name: string;
  bindings: { effector: string; tier_ceiling: number; scopes: string[] }[];
  receipt_ref: string; custody: unknown;
}
interface secrets03RegisteredConnector { connector: string; endpoint: string; slate: { revision: number } }
interface secrets03Consented {
  connector: string; endpoint: string;
  grants: { tool: string; grant_id: string; key_id: string; key_connector: string }[];
}
interface secrets03Tools {
  tools: { name: string; inputSchema: { properties: { schema_version: { const: string } } } }[];
}
interface secrets03McpResult {
  isError?: boolean;
  structuredContent: { output: FacadeResult<"self.use">; meta: { end: string } };
}
type secrets03Scan = (value: unknown) => void;

function secrets03Object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("SECRETS-03 expected a public JSON object; body withheld");
  }
  return value as Record<string, unknown>;
}
function secrets03ObserveWire<T>(reply: WireReply<T>, secrets03ScanBytes: secrets03Scan): void {
  secrets03ScanBytes(reply.bytes);
  secrets03ScanBytes(reply.body); // Parsed strings catch JSON escaping as well as literal wire copies.
  secrets03ScanBytes(Object.fromEntries(reply.headers));
}
async function secrets03Call<V extends FacadeVerb>(
  client: PublicHttpClient, verb: V, input: FacadeInput<V>, secrets03ScanBytes: secrets03Scan,
): Promise<FacadeResult<V>> {
  const reply = await client.raw<FacadeResult<V>>("POST", `/v1/core/facade/${verb}`, input,
    { "x-oneiron-invocation": crypto.randomUUID().replaceAll("-", "") });
  secrets03ObserveWire(reply, secrets03ScanBytes);
  expect(reply.status === 200).toBe(true);
  return reply.body;
}
function secrets03Exchange(id: string, admission: boolean, marker: string, result: Json): ProviderStep[] {
  const initializeId = admission ? "initialize" : 1;
  return [
    { id: `${id}-initialize`, origin: "connector", role: "custody-sink", purpose: "MCP handshake",
      request: { method: "POST", path: "/mcp", fields: { jsonrpc: "2.0", id: initializeId, method: "initialize" } },
      response: { kind: "json", body: { jsonrpc: "2.0", id: initializeId, result: {
        protocolVersion: "2025-11-25", capabilities: { tools: {} },
        serverInfo: { name: "secrets03-custody-sink", version: "1" },
      } } } },
    { id: `${id}-initialized`, origin: "connector", role: "custody-sink", purpose: "MCP ready notification",
      request: { method: "POST", path: "/mcp", fields: { jsonrpc: "2.0", method: "notifications/initialized" } },
      response: { kind: "bytes", body: new Uint8Array(), contentType: "application/json", status: 202 } },
    { id: `${id}-result`, origin: "connector", role: "custody-sink", purpose: admission ? "List approved tool" : "Use custody credential",
      request: { method: "POST", path: "/mcp", fields: admission
        ? { jsonrpc: "2.0", id: "tools/list:0", method: "tools/list", params: {} }
        : { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "check", arguments: { marker } } } },
      response: { kind: "json", body: { jsonrpc: "2.0", id: admission ? "tools/list:0" : 2, result } } },
  ];
}

/*
 * Promise: T0 connector use delivers the exact held generation only to its
 * authorized sink, keeps raw/base64 values out of agent-visible output, and
 * refuses the next use after either custody or connector permission is lost.
 * Doors: owner REST admission/bind/unbind/consent; typed HTTP facade use,
 * rotate, reveal, receipts, recall and stripped export; tool-first MCP use.
 * Wrong-actor rotate is no-record; value-free revoke supplies the refusal receipt.
 * Restart reads old receipts and uses the same handle/credential at generation 1.
 * Partial: no genuine attached-run fixture, T1 host consumer, T2 file consumer,
 * old-grant redemption, expiry or full cross-surface parity is claimed.
 */
suite.test(test, "SECRETS-03", "T0 custody use keeps values private across rotation and restart, and owner withdrawal stops the next use", async () => {
  const fixture = (await (await loadFixtures()).readJson<secrets03Scenario>("secrets-blocked-scenarios"))["SECRETS-03"];
  const rung = fixture.rungs.find(row => row.tier_ceiling === 0);
  if (!rung) throw new Error("SECRETS-03 fixture lacks its door-only rung");
  expect(rung.valuePlacement === "door only" && fixture.expected.providerReceivesCredential
    && !fixture.expected.modelReceivesCredential && !fixture.expected.deniedRevealContainsValue).toBe(true);
  const value0 = `e2e_custody_${crypto.randomUUID().replaceAll("-", "")}`;
  const value1 = `e2e_custody_${crypto.randomUUID().replaceAll("-", "")}`;
  const sentinel = `custody_result_${crypto.randomUUID().replaceAll("-", "")}`;
  for (const value of [value0, value1, sentinel]) redactor.add(value, Buffer.from(value).toString("base64"));
  const values = [value0, value1];
  const needles = values.flatMap(value => [Buffer.from(value), Buffer.from(Buffer.from(value).toString("base64"))]);
  // Record disclosure while reading; assert after all doors so a known leak
  // cannot prevent revocation, export and restart from being exercised.
  let valueFree = true;
  const secrets03ScanBytes: secrets03Scan = value => {
    const bytes = value instanceof Uint8Array ? Buffer.from(value)
      : Buffer.from(typeof value === "string" ? value : JSON.stringify(value) ?? "");
    valueFree = needles.every(needle => !bytes.includes(needle)) && valueFree;
  };
  const tool: Json = { name: "check", description: "Read the custody fixture status", inputSchema: {
    type: "object", properties: { marker: { type: "string" } }, required: ["marker"], additionalProperties: false,
  }, annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false } };
  const listing: Json = { tools: [tool] };
  const providers = await ScriptedProviders.start({ id: "SECRETS-03", steps: [
    ...secrets03Exchange("register", true, "", listing),
    ...secrets03Exchange("attest", true, "", listing),
  ] });
  let engine: EngineFixture | undefined;
  try {
    const origin = providers.urls.connector;
    if (!origin) throw new Error("SECRETS-03 connector origin was not assigned");
    const endpoint = `${origin}/mcp`;
    const current = await EngineFixture.start({ id: "SECRETS-03", profile, serverLog: "debug",
      serverConfig: `[connectors.secrets_probe]\ntransport = "mcp_http"\nendpoint = ${JSON.stringify(endpoint)}\n`,
    });
    engine = current;
    const secrets03Facade = <V extends FacadeVerb>(client: PublicHttpClient, verb: V, input: FacadeInput<V>) =>
      secrets03Call(client, verb, input, secrets03ScanBytes);
    const owner = current.client;
    const secrets03OwnerRequest = async <T>(method: string, path: string, body?: unknown): Promise<T> => {
      const reply = await owner.raw<T>(method, path, body);
      secrets03ObserveWire(reply, secrets03ScanBytes);
      expect(reply.status === 200).toBe(true);
      return reply.body;
    };
    const secrets03Gate = async (ref: string): Promise<void> => {
      expect(/^gate:[a-f0-9]+$/.test(ref)).toBe(true);
      const page = await awaitPublic(() => secrets03Facade(owner, "vault.receipts", { limit: 1000 }),
        result => result.receipts.some(row => row.receipt_ref === ref), { label: "SECRETS-03 Gate receipt" });
      expect(page.receipts.some(row => row.receipt_ref === ref)).toBe(true);
    };
    const secrets03Refuse = async <V extends FacadeVerb>(client: PublicHttpClient, verb: V, input: FacadeInput<V>, status: number, code: string, noRecord = false) => {
      const reply = await client.raw("POST", `/v1/core/facade/${verb}`, input);
      secrets03ObserveWire(reply, secrets03ScanBytes);
      const error = secrets03Object(secrets03Object(reply.body).error);
      expect(reply.status === status && error.code === code && typeof error.message === "string"
        && typeof error.requestId === "string" && Array.isArray(error.suggestions)).toBe(true);
      const ref = reply.headers.get("x-oneiron-receipt-ref");
      if (noRecord) {
        expect(ref === "none; no-record" && error.receiptRef == null).toBe(true);
        return;
      }
      if (!ref || !ref.startsWith("call:")) throw new Error("SECRETS-03 refusal lacks its public call receipt");
      expect(error.receiptRef === ref).toBe(true);
      const receipt = await secrets03Facade(client, "vault.receipts.get", { receipt_ref: ref });
      if (!receipt) throw new Error("SECRETS-03 refusal receipt was not readable by its caller");
      expect(receipt.receipt_ref === ref && receipt.verb === verb && receipt.actor_class === "agent").toBe(true);
      expect(typeof receipt.outcome === "object" && receipt.outcome.refused.code === code).toBe(true);
      return ref;
    };
    const secrets03Pair = async (name: string) => {
      const created = await secrets03Facade(owner, "vault.structural.put", {
        kind: "PERSON", body: { name }, occurred_at: 1735689600,
      });
      const read = await secrets03Facade(owner, "vault.get", { entity_ref: created.id_hex });
      expect(read.value?.id_hex === created.id_hex).toBe(true);
      return current.pairActor({ principalRef: created.id_hex, actorClass: "agent", scope: ["core:read", "core:write"] });
    };
    const agent = await secrets03Pair("SECRETS-03 custody agent");
    const noConnectorGrant = await secrets03Pair("SECRETS-03 unconsented agent");
    const registeredConnector = await secrets03OwnerRequest<secrets03RegisteredConnector>("POST", "/v1/owner/connectors/register", {
      connector: "secrets_probe", summary: "SECRETS-03 public custody check",
      tools: { check: { data_class: "public", spends: false } },
    });
    await secrets03OwnerRequest<unknown>("GET", "/v1/owner/connectors/setup?connector=secrets_probe");
    await secrets03OwnerRequest<unknown>("POST", "/v1/owner/connectors/slate/accept", {
      connector: "secrets_probe", revision: registeredConnector.slate.revision,
      rows: { check: "always_allow", "@elicitation": "never_allow" },
    });
    await secrets03OwnerRequest<unknown>("GET", "/v1/owner/connectors/setup?connector=secrets_probe");
    await secrets03OwnerRequest<unknown>("POST", "/v1/owner/connectors/attest", { connector: "secrets_probe" });
    const readiness = await secrets03OwnerRequest<{ ready: boolean; endpoint: string | null }>("GET",
      `/v1/owner/connectors/consent?connector=secrets_probe&actor=${agent.principalRef}`);
    expect(readiness.ready && readiness.endpoint === endpoint).toBe(true);
    const consent = await secrets03OwnerRequest<secrets03Consented>("POST", "/v1/owner/connectors/consent", {
      connector: "secrets_probe", actor: agent.principalRef, endpoint,
      rows: [{ tool: "check", ceiling: "public", headers: false }],
    });
    const consentGrant = consent.grants.find(row => row.tool === "check");
    if (!consentGrant) throw new Error("SECRETS-03 consent returned no tool grant");
    const registry = await secrets03Facade(owner, "vault.consent.registry", { limit: 1000, include_revoked: true });
    const boundGrant = registry.rows.find(row => row.selectors.includes(`grant:${consentGrant.grant_id}`));
    if (!boundGrant) throw new Error("SECRETS-03 registry did not read back connector consent");

    const registered = await secrets03Facade(owner, "vault.secrets.register", {
      name: "secrets03-custody", class: "custody-portable", device_only: false, rung: rung.tier_ceiling,
      value_base64: Buffer.from(value0).toString("base64"),
      bindings: [{ effector: "connector:secrets_probe", tier_ceiling: 0, scopes: ["read"] }],
    });
    expect(registered.rotation_generation === 0).toBe(true);
    const secrets03Bind = () => secrets03OwnerRequest<secrets03Bound>("POST", "/v1/owner/secrets/bind", {
      name: "secrets03-custody", effector: "connector:secrets_probe", tier_ceiling: 0, scopes: ["read"],
    });
    const bound = await secrets03Bind();
    const handle = bound.handle;
    expect(/^sc[0-9]+$/.test(handle) && bound.secret_id === registered.secret_id).toBe(true);
    await secrets03Gate(bound.receipt_ref);
    const secrets03Input = (marker: string): FacadeInput<"self.use"> => ({ handle, operation: "connector.call",
      arguments: { name: "secrets_probe", tool: "check", arguments: { marker } } });
    const secrets03Withdraw = async () => {
      const answer = await secrets03OwnerRequest<secrets03Bound>("POST", "/v1/owner/secrets/unbind", {
        handle, effector: "connector:secrets_probe",
      });
      await secrets03Gate(answer.receipt_ref);
      expect(!answer.bindings.some(row => row.effector === "connector:secrets_probe")).toBe(true);
    };
    await secrets03Withdraw();
    const beforeNoBinding = providers.seenFixtureCalls.length;
    await secrets03Refuse(agent.client, "self.use", secrets03Input("no-custody-binding"), 403, "FORBIDDEN");
    expect(providers.seenFixtureCalls.length === beforeNoBinding).toBe(true);
    await secrets03Gate((await secrets03Bind()).receipt_ref);

    const secrets03Held = async (client: PublicHttpClient, marker: string) => {
      const before = providers.seenFixtureCalls.length;
      const answer = await secrets03Facade(client, "self.use", secrets03Input(marker));
      const result = secrets03Object(answer.result);
      expect(answer.status === "failed" && result.outcome === "held" && Array.isArray(result.reasons)
        && result.reasons.includes("standing_grant_required")).toBe(true);
      await secrets03Gate(answer.receipt.decision);
      expect(providers.seenFixtureCalls.length === before && answer.receipt.presented_generation == null).toBe(true);
    };
    await secrets03Held(noConnectorGrant.client, "no-connector-grant"); // Never consent this held actor later.
    await secrets03Refuse(agent.client, "vault.secrets.rotate", {
      name: "secrets03-custody", value_base64: Buffer.from(value1).toString("base64"),
    }, 403, "FORBIDDEN", true);
    const wrongActorReceipt = await secrets03Refuse(agent.client, "vault.secrets.revoke", {
      name: "secrets03-custody",
    }, 403, "FORBIDDEN");
    if (!wrongActorReceipt) throw new Error("SECRETS-03 value-free refusal has no call receipt");

    const secrets03UseResult = async (answer: FacadeResult<"self.use">, generation: number) => {
      const result = secrets03Object(answer.result);
      const toolResult = secrets03Object(result.result);
      expect(answer.status === "answered" && result.outcome === "delivered" && toolResult.foreign === true
        && toolResult.is_error === false && (JSON.stringify(toolResult) ?? "").includes(sentinel)).toBe(true);
      expect(answer.receipt.handle === handle && answer.receipt.generation === generation
        && answer.receipt.presented_generation === generation && answer.receipt.effector === "connector:secrets_probe"
        && answer.receipt.operation === "connector.call").toBe(true);
      await secrets03Gate(answer.receipt.decision);
    };
    for (const step of secrets03Exchange("generation-0", false, "generation-0", {
      content: [{ type: "text", text: `${sentinel}:${value0}` }],
      structuredContent: { reflected: value0, [value0]: "reflected-key" }, isError: false,
    })) providers.enqueue(step);
    const generation0 = await secrets03Facade(agent.client, "self.use", secrets03Input("generation-0"));
    await secrets03UseResult(generation0, 0);
    expect((JSON.stringify(generation0.result) ?? "").includes(`[secret ${handle}]`)).toBe(true);
    await secrets03Refuse(agent.client, "reveal", { handle, why: "Check T0 custody disclosure permission" }, 400, "BAD_REQUEST");
    const card = await secrets03Facade(agent.client, "reveal.describe", { handle });
    expect(card.handle === handle && card.reveal === "refused" && typeof card.refusal === "string").toBe(true);

    const rotation = await secrets03Facade(owner, "vault.secrets.rotate", {
      name: "secrets03-custody", value_base64: Buffer.from(value1).toString("base64"),
    });
    expect(rotation.from_generation === 0 && rotation.to_generation === fixture.expected.nextLeaseGeneration
      && rotation.kind === "rotated").toBe(true);
    await current.restart();
    await secrets03Gate(generation0.receipt.decision);
    const persistedRefusal = await secrets03Facade(agent.client, "vault.receipts.get", { receipt_ref: wrongActorReceipt });
    if (!persistedRefusal) throw new Error("SECRETS-03 wrong-actor refusal did not survive restart");
    expect(persistedRefusal.receipt_ref === wrongActorReceipt && persistedRefusal.actor_ref === agent.principalRef
      && persistedRefusal.verb === "vault.secrets.revoke" && typeof persistedRefusal.outcome === "object"
      && persistedRefusal.outcome.refused.code === "FORBIDDEN").toBe(true);
    const restartedCard = await secrets03Facade(agent.client, "reveal.describe", { handle });
    expect(restartedCard.handle === handle && restartedCard.status === "active" && restartedCard.reveal === "refused").toBe(true);
    secrets03ScanBytes(await agent.mcp.initialize());
    const tools = await agent.mcp.listTools() as secrets03Tools;
    secrets03ScanBytes(tools);
    const useTool = tools.tools.find(row => row.name === "self.use");
    if (!useTool) throw new Error("SECRETS-03 tool-first self.use is absent");
    // The trusted sink deliberately reflects both forms; neither is allowed
    // back into ordinary HTTP/MCP output or the durable raw connector reply.
    for (const step of secrets03Exchange("generation-1", false, "generation-1", {
      content: [{ type: "text", text: `${sentinel}:${value1}:${Buffer.from(value1).toString("base64")}` }],
      structuredContent: { reflected: value1, encoded: Buffer.from(value1).toString("base64") }, isError: false,
    })) providers.enqueue(step);
    const mcpReply = await agent.mcp.callTool("self.use", {
      schema_version: useTool.inputSchema.properties.schema_version.const,
      consent: { policy_ref: "policy:secrets03-custody", purpose: "Use a T0 custody credential without disclosure" },
      arguments: { spec: secrets03Input("generation-1") },
    }) as secrets03McpResult;
    secrets03ScanBytes(mcpReply);
    expect(mcpReply.isError === false && mcpReply.structuredContent.meta.end === "Complete").toBe(true);
    await secrets03UseResult(mcpReply.structuredContent.output, fixture.expected.nextLeaseGeneration);

    const calls = providers.seenFixtureCalls;
    expect(calls.length === 12).toBe(true); // Two discoveries and two uses, three POSTs each.
    for (const call of calls) {
      secrets03ScanBytes(call.body);
      secrets03ScanBytes({ method: call.method, path: call.path });
      const expected = call.fixtureId?.startsWith("generation-0-") ? value0
        : call.fixtureId?.startsWith("generation-1-") ? value1 : null;
      // Authorization is the one authorized disclosure to the trusted sink.
      expect(expected === null ? call.headers?.authorization == null
        : call.headers?.authorization === `Bearer ${expected}`).toBe(true);
      for (const [name, value] of Object.entries(call.headers ?? {})) if (name !== "authorization") secrets03ScanBytes(value);
    }
    const beforeWithdrawal = providers.seenFixtureCalls.length;
    await secrets03Withdraw();
    await secrets03Refuse(agent.client, "self.use", secrets03Input("after-custody-withdrawal"), 403, "FORBIDDEN");
    expect(providers.seenFixtureCalls.length === beforeWithdrawal).toBe(true);
    await secrets03Gate((await secrets03Bind()).receipt_ref);
    const revoked = await secrets03Facade(owner, "vault.consent.revoke", { grant: boundGrant.grant_ref });
    if (revoked.decision_ref) await secrets03Gate(`gate:${revoked.decision_ref}`);
    await secrets03Facade(owner, "vault.consent.registry", { limit: 1000, include_revoked: true });
    await secrets03Held(agent.client, "after-connector-withdrawal");
    expect(providers.seenFixtureCalls.length === beforeWithdrawal).toBe(true);
    await secrets03Facade(agent.client, "vault.recall", { query: "secrets03-custody", effort: "light", limit: 5 });
    await secrets03Facade(owner, "vault.receipts", { limit: 1000 });
    const exported = await secrets03Facade(owner, "vault.export", { format: "archive", include_secrets: false, delivery: "inline" });
    if (!("archive" in exported)) throw new Error("SECRETS-03 inline export returned a transfer");
    secrets03ScanBytes(Buffer.from(exported.archive, "base64"));
    const members = publicZip(exported.archive);
    for (const [name, bytes] of members) { secrets03ScanBytes(name); secrets03ScanBytes(bytes); }
    expect(valueFree).toBe(true); // Promise oracle; source predicts encoded-reflection red.
  } catch (error) {
    if (error instanceof PublicHttpError) secrets03ObserveWire(error.reply, secrets03ScanBytes);
    else if (error instanceof McpRpcError) secrets03ScanBytes(error.response);
    else if (error instanceof CliError) { secrets03ScanBytes(error.result.stdout); secrets03ScanBytes(error.result.stderr); }
    throw error;
  } finally {
    try { await providers.close(); }
    finally {
      if (engine) {
        await engine.close();
        for (const value of values) {
          const base64 = Buffer.from(value).toString("base64");
          expect(engine.serverOutputHas([value, base64]).found === false
            && engine.serverOutputHas([value, base64]).truncated === false).toBe(true);
        }
      }
    }
  }
});

// SECRETS-04 — Device-bound versus portable custody should work (OF-422).
// Register DTO: {name,class:"custody-portable"|"custody-device-bound",
// device_only:boolean,rung:0,bindings:[{effector,tier_ceiling:0,scopes:["read"]}],
// value_base64}. Expected sync follows owner permission; device-bound bytes
// never cross WS, portable bytes reach only the enrolled authorized device;
// self.use on each device proves usability, and stripped export has no value.
// token pair --machine yours / device enrol and anchor-sign exist on main.
// EngineFixture.peers are independent vaults, NOT two devices of one vault.
// No typed SDK paired-device custody sync/apply/use lifecycle binds those
// steps yet. Do not copy an LMDB root or call peers:1 in this one-slot file.
suite.todo(test, "SECRETS-04", "waits on typed enrolled-device custody sync/apply observation and remote custody use lifecycle");

// SECRETS-05 — Secret-tainted output stays fenced should work (OF-431/597).
// Produce a custody-derived sentinel with the real MCP executor, above the
// unchanged default 1 MiB inline limit. The kept occurrence manifest carries
// producing run/step/effect, digest/length, provenance, taint refs and fence.
// Two equal-byte occurrences must retain separate authority. Unauthorized
// handle/slice/share/export views withhold the sentinel; the authorized view
// retains provenance and taint. Check rotation at the next read/export.
// Main's generic peek({group_ref}) is a TASK ask, not a result-body reader.
// Raw blobs, raw output-row IDs and vault.structural.put are not replacements
// for the missing typed result-body view and per-occurrence grant calls.
suite.todo(test, "SECRETS-05", "waits on typed result-body handle read/slice/share with taint, provenance and occurrence-scoped grants");

interface secrets06ScenarioFixture {
  "SECRETS-06": {
    person: { class: "names"; band: "private" };
    channels: { model: "public"; owner: "top" };
  };
}
interface secrets06RefusalEnvelope {
  error: { code: string; message: string; requestId: string;
    suggestions: string[]; receiptRef?: string | null };
}

function secrets06Object(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("SECRETS-06 expected a public object (body withheld)");
  }
  return value as Record<string, unknown>;
}

function secrets06Contains(bytes: Uint8Array, needles: readonly string[]): boolean {
  const buffer = Buffer.from(bytes);
  return needles.some(value => buffer.includes(Buffer.from(value, "utf8")));
}

/*
 * A private names claim serializes as its real person handle on a public agent
 * connection. Only the owner and the first consented reveal may read the name;
 * those two positive controls are scanned for presence, not asserted name-free.
 * Doors: typed REST facade, paired CLI, tool-first MCP, owner slip-revoke HTTP.
 * Read-back: people get/list, ceiling get, reveal wait/history, public receipts;
 * restart preserves the dial, masking, consent refusal and refusal receipt.
 * Not proved: model-generated prose, other data classes, lease expiry or code-run
 * replay. No model, clock change, store access, sleeps or private drains are used.
 */
suite.test(test, "SECRETS-06",
  "Public-ceiling agents see private person names only through owner-approved reveals",
  async () => {
    const catalog = await loadFixtures();
    const data = (await catalog.readJson<secrets06ScenarioFixture>("secrets-blocked-scenarios"))["SECRETS-06"];
    const { occurredAt } = await catalog.readJson<{ occurredAt: number }>("secrets-mask-on-write");
    const privateName = `Syntheticprivateperson ${randomBytes(12).toString("hex")}`;
    const privateNameBase64 = Buffer.from(privateName, "utf8").toString("base64");
    redactor.add(privateName, privateNameBase64);
    const needles = [privateName, privateNameBase64];
    const leaks = new Set<string>();
    const secrets06Scan = (label: string, bytes: Uint8Array): void => {
      if (secrets06Contains(bytes, needles)) leaks.add(label);
    };
    const secrets06ScanJson = (label: string, value: unknown): void => {
      secrets06Scan(label, Buffer.from(JSON.stringify(value) ?? "", "utf8"));
    };
    const engine = await EngineFixture.start({ id: "SECRETS-06", profile, serverLog: "debug" });
    try {
      // Preserve exact wire bytes and generated input/result types, even on reads.
      const secrets06Call = async <V extends FacadeVerb>(
        client: PublicHttpClient, verb: V, input: FacadeInput<V>,
      ): Promise<FacadeResult<V>> => {
        const reply = await client.raw<FacadeResult<V>>("POST", `/v1/core/facade/${verb}`, input);
        secrets06Scan(verb, reply.bytes);
        secrets06ScanJson(`${verb}:headers`, Object.fromEntries(reply.headers));
        expect(reply.status).toBe(200);
        return reply.body;
      };
      const secrets06Receipt = async (ref: string): Promise<NonNullable<FacadeResult<"vault.receipts.get">>> => {
        expect(/^call:[a-f0-9]{32}$/.test(ref)).toBe(true);
        const row = await awaitPublic(
          () => secrets06Call(engine.client, "vault.receipts.get", { receipt_ref: ref }),
          value => value !== null, { label: "SECRETS-06 public call receipt" },
        );
        if (row === null) throw new Error("SECRETS-06 call receipt is missing");
        expect(row.receipt_ref).toBe(ref);
        return row;
      };
      const secrets06GateReceipt = async (ref: string): Promise<void> => {
        // Claim/consent decisions supply real Gate refs; reveal and put ids do not.
        expect(/^gate:[a-f0-9]{32}$/.test(ref)).toBe(true);
        await awaitPublic(
          () => secrets06Call(engine.client, "vault.receipts", { limit: 1000 }),
          page => page.receipts.some(row => row.receipt_ref === ref),
          { label: "SECRETS-06 public governance receipt" },
        );
      };
      const secrets06Refuse = async <V extends FacadeVerb>(
        client: PublicHttpClient, verb: V, input: FacadeInput<V>,
        status: 401 | 403, actorRef: string,
      ): Promise<string> => {
        const reply = await client.raw<secrets06RefusalEnvelope>("POST", `/v1/core/facade/${verb}`, input);
        secrets06Scan(`refusal:${verb}`, reply.bytes);
        secrets06ScanJson(`refusal:${verb}:headers`, Object.fromEntries(reply.headers));
        // If full-vault export unexpectedly succeeds, inspect every decompressed
        // member before reporting its wrong status. A compressed scan is not proof.
        const body = secrets06Object(reply.body);
        if (typeof body.archive === "string") {
          secrets06Scan("unauthorized-export:zip", Buffer.from(body.archive, "base64"));
          for (const [path, bytes] of publicZip(body.archive)) secrets06Scan(`unauthorized-export:${path}`, bytes);
        }
        expect(reply.status).toBe(status);
        expect(reply.body.error.code).toBe(status === 403 ? "FORBIDDEN" : "UNAUTHORIZED");
        expect(typeof reply.body.error.message === "string" && reply.body.error.message.length > 0).toBe(true);
        expect(typeof reply.body.error.requestId === "string" && reply.body.error.requestId.length > 0).toBe(true);
        expect(Array.isArray(reply.body.error.suggestions)).toBe(true);
        const ref = reply.headers.get("x-oneiron-receipt-ref");
        if (ref === null) throw new Error("SECRETS-06 refusal has no receipt header");
        const row = await secrets06Receipt(ref); // Owner can also read an unauthenticated connection's receipt.
        if (status === 401) {
          expect(row).toMatchObject({ transport: "http_facade", actor_class: "connection",
            verb, outcome: { refused: { code: "HTTP_401" } } });
        } else {
          expect(reply.body.error.receiptRef).toBe(ref);
          expect(row).toMatchObject({ transport: "http_facade", actor_ref: actorRef,
            actor_class: "agent", verb: `v1/core/facade/${verb}`, outcome: { refused: { code: "FORBIDDEN" } } });
        }
        return ref;
      };

      // The shared scope discovery reads only the fresh owner's substrate,
      // before this fixture stores its private name anywhere.
      const scope = await ownerBaseClaimScope(engine.client, engine.pairedActor.principalRef);
      secrets06ScanJson("owner-base-scope", scope);
      const person = await secrets06Call(engine.client, "vault.structural.put", {
        kind: "PERSON", body: { name: privateName }, occurred_at: occurredAt,
      });
      const principal = await secrets06Call(engine.client, "vault.structural.put", {
        kind: "PERSON", body: { name: "SECRETS-06 model reader" }, occurred_at: occurredAt,
      });
      // Structural receipt_ref is a put marker, not a receipt to await. Both
      // PERSON writes are independently read back in the owner roster below.
      const claim = await secrets06Call(engine.client, "vault.claims.upsert", {
        predicate: "fixture.person.name", subject_ref: person.id_hex, value: privateName,
        confidence: 1, source: "user_stated", sensitivity: 1, scope, occurred_at: occurredAt,
      });
      expect(claim.approval).toBe("auto");
      const claimId = claim.claim?.id;
      if (!claimId) throw new Error("SECRETS-06 claim write returned no typed record id");
      if (claim.receipt_ref.startsWith("gate:")) await secrets06GateReceipt(claim.receipt_ref);
      else expect(claim.receipt_ref).toBe(`claim:${claimId}`); // Public documented marker, not a second receipt.


      const agent = await engine.pairActor({ principalRef: principal.id_hex, actorClass: "agent",
        scope: ["core:read", "core:write", "export"] });
      // Before the second pairing, exactly one slip belongs to this new principal.
      const audit = await secrets06Call(engine.client, "vault.authority.audit", { limit: 500 });
      expect(audit.next_after == null).toBe(true);
      const minted = audit.rows.filter(row => row.source_op === "slip_mint" && row.holder_ref === agent.principalRef);
      expect(minted.length).toBe(1);
      const mintedRow = minted[0];
      if (!mintedRow?.subject_ref) throw new Error("SECRETS-06 public authority audit has no paired slip id");
      expect(mintedRow.fold_valid).toBe(true);
      const slipId = mintedRow.subject_ref;
      expect(/^[a-f0-9]{64}$/.test(slipId)).toBe(true);
      const noRead = await engine.pairActor({ principalRef: principal.id_hex, actorClass: "agent",
        scope: ["core:write", "export"] });
      const connection = `agent:${agent.principalRef}`;
      const dial = { connection, class: data.person.class };

      // Authorized owner assembly is the positive control, not an absence claim.
      const ownerPage = await engine.client.raw<FacadeResult<"vault.people.list">>(
        "POST", "/v1/core/facade/vault.people.list", { page: 0 } satisfies FacadeInput<"vault.people.list">,
      );
      expect(ownerPage.status).toBe(200);
      secrets06ScanJson("owner-roster:headers", Object.fromEntries(ownerPage.headers));
      const ownerRow = ownerPage.body.people.find(row => row.person === person.id_hex);
      if (!ownerRow) throw new Error("SECRETS-06 owner roster has no created person");
      expect(ownerRow.name === privateName).toBe(true);
      expect(secrets06Contains(ownerPage.bytes, [privateName])).toBe(true);
      const handle = ownerRow.handle;
      expect(/^pr[0-9]+$/.test(handle)).toBe(true);
      expect(ownerPage.body.people.some(row => row.person === principal.id_hex)).toBe(true);
      secrets06ScanJson("owner-roster:metadata", { ...ownerPage.body, people: ownerPage.body.people.map(row =>
        row.person === person.id_hex ? { ...row, name: handle } : row) });
      const secrets06MaskedPerson = async (): Promise<void> => {
        const row = await secrets06Call(agent.client, "vault.people.get", { pr: handle });
        expect(row.person).toBe(person.id_hex);
        expect(row.handle === handle && row.name === handle && row.about == null).toBe(true);
      };
      const secrets06MaskedPage = async (): Promise<void> => {
        const page = await secrets06Call(agent.client, "vault.people.list", { page: 0 });
        const row = page.people.find(item => item.person === person.id_hex);
        expect(row?.handle === handle && row.name === handle && row.about == null).toBe(true);
      };
      const secrets06OwnerPerson = async (): Promise<void> => {
        const reply = await engine.client.raw<FacadeResult<"vault.people.get">>(
          "POST", "/v1/core/facade/vault.people.get", { pr: handle } satisfies FacadeInput<"vault.people.get">,
        );
        expect(reply.status).toBe(200);
        expect(reply.body.person === person.id_hex && reply.body.handle === handle && reply.body.name === privateName).toBe(true);
        expect(secrets06Contains(reply.bytes, [privateName])).toBe(true);
        secrets06ScanJson("owner-person:headers", Object.fromEntries(reply.headers));
        secrets06ScanJson("owner-person:metadata", { ...reply.body, name: handle });
      };
      const secrets06ReadDial = async (ceiling: "public" | null): Promise<void> => {
        const value = await secrets06Call(engine.client, "vault.disclosure.ceiling.get", dial);
        expect(value).toMatchObject({ ...dial, ceiling });
      };

      // A names override wins over a wider connection dial; neither is a grant.
      await secrets06Call(engine.client, "vault.disclosure.ceiling.set", { connection, ceiling: "restricted" });
      expect(await secrets06Call(engine.client, "vault.disclosure.ceiling.get", { connection }))
        .toMatchObject({ connection, ceiling: "restricted" });
      await secrets06Call(engine.client, "vault.disclosure.ceiling.set", { ...dial, ceiling: data.channels.model });
      await secrets06ReadDial("public");
      await secrets06MaskedPerson();
      await secrets06MaskedPage();
      const wrongActorRef = await secrets06Refuse(agent.client, "vault.disclosure.ceiling.set",
        { ...dial, ceiling: "restricted" }, 403, agent.principalRef);
      await secrets06ReadDial("public"); // Refused mutation left the registry unchanged.
      const card = await secrets06Call(agent.client, "reveal.describe", { handle });
      expect(card).toMatchObject({ handle, label: handle, class: data.person.class,
        status: "active", band: data.person.band, reveal: "asks",
        provenance: { record: claimId, place: "claim", kind: "names" } });
      expect(card.grant_ref == null && card.refusal == null && card.provenance?.learned_at != null).toBe(true);

      // Clearing applies on the next read, without a cache delay or a new grant.
      await secrets06Call(engine.client, "vault.disclosure.ceiling.clear", { connection });
      expect((await secrets06Call(engine.client, "vault.disclosure.ceiling.get", { connection })).ceiling == null).toBe(true);
      await secrets06ReadDial("public");
      await secrets06MaskedPerson();
      await secrets06Call(engine.client, "vault.disclosure.ceiling.clear", dial);
      await secrets06ReadDial(null);
      await secrets06MaskedPerson(); // The inferred agent ceiling is also public.
      await secrets06Call(engine.client, "vault.disclosure.ceiling.set", { ...dial, ceiling: "public" });
      await secrets06ReadDial("public");

      const why = "fixture identity lookup";
      const pending = await secrets06Call(agent.client, "reveal", { handle, why });
      expect(/^[a-f0-9]{32}$/.test(pending.reveal)).toBe(true);
      const secrets06NoValue = (answer: FacadeResult<"reveal.wait">, decision: "pending" | "denied" | "granted"): void => {
        expect(answer.decision).toBe(decision);
        expect(answer.value == null && answer.value_base64 == null).toBe(true);
        expect(answer.receipt).toMatchObject({ handle, class: "names", why, connection });
      };
      secrets06NoValue(await secrets06Call(agent.client, "reveal.wait", pending), "pending");
      const secrets06AnswerInput = async (reveal: string, outcome: "deny" | "standing"):
        Promise<FacadeInput<"vault.disclosure.reveals.answer">> => {
        const asks = await secrets06Call(engine.client, "vault.disclosure.reveals", { pending: true, limit: 50 });
        const ask = asks.find(row => row.receipt.reveal === reveal);
        if (!ask?.expected_digest) throw new Error("SECRETS-06 reveal ask has no engine-issued consent digest");
        expect(ask.state).toBe("asked");
        expect(ask.receipt).toMatchObject({ handle, class: "names", why, connection });
        return { reveal, expected_digest: ask.expected_digest, outcome };
      };
      const denyInput = await secrets06AnswerInput(pending.reveal, "deny");
      await secrets06Refuse(agent.client, "vault.disclosure.reveals.answer", denyInput, 403, agent.principalRef);
      secrets06NoValue(await secrets06Call(agent.client, "reveal.wait", pending), "pending");
      const denied = await secrets06Call(engine.client, "vault.disclosure.reveals.answer", denyInput);
      expect(denied.outcome).toBe("deny");
      await secrets06GateReceipt(denied.receipt_ref);
      const deniedWait = await secrets06Call(agent.client, "reveal.wait", pending);
      secrets06NoValue(deniedWait, "denied");
      expect(deniedWait.receipt).toMatchObject({ decision: denied.receipt_ref,
        answered_by: `owner:${engine.pairedActor.principalRef}` });

      const approved = await secrets06Call(agent.client, "reveal", { handle, why });
      const standing = await secrets06Call(engine.client, "vault.disclosure.reveals.answer",
        await secrets06AnswerInput(approved.reveal, "standing"));
      expect(standing.outcome).toBe("standing");
      const grant = standing.grant_ref;
      if (!grant) throw new Error("SECRETS-06 standing answer returned no grant reference");
      await secrets06GateReceipt(standing.receipt_ref);
      expect(await secrets06Call(agent.client, "reveal.describe", { handle })).toMatchObject({ reveal: "hydrates", grant_ref: grant });
      // Exactly this one consented value field is allowed. Scan all other fields.
      const delivered = await agent.client.raw<FacadeResult<"reveal.wait">>(
        "POST", "/v1/core/facade/reveal.wait", approved,
      );
      expect(delivered.status).toBe(200);
      expect(delivered.body.decision).toBe("granted");
      expect(delivered.body.value === privateName && delivered.body.value_base64 == null).toBe(true);
      expect(secrets06Contains(delivered.bytes, [privateName])).toBe(true);
      secrets06ScanJson("consented-reveal:headers", Object.fromEntries(delivered.headers));
      secrets06ScanJson("consented-reveal:metadata", { ...delivered.body, value: handle });
      expect(delivered.body.receipt).toMatchObject({ handle, class: "names", why, connection,
        answered_by: `owner:${engine.pairedActor.principalRef}` });
      const deliveryDecision = delivered.body.receipt?.decision;
      expect(delivered.body.receipt?.lease != null && delivered.body.receipt.delivered_at != null).toBe(true);
      if (!deliveryDecision) throw new Error("SECRETS-06 delivery returned no consent-use receipt");
      await secrets06GateReceipt(deliveryDecision);
      secrets06NoValue(await secrets06Call(agent.client, "reveal.wait", approved), "granted");
      await secrets06MaskedPerson(); // Consent never raises the ordinary channel ceiling.

      // Lose the exact disclosure grant BEFORE collecting a covered second ask.
      const covered = await secrets06Call(agent.client, "reveal", { handle, why });
      const revokedConsent = await secrets06Call(engine.client, "vault.consent.revoke", { grant });
      if (!revokedConsent.decision_ref) throw new Error("SECRETS-06 consent revoke has no decision reference");
      await secrets06GateReceipt(`gate:${revokedConsent.decision_ref}`);
      expect(await secrets06Call(agent.client, "reveal.describe", { handle })).toMatchObject({ reveal: "asks" });
      secrets06NoValue(await secrets06Call(agent.client, "reveal.wait", covered), "pending");
      await secrets06AnswerInput(covered.reveal, "deny"); // Read the newly filed ask; do not approve or deny it.

      const scopedInput = {
        selector: { kinds: ["PERSON", "CLAIM"] },
        channel: { channel_ref: connection, scope: {
          worlds: { kind: "all" }, facets: { kind: "all" }, bands: { kind: "all" },
          audience: { kind: "all" }, verbs: { kind: "all" }, sensitivity: { kind: "all" },
        } },
      } satisfies FacadeInput<"vault.export.scoped">;
      // Check every substrate door with no read grant, then with the SAME live
      // reader after its actual paired capability is revoked below.
      const secrets06RefusedReads = async (client: PublicHttpClient, status: 401 | 403): Promise<void> => {
        await secrets06Refuse(client, "vault.people.get", { pr: handle }, status, agent.principalRef);
        await secrets06Refuse(client, "vault.people.list", { page: 0 }, status, agent.principalRef);
        await secrets06Refuse(client, "vault.get", { entity_ref: person.id_hex }, status, agent.principalRef);
        await secrets06Refuse(client, "reveal.describe", { handle }, status, agent.principalRef);
        await secrets06Refuse(client, "reveal.wait", covered, status, agent.principalRef);
        await secrets06Refuse(client, "reveal", { handle, why }, status, agent.principalRef);
        await secrets06Refuse(client, "vault.recall", { query: "Syntheticprivateperson", effort: "light", limit: 10 }, status, agent.principalRef);
        await secrets06Refuse(client, "vault.export.scoped", scopedInput, status, agent.principalRef);
      };
      await secrets06RefusedReads(noRead.client, 403);

      // Assert the broad privacy promise, not only the roster projection.
      const genericPerson = await secrets06Call(agent.client, "vault.get", { entity_ref: person.id_hex });
      expect(genericPerson.value?.id_hex).toBe(person.id_hex);
      const genericClaim = await secrets06Call(agent.client, "vault.get", { entity_ref: claim.claim_short_id });
      expect(genericClaim.value?.id_hex).toBe(claimId);
      const exported = await secrets06Call(agent.client, "vault.export.scoped", scopedInput);
      expect(exported.records.some(row => row.record.id === claimId)).toBe(true);
      for (const row of exported.records) secrets06Scan(`scoped-export:${row.record.id}`, Buffer.from(row.bytes));
      await secrets06Refuse(agent.client, "vault.export", { format: "archive", include_secrets: false, delivery: "inline" }, 403, agent.principalRef);
      const recalled = await awaitPublic(
        () => secrets06Call(agent.client, "vault.recall", { query: "Syntheticprivateperson", effort: "light", limit: 10 }),
        pack => pack.items.some(item => item.record?.id === claimId),
        { label: "SECRETS-06 private claim recalled as a handle" },
      );
      const recalledClaim = recalled.items.find(item => item.record?.id === claimId);
      expect(recalledClaim?.value_text === handle).toBe(true);
      const cli = await agent.cli.run(["api", "call", "vault.people.get", "--data", "-"],
        JSON.stringify({ pr: handle } satisfies FacadeInput<"vault.people.get">));
      secrets06Scan("cli:stdout", Buffer.from(cli.stdout, "utf8"));
      secrets06Scan("cli:stderr", Buffer.from(cli.stderr, "utf8"));
      expect(cli.exitCode).toBe(0);
      const cliRow = secrets06Object(JSON.parse(cli.stdout));
      expect(cliRow.person === person.id_hex && cliRow.name === handle && cliRow.handle === handle).toBe(true);
      const listing = await agent.mcp.rpc("tools/list");
      secrets06ScanJson("mcp:tools-list", listing);
      if ("error" in listing) throw new Error("SECRETS-06 MCP listing returned a JSON-RPC refusal (body withheld)");
      const tools = secrets06Object(listing.result).tools;
      if (!Array.isArray(tools)) throw new Error("SECRETS-06 MCP listing has no tools");
      const peopleTool: unknown = tools.find((item: unknown) => secrets06Object(item).name === "vault.people.get");
      if (peopleTool === undefined) throw new Error("SECRETS-06 MCP people tool is absent");
      const properties = secrets06Object(secrets06Object(secrets06Object(peopleTool).inputSchema).properties);
      const schemaVersion = secrets06Object(properties.schema_version).const;
      if (typeof schemaVersion !== "string") throw new Error("SECRETS-06 MCP people tool has no schema version");
      const mcp = await agent.mcp.rpc("tools/call", { name: "vault.people.get", arguments: {
        schema_version: schemaVersion,
        consent: { policy_ref: "policy:secrets-06", purpose: "Read a private person through its channel ceiling" },
        arguments: { spec: { pr: handle } },
      } });
      secrets06ScanJson("mcp:outer", mcp);
      if ("error" in mcp) throw new Error("SECRETS-06 MCP read returned a JSON-RPC refusal (body withheld)");
      const mcpResult = secrets06Object(mcp.result);
      expect(mcpResult.isError).toBe(false);
      const mcpRow = secrets06Object(secrets06Object(mcpResult.structuredContent).output);
      expect(mcpRow.person === person.id_hex && mcpRow.name === handle && mcpRow.handle === handle).toBe(true);
      // Scan decoded MCP text too: the transport may JSON-escape a nested string.
      if (Array.isArray(mcpResult.content)) {
        for (const item of mcpResult.content) {
          const block = secrets06Object(item);
          if (typeof block.text === "string") secrets06Scan("mcp:text", Buffer.from(block.text, "utf8"));
        }
      }

      await engine.restart();
      await secrets06ReadDial("public");
      await secrets06MaskedPerson();
      await secrets06MaskedPage();
      await secrets06OwnerPerson();
      expect(await secrets06Call(agent.client, "reveal.describe", { handle })).toMatchObject({ band: "private", reveal: "asks" });
      secrets06NoValue(await secrets06Call(agent.client, "reveal.wait", pending), "denied");
      secrets06NoValue(await secrets06Call(agent.client, "reveal.wait", covered), "pending");
      expect((await secrets06Receipt(wrongActorRef)).outcome).toEqual({ refused: { code: "FORBIDDEN" } });

      const revoked = await engine.client.raw<{ revoked: boolean }>("POST", "/v1/core/slips/revoke", {
        slip_id: Array.from(Buffer.from(slipId, "hex")),
      });
      secrets06Scan("slip-revoke", revoked.bytes);
      secrets06ScanJson("slip-revoke:headers", Object.fromEntries(revoked.headers));
      expect(revoked.status === 200 && revoked.body.revoked === true).toBe(true);
      await secrets06RefusedReads(agent.client, 401); // The next uses retain the original credential.
      // Read the owner-authorized state again after loss of the agent's grant.
      await secrets06ReadDial("public");
      await secrets06OwnerPerson();
      const history = await secrets06Call(engine.client, "vault.disclosure.reveals", { pending: false, limit: 50 });
      expect(history.some(row => row.receipt.reveal === pending.reveal && row.state === "denied")).toBe(true);
      await secrets06Call(engine.client, "vault.receipts", { limit: 1000 });
      // Defer expected-red leak checks so restart, revocations and all carriers run.
      expect([...leaks].sort()).toEqual([]);
    } finally {
      await engine.close();
      expect(engine.serverOutputHas([privateName, privateNameBase64]).found === false
        && engine.serverOutputHas([privateName, privateNameBase64]).truncated === false).toBe(true);
    }
  });

interface secrets07Fixture {
  agents: [string, string];
  action: { operation: string; text: string };
  rewordedText: string;
}
type secrets07Enforcement = FacadeResult<"vault.policy.outbound.decide">;
type secrets07CallReceipt = NonNullable<FacadeResult<"vault.receipts.get">>;
type secrets07GateReceipt = FacadeResult<"vault.receipts">["receipts"][number];
type secrets07Action = "allow" | "warn" | "block" | "route_to_help";

function secrets07Object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("SECRETS-07 expected a public object; body withheld");
  }
  return value as Record<string, unknown>;
}

function secrets07Scan(value: unknown, values: readonly string[]): void {
  const bytes = value instanceof Uint8Array ? Buffer.from(value)
    : Buffer.from(typeof value === "string" ? value : JSON.stringify(value) ?? "");
  expect(values.every(text => !bytes.includes(Buffer.from(text))
    && !bytes.includes(Buffer.from(Buffer.from(text).toString("base64"))))).toBe(true);
}

// Encode the independent classifier's question-id protocol, not engine authority.
function secrets07QuestionId(document: string): string {
  const wording = "Does the candidate content, the user message just before this one, violate the policy the system message states?";
  const parts = [Buffer.from("policy_model.owner_violation"), Buffer.from(blake3(Buffer.from(document))),
    Buffer.from("binary"), Buffer.alloc(0), Buffer.from(wording)];
  const framed = Buffer.concat(parts.flatMap(part => {
    const length = Buffer.alloc(8);
    length.writeBigUInt64LE(BigInt(part.length));
    return [length, part];
  }));
  const digest = Buffer.from(blake3(framed, { context: "oneiron.decision.question.v1" })).subarray(0, 16);
  digest[6] = (digest[6]! & 0x0f) | 0x80;
  digest[8] = (digest[8]! & 0x3f) | 0x80;
  return digest.toString("hex");
}

/*
 * Promise: owner policy, not either agent's authored instructions, governs the
 * same candidate under Allow, Warn, Block and RouteToHelp. Warn keeps its exact
 * bytes; a fresh reworded retry is still blocked. Receipts omit candidate bytes.
 * Doors: owner agent/config/row writes; paired outbound.decide; public receipt
 * and config/definition reads; owner slip revocation; archive/recall; restart.
 * This is an enforcement-decision journey, not persona generation, connector
 * delivery, actual audio cancellation, hosted relay or trusted-contact delivery.
 */
suite.test(test, "SECRETS-07", "Owner policy applies the same Allow, Warn, Block and help-routing decisions to differently authored agents", async () => {
  const fixture = (await (await loadFixtures()).readJson<{ "SECRETS-07": secrets07Fixture }>(
    "secrets-blocked-scenarios"))["SECRETS-07"];
  const sentinel = crypto.randomUUID();
  redactor.add(sentinel, Buffer.from(sentinel).toString("base64"));
  const original = `${fixture.action.text} [${sentinel}]`;
  const retry = `${fixture.rewordedText} [${sentinel}]`;
  const values = [fixture.action.text, fixture.rewordedText, original, retry, sentinel];
  for (const value of values) redactor.add(value, Buffer.from(value).toString("base64"));

  const document = "Fixture-only checklist policy. Judge this synthetic candidate against the single active owner row.";
  const question = secrets07QuestionId(document);
  const phases = ["allow", "warn", "block", "retry", "help"] as const;
  const steps: ProviderStep[] = phases.flatMap(phase => [0, 1].map(index => ({
    id: `SECRETS-07-${phase}-${index}`, origin: "policy", role: "checker", purpose: "policy-owner-pass",
    request: { method: "POST" as const, path: "/v1/chat/completions", model: "policy-checker", fields: { stream: false } },
    response: openaiText(`secrets07-${phase}-${index}`, "policy-checker",
      JSON.stringify({ [question]: { yes: phase === "allow" ? 0 : 1, no: phase === "allow" ? 1 : 0 } }),
      { inputTokens: 32, outputTokens: 8 }),
  })));
  steps.push({ id: "SECRETS-07-restart-help", origin: "policy", role: "checker", purpose: "policy-owner-pass",
    request: { method: "POST", path: "/v1/chat/completions", model: "policy-checker", fields: { stream: false } },
    response: openaiText("secrets07-restart-help", "policy-checker", JSON.stringify({ [question]: { yes: 1, no: 0 } }),
      { inputTokens: 32, outputTokens: 8 }) });
  const providers = await ScriptedProviders.start({ id: "SECRETS-07", steps });
  try {
    const policyOrigin = providers.urls.policy;
    if (!policyOrigin) throw new Error("SECRETS-07 policy fixture has no origin");
    const engine = await EngineFixture.start({ id: "SECRETS-07", profile, serverLog: "debug", serverConfig: `
[models.providers.policy]
kind = "local-openai-compat"
base_url = "${policyOrigin}"
revision = "e2e-v1"
request_compression = false
[models.roles.checker]
model = "policy:policy-checker"
[models.dreamer]
enabled = false
` });
    try {
      redactor.add(engine.pairedActor.credential, Buffer.from(engine.pairedActor.credential).toString("base64"));
      const gates = new Map<string, secrets07GateReceipt>();
      const calls = new Map<string, secrets07CallReceipt>();
      const writeCalls: { ref: string; verb: string }[] = [];
      const secrets07Invocation = (): string => crypto.randomUUID().replaceAll("-", "");
      const secrets07Ref = (headers: Headers): string => {
        const ref = headers.get("x-oneiron-receipt-ref");
        expect(typeof ref === "string" && ref.startsWith("call:")).toBe(true);
        if (!ref || !ref.startsWith("call:")) throw new Error("SECRETS-07 authenticated call has no receipt");
        return ref;
      };
      async function secrets07Call<V extends FacadeVerb>(client: PublicHttpClient, verb: V, input: FacadeInput<V>): Promise<FacadeResult<V>> {
        const reply = await client.raw<FacadeResult<V>>("POST", `/v1/core/facade/${verb}`, input,
          { "x-oneiron-invocation": secrets07Invocation() });
        secrets07Scan(reply.bytes, values);
        secrets07Scan([...reply.headers], values);
        expect(reply.status).toBe(200);
        if (["vault.agents.create", "vault.policy.owner.configure", "vault.policy.owner.row.change"].includes(verb)) {
          writeCalls.push({ ref: secrets07Ref(reply.headers), verb });
        }
        return reply.body;
      }
      async function secrets07ReadCall(ref: string): Promise<secrets07CallReceipt> {
        const row = await awaitPublic(() => secrets07Call(engine.client, "vault.receipts.get", { receipt_ref: ref }),
          value => value !== null, { label: "SECRETS-07 public call receipt" });
        if (!row) throw new Error("SECRETS-07 call receipt did not become readable");
        expect(row.receipt_ref).toBe(ref);
        return row;
      }
      async function secrets07ReadGate(ref: string): Promise<secrets07GateReceipt> {
        const row = await awaitPublic(async () => {
          let after: string | undefined;
          const cursors = new Set<string>();
          for (;;) {
            const page = await secrets07Call(engine.client, "vault.receipts", { limit: 1000, ...(after ? { after } : {}) });
            expect(page.undecodable).toBe(0);
            const found = page.receipts.find(receipt => receipt.receipt_ref === ref);
            if (found) return found;
            if (!page.next_after) return null;
            expect(cursors.has(page.next_after)).toBe(false);
            cursors.add(page.next_after);
            after = page.next_after;
          }
        }, value => value !== null, { label: "SECRETS-07 public gate receipt" });
        if (!row) throw new Error("SECRETS-07 gate receipt did not become readable");
        return row;
      }
      async function secrets07Refuse(actor: PairedActor, verb: string, input: unknown, status: number, code: string, authenticated: boolean): Promise<void> {
        const count = providers.seenFixtureCalls.length;
        const reply = await actor.client.raw("POST", `/v1/core/facade/${verb}`, input,
          { "x-oneiron-invocation": secrets07Invocation() });
        secrets07Scan(reply.bytes, values);
        secrets07Scan([...reply.headers], values);
        expect(reply.status).toBe(status);
        const error = secrets07Object(secrets07Object(reply.body).error);
        expect(error.code).toBe(code);
        expect(typeof error.message === "string" && error.message.length > 0).toBe(true);
        expect(Array.isArray(error.suggestions)).toBe(true);
        expect(typeof error.requestId === "string" && error.requestId.length > 0).toBe(true);
        expect(providers.seenFixtureCalls.length).toBe(count);
        const ref = secrets07Ref(reply.headers);
        const row = await secrets07ReadCall(ref);
        expect(row.verb).toBe(verb);
        expect(row.transport).toBe("http_facade");
        if (authenticated) {
          expect(error.receiptRef === ref).toBe(true);
          expect(row.actor_ref).toBe(actor.principalRef);
          expect(row.actor_class).toBe("agent");
          expect(row.outcome).toEqual({ refused: { code } });
        } else {
          expect(row.actor_class).toBe("connection");
          expect(row.credential_ref == null).toBe(true);
          expect(row.outcome).toEqual({ refused: { code: `HTTP_${status}` } });
        }
        calls.set(ref, row);
      }
      const rowRef = "fixture.checklist";
      const rowText = "Apply the fixture checklist constraint.";
      async function secrets07Decide(actor: PairedActor, content: string, action: secrets07Action, stepId: string) {
        const count = providers.seenFixtureCalls.length;
        const input = { subject: "action", content } satisfies FacadeInput<"vault.policy.outbound.decide">;
        const reply = await actor.client.raw<secrets07Enforcement>("POST", "/v1/core/facade/vault.policy.outbound.decide", input,
          { "x-oneiron-invocation": secrets07Invocation() });
        secrets07Scan([...reply.headers], values);
        if (reply.status !== 200) secrets07Scan(reply.bytes, values);
        expect(reply.status).toBe(200);
        const result = reply.body;
        // Only the promised Allow/Warn final_content field may carry the candidate.
        if (action === "allow" || action === "warn") {
          const { final_content: finalContent, ...withoutFinalContent } = result;
          secrets07Scan(withoutFinalContent, values);
          expect(typeof finalContent === "string"
            && Buffer.from(finalContent).equals(Buffer.from(content))).toBe(true);
        } else {
          secrets07Scan(reply.bytes, values);
          expect(result.final_content == null).toBe(true);
        }
        expect(result.action).toBe(action);
        expect(result.verdict.decision).toBe(action === "route_to_help" ? "route-to-help" : action);
        expect(result.custom_tier_skipped).toBe(false);
        const halts = action === "block" || action === "route_to_help";
        expect(result.outbound_halted).toBe(halts);
        expect(result.pre_display_block).toBe(halts);
        if (halts) expect(result.barge_in_kill).toEqual({ cancel_tts: true, flush_playout_buffer: true, cancel_llm: true });
        if (action !== "allow") {
          expect(result.notice_voice).toBe("system");
          expect(result.verdict.category).toEqual({ category: "owner_policy", sub: { row_ref: rowRef } });
          const noticeType = action === "warn" ? "policy_warn" : action === "block" ? "policy_block" : "policy_help_card";
          const notice = result.system_notices?.find(item => item.notice_type === noticeType);
          expect(notice?.voice).toBe("system");
          expect(notice?.policy_plane).toBe("owner_policy");
          expect(notice?.row_ref).toBe(rowRef);
          expect(typeof notice?.body === "string" && notice.body.length > 0).toBe(true);
        }
        if (action === "route_to_help") {
          expect(result.help_routing?.diagnosis === null).toBe(true);
          expect(result.help_routing?.persona_present).toBe(true);
        }
        const ref = result.receipt_ref;
        expect(typeof ref === "string" && ref.startsWith("gate:")).toBe(true);
        if (!ref || !ref.startsWith("gate:")) throw new Error("SECRETS-07 enforcement has no gate receipt");
        expect(gates.has(ref)).toBe(false);
        const gate = await secrets07ReadGate(ref);
        expect(gate.kind).toBe("gate");
        expect(gate.outcome).toBe(action);
        expect(gate.reason_codes.includes(`gate.policy_model.${action}`)).toBe(true);
        expect(gate.actor_ref).toBe(actor.principalRef);
        expect(gate.content_kind).toBe("action");
        gates.set(ref, gate);
        const callRef = secrets07Ref(reply.headers);
        const call = await secrets07ReadCall(callRef);
        expect(call.verb).toBe("vault.policy.outbound.decide");
        expect(call.actor_ref).toBe(actor.principalRef);
        expect(call.outcome).toBe("ok");
        calls.set(callRef, call);
        const seen = providers.seenFixtureCalls;
        expect(seen.length).toBe(count + 1);
        const wire = seen[count];
        if (!wire) throw new Error("SECRETS-07 classifier request was not observed");
        expect(wire.fixtureId).toBe(stepId);
        const body = secrets07Object(wire.body);
        expect(body.model).toBe("policy-checker");
        expect(wire.headers?.["content-type"]?.startsWith("application/json")).toBe(true);
        if (!Array.isArray(body.messages)) throw new Error("SECRETS-07 classifier has no messages");
        expect(body.messages.some((message: unknown) => {
          const item = secrets07Object(message);
          return item.role === "user" && typeof item.content === "string"
            && Buffer.from(item.content).equals(Buffer.from(content));
        })).toBe(true);
        expect(body.messages.some((message: unknown) => {
          const item = secrets07Object(message);
          return item.role === "system" && item.content === document;
        })).toBe(true);
        secrets07Scan(body, ["Answer briefly.", "Explain each step in detail."]);
        secrets07Scan(wire.headers, values);
        return { result, call };
      }

      const authored = [
        { id: secrets07Invocation(), name: fixture.agents[0], instructions: "Answer briefly." },
        { id: secrets07Invocation(), name: fixture.agents[1], instructions: "Explain each step in detail." },
      ] as const;
      for (const definition of authored) {
        const created = await secrets07Call(engine.client, "vault.agents.create", {
          agent_def_ref: definition.id, definition: { agent_id: definition.name, display_name: definition.name,
            desc: "Synthetic checklist policy actor", version: "1", instructions: definition.instructions },
        });
        expect(created.agent_def_ref).toBe(definition.id);
        const saved = await secrets07Call(engine.client, "vault.agents.get", { agent_def_ref: definition.id });
        expect(saved.definition.instructions).toBe(definition.instructions);
      }
      const readOnly = await engine.pairActor({ principalRef: authored[0].id, actorClass: "agent", scope: ["core:read"] });
      redactor.add(readOnly.credential, Buffer.from(readOnly.credential).toString("base64"));
      const candidate = { subject: "action", content: original } satisfies FacadeInput<"vault.policy.outbound.decide">;
      await secrets07Refuse(readOnly, "vault.policy.outbound.decide", candidate, 403, "FORBIDDEN", true);
      const [concise, verbose] = await Promise.all(authored.map(definition => engine.pairActor({
        principalRef: definition.id, actorClass: "agent", scope: ["core:read", "core:write"],
      })));
      if (!concise || !verbose) throw new Error("SECRETS-07 needs both authored principals");
      const actors = [concise, verbose] as const;
      for (const actor of actors) {
        redactor.add(actor.credential, Buffer.from(actor.credential).toString("base64"));
        const identity = await secrets07Call(actor.client, "self.actor", {});
        expect(identity.actor_ref).toBe(actor.principalRef);
        expect(identity.actor_class).toBe("agent");
      }
      await secrets07Call(engine.client, "vault.policy.owner.row.change", { change: { Add: {
        row_ref: rowRef, text: rowText, action: "warn", scope: "Vault",
      } } });
      const current = await secrets07Call(engine.client, "vault.policy.owner.get", {});
      const configuration = { owner_policy_enabled: true, owner_policy_document: document,
        owner_policy_output_contract: "binary", owner_policy_patterns: [] } satisfies FacadeInput<"vault.policy.owner.configure">["configuration"];
      const configured = await secrets07Call(engine.client, "vault.policy.owner.configure", {
        expected_body_hash: current.body_hash, configuration,
      });
      gates.set(configured.receipt_ref, await secrets07ReadGate(configured.receipt_ref));
      const enabled = await secrets07Call(engine.client, "vault.policy.owner.get", {});
      expect(enabled.enabled).toBe(true);
      expect(enabled.configuration).toEqual(configuration);
      expect(enabled.body_hash).toBe(configured.configuration.body_hash);
      await secrets07Refuse(readOnly, "vault.policy.owner.get", {}, 403, "FORBIDDEN", true);
      await secrets07Refuse(concise, "vault.policy.owner.configure", {
        expected_body_hash: enabled.body_hash, configuration: { ...configuration, owner_policy_enabled: false },
      } satisfies FacadeInput<"vault.policy.owner.configure">, 403, "FORBIDDEN", true);
      await secrets07Refuse(concise, "vault.policy.owner.row.change", { change: { Edit: {
        row_ref: rowRef, text: rowText, action: "block", scope: "Vault",
      } } } satisfies FacadeInput<"vault.policy.owner.row.change">, 403, "FORBIDDEN", true);
      expect((await secrets07Call(engine.client, "vault.policy.owner.get", {})).body_hash).toBe(enabled.body_hash);

      let originalBlock: secrets07Enforcement | undefined;
      let conciseCall: secrets07CallReceipt | undefined;
      for (const phase of phases) {
        if (phase === "block" || phase === "help") {
          await secrets07Call(engine.client, "vault.policy.owner.row.change", { change: { Edit: {
            row_ref: rowRef, text: rowText, action: phase === "block" ? "block" : "route_to_help", scope: "Vault",
          } } });
        }
        const action: secrets07Action = phase === "retry" ? "block" : phase === "help" ? "route_to_help" : phase;
        const results: secrets07Enforcement[] = [];
        for (const [index, actor] of actors.entries()) {
          const observed = await secrets07Decide(actor, phase === "retry" ? retry : original, action, `SECRETS-07-${phase}-${index}`);
          results.push(observed.result);
          if (actor === concise) conciseCall = observed.call;
        }
        const [first, second] = results;
        if (!first || !second) throw new Error("SECRETS-07 has no decision pair");
        expect(first.verdict.binding.content_hash).toEqual(second.verdict.binding.content_hash);
        expect(first.verdict.binding.read_frontier_hash).toEqual(second.verdict.binding.read_frontier_hash);
        if (phase === "block") originalBlock = first;
        if (phase === "retry") {
          if (!originalBlock) throw new Error("SECRETS-07 has no original Block");
          expect(first.verdict.binding.content_hash).not.toEqual(originalBlock.verdict.binding.content_hash);
          expect(first.verdict.binding.read_frontier_hash).toEqual(originalBlock.verdict.binding.read_frontier_hash);
        }
      }
      if (!conciseCall || !/^[a-f0-9]{64}$/.test(conciseCall.credential_ref ?? "")) {
        throw new Error("SECRETS-07 call receipt has no paired slip identifier");
      }
      const slipBytes = Buffer.from(conciseCall.credential_ref!, "hex");
      expect(slipBytes.length).toBe(32);
      const revoked = await engine.client.raw<{ revoked: boolean }>("POST", "/v1/core/slips/revoke", { slip_id: [...slipBytes] });
      secrets07Scan(revoked.bytes, values);
      secrets07Scan([...revoked.headers], values);
      expect(revoked.status).toBe(200);
      expect(revoked.body.revoked).toBe(true);
      await secrets07Refuse(concise, "vault.policy.outbound.decide", candidate, 401, "UNAUTHORIZED", false);
      for (const write of writeCalls) {
        const row = await secrets07ReadCall(write.ref);
        expect(row.verb).toBe(write.verb);
        expect(row.actor_ref).toBe(engine.pairedActor.principalRef);
        expect(row.outcome).toBe("ok");
        calls.set(write.ref, row);
      }
      const beforeRestart = await secrets07Call(engine.client, "vault.policy.owner.get", {});
      await engine.restart();
      const afterRestart = await secrets07Call(engine.client, "vault.policy.owner.get", {});
      expect(afterRestart).toEqual(beforeRestart);
      for (const definition of authored) {
        const saved = await secrets07Call(engine.client, "vault.agents.get", { agent_def_ref: definition.id });
        expect(saved.definition.instructions).toBe(definition.instructions);
      }
      for (const [ref, row] of gates) expect(await secrets07ReadGate(ref)).toEqual(row);
      for (const [ref, row] of calls) expect(await secrets07ReadCall(ref)).toEqual(row);
      await secrets07Refuse(concise, "vault.policy.outbound.decide", candidate, 401, "UNAUTHORIZED", false);
      await secrets07Decide(verbose, original, "route_to_help", "SECRETS-07-restart-help");
      expect(providers.seenFixtureCalls.length).toBe(11);

      const recalled = await secrets07Call(engine.client, "vault.recall", { query: original, effort: "light", limit: 10 });
      secrets07Scan(recalled, values);
      const exported = await secrets07Call(engine.client, "vault.export", { format: "archive", include_secrets: false, delivery: "inline" });
      if (!("archive" in exported)) throw new Error("SECRETS-07 expected an inline public archive");
      const archive = Buffer.from(exported.archive, "base64");
      expect(Buffer.from(blake3(archive)).toString("hex")).toBe(exported.digest);
      secrets07Scan(archive, values);
      const members = publicZip(exported.archive);
      expect(members.size > 0).toBe(true);
      for (const bytes of members.values()) secrets07Scan(bytes, values);
      let after: string | undefined;
      const cursors = new Set<string>();
      for (;;) {
        const page = await secrets07Call(engine.client, "vault.receipts", { limit: 1000, ...(after ? { after } : {}) });
        expect(page.undecodable).toBe(0);
        if (!page.next_after) break;
        expect(cursors.has(page.next_after)).toBe(false);
        cursors.add(page.next_after);
        after = page.next_after;
      }
      await providers.close();
      await engine.close();
      expect(engine.serverOutputHas(values.flatMap(value => [value, Buffer.from(value).toString("base64")])).found === false
        && engine.serverOutputHas(values.flatMap(value => [value, Buffer.from(value).toString("base64")])).truncated === false).toBe(true);
    } finally {
      await engine.close();
    }
  } finally {
    await providers.close();
  }
});

/*
 * Promise: an adult trusted contact consents for itself; ask-first concern
 * notices carry only the fact of concern, require the person's authorization,
 * inform the sending agent, and stop after either party revokes, across restart.
 *
 * The typed name/consent/revoke/list/propose/asks/authorize/deliver doors exist.
 * Personal consent and authorization correctly require a human. However, the
 * substrate proposal and reads also require human proof: no live agent Grant
 * admits them, so owner revoke -> next-use refusal cannot be exercised.
 *
 * Human name -> consent -> propose -> revoke -> superseded is real, but does
 * not meet that mandatory grant-loss leg or prove fact-only delivery. Keep the
 * case blocked rather than count an empty deliver/asks read as a working notice.
 * Delivery also needs a fully scripted verified channel binding, not an
 * invented generic POST /concern sink; native-mail JMAP is a possible fixture.
 * The owner's own source read/archive may legitimately contain the conversation.
 * Report: <workspace>/Desktop/temp/vibe-build-20261017/lanes/kimi/OPUS-E2E-5/cases/SECRETS-08.report.md
 */
suite.todo(test, "SECRETS-08", "waits on owner-revocable agent Grant admission for vault.trusted_contacts.concern.propose, vault.trusted_contacts.concern.asks and vault.trusted_contacts.list");

// No additional imports; all dependencies are already imported by secrets.test.ts.

interface secrets09Fixture {
  "SECRETS-09": {
    action: { operation: string; text: string };
    backendFailure: {
      status: number;
      body: { error: { message: string; type: string } };
    };
  };
}

function secrets09Object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("SECRETS-09 expected a public object (body withheld)");
  }
  return value as Record<string, unknown>;
}

function secrets09Scan<T>(value: T, needles: readonly string[]): T {
  const bytes = value instanceof Uint8Array ? Buffer.from(value)
    : Buffer.from(typeof value === "string" ? value : JSON.stringify(value) ?? "");
  expect(needles.every(needle => !bytes.includes(Buffer.from(needle)))).toBe(true);
  return value;
}

function secrets09Invocation(): Record<string, string> {
  return { "x-oneiron-invocation": crypto.randomUUID().replaceAll("-", "") };
}

async function secrets09Call<V extends FacadeVerb>(
  client: PublicHttpClient, verb: V, input: FacadeInput<V>, needles: readonly string[],
): Promise<FacadeResult<V>> {
  const reply = await client.raw<FacadeResult<V>>(
    "POST", `/v1/core/facade/${verb}`, input, secrets09Invocation(),
  );
  secrets09Scan(reply.bytes, needles);
  secrets09Scan(reply.body, needles);
  secrets09Scan(Object.fromEntries(reply.headers), needles);
  expect(reply.status).toBe(200);
  return reply.body;
}

async function secrets09Decide(
  client: PublicHttpClient, input: FacadeInput<"vault.policy.outbound.decide">,
  needles: readonly string[],
): Promise<WireReply<FacadeResult<"vault.policy.outbound.decide">>> {
  const reply = await client.raw<FacadeResult<"vault.policy.outbound.decide">>(
    "POST", "/v1/core/facade/vault.policy.outbound.decide", input, secrets09Invocation(),
  );
  secrets09Scan(Object.fromEntries(reply.headers), needles);
  if (reply.status !== 200) secrets09Scan(reply.bytes, needles);
  expect(reply.status).toBe(200);
  // This field is the promised candidate, not a receipt or diagnostic leak.
  const { final_content: finalContent, ...otherFields } = reply.body;
  secrets09Scan(otherFields, needles);
  expect(typeof finalContent === "string"
    && Buffer.from(finalContent).equals(Buffer.from(input.content))).toBe(true);
  return reply;
}

async function secrets09Refuse<V extends FacadeVerb>(
  client: PublicHttpClient, verb: V, input: FacadeInput<V>, status: number,
  code: string, needles: readonly string[],
): Promise<WireReply<unknown>> {
  const reply = await client.raw("POST", `/v1/core/facade/${verb}`, input, secrets09Invocation());
  secrets09Scan(reply.bytes, needles);
  secrets09Scan(reply.body, needles);
  secrets09Scan(Object.fromEntries(reply.headers), needles);
  expect(reply.status).toBe(status);
  const error = secrets09Object(secrets09Object(reply.body).error);
  expect(error.code).toBe(code);
  expect(typeof error.message === "string" && error.message.length > 0).toBe(true);
  expect(Array.isArray(error.suggestions)).toBe(true);
  expect(typeof error.requestId === "string" && error.requestId.length > 0).toBe(true);
  return reply;
}

async function secrets09CallReceipt(
  client: PublicHttpClient, reply: WireReply<unknown>, verb: string,
  actorRef: string | null, outcome: "ok" | { refused: { code: string } }, needles: readonly string[],
): Promise<NonNullable<FacadeResult<"vault.receipts.get">>> {
  const ref = reply.headers.get("x-oneiron-receipt-ref");
  if (!ref || !/^call:[a-f0-9]{32}$/.test(ref)) {
    throw new Error("SECRETS-09 authenticated facade call lacks its call receipt");
  }
  if (reply.status !== 200) {
    const error = secrets09Object(secrets09Object(reply.body).error);
    if (actorRef === null) expect(error.receiptRef == null).toBe(true);
    else expect(error.receiptRef).toBe(ref);
  }
  const receipt = await awaitPublic(
    () => secrets09Call(client, "vault.receipts.get", { receipt_ref: ref }, needles),
    row => row !== null, { label: "SECRETS-09 call receipt" },
  );
  if (!receipt) throw new Error("SECRETS-09 call receipt is not publicly readable");
  expect(receipt.receipt_ref).toBe(ref);
  expect(receipt.verb).toBe(actorRef === null ? verb : `v1/core/facade/${verb}`);
  expect(receipt.transport).toBe("http_facade");
  if (actorRef === null) {
    expect(receipt.actor_class).toBe("connection");
    expect(/^[a-f0-9]{32}$/.test(receipt.actor_ref)).toBe(true);
    expect(receipt.credential_ref == null && receipt.result_digest == null).toBe(true);
  } else expect(receipt.actor_ref).toBe(actorRef);
  expect(receipt.outcome).toEqual(outcome);
  return receipt;
}

async function secrets09GateRows(client: PublicHttpClient, needles: readonly string[]) {
  const rows: FacadeResult<"vault.receipts">["receipts"] = [];
  let after: string | null = null;
  do {
    const page = await secrets09Call(client, "vault.receipts", {
      kinds: ["gate"], limit: 100, ...(after === null ? {} : { after }),
    }, needles);
    expect(page.undecodable).toBe(0);
    rows.push(...page.receipts);
    after = page.next_after ?? null;
  } while (after !== null);
  return rows;
}

async function secrets09Gate(client: PublicHttpClient, ref: string, needles: readonly string[]) {
  expect(/^gate:[a-f0-9]{32}$/.test(ref)).toBe(true);
  const rows = await awaitPublic(
    () => secrets09GateRows(client, needles),
    page => page.some(row => row.receipt_ref === ref), { label: "SECRETS-09 policy receipt" },
  );
  const receipt = rows.find(row => row.receipt_ref === ref);
  if (!receipt) throw new Error("SECRETS-09 policy receipt is not publicly readable");
  return receipt;
}

function secrets09Manifest(
  shape: FacadeResult<"vault.shape.read">, ref: string, needles: readonly string[],
): Record<string, unknown> {
  const row = shape.live.rows.find(item => item.kind === "manifest" && item.manifest_ref === ref);
  if (!row || row.kind !== "manifest") throw new Error("SECRETS-09 default manifest is absent");
  if (row.body) {
    const bytes = secrets09Scan(Buffer.from(row.body, "hex"), needles);
    return secrets09Object(secrets09Scan(decode(bytes), needles));
  }
  return secrets09Object(secrets09Scan(row.json, needles));
}

function secrets09AssertCooldown(body: Record<string, unknown>): void {
  if (!Array.isArray(body.policy_values)) throw new Error("SECRETS-09 policy values are absent");
  const rows = body.policy_values.map(secrets09Object).filter(row =>
    row.key === "provider_cooldown_max_wait_seconds"
    && secrets09Object(row.scope).level === "vault");
  expect(rows.length > 0 && rows.every(row => row.value === 0)).toBe(true);
}

/*
 * Promise: owner policy starts off; an opted-in classifier outage preserves the
 * candidate as Skipped with an honest, content-free, restart-durable receipt.
 * Doors: owner get/configure/row.change, shape read/plan/apply, agent create/get,
 * outbound.decide, receipts/get, public slip revoke, recall and decoded export.
 * PARTIAL: no authenticated hosted relay can be bound through a public door in
 * this binary. No hosted outage, service notice or actual delivery is claimed.
 */
suite.test(test, "SECRETS-09", "Owner policy is off by default; a configured backend outage returns Skipped, preserves the candidate, and never claims Allow", async () => {
  const fixture = (await (await loadFixtures()).readJson<secrets09Fixture>("secrets-blocked-scenarios"))["SECRETS-09"];
  const actionText = fixture.action.text;
  redactor.add(actionText, Buffer.from(actionText).toString("base64"));
  const sentinel = `secrets09-${crypto.randomUUID()}`;
  redactor.add(sentinel, Buffer.from(sentinel).toString("base64"));
  const value = `${actionText} ${sentinel}`;
  const base64 = Buffer.from(value).toString("base64");
  redactor.add(value, base64);
  const needles = [actionText, Buffer.from(actionText).toString("base64"),
    sentinel, Buffer.from(sentinel).toString("base64"), value, base64];
  const input = { subject: "action", content: value } satisfies FacadeInput<"vault.policy.outbound.decide">;
  const providers = await ScriptedProviders.start({ id: "SECRETS-09", steps: [{
    id: "secrets09-owner-outage", origin: "policy", role: "checker", purpose: "policy-owner-pass",
    request: { method: "POST", path: "/v1/chat/completions", model: "policy-checker", fields: { stream: false } },
    response: { kind: "json", status: fixture.backendFailure.status, body: fixture.backendFailure.body },
  }] });
  try {
    const origin = providers.urls.policy;
    if (!origin) throw new Error("SECRETS-09 scripted policy origin is absent");
    const engine = await EngineFixture.start({ id: "SECRETS-09", profile, serverLog: "debug", serverConfig: `
[models.providers.policy]
kind = "local-openai-compat"
base_url = "${origin}"
revision = "e2e-v1"
request_compression = false
[models.roles.checker]
model = "policy:policy-checker"
[models.dreamer]
enabled = false
` });
    try {
      const owner = engine.client;
      const initial = await secrets09Call(owner, "vault.policy.owner.get", {}, needles);
      expect(initial.enabled).toBe(false);
      expect(initial.configuration.owner_policy_enabled).toBe(false);
      expect(initial.configuration.owner_policy_document == null).toBe(true);
      expect(initial.configuration.owner_policy_output_contract == null).toBe(true);
      expect(initial.configuration.owner_policy_patterns ?? []).toEqual([]);
      const shape = await secrets09Call(owner, "vault.shape.read", {}, needles);
      const defaultBody = secrets09Manifest(shape, initial.manifest_ref, needles);
      expect(defaultBody.owner_policy_rows).toEqual([]);

      const off = await secrets09Decide(owner, input, needles);
      expect(off.body.action).toBe("allow");
      expect(off.body.verdict.decision).toBe("allow");
      expect(off.body.outbound_halted).toBe(false);
      expect(off.body.custom_tier_skipped).toBe(false);
      expect(off.body.receipt_ref == null).toBe(true);
      await secrets09CallReceipt(owner, off, "vault.policy.outbound.decide", engine.pairedActor.principalRef, "ok", needles);
      expect(providers.seenFixtureCalls.length).toBe(0);

      // Public owner policy, not a clock change: shipped max-wait 60 -> 0.
      const previousValues: unknown = defaultBody.policy_values ?? [];
      if (!Array.isArray(previousValues)) throw new Error("SECRETS-09 malformed public policy values");
      let replaced = false;
      const policyValues = previousValues.map(secrets09Object).map(row => {
        if (row.key !== "provider_cooldown_max_wait_seconds"
          || secrets09Object(row.scope).level !== "vault") return row;
        replaced = true;
        return { ...row, value: 0 };
      });
      if (!replaced) policyValues.push({ row_ref: "fixture.provider_cooldown_max_wait_seconds",
        key: "provider_cooldown_max_wait_seconds", value: 0, scope: { level: "vault" } });
      const rows = shape.live.rows.map(row => row.kind === "manifest" && row.manifest_ref === initial.manifest_ref
        ? { kind: "manifest" as const, manifest_ref: initial.manifest_ref,
          json: { ...defaultBody, policy_values: policyValues } } : row);
      const plan = await secrets09Call(owner, "vault.shape.plan", { seed: { rows } }, needles);
      expect(plan.items.length).toBe(1);
      expect(plan.items.some(item => item.target.kind === "manifest"
        && item.target.manifest_ref === initial.manifest_ref)).toBe(true);
      const applied = await secrets09Call(owner, "vault.shape.apply", { plan, approve: plan.items.map(item => item.seq) }, needles);
      expect(applied.done).toBe(true);
      for (const item of applied.items) expect(item.state.state).toBe("landed");
      const cooled = await secrets09Call(owner, "vault.shape.read", {}, needles);
      secrets09AssertCooldown(secrets09Manifest(cooled, initial.manifest_ref, needles));

      const agentRef = crypto.randomUUID().replaceAll("-", "");
      const definition = { agent_id: "fixture.policy-outage", display_name: "Fixture policy outage actor",
        desc: "Synthetic owner policy candidate submitter", version: "1", instructions: "Submit the synthetic candidate unchanged." };
      await secrets09Call(owner, "vault.agents.create", { agent_def_ref: agentRef, definition }, needles);
      const savedAgent = await secrets09Call(owner, "vault.agents.get", { agent_def_ref: agentRef }, needles);
      expect(savedAgent.agent_def_ref).toBe(agentRef);
      expect(savedAgent.definition.instructions).toBe(definition.instructions);
      const [withoutWrite, writer] = await Promise.all([
        engine.pairActor({ principalRef: savedAgent.agent_def_ref, actorClass: "agent", scope: ["core:read"] }),
        engine.pairActor({ principalRef: savedAgent.agent_def_ref, actorClass: "agent", scope: ["core:read", "core:write"] }),
      ]);
      const noGrant = await secrets09Refuse(withoutWrite.client, "vault.policy.outbound.decide", input, 403, "FORBIDDEN", needles);
      const noGrantReceipt = await secrets09CallReceipt(owner, noGrant, "vault.policy.outbound.decide", agentRef,
        { refused: { code: "FORBIDDEN" } }, needles);
      expect(noGrantReceipt.actor_class).toBe("agent");
      expect(providers.seenFixtureCalls.length).toBe(0);

      const rowText = "Apply the fixture checklist constraint.";
      const rowChange = { change: { Add: { row_ref: "fixture.checklist", text: rowText,
        action: "warn", scope: "Vault" } } } satisfies FacadeInput<"vault.policy.owner.row.change">;
      await secrets09Call(owner, "vault.policy.owner.row.change", rowChange, needles);
      const withRow = secrets09Manifest(await secrets09Call(owner, "vault.shape.read", {}, needles), initial.manifest_ref, needles);
      expect(Array.isArray(withRow.owner_policy_rows) && withRow.owner_policy_rows.some(value => {
        const row = secrets09Object(value);
        return row.row_ref === "fixture.checklist" && row.text === rowText && row.action === "warn" && row.active === true;
      })).toBe(true);
      const configuration = { owner_policy_enabled: true,
        owner_policy_document: "Fixture-only checklist policy. Judge this synthetic candidate against the single active owner row.",
        owner_policy_output_contract: "binary", owner_policy_patterns: [],
      } satisfies FacadeInput<"vault.policy.owner.configure">["configuration"];
      const beforeConfigure = await secrets09Call(owner, "vault.policy.owner.get", {}, needles);
      const configured = await secrets09Call(owner, "vault.policy.owner.configure", {
        expected_body_hash: beforeConfigure.body_hash, configuration,
      }, needles);
      const configurationReceipt = await secrets09Gate(owner, configured.receipt_ref, needles);
      expect(configurationReceipt.reason_codes).toContain("gate.allow.owner_content_policy_configuration");
      const enabled = await secrets09Call(owner, "vault.policy.owner.get", {}, needles);
      expect(enabled.enabled).toBe(true);
      expect(enabled.configuration).toEqual(configuration);
      expect(enabled.body_hash).toBe(configured.configuration.body_hash);

      // A write-capable agent still cannot act as the human owner.
      const wrongKind = await secrets09Refuse(writer.client, "vault.policy.owner.configure", {
        expected_body_hash: enabled.body_hash, configuration: { ...configuration, owner_policy_enabled: false },
      }, 403, "FORBIDDEN", needles);
      const wrongKindReceipt = await secrets09CallReceipt(owner, wrongKind, "vault.policy.owner.configure", agentRef,
        { refused: { code: "FORBIDDEN" } }, needles);
      expect(wrongKindReceipt.actor_class).toBe("agent");
      const afterRefusal = await secrets09Call(owner, "vault.policy.owner.get", {}, needles);
      expect(afterRefusal.body_hash).toBe(enabled.body_hash);
      expect(afterRefusal.enabled).toBe(true);
      expect(providers.seenFixtureCalls.length).toBe(0);

      const outage = await secrets09Decide(writer.client, input, needles);
      expect(outage.body.action).toBe("skipped");
      expect(outage.body.verdict.decision).toEqual({ skipped: "backend-unavailable" });
      expect(outage.body.custom_tier_skipped).toBe(true);
      expect(outage.body.outbound_halted).toBe(false);
      expect(outage.body.verdict.plane_minted).toBe("owner_policy");
      expect(outage.body.verdict.hosted_attestation == null).toBe(true);
      expect(providers.seenFixtureCalls.length).toBe(1);
      const seen = providers.seenFixtureCalls[0];
      if (!seen) throw new Error("SECRETS-09 classifier was not called");
      expect(seen.fixtureId).toBe("secrets09-owner-outage");
      const { body: providerBody, ...providerMetadata } = seen;
      secrets09Scan(providerMetadata, needles);
      const { messages, ...providerFields } = secrets09Object(providerBody);
      secrets09Scan(providerFields, needles);
      if (!Array.isArray(messages)) throw new Error("SECRETS-09 classifier messages are absent");
      let candidateMessages = 0;
      for (const value of messages) {
        const message = secrets09Object(value);
        if (message.role === "user" && message.content === input.content) {
          candidateMessages++;
          const { content: _candidate, ...otherFields } = message;
          secrets09Scan(otherFields, needles);
        } else secrets09Scan(message, needles);
      }
      expect(candidateMessages).toBe(1);

      const policyRef = outage.body.receipt_ref;
      if (!policyRef) throw new Error("SECRETS-09 skipped classification has no policy receipt");
      const policyReceipt = await secrets09Gate(owner, policyRef, needles);
      expect(policyReceipt.outcome).toBe("skipped");
      expect(policyReceipt.reason_codes).toContain("gate.policy_model.skipped");
      expect(policyReceipt.reason_codes).toContain("gate.policy_model.skip_reason.backend_unavailable");
      expect(policyReceipt.reason_codes.includes("gate.policy_model.allow")).toBe(false);
      expect(policyReceipt.actor_ref).toBe(agentRef);
      expect(policyReceipt.content_kind).toBe("action");
      const callReceipt = await secrets09CallReceipt(owner, outage, "vault.policy.outbound.decide", agentRef, "ok", needles);
      expect(callReceipt.actor_class).toBe("agent");
      const slipId = callReceipt.credential_ref;
      if (!slipId || !/^[a-f0-9]{64}$/.test(slipId)) throw new Error("SECRETS-09 call receipt lacks a revocable slip id");
      const revoked = await owner.raw("POST", "/v1/core/slips/revoke", { slip_id: Array.from(Buffer.from(slipId, "hex")) });
      secrets09Scan(revoked.bytes, needles);
      secrets09Scan(revoked.body, needles);
      secrets09Scan(Object.fromEntries(revoked.headers), needles);
      expect(revoked.status).toBe(200);
      expect(secrets09Object(revoked.body).revoked).toBe(true);
      const nextUse = await secrets09Refuse(writer.client, "vault.policy.outbound.decide", input, 401, "UNAUTHORIZED", needles);
      const nextUseReceipt = await secrets09CallReceipt(owner, nextUse, "vault.policy.outbound.decide", null,
        { refused: { code: "HTTP_401" } }, needles);
      expect(providers.seenFixtureCalls.length).toBe(1);

      await engine.restart();
      const restarted = await secrets09Call(owner, "vault.policy.owner.get", {}, needles);
      expect(restarted.enabled).toBe(true);
      expect(restarted.configuration).toEqual(configuration);
      expect(restarted.body_hash).toBe(enabled.body_hash);
      const durableShape = await secrets09Call(owner, "vault.shape.read", {}, needles);
      const durableManifest = secrets09Manifest(durableShape, initial.manifest_ref, needles);
      secrets09AssertCooldown(durableManifest);
      expect(durableManifest.owner_policy_rows).toEqual(withRow.owner_policy_rows);
      const durablePolicyReceipt = await secrets09Gate(owner, policyRef, needles);
      expect(durablePolicyReceipt).toEqual(policyReceipt);
      expect(await secrets09CallReceipt(owner, wrongKind, "vault.policy.owner.configure", agentRef,
        { refused: { code: "FORBIDDEN" } }, needles)).toEqual(wrongKindReceipt);
      expect(await secrets09CallReceipt(owner, noGrant, "vault.policy.outbound.decide", agentRef,
        { refused: { code: "FORBIDDEN" } }, needles)).toEqual(noGrantReceipt);
      expect(await secrets09CallReceipt(owner, outage, "vault.policy.outbound.decide", agentRef, "ok", needles)).toEqual(callReceipt);
      expect(await secrets09CallReceipt(owner, nextUse, "vault.policy.outbound.decide", null,
        { refused: { code: "HTTP_401" } }, needles)).toEqual(nextUseReceipt);
      const durableAgent = await secrets09Call(owner, "vault.agents.get", { agent_def_ref: agentRef }, needles);
      expect(durableAgent.definition.instructions).toBe(definition.instructions);
      // The original refusal remains readable; a fresh use is refused too.
      const revokedAfterRestart = await secrets09Refuse(writer.client, "vault.policy.outbound.decide", input, 401, "UNAUTHORIZED", needles);
      await secrets09CallReceipt(owner, revokedAfterRestart, "vault.policy.outbound.decide", null,
        { refused: { code: "HTTP_401" } }, needles);
      expect(providers.seenFixtureCalls.length).toBe(1);

      const disabled = await secrets09Call(owner, "vault.policy.owner.configure", {
        expected_body_hash: restarted.body_hash, configuration: { ...configuration, owner_policy_enabled: false },
      }, needles);
      await secrets09Gate(owner, disabled.receipt_ref, needles);
      const disabledView = await secrets09Call(owner, "vault.policy.owner.get", {}, needles);
      expect(disabledView.enabled).toBe(false);
      expect(disabledView.configuration).toEqual({ ...configuration, owner_policy_enabled: false });
      const offAgain = await secrets09Decide(owner, input, needles);
      expect(offAgain.body.action).toBe("allow");
      expect(offAgain.body.custom_tier_skipped).toBe(false);
      expect(offAgain.body.outbound_halted).toBe(false);
      expect(offAgain.body.receipt_ref == null).toBe(true);
      await secrets09CallReceipt(owner, offAgain, "vault.policy.outbound.decide", engine.pairedActor.principalRef, "ok", needles);
      expect(providers.seenFixtureCalls.length).toBe(1);
      await secrets09Call(owner, "vault.recall", { query: sentinel, effort: "light", limit: 10 }, needles);
      await secrets09GateRows(owner, needles);
      const exported = await secrets09Call(owner, "vault.export", { format: "archive", include_secrets: false, delivery: "inline" }, needles);
      if (!("archive" in exported)) throw new Error("SECRETS-09 inline export returned a transfer");
      expect(Buffer.from(blake3(Buffer.from(exported.archive, "base64"))).toString("hex")).toBe(exported.digest);
      const members = publicZip(exported.archive);
      for (const [name, bytes] of members) {
        secrets09Scan(name, needles);
        secrets09Scan(bytes, needles);
      }
      await engine.close();
      expect(engine.serverOutputHas(needles).found === false
        && engine.serverOutputHas(needles).truncated === false).toBe(true);
      expect(engine.serverOutputHas([value, base64]).found === false
        && engine.serverOutputHas([value, base64]).truncated === false).toBe(true);
    } finally {
      await engine.close();
    }
  } finally {
    await providers.close();
  }
});
