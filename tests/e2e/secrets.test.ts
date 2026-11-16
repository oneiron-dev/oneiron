import { afterAll, test } from "bun:test";
import { inflateRawSync } from "node:zlib";
import { blake3 } from "@noble/hashes/blake3";
import type { FacadeInput, FacadeResult, FacadeVerb } from "@oneiron/client";
import { EngineFixture, awaitPublic, type PairedActor } from "./support/engine.ts";
import { PublicHttpClient, PublicHttpError, McpRpcError, CliError, type WireReply } from "./support/clients.ts";
import { loadFixtures, ownerBaseClaimScope } from "./support/fixtures.ts";
import { defineFile, expect, redactor } from "./support/run.ts";
import type { Json, ProviderStep } from "./support/providers.ts";
import { randomBytes } from "node:crypto";
import { ScriptedProviders, openaiText } from "./support/providers.ts";
import { decode } from "@msgpack/msgpack";

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
type secrets03Scan = (value: unknown) => void;
type secrets03Ceiling = FacadeInput<"vault.gate.policy.put">["manifest"]["actor_ceilings"][number];

function secrets03JsonType(value: unknown): string {
  return value === null ? "null" : Array.isArray(value) ? "array" : typeof value;
}
function secrets03Object(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`SECRETS-03 ${label} expected a public JSON object; received ${secrets03JsonType(value)}; body withheld`);
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
  const secrets03Code = secrets03ErrorCode(reply.body);
  const secrets03Message = secrets03ErrorMessage(reply.body);
  expect({ check: `SECRETS-03 facade ${verb} returns HTTP 200`, status: reply.status, code: secrets03Code,
    message: secrets03Message, ok: reply.status === 200 }).toEqual({ check: `SECRETS-03 facade ${verb} returns HTTP 200`,
    status: 200, code: secrets03Code, message: secrets03Message, ok: true });
  return reply.body;
}
function secrets03ErrorCode(body: unknown): string {
  if (!body || typeof body !== "object" || Array.isArray(body)) return "unparsed-body";
  const error = (body as Record<string, unknown>).error;
  if (!error || typeof error !== "object" || Array.isArray(error)) return "no-envelope";
  const code = (error as Record<string, unknown>).code;
  return typeof code === "string" ? redactor.text(code) : "no-code";
}
// The refusal's message, redacted, so a red names why (no secret survives the redactor).
function secrets03ErrorMessage(body: unknown): string {
  if (!body || typeof body !== "object" || Array.isArray(body)) return "unparsed-body";
  const error = (body as Record<string, unknown>).error;
  if (!error || typeof error !== "object" || Array.isArray(error)) return "no-envelope";
  const message = (error as Record<string, unknown>).message;
  return typeof message === "string" ? redactor.text(message).slice(0, 300) : "no-message";
}
function secrets03SafeText(value: unknown): string {
  return typeof value === "string" ? redactor.text(value) : String(value);
}
async function secrets03McpCall<T>(method: string, call: () => Promise<T>, secrets03ScanBytes: secrets03Scan): Promise<T> {
  try {
    return await call();
  } catch (error) {
    if (error instanceof McpRpcError) {
      secrets03ScanBytes(error.response);
      if ("error" in error.response) {
        throw new Error(`SECRETS-03 MCP ${method} refused ${secrets03SafeText(error.response.error.code)}: ${secrets03SafeText(error.response.error.message)}`);
      }
      throw new Error(`SECRETS-03 MCP ${method} malformed reply`);
    }
    if (error instanceof PublicHttpError) {
      secrets03ObserveWire(error.reply, secrets03ScanBytes);
      throw new Error(`SECRETS-03 MCP ${method} HTTP ${error.reply.status} ${secrets03ErrorCode(error.reply.body)}`);
    }
    throw error;
  }
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
  expect({ check: "SECRETS-03 fixture keeps its door-only T0 rung", ok: rung.valuePlacement === "door only"
    && fixture.expected.providerReceivesCredential && !fixture.expected.modelReceivesCredential
    && !fixture.expected.deniedRevealContainsValue }).toEqual({ check: "SECRETS-03 fixture keeps its door-only T0 rung", ok: true });
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
  let secrets03BodyError: string | null = null; // Stash the masked body error for the finally scan report.
  try {
    const origin = providers.urls.connector;
    if (!origin) throw new Error("SECRETS-03 connector origin was not assigned");
    const endpoint = `${origin}/mcp`;
    // Debug for every workspace crate (EnvFilter matches targets by prefix, so "oneiron" covers oneiron_*); dependencies at
    // info keep each server stream inside the harness 4 MiB scan window (job 4: RUST_LOG=debug truncated it, absence unproved).
    const current = await EngineFixture.start({ id: "SECRETS-03", profile, serverLog: "info,oneiron=debug",
      serverConfig: `[connectors.secrets_probe]\ntransport = "mcp_http"\nendpoint = ${JSON.stringify(endpoint)}\n`,
    });
    engine = current;
    const secrets03Facade = <V extends FacadeVerb>(client: PublicHttpClient, verb: V, input: FacadeInput<V>) =>
      secrets03Call(client, verb, input, secrets03ScanBytes);
    const owner = current.client;
    const secrets03OwnerRequest = async <T>(method: string, path: string, body?: unknown): Promise<T> => {
      const reply = await owner.raw<T>(method, path, body);
      secrets03ObserveWire(reply, secrets03ScanBytes);
      const secrets03OwnerCode = secrets03ErrorCode(reply.body);
      const secrets03OwnerMessage = secrets03ErrorMessage(reply.body);
      expect({ check: `SECRETS-03 owner ${method} ${path} returns HTTP 200`, status: reply.status,
        code: secrets03OwnerCode, message: secrets03OwnerMessage, ok: reply.status === 200 }).toEqual({ check: `SECRETS-03 owner ${method} ${path} returns HTTP 200`,
        status: 200, code: secrets03OwnerCode, message: secrets03OwnerMessage, ok: true });
      return reply.body;
    };
    const secrets03Gate = async (ref: string): Promise<void> => {
      expect({ check: "SECRETS-03 gate ref is well formed", ok: /^gate:[a-f0-9]+$/.test(ref) }).toEqual({
        check: "SECRETS-03 gate ref is well formed", ok: true });
      const page = await awaitPublic(() => secrets03Facade(owner, "vault.receipts", { limit: 1000 }),
        result => result.receipts.some(row => row.receipt_ref === ref), { label: "SECRETS-03 Gate receipt" });
      expect({ check: "SECRETS-03 gate receipt is readable back", ref: secrets03SafeText(ref),
        ok: page.receipts.some(row => row.receipt_ref === ref) }).toEqual({
        check: "SECRETS-03 gate receipt is readable back", ref: secrets03SafeText(ref), ok: true });
    };
    const secrets03Refuse = async <V extends FacadeVerb>(client: PublicHttpClient, verb: V, input: FacadeInput<V>, status: number, code: string, noRecord = false) => {
      const reply = await client.raw("POST", `/v1/core/facade/${verb}`, input);
      secrets03ObserveWire(reply, secrets03ScanBytes);
      const error = secrets03Object(secrets03Object(reply.body, `${verb} refusal body`).error, `${verb} refusal error`);
      const secrets03ActualCode = typeof error.code === "string" ? redactor.text(error.code) : "no-code";
      expect({ check: `SECRETS-03 ${verb} refusal envelope`, status: reply.status, code: secrets03ActualCode,
        ok: reply.status === status && error.code === code && typeof error.message === "string"
          && typeof error.requestId === "string" && Array.isArray(error.suggestions) }).toEqual({
        check: `SECRETS-03 ${verb} refusal envelope`, status, code, ok: true });
      const ref = reply.headers.get("x-oneiron-receipt-ref");
      if (noRecord) {
        expect({ check: `SECRETS-03 ${verb} refusal is no-record`, header: secrets03SafeText(ref),
          ok: ref === "none; no-record" && error.receiptRef == null }).toEqual({
          check: `SECRETS-03 ${verb} refusal is no-record`, header: secrets03SafeText(ref), ok: true });
        return;
      }
      if (!ref || !ref.startsWith("call:")) throw new Error("SECRETS-03 refusal lacks its public call receipt");
      expect({ check: `SECRETS-03 ${verb} refusal receiptRef matches header`, receiptRef: secrets03SafeText(error.receiptRef),
        header: secrets03SafeText(ref), ok: error.receiptRef === ref }).toEqual({
        check: `SECRETS-03 ${verb} refusal receiptRef matches header`, receiptRef: secrets03SafeText(ref),
        header: secrets03SafeText(ref), ok: true });
      const receipt = await secrets03Facade(client, "vault.receipts.get", { receipt_ref: ref });
      if (!receipt) throw new Error("SECRETS-03 refusal receipt was not readable by its caller");
      expect({ check: `SECRETS-03 ${verb} refusal receipt reads back`, receipt_ref: secrets03SafeText(receipt.receipt_ref),
        receiptVerb: secrets03SafeText(receipt.verb), actorClass: secrets03SafeText(receipt.actor_class),
        ok: receipt.receipt_ref === ref && receipt.verb === verb && receipt.actor_class === "agent" }).toEqual({
        check: `SECRETS-03 ${verb} refusal receipt reads back`, receipt_ref: secrets03SafeText(ref),
        receiptVerb: verb, actorClass: "agent", ok: true });
      const secrets03RefusedActual: unknown = typeof receipt.outcome === "object" && receipt.outcome !== null
        && "refused" in receipt.outcome ? receipt.outcome.refused : "no-refusal";
      const secrets03RefusedCode: unknown = typeof secrets03RefusedActual === "object" && secrets03RefusedActual !== null
        && "code" in secrets03RefusedActual ? secrets03RefusedActual.code : secrets03RefusedActual;
      expect({ check: `SECRETS-03 ${verb} refusal receipt outcome is refused`, code: secrets03SafeText(secrets03RefusedCode),
        ok: typeof receipt.outcome === "object" && receipt.outcome.refused.code === code }).toEqual({
        check: `SECRETS-03 ${verb} refusal receipt outcome is refused`, code, ok: true });
      return ref;
    };
    const secrets03Pair = async (name: string) => {
      const created = await secrets03Facade(owner, "vault.structural.put", {
        kind: "PERSON", body: { name }, occurred_at: 1735689600,
      });
      const read = await secrets03Facade(owner, "vault.get", { entity_ref: created.id_hex });
      expect({ check: "SECRETS-03 paired person reads back", id: secrets03SafeText(read.value?.id_hex),
        created: secrets03SafeText(created.id_hex), ok: read.value?.id_hex === created.id_hex }).toEqual({
        check: "SECRETS-03 paired person reads back", id: secrets03SafeText(created.id_hex),
        created: secrets03SafeText(created.id_hex), ok: true });
      return current.pairActor({ principalRef: created.id_hex, actorClass: "agent", scope: ["core:read", "core:write"] });
    };
    const agent = await secrets03Pair("SECRETS-03 custody agent");
    const noConnectorGrant = await secrets03Pair("SECRETS-03 unconsented agent");
    // ARCH-0040 mcp-actor-ceilings: a paired agent's MCP credential resolves only
    // with a manifest ceiling row for (agent, principal); without one, initialize
    // answers JSON-RPC -32001 mcp_actor_ceiling_missing (actor_dispatch/auth.rs:300).
    // Install before connector consent: actor ceilings enter the policy frontier,
    // and a standing connector grant is valid only under the frontier that minted it.
    // "proposed" preserves the agent's default Gate posture; read it back after restart.
    const secrets03CeilingRow: secrets03Ceiling = { actor_class: "agent", actor_ref: agent.principalRef, ceiling: "proposed" };
    const secrets03CeilingBefore = await secrets03Facade(owner, "vault.gate.policy.get", {});
    const secrets03CeilingCurrent = secrets03CeilingBefore.manifests.find(row => row.manifest_ref === secrets03CeilingBefore.default_manifest_ref);
    if (!secrets03CeilingCurrent) throw new Error("SECRETS-03 default policy is absent");
    await secrets03Facade(owner, "vault.gate.policy.put", {
      manifest_ref: secrets03CeilingCurrent.manifest_ref, expected_body_hash: secrets03CeilingCurrent.body_hash,
      manifest: { ...secrets03CeilingCurrent.manifest,
        actor_ceilings: [...secrets03CeilingCurrent.manifest.actor_ceilings, secrets03CeilingRow] },
    });
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
    expect({ check: "SECRETS-03 connector ready at configured endpoint", ready: readiness.ready,
      endpoint: secrets03SafeText(readiness.endpoint), ok: readiness.ready && readiness.endpoint === endpoint }).toEqual({
      check: "SECRETS-03 connector ready at configured endpoint", ready: true, endpoint, ok: true });
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
    expect({ check: "SECRETS-03 custody starts at generation 0", generation: registered.rotation_generation,
      ok: registered.rotation_generation === 0 }).toEqual({ check: "SECRETS-03 custody starts at generation 0", generation: 0, ok: true });
    const secrets03Bind = () => secrets03OwnerRequest<secrets03Bound>("POST", "/v1/owner/secrets/bind", {
      name: "secrets03-custody", effector: "connector:secrets_probe", tier_ceiling: 0, scopes: ["read"],
    });
    const bound = await secrets03Bind();
    const handle = bound.handle;
    expect({ check: "SECRETS-03 bind handle correlates with register",
      ok: /^sc[0-9]+$/.test(handle) && bound.secret_id === registered.secret_id }).toEqual({
      check: "SECRETS-03 bind handle correlates with register", ok: true });
    await secrets03Gate(bound.receipt_ref);
    const secrets03Input = (marker: string): FacadeInput<"self.use"> => ({ handle, operation: "connector.call",
      arguments: { name: "secrets_probe", tool: "check", arguments: { marker } } });
    const secrets03Withdraw = async () => {
      const answer = await secrets03OwnerRequest<secrets03Bound>("POST", "/v1/owner/secrets/unbind", {
        handle, effector: "connector:secrets_probe",
      });
      await secrets03Gate(answer.receipt_ref);
      expect({ check: "SECRETS-03 unbind removes the connector effector",
        ok: !answer.bindings.some(row => row.effector === "connector:secrets_probe") }).toEqual({
        check: "SECRETS-03 unbind removes the connector effector", ok: true });
    };
    await secrets03Withdraw();
    const beforeNoBinding = providers.seenFixtureCalls.length;
    await secrets03Refuse(agent.client, "self.use", secrets03Input("no-custody-binding"), 403, "FORBIDDEN");
    expect({ check: "SECRETS-03 refused use sends nothing", sent: providers.seenFixtureCalls.length, before: beforeNoBinding,
      ok: providers.seenFixtureCalls.length === beforeNoBinding }).toEqual({ check: "SECRETS-03 refused use sends nothing",
      sent: beforeNoBinding, before: beforeNoBinding, ok: true });
    await secrets03Gate((await secrets03Bind()).receipt_ref);

    const secrets03Held = async (client: PublicHttpClient, marker: string) => {
      const before = providers.seenFixtureCalls.length;
      const answer = await secrets03Facade(client, "self.use", secrets03Input(marker));
      const result = secrets03Object(answer.result, "REST held self.use result");
      expect({ check: "SECRETS-03 unconsented use is held", status: secrets03SafeText(answer.status), outcome: secrets03SafeText(result.outcome),
        ok: answer.status === "failed" && result.outcome === "held" && Array.isArray(result.reasons)
          && result.reasons.includes("standing_grant_required") }).toEqual({ check: "SECRETS-03 unconsented use is held",
        status: "failed", outcome: "held", ok: true });
      await secrets03Gate(answer.receipt.decision);
      expect({ check: "SECRETS-03 held use sends nothing and presents nothing", sent: providers.seenFixtureCalls.length,
        presented: answer.receipt.presented_generation,
        ok: providers.seenFixtureCalls.length === before && answer.receipt.presented_generation == null }).toEqual({
        check: "SECRETS-03 held use sends nothing and presents nothing", sent: before,
        presented: answer.receipt.presented_generation, ok: true });
    };
    await secrets03Held(noConnectorGrant.client, "no-connector-grant"); // Never consent this held actor later.
    await secrets03Refuse(agent.client, "vault.secrets.rotate", {
      name: "secrets03-custody", value_base64: Buffer.from(value1).toString("base64"),
    }, 403, "FORBIDDEN", true);
    const wrongActorReceipt = await secrets03Refuse(agent.client, "vault.secrets.revoke", {
      name: "secrets03-custody",
    }, 403, "FORBIDDEN");
    if (!wrongActorReceipt) throw new Error("SECRETS-03 value-free refusal has no call receipt");

    const secrets03UseResult = async (value: unknown, generation: number, surface: "REST" | "MCP") => {
      const answer = secrets03Object(value, `${surface} self.use answer`);
      // MCP completion describes the carrier, not the operation's delivery.
      const secrets03FailedResult = answer.result !== null && typeof answer.result === "object" && !Array.isArray(answer.result)
        ? answer.result as Record<string, unknown> : {};
      // This DTO has failure, not a typed code/reason/stage; report absent fields
      // explicitly, plus the connector outcome and reason codes, never its body.
      const secrets03FailureFields = answer.status === "answered" ? {} : {
        code: secrets03SafeText(answer.code), reason: secrets03SafeText(answer.reason), stage: secrets03SafeText(answer.stage),
        failure: secrets03SafeText(answer.failure), "result.outcome": secrets03SafeText(secrets03FailedResult.outcome),
        "result.reasons": Array.isArray(secrets03FailedResult.reasons)
          ? secrets03FailedResult.reasons.map((reason: unknown) => secrets03SafeText(reason))
          : secrets03JsonType(secrets03FailedResult.reasons),
      };
      expect({ check: `SECRETS-03 ${surface} self.use answers the operation`, ...secrets03FailureFields,
        status: secrets03SafeText(answer.status), ok: answer.status === "answered" }).toEqual({
        check: `SECRETS-03 ${surface} self.use answers the operation`, ...secrets03FailureFields, status: "answered", ok: true });
      const result = secrets03Object(answer.result, `${surface} self.use answer.result`);
      expect({ check: `SECRETS-03 ${surface} self.use delivers the connector reply`,
        outcome: secrets03SafeText(result.outcome), ok: result.outcome === "delivered" }).toEqual({
        check: `SECRETS-03 ${surface} self.use delivers the connector reply`, outcome: "delivered", ok: true });
      const toolResult = secrets03Object(result.result, `${surface} self.use answer.result.result`);
      expect({ check: "SECRETS-03 use delivers foreign tool result with sentinel", status: secrets03SafeText(answer.status), outcome: secrets03SafeText(result.outcome),
        ok: answer.status === "answered" && result.outcome === "delivered" && toolResult.foreign === true
          && toolResult.is_error === false && (JSON.stringify(toolResult) ?? "").includes(sentinel) }).toEqual({
        check: "SECRETS-03 use delivers foreign tool result with sentinel", status: "answered", outcome: "delivered", ok: true });
      const receipt = secrets03Object(answer.receipt, `${surface} self.use receipt`);
      expect({ check: "SECRETS-03 use receipt names handle generation effector",
        generation: typeof receipt.generation === "number" ? receipt.generation : secrets03JsonType(receipt.generation),
        presented: typeof receipt.presented_generation === "number" ? receipt.presented_generation : secrets03JsonType(receipt.presented_generation),
        ok: receipt.handle === handle && receipt.generation === generation
          && receipt.presented_generation === generation && receipt.effector === "connector:secrets_probe"
          && receipt.operation === "connector.call" }).toEqual({
        check: "SECRETS-03 use receipt names handle generation effector", generation, presented: generation, ok: true });
      if (typeof receipt.decision !== "string") throw new Error(`SECRETS-03 ${surface} self.use receipt.decision expected string; received ${secrets03JsonType(receipt.decision)}`);
      await secrets03Gate(receipt.decision);
    };
    for (const step of secrets03Exchange("generation-0", false, "generation-0", {
      content: [{ type: "text", text: `${sentinel}:${value0}` }],
      structuredContent: { reflected: value0, [value0]: "reflected-key" }, isError: false,
    })) providers.enqueue(step);
    const generation0 = await secrets03Facade(agent.client, "self.use", secrets03Input("generation-0"));
    await secrets03UseResult(generation0, 0, "REST");
    expect({ check: "SECRETS-03 delivered result carries the handle placeholder",
      ok: (JSON.stringify(generation0.result) ?? "").includes(`[secret ${handle}]`) }).toEqual({
      check: "SECRETS-03 delivered result carries the handle placeholder", ok: true });
    await secrets03Refuse(agent.client, "reveal", { handle, why: "Check T0 custody disclosure permission" }, 400, "BAD_REQUEST");
    const card = await secrets03Facade(agent.client, "reveal.describe", { handle });
    expect({ check: "SECRETS-03 T0 handle describes as reveal-refused", reveal: secrets03SafeText(card.reveal),
      ok: card.handle === handle && card.reveal === "refused" && typeof card.refusal === "string" }).toEqual({
      check: "SECRETS-03 T0 handle describes as reveal-refused", reveal: "refused", ok: true });

    const rotation = await secrets03Facade(owner, "vault.secrets.rotate", {
      name: "secrets03-custody", value_base64: Buffer.from(value1).toString("base64"),
    });
    expect({ check: "SECRETS-03 owner rotation advances one generation", from: rotation.from_generation, to: rotation.to_generation,
      kind: secrets03SafeText(rotation.kind), ok: rotation.from_generation === 0 && rotation.to_generation === fixture.expected.nextLeaseGeneration
        && rotation.kind === "rotated" }).toEqual({ check: "SECRETS-03 owner rotation advances one generation", from: 0,
      to: fixture.expected.nextLeaseGeneration, kind: "rotated", ok: true });
    await current.restart();
    await secrets03Gate(generation0.receipt.decision);
    const persistedRefusal = await secrets03Facade(agent.client, "vault.receipts.get", { receipt_ref: wrongActorReceipt });
    if (!persistedRefusal) throw new Error("SECRETS-03 wrong-actor refusal did not survive restart");
    const secrets03PersistedRefused: unknown = typeof persistedRefusal.outcome === "object" && persistedRefusal.outcome !== null
      && "refused" in persistedRefusal.outcome ? persistedRefusal.outcome.refused : "no-refusal";
    const secrets03PersistedCode: unknown = typeof secrets03PersistedRefused === "object" && secrets03PersistedRefused !== null
      && "code" in secrets03PersistedRefused ? secrets03PersistedRefused.code : secrets03PersistedRefused;
    expect({ check: "SECRETS-03 wrong-actor refusal survives restart", verb: secrets03SafeText(persistedRefusal.verb), code: secrets03SafeText(secrets03PersistedCode),
      ok: persistedRefusal.receipt_ref === wrongActorReceipt && persistedRefusal.actor_ref === agent.principalRef
        && persistedRefusal.verb === "vault.secrets.revoke" && typeof persistedRefusal.outcome === "object"
        && persistedRefusal.outcome.refused.code === "FORBIDDEN" }).toEqual({
      check: "SECRETS-03 wrong-actor refusal survives restart", verb: "vault.secrets.revoke", code: "FORBIDDEN", ok: true });
    const restartedCard = await secrets03Facade(agent.client, "reveal.describe", { handle });
    expect({ check: "SECRETS-03 restarted handle stays active and reveal-refused", status: secrets03SafeText(restartedCard.status),
      reveal: secrets03SafeText(restartedCard.reveal), ok: restartedCard.handle === handle && restartedCard.status === "active"
        && restartedCard.reveal === "refused" }).toEqual({ check: "SECRETS-03 restarted handle stays active and reveal-refused",
      status: "active", reveal: "refused", ok: true });
    const secrets03CeilingAfter = await secrets03Facade(owner, "vault.gate.policy.get", { manifest_ref: secrets03CeilingCurrent.manifest_ref });
    const secrets03CeilingSaved = secrets03CeilingAfter.manifests.find(row => row.manifest_ref === secrets03CeilingCurrent.manifest_ref);
    expect({ check: "SECRETS-03 agent MCP ceiling reads back trusted", ok: secrets03CeilingSaved?.trusted }).toEqual({
      check: "SECRETS-03 agent MCP ceiling reads back trusted", ok: true });
    expect(secrets03CeilingSaved?.manifest.actor_ceilings).toContainEqual(secrets03CeilingRow);
    secrets03ScanBytes(await secrets03McpCall("initialize", () => agent.mcp.initialize(), secrets03ScanBytes));
    const tools = await secrets03McpCall("tools/list", () => agent.mcp.listTools(), secrets03ScanBytes) as secrets03Tools;
    secrets03ScanBytes(tools);
    const useTool = tools.tools.find(row => row.name === "self.use");
    if (!useTool) throw new Error("SECRETS-03 tool-first self.use is absent");
    // The trusted sink deliberately reflects both forms; neither is allowed
    // back into ordinary HTTP/MCP output or the durable raw connector reply.
    for (const step of secrets03Exchange("generation-1", false, "generation-1", {
      content: [{ type: "text", text: `${sentinel}:${value1}:${Buffer.from(value1).toString("base64")}` }],
      structuredContent: { reflected: value1, encoded: Buffer.from(value1).toString("base64") }, isError: false,
    })) providers.enqueue(step);
    const mcpReply = await secrets03McpCall("self.use", () => agent.mcp.callTool("self.use", {
      schema_version: useTool.inputSchema.properties.schema_version.const,
      consent: { policy_ref: "policy:secrets03-custody", purpose: "Use a T0 custody credential without disclosure" },
      arguments: { spec: secrets03Input("generation-1") },
    }), secrets03ScanBytes);
    secrets03ScanBytes(mcpReply);
    const secrets03McpReply = secrets03Object(mcpReply, "MCP self.use reply");
    const secrets03McpStructured = secrets03Object(secrets03McpReply.structuredContent, "MCP self.use structuredContent");
    const secrets03McpMeta = secrets03Object(secrets03McpStructured.meta, "MCP self.use structuredContent.meta");
    expect({ check: "SECRETS-03 MCP use completes without error", end: secrets03SafeText(secrets03McpMeta.end),
      ok: secrets03McpReply.isError === false && secrets03McpMeta.end === "Complete" }).toEqual({
      check: "SECRETS-03 MCP use completes without error", end: "Complete", ok: true });
    await secrets03UseResult(secrets03McpStructured.output, fixture.expected.nextLeaseGeneration, "MCP");
    expect({ check: "SECRETS-03 MCP delivered result carries the handle placeholder",
      ok: (JSON.stringify(secrets03McpStructured.output) ?? "").includes(`[secret ${handle}]`) }).toEqual({
      check: "SECRETS-03 MCP delivered result carries the handle placeholder", ok: true });

    const calls = providers.seenFixtureCalls;
    expect({ check: "SECRETS-03 sink sees twelve scripted POSTs", calls: calls.length, ok: calls.length === 12 }).toEqual({
      check: "SECRETS-03 sink sees twelve scripted POSTs", calls: 12, ok: true }); // Two discoveries and two uses, three POSTs each.
    for (const call of calls) {
      secrets03ScanBytes(call.body);
      secrets03ScanBytes({ method: call.method, path: call.path });
      const expected = call.fixtureId?.startsWith("generation-0-") ? value0
        : call.fixtureId?.startsWith("generation-1-") ? value1 : null;
      // Authorization is the one authorized disclosure to the trusted sink.
      expect({ check: "SECRETS-03 sink authorization matches its generation", fixture: call.fixtureId,
        ok: expected === null ? call.headers?.authorization == null
          : call.headers?.authorization === `Bearer ${expected}` }).toEqual({
        check: "SECRETS-03 sink authorization matches its generation", fixture: call.fixtureId, ok: true });
      for (const [name, value] of Object.entries(call.headers ?? {})) if (name !== "authorization") secrets03ScanBytes(value);
    }
    const beforeWithdrawal = providers.seenFixtureCalls.length;
    await secrets03Withdraw();
    await secrets03Refuse(agent.client, "self.use", secrets03Input("after-custody-withdrawal"), 403, "FORBIDDEN");
    expect({ check: "SECRETS-03 custody withdrawal sends nothing", sent: providers.seenFixtureCalls.length,
      ok: providers.seenFixtureCalls.length === beforeWithdrawal }).toEqual({
      check: "SECRETS-03 custody withdrawal sends nothing", sent: beforeWithdrawal, ok: true });
    await secrets03Gate((await secrets03Bind()).receipt_ref);
    const revoked = await secrets03Facade(owner, "vault.consent.revoke", { grant: boundGrant.grant_ref });
    if (revoked.decision_ref) await secrets03Gate(`gate:${revoked.decision_ref}`);
    await secrets03Facade(owner, "vault.consent.registry", { limit: 1000, include_revoked: true });
    await secrets03Held(agent.client, "after-connector-withdrawal");
    expect({ check: "SECRETS-03 connector withdrawal sends nothing", sent: providers.seenFixtureCalls.length,
      ok: providers.seenFixtureCalls.length === beforeWithdrawal }).toEqual({
      check: "SECRETS-03 connector withdrawal sends nothing", sent: beforeWithdrawal, ok: true });
    await secrets03Facade(agent.client, "vault.recall", { query: "secrets03-custody", effort: "light", limit: 5 });
    await secrets03Facade(owner, "vault.receipts", { limit: 1000 });
    const exported = await secrets03Facade(owner, "vault.export", { format: "archive", include_secrets: false, delivery: "inline" });
    if (!("archive" in exported)) throw new Error("SECRETS-03 inline export returned a transfer");
    secrets03ScanBytes(Buffer.from(exported.archive, "base64"));
    const members = publicZip(exported.archive);
    for (const [name, bytes] of members) { secrets03ScanBytes(name); secrets03ScanBytes(bytes); }
    expect({ check: "SECRETS-03 observed bytes exclude both custody values", ok: valueFree }).toEqual({
      check: "SECRETS-03 observed bytes exclude both custody values", ok: true }); // Promise oracle; source predicts encoded-reflection red.
  } catch (error) {
    if (error instanceof PublicHttpError) secrets03ObserveWire(error.reply, secrets03ScanBytes);
    else if (error instanceof McpRpcError) secrets03ScanBytes(error.response);
    else if (error instanceof CliError) { secrets03ScanBytes(error.result.stdout); secrets03ScanBytes(error.result.stderr); }
    secrets03BodyError = redactor.text(error instanceof Error ? `${error.name}: ${error.message}` : "unknown failure");
    throw error;
  } finally {
    try { await providers.close(); }
    catch (cleanupError) {
      // A provider-script error (unconsumed steps) must not replace the body failure it follows.
      if (secrets03BodyError !== null) throw new Error(redactor.text(`SECRETS-03 body failed: ${secrets03BodyError}; `
        + `provider cleanup failed: ${cleanupError instanceof Error ? cleanupError.message : "non-Error failure"}`));
      throw cleanupError;
    }
    finally {
      if (engine) {
        await engine.close();
        for (const [index, value] of values.entries()) {
          const base64 = Buffer.from(value).toString("base64");
          const secrets03LogScan = engine.serverOutputHas([value, base64]);
          try {
            expect({ check: `SECRETS-03 server output excludes custody value ${index}`, found: secrets03LogScan.found,
              ok: secrets03LogScan.found === false }).toEqual({
              check: `SECRETS-03 server output excludes custody value ${index}`, found: false, ok: true });
            expect({ check: `SECRETS-03 server output window complete for custody value ${index}`,
              truncated: secrets03LogScan.truncated, ok: secrets03LogScan.truncated === false }).toEqual({
              check: `SECRETS-03 server output window complete for custody value ${index}`, truncated: false, ok: true });
          } catch {
            throw new Error(`SECRETS-03 server log scan failed for custody value ${index} `
              + `(found=${secrets03LogScan.found} truncated=${secrets03LogScan.truncated}); body error was: ${secrets03BodyError ?? "none"}`);
          }
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
 * those positive controls (owner roster, owner person, owner review, owner
 * settle, consented reveal) assert the exact value and scan the bytes for
 * presence, not absence; every other reply is asserted name-free.
 * The agent opens the sensitivity-marked claim (held Proposed); the owner
 * reviews and settles it live before any disclosure step runs.
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
    // Debug for every workspace crate (EnvFilter matches targets by prefix, so "oneiron" covers oneiron_*); dependencies at
    // info keep each server stream inside the harness 4 MiB scan window (job 4: RUST_LOG=debug truncated it, absence unproved).
    const engine = await EngineFixture.start({ id: "SECRETS-06", profile, serverLog: "info,oneiron=debug" });
    let secrets06BodyFailure: unknown = null;
    try {
      // Preserve exact wire bytes and generated input/result types, even on reads.
      const secrets06ErrorCode = (body: unknown): string => {
        const code = (body as { error?: { code?: unknown } } | null)?.error?.code;
        return typeof code === "string" ? code : "no-error-code";
      };
      // Stable refusal tokens first (gate.* codes, never content); the redacted
      // message follows because a gate rejection carries its reasons only there:
      // the facade drops the typed gate_denial on the wire. The job-4 403 that
      // named only FORBIDDEN hid which gate rule refused the owner settle.
      const secrets06RefusalDetail = (body: unknown): string => {
        const codes: string[] = [];
        const collect = (value: unknown): void => {
          if (Array.isArray(value)) {
            for (const item of value) {
              if (typeof item === "string") codes.push(item);
            }
          }
        };
        const error = (body as { error?: { message?: unknown; reasonCodes?: unknown; gateDenial?: { outcome?: unknown; reasonCodes?: unknown } } } | null)?.error;
        collect(error?.reasonCodes);
        collect(error?.gateDenial?.reasonCodes);
        const outcome = error?.gateDenial?.outcome;
        const message = error?.message;
        const rendered = codes.length > 0 ? codes.map(code => redactor.text(code)).join(",") : "none";
        const outcomeText = typeof outcome === "string" ? ` outcome=${redactor.text(outcome)}` : "";
        const messageText = typeof message === "string" ? ` msg=${redactor.text(message)}` : "";
        return `reasons=${rendered}${outcomeText}${messageText}`;
      };
      const secrets06Call = async <V extends FacadeVerb>(
        client: PublicHttpClient, verb: V, input: FacadeInput<V>,
      ): Promise<FacadeResult<V>> => {
        const reply = await client.raw<FacadeResult<V>>("POST", `/v1/core/facade/${verb}`, input);
        secrets06Scan(verb, reply.bytes);
        secrets06ScanJson(`${verb}:headers`, Object.fromEntries(reply.headers));
        if (reply.status !== 200) {
          throw new Error(`SECRETS-06 facade ${verb} HTTP ${reply.status}: ${redactor.text(secrets06ErrorCode(reply.body))} ${secrets06RefusalDetail(reply.body)}`);
        }
        return reply.body;
      };
      const secrets06HttpOk = (label: string, reply: { status: number; body: unknown; bytes: Uint8Array; headers: Headers }): void => {
        if (reply.status === 200) return;
        secrets06Scan(`${label}:error`, reply.bytes);
        secrets06ScanJson(`${label}:error:headers`, Object.fromEntries(reply.headers));
        throw new Error(`SECRETS-06 ${label} HTTP ${reply.status}: ${redactor.text(secrets06ErrorCode(reply.body))} ${secrets06RefusalDetail(reply.body)}`);
      };
      const secrets06Mcp = async (method: "tools/list" | "tools/call", params: unknown = {}, tool = "") => {
        const label = tool === "" ? `MCP ${method}` : `MCP ${method} ${tool}`;
        try {
          return await agent.mcp.rpc(method, params);
        } catch (error) {
          const reply = (error as { reply?: { status?: unknown; body?: unknown; bytes?: Uint8Array; headers?: Headers } } | null)?.reply;
          if (reply == null) throw error;
          if (reply.bytes !== undefined) secrets06Scan(`${label}:error`, reply.bytes);
          if (reply.body !== undefined) secrets06ScanJson(`${label}:error:body`, reply.body);
          if (reply.headers !== undefined) secrets06ScanJson(`${label}:error:headers`, Object.fromEntries(reply.headers));
          throw new Error(`SECRETS-06 ${label} HTTP ${String(reply.status ?? "unknown")}: ${reply.body === undefined ? "no-reply-body" : redactor.text(secrets06ErrorCode(reply.body))} ${secrets06RefusalDetail(reply.body)}`);
        }
      };
      const secrets06Receipt = async (ref: string): Promise<NonNullable<FacadeResult<"vault.receipts.get">>> => {
        expect({ check: "refusal receipt is a call ref", ok: /^call:[a-f0-9]{32}$/.test(ref) }).toEqual({ check: "refusal receipt is a call ref", ok: true });
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
        expect({ check: "governance receipt is a gate ref", ok: /^gate:[a-f0-9]{32}$/.test(ref) }).toEqual({ check: "governance receipt is a gate ref", ok: true });
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
        expect({ check: `refusal ${verb} uses HTTP ${status}`, status: reply.status }).toEqual({ check: `refusal ${verb} uses HTTP ${status}`, status });
        expect({ check: `refusal ${verb} carries ${status === 403 ? "FORBIDDEN" : "UNAUTHORIZED"}`, code: redactor.text(secrets06ErrorCode(reply.body)) }).toEqual({ check: `refusal ${verb} carries ${status === 403 ? "FORBIDDEN" : "UNAUTHORIZED"}`, code: status === 403 ? "FORBIDDEN" : "UNAUTHORIZED" });
        expect({ check: `refusal ${verb} carries a message`, ok: typeof reply.body.error.message === "string" && reply.body.error.message.length > 0 }).toEqual({ check: `refusal ${verb} carries a message`, ok: true });
        expect({ check: `refusal ${verb} carries a request id`, ok: typeof reply.body.error.requestId === "string" && reply.body.error.requestId.length > 0 }).toEqual({ check: `refusal ${verb} carries a request id`, ok: true });
        expect({ check: `refusal ${verb} carries suggestions`, ok: Array.isArray(reply.body.error.suggestions) }).toEqual({ check: `refusal ${verb} carries suggestions`, ok: true });
        const ref = reply.headers.get("x-oneiron-receipt-ref");
        if (ref === null) throw new Error("SECRETS-06 refusal has no receipt header");
        const row = await secrets06Receipt(ref); // Owner can also read an unauthenticated connection's receipt.
        if (status === 401) {
          expect(row).toMatchObject({ transport: "http_facade", actor_class: "connection",
            verb, outcome: { refused: { code: "HTTP_401" } } });
        } else {
          expect(reply.body.error.receiptRef).toBe(ref);
          expect(row).toMatchObject({ transport: "http_facade", actor_ref: actorRef,
            actor_class: "agent", verb, outcome: { refused: { code: "FORBIDDEN" } } });
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
      const agent = await engine.pairActor({ principalRef: principal.id_hex, actorClass: "agent",
        scope: ["core:read", "core:write", "export"] });
      // A sensitivity-marked write lands held, never auto: the agent opens the
      // names claim and the owner reviews and settles it live. An owner-opened
      // proposal is unsettleable, so the owner cannot open this claim itself.
      const claim = await secrets06Call(agent.client, "vault.claims.upsert", {
        predicate: "fixture.person.name", subject_ref: person.id_hex, value: privateName,
        confidence: 1, source: "user_stated", sensitivity: 1, scope, occurred_at: occurredAt,
      });
      expect(claim.approval).toBe("proposed");
      const claimId = claim.claim?.id;
      if (!claimId) throw new Error("SECRETS-06 claim write returned no typed record id");
      if (claim.receipt_ref.startsWith("gate:")) await secrets06GateReceipt(claim.receipt_ref);
      else expect(claim.receipt_ref).toBe(`claim:${claimId}`); // Public documented marker, not a second receipt.
      const reviewReply = await engine.client.raw<FacadeResult<"vault.claims.review">>(
        "POST", "/v1/core/facade/vault.claims.review", { claim_ref: claimId } satisfies FacadeInput<"vault.claims.review">,
      );
      secrets06HttpOk("owner-review vault.claims.review", reviewReply);
      const review = reviewReply.body;
      expect({ check: "owner review reads the authorized claim value", ok: review.claim.value === privateName }).toEqual({ check: "owner review reads the authorized claim value", ok: true });
      expect({ check: "owner review bytes carry the claim value", ok: secrets06Contains(reviewReply.bytes, [privateName]) }).toEqual({ check: "owner review bytes carry the claim value", ok: true });
      expect({ check: "owner review labels the authorized claim value", ok: review.claim.claim?.label === privateName }).toEqual({ check: "owner review labels the authorized claim value", ok: true });
      secrets06ScanJson("owner-review:headers", Object.fromEntries(reviewReply.headers));
      secrets06ScanJson("owner-review:metadata", { ...review, claim: { ...review.claim,
        value: "AUTHORIZED-VALUE",
        claim: review.claim.claim == null ? review.claim.claim : { ...review.claim.claim, label: "AUTHORIZED-VALUE" } } });
      expect(review.claim.approval).toBe("proposed");
      const settleReply = await engine.client.raw<FacadeResult<"vault.claims.settle">>(
        "POST", "/v1/core/facade/vault.claims.settle", { claim_ref: claimId, review_id: review.review_id, decision: "approve" } satisfies FacadeInput<"vault.claims.settle">,
      );
      secrets06HttpOk("owner-settle vault.claims.settle", settleReply);
      const settled = settleReply.body;
      expect({ check: "owner settle lands the authorized claim value", ok: settled.claim.value === privateName }).toEqual({ check: "owner settle lands the authorized claim value", ok: true });
      expect({ check: "owner settle bytes carry the claim value", ok: secrets06Contains(settleReply.bytes, [privateName]) }).toEqual({ check: "owner settle bytes carry the claim value", ok: true });
      expect({ check: "owner settle labels the authorized claim value", ok: settled.claim.claim?.label === privateName }).toEqual({ check: "owner settle labels the authorized claim value", ok: true });
      secrets06ScanJson("owner-settle:headers", Object.fromEntries(settleReply.headers));
      secrets06ScanJson("owner-settle:metadata", { ...settled, claim: { ...settled.claim,
        value: "AUTHORIZED-VALUE",
        claim: settled.claim.claim == null ? settled.claim.claim : { ...settled.claim.claim, label: "AUTHORIZED-VALUE" } } });
      expect(settled.review_id).toBe(review.review_id);
      expect(settled.proposal_ref).toBe(review.proposal_ref);
      expect(settled.verdict).toBe("landed");
      expect(settled.claim.approval).toBe("approved");
      await secrets06GateReceipt(settled.receipt_ref);
      // Before the second pairing, exactly one slip belongs to this new principal.
      const audit = await secrets06Call(engine.client, "vault.authority.audit", { limit: 500 });
      expect({ check: "authority audit fits one page", ok: audit.next_after == null }).toEqual({ check: "authority audit fits one page", ok: true });
      const minted = audit.rows.filter(row => row.source_op === "slip_mint" && row.holder_ref === agent.principalRef);
      expect(minted.length).toBe(1);
      const mintedRow = minted[0];
      if (!mintedRow?.subject_ref) throw new Error("SECRETS-06 public authority audit has no paired slip id");
      expect({ check: "paired slip row is fold-valid", ok: mintedRow.fold_valid }).toEqual({ check: "paired slip row is fold-valid", ok: true });
      const slipId = mintedRow.subject_ref;
      expect({ check: "paired slip id is 32 bytes hex", ok: /^[a-f0-9]{64}$/.test(slipId) }).toEqual({ check: "paired slip id is 32 bytes hex", ok: true });
      const noRead = await engine.pairActor({ principalRef: principal.id_hex, actorClass: "agent",
        scope: ["core:write", "export"] });
      const connection = `agent:${agent.principalRef}`;
      const dial = { connection, class: data.person.class };

      // Authorized owner assembly is the positive control, not an absence claim.
      const ownerPage = await engine.client.raw<FacadeResult<"vault.people.list">>(
        "POST", "/v1/core/facade/vault.people.list", { page: 0 } satisfies FacadeInput<"vault.people.list">,
      );
      secrets06HttpOk("owner-roster vault.people.list", ownerPage);
      secrets06ScanJson("owner-roster:headers", Object.fromEntries(ownerPage.headers));
      const ownerRow = ownerPage.body.people.find(row => row.person === person.id_hex);
      if (!ownerRow) throw new Error("SECRETS-06 owner roster has no created person");
      expect({ check: "owner roster returns the created name", ok: ownerRow.name === privateName }).toEqual({ check: "owner roster returns the created name", ok: true });
      expect({ check: "owner roster bytes carry the name", ok: secrets06Contains(ownerPage.bytes, [privateName]) }).toEqual({ check: "owner roster bytes carry the name", ok: true });
      const handle = ownerRow.handle;
      expect({ check: "person handle is a bare pr handle", ok: /^pr[0-9]+$/.test(handle) }).toEqual({ check: "person handle is a bare pr handle", ok: true });
      expect({ check: "owner roster returns the reader principal", ok: ownerPage.body.people.some(row => row.person === principal.id_hex) }).toEqual({ check: "owner roster returns the reader principal", ok: true });
      secrets06ScanJson("owner-roster:metadata", { ...ownerPage.body, people: ownerPage.body.people.map(row =>
        row.person === person.id_hex ? { ...row, name: handle } : row) });
      const secrets06MaskedPerson = async (): Promise<void> => {
        const row = await secrets06Call(agent.client, "vault.people.get", { pr: handle });
        expect(row.person).toBe(person.id_hex);
        expect({ check: "agent people.get masks the name to its handle", ok: row.handle === handle && row.name === handle && row.about == null }).toEqual({ check: "agent people.get masks the name to its handle", ok: true });
      };
      const secrets06MaskedPage = async (): Promise<void> => {
        const page = await secrets06Call(agent.client, "vault.people.list", { page: 0 });
        const row = page.people.find(item => item.person === person.id_hex);
        expect({ check: "agent people.list masks the name to its handle", ok: row?.handle === handle && row.name === handle && row.about == null }).toEqual({ check: "agent people.list masks the name to its handle", ok: true });
      };
      const secrets06OwnerPerson = async (): Promise<void> => {
        const reply = await engine.client.raw<FacadeResult<"vault.people.get">>(
          "POST", "/v1/core/facade/vault.people.get", { pr: handle } satisfies FacadeInput<"vault.people.get">,
        );
        secrets06HttpOk("owner-person vault.people.get", reply);
        expect({ check: "owner people.get returns the real name", ok: reply.body.person === person.id_hex && reply.body.handle === handle && reply.body.name === privateName }).toEqual({ check: "owner people.get returns the real name", ok: true });
        expect({ check: "owner person bytes carry the name", ok: secrets06Contains(reply.bytes, [privateName]) }).toEqual({ check: "owner person bytes carry the name", ok: true });
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
      expect({ check: "describe carries no grant or refusal before consent", ok: card.grant_ref == null && card.refusal == null && card.provenance?.learned_at != null }).toEqual({ check: "describe carries no grant or refusal before consent", ok: true });

      // Clearing applies on the next read, without a cache delay or a new grant.
      await secrets06Call(engine.client, "vault.disclosure.ceiling.clear", { connection });
      const clearedDial = await secrets06Call(engine.client, "vault.disclosure.ceiling.get", { connection });
      expect({ check: "cleared connection dial reads no stored ceiling", ok: clearedDial.ceiling == null }).toEqual({ check: "cleared connection dial reads no stored ceiling", ok: true });
      await secrets06ReadDial("public");
      await secrets06MaskedPerson();
      await secrets06Call(engine.client, "vault.disclosure.ceiling.clear", dial);
      await secrets06ReadDial(null);
      await secrets06MaskedPerson(); // The inferred agent ceiling is also public.
      await secrets06Call(engine.client, "vault.disclosure.ceiling.set", { ...dial, ceiling: "public" });
      await secrets06ReadDial("public");

      const why = "fixture identity lookup";
      const pending = await secrets06Call(agent.client, "reveal", { handle, why });
      expect({ check: "reveal act returns a bare reveal id", ok: /^[a-f0-9]{32}$/.test(pending.reveal) }).toEqual({ check: "reveal act returns a bare reveal id", ok: true });
      const secrets06NoValue = (answer: FacadeResult<"reveal.wait">, decision: "pending" | "denied" | "granted"): void => {
        expect(answer.decision).toBe(decision);
        expect({ check: `reveal wait ${decision} releases no value`, ok: answer.value == null && answer.value_base64 == null }).toEqual({ check: `reveal wait ${decision} releases no value`, ok: true });
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
      secrets06HttpOk("consented-reveal reveal.wait", delivered);
      expect(delivered.body.decision).toBe("granted");
      expect({ check: "consented wait delivers exactly the private name", ok: delivered.body.value === privateName && delivered.body.value_base64 == null }).toEqual({ check: "consented wait delivers exactly the private name", ok: true });
      expect({ check: "consented wait bytes carry the name", ok: secrets06Contains(delivered.bytes, [privateName]) }).toEqual({ check: "consented wait bytes carry the name", ok: true });
      secrets06ScanJson("consented-reveal:headers", Object.fromEntries(delivered.headers));
      secrets06ScanJson("consented-reveal:metadata", { ...delivered.body, value: handle });
      expect(delivered.body.receipt).toMatchObject({ handle, class: "names", why, connection,
        answered_by: `owner:${engine.pairedActor.principalRef}` });
      const deliveryDecision = delivered.body.receipt?.decision;
      expect({ check: "delivery receipt carries a lease and stamp", ok: delivered.body.receipt?.lease != null && delivered.body.receipt.delivered_at != null }).toEqual({ check: "delivery receipt carries a lease and stamp", ok: true });
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
      expect({ check: "scoped export includes the fixture claim", ok: exported.records.some(row => row.record.id === claimId) }).toEqual({ check: "scoped export includes the fixture claim", ok: true });
      for (const row of exported.records) secrets06Scan(`scoped-export:${row.record.id}`, Buffer.from(row.bytes));
      await secrets06Refuse(agent.client, "vault.export", { format: "archive", include_secrets: false, delivery: "inline" }, 403, agent.principalRef);
      const recalled = await awaitPublic(
        () => secrets06Call(agent.client, "vault.recall", { query: "Syntheticprivateperson", effort: "light", limit: 10 }),
        pack => pack.items.some(item => item.record?.id === claimId),
        { label: "SECRETS-06 private claim recalled as a handle" },
      );
      const recalledClaim = recalled.items.find(item => item.record?.id === claimId);
      expect({ check: "recalled claim renders as its handle", ok: recalledClaim?.value_text === handle }).toEqual({ check: "recalled claim renders as its handle", ok: true });
      const cli = await agent.cli.run(["api", "call", "vault.people.get", "--data", "-"],
        JSON.stringify({ pr: handle } satisfies FacadeInput<"vault.people.get">));
      secrets06Scan("cli:stdout", Buffer.from(cli.stdout, "utf8"));
      secrets06Scan("cli:stderr", Buffer.from(cli.stderr, "utf8"));
      expect(cli.exitCode).toBe(0);
      const cliRow = secrets06Object(JSON.parse(cli.stdout));
      expect({ check: "CLI people.get masks the name to its handle", ok: cliRow.person === person.id_hex && cliRow.name === handle && cliRow.handle === handle }).toEqual({ check: "CLI people.get masks the name to its handle", ok: true });
      const listing = await secrets06Mcp("tools/list");
      secrets06ScanJson("mcp:tools-list", listing);
      if ("error" in listing) throw new Error(`SECRETS-06 MCP tools/list refused ${listing.error.code}: ${redactor.text(listing.error.message)}`);
      const tools = secrets06Object(listing.result).tools;
      if (!Array.isArray(tools)) throw new Error("SECRETS-06 MCP listing has no tools");
      const peopleTool: unknown = tools.find((item: unknown) => secrets06Object(item).name === "vault.people.get");
      if (peopleTool === undefined) throw new Error("SECRETS-06 MCP people tool is absent");
      const properties = secrets06Object(secrets06Object(secrets06Object(peopleTool).inputSchema).properties);
      const schemaVersion = secrets06Object(properties.schema_version).const;
      if (typeof schemaVersion !== "string") throw new Error("SECRETS-06 MCP people tool has no schema version");
      const mcp = await secrets06Mcp("tools/call", { name: "vault.people.get", arguments: {
        schema_version: schemaVersion,
        consent: { policy_ref: "policy:secrets-06", purpose: "Read a private person through its channel ceiling" },
        arguments: { spec: { pr: handle } },
      } }, "vault.people.get");
      secrets06ScanJson("mcp:outer", mcp);
      if ("error" in mcp) throw new Error(`SECRETS-06 MCP tools/call vault.people.get refused ${mcp.error.code}: ${redactor.text(mcp.error.message)}`);
      const mcpResult = secrets06Object(mcp.result);
      expect({ check: "MCP people read reports no tool error", ok: mcpResult.isError }).toEqual({ check: "MCP people read reports no tool error", ok: false });
      const mcpRow = secrets06Object(secrets06Object(mcpResult.structuredContent).output);
      expect({ check: "MCP people read masks the name to its handle", ok: mcpRow.person === person.id_hex && mcpRow.name === handle && mcpRow.handle === handle }).toEqual({ check: "MCP people read masks the name to its handle", ok: true });
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
      secrets06HttpOk("slip-revoke", revoked);
      expect({ check: "owner slip revoke reports revoked", ok: revoked.body.revoked === true }).toEqual({ check: "owner slip revoke reports revoked", ok: true });
      await secrets06RefusedReads(agent.client, 401); // The next uses retain the original credential.
      // Read the owner-authorized state again after loss of the agent's grant.
      await secrets06ReadDial("public");
      await secrets06OwnerPerson();
      const history = await secrets06Call(engine.client, "vault.disclosure.reveals", { pending: false, limit: 50 });
      expect({ check: "reveal history keeps the denied ask", ok: history.some(row => row.receipt.reveal === pending.reveal && row.state === "denied") }).toEqual({ check: "reveal history keeps the denied ask", ok: true });
      await secrets06Call(engine.client, "vault.receipts", { limit: 1000 });
      // Defer expected-red leak checks so restart, revocations and all carriers run.
      expect([...leaks].sort()).toEqual([]);
    } catch (error) {
      secrets06BodyFailure = error;
    }
    // Teardown always runs, and the body failure is reported first, so a close
    // or log failure can no longer mask it. Both log checks stay strict even
    // when one of them fails. All interpolated error text is redactor-scrubbed.
    const secrets06Teardown: string[] = [];
    try {
      await engine.close();
    } catch (error) {
      secrets06Teardown.push(`close threw: ${redactor.text(error instanceof Error ? error.message : String(error))}`);
    }
    let secrets06ServerOutput: { found: boolean; truncated: boolean } | null = null;
    try {
      secrets06ServerOutput = engine.serverOutputHas([privateName, privateNameBase64]);
    } catch (error) {
      secrets06Teardown.push(`server-output scan threw: ${redactor.text(error instanceof Error ? error.message : String(error))}`);
    }
    if (secrets06ServerOutput !== null) {
      try {
        expect({ check: "server output carries no private-name bytes", found: secrets06ServerOutput.found }).toEqual({ check: "server output carries no private-name bytes", found: false });
      } catch (error) {
        secrets06Teardown.push(`log content check failed: ${redactor.text(error instanceof Error ? error.message : String(error))}`);
      }
      try {
        expect({ check: "server output was fully retained", truncated: secrets06ServerOutput.truncated }).toEqual({ check: "server output was fully retained", truncated: false });
      } catch (error) {
        secrets06Teardown.push(`log retention check failed: ${redactor.text(error instanceof Error ? error.message : String(error))}`);
      }
    }
    if (secrets06BodyFailure !== null || secrets06Teardown.length > 0) {
      const secrets06BodyText = secrets06BodyFailure === null ? null
        : redactor.text(secrets06BodyFailure instanceof Error ? secrets06BodyFailure.message : String(secrets06BodyFailure));
      throw new Error(`SECRETS-06 failed: ${[
        ...(secrets06BodyText === null ? [] : [`body: ${secrets06BodyText}`]),
        ...secrets06Teardown.map(part => `teardown: ${part}`),
      ].join(" | ")}`);
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
  expect({ check: "SECRETS-07 scanned bytes carry no candidate raw or base64", ok: values.every(text => !bytes.includes(Buffer.from(text))
    && !bytes.includes(Buffer.from(Buffer.from(text).toString("base64")))) }).toEqual({ check: "SECRETS-07 scanned bytes carry no candidate raw or base64", ok: true });
}

// Safe failure context for an unexpected HTTP status: the static route plus the
// envelope's string error code only. Bodies and headers were already scanned;
// values never enter this text.
function secrets07ErrorText(body: unknown): string {
  if (!body || typeof body !== "object") return "code=none";
  const error = (body as Record<string, unknown>).error;
  if (!error || typeof error !== "object") return "code=none";
  const code = (error as Record<string, unknown>).code;
  return typeof code === "string" ? `code=${redactor.text(code)}` : "code=none";
}

// One-line summary for the failure aggregator. The harness redacts registered
// values from the reported reason; this keeps the body failure first.
function secrets07Summarize(error: unknown): string {
  return error instanceof Error ? `${error.name}: ${error.message}` : String(error);
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
  // Failure attribution: a body failure must never be masked by provider or
  // engine cleanup. Completeness stays strict: the explicit close inside the
  // body still throws on unconsumed steps or violations.
  const secrets07BodyFailures: unknown[] = [];
  const secrets07CleanupFailures: unknown[] = [];
  try {
    const policyOrigin = providers.urls.policy;
    if (!policyOrigin) throw new Error("SECRETS-07 policy fixture has no origin");
    // Debug for every workspace crate (EnvFilter matches targets by prefix, so "oneiron" covers oneiron_*); dependencies at
    // info keep each server stream inside the harness 4 MiB scan window (job 4: RUST_LOG=debug truncated it, absence unproved).
    const engine = await EngineFixture.start({ id: "SECRETS-07", profile, serverLog: "info,oneiron=debug", serverConfig: `
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
        expect({ check: "SECRETS-07 reply states a call receipt", ok: typeof ref === "string" && ref.startsWith("call:") }).toEqual({ check: "SECRETS-07 reply states a call receipt", ok: true });
        if (!ref || !ref.startsWith("call:")) throw new Error("SECRETS-07 authenticated call has no receipt");
        return ref;
      };
      async function secrets07Call<V extends FacadeVerb>(client: PublicHttpClient, verb: V, input: FacadeInput<V>): Promise<FacadeResult<V>> {
        const reply = await client.raw<FacadeResult<V>>("POST", `/v1/core/facade/${verb}`, input,
          { "x-oneiron-invocation": secrets07Invocation() });
        secrets07Scan(reply.bytes, values);
        secrets07Scan([...reply.headers], values);
        if (reply.status !== 200) {
          throw new Error(`SECRETS-07 ${verb} expected HTTP 200 but answered HTTP ${reply.status} (${secrets07ErrorText(reply.body)})`);
        }
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
            expect({ check: "SECRETS-07 gate pagination advances", ok: cursors.has(page.next_after) }).toEqual({ check: "SECRETS-07 gate pagination advances", ok: false });
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
        const error = secrets07Object(secrets07Object(reply.body).error);
        expect({ check: `SECRETS-07 ${verb} refusal answers HTTP ${status} with ${code}`, status: reply.status, error: secrets07ErrorText(reply.body), ok: reply.status === status && error.code === code }).toEqual({ check: `SECRETS-07 ${verb} refusal answers HTTP ${status} with ${code}`, status, error: `code=${code}`, ok: true });
        expect({ check: "SECRETS-07 refusal carries a message", ok: typeof error.message === "string" && error.message.length > 0 }).toEqual({ check: "SECRETS-07 refusal carries a message", ok: true });
        expect({ check: "SECRETS-07 refusal carries suggestions", ok: Array.isArray(error.suggestions) }).toEqual({ check: "SECRETS-07 refusal carries suggestions", ok: true });
        expect({ check: "SECRETS-07 refusal carries a request id", ok: typeof error.requestId === "string" && error.requestId.length > 0 }).toEqual({ check: "SECRETS-07 refusal carries a request id", ok: true });
        expect(providers.seenFixtureCalls.length).toBe(count);
        const ref = secrets07Ref(reply.headers);
        const row = await secrets07ReadCall(ref);
        expect(row.verb).toBe(verb);
        expect(row.transport).toBe("http_facade");
        if (authenticated) {
          expect({ check: "SECRETS-07 refusal receipt matches its header", ok: error.receiptRef === ref }).toEqual({ check: "SECRETS-07 refusal receipt matches its header", ok: true });
          expect(row.actor_ref).toBe(actor.principalRef);
          expect(row.actor_class).toBe("agent");
          expect(row.outcome).toEqual({ refused: { code } });
        } else {
          expect(row.actor_class).toBe("connection");
          expect({ check: "SECRETS-07 connection receipt carries no credential", ok: row.credential_ref == null }).toEqual({ check: "SECRETS-07 connection receipt carries no credential", ok: true });
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
        if (reply.status !== 200) {
          throw new Error(`SECRETS-07 vault.policy.outbound.decide expected HTTP 200 but answered HTTP ${reply.status} (${secrets07ErrorText(reply.body)})`);
        }
        const result = reply.body;
        // Only the promised Allow/Warn final_content field may carry the candidate.
        if (action === "allow" || action === "warn") {
          const { final_content: finalContent, ...withoutFinalContent } = result;
          secrets07Scan(withoutFinalContent, values);
          expect({ check: "SECRETS-07 allow/warn returns exact candidate bytes", ok: typeof finalContent === "string"
            && Buffer.from(finalContent).equals(Buffer.from(content)) }).toEqual({ check: "SECRETS-07 allow/warn returns exact candidate bytes", ok: true });
        } else {
          secrets07Scan(reply.bytes, values);
          expect({ check: "SECRETS-07 block/help returns no content", ok: result.final_content == null }).toEqual({ check: "SECRETS-07 block/help returns no content", ok: true });
        }
        expect(result.action).toBe(action);
        expect(result.verdict.decision).toBe(action === "route_to_help" ? "route-to-help" : action);
        expect({ check: "SECRETS-07 owner model ran", ok: result.custom_tier_skipped }).toEqual({ check: "SECRETS-07 owner model ran", ok: false });
        const halts = action === "block" || action === "route_to_help";
        expect({ check: "SECRETS-07 outbound halt matches the action", ok: result.outbound_halted }).toEqual({ check: "SECRETS-07 outbound halt matches the action", ok: halts });
        expect({ check: "SECRETS-07 pre-display block matches the action", ok: result.pre_display_block }).toEqual({ check: "SECRETS-07 pre-display block matches the action", ok: halts });
        if (halts) expect(result.barge_in_kill).toEqual({ cancel_tts: true, flush_playout_buffer: true, cancel_llm: true });
        if (action !== "allow") {
          expect(result.notice_voice).toBe("system");
          expect(result.verdict.category).toEqual({ category: "owner_policy", sub: { row_ref: rowRef } });
          const noticeType = action === "warn" ? "policy_warn" : action === "block" ? "policy_block" : "policy_help_card";
          const notice = result.system_notices?.find(item => item.notice_type === noticeType);
          expect(notice?.voice).toBe("system");
          expect(notice?.policy_plane).toBe("owner_policy");
          expect(notice?.row_ref).toBe(rowRef);
          expect({ check: "SECRETS-07 notice carries a body", ok: typeof notice?.body === "string" && notice.body.length > 0 }).toEqual({ check: "SECRETS-07 notice carries a body", ok: true });
        }
        if (action === "route_to_help") {
          expect({ check: "SECRETS-07 help routing carries no diagnosis", ok: result.help_routing?.diagnosis === null }).toEqual({ check: "SECRETS-07 help routing carries no diagnosis", ok: true });
          expect({ check: "SECRETS-07 help routing keeps a persona", ok: result.help_routing?.persona_present }).toEqual({ check: "SECRETS-07 help routing keeps a persona", ok: true });
        }
        const ref = result.receipt_ref;
        expect({ check: "SECRETS-07 enforcement states a gate receipt", ok: typeof ref === "string" && ref.startsWith("gate:") }).toEqual({ check: "SECRETS-07 enforcement states a gate receipt", ok: true });
        if (!ref || !ref.startsWith("gate:")) throw new Error("SECRETS-07 enforcement has no gate receipt");
        expect({ check: "SECRETS-07 enforcement mints a fresh gate receipt", ok: gates.has(ref) }).toEqual({ check: "SECRETS-07 enforcement mints a fresh gate receipt", ok: false });
        const gate = await secrets07ReadGate(ref);
        expect(gate.kind).toBe("gate");
        expect(gate.outcome).toBe(action);
        expect({ check: "SECRETS-07 gate reason names the action", ok: gate.reason_codes.includes(`gate.policy_model.${action}`) }).toEqual({ check: "SECRETS-07 gate reason names the action", ok: true });
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
        expect({ check: "SECRETS-07 classifier call is JSON", ok: wire.headers?.["content-type"]?.startsWith("application/json") }).toEqual({ check: "SECRETS-07 classifier call is JSON", ok: true });
        if (!Array.isArray(body.messages)) throw new Error("SECRETS-07 classifier has no messages");
        expect({ check: "SECRETS-07 classifier sees the exact candidate", ok: body.messages.some((message: unknown) => {
          const item = secrets07Object(message);
          return item.role === "user" && typeof item.content === "string"
            && Buffer.from(item.content).equals(Buffer.from(content));
        }) }).toEqual({ check: "SECRETS-07 classifier sees the exact candidate", ok: true });
        expect({ check: "SECRETS-07 classifier sees the owner document", ok: body.messages.some((message: unknown) => {
          const item = secrets07Object(message);
          return item.role === "system" && item.content === document;
        }) }).toEqual({ check: "SECRETS-07 classifier sees the owner document", ok: true });
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
      expect({ check: "SECRETS-07 owner plane is enabled", ok: enabled.enabled }).toEqual({ check: "SECRETS-07 owner plane is enabled", ok: true });
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
      if (revoked.status !== 200) {
        throw new Error(`SECRETS-07 /v1/core/slips/revoke expected HTTP 200 but answered HTTP ${revoked.status} (${secrets07ErrorText(revoked.body)})`);
      }
      expect({ check: "SECRETS-07 owner revocation lands", ok: revoked.body.revoked }).toEqual({ check: "SECRETS-07 owner revocation lands", ok: true });
      await secrets07Refuse(concise, "vault.policy.outbound.decide", candidate, 401, "UNAUTHORIZED", false);
      // Independent read-only receipt reads after all writes completed: every
      // original ref, read-back, scan and assertion is still required.
      await Promise.all(writeCalls.map(async (write) => {
        const row = await secrets07ReadCall(write.ref);
        expect(row.verb).toBe(write.verb);
        expect(row.actor_ref).toBe(engine.pairedActor.principalRef);
        expect(row.outcome).toBe("ok");
        calls.set(write.ref, row);
      }));
      const beforeRestart = await secrets07Call(engine.client, "vault.policy.owner.get", {});
      await engine.restart();
      const afterRestart = await secrets07Call(engine.client, "vault.policy.owner.get", {});
      expect(afterRestart).toEqual(beforeRestart);
      for (const definition of authored) {
        const saved = await secrets07Call(engine.client, "vault.agents.get", { agent_def_ref: definition.id });
        expect(saved.definition.instructions).toBe(definition.instructions);
      }
      // Post-restart durability without one polling sweep per gate: a single paged
      // sweep re-reads every saved gate receipt, then each is compared in full.
      const secrets07Reread = new Map<string, secrets07GateReceipt>();
      let secrets07After: string | undefined;
      const secrets07Seen = new Set<string>();
      for (;;) {
        const secrets07Page = await secrets07Call(engine.client, "vault.receipts", { limit: 1000, ...(secrets07After ? { after: secrets07After } : {}) });
        expect(secrets07Page.undecodable).toBe(0);
        for (const secrets07Row of secrets07Page.receipts) secrets07Reread.set(secrets07Row.receipt_ref, secrets07Row);
        if (!secrets07Page.next_after) break;
        expect({ check: "SECRETS-07 post-restart gate sweep advances", ok: secrets07Seen.has(secrets07Page.next_after) }).toEqual({ check: "SECRETS-07 post-restart gate sweep advances", ok: false });
        secrets07Seen.add(secrets07Page.next_after);
        secrets07After = secrets07Page.next_after;
      }
      for (const [secrets07GateRef, secrets07GateRow] of gates) expect(secrets07Reread.get(secrets07GateRef)).toEqual(secrets07GateRow);
      await Promise.all([...calls].map(async ([ref, row]) => {
        expect(await secrets07ReadCall(ref)).toEqual(row);
      }));
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
      expect({ check: "SECRETS-07 export archive has members", ok: members.size > 0 }).toEqual({ check: "SECRETS-07 export archive has members", ok: true });
      for (const bytes of members.values()) secrets07Scan(bytes, values);
      let after: string | undefined;
      const cursors = new Set<string>();
      for (;;) {
        const page = await secrets07Call(engine.client, "vault.receipts", { limit: 1000, ...(after ? { after } : {}) });
        expect(page.undecodable).toBe(0);
        if (!page.next_after) break;
        expect({ check: "SECRETS-07 ledger sweep advances", ok: cursors.has(page.next_after) }).toEqual({ check: "SECRETS-07 ledger sweep advances", ok: false });
        cursors.add(page.next_after);
        after = page.next_after;
      }
      await providers.close();
      await engine.close();
      const secrets07Logged = values.flatMap(value => [value, Buffer.from(value).toString("base64")]);
      const secrets07ServerOutput = engine.serverOutputHas(secrets07Logged);
      expect({ check: "SECRETS-07 server logs carry no candidate", found: secrets07ServerOutput.found }).toEqual({ check: "SECRETS-07 server logs carry no candidate", found: false });
      expect({ check: "SECRETS-07 server log window is complete", truncated: secrets07ServerOutput.truncated }).toEqual({ check: "SECRETS-07 server log window is complete", truncated: false });
    } catch (error) {
      secrets07BodyFailures.push(error);
    } finally {
      try {
        await engine.close();
      } catch (error) {
        secrets07CleanupFailures.push(error);
      }
    }
  } catch (error) {
    secrets07BodyFailures.push(error);
  }
  try {
    await providers.close();
  } catch (error) {
    secrets07CleanupFailures.push(error);
  }
  if (secrets07BodyFailures.length > 0 || secrets07CleanupFailures.length > 0) {
    const secrets07All = [...secrets07BodyFailures, ...secrets07CleanupFailures];
    if (secrets07All.length === 1) throw secrets07All[0];
    throw new AggregateError(secrets07All, `SECRETS-07 body failures=${secrets07BodyFailures.length} cleanup failures=${secrets07CleanupFailures.length}: ${secrets07All.map(secrets07Summarize).join(" | ")}`);
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
 * Report: <workspace>/vibe-build-20261017/lanes/kimi/OPUS-E2E-5/cases/SECRETS-08.report.md
 */
suite.todo(test, "SECRETS-08", "waits on owner-revocable agent Grant admission for vault.trusted_contacts.concern.propose, vault.trusted_contacts.concern.asks and vault.trusted_contacts.list");

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

function secrets09Scan<T>(value: T, needles: readonly string[], what: string): T {
  const bytes = value instanceof Uint8Array ? Buffer.from(value)
    : Buffer.from(typeof value === "string" ? value : JSON.stringify(value) ?? "");
  const ok = needles.every(needle => !bytes.includes(Buffer.from(needle)));
  expect({ check: what, ok }).toEqual({ check: what, ok: true });
  return value;
}

function secrets09SafeErrorField(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? redactor.text(value) : null;
}

function secrets09SafeMessage(error: unknown): string {
  return redactor.text(error instanceof Error ? error.message : String(error));
}

// A refusal summary naming the verb, the status and the envelope code. The
// code and message are quoted only when both are strings, and both pass
// through the redactor; a malformed envelope reports UNKNOWN instead.
function secrets09RefusalSummary(verb: string, status: number, body: unknown): string {
  const record = body !== null && typeof body === "object" && !Array.isArray(body)
    ? body as Record<string, unknown> : null;
  const raw = record?.error;
  const fields = raw !== null && typeof raw === "object" && !Array.isArray(raw)
    ? raw as Record<string, unknown> : null;
  const code = fields ? secrets09SafeErrorField(fields.code) : null;
  const message = fields ? secrets09SafeErrorField(fields.message) : null;
  const detail = code !== null && message !== null ? `${code}: ${message}` : "UNKNOWN";
  return `SECRETS-09 HTTP ${verb} refused ${status}: ${detail}`;
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
  secrets09Scan(reply.bytes, needles, `SECRETS-09 ${verb} raw bytes exclude raw and base64 values`);
  secrets09Scan(reply.body, needles, `SECRETS-09 ${verb} body excludes raw and base64 values`);
  secrets09Scan(Object.fromEntries(reply.headers), needles, `SECRETS-09 ${verb} headers exclude raw and base64 values`);
  try {
    expect(reply.status).toBe(200);
  } catch (error) {
    if (error instanceof Error) error.message = `${secrets09RefusalSummary(verb, reply.status, reply.body)} (${error.message})`;
    throw error;
  }
  return reply.body;
}

async function secrets09Decide(
  client: PublicHttpClient, input: FacadeInput<"vault.policy.outbound.decide">,
  needles: readonly string[],
): Promise<WireReply<FacadeResult<"vault.policy.outbound.decide">>> {
  const reply = await client.raw<FacadeResult<"vault.policy.outbound.decide">>(
    "POST", "/v1/core/facade/vault.policy.outbound.decide", input, secrets09Invocation(),
  );
  secrets09Scan(Object.fromEntries(reply.headers), needles, "SECRETS-09 outbound.decide headers exclude raw and base64 values");
  if (reply.status !== 200) secrets09Scan(reply.bytes, needles, "SECRETS-09 outbound.decide refusal bytes exclude raw and base64 values");
  try {
    expect(reply.status).toBe(200);
  } catch (error) {
    if (error instanceof Error) error.message = `${secrets09RefusalSummary("vault.policy.outbound.decide", reply.status, reply.body)} (${error.message})`;
    throw error;
  }
  // This field is the promised candidate, not a receipt or diagnostic leak.
  const { final_content: finalContent, ...otherFields } = reply.body;
  secrets09Scan(otherFields, needles, "SECRETS-09 outbound.decide non-candidate fields exclude raw and base64 values");
  const preserved = typeof finalContent === "string"
    && Buffer.from(finalContent).equals(Buffer.from(input.content));
  expect({ check: "SECRETS-09 outbound.decide preserves the exact candidate bytes", ok: preserved })
    .toEqual({ check: "SECRETS-09 outbound.decide preserves the exact candidate bytes", ok: true });
  return reply;
}

async function secrets09Refuse<V extends FacadeVerb>(
  client: PublicHttpClient, verb: V, input: FacadeInput<V>, status: number,
  code: string, needles: readonly string[],
): Promise<WireReply<unknown>> {
  const reply = await client.raw("POST", `/v1/core/facade/${verb}`, input, secrets09Invocation());
  secrets09Scan(reply.bytes, needles, `SECRETS-09 ${verb} refusal bytes exclude raw and base64 values`);
  secrets09Scan(reply.body, needles, `SECRETS-09 ${verb} refusal body excludes raw and base64 values`);
  secrets09Scan(Object.fromEntries(reply.headers), needles, `SECRETS-09 ${verb} refusal headers exclude raw and base64 values`);
  const error = secrets09Object(secrets09Object(reply.body).error);
  const actualCode = secrets09SafeErrorField(error.code);
  const actualMessage = secrets09SafeErrorField(error.message);
  expect({ check: `SECRETS-09 ${verb} refuses with status ${status}`, ok: reply.status })
    .toEqual({ check: `SECRETS-09 ${verb} refuses with status ${status}`, ok: status });
  expect({ check: `SECRETS-09 ${verb} refuses with code ${code}`, ok: actualCode })
    .toEqual({ check: `SECRETS-09 ${verb} refuses with code ${code}`, ok: code });
  expect({ check: `SECRETS-09 ${verb} refusal message is non-empty`, ok: actualMessage !== null })
    .toEqual({ check: `SECRETS-09 ${verb} refusal message is non-empty`, ok: true });
  expect({ check: `SECRETS-09 ${verb} refusal carries suggestions`, ok: Array.isArray(error.suggestions) })
    .toEqual({ check: `SECRETS-09 ${verb} refusal carries suggestions`, ok: true });
  expect({ check: `SECRETS-09 ${verb} refusal carries a request id`, ok: typeof error.requestId === "string" && error.requestId.length > 0 })
    .toEqual({ check: `SECRETS-09 ${verb} refusal carries a request id`, ok: true });
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
    if (actorRef === null) expect({ check: `SECRETS-09 ${verb} connection refusal carries no body receipt ref`, ok: error.receiptRef == null })
      .toEqual({ check: `SECRETS-09 ${verb} connection refusal carries no body receipt ref`, ok: true });
    else expect(error.receiptRef).toBe(ref);
  }
  const receipt = await awaitPublic(
    () => secrets09Call(client, "vault.receipts.get", { receipt_ref: ref }, needles),
    row => row !== null, { label: `SECRETS-09 ${verb} call receipt` },
  );
  if (!receipt) throw new Error("SECRETS-09 call receipt is not publicly readable");
  expect(receipt.receipt_ref).toBe(ref);
  // Both receipt doors store the dotted verb: the facade router nests under
  // "/v1/core/facade", so axum strips that prefix before the receipt
  // middleware reads the path; the outer connection door strips it itself.
  expect(receipt.verb).toBe(verb);
  expect(receipt.transport).toBe("http_facade");
  if (actorRef === null) {
    expect(receipt.actor_class).toBe("connection");
    expect({ check: `SECRETS-09 ${verb} connection receipt names a connection id`, ok: /^[a-f0-9]{32}$/.test(receipt.actor_ref) })
      .toEqual({ check: `SECRETS-09 ${verb} connection receipt names a connection id`, ok: true });
    expect({ check: `SECRETS-09 ${verb} connection receipt carries no credential or result digest`, ok: receipt.credential_ref == null && receipt.result_digest == null })
      .toEqual({ check: `SECRETS-09 ${verb} connection receipt carries no credential or result digest`, ok: true });
  } else expect(receipt.actor_ref).toBe(actorRef);
  expect(receipt.outcome).toEqual(outcome);
  return receipt;
}

async function secrets09GateRows(client: PublicHttpClient, needles: readonly string[]) {
  const rows: FacadeResult<"vault.receipts">["receipts"] = [];
  let after: string | null = null;
  do {
    const page: FacadeResult<"vault.receipts"> = await secrets09Call(client, "vault.receipts", {
      kinds: ["gate"], limit: 100, ...(after === null ? {} : { after }),
    }, needles);
    expect(page.undecodable).toBe(0);
    rows.push(...page.receipts);
    after = page.next_after ?? null;
  } while (after !== null);
  return rows;
}

async function secrets09Gate(client: PublicHttpClient, ref: string, needles: readonly string[]) {
  expect({ check: "SECRETS-09 policy receipt ref is a gate ref", ok: /^gate:[a-f0-9]{32}$/.test(ref) })
    .toEqual({ check: "SECRETS-09 policy receipt ref is a gate ref", ok: true });
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
    const bytes = secrets09Scan(Buffer.from(row.body, "hex"), needles, "SECRETS-09 manifest body bytes exclude raw and base64 values");
    return secrets09Object(secrets09Scan(decode(bytes), needles, "SECRETS-09 decoded manifest excludes raw and base64 values"));
  }
  return secrets09Object(secrets09Scan(row.json, needles, "SECRETS-09 manifest JSON excludes raw and base64 values"));
}

function secrets09AssertCooldown(body: Record<string, unknown>): void {
  if (!Array.isArray(body.policy_values)) throw new Error("SECRETS-09 policy values are absent");
  const rows = body.policy_values.map(secrets09Object).filter(row =>
    row.key === "provider_cooldown_max_wait_seconds"
    && secrets09Object(row.scope).level === "vault");
  expect({ check: "SECRETS-09 vault cooldown max-wait is zero", ok: rows.length > 0 && rows.every(row => row.value === 0) })
    .toEqual({ check: "SECRETS-09 vault cooldown max-wait is zero", ok: true });
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
  // A cleanup failure must not mask the body failure: capture the body error
  // and report both together. Provider completeness stays strict.
  let secrets09BodyError: unknown = null;
  try {
    const origin = providers.urls.policy;
    if (!origin) throw new Error("SECRETS-09 scripted policy origin is absent");
    // Debug for every workspace crate (EnvFilter matches targets by prefix, so "oneiron" covers oneiron_*); dependencies at
    // info keep each server stream inside the harness 4 MiB scan window (job 4: RUST_LOG=debug truncated it, absence unproved).
    const engine = await EngineFixture.start({ id: "SECRETS-09", profile, serverLog: "info,oneiron=debug", serverConfig: `
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
    let secrets09EngineError: unknown = null;
    try {
      const owner = engine.client;
      const initial = await secrets09Call(owner, "vault.policy.owner.get", {}, needles);
      expect({ check: "SECRETS-09 default owner policy is disabled", ok: initial.enabled })
        .toEqual({ check: "SECRETS-09 default owner policy is disabled", ok: false });
      expect({ check: "SECRETS-09 default authored owner policy is disabled", ok: initial.configuration.owner_policy_enabled })
        .toEqual({ check: "SECRETS-09 default authored owner policy is disabled", ok: false });
      expect({ check: "SECRETS-09 default owner document is absent", ok: initial.configuration.owner_policy_document == null })
        .toEqual({ check: "SECRETS-09 default owner document is absent", ok: true });
      expect({ check: "SECRETS-09 default owner output contract is absent", ok: initial.configuration.owner_policy_output_contract == null })
        .toEqual({ check: "SECRETS-09 default owner output contract is absent", ok: true });
      expect(initial.configuration.owner_policy_patterns ?? []).toEqual([]);
      const shape = await secrets09Call(owner, "vault.shape.read", {}, needles);
      const defaultBody = secrets09Manifest(shape, initial.manifest_ref, needles);
      expect(defaultBody.owner_policy_rows).toEqual([]);

      const off = await secrets09Decide(owner, input, needles);
      expect(off.body.action).toBe("allow");
      expect(off.body.verdict.decision).toBe("allow");
      expect({ check: "SECRETS-09 off decision does not halt", ok: off.body.outbound_halted })
        .toEqual({ check: "SECRETS-09 off decision does not halt", ok: false });
      expect({ check: "SECRETS-09 off decision skips no custom tier", ok: off.body.custom_tier_skipped })
        .toEqual({ check: "SECRETS-09 off decision skips no custom tier", ok: false });
      expect({ check: "SECRETS-09 off decision leaves no policy receipt", ok: off.body.receipt_ref == null })
        .toEqual({ check: "SECRETS-09 off decision leaves no policy receipt", ok: true });
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
      expect({ check: "SECRETS-09 shape plan targets the default manifest", ok: plan.items.some(item => item.target.kind === "manifest"
        && item.target.manifest_ref === initial.manifest_ref) })
        .toEqual({ check: "SECRETS-09 shape plan targets the default manifest", ok: true });
      const applied = await secrets09Call(owner, "vault.shape.apply", { plan, approve: plan.items.map(item => item.seq) }, needles);
      expect({ check: "SECRETS-09 shape apply completed", ok: applied.done })
        .toEqual({ check: "SECRETS-09 shape apply completed", ok: true });
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
      expect({ check: "SECRETS-09 owner row is readable through shape", ok: Array.isArray(withRow.owner_policy_rows) && withRow.owner_policy_rows.some(value => {
        const row = secrets09Object(value);
        return row.row_ref === "fixture.checklist" && row.text === rowText && row.action === "warn" && row.active === true;
      }) }).toEqual({ check: "SECRETS-09 owner row is readable through shape", ok: true });
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
      expect({ check: "SECRETS-09 owner policy is enabled after configure", ok: enabled.enabled })
        .toEqual({ check: "SECRETS-09 owner policy is enabled after configure", ok: true });
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
      expect({ check: "SECRETS-09 owner policy stays enabled after agent refusal", ok: afterRefusal.enabled })
        .toEqual({ check: "SECRETS-09 owner policy stays enabled after agent refusal", ok: true });
      expect(providers.seenFixtureCalls.length).toBe(0);

      const outage = await secrets09Decide(writer.client, input, needles);
      expect(outage.body.action).toBe("skipped");
      expect(outage.body.verdict.decision).toEqual({ skipped: "backend-unavailable" });
      expect({ check: "SECRETS-09 outage decision skips the custom tier", ok: outage.body.custom_tier_skipped })
        .toEqual({ check: "SECRETS-09 outage decision skips the custom tier", ok: true });
      expect({ check: "SECRETS-09 outage decision does not halt", ok: outage.body.outbound_halted })
        .toEqual({ check: "SECRETS-09 outage decision does not halt", ok: false });
      expect(outage.body.verdict.plane_minted).toBe("owner_policy");
      expect({ check: "SECRETS-09 skipped verdict carries no hosted attestation", ok: outage.body.verdict.hosted_attestation == null })
        .toEqual({ check: "SECRETS-09 skipped verdict carries no hosted attestation", ok: true });
      expect(providers.seenFixtureCalls.length).toBe(1);
      const seen = providers.seenFixtureCalls[0];
      if (!seen) throw new Error("SECRETS-09 classifier was not called");
      expect(seen.fixtureId).toBe("secrets09-owner-outage");
      const { body: providerBody, ...providerMetadata } = seen;
      secrets09Scan(providerMetadata, needles, "SECRETS-09 classifier metadata excludes raw and base64 values");
      const { messages, ...providerFields } = secrets09Object(providerBody);
      secrets09Scan(providerFields, needles, "SECRETS-09 classifier non-message fields exclude raw and base64 values");
      if (!Array.isArray(messages)) throw new Error("SECRETS-09 classifier messages are absent");
      let candidateMessages = 0;
      for (const value of messages) {
        const message = secrets09Object(value);
        if (message.role === "user" && message.content === input.content) {
          candidateMessages++;
          const { content: _candidate, ...otherFields } = message;
          secrets09Scan(otherFields, needles, "SECRETS-09 candidate message envelope excludes raw and base64 values");
        } else secrets09Scan(message, needles, "SECRETS-09 non-candidate classifier message excludes raw and base64 values");
      }
      expect(candidateMessages).toBe(1);

      const policyRef = outage.body.receipt_ref;
      if (!policyRef) throw new Error("SECRETS-09 skipped classification has no policy receipt");
      const policyReceipt = await secrets09Gate(owner, policyRef, needles);
      expect(policyReceipt.outcome).toBe("skipped");
      expect(policyReceipt.reason_codes).toContain("gate.policy_model.skipped");
      expect(policyReceipt.reason_codes).toContain("gate.policy_model.skip_reason.backend_unavailable");
      expect({ check: "SECRETS-09 skipped receipt never claims allow", ok: policyReceipt.reason_codes.includes("gate.policy_model.allow") })
        .toEqual({ check: "SECRETS-09 skipped receipt never claims allow", ok: false });
      expect(policyReceipt.actor_ref).toBe(agentRef);
      expect(policyReceipt.content_kind).toBe("action");
      const callReceipt = await secrets09CallReceipt(owner, outage, "vault.policy.outbound.decide", agentRef, "ok", needles);
      expect(callReceipt.actor_class).toBe("agent");
      const slipId = callReceipt.credential_ref;
      if (!slipId || !/^[a-f0-9]{64}$/.test(slipId)) throw new Error("SECRETS-09 call receipt lacks a revocable slip id");
      const revoked = await owner.raw("POST", "/v1/core/slips/revoke", { slip_id: Array.from(Buffer.from(slipId, "hex")) });
      secrets09Scan(revoked.bytes, needles, "SECRETS-09 slip revocation bytes exclude raw and base64 values");
      secrets09Scan(revoked.body, needles, "SECRETS-09 slip revocation body excludes raw and base64 values");
      secrets09Scan(Object.fromEntries(revoked.headers), needles, "SECRETS-09 slip revocation headers exclude raw and base64 values");
      try {
        expect(revoked.status).toBe(200);
      } catch (error) {
        if (error instanceof Error) error.message = `${secrets09RefusalSummary("POST /v1/core/slips/revoke", revoked.status, revoked.body)} (${error.message})`;
        throw error;
      }
      expect({ check: "SECRETS-09 slip revocation is acknowledged", ok: secrets09Object(revoked.body).revoked })
        .toEqual({ check: "SECRETS-09 slip revocation is acknowledged", ok: true });
      const nextUse = await secrets09Refuse(writer.client, "vault.policy.outbound.decide", input, 401, "UNAUTHORIZED", needles);
      const nextUseReceipt = await secrets09CallReceipt(owner, nextUse, "vault.policy.outbound.decide", null,
        { refused: { code: "HTTP_401" } }, needles);
      expect(providers.seenFixtureCalls.length).toBe(1);

      await engine.restart();
      const restarted = await secrets09Call(owner, "vault.policy.owner.get", {}, needles);
      expect({ check: "SECRETS-09 owner policy stays enabled across restart", ok: restarted.enabled })
        .toEqual({ check: "SECRETS-09 owner policy stays enabled across restart", ok: true });
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
      expect({ check: "SECRETS-09 owner policy is disabled after configure-off", ok: disabledView.enabled })
        .toEqual({ check: "SECRETS-09 owner policy is disabled after configure-off", ok: false });
      expect(disabledView.configuration).toEqual({ ...configuration, owner_policy_enabled: false });
      const offAgain = await secrets09Decide(owner, input, needles);
      expect(offAgain.body.action).toBe("allow");
      expect({ check: "SECRETS-09 re-disabled decision skips no custom tier", ok: offAgain.body.custom_tier_skipped })
        .toEqual({ check: "SECRETS-09 re-disabled decision skips no custom tier", ok: false });
      expect({ check: "SECRETS-09 re-disabled decision does not halt", ok: offAgain.body.outbound_halted })
        .toEqual({ check: "SECRETS-09 re-disabled decision does not halt", ok: false });
      expect({ check: "SECRETS-09 re-disabled decision leaves no policy receipt", ok: offAgain.body.receipt_ref == null })
        .toEqual({ check: "SECRETS-09 re-disabled decision leaves no policy receipt", ok: true });
      await secrets09CallReceipt(owner, offAgain, "vault.policy.outbound.decide", engine.pairedActor.principalRef, "ok", needles);
      expect(providers.seenFixtureCalls.length).toBe(1);
      await secrets09Call(owner, "vault.recall", { query: sentinel, effort: "light", limit: 10 }, needles);
      await secrets09GateRows(owner, needles);
      const exported = await secrets09Call(owner, "vault.export", { format: "archive", include_secrets: false, delivery: "inline" }, needles);
      if (!("archive" in exported)) throw new Error("SECRETS-09 inline export returned a transfer");
      expect(Buffer.from(blake3(Buffer.from(exported.archive, "base64"))).toString("hex")).toBe(exported.digest);
      const members = publicZip(exported.archive);
      for (const [name, bytes] of members) {
        secrets09Scan(name, needles, "SECRETS-09 export member name excludes raw and base64 values");
        secrets09Scan(bytes, needles, "SECRETS-09 export member bytes exclude raw and base64 values");
      }
      await engine.close();
      const secrets09NeedleScan = engine.serverOutputHas(needles);
      const secrets09PairScan = engine.serverOutputHas([value, base64]);
      expect({ check: "SECRETS-09 server output excludes raw and base64 needles", found: secrets09NeedleScan.found })
        .toEqual({ check: "SECRETS-09 server output excludes raw and base64 needles", found: false });
      expect({ check: "SECRETS-09 server output excludes the candidate pair", found: secrets09PairScan.found })
        .toEqual({ check: "SECRETS-09 server output excludes the candidate pair", found: false });
      expect({ check: "SECRETS-09 server log window is complete", truncated: secrets09NeedleScan.truncated || secrets09PairScan.truncated })
        .toEqual({ check: "SECRETS-09 server log window is complete", truncated: false });
    } catch (error) {
      secrets09BodyError = error;
    }
    try {
      await engine.close();
    } catch (error) {
      secrets09EngineError = error;
    }
    if (secrets09BodyError !== null && secrets09EngineError !== null) {
      throw new AggregateError(
        [secrets09BodyError, secrets09EngineError],
        `SECRETS-09 body failure: ${secrets09SafeMessage(secrets09BodyError)}; engine cleanup also failed: ${secrets09SafeMessage(secrets09EngineError)}`,
      );
    }
    if (secrets09EngineError !== null) throw secrets09EngineError;
    if (secrets09BodyError !== null) throw secrets09BodyError;
  } catch (error) {
    secrets09BodyError = error;
  }
  let secrets09ProviderError: unknown = null;
  try {
    await providers.close();
  } catch (error) {
    secrets09ProviderError = error;
  }
  if (secrets09BodyError !== null && secrets09ProviderError !== null) {
    throw new AggregateError(
      [secrets09BodyError, secrets09ProviderError],
      `SECRETS-09 body failure: ${secrets09SafeMessage(secrets09BodyError)}; provider cleanup also failed: ${secrets09SafeMessage(secrets09ProviderError)}`,
    );
  }
  if (secrets09ProviderError !== null) throw secrets09ProviderError;
  if (secrets09BodyError !== null) throw secrets09BodyError;
});
