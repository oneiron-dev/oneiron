import { afterAll, expect, test } from "bun:test";
import { inflateRawSync } from "node:zlib";
import { blake3 } from "@noble/hashes/blake3";
import type { FacadeInput, FacadeResult } from "@oneiron/client";
import { EngineFixture } from "./support/engine.ts";
import { PublicHttpClient } from "./support/clients.ts";
import { loadFixtures, ownerBaseClaimScope } from "./support/fixtures.ts";
import { defineFile, redactor } from "./support/run.ts";

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
    const exported = await engine.client.call("vault.export", { format: "archive", include_secrets: false });
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

// SECRETS-03 — Custody use without value disclosure should work (OF-431/425).
// Current typed input: self.use({handle,operation:"connector.call",arguments})
// -> SecretUseAnswer {status,result?,failure?,receipt:{handle,generation,
// effector,operation,decision,used_at}}. Bindings declare tier_ceiling:0|1|2;
// the agent never selects a rung. A local provider must see the fixture key,
// while the MCP result/receipt must not. Deny reveal; rotate by owner with
// {name,value_base64}; then a NEW lease uses generation 1 and the OLD lease
// refuses. self.use has no lease token, and the public catalog has no typed
// materialize/renew/teardown/use-by-lease call. Reusing the handle after
// rotation only proves a new doored use, not invalidation of an old lease.
suite.todo(test, "SECRETS-03", "waits on typed T0/T1/T2 lease materialize, renew, teardown and old-lease use calls");

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

// SECRETS-06 — Channel disclosure ceiling should work (OF-061/453).
// A private names-class person claim above a public model-channel ceiling
// must serialize as a real bare pr handle. describe gives class/status/band/
// provenance and reveal effect, never a fake name. reveal({handle,why}) gives
// a pending handle; wait gives the current grant decision and, only inside
// the grant, the value plus handle/class/why/connection/answerer receipt.
// Owner-channel assembly retains the real fixture name. Current generated
// RevealRequest/RevealHandleCard/RevealWaitAnswer and their implementations
// address SECRET custody, not PERSON claims or connection/class ceilings.
suite.todo(test, "SECRETS-06", "waits on typed person-handle describe/reveal/wait and connection/class disclosure-ceiling setting");

// SECRETS-07 — Policy enforcement independent of persona should work (OF-333).
// Explicitly opt into owner policy (or use an attested hosted route), then
// run the SAME benign action as both authored agent definitions. A scripted
// verdict backend returns Allow/Warn/Block/RouteToHelp. Expected outcomes are
// persona-independent; Warn preserves exact bytes; Block emits a system-voice
// notice and hash-only receipt. A reworded retry stays governed, never a
// persona-authored rewrite. ai.verdict alone is not policy enforcement, and
// vault.settings.wake_policy.set is a Dreamer setting, not owner content policy.
suite.todo(test, "SECRETS-07", "waits on typed owner-policy configuration and policy-governed outbound decision/notice calls");

// SECRETS-08 — Trusted-contact concern notice should work (OF-527).
// A consenting adult trusted_contact, approved by the owner, is ask-first.
// RouteToHelp proposes fact-of-concern only; the fake delivery sink receives
// nothing before authorization and no private conversation details afterward.
// Either side's revocation prevents the next delivery. Every notify informs
// the agent. The typed notice needs the contact, concern fact, authorization
// and delivery receipt, never raw private text. self.inbox.concern and the
// owner's /inbox/concern are OF-568 agent-health cards, NOT this notification.
suite.todo(test, "SECRETS-08", "waits on typed trusted_contact consent/revoke and concern-notification propose/authorize/deliver calls");

// SECRETS-09 — Local and hosted policy failures stay distinct should work.
// Owner plane: off by default; no engine policy categories. A configured
// backend failure is Skipped(reason), NEVER Allow, and delivers unchanged
// benign content with an honest receipt. Hosted legal plane: only on bytes
// the attested relay carries, fail closed, no delivery; its notice speaks as
// the service and points to the local-model path. Never mint a hosted verdict
// or forge its attestation in a helper, and never treat an owner-plane result
// as evidence of a hosted pass. The current public catalog exposes no typed
// owner-policy toggle or hosted-attested relay decision/notice route.
suite.todo(test, "SECRETS-09", "waits on typed owner-policy off/on and hosted-attested relay decision, receipt and notice calls");
