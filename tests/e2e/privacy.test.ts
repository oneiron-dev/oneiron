import { afterAll, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { resolve } from "node:path";
import { inflateRawSync } from "node:zlib";
import { decode } from "@msgpack/msgpack";
import { blake3 } from "@noble/hashes/blake3";
import type { Facade, FacadeInput, FacadeResult } from "@oneiron/client";
import { EngineFixture, awaitPublic } from "./support/engine.ts";
import type { PairedActor } from "./support/engine.ts";
import { PublicHttpError } from "./support/clients.ts";
import type { PublicHttpClient, McpClient } from "./support/clients.ts";
import { loadFixtures, ownerBaseClaimScope } from "./support/fixtures.ts";
import { ScriptedProviders, openaiText } from "./support/providers.ts";
import type { ProviderStep } from "./support/providers.ts";
import { BlockedDoor, defineFile, redactor, secretHex } from "./support/run.ts";

const recipeDefaults = JSON.parse(await Bun.file(new URL("../../crates/oneiron/src/dreamer_wake/recipe_policy_defaults.json", import.meta.url)).text());
const extractionPrompt = JSON.parse(await Bun.file(new URL("../../crates/oneiron/src/dreamer_consolidation/executor/extraction_prompt.json", import.meta.url)).text());

const profile = process.env.E2E_PROFILE === "real-small-model"
  ? "real-small-model" : "deterministic";
const suite = defineFile(import.meta, { profile, slots: 1 });
afterAll(suite.flush);

// The suite-plan owns the IDs, registry rows and canon anchors. Bindings were
// read from the e2440c33 worktree. Source inspection is not runtime evidence.
interface PrivacyFixtures {
  sharedBlobs: { names: [string, string]; versions: string[] };
  legalHold: {
    name: string;
    matterRef: string;
    expected: {
      kind: "customer";
      refusalEvent: "delete_refused";
      refusalReason: "held_record";
      confirmEvent: "lift_and_erase_confirmed";
      unprivilegedLiftStatus: 403;
      // Final completion via vault.records.erase_sweep (erase_complete_at +
      // final_ref), not the immediate lift_and_erase state. Immediate may be
      // erased (completed at once) or completion_pending (confirmed, sweep or
      // custody still retiring). verbs/legal_hold.rs LegalHoldEraseState.
      // Read via catalog.readJson("privacy-scenarios") ->
      // tests/e2e/fixtures/privacy/scenarios.json (manifest map), not a
      // guessed filename. JSON value "erased" is the completed state.
      ownerEraseState: "erased";
    };
  };
}

type DeleteReceipt = Extract<FacadeResult<"vault.records.erase_confirm">, { first: unknown }>["first"];
type Artifact = FacadeResult<"vault.artifacts.put">;

interface RedactionAudit {
  request_id: string;
  scope: { entity_ids: string[]; revision_ids: string[] };
  reason: string;
  requested_at: number;
  soft_complete_at: number;
  hard_purge_complete_at: number;
  sweep_queued_at: number | null;
  sweep_deadline_at: number | null;
  sweep_complete_at: number | null;
  erase_complete_at: number | null;
  affected_revision_ids: string[];
  custody_retirements: string[];
  capture_failures?: unknown[];
  verification: Record<string, string>;
}

// POST /v1/owner/maintain returns HousekeepingReport/SweepWork, not a job
// drain. This local DTO covers only the historical-sweep observation we use.
interface HousekeepingReport {
  started_at: number;
  sweeps: {
    sweep: string;
    outcome: string;
    complete?: boolean;
    work?: {
      hard_erase?: {
        jobs_processed: number;
        jobs_deferred: number;
        jobs_failed: number;
        windows_deferred_live: number;
        windows_deferred_raced: number;
        windows_deferred_held: number;
        receipts_finalized: number;
        deadline_breaches: number;
        obligations_undecodable: number;
      };
    };
  }[];
}

async function uploadVersions(
  client: PublicHttpClient,
  name: string,
  versions: readonly Uint8Array[],
): Promise<Artifact> {
  const occurred_at = Math.floor(Date.now() / 1000);
  const record = await client.call("vault.artifacts.put", {
    name, media_type: "text/plain", occurred_at,
  });
  for (const [index, bytes] of versions.entries()) {
    const outcome = await client.call("vault.artifacts.append", {
      artifact_ref: record.id_hex,
      content_base64: Buffer.from(bytes).toString("base64"),
      occurred_at,
    });
    if (!("landed" in outcome)) throw new Error(`Append proposed, expected landed (proposal ${outcome.proposed.proposal_ref})`);
    const version = outcome.landed;
    expect(version.version).toBe(index + 1);
    // Standard hashing of fixture bytes, not an engine-generated answer.
    expect(version.content_hash_hex).toBe(Buffer.from(blake3(bytes)).toString("hex"));
  }
  return record;
}

async function eraseRecord(client: PublicHttpClient, record: string): Promise<DeleteReceipt> {
  const preview = await client.call("vault.records.erase_preview", { record });
  expect(preview.record).toBe(record);
  const outcome = await client.call("vault.records.erase_confirm", {
    record, preview_digest: preview.preview_digest, also_same_bytes: false,
  });
  if (!("first" in outcome)) throw new Error("Erase confirm answered no first receipt");
  expect(outcome.first_act ?? null).toBeNull(); // Personal vault: no shared-owner veto.
  expect(outcome.same_bytes).toEqual([]); // Same-bytes fan-out was not requested.
  expect(outcome.first.existed).toBe(true);
  // The owner erase_confirm door records OwnerErase (byte 6, rendered
  // owner_erase), distinct from an ordinary restorable user_hard_delete.
  expect(outcome.first.reason).toBe("owner_erase");
  return outcome.first;
}

async function readAudit(
  client: PublicHttpClient, receiptRef: string | null | undefined, record: string, forbidden: readonly string[],
): Promise<RedactionAudit> {
  const match = /^redaction:([a-f0-9]{32})$/.exec(receiptRef ?? "");
  if (!match) throw new Error("Erase returned no redaction receipt reference");
  const result = await client.call("vault.get", { entity_ref: match[1]! });
  expect(result.value).not.toBeNull();
  expect(result.value?.kind).toBe("REDACTION_AUDIT");
  const body = result.value?.body as RedactionAudit;
  expect(body.scope.entity_ids).toContain(record);
  expect(body.request_id).toMatch(/^[a-f0-9-]+$/i);
  expect(body.hard_purge_complete_at).toBeGreaterThanOrEqual(body.requested_at);
  expect(body.sweep_queued_at).not.toBeNull();
  const text = JSON.stringify(body);
  for (const content of forbidden) expect(text.includes(content)).toBe(false);
  // Canon permits opaque IDs, times, the delete reason and attestation only.
  const allowed = new Set([
    "request_id", "scope", "reason", "requested_at", "soft_complete_at",
    "hard_purge_complete_at", "sweep_queued_at", "sweep_deadline_at", "sweep_complete_at",
    "affected_revision_ids", "actor_ref", "room_ref", "room_role", "erase_complete_at",
    "custody_retirements", "capture_failures", "verification",
  ]);
  expect(Object.keys(body).every(key => allowed.has(key))).toBe(true);
  for (const id of [...body.scope.entity_ids, ...body.scope.revision_ids, ...body.affected_revision_ids]) {
    expect(id).toMatch(/^[a-f0-9]{32}$/i);
  }
  // These fixtures provoke no corrupt-CLAIM capture exception.
  expect(body.capture_failures ?? []).toEqual([]);
  for (const retirement of body.custody_retirements) {
    expect(retirement).toMatch(/^[a-z0-9_]+\.[a-f0-9]{32}\.[a-f0-9]+$/i);
  }
  expect(Object.keys(body.verification).sort()).toEqual(["att_client", "att_pk", "att_sig", "att_v"]);
  expect(body.verification.att_client).toMatch(/^[a-f0-9]{16}$/);
  expect(body.verification.att_pk).toMatch(/^[a-f0-9]{64}$/);
  expect(body.verification.att_sig).toMatch(/^[a-f0-9]{128}$/);
  expect(body.verification.att_v).toBe("1");
  return body;
}

async function expectBlobGone(client: PublicHttpClient, record: string, version: number): Promise<void> {
  try {
    expect(await client.call("vault.artifacts.read", { artifact_ref: record, version })).toBeNull();
  } catch (error) {
    // The current read door resolves a missing handle before reading bytes.
    // Both its typed missing-reference error and an absent version mean no body.
    if (!(error instanceof PublicHttpError)) throw error;
    expect([404, 422]).toContain(error.reply.status);
    const code = error.error?.code;
    if (code === undefined) throw error;
    expect(["NOT_FOUND", "INVENTED_REFERENCE"]).toContain(code);
  }
}

async function finishHistoricalSweep(engine: EngineFixture): Promise<void> {
  // This is one explicit owner action, never a silently retried mutation or
  // a private clock tick. Its response awaits the real production sweep.
  const reply = await engine.client.request<HousekeepingReport>("POST", "/v1/owner/maintain");
  const sweep = reply.body.sweeps.find(row => row.sweep === "hard_erase_sweep");
  expect(sweep?.outcome).toBe("ran");
  expect(sweep?.complete).toBe(true);
  const work = sweep?.work?.hard_erase;
  expect(work).toBeDefined();
  expect(work?.jobs_failed).toBe(0);
  expect(work?.jobs_deferred).toBe(0);
  expect(work?.windows_deferred_live).toBe(0);
  expect(work?.windows_deferred_raced).toBe(0);
  expect(work?.windows_deferred_held).toBe(0);
  expect(work?.obligations_undecodable).toBe(0);
  expect(work?.deadline_breaches).toBe(0);
  // Counts need not be positive: a scheduled pass may already have finished.
  // A completed scan with no deferred/failed obligations is the public signal.
  await engine.artifacts.json("historical-sweep.json", reply.body);
}


function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Expected a public object");
  }
  return value as Record<string, unknown>;
}

// Read every central-directory entry, including binary file members. The
// archive contract is ZIP; this small fresh vault uses neither ZIP64 nor encryption.
function zipMembers(bytes: Buffer): Map<string, Buffer> {
  let end = bytes.length - 22;
  while (end >= Math.max(0, bytes.length - 65557)
    && bytes.readUInt32LE(end) !== 0x06054b50) end--;
  if (end < 0 || bytes.readUInt32LE(end) !== 0x06054b50) throw new Error("Missing ZIP directory");
  expect(bytes.readUInt16LE(end + 4)).toBe(0);
  expect(bytes.readUInt16LE(end + 6)).toBe(0);
  const count = bytes.readUInt16LE(end + 10);
  expect(count).toBeGreaterThan(0);
  expect(count).not.toBe(0xffff);
  let cursor = bytes.readUInt32LE(end + 16);
  const members = new Map<string, Buffer>();
  for (let index = 0; index < count; index++) {
    expect(bytes.readUInt32LE(cursor)).toBe(0x02014b50);
    const flags = bytes.readUInt16LE(cursor + 8);
    const method = bytes.readUInt16LE(cursor + 10);
    const size = bytes.readUInt32LE(cursor + 20);
    const expandedSize = bytes.readUInt32LE(cursor + 24);
    const nameSize = bytes.readUInt16LE(cursor + 28);
    const extraSize = bytes.readUInt16LE(cursor + 30);
    const commentSize = bytes.readUInt16LE(cursor + 32);
    const local = bytes.readUInt32LE(cursor + 42);
    const name = bytes.subarray(cursor + 46, cursor + 46 + nameSize).toString("utf8");
    expect(flags & 1).toBe(0);
    expect([0, 8]).toContain(method);
    expect(bytes.readUInt32LE(local)).toBe(0x04034b50);
    const start = local + 30 + bytes.readUInt16LE(local + 26) + bytes.readUInt16LE(local + 28);
    expect(start + size).toBeLessThanOrEqual(bytes.length);
    const compressed = bytes.subarray(start, start + size);
    const body = method === 8 ? inflateRawSync(compressed) : compressed;
    expect(body.length).toBe(expandedSize);
    expect(members.has(name)).toBe(false);
    members.set(name, body);
    cursor += 46 + nameSize + extraSize + commentSize;
  }
  return members;
}

// Export rows may wrap binary bodies in base64 or byte arrays. Inspect those
// too, rather than searching only the JSONL spelling or the compressed ZIP.
function exportedText(members: Map<string, Buffer>): string {
  const strings = new Set<string>();
  function bytes(value: Uint8Array): void {
    const text = Buffer.from(value).toString("utf8");
    if (strings.has(text)) return;
    strings.add(text);
    try { visit(decode(value)); } catch { /* A file need not be MessagePack. */ }
    for (const line of text.split("\n")) {
      try { visit(JSON.parse(line)); } catch { /* A member need not be JSONL. */ }
    }
  }
  function visit(value: unknown): void {
    if (typeof value === "string") {
      if (strings.has(value)) return;
      strings.add(value);
      if (value.length >= 8 && value.length % 4 === 0 && /^[A-Za-z0-9+/]+={0,2}$/.test(value)) {
        const decoded = Buffer.from(value, "base64");
        if (decoded.toString("base64") === value) bytes(decoded);
      }
    } else if (value instanceof Uint8Array) bytes(value);
    else if (Array.isArray(value)) {
      if (value.length && value.every(n => Number.isInteger(n) && n >= 0 && n <= 255)) {
        bytes(Uint8Array.from(value));
      } else for (const item of value) visit(item);
    } else if (value && typeof value === "object") {
      for (const item of Object.values(value)) visit(item);
    }
  }
  for (const [name, body] of members) { strings.add(name); bytes(body); }
  return [...strings].join("\n");
}

async function exportMembers(client: PublicHttpClient): Promise<Map<string, Buffer>> {
  const exported = await client.call("vault.export", { format: "archive", delivery: "inline" });
  if (!("archive" in exported)) throw new Error("Inline export returned a transfer");
  const bytes = Buffer.from(exported.archive, "base64");
  expect(Buffer.from(blake3(bytes)).toString("hex")).toBe(exported.digest);
  return zipMembers(bytes);
}
async function exportText(client: PublicHttpClient): Promise<string> {
  return exportedText(await exportMembers(client));
}

function excludes(value: unknown, forbidden: readonly string[]): void {
  const text = typeof value === "string" ? value : JSON.stringify(value);
  for (const content of forbidden) expect(text.includes(content)).toBe(false);
}

// Tool-first MCP verb envelope (BOOT-07 pattern): the schema_version const
// comes from tools/list and consent is caller-declared; the verb input goes
// under arguments.spec. A refused call proves nothing, so every MCP read
// below asserts isError === false — including the post-erase exclusions.
interface McpTool { name: string; inputSchema: { properties: { schema_version: { const: string } } } }
interface McpTools { surfaceMode: string; tools: McpTool[] }
interface McpToolResult { isError: boolean; structuredContent: unknown }
function mcpArguments(tools: McpTools, name: string, spec: unknown): Record<string, unknown> {
  const tool = tools.tools.find(item => item.name === name);
  if (!tool) throw new Error(`Required public MCP tool not registered: ${name}`);
  return { schema_version: tool.inputSchema.properties.schema_version.const,
    consent: { policy_ref: "policy:privacy-session", purpose: "privacy hard-erase journey" },
    arguments: { spec } };
}
async function mcpRead(mcp: McpClient, tools: McpTools, name: string, spec: unknown): Promise<unknown> {
  const reply = await mcp.callTool(name, mcpArguments(tools, name, spec)) as McpToolResult;
  expect(reply.isError).toBe(false);
  return reply;
}

const receiptKinds = [
  "outbound", "gate", "identity_lifecycle", "scoped_read", "share", "artifact_settle",
  "proposal_outcome", "commitment_lifecycle", "extraction", "served_form", "hook",
  "reference_refusal", "task_lifecycle",
];
async function allReceipts(client: PublicHttpClient) {
  const rows: FacadeResult<"vault.receipts">["receipts"] = [];
  let after: string | undefined;
  do {
    const page = await client.call("vault.receipts", { limit: 100, kinds: receiptKinds, ...(after === undefined ? {} : { after }) });
    expect(page.undecodable).toBe(0);
    rows.push(...page.receipts);
    after = page.next_after ?? undefined;
  } while (after !== undefined);
  return rows.sort((a, b) => a.receipt_ref.localeCompare(b.receipt_ref));
}

function turn(conversation: string, text: string): FacadeInput<"vault.witness"> {
  return {
    conversation_ref: conversation, occurred_at: Math.floor(Date.now() / 1000),
    messages: [{ author: "user", message_type: "text", content: text, is_visible: true, order: 0 }],
  };
}
async function ownerRoom(engine: EngineFixture, title: string, name?: string, occurredAt?: number) {
  return engine.client.call("vault.conversations.create", {
    ...(occurredAt === undefined ? {} : { occurred_start: occurredAt, occurred_end: occurredAt }),
    body: { v: 1, kind: "direct", member_ids: [engine.pairedActor.principalRef], title,
      ...(name === undefined ? {} : { name }) },
    text: [{ field: "title", value: title }],
  });
}

async function anonymousPolicy(engine: EngineFixture, policyRow: string): Promise<void> {
  const ownerPolicy = await engine.client.call("vault.policy.owner.get", {});
  const shape = await engine.client.call("vault.shape.read", {});
  const manifest = shape.live.rows.find(row => row.kind === "manifest"
    && row.manifest_ref === ownerPolicy.manifest_ref);
  if (!manifest || manifest.kind !== "manifest" || !manifest.body) {
    throw new Error("Owner policy has no manifest in the public shape");
  }
  const body = object(decode(Buffer.from(manifest.body, "hex")));
  const configured = {
    ...body,
    owner_policy_enabled: true,
    owner_policy_rows: [{ row_ref: policyRow, text: "Do not reveal the ending of the fixture story.",
      active: true, action: "block" }],
    owner_policy_patterns: [{ id: "privacy.story-ending", pattern: "privacyanonymousblock",
      category: policyRow, role: "decide" as const }],
  };
  const rows = shape.live.rows.map(row => row === manifest
    ? { kind: "manifest" as const, manifest_ref: manifest.manifest_ref, json: configured }
    : row);
  const plan = await engine.client.call("vault.shape.plan", { seed: { rows } });
  expect(plan.items.some(item => item.target.kind === "manifest"
    && item.target.manifest_ref === manifest.manifest_ref)).toBe(true);
  const applied = await engine.client.call("vault.shape.apply", {
    plan, approve: plan.items.map(item => item.seq),
  });
  expect(applied.done).toBe(true);
  for (const item of applied.items) expect(item.state.state).toBe("landed");
  const readback = await engine.client.call("vault.policy.owner.get", {});
  expect(readback.enabled).toBe(true);
  expect(readback.configuration.owner_policy_patterns).toEqual(configured.owner_policy_patterns);
}

const SUMMARY_PROMPT = "Summarize the admitted source text and retain its location fact.";
const PERSON_ABOUT_PROMPT = "You write the one-line `about` of a person on an agent's roster of people. The facts below are everything you may use, one per line as `predicate: value`. Write one plain sentence of at most 25 words that says who this person is. Never add, guess or imply a fact that is not listed, and never say that facts are missing. A fact marked (observed) was read from what the person did; where it disagrees with a fact marked (stated), go by the stated one. No markup and no quotes.";

function dreamerConfig(providers: ScriptedProviders, summary = false): string {
  return `
[models]
extraction_egress = true
[models.providers.privacy]
kind = "local-openai-compat"
base_url = "${providers.urls.extraction}"
revision = "e2e-v1"
[models.roles.extraction_teacher]
model = "privacy:privacy-extract"
[models.providers.summary]
kind = "local-openai-compat"
base_url = "${providers.urls.summary ?? providers.urls.extraction}"
revision = "e2e-v1"
[models.roles.dreamer_current]
model = "summary:privacy-summary"
[models.dreamer]
enabled = true
${summary ? 'summary_prompt = "' + SUMMARY_PROMPT + '"' : ""}
[models.workflows]
enabled = false
`;
}

type BackgroundKey = "follower_instruction" | "follower_keyframe_instruction" | "novelty_instruction" | "audit_window_instruction";
// The Dreamer's background extraction producers. A keyframe fold accepts
// any non-blank text and a window audit accepts an empty finding, so both
// get that valid answer. The follower (one reading per asked span) and the
// novelty rung (a decision pack keyed by span-derived question ids) have no
// static valid answer: they keep a declared 503, which the step retries
// and then parks. A case that scripts one of them itself omits its rule.
const BACKGROUND_REPLIES: Partial<Record<BackgroundKey, string>> = {
  follower_keyframe_instruction: "No change to the keyframe.",
  audit_window_instruction: JSON.stringify({ discovered: [] }),
};
function backgroundExtraction(model: string, omit: readonly BackgroundKey[] = []): ProviderStep[] {
  return (["follower_instruction", "follower_keyframe_instruction", "novelty_instruction", "audit_window_instruction"] as const)
    .filter(key => !omit.includes(key))
    .map(key => {
      const text = BACKGROUND_REPLIES[key];
      return { id: `background-${key}`, origin: "extraction", role: "extraction_teacher",
        purpose: `background ${key}`, standing: true as const,
        request: { method: "POST" as const, path: "/v1/chat/completions", model, system: recipeDefaults[key] },
        response: text === undefined
          ? { kind: "json" as const, status: 503,
            body: { error: { type: "fixture_background_unscripted", message: "Background producer is not scripted" } } }
          : openaiText(`background-${key}`, model, text, { inputTokens: 64, outputTokens: 8 }) };
    });
}

async function grantExtraction(engine: EngineFixture): Promise<void> {
  // Public stopped-vault owner command. Do this before authoring any source,
  // never by editing defaults, the vault, a lease or an engine clock on disk.
  await engine.kill();
  const grant = await engine.cli.run(["dreamer", "grant", "--config", `${engine.root}/oneiron.toml`,
    "--extraction-route", "own_server"]);
  expect(grant.exitCode).toBe(0);
  await engine.restart();
}
async function extract(engine: EngineFixture, turnRef: string, providers: ScriptedProviders) {
  const ticket = await engine.client.call("vault.memory.signal_extraction", { turn_refs: [turnRef] });
  expect(ticket.job_refs.length).toBeGreaterThan(0);
  providers.releaseBarrier("extract");
  const results: NonNullable<FacadeResult<"vault.memory.signal_extraction.result">>[] = [];
  for (const job_ref of ticket.job_refs) {
    const result = await awaitPublic(
      () => engine.client.call("vault.memory.signal_extraction.result", { job_ref }),
      value => value?.job.state === "completed",
      { label: "production signal extraction" },
    );
    if (!result) throw new Error("Completed extraction has no typed result");
    expect(result.job.last_error ?? null).toBeNull();
    results.push(result);
  }
  return results.flatMap(result => result.claims);
}
function turnId(receipt: FacadeResult<"vault.witness">): string {
  if (!receipt.turn) throw new Error("Witness returned no typed TURN record");
  return receipt.turn.id;
}
async function people(client: PublicHttpClient) {
  const rows: FacadeResult<"vault.people.list">["people"] = [];
  let page = 0;
  for (;;) {
    const result = await client.call("vault.people.list", { page });
    rows.push(...result.people);
    if (!result.more) return rows;
    page++;
  }
}
function exportedRecord(members: Map<string, Buffer>, id: string): Record<string, unknown> {
  const matches: Record<string, unknown>[] = [];
  for (const [path, bytes] of members) {
    if (!path.endsWith(".jsonl")) continue;
    for (const line of bytes.toString("utf8").split("\n").filter(Boolean)) {
      const row = object(JSON.parse(line));
      if (row.id === id && "entity_type" in row) matches.push(row);
    }
  }
  expect(matches).toHaveLength(1);
  return matches[0]!;
}

async function expectReferenceGone(client: PublicHttpClient, reference: string, forbidden: readonly string[]): Promise<void> {
  try {
    const result = await client.call("vault.refs.resolve", { reference });
    excludes(result, forbidden);
    expect(result.value.snippet ?? null).toBeNull();
    expect(result.value.revision ?? null).toBeNull();
    // A surviving opaque reference must not resolve back to a retained body.
    expect((await client.call("vault.get", { entity_ref: reference })).value).toBeNull();
  } catch (error) {
    if (!(error instanceof PublicHttpError)) throw error;
    excludes(error.reply.body, forbidden);
    expect([404, 422]).toContain(error.reply.status);
    const code = error.error?.code;
    if (code === undefined) throw error;
    expect(["NOT_FOUND", "INVENTED_REFERENCE"]).toContain(code);
  }
}

// ARCH-0038: erase purges the active store at once, so no read door serves
// the erased content. Canon fixes no answer shape for a hydrate of erased
// refs. An empty list and the read's NOT_FOUND refusal both carry nothing.
async function expectHydrateGone(
  client: PublicHttpClient, refs: FacadeInput<"vault.hydrate">["refs"], forbidden: readonly string[],
): Promise<void> {
  try {
    expect((await client.call("vault.hydrate", { refs })).value).toEqual([]);
  } catch (error) {
    if (!(error instanceof PublicHttpError)) throw error;
    excludes(error.reply.body, forbidden);
    expect(error.reply.status).toBe(404);
    expect(error.error?.code).toBe("NOT_FOUND");
  }
}

async function expectMcpHydrateGone(
  mcp: McpClient, tools: McpTools, refs: FacadeInput<"vault.hydrate">["refs"], forbidden: readonly string[],
): Promise<void> {
  const reply = await mcp.callTool("vault.hydrate", mcpArguments(tools, "vault.hydrate", { refs })) as McpToolResult;
  excludes(reply, forbidden);
  if (reply.isError) expect(JSON.stringify(reply)).toContain("NOT_FOUND");
}

function errorText(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

// PRIVACY-01. The real extraction response mints eligible PERSON records;
// ordinary owner-created PERSONs have no extraction provenance and are not candidates.
suite.test(test, "PRIVACY-01", "Archive restoration without erasure should work", async () => {
  const catalog = await loadFixtures();
  const data = await catalog.readJson<{ archive: {
    occurredAt: number;
    empty: { body: { name: string } }; protected: { body: { name: string }; claimText: string };
    cleanup: { posture: "propose_first"; task_retention_days: number }; mention: string;
  } }>("privacy-scenarios");
  const spec = data.archive;
  const names = [spec.empty.body.name, spec.protected.body.name];
  redactor.add(...names, spec.protected.claimText);
  const providers = await ScriptedProviders.start({ id: "privacy-archive", steps: [{
    id: "eligible-people", origin: "extraction", role: "extraction_teacher", purpose: "extract witnessed people",
    request: { method: "POST", path: "/v1/chat/completions", model: "privacy-extract", system: extractionPrompt.system }, barrier: "extract",
    response: openaiText("eligible-people", "privacy-extract", JSON.stringify({ candidates: [],
      persons: names.map((name, index) => ({ id: `new:P${index + 1}`, name, evidence_turn_refs: ["T1"] })) }),
      { inputTokens: 128, outputTokens: 64 }),
  }, {
    id: "archive-summary", origin: "summary", role: "dreamer_current", purpose: "background scope summary",
    standing: true,
    request: { method: "POST", path: "/v1/chat/completions", model: "privacy-summary", fields: { response_format: { type: "json_schema" } } },
    response: openaiText("archive-summary", "privacy-summary", JSON.stringify({ text: "A short note was recorded.", keep: "" }),
      { inputTokens: 128, outputTokens: 16 }),
  }, ...backgroundExtraction("privacy-extract")] });
  let engine: EngineFixture | undefined;
  let primaryFailed: boolean = false;
  let primary: unknown;
  let stage = "archive engine setup";
  try {
    engine = await EngineFixture.start({ id: "PRIVACY-01", profile, serverConfig: dreamerConfig(providers) });
    await grantExtraction(engine);
    const room = await ownerRoom(engine, "Privacy archive source", undefined, spec.occurredAt);
    // Arm the handoff before witnessing can schedule Micro alongside Meso.
    // Standing matches precede FIFO, so install only once eligible-people is
    // already selected and held at the external provider boundary.
    const extractionHandoff = providers.awaitBarrier("extract").then(() => {
      providers.enqueue({
        id: "archive-reextract", origin: "extraction", role: "extraction_teacher",
        purpose: "background re-extraction of the active archive source turn",
        standing: true,
        request: { method: "POST", path: "/v1/chat/completions", model: "privacy-extract", system: extractionPrompt.system },
        response: openaiText("archive-reextract", "privacy-extract", JSON.stringify({ candidates: [] }),
          { inputTokens: 128, outputTokens: 16 }),
      });
      return null;
    }).catch((error: unknown) => new Error(
      `PRIVACY-01 extraction barrier: ${errorText(error)}; last provider observation: ${JSON.stringify(providers.seenFixtureCalls.map(call => ({ fixtureId: call.fixtureId, origin: call.origin, method: call.method, path: call.path })))}`,
      { cause: error },
    ));
    const source = await engine.client.call("vault.witness", {
      ...turn(room.id, `${names[0]}. ${names[1]}. ${spec.protected.claimText}`),
      occurred_at: spec.occurredAt,
    });
    const savedTurn = await engine.client.call("vault.get", { entity_ref: source.turn_id });
    expect(savedTurn.value?.kind).toBe("TURN");
    expect(savedTurn.value?.id_hex).toBe(source.turn_id);
    const messageRef = source.message_short_ids[0];
    if (!messageRef) throw new Error("Archive source witness returned no MESSAGE reference");
    const savedMessage = await engine.client.call("vault.get", { entity_ref: messageRef });
    expect(savedMessage.value?.kind).toBe("MESSAGE");
    expect(savedMessage.value?.body).toEqual(expect.objectContaining({
      content: `${names[0]}. ${names[1]}. ${spec.protected.claimText}`,
    }));
    stage = "initial extraction admission and provider barrier";
    const ticket = await engine.client.call("vault.memory.signal_extraction", {
      turn_refs: [turnId(source)],
    });
    expect(ticket.job_refs.length).toBeGreaterThan(0);
    const handoffFailure = await extractionHandoff;
    if (handoffFailure !== null) throw handoffFailure;
    providers.releaseBarrier("extract");
    stage = "initial extraction completion";
    for (const job_ref of ticket.job_refs) {
      const result = await awaitPublic(
        () => engine!.client.call("vault.memory.signal_extraction.result", { job_ref }),
        value => value?.job.state === "completed",
        { label: `PRIVACY-01 extraction ${job_ref} completion` },
      );
      if (!result) throw new Error("Completed extraction has no typed result");
      expect(result.job.last_error ?? null).toBeNull();
    }
    stage = "extracted PERSON readbacks";
    // The first request may belong to Micro rather than the explicit Meso
    // job. Observe its PERSON writes, not the scheduler's relative order.
    const rows = await awaitPublic(
      () => people(engine!.client),
      value => names.every(name => value.filter(row => row.name === name).length === 1),
      { label: "PRIVACY-01 eligible PERSON readback after extraction" },
    );
    const empty = rows.filter(row => row.name === names[0]);
    const protectedRows = rows.filter(row => row.name === names[1]);
    expect(empty).toHaveLength(1);
    expect(protectedRows).toHaveLength(1);
    const emptyId = empty[0]!.person;
    const protectedId = protectedRows[0]!.person;
    const before = (await engine.client.call("vault.get", { entity_ref: emptyId })).value;
    expect(before?.kind).toBe("PERSON");
    expect(object(before?.body).name).toBe(spec.mention);
    const scope = await ownerBaseClaimScope(engine.client, engine.pairedActor.principalRef);
    stage = "protected PERSON claim write";
    const protection = await engine.client.call("vault.claims.upsert", {
      subject_ref: protectedId, predicate: "privacy.archive_protection", value: spec.protected.claimText,
      confidence: 1, source: "user_stated", scope,
    });
    expect(protection.approval).toBe("auto");
    const protectionRead = await engine.client.call("vault.claims.list", {
      subject_ref: protectedId, predicate: "privacy.archive_protection", limit: 10,
    });
    expect(protectionRead.value.some(row => row.value === spec.protected.claimText)).toBe(true);
    const protectedBefore = (await engine.client.call("vault.get", { entity_ref: protectedId })).value;
    // Save the public, credential-nulled archive representation before the mark.
    const storedBefore = exportedRecord(await exportMembers(engine.client), emptyId);
    stage = "cleanup policy and proposal readback";
    await engine.client.request("POST", "/v1/owner/cleanup", spec.cleanup);
    const run = await engine.client.call("vault.cleanup.run", {});
    expect(run.posture).toBe("propose_first");
    expect(run.archived).toEqual([]);
    expect(run.candidates.some(row => row.entity === emptyId)).toBe(true);
    expect(run.candidates.some(row => row.entity === protectedId)).toBe(false);
    if (!run.proposal) throw new Error("Eligible empty PERSON produced no cleanup proposal");
    const review = await engine.client.call("vault.cleanup.review", { proposal: run.proposal });
    const item = review.items.find(row => row.entity === emptyId);
    expect(item?.evidence?.extraction_minted).toBe(true);
    expect(item?.evidence?.live_claims).toBe(0);
    expect(item?.content?.record?.value?.body).toEqual(before?.body);
    stage = "cleanup archive decision and retained-body readback";
    const decided = await engine.client.call("vault.cleanup.decide", {
      proposal: run.proposal, expected_revision: review.revision,
      choices: review.items.map(row => ({ slot: row.slot,
        decision: row.entity === emptyId ? "accept" : "reject" })),
    });
    expect(decided.items.find(row => row.entity === emptyId)?.outcome).toBe("archived");
    expect((await engine.client.call("vault.get", { entity_ref: emptyId })).value).toBeNull();
    expect((await engine.client.call("vault.get", { entity_ref: protectedId })).value).toEqual(protectedBefore);
    const archived = await engine.client.request<{ archived: { entity: string; kind: string }[] }>(
      "GET", "/v1/owner/cleanup",
    );
    expect(archived.body.archived).toContainEqual(expect.objectContaining({ entity: emptyId, kind: "record" }));
    expect(archived.body.archived.some(row => row.entity === protectedId)).toBe(false);
    const storedArchived = exportedRecord(await exportMembers(engine.client), emptyId);
    expect(storedArchived.body).toEqual(storedBefore.body); // Same ID and retained body, not just a count.
    // Author the resolver's actual confidence CLAIM only after the archive.
    // Putting it on the empty PERSON before the pass would protect that PERSON.
    stage = "resolver-confidence claim while archived";
    const evidence = await engine.client.call("vault.claims.upsert", {
      subject_ref: emptyId, predicate: "provider.enrichment", value: { provider: "privacy", name: spec.mention },
      confidence: 0.99, source: "user_stated", scope,
    });
    expect(evidence.approval).toBe("auto");
    if (!evidence.claim) throw new Error("Mention confidence claim has no typed record ref");
    const evidenceRead = await engine.client.call("vault.get", { entity_ref: evidence.claim.id });
    expect(evidenceRead.value?.kind).toBe("CLAIM");
    expect(object(evidenceRead.value?.body).val).toEqual({ provider: "privacy", name: spec.mention });
    expect((await engine.client.call("vault.get", { entity_ref: emptyId })).value).toBeNull();
    const stillArchived = await engine.client.request<{ archived: { entity: string }[] }>(
      "GET", "/v1/owner/cleanup",
    );
    expect(stillArchived.body.archived.some(row => row.entity === emptyId)).toBe(true);
    stage = "mention restoration and no-erasure readbacks";
    const mention = await engine.client.call("vault.entities.mention", {
      candidates: [{ subject: emptyId, confidence_claim_ref: evidence.claim.id }],
    });
    expect(mention.selected).toBe(emptyId);
    expect(mention.route).toBe("hard_link");
    expect(mention.claims_suppressed).toBe(0);
    expect((await engine.client.call("vault.get", { entity_ref: emptyId })).value?.body).toEqual(before?.body);
    const after = await people(engine.client);
    expect(after.filter(row => row.name === spec.mention).map(row => row.person)).toEqual([emptyId]);
    expect((await engine.client.call("vault.get", { entity_ref: protectedId })).value).toEqual(protectedBefore);
    const receipts = await allReceipts(engine.client);
    expect(receipts.filter(row => /delete|erase/i.test([row.kind, row.outcome, ...row.reason_codes].join(" "))))
      .toEqual([]);
    expect(providers.seenFixtureCalls.filter(call => call.fixtureId === "eligible-people")).toHaveLength(1);
  } catch (error) {
    primaryFailed = true;
    primary = error instanceof PublicHttpError
      ? new Error(`PRIVACY-01 ${stage}: status=${error.reply.status} code=${error.error?.code ?? "<none>"} message=${error.error?.message ?? "<none>"} suggestion=${error.error?.suggestions?.[0] ?? "<none>"}`, { cause: error })
      : new Error(`PRIVACY-01 ${stage}: ${errorText(error)}`, { cause: error });
  } finally {
    const cleanups: string[] = [];
    try { await engine?.close(); } catch (error) { cleanups.push(errorText(error)); }
    try { await providers.close(); } catch (error) { cleanups.push(errorText(error)); }
    if (primaryFailed) {
      if (cleanups.length) throw new Error(`${errorText(primary)}; cleanup: ${cleanups.join("; ")}`);
      throw primary;
    }
    if (cleanups.length) throw new Error(`cleanup: ${cleanups.join("; ")}`);
  }
});

// PRIVACY-02. The source is a real conversation containing a witnessed TURN.
// Its name drives phonetic indexing; the production extractor and Dreamer
// create the dependent CLAIM and SUMMARY, with their real source-version pins.
suite.test(test, "PRIVACY-02", "Hard erase across public reads should work", async () => {
  const catalog = await loadFixtures();
  const data = await catalog.readJson<{ hardErase: {
    sourceText: string; claimText: string; summaryText: string; unrelatedText: string;
    phoneticName: string; phoneticQuery: string;
    vectorTable: { dimensions: number; source: number[]; claim: number[]; summary: number[];
      unrelated: number[]; query: number[] };
    expected: { historicalSweepMaxSeconds: number };
  } }>("privacy-scenarios");
  const spec = data.hardErase;
  const forbidden = [spec.sourceText, spec.claimText, spec.summaryText, spec.phoneticName];
  redactor.add(...forbidden, spec.unrelatedText);
  const providers = await ScriptedProviders.start({ id: "privacy-erase", steps: [{
    id: "source-claim", origin: "extraction", role: "extraction_teacher", purpose: "extract cited location",
    request: { method: "POST", path: "/v1/chat/completions", model: "privacy-extract", system: extractionPrompt.system }, barrier: "extract",
    response: openaiText("source-claim", "privacy-extract", JSON.stringify({
      persons: [{ id: "new:P1", name: "Mira", evidence_turn_refs: ["T1"] }],
      candidates: [{ subject: "new:P1", predicate: "privacy.location", value: spec.claimText,
        confidence: 0.95, evidence_refs: [{ source: "T1", quote: spec.sourceText }] }],
    }), { inputTokens: 128, outputTokens: 96 }),
  }, {
    // G6 exact source contract (FIX21902 closure, Engine 12:03). P02 authors
    // one TURN via a single vault.witness with one visible text message
    // (sourceText); ownerRoom/claims/summaries create no TURNs. sourceText =
    // "privacyeraseaurelium: Mira keeps the cobalt notebook at the north
    // observatory." Sieve over it (RULES_VERSION 1, no saved oneiroNER tags
    // in a fresh vault): leading marker lowercase so no capitalized run;
    // ':' never opens a sentence (words.rs:90-92 opens_next only .!? newline
    // and JP); "Mira" is the sole capitalized non-stop word (words.rs:17-70
    // NOT_NAMES, 222-229 capitalized), mid-sentence (opens false) so
    // RuleClass::Name (words.rs:268-272), not InitialName; no numbers/months
    // /weekdays/phrases so no Absolute/Relative/VagueDate; no katakana
    // U+30A1-30FA runs (words.rs:283-317); no backticks/fences so no code
    // exclusion. Exactly one RuleSpan. read.rs:273-287 maps non-date
    // RuleClass without saved tags to SpanKind::Name (snake_case date|name,
    // sieve/mod.rs); policy sieve_policy_defaults.json gives name_confidence
    // 70, uncertain [35,75), so band Uncertain, owed [Novelty, Typing]
    // (read.rs:371-374), score 7000. Caller is the batched follower on the
    // extraction route, not a per-span novelty rung: follower_enabled
    // defaults true (recipe_policy_defaults.json); follower_attempt/mod.rs:
    // 165-172 resolves DREAMER_EXTRACTION_ROLE (roles.rs:30
    // ExtractionTeacher) and factory.rs:492-507 lends that model's window;
    // narrative DreamerCurrent stays separate (factory.rs:480-487,
    // roles.rs:34). dreamerConfig binds extraction_teacher to
    // privacy:privacy-extract (origin extraction) and dreamer_current to
    // summary:privacy-summary (origin summary), so origin extraction + role
    // extraction_teacher + model privacy-extract is exact; no remap. Suffix
    // numbers owed readable spans from 1 (request.rs:70-76 span index+1), so
    // the real question asks exactly span 1. WireReadings
    // (follower_attempt/output.rs:18-35 deny_unknown_fields) requires exactly
    // one reading per asked span in order; decode rejects omissions, repeats,
    // unknown spans, out-of-candidate entities and confidence>100 (:40-81).
    // Response readings [{span:1,kind:"name",novel:true,confidence:50}] is
    // lawful: span exists, kind matches Name, novel true = new info worth
    // retaining (follower_instruction), confidence 50 in 0..100, entity
    // omitted (optional; P-labels runtime-assigned per request.rs:49-59,
    // inventing one would be speculative). Strict errors preserved; observed
    // second failed send is the same digest retried (durable step), not two
    // independent responses. No source contract changed.
    id: "source-follower", origin: "extraction", role: "extraction_teacher",
    purpose: "consolidation follower span readings",
    request: { method: "POST", path: "/v1/chat/completions", model: "privacy-extract" },
    response: openaiText("source-follower", "privacy-extract", JSON.stringify({
      readings: [{ span: 1, kind: "name", novel: true, confidence: 50 }],
    }), { inputTokens: 128, outputTokens: 32 }),
  }, {
    // FIX 22183: the consolidation pass re-extracts the source with P2 Mira
    // and claim C1 listed (one durable step; its two failed sends were two
    // ladder passes of one generate, P22183-CARDINALITY). An empty reply is
    // lawful (wire.rs contract_reply) and writes nothing; a restatement citing
    // C1 would meet resources/write.rs "claim evidence cannot support itself".
    id: "source-reextract", origin: "extraction", role: "extraction_teacher",
    purpose: "consolidation re-extraction of the listed source claim",
    request: { method: "POST", path: "/v1/chat/completions", model: "privacy-extract", system: extractionPrompt.system },
    response: openaiText("source-reextract", "privacy-extract", JSON.stringify({ candidates: [] }),
      { inputTokens: 128, outputTokens: 16 }),
  }, {
    // The extracted person's roster About producer shares the narrative origin,
    // but is not the declared source SUMMARY. R36's captured rejected bodies
    // carried this prompt with no response_format; answer separately and strictly.
    id: "source-person-about", origin: "summary", role: "dreamer_current", purpose: "summarize extracted person for roster About",
    standing: true,
    request: { method: "POST", path: "/v1/chat/completions", model: "privacy-summary", system: PERSON_ABOUT_PROMPT },
    response: openaiText("source-person-about", "privacy-summary", "Mira has a stated fact.",
      { inputTokens: 128, outputTokens: 16 }),
  }, {
    id: "source-summary", origin: "summary", role: "dreamer_current", purpose: "summarize declared source",
    standing: true,
    request: { method: "POST", path: "/v1/chat/completions", model: "privacy-summary", system: SUMMARY_PROMPT, fields: { response_format: { type: "json_schema" } } },
    response: openaiText("source-summary", "privacy-summary", JSON.stringify({ text: spec.summaryText, keep: "" }),
      { inputTokens: 128, outputTokens: 48 }),
  }, ...backgroundExtraction("privacy-extract", ["follower_instruction"])] });
  let engine: EngineFixture | undefined;
  let primaryFailed: boolean = false;
  let primary: unknown;
  try {
    engine = await EngineFixture.start({ id: "PRIVACY-02", profile,
      initArgs: ["--dimensions", String(spec.vectorTable.dimensions)], serverConfig: dreamerConfig(providers, true) });
    await grantExtraction(engine);
    const source = await ownerRoom(engine, spec.sourceText, spec.phoneticName);
    const witnessed = await engine.client.call("vault.witness", turn(source.id, spec.sourceText));
    const sourceTurn = turnId(witnessed);
    const extracted = await extract(engine, sourceTurn, providers);
    const dependent = extracted.filter(row => row.claim.predicate === "privacy.location"
      && row.claim.value === spec.claimText);
    expect(dependent).toHaveLength(1);
    const claim = dependent[0]!;
    expect(claim.claim.source).toBe("generated");
    expect(claim.sources.some(pin => pin.source_ref === sourceTurn)).toBe(true);
    for (const pin of claim.sources) {
      expect(pin.content_hash).toMatch(/^[a-f0-9]{64}$/);
      expect(pin.messages.length).toBeGreaterThan(0);
      for (const message of pin.messages) {
        expect(message.revision).toMatch(/^[a-f0-9]{64}$/);
        expect(message.byte_range[1]).toBeGreaterThan(message.byte_range[0]);
      }
    }
    // DEFECT (2026-11-10, FIX DREAMER-STAMP-FACET): the SUMMARY birth parks with "summary landing
    // refused: invalid active facet": actor_stamp_in_txn (provenance/actor_stamp.rs) and bind_peer
    // (typed_body.rs) build their bookkeeping CLAIM with ClaimBody::new, whose scope facet is the
    // subject's PERSON substrate facet, and the Dreamer is a MACHINE with no such FACET. PRIVACY-02
    // stays red at this wait until both writers take the vault default facet.
    const queued = await engine.client.call("vault.summaries.create", {
      scope: { conversation_ref: source.id, path: "canonical" },
    });
    const completed = await awaitPublic(
      () => engine!.client.call("vault.summaries.status", { attempt: queued.attempt }),
      value => value.state === "completed", { label: "source-linked SUMMARY" },
    );
    if (!completed.result) throw new Error("Completed summary has no result");
    const summaryId = completed.result.summary;
    const summary = await engine.client.call("vault.summaries.read", { summary_ref: summaryId });
    expect(summary.value?.text).toBe(spec.summaryText);
    expect(summary.value?.covers).toContain(sourceTurn);
    expect(summary.value?.metadata.derivation.sources.some(pin => pin.id === sourceTurn)).toBe(true);
    const scope = await ownerBaseClaimScope(engine.client, engine.pairedActor.principalRef);
    const controlRoom = await ownerRoom(engine, spec.unrelatedText, "Copper Telescope");
    const unrelated = await engine.client.call("vault.claims.upsert", {
      subject_ref: controlRoom.id, predicate: "privacy.unrelated_control",
      value: spec.unrelatedText, confidence: 1, source: "user_stated", scope,
    });
    expect(unrelated.approval).toBe("auto");
    if (!unrelated.claim) throw new Error("Unrelated control has no typed record ref");
    const controlId = unrelated.claim.id;
    const targets = [source.id, claim.claim.claim_ref, summaryId];
    for (const [entity_ref, vector] of [
      [source.id, spec.vectorTable.source], [claim.claim.claim_ref, spec.vectorTable.claim],
      [summaryId, spec.vectorTable.summary], [controlId, spec.vectorTable.unrelated],
    ] as const) await engine.client.call("vault.vectors.put", { entity_ref, vector: [...vector] });
    const sourceRow = (await engine.client.call("vault.get", { entity_ref: source.id })).value;
    const claimRow = (await engine.client.call("vault.get", { entity_ref: claim.claim.claim_ref })).value;
    const summaryRow = (await engine.client.call("vault.get", { entity_ref: summaryId })).value;
    if (!sourceRow?.short_ref || !claimRow?.short_ref || !summaryRow?.short_ref) {
      throw new Error("Created erase targets have no public short refs");
    }
    const hydratedBefore = await engine.client.call("vault.hydrate", { refs: [...targets, controlId] });
    for (const id of [...targets, controlId]) expect(hydratedBefore.value.map(row => row.id_hex)).toContain(id);
    for (const row of [sourceRow, claimRow, summaryRow]) {
      expect((await engine.client.call("vault.refs.resolve", { reference: row.short_ref! })).value.record.id)
        .toBe(row.id_hex);
    }
    const controlLexical = { query: spec.unrelatedText.split(":")[0]!, limit: 100 };
    expect((await engine.client.call("vault.search.bm25", controlLexical)).value
      .some(hit => hit.record?.id === controlId || hit.short_id === unrelated.claim_short_id)).toBe(true);
    const lexicalQueries = [spec.sourceText.split(":")[0]!, spec.claimText.split(":")[0]!,
      spec.summaryText.split(":")[0]!];
    for (const [index, query] of lexicalQueries.entries()) {
      const hits = await engine.client.call("vault.search.bm25", { query, limit: 100 });
      expect(hits.value.some(hit => hit.record?.id === targets[index]
        || hit.short_id === [sourceRow, claimRow, summaryRow][index]!.short_ref)).toBe(true);
    }
    const vectorBefore = await engine.client.call("vault.search.vector", { query: spec.vectorTable.query, limit: 100 });
    for (const id of targets) expect(vectorBefore.value.hits.map(hit => hit.entity_ref)).toContain(id);
    // Standard English Soundex, authored from Selina/Saleena Aurelium: S-L-N-R => S456.
    // Only the public index key prefix is a transport binding, not an oracle.
    expect(spec.phoneticName).toBe("Selina Aurelium");
    expect(spec.phoneticQuery).toBe("Saleena Aurelium");
    const phonetic = { phonetic_codes: ["en:soundex:S456"], limit: 100 } satisfies FacadeInput<"vault.search.hybrid">;
    expect((await engine.client.call("vault.search.hybrid", phonetic)).value.map(hit => hit.entity_ref)).toContain(source.id);
    // The unrelated room's independently named control has Soundex C163.
    const controlPhonetic = { phonetic_codes: ["en:soundex:C163"], limit: 100 };
    expect((await engine.client.call("vault.search.hybrid", controlPhonetic)).value.map(hit => hit.entity_ref))
      .toContain(controlRoom.id);
    expect((await engine.client.call("vault.search.vector", { query: spec.vectorTable.unrelated, limit: 100 }))
      .value.hits.map(hit => hit.entity_ref)).toContain(controlId);
    const hybrid = { ...phonetic, query: lexicalQueries.join(" "), query_vector: spec.vectorTable.query };
    const hybridBefore = await engine.client.call("vault.search.hybrid", hybrid);
    for (const id of targets) expect(hybridBefore.value.map(hit => hit.entity_ref)).toContain(id);
    const packBefore = await engine.client.call("vault.recall", { query: "cobalt notebook", effort: "light", limit: 100 });
    expect(packBefore.items.some(item => item.value_text.includes(spec.claimText))).toBe(true);
    expect((await engine.client.call("vault.neighbors", { entity_ref: source.id, opts: { limit: 100 } })).value.length)
      .toBeGreaterThan(0);
    await engine.mcp.initialize();
    const tools = await engine.mcp.request<McpTools>("tools/list");
    expect(JSON.stringify(await mcpRead(engine.mcp, tools, "vault.get", { entity_ref: source.id }))).toContain(spec.sourceText);
    const mcpHydrateBefore = await mcpRead(engine.mcp, tools, "vault.hydrate", { refs: [...targets, controlId] });
    expect(JSON.stringify(mcpHydrateBefore)).toContain(spec.sourceText);
    expect(JSON.stringify(mcpHydrateBefore)).toContain(spec.unrelatedText);
    expect(JSON.stringify(await mcpRead(engine.mcp, tools, "vault.recall", {
      query: "cobalt notebook", effort: "light", limit: 100,
    }))).toContain(spec.claimText);
    const exportedBefore = await exportText(engine.client);
    for (const text of [...forbidden, spec.unrelatedText]) expect(exportedBefore.includes(text)).toBe(true);
    expect((await engine.client.call("vault.recall", { query: "privacyeraseunrelated", effort: "light", limit: 100 }))
      .items.some(item => item.value_text.includes(spec.unrelatedText))).toBe(true);
    const controlNeighbors = (await engine.client.call("vault.neighbors", { entity_ref: controlId, opts: { limit: 100 } })).value;
    expect(controlNeighbors.length).toBeGreaterThan(0);
    const controlBefore = (await engine.client.call("vault.get", { entity_ref: controlId })).value;
    expect(controlBefore).not.toBeNull();
    const receipt = await eraseRecord(engine.client, source.id);
    expect(receipt.state).toBe("applied");
    // No poll, receipt read or sweep may precede any of these active-store reads.
    const allIds = [...targets, sourceTurn, ...(witnessed.messages ?? []).map(row => row.id)];
    for (const entity_ref of allIds) {
      expect((await engine.client.call("vault.get", { entity_ref })).value).toBeNull();
    }
    await expectHydrateGone(engine.client, allIds, forbidden);
    for (const query of lexicalQueries) {
      expect((await engine.client.call("vault.search.bm25", { query, limit: 100 })).value).toEqual([]);
    }
    const vectorAfter = await engine.client.call("vault.search.vector", { query: spec.vectorTable.query, limit: 100 });
    for (const id of allIds) expect(vectorAfter.value.hits.map(hit => hit.entity_ref)).not.toContain(id);
    expect((await engine.client.call("vault.search.hybrid", phonetic)).value).toEqual([]);
    for (const spec of [hybrid, { query: "cobalt notebook", limit: 100 }]) {
      const hits = await engine.client.call("vault.search.hybrid", spec);
      for (const id of allIds) expect(hits.value.map(hit => hit.entity_ref)).not.toContain(id);
      excludes(hits, forbidden);
    }
    const packAfter = await engine.client.call("vault.recall", { query: "cobalt notebook", effort: "light", limit: 100 });
    excludes(packAfter, forbidden);
    for (const id of allIds) expect(packAfter.items.map(item => item.record?.id)).not.toContain(id);
    expect((await engine.client.call("vault.neighbors", { entity_ref: source.id, opts: { limit: 100 } })).value).toEqual([]);
    for (const row of [sourceRow, claimRow, summaryRow]) {
      await expectReferenceGone(engine.client, row.short_ref!, forbidden);
    }
    for (const [name, spec] of [
      ["vault.get", { entity_ref: source.id }],
      ["vault.recall", { query: "cobalt notebook", effort: "light", limit: 100 }],
    ] as const) excludes(await mcpRead(engine.mcp, tools, name, spec), forbidden);
    await expectMcpHydrateGone(engine.mcp, tools, allIds, forbidden);
    expect((await engine.client.call("vault.get", { entity_ref: controlId })).value).toEqual(controlBefore);
    expect((await engine.client.call("vault.recall", { query: "privacyeraseunrelated", effort: "light", limit: 100 }))
      .items.some(item => item.value_text.includes(spec.unrelatedText))).toBe(true);
    expect((await engine.client.call("vault.search.vector", { query: spec.vectorTable.unrelated, limit: 100 }))
      .value.hits.map(hit => hit.entity_ref)).toContain(controlId);
    expect((await engine.client.call("vault.search.hybrid", controlPhonetic)).value.map(hit => hit.entity_ref))
      .toContain(controlRoom.id);
    expect((await engine.client.call("vault.search.bm25", controlLexical)).value
      .some(hit => hit.record?.id === controlId || hit.short_id === unrelated.claim_short_id)).toBe(true);
    expect((await engine.client.call("vault.neighbors", { entity_ref: controlId, opts: { limit: 100 } })).value)
      .toEqual(controlNeighbors);
    expect(JSON.stringify(await mcpRead(engine.mcp, tools, "vault.get", { entity_ref: controlId })))
      .toContain(spec.unrelatedText);
    const exported = await exportText(engine.client);
    excludes(exported, forbidden);
    expect(exported.includes(spec.unrelatedText)).toBe(true);
    await readAudit(engine.client, receipt.receipt_ref, source.id, forbidden);
    if (!receipt.receipt_ref) throw new Error("Erase has no redaction receipt");
    const sweep = await engine.client.call("vault.records.erase_sweep", { receipt_ref: receipt.receipt_ref });
    if (!sweep || sweep.deadline_at == null || sweep.sweep_queued_at == null) {
      throw new Error("Erase has no recorded historical-sweep deadline and queue time");
    }
    expect(sweep.deadline_at).toBeGreaterThanOrEqual(sweep.requested_at);
    expect(sweep.deadline_at - sweep.requested_at).toBeLessThanOrEqual(spec.expected.historicalSweepMaxSeconds);
    await finishHistoricalSweep(engine);
    expect(providers.seenFixtureCalls.filter(call => call.fixtureId === "source-claim")).toHaveLength(1);
    expect(providers.seenFixtureCalls.filter(call => call.fixtureId === "source-person-about").length).toBeGreaterThanOrEqual(1);
    expect(providers.seenFixtureCalls.filter(call => call.fixtureId === "source-summary").length).toBeGreaterThanOrEqual(1);
    expect(providers.seenFixtureCalls.filter(call => call.fixtureId === "source-summary").every(call => (call.body as any)?.response_format?.json_schema?.schema?.required?.join(",") === "text,keep")).toBe(true);
  } catch (error) {
    primaryFailed = true;
    primary = error;
  } finally {
    const cleanups: string[] = [];
    // Capture the real summary wire body before provider cleanup. The standing
    // matcher stays strict; this artifact makes any mismatching field visible.
    try { await engine?.artifacts.json("diagnostic-privacy-02-provider-calls.json", { seen: providers.seenFixtureCalls }); }
    catch (error) { cleanups.push(errorText(error)); }
    try { await engine?.close(); } catch (error) { cleanups.push(errorText(error)); }
    try { await providers.close(); } catch (error) { cleanups.push(errorText(error)); }
    if (primaryFailed) {
      if (cleanups.length) throw new Error(`${errorText(primary)}; cleanup: ${cleanups.join("; ")}`);
      throw primary;
    }
    if (cleanups.length) throw new Error(`cleanup: ${cleanups.join("; ")}`);
  }
});

// PRIVACY-03. ARCH-0038 #harderase-v1 and ARCH-0023b #two-planes.
// Keep the whole replay/erasure oracle, using the real public flow ruled by
// Engine 2026-11-07 07:36 JST: pair a machine link, device enrol B as a copy of
// A's vault, and serve receiver B. Back up B before erasure, sync the genuine
// source and document forks, disconnect B, then erase at A. Restore B's
// pre-erase backup and sync again to exercise replay of its stale state.
// Observe rows still owed to home and their Durable/Held receipts through
// vault.sync.outbox, not a test-only capture endpoint. Source and every fork
// must stay absent on both peers before and after restart. No raw WS
// counterfeit, independent-vault substitute, or private storage edits.
// Pending door (Engine CORE-FOUR-SKIPS = A): vault.sync.outbox is missing. Empty-vault enrolment
// exists now (device enrol; EngineFixture.startDevicePeer). This file's one slot remains unchanged.
suite.pendingDoor(test, "PRIVACY-03",
  "waits on vault.sync.outbox, a typed public read of the rows a device still owes its home with their Durable/Held ACK state. Erasure resists offline replay should work",
  { fix: "FIX 22500", deadline: "2026-12-01" });

suite.test(test, "PRIVACY-04", "Shared blobs survive one record erasure should work", async () => {
  const catalog = await loadFixtures();
  const data = await catalog.readJson<PrivacyFixtures>("privacy-scenarios");
  const versions = await Promise.all(data.sharedBlobs.versions.map(id => catalog.readArchive(id)));
  for (const bytes of versions) redactor.add(new TextDecoder().decode(bytes));
  const engine = await EngineFixture.start({ id: "PRIVACY-04", profile });
  let primaryFailed: boolean = false;
  let primary: unknown;
  try {
    await engine.requireHttpDoor("/v1/owner/maintain", "POST");
    // Two independent records upload both versions, not an alias of A's handle.
    const a = await uploadVersions(engine.client, data.sharedBlobs.names[0], versions);
    const b = await uploadVersions(engine.client, data.sharedBlobs.names[1], versions);
    expect(a.id_hex).not.toBe(b.id_hex);
    const preview = await engine.client.call("vault.records.erase_preview", { record: a.id_hex });
    expect(preview.same_bytes).toContain(b.id_hex);
    expect(preview.held_bytes).toHaveLength(versions.length);
    for (const holder of preview.held_bytes) expect(holder.other_holders).toContain(b.id_hex);

    const erasedA = await eraseRecord(engine.client, a.id_hex);
    // Active removal is synchronous; no sweep or observation loop precedes it.
    expect((await engine.client.call("vault.get", { entity_ref: a.id_hex })).value).toBeNull();
    for (const [index, expectedBytes] of versions.entries()) {
      await expectBlobGone(engine.client, a.id_hex, index + 1);
      const copy = await engine.client.call("vault.artifacts.read", {
        artifact_ref: b.id_hex, version: index + 1,
      });
      expect(copy).not.toBeNull();
      const bytes = Buffer.from(copy!.content_base64, "base64");
      const facts = catalog.expected<{ byteLength: number; sha256: string }>(data.sharedBlobs.versions[index]!);
      expect(bytes.byteLength).toBe(facts.byteLength);
      expect(createHash("sha256").update(bytes).digest("hex")).toBe(facts.sha256);
    }
    const narrow = await engine.pairActor({
      principalRef: engine.pairedActor.principalRef, actorClass: "human", scope: ["core:propose"],
    });
    const readInput = { artifact_ref: b.id_hex, version: 1 } satisfies FacadeInput<"vault.artifacts.read">;
    const denied = await narrow.client.raw("POST", "/v1/core/facade/vault.artifacts.read", readInput);
    expect(denied.status).toBe(403); // A surviving reference is not an auth bypass.
    const erasedB = await eraseRecord(engine.client, b.id_hex);
    expect((await engine.client.call("vault.get", { entity_ref: b.id_hex })).value).toBeNull();
    const forbidden = [...data.sharedBlobs.names, ...versions.map(bytes => new TextDecoder().decode(bytes))];
    await readAudit(engine.client, erasedA.receipt_ref, a.id_hex, forbidden);
    await readAudit(engine.client, erasedB.receipt_ref, b.id_hex, forbidden);
    await finishHistoricalSweep(engine);
    for (const record of [a, b]) {
      for (const [index] of versions.entries()) {
        await expectBlobGone(engine.client, record.id_hex, index + 1);
      }
    }
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

suite.test(test, "PRIVACY-05", "Legal hold narrows delete should work", async () => {
  const catalog = await loadFixtures();
  const data = await catalog.readJson<PrivacyFixtures>("privacy-scenarios");
  const spec = data.legalHold;
  const bytes = await catalog.readArchive("privacy-blob-v1");
  redactor.add(new TextDecoder().decode(bytes));
  const engine = await EngineFixture.start({ id: "PRIVACY-05", profile });
  let primaryFailed: boolean = false;
  let primary: unknown;
  try {
    const record = await uploadVersions(engine.client, spec.name, [bytes]);
    const hold = await engine.client.call("vault.legal_holds.place", {
      targets: [{ record: record.id_hex }], matter_ref: spec.matterRef,
    });
    expect(hold.kind).toBe(spec.expected.kind);
    expect(hold.targets).toEqual([{ record: record.id_hex }]);
    expect(hold.lifted_at ?? null).toBeNull();
    const preview = await engine.client.call("vault.records.erase_preview", { record: record.id_hex });
    const eraseInput = {
      record: record.id_hex, preview_digest: preview.preview_digest, also_same_bytes: false,
    } satisfies FacadeInput<"vault.records.erase_confirm">;
    const refusal = await engine.client.raw<{ error: { code: string } }>(
      "POST", "/v1/core/facade/vault.records.erase_confirm", eraseInput,
    );
    expect(refusal.status).toBeGreaterThanOrEqual(400);
    expect(refusal.status).toBeLessThan(500);
    expect(refusal.body.error.code.length).toBeGreaterThan(0);
    expect((await engine.client.call("vault.get", { entity_ref: record.id_hex })).value).not.toBeNull();
    const kept = await engine.client.call("vault.artifacts.read", { artifact_ref: record.id_hex, version: 1 });
    expect(kept?.content_base64).toBe(Buffer.from(bytes).toString("base64"));

    // The refusal's public hold-log receipt names the applicable hold and
    // target. It must not quote the held content. Do not match error prose.
    const events = await engine.client.call("vault.legal_holds.log", {});
    const refused = events.filter(event => event.event === spec.expected.refusalEvent);
    expect(refused.some(event => event.hold_id === hold.hold_id
      && event.reason === spec.expected.refusalReason
      && event.targets.some(target => "record" in target && target.record === record.id_hex))).toBe(true);
    expect(JSON.stringify(events).includes(new TextDecoder().decode(bytes))).toBe(false);
    expect(JSON.stringify(events).includes(spec.name)).toBe(false);

    const narrow = await engine.pairActor({
      principalRef: engine.pairedActor.principalRef, actorClass: "human", scope: ["core:read"],
    });
    const standing = await engine.client.call("vault.legal_holds.list", {});
    const shown = standing.find(row => row.hold_id === hold.hold_id);
    if (!shown) throw new Error("Placed hold is not standing");
    const liftInput = {
      records: [record.id_hex],
      shown_state: {
        title: "Lift the hold and erase?",
        prompt: "This lifts your hold and erases these records. It does not end any legal duty to keep them. This choice is recorded.",
        records: [record.id_hex],
        holds: [{
          hold_id: shown.hold_id, targets: shown.targets, placed_by: shown.placed_by ?? null,
          placed_at: shown.placed_at, matter_ref: shown.matter_ref ?? null,
        }],
      },
    } satisfies FacadeInput<"vault.legal_holds.lift_and_erase">;
    const denied = await narrow.client.raw("POST", "/v1/core/facade/vault.legal_holds.lift_and_erase", liftInput);
    expect(denied.status).toBe(spec.expected.unprivilegedLiftStatus);
    const stillHeld = await engine.client.call("vault.legal_holds.list", {});
    expect(stillHeld.find(row => row.hold_id === hold.hold_id)?.lifted_at ?? null).toBeNull();
    expect((await engine.client.call("vault.get", { entity_ref: record.id_hex })).value).not.toBeNull();

    // The later LEGAL-HOLD=B ruling requires one owner confirm that lifts
    // AND retries the erase, not an unrestricted stand-alone revoke call.
    const erased = await engine.client.call("vault.legal_holds.lift_and_erase", liftInput);
    expect(erased.holds).toContain(hold.hold_id);
    expect(erased.records).toHaveLength(1);
    expect(erased.records[0]?.record).toBe(record.id_hex);
    // Confirmation is not completion (G5 FIX21902 closure): immediate may be
    // erased (completed at once, fixture ownerEraseState via
    // readJson("privacy-scenarios")) or completion_pending (confirmed, sweep
    // or custody still retiring). Typed in verbs/legal_hold.rs:63-82;
    // pending reasons exhaustive in deletion/legal_hold/types.rs:295-306.
    // Accept confirmed, fail fast on failed, then observe final completion
    // through erase_sweep. 10s poll + instant asserts below unchanged.
    const status = erased.records[0]!.status;
    if (status.state === "failed") throw new Error(`Owner confirm failed: ${status.message}`);
    expect(status.state === spec.expected.ownerEraseState || status.state === "completion_pending").toBe(true);
    if (status.state === "completion_pending" && status.reason != null) {
      expect(["historical_sweep", "custody_retirement", "veto_window"]).toContain(status.reason);
    }
    const receiptRef = status.receipt_ref;
    if (!receiptRef) throw new Error("Confirmed erase has no redaction receipt");
    expect((await engine.client.call("vault.get", { entity_ref: record.id_hex })).value).toBeNull();
    await expectBlobGone(engine.client, record.id_hex, 1);
    const after = await engine.client.call("vault.legal_holds.log", {});
    expect(after.some(event => event.hold_id === hold.hold_id
      && event.event === spec.expected.confirmEvent
      && event.actor_ref === engine.pairedActor.principalRef
      && event.actor_kind === "owner")).toBe(true);
    const lifted = (await engine.client.call("vault.legal_holds.list", {}))
      .find(row => row.hold_id === hold.hold_id);
    expect(lifted?.lifted_at).toBeGreaterThanOrEqual(hold.placed_at);
    // G-ERASE-DRIVER (FIX21914): force the existing historical sweep before
    // polling completion; status polling alone never triggers it.
    await finishHistoricalSweep(engine);
    const sweep = await awaitPublic(
      () => engine.client.call("vault.records.erase_sweep", { receipt_ref: receiptRef }),
      value => value != null && value.erase_complete_at != null && value.final_ref != null,
      { label: "held-record erase completion" },
    );
    if (!sweep || sweep.erase_complete_at == null || sweep.final_ref == null) {
      throw new Error("Held-record erase did not reach final completion");
    }
    expect(sweep.custody?.pending ?? []).toEqual([]);
    await readAudit(engine.client, receiptRef, record.id_hex,
      [spec.name, new TextDecoder().decode(bytes)]);
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

// PRIVACY-06. ARCH-0052 #target, ARCH-0032 #writers and ARCH-0069 #handles.
// Session-bound start/witness/notes.create/claims.upsert/recall/discard now
// have generated HTTP+SDK types. self.off_record.execute genuinely owns a
// session-bound production code run; an unowned self.run.attach is not setup.
// Keep durable base + overlay union reads, an actual spilling MCP output,
// and decoded full export and backup while the overlay is LIVE: neither
// carrier may contain overlay/spill bytes. No note-only discard substitute.
// Engine 2026-11-07 07:36 JST replaces the capture-door premise with real
// public flows: pair a machine link, device enrol and serve receiver B;
// back up B, sync, erase at A, restore B's pre-erase backup and sync again.
// Observe ACK state through vault.sync.outbox. While A's overlay is LIVE,
// read A's actual overlay and spill ids FROM B and expect nothing, while
// proving base sync works. No test-only capture door or independent vault.
// Close without saving, restart, then prove session-not-found, absent overlay
// bodies/receipts/spill handles and unchanged durable memory. No floor event
// is provoked, so no floor-receipt exception applies here.
// Pending door (Engine CORE-FOUR-SKIPS = A): vault.sync.outbox is missing; empty-vault enrolment
// exists now. No weakening of the privacy oracle.
suite.pendingDoor(test, "PRIVACY-06",
  "waits on vault.sync.outbox, a typed public read of the rows a device still owes its home with their Durable/Held ACK state; the session write/read/execute doors and device enrolment exist. Off-record session discard should work",
  { fix: "FIX 22500", deadline: "2026-12-01" });

// PRIVACY-07. ARCH-0052 #d5-notice/#d5-save-grant, ARCH-0040 #mcp-actor-ceilings.
// E2E-PARTIAL (Engine 23:01): the person-holder subset. One personal-vault room with three real
// credentials on the initial roster: the owner (a person holder), a propose-only agent and a human
// guest with no save grant. A suggestion or a decline saves nothing; the guest and the proposer are
// refused both save forms; the holder saves whole visible turns, saves a later turn, and saves from
// here; hidden reasoning, the temporary summary and out-of-window speech never reach the vault. The
// owner then leaves the room live (vault.rooms.leave): the next landing stays off record and
// saving_stopped names the act; rejoining alone does not resume saving, and only a new save from here
// starts a new saving period. The base is read after each boundary through the full-vault export, the
// guest's own export carries what it sat through, and the notices are content-free {act,by,at}.
// Closing the stretch drops its overlay and its notices.
// Unproved here: a vault agent as a second save holder. `token agent` mints a PERSON with no
// class-agent actor binding, so the save grant refuses it (403), and an AGENT_DEF cannot sit on a
// room roster (FIX row filed with the READY). POST /v1/core/off-record/export works but is not in
// the OpenAPI document, so the case calls it without a door probe (FIX row filed with the READY).
interface PrivacyRoom {
  sessionRef: string; visibleTexts: [string, string]; hiddenText: string; summaryText: string;
  fromHereTexts: [string, string]; afterLossText: string; afterRejoinText: string;
  guestText: string; outOfWindowText: string;
  expected: { noticeActs: string[]; guestSaveStatus: number };
}
type RoomView = FacadeResult<"vault.off_record.rooms.status">;
function noticesOnly(view: RoomView): void {
  for (const notice of view.notices) expect(Object.keys(notice).sort()).toEqual(["act", "at", "by"]);
}
suite.test(test, "PRIVACY-07", "Off-record save from the middle: only a person holder saves, leaving stops saving and rejoining does not resume it", async () => {
  const room = (await (await loadFixtures()).readJson<{ room: PrivacyRoom }>("privacy-scenarios")).room;
  const engine = await EngineFixture.start({ id: "PRIVACY-07", profile,
    serverConfig: "[models.dreamer]\nenabled = false\n[models.workflows]\nenabled = false\n" });
  await engine.requireHttpDoor("/v1/owner/off-record/close", "POST");
  const owner = engine.pairedActor;
  // The propose-only agent is minted on the stopped vault before the stretch exists.
  await engine.client.call("vault.receipts", { limit: 1 });
  await engine.kill();
  const minted = await engine.cli.run(["token", "agent", "--name", "privacy-suggesting-agent", "--tier", "propose-only",
    "--config", resolve(engine.root, "oneiron.toml"), "--out", resolve(engine.root, "privacy-suggesting-agent.credential")],
    undefined, undefined, true);
  expect(minted.exitCode).toBe(0);
  await engine.restart();
  const proposer = await engine.pairActor({ principalRef: (JSON.parse(minted.stdout) as { principal_ref: string }).principal_ref,
    actorClass: "agent", scope: ["core:read", "core:propose"] });
  const setup = await ownerRoom(engine, "Privacy guest evidence");
  const evidence = await engine.client.call("vault.witness", turn(setup.id, "This distinct person is Privacy Human Guest."));
  const person = await engine.client.call("vault.people.create", {
    identity: { name: "Privacy Human Guest" }, identity_evidence_refs: [evidence.turn_id], occurred_at: Math.floor(Date.now() / 1000),
  });
  const guest = await engine.pairActor({ principalRef: person.person.id_hex, actorClass: "human", scope: ["core:read", "core:write"] });
  const members = [owner.principalRef, proposer.principalRef, guest.principalRef];
  expect(new Set(members).size).toBe(3);
  const t0 = Math.floor(Date.now() / 1000) - 10;
  const created = await engine.client.call("vault.conversations.create", {
    occurred_start: t0, occurred_end: t0,
    body: { v: 1, kind: "direct", member_ids: members, title: "Privacy room" },
    text: [{ field: "title", value: "Privacy room" }],
  });
  const q = { room: created.id, session_ref: room.sessionRef };
  const said = (actor: PairedActor, content: string, at = Math.floor(Date.now() / 1000)) =>
    actor.client.call("vault.off_record.rooms.witness", { ...q, turn: { conversation_ref: "", occurred_at: at,
      messages: [{ author: "user", message_type: "text", content, is_visible: true, order: 0 }] } });
  const neverSaved = [room.hiddenText, room.summaryText, room.outOfWindowText];
  const base = async (has: readonly string[], lacks: readonly string[]): Promise<void> => {
    const text = await exportText(owner.client);
    for (const value of has) expect(text.includes(value)).toBe(true);
    for (const value of [...lacks, ...neverSaved]) expect(text.includes(value)).toBe(false);
  };
  const talk = [...room.visibleTexts, room.guestText, ...room.fromHereTexts, room.afterLossText, room.afterRejoinText];
  const saved = [...room.visibleTexts, room.guestText, ...room.fromHereTexts];
  const neverOnRecord = [room.afterLossText, room.afterRejoinText];

  const started = await owner.client.call("vault.off_record.rooms.start", { ...q, backend: "local" });
  expect(started).toMatchObject({ mode: "off_record", room: created.id, closing: false, notices: [], waiting_suggestions: [] });
  await said(owner, room.outOfWindowText, t0 - 1);
  await owner.client.call("vault.off_record.rooms.witness", { ...q, summary: room.summaryText, turn: {
    conversation_ref: "", occurred_at: Math.floor(Date.now() / 1000), messages: [
      { author: "user", message_type: "text", content: room.visibleTexts[0], is_visible: true, order: 0 },
      { author: "user", message_type: "text", content: room.visibleTexts[1], is_visible: true, order: 1 },
    ] } });
  // Hidden reasoning is a companion row in a turn of its own: an invisible `user` row is a malformed
  // envelope (witness_message_body.rs: a user's own words are never invisible), and a TURN has one speaker.
  await owner.client.call("vault.off_record.rooms.witness", { ...q, turn: {
    conversation_ref: "", occurred_at: Math.floor(Date.now() / 1000), messages: [
      { author: "companion", message_type: "reasoning", content: room.hiddenText, is_visible: false, order: 0 },
    ] } });
  // A suggestion and a decline save nothing; neither the guest nor the proposer may save in either form.
  const suggested = await proposer.client.call("vault.off_record.rooms.suggest_save", q);
  expect(suggested.mode).toBe("off_record");
  expect(suggested.waiting_suggestions.map(row => row.by)).toEqual([proposer.principalRef]);
  const declined = await owner.client.call("vault.off_record.rooms.decline_save", q);
  expect(declined.waiting_suggestions).toEqual([]);
  for (const actor of [guest, proposer]) {
    for (const verb of ["save", "save_from_here"] as const) {
      const refused = await actor.client.raw("POST", `/v1/core/facade/vault.off_record.rooms.${verb}`, q);
      expect(refused.status).toBe(room.expected.guestSaveStatus);
      expect((refused.body as { error?: { code?: string } }).error?.code).toBe("FORBIDDEN");
    }
  }
  expect((await guest.client.call("vault.off_record.rooms.status", q)).mode).toBe("off_record");
  await base([], talk);
  // The holder saves the whole visible talk it could see, then the guest's later turn.
  const ownerSave = await owner.client.call("vault.off_record.rooms.save", q);
  expect(ownerSave.saved).toHaveLength(1);
  await base(room.visibleTexts, talk.slice(2));
  await said(guest, room.guestText);
  const guestTurnSave = await owner.client.call("vault.off_record.rooms.save", q);
  expect(guestTurnSave.saved).toHaveLength(1);
  await base([...room.visibleTexts, room.guestText], talk.slice(3));
  // The holder saves from here: later speech lands in the vault as it is said.
  const fromHere = await owner.client.call("vault.off_record.rooms.save_from_here", q);
  expect(fromHere.mode).toBe("on_record");
  await said(guest, room.fromHereTexts[0]);
  await base([...room.visibleTexts, room.guestText, room.fromHereTexts[0]], talk.slice(4));
  // The saver leaves the room live: the next landing stays off record and saving_stopped names the act.
  const left = await owner.client.call("vault.rooms.leave", { room: created.id, person: owner.principalRef });
  expect(left.member_ids).not.toContain(owner.principalRef);
  expect(left.member_ids).toEqual(expect.arrayContaining([proposer.principalRef, guest.principalRef]));
  await said(guest, room.afterLossText);
  const stopped = await guest.client.call("vault.off_record.rooms.status", q);
  expect(stopped.mode).toBe("off_record");
  expect(stopped.notices).toEqual(expect.arrayContaining([expect.objectContaining({ act: "saving_stopped", by: owner.principalRef })]));
  noticesOnly(stopped);
  // Rejoining alone does not resume saving; only a new save from here starts a new saving period.
  const rejoined = await owner.client.call("vault.rooms.join", { room: created.id,
    subject: { kind: "person", id: owner.principalRef }, paid: false, intent_key: "privacy-owner-rejoin-1" });
  expect(rejoined.decision.state).toBe("ready");
  expect(rejoined.receipt_ref).not.toBeNull();
  await said(guest, room.afterRejoinText);
  expect((await guest.client.call("vault.off_record.rooms.status", q)).mode).toBe("off_record");
  expect((await owner.client.call("vault.off_record.rooms.save_from_here", q)).mode).toBe("on_record");
  await said(guest, room.fromHereTexts[1]);
  await base(saved, neverOnRecord);
  // The guest's export carries the visible talk it sat through and writes nothing to the vault.
  const exported = await guest.client.raw("POST", "/v1/core/off-record/export", { ...q, travel: { refs: "preserve" } });
  expect(exported.status).toBe(200);
  expect(exported.headers.get("content-disposition")).toBe('attachment; filename="off-record-talk.json"');
  const exportedBody = JSON.stringify(exported.body);
  for (const text of [...room.visibleTexts, room.guestText, room.afterLossText, room.afterRejoinText, ...room.fromHereTexts])
    expect(exportedBody.includes(text)).toBe(true);
  excludes(exported.body, neverSaved);
  const unsaved = (exported.body as { turns: { saved: boolean; messages: { content: string }[] }[] }).turns
    .filter(row => row.messages.some(message => neverOnRecord.includes(message.content)));
  expect(unsaved.map(row => row.saved)).toEqual([false, false]);
  const final = await guest.client.call("vault.off_record.rooms.status", q);
  const finalActs: string[] = final.notices.map(row => row.act);
  for (const act of room.expected.noticeActs) expect(finalActs).toContain(act);
  expect(final.notices.filter(row => row.act === "saving_from_here").map(row => row.by))
    .toEqual([owner.principalRef, owner.principalRef]);
  expect(final.notices.find(row => row.act === "exported")?.by).toBe(guest.principalRef);
  noticesOnly(final);
  // Closing the stretch drops its overlay; saved turns stay and the notices go with the session.
  await owner.client.request("POST", "/v1/owner/off-record/close", { session_ref: `room:${created.id}:${room.sessionRef}` });
  await base(saved, neverOnRecord);
  const gone = await guest.client.raw("POST", "/v1/core/facade/vault.off_record.rooms.status", q);
  expect(gone.status).toBe(404);
  expect((gone.body as { error?: { code?: string } }).error?.code).toBe("NOT_FOUND");
});

// PRIVACY-08. ARCH-0052 anonymous mode and G10=B require zero durable
// records, including hash-only safety receipts. Script only the external model wire.
suite.test(test, "PRIVACY-08", "Anonymous chat has no memory should work", async () => {
  const catalog = await loadFixtures();
  const data = await catalog.readJson<{
    anonymous: { input: string; followUp: string; normalText: string; blockedInput: string;
      policyRow: string; modelReplies: [string, string] };
  }>("privacy-scenarios");
  const spec = data.anonymous;
  const privateText = [spec.input, spec.followUp, spec.blockedInput, ...spec.modelReplies];
  redactor.add(...privateText, spec.normalText);
  const providers = await ScriptedProviders.start({
    id: "privacy-anonymous",
    steps: spec.modelReplies.map((reply, index): ProviderStep => ({
      id: `anonymous-${index + 1}`, origin: "responder", role: "generative_reasoner",
      purpose: "standalone anonymous reply",
      request: { method: "POST", path: "/v1/chat/completions", model: "privacy-anonymous" },
      response: openaiText(`anonymous-${index + 1}`, "privacy-anonymous", reply,
        { inputTokens: 32, outputTokens: 16 }),
    })),
  });
  let engine: EngineFixture | undefined;
  let primaryFailed: boolean = false;
  let primary: unknown;
  try {
    engine = await EngineFixture.start({ id: "PRIVACY-08", profile, serverConfig: `
[models.providers.privacy]
kind = "local-openai-compat"
base_url = "${providers.urls.responder}"
revision = "e2e-v1"
[models.roles.generative_reasoner]
model = "privacy:privacy-anonymous"
[models.dreamer]
enabled = false
[models.workflows]
enabled = false
` });
    await engine.requireHttpDoor("/v1/ai/anonymous-chat", "POST");
    await anonymousPolicy(engine, spec.policyRow);
    const scope = await ownerBaseClaimScope(engine.client, engine.pairedActor.principalRef);
    const normal = await engine.client.call("vault.claims.upsert", {
      subject_ref: engine.pairedActor.principalRef, predicate: "privacy.normal_memory",
      value: spec.normalText, confidence: 1, source: "user_stated", scope,
    });
    expect(normal.approval).toBe("auto");
    const normalRow = await engine.client.call("vault.get", { entity_ref: normal.claim_short_id });
    expect(normalRow.value).not.toBeNull();
    const baselineReceipts = await allReceipts(engine.client);
    const baselineTelemetry = await engine.client.call("vault.retrieval.runs", { limit: 100 });
    const requestIds: string[] = [];
    async function chat(text: string) {
      const input = { text, target: "house_mind" } satisfies FacadeInput<"ai.anonymous_chat">;
      const reply = await engine!.client.request<FacadeResult<"ai.anonymous_chat">>(
        "POST", "/v1/ai/anonymous-chat", input,
      );
      expect(reply.headers.get("cache-control")).toBe("no-store");
      expect(reply.headers.get("x-oneiron-receipt-ref")).toBe("none; no-record");
      const requestId = reply.headers.get("x-request-id");
      if (!requestId) throw new Error("Anonymous response has no request id");
      requestIds.push(requestId);
      return reply.body;
    }
    const first = await chat(spec.input);
    if (first.type !== "reply") throw new Error("Ordinary anonymous turn was blocked");
    expect(first.content).toBe(spec.modelReplies[0]);
    // G-ANONYMOUS (FIX21914): document-free fixture correctly skips input+output.
    expect(first.skipped_checks).toEqual([{input:true,reason:"no-document"},{input:false,reason:"no-document"}]);
    const second = await chat(spec.followUp);
    if (second.type !== "reply") throw new Error("Independent anonymous turn was blocked");
    expect(second.content).toBe(spec.modelReplies[1]);
    expect(second.skipped_checks).toEqual([{input:true,reason:"no-document"},{input:false,reason:"no-document"}]);
    const calls = providers.seenFixtureCalls;
    expect(calls).toHaveLength(2);
    expect(JSON.stringify(calls[0]!.body)).toContain(spec.input);
    expect(JSON.stringify(calls[1]!.body)).toContain(spec.followUp);
    excludes(calls[0]!.body, [spec.normalText]);
    excludes(calls[1]!.body, [spec.input, spec.modelReplies[0], spec.normalText]);
    // These reads do not search for secret text. A test probe containing it
    // would itself be a normal recorded request, invalidating the export check.
    expect(await allReceipts(engine.client)).toEqual(baselineReceipts);
    expect(await engine.client.call("vault.retrieval.runs", { limit: 100 })).toEqual(baselineTelemetry);
    const forbidden = [...privateText, ...privateText.flatMap(text => [
      createHash("sha256").update(text).digest("hex"),
      Buffer.from(blake3(new TextEncoder().encode(text))).toString("hex"),
    ])];
    excludes(await exportText(engine.client), forbidden);
    const blockReceipts = await allReceipts(engine.client);
    const blockTelemetry = await engine.client.call("vault.retrieval.runs", { limit: 100 });
    const blocked = await chat(spec.blockedInput);
    if (blocked.type !== "blocked") throw new Error("Owner's story-ending policy did not block");
    expect(blocked.input).toBe(true);
    expect(blocked.reason).toBe("policy");
    expect(blocked.notice.audience).toBe("user_and_model");
    expect(blocked.notice.row_ref).toBe(spec.policyRow);
    expect(blocked.notice.body.length).toBeGreaterThan(0);
    expect(blocked.model_notices).toContainEqual(blocked.notice);
    expect(providers.seenFixtureCalls).toHaveLength(2); // Input block never reaches the responder.
    expect(await allReceipts(engine.client)).toEqual(blockReceipts);
    expect(await engine.client.call("vault.retrieval.runs", { limit: 100 })).toEqual(blockTelemetry);
    for (const id of requestIds) {
      expect(await engine.client.call("vault.receipts.get", { receipt_ref: `call:${id}` })).toBeNull();
    }
    async function memoryAndExport() {
      const found = await engine!.client.call("vault.recall", {
        query: "privacynormalmemory", effort: "light", limit: 10,
      });
      expect(found.items.some(item => item.value_text.includes(spec.normalText))).toBe(true);
      // BM25 matches tokens, not arbitrary prefixes of the fixture markers.
      // Probe the exact unique input tokens, not the complete secret sentences.
      for (const query of [spec.input, spec.blockedInput].map(text => text.split(":")[0]!)) {
        const absent = await engine!.client.call("vault.search.bm25", { query, limit: 100 });
        expect(absent.value).toEqual([]);
      }
      expect((await engine!.client.call("vault.get", { entity_ref: normal.claim_short_id })).value)
        .toEqual(normalRow.value);
      excludes(await exportText(engine!.client), forbidden);
    }
    await memoryAndExport();
    // Snapshot again after the suite's own ordinary reads and export, before restart.
    const beforeRestartReceipts = await allReceipts(engine.client);
    const beforeRestartTelemetry = await engine.client.call("vault.retrieval.runs", { limit: 100 });
    await engine.restart();
    expect(await allReceipts(engine.client)).toEqual(beforeRestartReceipts);
    expect(await engine.client.call("vault.retrieval.runs", { limit: 100 })).toEqual(beforeRestartTelemetry);
    await memoryAndExport();
  } catch (error) {
    primaryFailed = true;
    primary = error;
  } finally {
    const cleanups: string[] = [];
    try { await engine?.close(); } catch (error) { cleanups.push(errorText(error)); }
    try { await providers.close(); } catch (error) { cleanups.push(errorText(error)); }
    if (primaryFailed) {
      if (cleanups.length) throw new Error(`${errorText(primary)}; cleanup: ${cleanups.join("; ")}`);
      throw primary;
    }
    if (cleanups.length) throw new Error(`cleanup: ${cleanups.join("; ")}`);
  }
});

type museLabel01ClaimRow = FacadeResult<"vault.claims.list">["value"][number];
type museLabel01Scope = FacadeInput<"vault.claims.upsert">["scope"];
type museLabel01AuditRow = FacadeResult<"vault.authority.audit">["rows"][number];

interface museLabel01ErrorBody {
  error?: { code?: unknown; message?: unknown };
}

interface museLabel01FacetRow {
  idHex: string;
  bodyKind: string | null;
}

function museLabel01Omit(value: object, key: string): Record<string, unknown> {
  const copy: Record<string, unknown> = { ...(value as Record<string, unknown>) };
  delete copy[key];
  return copy;
}

function museLabel01ExpectErrorEnvelope(body: museLabel01ErrorBody): void {
  const code = body.error?.code;
  const message = body.error?.message;
  expect(typeof code === "string" && code.length > 0).toBe(true);
  expect(typeof message === "string" && message.length > 0).toBe(true);
}

async function museLabel01Facets(
  client: PublicHttpClient,
  personRef: string,
): Promise<museLabel01FacetRow[]> {
  const neighbors = await client.call("vault.neighbors", {
    entity_ref: personRef,
    opts: { edge_kind: "has_facet", limit: 100 },
  });
  const rows: museLabel01FacetRow[] = [];
  for (const hit of neighbors.value) {
    const got = await client.call("vault.get", { entity_ref: hit.short_id });
    const row = got.value;
    if (!row || row.kind !== "FACET") continue;
    let bodyKind: string | null = null;
    const body = row.body;
    if (typeof body === "object" && body !== null && "kind" in body) {
      const kind = (body as { kind: unknown }).kind;
      if (typeof kind === "string") bodyKind = kind;
    }
    rows.push({ idHex: row.id_hex, bodyKind });
  }
  return rows;
}

async function museLabel01ListClaims(
  client: PublicHttpClient,
  subjectRef: string,
  predicate: string,
): Promise<museLabel01ClaimRow[]> {
  const list = await client.call("vault.claims.list", {
    subject_ref: subjectRef,
    predicate,
    limit: 100,
  });
  return list.value;
}

async function museLabel01ReadOnlyClaim(
  client: PublicHttpClient,
  subjectRef: string,
  predicate: string,
  value: string,
): Promise<museLabel01ClaimRow> {
  const rows = await museLabel01ListClaims(client, subjectRef, predicate);
  const matches = rows.filter((row) => row.value === value);
  expect(matches).toHaveLength(1);
  const row = matches[0]!;
  expect(row.subject_ref).toBe(subjectRef);
  expect(row.predicate).toBe(predicate);
  expect(row.value).toBe(value);
  return row;
}

function museLabel01ExpectScope(row: museLabel01ClaimRow, scope: museLabel01Scope): void {
  expect(row.claim_scope.world_id).toBe(scope.world_id);
  expect(row.claim_scope.scope_facet_id).toBe(scope.scope_facet_id);
  expect(row.claim_scope.scope_relationship_id).toEqual(scope.scope_relationship_id);
  expect(row.claim_scope.scope_project_id).toBe(scope.scope_project_id);
}

async function museLabel01FacetOf(
  client: PublicHttpClient,
  claimIdHex: string,
): Promise<string> {
  const neighbors = await client.call("vault.neighbors", {
    entity_ref: claimIdHex,
    opts: { edge_kind: "facet_of", limit: 10 },
  });
  expect(neighbors.value).toHaveLength(1);
  const hit = neighbors.value[0]!;
  expect(hit.edge_kind).toBe("facet_of");
  expect(hit.kind).toBe("FACET");
  const got = await client.call("vault.get", { entity_ref: hit.short_id });
  if (!got.value) throw new Error("facet_of target is not readable through vault.get");
  expect(got.value.kind).toBe("FACET");
  return got.value.id_hex;
}

async function museLabel01AuditRows(client: PublicHttpClient): Promise<museLabel01AuditRow[]> {
  const rows: museLabel01AuditRow[] = [];
  let after: string | undefined;
  const cursors = new Set<string>();
  for (;;) {
    const query: FacadeInput<"vault.authority.audit"> = {
      limit: 500,
      ...(after ? { after } : {}),
    };
    const page = await client.call("vault.authority.audit", query);
    rows.push(...page.rows);
    if (!page.next_after) return rows;
    cursors.add(page.next_after);
    after = page.next_after;
  }
}

function museLabel01MintedSlipId(
  before: readonly museLabel01AuditRow[],
  after: readonly museLabel01AuditRow[],
  holderRef: string,
): string {
  const existing = new Set(before.map((row) => row.entry_hash));
  const minted = after.filter(
    (row) =>
      !existing.has(row.entry_hash) &&
      row.source_op === "slip_mint" &&
      row.holder_ref === holderRef,
  );
  expect(minted).toHaveLength(1);
  const row = minted[0]!;
  const slipId = row.subject_ref;
  if (!slipId) throw new Error("Minted slip audit row has no subject_ref slip id");
  expect(slipId).toMatch(/^[a-f0-9]{64}$/);
  return slipId;
}

// MUSE-LABEL-01 (PARTIAL) - promises and doors.
// P-LABEL-001: a claim write missing any required world, facet, relationship or
// project scope is rejected. Driven as malformed raw bodies on the existing
// POST /v1/core/facade/vault.claims.upsert door, plus one vault.commit batch
// whose facet key names a PERSON instead of a FACET.
// P-LABEL-004: a record keeps the facet stamp it received at birth. Driven for
// one CLAIM: vault.claims.upsert writes it, vault.claims.list reads
// claim_scope back, vault.get / vault.hydrate read the entity, and
// vault.neighbors reads its one facet_of edge. The stamp is re-read after a
// wrong-actor attempt, after an agent grant is minted and revoked, and after
// engine.restart().
// P-LABEL-007, in part only: vault.agents.grants.mint grants a base named
// agent read verbs inside a Scope naming the claim facet, then
// vault.agents.grants.revoke removes that Grant; the stamp is re-read after
// each act. No typed door was found that shares one named record through a
// Grant, and no deterministic door was found that makes that resident agent
// use the Grant, so single-record sharing and the agent next-use after this
// AgentGrant revoke stay unproved.
// Unproved: P-LABEL-005 (no deterministic public derivation door was found
// that stamps a derived record from its source without the caller supplying
// the scope) and P-LABEL-023 (no typed facet read or facet-mint door was found
// that exposes a facet exposure of public/private). vault.get also returns an
// EntityView with no typed facet or scope field, so the stamp itself is read
// through ClaimView.claim_scope, not through getEntity alone.
suite.test(test, "MUSE-LABEL-01", "A claim write missing any of its four scope keys is rejected and lands nothing, and a complete claim keeps its birth facet through read-backs, an agent grant, wrong-actor attempts and a restart", async () => {
  const engine = await EngineFixture.start({ id: "MUSE-LABEL-01", profile });
  let stage = "witness setup";
  try {
    const occurred = 1769947200;
    const ownerRef = engine.pairedActor.principalRef;
    const predicate = "decision.practical";
    const sentinel = `muse-label-01-${secretHex(8)}`;
    redactor.add(sentinel);
    const personName = `Muse Label Person ${sentinel}`;
    redactor.add(personName);

    const conversation = await engine.client.call("vault.conversations.create", {
      body: {},
      occurred_start: occurred,
      occurred_end: occurred,
      learned_at: occurred,
    } satisfies FacadeInput<"vault.conversations.create">);
    const witness = await engine.client.call("vault.witness", {
      conversation_ref: conversation.id,
      occurred_at: occurred,
      messages: [{
        author: "user",
        message_type: "text",
        content: `This distinct person is ${personName}.`,
        is_visible: true,
        order: 0,
      }],
    } satisfies FacadeInput<"vault.witness">);
    // witness: is a write marker, not a vault.receipts row (ARCH-0044).
    // Read both records through a door other than the writing door.
    const messageRef = witness.message_short_ids[0];
    if (!messageRef) throw new Error("Witness returned no MESSAGE reference");
    const message = await engine.client.call("vault.get", { entity_ref: messageRef });
    expect(message.value?.kind).toBe("MESSAGE");
    expect(message.value?.body).toEqual(expect.objectContaining({
      content: `This distinct person is ${personName}.`,
    }));
    const turn = await engine.client.call("vault.get", {
      entity_ref: witness.turn_short_id,
    } satisfies FacadeInput<"vault.get">);
    if (turn.value?.kind !== "TURN" || !turn.value.id_hex) {
      throw new Error("Witnessed TURN is not readable through vault.get");
    }
    expect(turn.value.id_hex).toBe(witness.turn_id);
    stage = "person creation and scope readback";
    const createdPerson = await engine.client.call("vault.people.create", {
      identity: { name: personName },
      identity_evidence_refs: [turn.value.id_hex],
      occurred_at: occurred,
    } satisfies FacadeInput<"vault.people.create">);
    const subjectRef = createdPerson.person.id_hex;
    expect(subjectRef).not.toBe(ownerRef);
    const subjectEntity = await engine.client.call("vault.get", {
      entity_ref: createdPerson.person.entity_ref,
    } satisfies FacadeInput<"vault.get">);
    expect(subjectEntity.value?.kind).toBe("PERSON");

    const baseScope = await ownerBaseClaimScope(engine.client, ownerRef);
    const ownerFacets = await museLabel01Facets(engine.client, ownerRef);
    expect(ownerFacets.length).toBeGreaterThan(0);
    const namedFacet = ownerFacets.find((row) => row.idHex !== baseScope.scope_facet_id);
    const birthScope: museLabel01Scope = {
      ...baseScope,
      scope_facet_id: namedFacet?.idHex ?? baseScope.scope_facet_id,
    };
    await engine.artifacts.json("muse-label-01-facets.json", {
      ownerFacets,
      namedFacetFound: namedFacet !== undefined,
      birthScope,
    });

    const completeInput = {
      predicate,
      subject_ref: subjectRef,
      value: sentinel,
      confidence: 1,
      source: "user_stated",
      scope: birthScope,
      occurred_at: occurred,
    } satisfies FacadeInput<"vault.claims.upsert">;

    // P-LABEL-001: each missing axis, then the whole scope object, is refused.
    stage = "missing-scope refusal controls";
    const missingKeys = [
      "world_id",
      "scope_facet_id",
      "scope_relationship_id",
      "scope_project_id",
    ] as const;
    for (const missingKey of missingKeys) {
      const missingValue = `${sentinel}-missing-${missingKey}`;
      redactor.add(missingValue);
      const reply = await engine.client.raw<museLabel01ErrorBody>(
        "POST",
        "/v1/core/facade/vault.claims.upsert",
        {
          ...completeInput,
          value: missingValue,
          scope: museLabel01Omit(birthScope, missingKey),
        },
      );
      expect(reply.status).toBeGreaterThanOrEqual(400);
      expect(reply.status).toBeLessThan(600);
      museLabel01ExpectErrorEnvelope(reply.body);
    }
    const noScopeValue = `${sentinel}-missing-scope`;
    redactor.add(noScopeValue);
    const noScopeReply = await engine.client.raw<museLabel01ErrorBody>(
      "POST",
      "/v1/core/facade/vault.claims.upsert",
      { ...museLabel01Omit(completeInput, "scope"), value: noScopeValue },
    );
    expect(noScopeReply.status).toBeGreaterThanOrEqual(400);
    expect(noScopeReply.status).toBeLessThan(600);
    museLabel01ExpectErrorEnvelope(noScopeReply.body);

    // The batch door answers a gate refusal as a typed outcome with a receipt.
    // A PERSON id is a real entity id in facet format, but it is no FACET.
    const inventedFacetValue = `${sentinel}-person-as-facet`;
    redactor.add(inventedFacetValue);
    stage = "PERSON-as-FACET batch refusal and receipt";
    const commitOutcomes = await engine.client.call("vault.commit", {
      claims: [{
        ...completeInput,
        value: inventedFacetValue,
        scope: { ...birthScope, scope_facet_id: subjectRef },
      }],
    } satisfies FacadeInput<"vault.commit">);
    expect(commitOutcomes).toHaveLength(1);
    const commitOutcome = commitOutcomes[0]!;
    expect(commitOutcome.outcome).toBe("refused");
    if (commitOutcome.outcome !== "refused") {
      throw new Error("vault.commit landed a claim whose facet key names a PERSON");
    }
    const refusalReceipt = commitOutcome.receipt_ref;
    expect(typeof refusalReceipt === "string" && refusalReceipt.length > 0).toBe(true);
    if (!refusalReceipt) throw new Error("Refused commit outcome has no receipt_ref");
    await awaitPublic(
      () => engine.client.call("vault.receipts", { limit: 100, kinds: ["reference_refusal"] }),
      page => page.receipts.some(row => row.receipt_ref === refusalReceipt),
      { label: `MUSE-LABEL-01 PERSON-as-FACET refusal receipt ${refusalReceipt}` },
    );

    // None of the refused writes above landed on this fresh subject.
    expect(await museLabel01ListClaims(engine.client, subjectRef, predicate)).toHaveLength(0);

    // Positive control: the same input with all four keys lands once.
    stage = "complete claim write and birth-stamp readback";
    const written = await engine.client.call("vault.claims.upsert", completeInput);
    expect(written.claim_short_id.length).toBeGreaterThan(0);
    expect(written.receipt_ref.length).toBeGreaterThan(0);
    await engine.awaitReceipt(written.receipt_ref);

    // P-LABEL-004 read-back through doors other than the writing door.
    const bornRow = await museLabel01ReadOnlyClaim(
      engine.client,
      subjectRef,
      predicate,
      sentinel,
    );
    museLabel01ExpectScope(bornRow, birthScope);
    const bornEntity = await engine.client.call("vault.get", {
      entity_ref: written.claim_short_id,
    } satisfies FacadeInput<"vault.get">);
    if (!bornEntity.value) throw new Error("Born claim is not readable through vault.get");
    expect(bornEntity.value.kind).toBe("CLAIM");
    const claimIdHex = bornEntity.value.id_hex;
    expect(claimIdHex.length).toBeGreaterThan(0);
    const hydrated = await engine.client.call("vault.hydrate", {
      refs: [claimIdHex],
    } satisfies FacadeInput<"vault.hydrate">);
    expect(hydrated.value).toHaveLength(1);
    expect(hydrated.value[0]!.id_hex).toBe(claimIdHex);
    expect(hydrated.value[0]!.kind).toBe("CLAIM");
    expect(await museLabel01FacetOf(engine.client, claimIdHex)).toBe(
      birthScope.scope_facet_id,
    );

    // P-LABEL-007 in part: share read access inside this facet through a
    // named-agent Grant, then revoke it. The record stamp must not move.
    stage = "named-agent read Grant mint and readback";
    const baseAgents = await engine.client.call("vault.agents.base", {});
    expect(baseAgents.agents.length).toBeGreaterThan(0);
    const namedAgent = baseAgents.agents[0]!;
    const mintedGrant = await engine.client.call("vault.agents.grants.mint", {
      agent: namedAgent.id,
      authority_scope: {
        worlds: { kind: "some", values: [birthScope.world_id] },
        facets: { kind: "some", values: [birthScope.scope_facet_id] },
        bands: { kind: "all" },
        audience: { kind: "all" },
        verbs: { kind: "some", values: ["read"] },
        sensitivity: { kind: "all" },
      },
    } satisfies FacadeInput<"vault.agents.grants.mint">);
    expect(mintedGrant.grant.grant_ref.length).toBeGreaterThan(0);
    expect(mintedGrant.grant.confers).toBe(true);
    const mintedGrantRead = await engine.client.call("vault.get", {
      entity_ref: mintedGrant.grant.grant_ref,
    });
    expect(mintedGrantRead.value?.kind).toBe("FEDERATION_GRANT");
    expect(mintedGrantRead.value?.id_hex).toBe(mintedGrant.grant.grant_ref);
    expect(object(mintedGrantRead.value?.body).authority_scope).toEqual(mintedGrant.grant.authority_scope);
    museLabel01ExpectScope(
      await museLabel01ReadOnlyClaim(engine.client, subjectRef, predicate, sentinel),
      birthScope,
    );
    stage = "named-agent Grant revoke and readback";
    const revokedGrant = await engine.client.call("vault.agents.grants.revoke", {
      grant_ref: mintedGrant.grant.grant_ref,
    } satisfies FacadeInput<"vault.agents.grants.revoke">);
    expect(revokedGrant.grant_ref).toBe(mintedGrant.grant.grant_ref);
    expect(revokedGrant.changed).toBe(true);
    const grantAudit = await museLabel01AuditRows(engine.client);
    expect(grantAudit.some(row => row.source_op === "agent_grant_act"
      && row.grant_ref === mintedGrant.grant.grant_ref
      && row.detail === "revoke" && row.fold_valid)).toBe(true);
    museLabel01ExpectScope(
      await museLabel01ReadOnlyClaim(engine.client, subjectRef, predicate, sentinel),
      birthScope,
    );

    // Wrong actor kind: an externally paired agent held only to core:read.
    // It can name itself, cannot write the claim, and loses even that use
    // when the owner revokes its slip through the public revoke route.
    stage = "read-only agent write refusal";
    const agentName = `Muse Label Agent ${sentinel}`;
    redactor.add(agentName);
    const agentRecord = await engine.client.call("vault.structural.put", {
      kind: "PERSON",
      body: { name: agentName },
      occurred_at: occurred,
    } satisfies FacadeInput<"vault.structural.put">);
    const auditBeforePair = await museLabel01AuditRows(engine.client);
    const readOnlyAgent = await engine.pairActor({
      principalRef: agentRecord.id_hex,
      actorClass: "agent",
      scope: ["core:read"],
    });
    const agentSelf = await readOnlyAgent.client.call("self.actor", {});
    expect(agentSelf.actor_ref.length).toBeGreaterThan(0);
    expect(agentSelf.actor_class).toBe("agent");

    const wrongActorValue = `${sentinel}-wrong-actor`;
    redactor.add(wrongActorValue);
    const wrongActorReply = await readOnlyAgent.client.raw<museLabel01ErrorBody>(
      "POST",
      "/v1/core/facade/vault.claims.upsert",
      { ...completeInput, value: wrongActorValue },
    );
    expect(wrongActorReply.status === 202 || wrongActorReply.status >= 400).toBe(true);
    museLabel01ExpectErrorEnvelope(wrongActorReply.body);
    const afterWrongActor = await museLabel01ListClaims(
      engine.client,
      subjectRef,
      predicate,
    );
    expect(afterWrongActor.some((row) => row.value === wrongActorValue)).toBe(false);
    museLabel01ExpectScope(
      await museLabel01ReadOnlyClaim(engine.client, subjectRef, predicate, sentinel),
      birthScope,
    );

    stage = "reader slip revoke and audit readback";
    const agentSlipId = museLabel01MintedSlipId(
      auditBeforePair,
      await museLabel01AuditRows(engine.client),
      agentRecord.id_hex,
    );
    const slipRevoked = await engine.client.request<{ revoked: boolean }>(
      "POST",
      "/v1/core/slips/revoke",
      { slip_id: Array.from(Buffer.from(agentSlipId, "hex")) },
    );
    expect(slipRevoked.status).toBe(200);
    expect(slipRevoked.body.revoked).toBe(true);
    const deniedAgent = await readOnlyAgent.client.raw<museLabel01ErrorBody>(
      "POST",
      "/v1/core/facade/self.actor",
      {},
    );
    expect(deniedAgent.status).toBe(401);
    museLabel01ExpectErrorEnvelope(deniedAgent.body);
    const auditAfterRevoke = await museLabel01AuditRows(engine.client);
    expect(
      auditAfterRevoke.some(
        (row) =>
          row.source_op === "slip_revoke" &&
          row.subject_ref === agentSlipId &&
          row.fold_valid,
      ),
    ).toBe(true);

    // The stamp, the facet_of edge and the revoked slip survive a restart.
    stage = "restart stamp and revoked-slip readback";
    await engine.restart();
    museLabel01ExpectScope(
      await museLabel01ReadOnlyClaim(engine.client, subjectRef, predicate, sentinel),
      birthScope,
    );
    const afterRestartEntity = await engine.client.call("vault.get", {
      entity_ref: claimIdHex,
    } satisfies FacadeInput<"vault.get">);
    expect(afterRestartEntity.value?.kind).toBe("CLAIM");
    expect(afterRestartEntity.value?.id_hex).toBe(claimIdHex);
    expect(await museLabel01FacetOf(engine.client, claimIdHex)).toBe(
      birthScope.scope_facet_id,
    );
    const deniedAfterRestart = await readOnlyAgent.client.raw<museLabel01ErrorBody>(
      "POST",
      "/v1/core/facade/self.actor",
      {},
    );
    expect(deniedAfterRestart.status).toBe(401);
    museLabel01ExpectErrorEnvelope(deniedAfterRestart.body);

    await engine.artifacts.json("muse-label-01-result.json", {
      claimShortId: written.claim_short_id,
      writeReceipt: written.receipt_ref,
      commitRefusalReceipt: refusalReceipt,
      birthScope,
      grantRef: mintedGrant.grant.grant_ref,
      namedAgent: namedAgent.name,
      revokedSlipAuditSubject: agentSlipId,
    });
  } catch (error) {
    if (error instanceof PublicHttpError) {
      throw new Error(
        `MUSE-LABEL-01 ${stage}: status=${error.reply.status} code=${error.error?.code ?? "<none>"} message=${error.error?.message ?? "<none>"} suggestion=${error.error?.suggestions?.[0] ?? "<none>"}`,
        { cause: error },
      );
    }
    throw new Error(`MUSE-LABEL-01 ${stage}: ${errorText(error)}`, { cause: error });
  } finally {
    await engine.close();
  }
});

//
// MUSE-LABEL-02 — P-LABEL-002, P-LABEL-003, P-LABEL-008, P-LABEL-011.
// Doors used: vault.claims.upsert (act), vault.claims.list / vault.get /
// vault.neighbors (second-door reads), vault.recall and vault.hydrate (the
// register doors), vault.authority.audit and POST /v1/core/slips/revoke
// (grant loss read back), EngineFixture.restart (survival).
// Unproved here: MCP parity for the same credential, a room-carried facet
// limit, and pairing's refusal of a facet limit on an owner credential.
// Those need doors/shapes the allowed typed surface does not name; see the
// report. The facet-limited pairing below also needs the small harness
// option described at its call site and in the report under HARNESS NEEDS.

type museLabel02Facet = { idHex: string; substrate: boolean };
type museLabel02AuditRow = FacadeResult<"vault.authority.audit">["rows"][number];
type museLabel02ClaimView = FacadeResult<"vault.claims.list">["value"][number];

async function museLabel02OwnerFacets(
  client: PublicHttpClient,
  ownerRef: string,
): Promise<museLabel02Facet[]> {
  const neighbors = await client.call("vault.neighbors", {
    entity_ref: ownerRef, opts: { edge_kind: "has_facet", limit: 100 },
  });
  const facets: museLabel02Facet[] = [];
  for (const hit of neighbors.value) {
    const row = (await client.call("vault.get", { entity_ref: hit.short_id })).value;
    if (!row || row.kind !== "FACET") continue;
    const body = row.body;
    const classified = typeof body === "object" && body !== null && "kind" in body;
    if (!classified) continue;
    facets.push({
      idHex: row.id_hex,
      substrate: (body as { kind: unknown }).kind === "substrate",
    });
  }
  facets.sort((a, b) => a.idHex.localeCompare(b.idHex));
  return facets;
}

async function museLabel02AuditRows(client: PublicHttpClient): Promise<museLabel02AuditRow[]> {
  const rows: museLabel02AuditRow[] = [];
  let after: string | undefined;
  const cursors = new Set<string>();
  for (;;) {
    const query: FacadeInput<"vault.authority.audit"> = {
      limit: 500, ...(after ? { after } : {}),
    };
    const page = await client.call("vault.authority.audit", query);
    rows.push(...page.rows);
    if (!page.next_after) return rows;
    cursors.add(page.next_after);
    after = page.next_after;
  }
}

function museLabel02MintedSlipId(
  before: readonly museLabel02AuditRow[],
  after: readonly museLabel02AuditRow[],
  holder: string,
): string {
  const existing = new Set(before.map((row) => row.entry_hash));
  const minted = after.filter((row) => !existing.has(row.entry_hash)
    && row.source_op === "slip_mint" && row.holder_ref === holder);
  expect(minted).toHaveLength(1);
  const row = minted[0]!;
  return row.subject_ref!;
}

async function museLabel02Recall(
  client: PublicHttpClient,
  query: string,
  facetId?: string,
): Promise<FacadeResult<"vault.recall">> {
  const input: FacadeInput<"vault.recall"> = facetId
    ? { query, effort: "light", limit: 20, scope: { facet: facetId } }
    : { query, effort: "light", limit: 20 };
  return client.call("vault.recall", input);
}

function museLabel02PackHas(
  pack: FacadeResult<"vault.recall">,
  sentinel: string,
): boolean {
  return pack.items.some((item) => item.value_text.includes(sentinel)
    || (item.cited_messages?.some((message) => message.value_text.includes(sentinel)) ?? false));
}

async function museLabel02ListSharedClaims(
  client: PublicHttpClient,
  subjectRef: string,
  predicate: string,
  shared: string,
): Promise<museLabel02ClaimView[]> {
  const page = await client.call("vault.claims.list", {
    subject_ref: subjectRef, predicate, limit: 20,
  });
  return page.value.filter((view) => typeof view.value === "string"
    && view.value.includes(shared));
}

function museLabel02ExpectNoSentinels(
  value: unknown,
  sentinels: readonly string[],
): void {
  const text = JSON.stringify(value) ?? "";
  for (const sentinel of sentinels) expect(text.includes(sentinel)).toBe(false);
}

function museLabel02ErrorCode(body: unknown): unknown {
  if (typeof body !== "object" || body === null) return undefined;
  const record = body as Record<string, unknown>;
  const nested = record.error;
  if (typeof nested === "object" && nested !== null && "code" in nested) {
    return (nested as { code: unknown }).code;
  }
  return record.code;
}

async function museLabel02MakeAgentPerson(
  engine: EngineFixture,
  name: string,
  occurredAt: number,
): Promise<string> {
  const created = await engine.client.call("vault.structural.put", {
    kind: "PERSON", body: { name }, occurred_at: occurredAt,
  });
  const got = await engine.client.call("vault.get", { entity_ref: created.entity_ref });
  expect(got.value?.kind).toBe("PERSON");
  return created.id_hex;
}

suite.test(test, "MUSE-LABEL-02", "Strict facet recall stays in the mask, a facet-limited agent reads only its facet, and the owner reads every facet", async () => {
  const engine = await EngineFixture.start({ id: "MUSE-LABEL-02", profile });
  try {
    const occurred = 1769947200;
    const predicate = "decision.social";
    const ownerRef = engine.pairedActor.principalRef;
    const shared = `ml02shared${secretHex(6)}`;
    redactor.add(shared);
    const sentinelA = `ml02alpha${secretHex(6)}`;
    redactor.add(sentinelA);
    const sentinelB = `ml02beta${secretHex(6)}`;
    redactor.add(sentinelB);
    const sentinelCore = `ml02core${secretHex(6)}`;
    redactor.add(sentinelCore);
    const allSentinels = [sentinelA, sentinelB, sentinelCore];

    // Setup: the owner's own facets, read through public graph doors. The
    // case needs the substrate (core, no mask) plus two named masks. No
    // typed door in the allowed surface mints a named mask for a person,
    // so a fresh vault without two masks blocks honestly instead of a
    // guessed structural body standing in for that door.
    const facets = await museLabel02OwnerFacets(engine.client, ownerRef);
    const substrate = facets.find((facet) => facet.substrate);
    const masks = facets.filter((facet) => !facet.substrate);
    if (!substrate || masks.length < 2) {
      throw new BlockedDoor(
        "waits on a public door to mint named FACET masks for a person",
      );
    }
    const facetA = masks[0]!;
    const facetB = masks[1]!;
    const baseScope = await ownerBaseClaimScope(engine.client, ownerRef);
    expect(baseScope.scope_facet_id).toBe(substrate.idHex);

    // ACT: three owner claims that differ only in facet stamp and sentinel.
    const specs = [
      { facetId: facetA.idHex, sentinel: sentinelA },
      { facetId: facetB.idHex, sentinel: sentinelB },
      { facetId: substrate.idHex, sentinel: sentinelCore },
    ];
    const written: { facetId: string; sentinel: string; shortId: string }[] = [];
    for (const spec of specs) {
      const receipt = await engine.client.call("vault.claims.upsert", {
        predicate,
        subject_ref: ownerRef,
        value: `${shared} ${spec.sentinel}`,
        confidence: 1,
        source: "user_stated",
        scope: { ...baseScope, scope_facet_id: spec.facetId },
        occurred_at: occurred,
      });
      await engine.awaitReceipt(receipt.receipt_ref);
      written.push({ ...spec, shortId: receipt.claim_short_id });
    }
    const shortA = written[0]!.shortId;
    const shortB = written[1]!.shortId;
    const allShortIds = written.map((row) => row.shortId);

    // OBSERVE through a second door: claims.list reads the writes back and
    // shows each claim under the facet it was stamped with.
    const ownerListed = await museLabel02ListSharedClaims(
      engine.client, ownerRef, predicate, shared,
    );
    expect(ownerListed).toHaveLength(3);
    for (const row of written) {
      expect(ownerListed.some((view) => view.value === `${shared} ${row.sentinel}`
        && view.claim_scope.scope_facet_id === row.facetId)).toBe(true);
    }

    // P-LABEL-011 and P-LABEL-003, owner side: with no mask requested, the
    // owner recalling alone and hydrating by ref reads every facet.
    const ownerPack = await awaitPublic(
      () => museLabel02Recall(engine.client, shared),
      (pack) => museLabel02PackHas(pack, sentinelA)
        && museLabel02PackHas(pack, sentinelB)
        && museLabel02PackHas(pack, sentinelCore),
      { label: "owner recall returns all facet claims" },
    );
    expect(museLabel02PackHas(ownerPack, sentinelA)).toBe(true);
    expect(museLabel02PackHas(ownerPack, sentinelB)).toBe(true);
    expect(museLabel02PackHas(ownerPack, sentinelCore)).toBe(true);
    const ownerHydrated = await engine.client.call("vault.hydrate", { refs: allShortIds });
    expect(ownerHydrated.value).toHaveLength(3);

    // P-LABEL-008, mask half: strict recall under one named mask keeps that
    // mask's claim and the core (substrate, no-mask) claim, and excludes
    // the claim stamped with the other mask. Both directions.
    const ownerPackA = await museLabel02Recall(engine.client, shared, facetA.idHex);
    expect(museLabel02PackHas(ownerPackA, sentinelA)).toBe(true);
    expect(museLabel02PackHas(ownerPackA, sentinelCore)).toBe(true);
    expect(museLabel02PackHas(ownerPackA, sentinelB)).toBe(false);
    const ownerPackB = await museLabel02Recall(engine.client, shared, facetB.idHex);
    expect(museLabel02PackHas(ownerPackB, sentinelB)).toBe(true);
    expect(museLabel02PackHas(ownerPackB, sentinelCore)).toBe(true);
    expect(museLabel02PackHas(ownerPackB, sentinelA)).toBe(false);

    // Actors: one read agent whose credential opted in to facet A only,
    // and one write-only agent with no read grant at all.
    const auditBefore = await museLabel02AuditRows(engine.client);
    const limitedPerson = await museLabel02MakeAgentPerson(
      engine, "Muse Label 02 Limited Agent", occurred,
    );
    // HARNESS NEED: PairActorOptions needs facetRefs (FACET id_hex values)
    // passed to the real pairing door so the minted slip carries the
    // opt-in facet limit and its write facet. See the report.
    const limited = await engine.pairActor({
      principalRef: limitedPerson, actorClass: "agent",
      scope: ["core:read"], facetRefs: [facetA.idHex],
    });
    const auditAfterPair = await museLabel02AuditRows(engine.client);
    const limitedSlip = museLabel02MintedSlipId(auditBefore, auditAfterPair, limitedPerson);
    const wrongPerson = await museLabel02MakeAgentPerson(
      engine, "Muse Label 02 Write Only Agent", occurred,
    );
    const wrong = await engine.pairActor({
      principalRef: wrongPerson, actorClass: "agent", scope: ["core:write"],
    });

    // P-LABEL-008, credential half, and P-LABEL-002: the limited agent
    // reads facet A's claim through three read doors and nothing stamped
    // with facet B or the substrate. Naming facet B in the request mask
    // cannot widen the credential limit, and a leaked ref hydrates as
    // missing.
    const limitedListed = await museLabel02ListSharedClaims(
      limited.client, ownerRef, predicate, shared,
    );
    expect(limitedListed).toHaveLength(1);
    expect(limitedListed[0]!.value).toBe(`${shared} ${sentinelA}`);
    expect(limitedListed[0]!.claim_scope.scope_facet_id).toBe(facetA.idHex);
    const limitedPack = await museLabel02Recall(limited.client, shared);
    expect(museLabel02PackHas(limitedPack, sentinelA)).toBe(true);
    expect(museLabel02PackHas(limitedPack, sentinelB)).toBe(false);
    expect(museLabel02PackHas(limitedPack, sentinelCore)).toBe(false);
    const limitedPackMaskB = await museLabel02Recall(limited.client, shared, facetB.idHex);
    expect(museLabel02PackHas(limitedPackMaskB, sentinelB)).toBe(false);
    expect(museLabel02PackHas(limitedPackMaskB, sentinelA)).toBe(false);
    expect(museLabel02PackHas(limitedPackMaskB, sentinelCore)).toBe(false);
    const limitedPackMaskA = await museLabel02Recall(limited.client, shared, facetA.idHex);
    expect(museLabel02PackHas(limitedPackMaskA, sentinelA)).toBe(true);
    expect(museLabel02PackHas(limitedPackMaskA, sentinelB)).toBe(false);
    expect(museLabel02PackHas(limitedPackMaskA, sentinelCore)).toBe(false);
    const limitedHydrated = await limited.client.call("vault.hydrate", { refs: allShortIds });
    expect(limitedHydrated.value).toHaveLength(1);
    museLabel02ExpectNoSentinels(limitedHydrated, [sentinelB, sentinelCore]);
    const limitedGetB = await limited.client.call("vault.get", { entity_ref: shortB });
    expect(limitedGetB.value).toBeNull();
    const limitedGetA = await limited.client.call("vault.get", { entity_ref: shortA });
    expect(limitedGetA.value).not.toBeNull();
    const ownerGetB = await engine.client.call("vault.get", { entity_ref: shortB });
    expect(ownerGetB.value).not.toBeNull();

    // REFUSE the wrong actor: a facet named in the request grants nothing
    // to an agent with no read grant. Standard error envelope, no data,
    // on both register doors.
    const wrongRecallInput: FacadeInput<"vault.recall"> = {
      query: shared, effort: "light", limit: 20, scope: { facet: facetA.idHex },
    };
    const wrongRecall = await wrong.client.raw(
      "POST", "/v1/core/facade/vault.recall", wrongRecallInput,
    );
    expect([401, 403]).toContain(wrongRecall.status);
    expect(typeof museLabel02ErrorCode(wrongRecall.body)).toBe("string");
    museLabel02ExpectNoSentinels(wrongRecall.body, allSentinels);
    const wrongHydrateInput: FacadeInput<"vault.hydrate"> = { refs: allShortIds };
    const wrongHydrate = await wrong.client.raw(
      "POST", "/v1/core/facade/vault.hydrate", wrongHydrateInput,
    );
    expect([401, 403]).toContain(wrongHydrate.status);
    expect(typeof museLabel02ErrorCode(wrongHydrate.body)).toBe("string");
    museLabel02ExpectNoSentinels(wrongHydrate.body, allSentinels);

    // The refusals changed nothing the owner reads back through a second
    // door.
    const ownerListedAfterRefusals = await museLabel02ListSharedClaims(
      engine.client, ownerRef, predicate, shared,
    );
    expect(ownerListedAfterRefusals).toHaveLength(3);

    // SURVIVE a restart: each actor reads exactly what it read before.
    await engine.restart();
    const ownerPackAfter = await awaitPublic(
      () => museLabel02Recall(engine.client, shared),
      (pack) => museLabel02PackHas(pack, sentinelA)
        && museLabel02PackHas(pack, sentinelB)
        && museLabel02PackHas(pack, sentinelCore),
      { label: "owner recall after restart returns all facet claims" },
    );
    expect(museLabel02PackHas(ownerPackAfter, sentinelA)).toBe(true);
    expect(museLabel02PackHas(ownerPackAfter, sentinelB)).toBe(true);
    expect(museLabel02PackHas(ownerPackAfter, sentinelCore)).toBe(true);
    const limitedPackAfter = await museLabel02Recall(limited.client, shared);
    expect(museLabel02PackHas(limitedPackAfter, sentinelA)).toBe(true);
    expect(museLabel02PackHas(limitedPackAfter, sentinelB)).toBe(false);
    expect(museLabel02PackHas(limitedPackAfter, sentinelCore)).toBe(false);
    const limitedHydratedAfter = await limited.client.call("vault.hydrate", { refs: allShortIds });
    expect(limitedHydratedAfter.value).toHaveLength(1);
    museLabel02ExpectNoSentinels(limitedHydratedAfter, [sentinelB, sentinelCore]);

    // LOSES the grant mid-flow: the owner revokes the limited agent's slip
    // through the public revoke door, its next recall is refused, the
    // authority audit reads the revoke back, and the owner is unaffected.
    const revoked = await engine.client.request<{ revoked: boolean }>(
      "POST", "/v1/core/slips/revoke",
      { slip_id: Array.from(Buffer.from(limitedSlip, "hex")) },
    );
    expect(revoked.status).toBe(200);
    expect(revoked.body.revoked).toBe(true);
    const revokedRecallInput: FacadeInput<"vault.recall"> = {
      query: shared, effort: "light", limit: 20, scope: { facet: facetA.idHex },
    };
    const revokedRecall = await limited.client.raw(
      "POST", "/v1/core/facade/vault.recall", revokedRecallInput,
    );
    expect(revokedRecall.status).toBe(401);
    expect(typeof museLabel02ErrorCode(revokedRecall.body)).toBe("string");
    museLabel02ExpectNoSentinels(revokedRecall.body, allSentinels);
    const finalAudit = await museLabel02AuditRows(engine.client);
    expect(finalAudit.some((row) => row.source_op === "slip_revoke"
      && row.subject_ref === limitedSlip && row.fold_valid)).toBe(true);
    const ownerListedFinal = await museLabel02ListSharedClaims(
      engine.client, ownerRef, predicate, shared,
    );
    expect(ownerListedFinal).toHaveLength(3);
  } finally {
    await engine.close();
  }
});


type museLabel03AuditRow = FacadeResult<"vault.authority.audit">["rows"][number];
type museLabel03ClaimView = FacadeResult<"vault.claims.list">["value"][number];

function museLabel03Object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Expected a public JSON object (body withheld)");
  }
  return value as Record<string, unknown>;
}

function museLabel03Includes(value: unknown, sentinel: string): boolean {
  // Boolean use keeps generated sentinels out of assertion diagnostics.
  return (JSON.stringify(value) ?? "").includes(sentinel);
}

async function museLabel03Recall(
  client: PublicHttpClient,
  query: string,
  publicOnly: boolean,
): Promise<FacadeResult<"vault.recall">> {
  const input: FacadeInput<"vault.recall"> = publicOnly
    ? { query, effort: "light", limit: 20, filter: { max_sensitivity_band: 0 } }
    : { query, effort: "light", limit: 20 };
  return client.call("vault.recall", input);
}

async function museLabel03AuditRows(
  client: PublicHttpClient,
): Promise<museLabel03AuditRow[]> {
  const rows: museLabel03AuditRow[] = [];
  let after: string | undefined;
  const cursors = new Set<string>();
  for (;;) {
    const query: FacadeInput<"vault.authority.audit"> = {
      limit: 500,
      ...(after ? { after } : {}),
    };
    const page = await client.call("vault.authority.audit", query);
    rows.push(...page.rows);
    if (!page.next_after) return rows;
    cursors.add(page.next_after);
    after = page.next_after;
  }
}

function museLabel03MintedSlipId(
  before: readonly museLabel03AuditRow[],
  after: readonly museLabel03AuditRow[],
  holder: string,
): string {
  const existing = new Set(before.map((row) => row.entry_hash));
  const minted = after.filter((row) => !existing.has(row.entry_hash)
    && row.source_op === "slip_mint" && row.holder_ref === holder);
  if (minted.length !== 1) throw new Error("Reader slip mint row is not unique");
  const row = minted[0];
  if (!row || !row.fold_valid) throw new Error("Reader slip mint row is missing or invalid");
  const slipId = row.subject_ref;
  if (!slipId || !/^[a-f0-9]{64}$/.test(slipId)) {
    throw new Error("Reader slip mint row has no slip id");
  }
  return slipId;
}

function museLabel03OnlyClaim(
  claims: FacadeResult<"vault.claims.list">,
  expectedValue: string,
): museLabel03ClaimView {
  expect(claims.value).toHaveLength(1);
  const claim = claims.value[0];
  if (!claim) throw new Error("Claim list read returned no claim");
  expect(claim.value).toBe(expectedValue);
  return claim;
}

// MUSE-LABEL-03 (PARTIAL) — promises P-LABEL-013, P-LABEL-014, P-LABEL-022.
// P-LABEL-013: a derived claim inherits the most restrictive exposure of its
// source turns. P-LABEL-014: private provenance cannot become public merely
// because its exposure stamp is missing. P-LABEL-022: relevance ranking never
// overrides the disclosure check.
// Doors used: vault.conversations.create, vault.witness, vault.claims.upsert
// (with evidence_turn_refs), then as separate read doors vault.get,
// vault.claims.list, vault.claims.read_filtered, vault.recall, vault.hydrate
// and vault.export.scoped. Refusals go through the raw facade routes, the
// refusal receipt through self.admission.status, and slip loss through
// POST /v1/core/slips/revoke read back in vault.authority.audit.
// What stays unproved, and why: the room/interlocutor disclosure clamp of
// POST /v1/core/context-pack (the door named for P-LABEL-022) has no typed
// request or roster shape in the SDK snapshot given to this writer, and no
// public door was found that stamps a source turn with a facet or sensitivity
// or that runs Dreamer extraction from source turns deterministically. So
// this case proves the failure-closed default at the typed read doors: an
// unstamped claim that cites an owner-only turn must stay out of every
// public-only view, however exact its match, while a positively stamped
// public claim in the same views proves the doors are not simply empty.
// Sensitivity bands are used as the generated types present them: a request
// for max_sensitivity_band 0 is the public-only request, and sensitivity 2
// is the sensitive control that no non-owner may be shown.
suite.test(test, "MUSE-LABEL-03", "An unstamped claim citing an owner-only turn stays out of public-only recall, hydrate and scoped export", async () => {
  const occurred = 1769947200;
  const queryToken = `label03query${secretHex(6)}`;
  const turnSentinel = `label03turn${secretHex(6)}`;
  const sourceSentinel = `label03source${secretHex(6)}`;
  const derivedSentinel = `label03derived${secretHex(6)}`;
  const publicSentinel = `label03public${secretHex(6)}`;
  const forbiddenSentinel = `label03forbidden${secretHex(6)}`;
  redactor.add(
    queryToken,
    turnSentinel,
    sourceSentinel,
    derivedSentinel,
    publicSentinel,
    forbiddenSentinel,
  );
  const publicValue = `${queryToken} public rehearsal room note ${publicSentinel}`;
  const sourceValue = `${queryToken} sensitive rehearsal note ${sourceSentinel} from ${turnSentinel}`;
  const derivedValue = `${queryToken} ${queryToken} derived rehearsal summary ${derivedSentinel} from ${turnSentinel}`;
  const forbiddenValue = `${queryToken} forbidden rehearsal note ${forbiddenSentinel}`;

  const engine = await EngineFixture.start({ id: "MUSE-LABEL-03", profile });
  let stage = "scoped actors and witness setup";
  try {
    const scope = await ownerBaseClaimScope(
      engine.client,
      engine.pairedActor.principalRef,
    );

    // Two agents through the public pairing door: one may write but may not
    // read, one may read but may not write.
    const writeOnlyRecord = await engine.client.call("vault.structural.put", {
      kind: "PERSON",
      body: { name: "MUSE LABEL 03 write only agent" },
      occurred_at: occurred,
    } satisfies FacadeInput<"vault.structural.put">);
    const writeOnly = await engine.pairActor({
      principalRef: writeOnlyRecord.id_hex,
      actorClass: "agent",
      scope: ["core:write"],
    });
    const readerRecord = await engine.client.call("vault.structural.put", {
      kind: "PERSON",
      body: { name: "MUSE LABEL 03 reader agent" },
      occurred_at: occurred,
    } satisfies FacadeInput<"vault.structural.put">);
    const auditBeforeReader = await museLabel03AuditRows(engine.client);
    const reader = await engine.pairActor({
      principalRef: readerRecord.id_hex,
      actorClass: "agent",
      scope: ["core:read"],
    });

    // Act: an owner-only conversation and one witnessed turn in it.
    const conversation = await engine.client.call("vault.conversations.create", {
      body: { members: [engine.pairedActor.principalRef] },
      occurred_start: occurred,
      occurred_end: occurred,
    } satisfies FacadeInput<"vault.conversations.create">);
    const witnessed = await engine.client.call("vault.witness", {
      conversation_ref: conversation.id,
      occurred_at: occurred,
      messages: [{
        author: "user",
        message_type: "text",
        is_visible: true,
        order: 0,
        content: `Owner-only note ${turnSentinel} for a private rehearsal plan.`,
      }],
    } satisfies FacadeInput<"vault.witness">);
    // witness: names the write; the MESSAGE and TURN reads below prove it landed.
    const messageRef = witnessed.message_short_ids[0];
    if (!messageRef) throw new Error("Witness returned no message reference");
    const savedMessage = await engine.client.call("vault.get", {
      entity_ref: messageRef,
    } satisfies FacadeInput<"vault.get">);
    if (!savedMessage.value) throw new Error("Witnessed message is not readable by the owner");
    expect(savedMessage.value.kind).toBe("MESSAGE");
    expect(savedMessage.value.body).toEqual(expect.objectContaining({
      content: `Owner-only note ${turnSentinel} for a private rehearsal plan.`,
    }));
    expect(museLabel03Includes(savedMessage, turnSentinel)).toBe(true);
    const turn = await engine.client.call("vault.get", {
      entity_ref: witnessed.turn_short_id,
    } satisfies FacadeInput<"vault.get">);
    if (turn.value?.kind !== "TURN" || !turn.value.id_hex) {
      throw new Error("Witnessed TURN is not readable by the owner");
    }
    expect(turn.value.id_hex).toBe(witnessed.turn_id);
    const turnHex = turn.value.id_hex;

    // Act: three claims about the same conversation. The public control is
    // positively stamped public. The source control is stamped private and
    // cites the turn. The derived claim cites the same turn, is the most
    // relevant text for the query, and carries no sensitivity stamp at all.
    stage = "private-source claim admission";
    const sourceClaim = await engine.client.call("vault.claims.upsert", {
      predicate: "label03.source_note",
      subject_ref: conversation.id,
      value: sourceValue,
      confidence: 1,
      source: "user_stated",
      scope,
      // Private is enough to test a Public-only ceiling. Sensitive (2)
      // requires consent before recall (ARCH-0003); this is not a consent case.
      sensitivity: 1,
      evidence_turn_refs: [turnHex],
      occurred_at: occurred,
      salience: 1,
    } satisfies FacadeInput<"vault.claims.upsert">);
    await engine.awaitReceipt(sourceClaim.receipt_ref);
    stage = "public-control claim admission";
    const publicClaim = await engine.client.call("vault.claims.upsert", {
      predicate: "label03.public_note",
      subject_ref: conversation.id,
      value: publicValue,
      confidence: 1,
      source: "user_stated",
      scope,
      sensitivity: 0,
      occurred_at: occurred,
    } satisfies FacadeInput<"vault.claims.upsert">);
    await engine.awaitReceipt(publicClaim.receipt_ref);
    stage = "unstamped-derived claim admission";
    const derivedClaim = await engine.client.call("vault.claims.upsert", {
      predicate: "label03.derived_note",
      subject_ref: conversation.id,
      value: derivedValue,
      confidence: 1,
      source: "user_stated",
      scope,
      // No sensitivity key: the derived claim is deliberately unstamped.
      evidence_turn_refs: [turnHex],
      occurred_at: occurred,
      salience: 1,
    } satisfies FacadeInput<"vault.claims.upsert">);
    await engine.awaitReceipt(derivedClaim.receipt_ref);

    // Observe through a second door: exact claim reads by subject/predicate.
    stage = "recorded claim readbacks";
    const sourceClaimView = museLabel03OnlyClaim(
      await engine.client.call("vault.claims.list", {
        subject_ref: conversation.id,
        predicate: "label03.source_note",
        limit: 10,
      } satisfies FacadeInput<"vault.claims.list">),
      sourceValue,
    );
    const publicClaimView = museLabel03OnlyClaim(
      await engine.client.call("vault.claims.list", {
        subject_ref: conversation.id,
        predicate: "label03.public_note",
        limit: 10,
      } satisfies FacadeInput<"vault.claims.list">),
      publicValue,
    );
    const derivedClaimView = museLabel03OnlyClaim(
      await engine.client.call("vault.claims.list", {
        subject_ref: conversation.id,
        predicate: "label03.derived_note",
        limit: 10,
      } satisfies FacadeInput<"vault.claims.list">),
      derivedValue,
    );

    // Owner-alone control: an unfiltered ranked recall as the owner finds
    // all three, and the derived item still cites its source turn.
    stage = `ENGINE DEFECT 2026-11-11: FIX 23103 explicit Public/Private stamps force Proposed; owner recall controls; last recorded approvals public=${publicClaimView.approval}, private=${sourceClaimView.approval}, unstamped=${derivedClaimView.approval}`;
    const ownerRecall = await museLabel03Recall(engine.client, queryToken, false);
    expect(museLabel03Includes(ownerRecall, publicSentinel)).toBe(true);
    expect(museLabel03Includes(ownerRecall, sourceSentinel)).toBe(true);
    expect(museLabel03Includes(ownerRecall, derivedSentinel)).toBe(true);
    const derivedItem = ownerRecall.items.find(
      (item) => item.value_text.includes(derivedSentinel),
    );
    if (!derivedItem) throw new Error("Derived claim is missing from owner recall");
    stage = "derived claim exact evidence birth readback";
    // CLAIM recall items leave the legacy evidence_turn_ids projection empty.
    // Verify the exact cited TURN in the recorded claim's host-stamped birth.
    expect(derivedClaimView.made_by?.inputs).toContainEqual({ row: turnHex, role: "input" });

    // Public-only claim reads: the positively public claim is served, the
    // stamped-private claim and the unstamped derived claim are not.
    stage = "ENGINE DEFECT 2026-11-11: FIX 23103 Proposed Public control is withheld by the Surfaceable filtered read";
    const publicFiltered = await engine.client.call("vault.claims.read_filtered", {
      claim_ref: publicClaimView.claim_ref,
      filter: { max_sensitivity_band: 0 },
    } satisfies FacadeInput<"vault.claims.read_filtered">);
    expect(publicFiltered.value?.value).toBe(publicValue);
    stage = "public-only private and unstamped claim withholding";
    const sourceFiltered = await engine.client.call("vault.claims.read_filtered", {
      claim_ref: sourceClaimView.claim_ref,
      filter: { max_sensitivity_band: 0 },
    } satisfies FacadeInput<"vault.claims.read_filtered">);
    expect(sourceFiltered.value).toBeNull();
    const derivedFiltered = await engine.client.call("vault.claims.read_filtered", {
      claim_ref: derivedClaimView.claim_ref,
      filter: { max_sensitivity_band: 0 },
    } satisfies FacadeInput<"vault.claims.read_filtered">);
    expect(derivedFiltered.value).toBeNull();
    expect(museLabel03Includes(derivedFiltered, derivedSentinel)).toBe(false);

    // Public-only ranked recall: relevance does not pull the private-derived
    // item in, while the less salient public control is still found.
    stage = "public-only ranked recall";
    const publicRecall = await museLabel03Recall(engine.client, queryToken, true);
    expect(museLabel03Includes(publicRecall, publicSentinel)).toBe(true);
    expect(museLabel03Includes(publicRecall, sourceSentinel)).toBe(false);
    expect(museLabel03Includes(publicRecall, derivedSentinel)).toBe(false);
    expect(museLabel03Includes(publicRecall, turnSentinel)).toBe(false);

    // Hydrate is the next door in both directions.
    stage = "hydrate controls and public-only filter";
    const hydratedAll = await engine.client.call("vault.hydrate", {
      refs: [
        derivedClaim.claim_short_id,
        sourceClaim.claim_short_id,
        publicClaim.claim_short_id,
      ],
    } satisfies FacadeInput<"vault.hydrate">);
    expect(museLabel03Includes(hydratedAll, derivedSentinel)).toBe(true);
    expect(museLabel03Includes(hydratedAll, publicSentinel)).toBe(true);
    // hydrate is all-or-error, not a partial-result filter. Test the public
    // positive control separately, then each withheld private reference.
    const hydratedPublic = await engine.client.call("vault.hydrate", {
      refs: [publicClaim.claim_short_id],
      filter: { max_sensitivity_band: 0 },
    } satisfies FacadeInput<"vault.hydrate">);
    expect(museLabel03Includes(hydratedPublic, publicSentinel)).toBe(true);
    expect(museLabel03Includes(hydratedPublic, sourceSentinel)).toBe(false);
    expect(museLabel03Includes(hydratedPublic, derivedSentinel)).toBe(false);
    expect(museLabel03Includes(hydratedPublic, turnSentinel)).toBe(false);
    for (const [label, claimRef] of [
      ["private source", sourceClaim.claim_short_id],
      ["unstamped derived", derivedClaim.claim_short_id],
    ] as const) {
      const denied = await engine.client.raw<{
        error?: { code?: string; message?: string; suggestions?: string[] };
      }>("POST", "/v1/core/facade/vault.hydrate", {
        refs: [claimRef], filter: { max_sensitivity_band: 0 },
      } satisfies FacadeInput<"vault.hydrate">);
      if (denied.status !== 404 || denied.body.error?.code !== "NOT_FOUND") {
        throw new Error(`MUSE-LABEL-03 ${label} public-only hydrate refusal: status=${denied.status} code=${denied.body.error?.code ?? "<none>"} message=${denied.body.error?.message ?? "<none>"} suggestion=${denied.body.error?.suggestions?.[0] ?? "<none>"}`);
      }
      expect(museLabel03Includes(denied.body, sourceSentinel)).toBe(false);
      expect(museLabel03Includes(denied.body, derivedSentinel)).toBe(false);
      expect(museLabel03Includes(denied.body, turnSentinel)).toBe(false);
    }

    // Scoped export through a public channel is the export door.
    stage = "public scoped export";
    const scopedExport = await engine.client.call("vault.export.scoped", {
      selector: {},
      channel: {
        channel_ref: "muse-label-03-public",
        scope: {
          worlds: { kind: "some", values: [scope.world_id] },
          facets: { kind: "some", values: [scope.scope_facet_id] },
          // bands are entity-type bytes; CLAIM=0, separate from sensitivity.
          bands: { kind: "some", values: [0] },
          audience: { kind: "all" },
          verbs: { kind: "some", values: ["read"] },
          sensitivity: { kind: "at_most", value: "public" },
        },
      },
    } satisfies FacadeInput<"vault.export.scoped">);
    const exportText = scopedExport.records
      .map((record) => Buffer.from(record.bytes).toString("utf8"))
      .join("\n");
    expect(exportText.includes(publicSentinel)).toBe(true);
    expect(exportText.includes(sourceSentinel)).toBe(false);
    expect(exportText.includes(derivedSentinel)).toBe(false);
    expect(exportText.includes(turnSentinel)).toBe(false);

    // Survive a restart, then repeat the public-only checks through recall,
    // the filtered claim read, and the second (reader agent) actor.
    stage = "restart and reader recall";
    await engine.restart();
    museLabel03OnlyClaim(
      await engine.client.call("vault.claims.list", {
        subject_ref: conversation.id,
        predicate: "label03.derived_note",
        limit: 10,
      } satisfies FacadeInput<"vault.claims.list">),
      derivedValue,
    );
    const derivedAfterRestart = await engine.client.call("vault.claims.read_filtered", {
      claim_ref: derivedClaimView.claim_ref,
      filter: { max_sensitivity_band: 0 },
    } satisfies FacadeInput<"vault.claims.read_filtered">);
    expect(derivedAfterRestart.value).toBeNull();
    const publicAfterRestart = await museLabel03Recall(engine.client, queryToken, true);
    expect(museLabel03Includes(publicAfterRestart, publicSentinel)).toBe(true);
    expect(museLabel03Includes(publicAfterRestart, derivedSentinel)).toBe(false);
    stage = "ENGINE DEFECT 2026-11-11: FIX 23103 Proposed Public control is absent from the reader recall";
    const readerRecall = await museLabel03Recall(reader.client, queryToken, true);
    expect(museLabel03Includes(readerRecall, publicSentinel)).toBe(true);
    expect(museLabel03Includes(readerRecall, derivedSentinel)).toBe(false);
    expect(museLabel03Includes(readerRecall, sourceSentinel)).toBe(false);

    // Refuse the wrong actor kind for a read: the write-only agent has no
    // core:read grant behind vault.hydrate, and learns no claim text.
    stage = "write-only actor read refusal";
    const refusedHydrate = await writeOnly.client.raw(
      "POST",
      "/v1/core/facade/vault.hydrate",
      { refs: [publicClaim.claim_short_id] } satisfies FacadeInput<"vault.hydrate">,
    );
    expect(refusedHydrate.status).toBe(403);
    const refusedHydrateError = museLabel03Object(
      museLabel03Object(refusedHydrate.body).error,
    );
    expect(typeof refusedHydrateError.code).toBe("string");
    expect(typeof refusedHydrateError.message).toBe("string");

    // Refuse the wrong actor kind for a write, and read the refusal receipt
    // back under the invocation id this case supplied for that one raw call.
    stage = "read-only actor write refusal receipt";
    const invocation = secretHex(16);
    redactor.add(invocation);
    const refusedWrite = await reader.client.raw(
      "POST",
      "/v1/core/facade/vault.claims.upsert",
      {
        predicate: "label03.forbidden_note",
        subject_ref: conversation.id,
        value: forbiddenValue,
        confidence: 1,
        source: "user_stated",
        scope,
        sensitivity: 0,
        evidence_turn_refs: [turnHex],
        occurred_at: occurred,
      } satisfies FacadeInput<"vault.claims.upsert">,
      { "x-oneiron-invocation": invocation },
    );
    expect(refusedWrite.status).toBe(403);
    const refusedWriteError = museLabel03Object(
      museLabel03Object(refusedWrite.body).error,
    );
    expect(typeof refusedWriteError.code).toBe("string");
    expect(typeof refusedWriteError.message).toBe("string");
    const admission = await reader.client.call("self.admission.status", {
      intent_key: invocation,
    } satisfies FacadeInput<"self.admission.status">);
    expect(admission?.verb).toBe("vault.claims.upsert");
    expect(admission?.state.status).toBe("refused");
    const forbiddenClaims = await engine.client.call("vault.claims.list", {
      subject_ref: conversation.id,
      predicate: "label03.forbidden_note",
      limit: 10,
    } satisfies FacadeInput<"vault.claims.list">);
    expect(forbiddenClaims.value).toHaveLength(0);

    // Lose the grant mid-flow: the owner revokes the reader's slip through
    // the public revoke door, the reader's next recall is refused, and the
    // revocation is read back in the authority audit.
    stage = "reader slip revoke and next use";
    const auditBeforeRevoke = await museLabel03AuditRows(engine.client);
    const readerSlipId = museLabel03MintedSlipId(
      auditBeforeReader,
      auditBeforeRevoke,
      reader.principalRef,
    );
    redactor.add(readerSlipId);
    const revoked = await engine.client.request<{ revoked: boolean }>(
      "POST",
      "/v1/core/slips/revoke",
      { slip_id: Array.from(Buffer.from(readerSlipId, "hex")) },
    );
    expect(revoked.status).toBe(200);
    expect(revoked.body.revoked).toBe(true);
    const refusedRecall = await reader.client.raw(
      "POST",
      "/v1/core/facade/vault.recall",
      {
        query: queryToken,
        effort: "light",
        limit: 1,
      } satisfies FacadeInput<"vault.recall">,
    );
    expect(refusedRecall.status).toBe(401);
    const refusedRecallError = museLabel03Object(
      museLabel03Object(refusedRecall.body).error,
    );
    expect(museLabel03Includes(refusedRecall.body, publicSentinel)).toBe(false);
    const finalAudit = await museLabel03AuditRows(engine.client);
    expect(finalAudit.some((row) => row.source_op === "slip_revoke"
      && row.subject_ref === readerSlipId && row.fold_valid)).toBe(true);

    // Control: the refusal above is the lost slip, not a dead server.
    museLabel03OnlyClaim(
      await engine.client.call("vault.claims.list", {
        subject_ref: conversation.id,
        predicate: "label03.derived_note",
        limit: 10,
      } satisfies FacadeInput<"vault.claims.list">),
      derivedValue,
    );
    await engine.artifacts.json("muse-label-03-receipts.json", {
      turn: witnessed.turn_short_id,
      writeReceipt: witnessed.receipt_ref,
      claims: {
        source: sourceClaim.claim_short_id,
        sourceReceipt: sourceClaim.receipt_ref,
        public: publicClaim.claim_short_id,
        publicReceipt: publicClaim.receipt_ref,
        derived: derivedClaim.claim_short_id,
        derivedReceipt: derivedClaim.receipt_ref,
      },
      readerSlipRevoked: revoked.body.revoked,
    });
  } catch (error) {
    if (error instanceof PublicHttpError) {
      throw new Error(
        `MUSE-LABEL-03 ${stage}: status=${error.reply.status} code=${error.error?.code ?? "<none>"} message=${error.error?.message ?? "<none>"} suggestion=${error.error?.suggestions?.[0] ?? "<none>"}`,
        { cause: error },
      );
    }
    throw new Error(`MUSE-LABEL-03 ${stage}: ${errorText(error)}`, { cause: error });
  } finally {
    await engine.close();
  }
});


// MUSE-LABEL-04 (PARTIAL) — P-LABEL-025 subset only.
// P-LABEL-025: Guest federation capabilities cannot widen access to the host
// vault. This case proves the mint-side slice a user would recognise: an
// owner can mint an inert Connect guest grant for exactly one named local
// WORLD with only the "read"/"propose" verbs, the resolved scope is not
// widened to base reality or to any other verb, wider grants are refused,
// a paired agent cannot mint one, and a revoked guest grant mints no new
// slip. Doors used: vault.federation.connect.identity, vault.structural.put,
// vault.get, vault.federation.status, vault.federation.connect.grants.mint,
// vault.guests.mint_slip, vault.guests.revoke, vault.receipts.get, owner
// pairing and agent pairing.
// P-LABEL-024 stays UNPROVED here: no typed door in the generated facade
// returns the window_key vault.federation.connect.export and
// vault.guests.share require, privacy.test.ts is a one-slot file (a second
// live peer vault needs two slots), and the harness has no way to turn a
// minted guest slip into a guest client. The report names the missing
// doors. Nothing in this case ships a federated slice or reads an edge on
// a guest vault.
const museLabel04OccurredAt = 1769947200;
const museLabel04SlipExpiresAt = 1893456000;
const museLabel04WorldName = "Muse Label 04 Named World";
const museLabel04AgentName = "Muse Label 04 Agent";

interface museLabel04ErrorEnvelope {
  error: {
    code: string;
    message: string;
    requestId: string;
    receiptRef?: string;
  };
}

type museLabel04MintInput = FacadeInput<"vault.federation.connect.grants.mint">;
type museLabel04ResolvedScope =
  FacadeResult<"vault.federation.connect.grants.mint">["resolved_scope"];

function museLabel04Mint(
  peerVault: string,
  worldId: string,
  facetId: string,
  verbs: readonly string[],
): museLabel04MintInput {
  return {
    peer_vault: peerVault,
    authority_scope: {
      worlds: { kind: "some", values: [worldId] },
      facets: { kind: "some", values: [facetId] },
      bands: { kind: "all" },
      audience: { kind: "all" },
      sensitivity: { kind: "at_most", value: "private" },
      verbs: { kind: "some", values: [...verbs] },
    },
  };
}

function museLabel04AxisValues(
  axis: museLabel04ResolvedScope["worlds"],
): string[] {
  if (axis === undefined || axis.kind === "bottom") return [];
  if (axis.kind === "all") {
    throw new Error("MUSE-LABEL-04 resolved guest scope widened an axis to all");
  }
  return [...axis.values];
}

// One refused facade call, checked three ways: an expected HTTP status, the
// standard {error:{code,message,...}} envelope, and the call receipt the
// refusal leaves, read back by the owner through vault.receipts.get.
async function museLabel04Refused(
  actor: PublicHttpClient,
  owner: PublicHttpClient,
  verb: string,
  input: unknown,
  statuses: readonly number[],
): Promise<string> {
  const denied = await actor.raw<museLabel04ErrorEnvelope>(
    "POST", `/v1/core/facade/${verb}`, input,
  );
  if (!statuses.includes(denied.status)) throw new PublicHttpError(denied);
  expect(statuses).toContain(denied.status);
  const error = denied.body?.error;
  if (!error || typeof error.code !== "string" || error.code.length === 0
    || typeof error.message !== "string" || error.message.length === 0
    || typeof error.requestId !== "string" || error.requestId.length === 0) {
    throw new Error(`MUSE-LABEL-04 refusal for ${verb} has no standard error envelope`);
  }
  const receiptRef = error.receiptRef && error.receiptRef.length > 0
    ? error.receiptRef : `call:${error.requestId}`;
  const receipt = await awaitPublic(
    () => owner.call("vault.receipts.get", { receipt_ref: receiptRef }),
    value => value !== null,
    { label: `MUSE-LABEL-04 refusal receipt for ${verb}` },
  );
  if (!receipt) throw new Error(`MUSE-LABEL-04 refusal for ${verb} left no call receipt`);
  expect(receipt.verb).toBe(verb);
  if (receipt.outcome === "ok") {
    throw new Error(`MUSE-LABEL-04 call receipt for ${verb} does not record a refusal`);
  }
  expect(receipt.outcome.refused.code).toBe(error.code);
  return error.code;
}

suite.test(test, "MUSE-LABEL-04", "A guest federation grant stays inside its named-world read/propose ceiling and a revoked guest grant mints no new slip", async () => {
  redactor.add(museLabel04WorldName, museLabel04AgentName);

  // A real second vault identity, read before this one-slot file starts the
  // host vault (the SECRETS-01 sequential-vault pattern). No peers option,
  // no concurrent second server.
  let stage = "peer identity setup";
  const peer = await EngineFixture.start({ id: "MUSE-LABEL-04-peer", profile });
  let peerVault = "";
  let peerHolderKey = "";
  try {
    const peerIdentity = await peer.client.call("vault.federation.connect.identity", {});
    expect(peerIdentity.vault.length).toBeGreaterThan(0);
    peerVault = peerIdentity.vault;
    peerHolderKey = peerIdentity.host_key;
  } catch (error) {
    if (error instanceof PublicHttpError) {
      throw new Error(
        `MUSE-LABEL-04 ${stage}: status=${error.reply.status} code=${error.error?.code ?? "<none>"} message=${error.error?.message ?? "<none>"} suggestion=${error.error?.suggestions?.[0] ?? "<none>"}`,
        { cause: error },
      );
    }
    throw new Error(`MUSE-LABEL-04 ${stage}: ${errorText(error)}`, { cause: error });
  } finally {
    await peer.close();
  }
  if (peerVault.length === 0) throw new Error("MUSE-LABEL-04 peer vault has no identity");

  const engine = await EngineFixture.start({ id: "MUSE-LABEL-04", profile });
  try {
    stage = "host identity and named WORLD readback";
    const hostIdentity = await engine.client.call("vault.federation.connect.identity", {});
    expect(hostIdentity.vault.length).toBeGreaterThan(0);
    expect(hostIdentity.vault).not.toBe(peerVault);

    // The owner's base claim scope supplies the reserved base world id and
    // the owner's substrate facet; the guest grant must name neither base
    // nor any facet but the one named.
    const baseScope = await ownerBaseClaimScope(engine.client, engine.pairedActor.principalRef);

    // Act: create one named local WORLD, then read it back through vault.get.
    const world = await engine.client.call("vault.structural.put", {
      kind: "WORLD",
      body: { name: museLabel04WorldName, kind: "fictional" },
      occurred_at: museLabel04OccurredAt,
    } satisfies FacadeInput<"vault.structural.put">);
    const worldRead = await engine.client.call("vault.get", { entity_ref: world.entity_ref });
    expect(worldRead.value?.kind).toBe("WORLD");
    expect(worldRead.value?.id_hex).toBe(world.id_hex);
    expect(world.id_hex).not.toBe(baseScope.world_id);

    // An inert guest grant activates no pact on its own.
    expect((await engine.client.call("vault.federation.status", {})).pacts).toEqual([]);

    // Act: the owner mints a Connect guest grant for the peer vault over
    // exactly this named world and facet, with only "read"/"propose".
    const validMint = museLabel04Mint(
      peerVault, world.id_hex, baseScope.scope_facet_id, ["read", "propose"],
    );
    stage = "complete six-axis named-world guest grant mint";
    const grant = await engine.client.call("vault.federation.connect.grants.mint", validMint);
    expect(grant.grant.length).toBeGreaterThan(0);
    // The resolved ceiling is not widened: exactly the named world (never
    // the reserved base world), no facet but the named substrate, and no
    // verb but "read"/"propose" — with "read" actually granted.
    expect(museLabel04AxisValues(grant.resolved_scope.worlds)).toEqual([world.id_hex]);
    for (const facet of museLabel04AxisValues(grant.resolved_scope.facets)) {
      expect(facet).toBe(baseScope.scope_facet_id);
    }
    const resolvedVerbs = museLabel04AxisValues(grant.resolved_scope.verbs);
    expect(resolvedVerbs).toContain("read");
    for (const verb of resolvedVerbs) expect(["read", "propose"]).toContain(verb);
    // Observe through a second door: minting the inert grant alone still
    // leaves this vault with no pact.
    expect((await engine.client.call("vault.federation.status", {})).pacts).toEqual([]);

    // An inert Connect grant is stored, but is not yet authority to mint a
    // guest credential: that also needs an operative pact. Read the grant
    // through a second door and check the inactive-pact refusal explicitly.
    stage = "stored inert grant readback and inactive-pact slip refusal";
    const grantRead = await engine.client.call("vault.get", { entity_ref: grant.grant });
    expect(grantRead.value?.kind).toBe("FEDERATION_GRANT");
    expect(grantRead.value?.id_hex).toBe(grant.grant);
    expect(object(grantRead.value?.body).authority_scope).toEqual(grant.resolved_scope);
    const slipInput = {
      grant_ref: grant.grant, holder_key: peerHolderKey,
      expires_at: museLabel04SlipExpiresAt,
    } satisfies FacadeInput<"vault.guests.mint_slip">;
    await museLabel04Refused(engine.client, engine.client,
      "vault.guests.mint_slip", slipInput, [400, 403, 422]);

    // Refuse a widened grant: a verb outside "read"/"propose" is rejected,
    // and so is a grant that names the reserved base world. Each refusal
    // leaves a call receipt the owner reads back.
    stage = "widened-verb and base-world grant refusals";
    await museLabel04Refused(engine.client, engine.client,
      "vault.federation.connect.grants.mint",
      museLabel04Mint(peerVault, world.id_hex, baseScope.scope_facet_id,
        ["read", "propose", "write"]),
      [400, 403, 422]);
    await museLabel04Refused(engine.client, engine.client,
      "vault.federation.connect.grants.mint",
      museLabel04Mint(peerVault, baseScope.world_id, baseScope.scope_facet_id,
        ["read", "propose"]),
      [400, 403, 422]);

    // Refuse the wrong actor kind: a paired agent with ordinary read/write
    // credential scope cannot mint a guest grant on the host.
    stage = "agent guest-grant mint refusal";
    const agentRecord = await engine.client.call("vault.structural.put", {
      kind: "PERSON", body: { name: museLabel04AgentName },
      occurred_at: museLabel04OccurredAt,
    } satisfies FacadeInput<"vault.structural.put">);
    const agent = await engine.pairActor({
      principalRef: agentRecord.id_hex, actorClass: "agent",
      scope: ["core:read", "core:write"],
    });
    await museLabel04Refused(agent.client, engine.client,
      "vault.federation.connect.grants.mint", validMint, [403]);
    // The refused mints changed nothing observable: still no pact.
    expect((await engine.client.call("vault.federation.status", {})).pacts).toEqual([]);

    // Survive a restart: the named world and the no-pact state read back
    // unchanged, and the grant is still live enough to revoke below.
    stage = "restart named-world and inert-grant readback";
    await engine.restart();
    const worldAfterRestart = await engine.client.call("vault.get", { entity_ref: world.entity_ref });
    expect(worldAfterRestart.value?.kind).toBe("WORLD");
    expect(worldAfterRestart.value?.id_hex).toBe(world.id_hex);
    expect((await engine.client.call("vault.federation.status", {})).pacts).toEqual([]);

    // The owner revokes the guest grant through its public door; the next
    // use of that grant — minting another slip — is refused with a receipt.
    stage = "guest grant revoke and next slip refusal";
    const revoked = await engine.client.call("vault.guests.revoke", {
      grant_ref: grant.grant,
    } satisfies FacadeInput<"vault.guests.revoke">);
    expect(revoked.grant_ref).toBe(grant.grant);
    expect(revoked.changed).toBe(true);
    expect((await engine.client.call("vault.get", { entity_ref: grant.grant })).value).toBeNull();
    // Withdrawal is checked before pact admission and answers NOT_FOUND (404),
    // unlike the inactive but still-stored grant checked above.
    const revokedCode = await museLabel04Refused(engine.client, engine.client,
      "vault.guests.mint_slip", slipInput, [404]);
    expect(revokedCode).toBe("NOT_FOUND");
  } catch (error) {
    if (error instanceof PublicHttpError) {
      throw new Error(
        `MUSE-LABEL-04 ${stage}: status=${error.reply.status} code=${error.error?.code ?? "<none>"} message=${error.error?.message ?? "<none>"} suggestion=${error.error?.suggestions?.[0] ?? "<none>"}`,
        { cause: error },
      );
    }
    throw new Error(`MUSE-LABEL-04 ${stage}: ${errorText(error)}`, { cause: error });
  } finally {
    await engine.close();
  }
});


// MUSE-LABEL-05 — owner-only linked facet fork and durable ledger (E2E-PARTIAL).
// Title: Only the owner can fork a claim to a facet; the original keeps its scope and the linked fork and ledger survive restart.
// P-LABEL-015: neither read-only nor read/write agent applies the fork; the
// owner applies it. The clearance-offer half is not exercised (FIX 22495).
// P-LABEL-006: the CLAIM fork has the new facet and a derived_from link;
// the origin's ClaimScope and scope position do not change.
// P-LABEL-016: the fork's topology event and owner governance receipt read
// back through identity.events.get and receipts, again after restart.
// Doors: vault.conversations.create, vault.witness, vault.people.create,
// vault.structural.put, vault.get, vault.claims.upsert/list/history,
// vault.scope.position, vault.identity.resolve/facet/events.get,
// vault.neighbors, vault.receipts/get, vault.authority.audit, self.actor,
// POST /v1/core/slips/revoke, raw facade refusals, pairActor and restart.
// Unproved: clearance-offer no-widening and sharing durability (model-backed
// companion plus vault.counterparty_contacts.create, FIX 22495), owner offer
// application (expected_delta unspecified), private/public or invariant
// promotion, NOTE/ASSET forks, model-proposal and behavioural-inference widening,
// and restamp-style upsert (ScopedClaimInput.id semantics unspecified).

type MuseLabel05Receipt = FacadeResult<"vault.receipts">["receipts"][number];
type MuseLabel05AuditRow = FacadeResult<"vault.authority.audit">["rows"][number];
type MuseLabel05ClaimRow = FacadeResult<"vault.claims.list">["value"][number];

const museLabel05ReceiptKinds: string[] = [
  "outbound", "gate", "identity_lifecycle", "scoped_read", "share", "artifact_settle",
  "proposal_outcome", "commitment_lifecycle", "extraction", "served_form", "hook",
  "reference_refusal", "task_lifecycle",
];

async function museLabel05Receipts(client: PublicHttpClient): Promise<MuseLabel05Receipt[]> {
  const rows: MuseLabel05Receipt[] = [];
  let after: string | undefined;
  do {
    const page = await client.call("vault.receipts", {
      limit: 100, kinds: [...museLabel05ReceiptKinds],
      ...(after === undefined ? {} : { after }),
    });
    rows.push(...page.receipts);
    after = page.next_after ?? undefined;
  } while (after !== undefined);
  return rows;
}

async function museLabel05AuditRows(client: PublicHttpClient): Promise<MuseLabel05AuditRow[]> {
  const rows: MuseLabel05AuditRow[] = [];
  let after: string | undefined;
  const cursors = new Set<string>();
  for (;;) {
    const query: FacadeInput<"vault.authority.audit"> = {
      limit: 500, ...(after ? { after } : {}),
    };
    const page = await client.call("vault.authority.audit", query);
    rows.push(...page.rows);
    const nextAfter = page.next_after;
    if (!nextAfter) return rows;
    cursors.add(nextAfter);
    after = nextAfter;
  }
}

function museLabel05MintedSlip(
  before: readonly MuseLabel05AuditRow[],
  after: readonly MuseLabel05AuditRow[],
  holder: string,
): MuseLabel05AuditRow {
  const existing = new Set(before.map(row => row.entry_hash));
  const minted = after.filter(row => !existing.has(row.entry_hash)
    && row.source_op === "slip_mint" && row.holder_ref === holder);
  const row = minted[0]!;
  return row;
}

function museLabel05ClaimRowFor(
  rows: readonly MuseLabel05ClaimRow[], claimId: string,
): MuseLabel05ClaimRow | undefined {
  return rows.find(row => row.claim_ref === claimId || row.claim?.id === claimId);
}

suite.test(test, "MUSE-LABEL-05", "Only the owner can fork a claim to a facet; the original keeps its scope and the linked fork and ledger survive restart", async () => {
  const engine = await EngineFixture.start({ id: "MUSE-LABEL-05", profile });
  let primaryFailed = false;
  let primary: unknown;
  let stage = "people and scoped actors";
  try {
    const occurred = 1769947200;
    const suffix = secretHex(4);
    const sentinel = `label05-private-sentinel-${secretHex(8)}`;
    redactor.add(sentinel);
    const predicate = "privacy.label05_private_note";
    const ownerPrincipal = engine.pairedActor.principalRef;
    const ownerActorRef = (await engine.client.call("self.actor", {})).actor_ref;

    // People and actors, all through public doors. The subject PERSON follows
    // the witness-then-create pattern; the agent PERSON record follows
    // the structural create pattern. Pairing never creates a person.
    const subjectName = `Label05 Subject ${suffix}`;
    const conversation = await engine.client.call("vault.conversations.create", {
      body: {}, occurred_start: occurred, occurred_end: occurred, learned_at: occurred,
    } satisfies FacadeInput<"vault.conversations.create">);
    const witnessed = await engine.client.call("vault.witness", {
      conversation_ref: conversation.id,
      occurred_at: occurred,
      messages: [{
        author: "user", message_type: "text",
        content: `This distinct person is ${subjectName}.`,
        is_visible: true, order: 0,
      }],
    } satisfies FacadeInput<"vault.witness">);
    const turn = await engine.client.call("vault.get", { entity_ref: witnessed.turn_short_id });
    if (turn.value?.kind !== "TURN" || !turn.value.id_hex) {
      throw new Error("Witnessed TURN missing");
    }
    const turnIdHex = turn.value.id_hex;
    const subject = await engine.client.call("vault.people.create", {
      identity: { name: subjectName },
      identity_evidence_refs: [turnIdHex],
      occurred_at: occurred,
    } satisfies FacadeInput<"vault.people.create">);
    const subjectId = subject.person.id_hex;
    const subjectRead = await engine.client.call("vault.get", {
      entity_ref: subject.person.entity_ref,
    });
    expect(subjectRead.value?.kind).toBe("PERSON");

    const agentRecord = await engine.client.call("vault.structural.put", {
      kind: "PERSON", body: { name: `Label05 Agent ${suffix}` }, occurred_at: occurred,
    } satisfies FacadeInput<"vault.structural.put">);
    const agentPersonId = agentRecord.id_hex;

    // One agent person, two slips: read-only (without the write grant) and
    // read/write. The read/write slip is captured from the authority audit so
    // the owner can revoke exactly it mid-flow.
    const agentRead = await engine.pairActor({
      principalRef: agentPersonId, actorClass: "agent", scope: ["core:read"],
    });
    const auditBeforeWritePair = await museLabel05AuditRows(engine.client);
    const agentWrite = await engine.pairActor({
      principalRef: agentPersonId, actorClass: "agent", scope: ["core:read", "core:write"],
    });
    const writeSlip = museLabel05MintedSlip(
      auditBeforeWritePair, await museLabel05AuditRows(engine.client), agentPersonId,
    );
    const writeSlipId = writeSlip.subject_ref!;
    const agentActorRef = (await agentWrite.client.call("self.actor", {})).actor_ref;

    // The owner authors the origin claim under the substrate mask, then reads
    // it back through doors that did not write it.
    const scope = await ownerBaseClaimScope(engine.client, ownerPrincipal);
    stage = "origin claim and scope readbacks";
    const originCommit = await engine.client.call("vault.claims.upsert", {
      subject_ref: subjectId, predicate, value: sentinel,
      confidence: 1, source: "user_stated", scope, occurred_at: occurred,
    } satisfies FacadeInput<"vault.claims.upsert">);
    expect(originCommit.approval).toBe("auto");
    if (!originCommit.claim) throw new Error("Origin claim has no typed record reference");
    const originId = originCommit.claim.id;
    await engine.awaitReceipt(originCommit.receipt_ref);

    const listSubjectClaims = async (): Promise<MuseLabel05ClaimRow[]> =>
      (await engine.client.call("vault.claims.list", {
        subject_ref: subjectId, predicate, limit: 10,
      } satisfies FacadeInput<"vault.claims.list">)).value;
    const positionOf = async (recordRef: string) => {
      const read = await engine.client.call("vault.scope.position", { record_ref: recordRef });
      const value = read.value;
      if (!value) throw new Error("Record has no stamped scope position");
      return value;
    };

    const beforeRows = await listSubjectClaims();
    expect(beforeRows).toHaveLength(1);
    const originBefore = museLabel05ClaimRowFor(beforeRows, originId);
    if (!originBefore) throw new Error("Origin claim does not read back by subject");
    expect(originBefore.value).toBe(sentinel);
    expect(originBefore.claim_scope.scope_facet_id).toBe(scope.scope_facet_id);
    const originClaimScopeBefore = originBefore.claim_scope;
    const originShort = originBefore.short_ref ?? originCommit.claim_short_id;
    const originPositionBefore = await positionOf(originId);
    expect(originPositionBefore.kind).toBe("position");
    const resolvedBefore = await engine.client.call("vault.identity.resolve", {
      entity: subjectId,
    });
    const facetsBefore = resolvedBefore.facets;
    const baselineReceiptRefs = new Set(
      (await museLabel05Receipts(engine.client)).map(row => row.receipt_ref),
    );

    const facetLabel = `label05 mask ${suffix}`;
    const facetInput = {
      entity: subjectId,
      facets: [{ label: facetLabel }],
      reassignment_map: [{
        item: { kind: "claim", claim: originId },
        target: { kind: "facet", index: 0 },
      }],
      evidence: {
        refs: [turnIdHex],
        rationale: "Owner separates this generated claim under a new mask.",
      },
    } satisfies FacadeInput<"vault.identity.facet">;

    // Wrong actors first, with the exact input the owner uses below. A facet
    // fork is a move only the owner may apply; neither agent slip may do it,
    // and the read/write refusal leaves a governance receipt.
    stage = "agent facet-fork admission refusal and call receipts";
    const readDenied = await agentRead.client.raw<{
      error: { code: string; message: string; suggestions?: string[]; receiptRef?: string };
    }>(
      "POST", "/v1/core/facade/vault.identity.facet", facetInput,
    );
    expect(readDenied.status).toBe(403);
    expect(readDenied.body.error?.code?.length ?? 0).toBeGreaterThan(0);
    const writeDenied = await agentWrite.client.raw<{
      error: { code: string; message: string; suggestions?: string[]; receiptRef?: string };
    }>(
      "POST", "/v1/core/facade/vault.identity.facet", facetInput,
    );
    expect(writeDenied.status).toBe(403);
    expect(writeDenied.body.error?.code?.length ?? 0).toBeGreaterThan(0);
    // Host-door admission refuses before a topology/Gate row is written.
    // Its durable evidence is the HTTP facade call receipt, not receipts().
    let refusalReceiptRef = "";
    for (const [actorLabel, denied] of [["read-only", readDenied], ["read/write", writeDenied]] as const) {
      const receiptRef = denied.body.error?.receiptRef;
      if (!receiptRef) {
        throw new Error(`MUSE-LABEL-05 ${actorLabel} facet-fork refusal: status=${denied.status} code=${denied.body.error?.code ?? "<none>"} message=${denied.body.error?.message ?? "<none>"} suggestion=${denied.body.error?.suggestions?.[0] ?? "<none>"}; no receiptRef`);
      }
      const receipt = await awaitPublic(
        () => engine.client.call("vault.receipts.get", { receipt_ref: receiptRef }),
        value => value !== null,
        { label: `MUSE-LABEL-05 ${actorLabel} facet-fork call receipt ${receiptRef}`, timeoutMs: 5_000 },
      );
      if (!receipt) throw new Error("Agent facet-fork refusal left no call receipt");
      expect(receipt.actor_ref).toBe(agentActorRef);
      expect(receipt.verb).toBe("vault.identity.facet");
      if (receipt.outcome === "ok") throw new Error("Agent facet-fork receipt records success");
      expect(receipt.outcome.refused.code).toBe(denied.body.error.code);
      if (actorLabel === "read/write") refusalReceiptRef = receiptRef;
    }

    // Nothing moved: still one claim, same stamp, no new facet on the subject.
    const afterRefusalRows = await listSubjectClaims();
    expect(afterRefusalRows).toHaveLength(1);
    expect(museLabel05ClaimRowFor(afterRefusalRows, originId)?.claim_scope)
      .toEqual(originClaimScopeBefore);
    expect((await positionOf(originId)).scope).toEqual(originPositionBefore.scope);
    expect((await engine.client.call("vault.identity.resolve", { entity: subjectId })).facets)
      .toEqual(facetsBefore);

    // The owner applies the same fork. Read every effect back elsewhere.
    stage = "owner facet fork and linked-claim readbacks";
    const forkResult = await engine.client.call("vault.identity.facet", facetInput);
    expect(forkResult.outcome).toBe("applied");
    if (forkResult.outcome !== "applied") throw new Error("Owner facet fork did not apply");
    const topologyReceipt = forkResult.receipt;
    const topologyAction = topologyReceipt.action;
    expect(topologyAction.op).toBe("facet");
    if (topologyAction.op !== "facet") {
      throw new Error("Owner facet fork recorded a different topology action");
    }
    expect(topologyAction.forked).toHaveLength(1);
    expect(topologyAction.facets).toHaveLength(1);
    // The event lists forked ORIGIN ids, not the newly minted claim ids.
    expect(topologyAction.forked).toEqual([originId]);
    const newFacetId = topologyAction.facets[0];
    if (!newFacetId) throw new Error("Owner facet fork named no facet");
    const topologyEvent = topologyReceipt.event;
    expect(newFacetId).not.toBe(scope.scope_facet_id);

    const afterForkRows = await listSubjectClaims();
    const forks = afterForkRows.filter(row => row.claim?.id !== originId
      && row.claim_scope.scope_facet_id === newFacetId && row.value === sentinel);
    expect(forks).toHaveLength(1);
    const forkRow = forks[0];
    const forkId = forkRow?.claim?.id;
    if (!forkRow || !forkId) throw new Error("Facet fork does not read back by subject");
    expect(forkId).not.toBe(originId);
    expect(forkRow.claim_scope.scope_facet_id).toBe(newFacetId);
    expect(forkRow.subject_ref).toBe(subjectId);
    expect(forkRow.predicate).toBe(predicate);
    expect(forkRow.value).toBe(sentinel);
    // The fork may supersede the origin; if the origin still lists, its stamp
    // must be the original one. Its timeline must start with the original too.
    const originAfter = museLabel05ClaimRowFor(afterForkRows, originId);
    if (originAfter) expect(originAfter.claim_scope).toEqual(originClaimScopeBefore);
    const historyRows = (await engine.client.call("vault.claims.history", {
      claim_ref: originId,
    })).value;
    expect(historyRows.length).toBeGreaterThanOrEqual(1);
    expect(historyRows[0]?.claim_scope).toEqual(originClaimScopeBefore);
    expect((await positionOf(originId)).scope).toEqual(originPositionBefore.scope);

    const forkNeighbours = await engine.client.call("vault.neighbors", {
      entity_ref: forkId, opts: { edge_kind: "derived_from", limit: 10 },
    });
    const neighbourIds = forkNeighbours.value.flatMap(hit => [
      hit.short_id, hit.record?.id ?? "", hit.record?.short_id ?? "",
    ]);
    expect(neighbourIds.some(id => id === originId || id === originShort)).toBe(true);
    expect((await engine.client.call("vault.identity.resolve", { entity: subjectId })).facets)
      .toContain(newFacetId);

    // The decision is in the ledger, read through doors that did not write it.
    stage = "owner facet-fork ledger readbacks";
    const recordedEvent = await engine.client.call("vault.identity.events.get", {
      event: topologyEvent,
    });
    expect(recordedEvent.event).toBe(topologyEvent);
    expect(recordedEvent.seen).toBe(topologyReceipt.seen);
    const recordedAction = recordedEvent.action;
    expect(recordedAction.op).toBe("facet");
    if (recordedAction.op !== "facet") {
      throw new Error("Recorded topology event is not the facet fork");
    }
    expect(recordedAction.forked).toContain(originId);
    expect(recordedAction.facets).toContain(newFacetId);
    const forkLedgerRows = await awaitPublic(
      () => museLabel05Receipts(engine.client),
      rows => rows.some(row => !baselineReceiptRefs.has(row.receipt_ref)
        && row.kind === "identity_lifecycle"
        && (row.actor_ref === ownerActorRef || row.actor_ref === ownerPrincipal)),
      { label: "owner facet-fork governance receipt", timeoutMs: 5_000 },
    );
    const forkReceipt = forkLedgerRows.find(row => !baselineReceiptRefs.has(row.receipt_ref)
      && row.kind === "identity_lifecycle"
      && (row.actor_ref === ownerActorRef || row.actor_ref === ownerPrincipal));
    if (!forkReceipt) throw new Error("Owner facet fork left no governance receipt");
    await engine.artifacts.json("muse-label05-ledger.json", {
      subjectId, originId, forkId, newFacetId, topologyEvent,
      refusalReceiptRef,
      forkReceiptRef: forkReceipt.receipt_ref,
    });

    // E2E-PARTIAL: the clearance-offer half needs a model-backed companion
    // PERSON and a CID-7 contact. Ordinary PERSON fixtures do not supply them;
    // vault.counterparty_contacts.create is missing (FIX 22495). Filing an
    // offer without widening, owner application and sharing durability stay
    // unproved. The owner-only linked fork and its ledger remain in this case.

    // The owner revokes the same agent's slip, then reads the authority audit.
    stage = "agent slip revoke";
    const revoked = await engine.client.request<{ revoked: boolean }>(
      "POST", "/v1/core/slips/revoke",
      { slip_id: Array.from(Buffer.from(writeSlipId, "hex")) },
    );
    expect(revoked.status).toBe(200);
    expect(revoked.body.revoked).toBe(true);
    expect((await museLabel05AuditRows(engine.client)).some(row =>
      row.source_op === "slip_revoke" && row.subject_ref === writeSlipId && row.fold_valid,
    )).toBe(true);

    // Everything above survives a restart, read back through the same doors.
    stage = "restart fork ledger readbacks";
    await engine.restart();
    const afterRestartRows = await listSubjectClaims();
    const forkAfterRestart = museLabel05ClaimRowFor(afterRestartRows, forkId);
    if (!forkAfterRestart) throw new Error("Facet fork does not read back after restart");
    expect(forkAfterRestart.claim_scope.scope_facet_id).toBe(newFacetId);
    expect(forkAfterRestart.value).toBe(sentinel);
    const originAfterRestart = museLabel05ClaimRowFor(afterRestartRows, originId);
    if (originAfterRestart) {
      expect(originAfterRestart.claim_scope).toEqual(originClaimScopeBefore);
    }
    expect((await positionOf(originId)).scope).toEqual(originPositionBefore.scope);
    expect((await engine.client.call("vault.identity.resolve", { entity: subjectId })).facets)
      .toContain(newFacetId);
    expect((await engine.client.call("vault.identity.events.get", {
      event: topologyEvent,
    })).seen).toBe(topologyReceipt.seen);
    expect((await museLabel05Receipts(engine.client))
      .some(row => row.receipt_ref === forkReceipt.receipt_ref)).toBe(true);
  } catch (error) {
    primaryFailed = true;
    primary = error instanceof PublicHttpError
      ? new Error(`MUSE-LABEL-05 ${stage}: status=${error.reply.status} code=${error.error?.code ?? "<none>"} message=${error.error?.message ?? "<none>"} suggestion=${error.error?.suggestions?.[0] ?? "<none>"}`, { cause: error })
      : new Error(`MUSE-LABEL-05 ${stage}: ${errorText(error)}`, { cause: error });
  } finally {
    try { await engine.close(); } catch (cleanup) {
      if (primaryFailed) {
        throw new AggregateError([primary, cleanup], `${String(primary)}; cleanup: ${String(cleanup)}`);
      }
      throw cleanup;
    }
    if (primaryFailed) throw primary;
  }
});


// MUSE-LABEL-06 - A room discloses only what every non-owner present may see,
// and narrows at once on doubt.
//
// Promises (stated precisely; changing an assertion later needs a
// "promise changed" ruling):
//   P-LABEL-009 (MUST): A room may disclose public content plus only the
//     scopes cleared for every non-owner present.
//   P-LABEL-010 (MUST): An unknown participant restricts room disclosure
//     to public content.
//   P-LABEL-012 (MUST): An owner's presence does not widen a guest's
//     clearance.
//   P-LABEL-017 (MUST): Uncertain participant identification narrows
//     disclosure immediately.
//   P-LABEL-018 (MUST): A momentary silence does not count as confirmation
//     that a participant has left.
//   P-LABEL-019 (MUST): A newly present participant causes in-flight output
//     to be aborted or redacted under the new disclosure scope.
//   P-LABEL-020 (MUST): The disclosure filter applies to transcript turns
//     as well as retrieved claims.
//   P-LABEL-021 (MUST): A disclosure override requires an
//     owner-authenticated session credential, not voice identification alone.
// Canon: oneiron/gate/one-1592-ildf2-ratify.md #rule, #owner-presence-built
// and #pins (P1/P4/P5/P6/P7), with the consent-channel and DEC-0006 pages
// named in the report. Exact mirror lines are in MUSE-LABEL-06.report.md.
//
// Doors used by this fragment: none. This is a suite.todo registration only.
// It is not passing coverage and it executes no assertion.
//
// Why no executable case is written from the current typed surface:
// the core act is to declare who is PRESENT for a disclosure assembly -
// identified contact, unknown party, or sub-threshold identification -
// then read what the room discloses, then change presence (silence,
// confirmed departure, newcomer arrival) and read again, including while
// output is in flight. In the generated facade snapshot given to this
// writer (1353 rows) there is no verb to report present parties or an
// identification state, no verb to attempt a disclosure override, and no
// facade verb for the context-pack / context-board assemblies canon
// names as reachable routes (POST /v1/core/context-pack,
// POST /v1/core/context-board). Their request/result shapes are not in
// the facade types this writer may check by hand, so calling them raw
// would invent a wire shape. Do not cast a name to FacadeVerb, do not
// send a guessed context-pack body, and do not substitute deterministic
// chat-room membership (vault.rooms.join/leave) for presence under
// identification doubt: a join is deterministic, while P-LABEL-017/018
// are about an identification guess and a silence heuristic, which a
// join/leave case would not prove.
//
// Adjacent typed doors that exist, and why each is not the missing act:
// - vault.rooms.sharing (Read, for a room member) returns a room's
//   effective Scope and clamps, including contact_clearance and unknown
//   member counts. It is a scope view, not a content-disclosure read,
//   and no typed door in the snapshot sets the local contact clearance
//   it meets or reports a party as sub-threshold/unknown-but-present.
// - vault.rooms.messages (Read) returns room turns this reader may read.
//   Canon states a member's own read of a room outside a turn takes no
//   clearance term, so it cannot prove the present-party meet.
// - vault.recall / vault.hydrate (Read) take no room or interlocutor
//   input in their typed requests. Canon states plain recall installs
//   no disclosure clamp; a room turn's recall does, and no typed door
//   here opens such a turn read with a declared roster.
// - vault.disclosure.offer (Write, proposes) lets an agent file a
//   clearance offer for one contact. vault.companions.sharing.set
//   (Write, owner) is a standing yes to a frozen offer for a companion's
//   contact in a companion's source vault, and takes an opaque
//   expected_delta string. Neither is identified in canon or in its
//   catalog line as setting the local present-party contact clearance
//   that room_scope meets.
// - vault.consent.create_standing_grant (Write, owner, host door) can
//   create a disclosure grant bound {audience, class, envelope:
//   {selectors}}. The class/selectors vocabulary that would make it a
//   contact's clearance Scope is not stated in the allowed surface.
// - ai.voice.start (Write, owner-bound, host door) takes an optional
//   room_ref and roster_ref, and ai.voice.events can report a playout
//   stop with reason "roster_changed". No typed door creates or updates
//   that roster mid-session, reports an identification confidence, or
//   submits a voice-only override, so P-LABEL-017/018/019/021 cannot be
//   driven through it without guessing the roster record and the voice
//   route setup.
//
// Types below are CANON DESIGN NOTES, not wire DTOs and not a client
// adapter. Existing-door notes bind generated FacadeInput/FacadeResult.
// Waiting shapes name only canon's semantic arguments and observable
// results; final verb names, HTTP paths and SDK methods must come from
// the typed catalog, never be guessed (G01).
type museLabel06Ref = string;
type museLabel06CurrentRoomSharing = {
  request: FacadeInput<"vault.rooms.sharing">;
  result: FacadeResult<"vault.rooms.sharing">;
};
type museLabel06CurrentClearanceOffer = {
  request: FacadeInput<"vault.disclosure.offer">;
  result: FacadeResult<"vault.disclosure.offer">;
};
type museLabel06CurrentCompanionSharing = {
  setRequest: FacadeInput<"vault.companions.sharing.set">;
  getResult: FacadeResult<"vault.companions.sharing.get">;
};
// P4: sub-threshold identification is UNKNOWN and narrows immediately.
// Departure widens only on deterministic confirmation (channel
// disconnect, owner statement) or after a hold-down window, never on a
// momentary-silence heuristic.
type museLabel06Identification =
  | "identified_contact"
  | "unknown"
  | "sub_threshold";
type museLabel06PresenceEvent =
  | "arrived"
  | "momentary_silence"
  | "departed_channel_disconnect"
  | "departed_owner_statement";
// Waiting door, behind a grant: a typed present-party report for one
// room/session, narrow-only for inference. An ungranted agent must be
// refused, and an agent whose grant is revoked mid-flow must be refused
// at its next report (owner revokes through a public door).
type museLabel06PresenceReport = {
  room: museLabel06Ref;
  party: museLabel06Ref;
  identification: museLabel06Identification;
  event: museLabel06PresenceEvent;
};
// Waiting door: the owner, on an owner-authenticated session credential,
// sets and reads one contact's standing clearance. A clearance is the
// contact's Scope, so the scope field is the existing generated Scope.
type museLabel06ContactClearanceSet = {
  contact: museLabel06Ref;
  scope: Facade.Scope;
};
// Waiting door: one room-scoped disclosure assembly over already-written
// claims and transcript turns, under the room's current present-party
// roster. The result must let a case tell, by record ref, exactly what
// was disclosed, and must carry the effective scope it used.
type museLabel06RoomAssemblyRequest = {
  room: museLabel06Ref;
  query: string;
};
type museLabel06RoomAssembly = {
  disclosed_record_refs: museLabel06Ref[];
  effective: Facade.Scope;
};
// Waiting door: an explicit disclosure override for named records in one
// room. The credential is the caller's owner-authenticated session
// credential; there is deliberately no voice-identification field,
// because voice-detected owner presence never suffices (P6).
type museLabel06DisclosureOverride = {
  room: museLabel06Ref;
  record_refs: museLabel06Ref[];
};
// P5: a roster widening is a barrier event - in-flight generation is
// aborted, or redacted and re-assembled under the new disclosable set.
type museLabel06InFlightOutcome = "aborted" | "redacted_and_reassembled";

// Planned journey once the waiting doors exist (full-door form; every
// planned assertion is sourced in MUSE-LABEL-06.report.md):
// 1. Act. As the owner, write one positively public claim, one private
//    claim below Tier A, one private transcript turn and one claim
//    derived from that turn, each carrying a generated sentinel passed
//    to redactor.add before first use. Set guest A's clearance to admit
//    the private claim's scope; leave guest B without that clearance.
//    Report the owner and guest A present and identified.
// 2. Observe through a second door. Read a room-scoped assembly (a
//    different verb from every write above) and vault.rooms.sharing:
//    public and cleared-private records are disclosed (009). Repeat
//    with guest B also present: the private claim, the private turn
//    and its derived claim are all withheld (009, 020; disjoint or
//    missing clearance meets to public-only, never a union). Repeat
//    with an unknown party present: public only (010). Compare the
//    owner-plus-guest assembly with a guest-only assembly: the same
//    private records are withheld either way (012).
// 3. Doubt narrows at once. Report guest A's identification as
//    sub-threshold and, with no other change, read the assembly again:
//    public only (017). Report momentary silence for guest B and read
//    again: still public only (018). Only a deterministic departure
//    confirmation for guest B, with guest A identified again, may let
//    the cleared-private record return.
// 4. In flight. Start one streamed room reply held at a scripted
//    provider barrier (no sleep, no wall clock), then report a newcomer
//    present. The stream must end aborted, or its delivered output must
//    be redacted under the new scope, and the re-assembled output must
//    contain no sentinel from a record the newcomer may not see (019).
//    Read the outcome back through the stream/events door and through
//    the assembly door, not only from the acting call.
// 5. Override. Attempt the override on voice identification alone (a
//    non-owner session credential): refused, with the standard refusal
//    envelope, and the refusal receipt read back through vault.receipts
//    or vault.authority.audit. Then perform it on the owner's
//    authenticated session: exactly the named records are disclosed,
//    receipted, and read back through the assembly door (021).
// 6. Refuse the wrong actor kinds. A non-member reading the assembly, a
//    guest reporting presence or setting a clearance, an agent without
//    the presence-report grant, and that same agent after the owner
//    revokes its grant mid-flow (vault.agents.grants.revoke) are each
//    refused at next use; each refusal leaves state unchanged when read
//    back, and leaves a receipt that is read back.
// 7. Restart. await engine.restart(), then read sharing, the standing
//    clearance and the assembly again: the meet, the unknown-party
//    narrowing and every withholding above are unchanged. A presence
//    report that was only a momentary silence must not have become a
//    departure across the restart either.
// Deterministic throughout: awaitPublic repeats reads only; the one
// in-flight boundary is a ScriptedProviders barrier, never a sleep.
suite.todo(test, "MUSE-LABEL-06", "waits on typed room presence/identification reporting, local contact-clearance set/read, room-scoped disclosure assembly, roster-barrier and owner-credential disclosure override doors");
