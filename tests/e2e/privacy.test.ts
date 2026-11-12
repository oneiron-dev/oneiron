import { afterAll, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { resolve } from "node:path";
import { inflateRawSync } from "node:zlib";
import { decode } from "@msgpack/msgpack";
import { blake3 } from "@noble/hashes/blake3";
import type { FacadeInput, FacadeResult } from "@oneiron/client";
import { EngineFixture, awaitPublic } from "./support/engine.ts";
import type { PairedActor } from "./support/engine.ts";
import { PublicHttpError } from "./support/clients.ts";
import type { PublicHttpClient } from "./support/clients.ts";
import type { McpClient } from "./support/clients.ts";
import { loadFixtures, ownerBaseClaimScope } from "./support/fixtures.ts";
import { ScriptedProviders, openaiText } from "./support/providers.ts";
import type { ProviderStep } from "./support/providers.ts";
import { Artifacts, defineFile, redactor } from "./support/run.ts";

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
  "reference_refusal", "task_lifecycle", "run_hold_override", "check_in", "inquiry",
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
  // The redacted provider transcript, request bodies included, goes to PRIVACY-01-providers/provider-privacy-archive.json:
  // a background request rejected at cleanup then shows its prompt and response_format, not only its origin.
  const providers = await ScriptedProviders.start({ id: "privacy-archive",
    ...(process.env.E2E_ARTIFACTS_DIR ? { artifacts: new Artifacts(resolve(process.env.E2E_ARTIFACTS_DIR, "PRIVACY-01-providers")) } : {}),
    steps: [{
    id: "eligible-people", origin: "extraction", role: "extraction_teacher", purpose: "extract witnessed people",
    request: { method: "POST", path: "/v1/chat/completions", model: "privacy-extract", system: extractionPrompt.system }, barrier: "extract",
    response: openaiText("eligible-people", "privacy-extract", JSON.stringify({ candidates: [],
      persons: names.map((name, index) => ({ id: `new:P${index + 1}`, name, evidence_turn_refs: ["T1"] })) }),
      { inputTokens: 128, outputTokens: 64 }),
  }, {
    id: "archive-summary", origin: "summary", role: "dreamer_current", purpose: "background scope summary",
    standing: true,
    request: { method: "POST", path: "/v1/chat/completions", model: "privacy-summary", system: SUMMARY_PROMPT, fields: { response_format: { type: "json_schema" } } },
    response: openaiText("archive-summary", "privacy-summary", JSON.stringify({ text: "A short note was recorded.", keep: "" }),
      { inputTokens: 128, outputTokens: 16 }),
  }, {
    // A later wake sees the protection/enrichment facts added below. This is
    // the roster About producer, not another conversation-summary response.
    id: "archive-person-about", origin: "summary", role: "dreamer_current",
    purpose: "roster About refresh after the archive case adds person facts", standing: true,
    request: { method: "POST", path: "/v1/chat/completions", model: "privacy-summary", system: PERSON_ABOUT_PROMPT },
    response: openaiText("archive-person-about", "privacy-summary", "A person has a recorded profile fact.",
      { inputTokens: 128, outputTokens: 16 }),
  }, ...backgroundExtraction("privacy-extract")] });
  let engine: EngineFixture | undefined;
  let primaryFailed: boolean = false;
  let primary: unknown;
  let stage = "archive engine setup";
  try {
    engine = await EngineFixture.start({ id: "PRIVACY-01", profile, serverConfig: dreamerConfig(providers, true) });
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
    try {
      for (const call of providers.seenFixtureCalls.filter(call => call.fixtureId === "archive-person-about")) {
        const body = call.body as { response_format?: unknown; messages?: { content: string }[] };
        expect(body.response_format).toBeUndefined();
        const facts = body.messages?.[1]?.content.split("\n") ?? [];
        expect(facts.length).toBeGreaterThan(0);
        expect(facts.every(line => line.startsWith("privacy.archive_protection: ")
          || line.startsWith("provider.enrichment: "))).toBe(true);
      }
    } catch (error) { cleanups.push(`PRIVACY-01 roster About request contract: ${errorText(error)}`); }
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
  }, {
    // The uncertain follower reading above owes Typing on GenerativeReasoner,
    // which this host leaves on its narrative backend. This is not a summary.
    id: "source-span-typing", origin: "summary", role: "generative_reasoner",
    purpose: "type the one uncertain Mira span from the witnessed source", standing: true,
    request: { method: "POST", path: "/v1/chat/completions", model: "privacy-summary",
      system: recipeDefaults.typing_instruction,
      fields: { response_format: { type: "json_schema", json_schema: { schema: {
        properties: { Q4: { required: ["none", "P1"] } }, additionalProperties: false,
      } } } } },
    response: openaiText("source-span-typing", "privacy-summary", JSON.stringify({
      Q1: { yes: 1, no: 0 }, Q2: { date: 0, name: 1 },
      Q3: { score: 50, probability: 1 }, Q4: { none: 1, P1: 0 },
    }), { inputTokens: 128, outputTokens: 64 }),
  }, {
    // Keep automatic embedding unadmitted: this journey supplies its own
    // vectors and tests their erasure, not encoder availability. The public
    // endpoint configuration still pins the space. A POST is NOT scripted;
    // any attempt to embed a document or query remains a loud fixture error.
    id: "erase-vector-model-unavailable", origin: "embedding", role: "embedder",
    purpose: "declared unavailable encoder for client-supplied vectors", standing: true,
    request: { method: "GET", path: "/v1/models" },
    response: { kind: "json", status: 503, body: {
      error: { type: "fixture_encoder_unavailable", message: "This journey supplies vectors through vault.vectors.put." },
    } },
  }, ...backgroundExtraction("privacy-extract", ["follower_instruction"])] });
  let engine: EngineFixture | undefined;
  let primaryFailed: boolean = false;
  let primary: unknown;
  let stage = "setup";
  try {
    const embeddingEndpoint = `${providers.urls.embedding!}/v1`;
    const embeddingModelId = "e2e/privacy-erase@v1";
    engine = await EngineFixture.start({ id: "PRIVACY-02", profile,
      // EngineFixture supplies remote egress flags, so declare an owner-server
      // rung and the same-space loopback fallback, as retrieval.test.ts does.
      initArgs: ["--embedder-locality", "owner-server", "--embedder-fallback-endpoint", embeddingEndpoint],
      embedder: { endpoint: embeddingEndpoint, modelKey: "privacy-vectors", modelId: embeddingModelId,
        dimensions: spec.vectorTable.dimensions, egress: { allowAll: true } },
      serverConfig: dreamerConfig(providers, true) });
    await grantExtraction(engine);
    stage = "configured and persisted vector-space readback";
    const modelStatus = await engine.client.request<{ embedder: {
      configured: { model_id: string; dimensions: number } | null;
      persisted: { model_id: string | null; dimensions: number | null } | null;
    } }>("GET", "/v1/owner/status");
    expect(modelStatus.body.embedder.configured?.model_id).toBe(embeddingModelId);
    expect(modelStatus.body.embedder.persisted?.model_id).toBe(embeddingModelId);
    expect(modelStatus.body.embedder.configured?.dimensions).toBe(spec.vectorTable.dimensions);
    stage = "source conversation, witness and extraction";
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
    stage = "source-linked SUMMARY create and completion";
    const queued = await engine.client.call("vault.summaries.create", {
      scope: { conversation_ref: source.id, path: "canonical" },
    });
    const completed = await awaitPublic(
      () => engine!.client.call("vault.summaries.status", { attempt: queued.attempt }),
      value => value.state === "completed", { label: "PRIVACY-02 source-linked SUMMARY completion" },
    );
    if (!completed.result) throw new Error("Completed summary has no result");
    const summaryId = completed.result.summary;
    const summary = await engine.client.call("vault.summaries.read", { summary_ref: summaryId });
    expect(summary.value?.text).toBe(spec.summaryText);
    expect(summary.value?.covers).toContain(sourceTurn);
    expect(summary.value?.metadata.derivation.sources.some(pin => pin.id === sourceTurn)).toBe(true);
    stage = "unrelated control write";
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
    for (const [target, entity_ref, vector] of [
      ["source", source.id, spec.vectorTable.source], ["claim", claim.claim.claim_ref, spec.vectorTable.claim],
      ["summary", summaryId, spec.vectorTable.summary], ["control", controlId, spec.vectorTable.unrelated],
    ] as const) {
      stage = `vault.vectors.put ${target}`;
      const put = await engine.client.call("vault.vectors.put", { entity_ref, vector: [...vector] });
      expect(put.entity_ref).toBe(entity_ref);
      expect(put.dimensions).toBe(spec.vectorTable.dimensions);
    }
    stage = "erase and public reads";
    const sourceRow = (await engine.client.call("vault.get", { entity_ref: source.id })).value;
    const claimRow = (await engine.client.call("vault.get", { entity_ref: claim.claim.claim_ref })).value;
    const summaryRow = (await engine.client.call("vault.get", { entity_ref: summaryId })).value;
    if (!sourceRow?.short_ref || !claimRow?.short_ref || !summaryRow?.short_ref) {
      throw new Error("Created erase targets have no public short refs");
    }
    const hydratedBefore = await engine.client.call("vault.hydrate", { refs: [...targets, controlId] });
    for (const id of [...targets, controlId]) expect(hydratedBefore.value.map(row => row.id_hex)).toContain(id);
    // Each erase target must resolve through the public ref door before the erase, by the very
    // short_ref vault.get issued for it (ARCH-0019 short_ids rows 03-04: the forward key is
    // (short_id, content_hash)). Triage 19 (job 19, set bd95597c8af): the CONVERSATION and the
    // CLAIM resolve; the SUMMARY answers 404 NOT_FOUND. vault.get issues the NAME from
    // short_ids_reverse plus the hash of the row it just read (memory/read_lane.rs:746-753), and
    // vault.refs.resolve looks (name, hash) up in the forward index (ports/lmdb_index.rs:298-310).
    // A scope SUMMARY is minted with its full body (scope_summary/request.rs:543, index hashed
    // there), then rewritten to a document pointer (request.rs:587 -> entity_doc/summary.rs:154 ->
    // ports/lmdb_operational_entities.rs:75-103, a raw entities.put) and no short-id row is
    // refreshed, so the issued hash is the pointer row's and the index still holds the old one.
    // The assertion stays; only the failure text names the defect.
    for (const [target, row] of [
      ["source", sourceRow], ["claim", claimRow], ["summary", summaryRow],
    ] as const) {
      const reference = row.short_ref!;
      stage = `pre-erase vault.refs.resolve ${target} ${row.kind} record=${row.id_hex} reference=${reference}`;
      try {
        expect((await engine.client.call("vault.refs.resolve", { reference })).value.record.id)
          .toBe(row.id_hex);
      } catch (error) {
        if (target === "summary" && error instanceof PublicHttpError
          && error.reply.status === 404 && error.error?.code === "NOT_FOUND") {
          stage = `ENGINE DEFECT 2026-11-12: [SUMMARY-SHORT-REF-INDEX] the short ref vault.get issued for this SUMMARY carries the content hash of its document-pointer row, while the short-id index still holds the hash of the body it was minted with, so the issued ref does not resolve (FIX 23470); ${stage}`;
        }
        throw error;
      }
    }
    stage = "BM25 readback before erase";
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
    stage = "client-supplied vector readback before erase";
    const vectorBefore = await awaitPublic(
      () => engine!.client.call("vault.search.vector", { query: spec.vectorTable.query, limit: 100 }),
      value => targets.every(id => value.value.hits.some(hit => hit.entity_ref === id)),
      { label: "PRIVACY-02 source, claim and summary vectors searchable before erase" },
    );
    for (const id of targets) expect(vectorBefore.value.hits.map(hit => hit.entity_ref)).toContain(id);
    stage = "phonetic, vector, hybrid and recall readbacks before erase";
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
    stage = "MCP, export and unrelated control readbacks before erase";
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
    stage = "owner erase and immediate active-store readbacks";
    const receipt = await eraseRecord(engine.client, source.id);
    expect(receipt.state).toBe("applied");
    // No poll, receipt read or sweep may precede any of these active-store reads.
    const allIds = [...targets, sourceTurn, ...(witnessed.messages ?? []).map(row => row.id)];
    for (const entity_ref of allIds) {
      const read = await engine.client.call("vault.get", { entity_ref });
      try { expect(read.value).toBeNull(); }
      catch (error) {
        if (entity_ref === source.id) throw error;
        // The engine's CONVERSATION erase takes the room's side rows, not its TURN/MESSAGE
        // (workspace_roster/rooms/history.rs:205-232, CONVERSATION arm :215), and the room rail refuses
        // OwnerErase for a TURN/MESSAGE (conversation/deletion/record.rs:221-226), so the CLAIM and SUMMARY that
        // cite the TURN stay. A second public read says whether that TURN stayed too.
        const turnAfter = (await engine.client.call("vault.get", { entity_ref: sourceTurn })).value;
        throw new Error(`PRIVACY-02 MISSING DOOR 2026-11-12: vault.records.erase_confirm erased the CONVERSATION; ${read.value?.kind ?? "record"} ${entity_ref} survives and the source TURN ${sourceTurn} ${turnAfter ? "survives" : "is gone"}. FIX 23156: room-aware OwnerErase preview/confirm for TURN/MESSAGE is absent; source and dependent erasure remain unproved. ${errorText(error)}`, { cause: error });
      }
    }
    stage = "hydrate, BM25, vector, hybrid, recall and neighbor reads after erase";
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
    for (const [target, row] of [
      ["source", sourceRow], ["claim", claimRow], ["summary", summaryRow],
    ] as const) {
      stage = `post-erase vault.refs.resolve ${target} ${row.kind} record=${row.id_hex} reference=${row.short_ref!}`;
      await expectReferenceGone(engine.client, row.short_ref!, forbidden);
    }
    stage = "MCP reads and unrelated controls after erase";
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
    stage = "content-free audit and historical sweep deadline readback";
    await readAudit(engine.client, receipt.receipt_ref, source.id, forbidden);
    if (!receipt.receipt_ref) throw new Error("Erase has no redaction receipt");
    const sweep = await engine.client.call("vault.records.erase_sweep", { receipt_ref: receipt.receipt_ref });
    if (!sweep || sweep.deadline_at == null || sweep.sweep_queued_at == null) {
      throw new Error("Erase has no recorded historical-sweep deadline and queue time");
    }
    expect(sweep.deadline_at).toBeGreaterThanOrEqual(sweep.requested_at);
    expect(sweep.deadline_at - sweep.requested_at).toBeLessThanOrEqual(spec.expected.historicalSweepMaxSeconds);
    stage = "owner-forced historical sweep";
    await finishHistoricalSweep(engine);
    expect(providers.seenFixtureCalls.filter(call => call.fixtureId === "source-claim")).toHaveLength(1);
    expect(providers.seenFixtureCalls.filter(call => call.fixtureId === "source-person-about").length).toBeGreaterThanOrEqual(1);
    expect(providers.seenFixtureCalls.filter(call => call.fixtureId === "source-summary").length).toBeGreaterThanOrEqual(1);
    expect(providers.seenFixtureCalls.filter(call => call.fixtureId === "source-summary").every(call => (call.body as any)?.response_format?.json_schema?.schema?.required?.join(",") === "text,keep")).toBe(true);
  } catch (error) {
    primaryFailed = true;
    // A refused public call keeps its wire code and message; a bare "HTTP 400" names neither step nor cause.
    primary = error instanceof PublicHttpError
      ? new Error(`PRIVACY-02 ${stage}: status=${error.reply.status} code=${error.error?.code ?? "<none>"} message=${error.error?.message ?? "<none>"} suggestion=${error.error?.suggestions?.[0] ?? "<none>"}`, { cause: error })
      : new Error(`PRIVACY-02 ${stage}: ${errorText(error)}`, { cause: error });
  } finally {
    const cleanups: string[] = [];
    // Capture the real summary wire body before provider cleanup. The standing
    // matcher stays strict; this artifact makes any mismatching field visible.
    try { await engine?.artifacts.json("diagnostic-privacy-02-provider-calls.json", { seen: providers.seenFixtureCalls }); }
    catch (error) { cleanups.push(errorText(error)); }
    try { await engine?.close(); } catch (error) { cleanups.push(errorText(error)); }
    // Check after shutdown too: a final wake can reach the provider during close.
    try {
      const embeddingCalls = providers.seenFixtureCalls.filter(call => call.origin === "embedding");
      expect(embeddingCalls.length).toBeGreaterThan(0);
      expect(embeddingCalls.every(call => call.fixtureId === "erase-vector-model-unavailable"
        && call.method === "GET" && call.path === "/v1/models")).toBe(true);
      for (const call of providers.seenFixtureCalls.filter(call => call.fixtureId === "source-span-typing")) {
        const body = call.body as { response_format?: { json_schema?: { schema?: { properties?: object } } };
          messages?: { content: string }[] };
        expect(Object.keys(body.response_format?.json_schema?.schema?.properties ?? {}).sort())
          .toEqual(["Q1", "Q2", "Q3", "Q4"]);
        const request = JSON.parse(body.messages?.[1]?.content ?? "{}");
        expect(request.state?.spans).toHaveLength(1);
        expect(request.state.spans[0].span.text).toBe("Mira");
        expect(request.state.contexts.map((row: { text: string }) => row.text)).toEqual([spec.sourceText]);
      }
    } catch (error) { cleanups.push(`PRIVACY-02 embedding/typing request contract: ${errorText(error)}`); }
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
// One personal-vault room with four real credentials on the initial roster: the owner (a person
// holder), a full-access vault agent (an agent holder: #6925 binds a token agent's principal as one of
// the vault's own agents), a propose-only agent and a human guest with no save grant. A suggestion or
// a decline saves nothing; the guest and the proposer are refused both save forms; the person holder
// saves whole visible turns, the agent holder saves a later turn, and the person holder saves from
// here; hidden reasoning, the temporary summary and out-of-window speech never reach the vault. The
// owner then leaves the room live (vault.rooms.leave): the next landing stays off record and
// saving_stopped names the act; rejoining alone does not resume saving, and only a new save from here
// starts a new saving period. The base is read after each boundary through the full-vault export, the
// guest's own export carries what it sat through, and the notices are content-free {act,by,at}.
// Closing the stretch drops its overlay and its notices. The export door is probed (#6923 publishes it).
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
suite.test(test, "PRIVACY-07", "Off-record save from the middle: only a person or agent holder saves, leaving stops saving and rejoining does not resume it", async () => {
  const room = (await (await loadFixtures()).readJson<{ room: PrivacyRoom }>("privacy-scenarios")).room;
  const engine = await EngineFixture.start({ id: "PRIVACY-07", profile,
    serverConfig: "[models.dreamer]\nenabled = false\n[models.workflows]\nenabled = false\n" });
  await engine.requireHttpDoor("/v1/owner/off-record/close", "POST");
  await engine.requireHttpDoor("/v1/core/off-record/export", "POST");
  const owner = engine.pairedActor;
  // The propose-only agent and the full-access agent are minted on the stopped vault before the stretch exists.
  await engine.client.call("vault.receipts", { limit: 1 });
  await engine.kill();
  const minted = await engine.cli.run(["token", "agent", "--name", "privacy-suggesting-agent", "--tier", "propose-only",
    "--config", resolve(engine.root, "oneiron.toml"), "--out", resolve(engine.root, "privacy-suggesting-agent.credential")],
    undefined, undefined, true);
  expect(minted.exitCode).toBe(0);
  const mintedHolder = await engine.cli.run(["token", "agent", "--name", "privacy-holder-agent", "--tier", "full-access",
    "--config", resolve(engine.root, "oneiron.toml"), "--out", resolve(engine.root, "privacy-holder-agent.credential")],
    undefined, undefined, true);
  expect(mintedHolder.exitCode).toBe(0);
  await engine.restart();
  const proposer = await engine.pairActor({ principalRef: (JSON.parse(minted.stdout) as { principal_ref: string }).principal_ref,
    actorClass: "agent", scope: ["core:read", "core:propose"] });
  const holderAgent = await engine.pairActor({ principalRef: (JSON.parse(mintedHolder.stdout) as { principal_ref: string }).principal_ref,
    actorClass: "agent", scope: ["core:read", "core:write"] });
  const setup = await ownerRoom(engine, "Privacy guest evidence");
  const evidence = await engine.client.call("vault.witness", turn(setup.id, "This distinct person is Privacy Human Guest."));
  const person = await engine.client.call("vault.people.create", {
    identity: { name: "Privacy Human Guest" }, identity_evidence_refs: [evidence.turn_id], occurred_at: Math.floor(Date.now() / 1000),
  });
  const guest = await engine.pairActor({ principalRef: person.person.id_hex, actorClass: "human", scope: ["core:read", "core:write"] });
  const members = [owner.principalRef, holderAgent.principalRef, proposer.principalRef, guest.principalRef];
  expect(new Set(members).size).toBe(4);
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
  // The person holder saves the whole visible talk it could see; the agent holder, as itself, saves the guest's later turn.
  const ownerSave = await owner.client.call("vault.off_record.rooms.save", q);
  expect(ownerSave.saved).toHaveLength(1);
  await base(room.visibleTexts, talk.slice(2));
  await said(guest, room.guestText);
  const guestTurnSave = await holderAgent.client.call("vault.off_record.rooms.save", q);
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
  expect(left.member_ids).toEqual(expect.arrayContaining([holderAgent.principalRef, proposer.principalRef, guest.principalRef]));
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
  expect(final.notices.filter(row => row.act === "saved_talk").map(row => row.by))
    .toEqual([owner.principalRef, holderAgent.principalRef]);
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
