import { afterAll, expect, test } from "bun:test";
import type { Facade, FacadeInput, FacadeResult } from "@oneiron/client";
import { EngineFixture, awaitPublic } from "./support/engine.ts";
import type { McpClient } from "./support/clients.ts";
import { loadFixtures } from "./support/fixtures.ts";
import type { FixtureCatalog } from "./support/fixtures.ts";
import { defineFile, redactor } from "./support/run.ts";

const profile = process.env.E2E_PROFILE === "real-small-model"
  ? "real-small-model" : "deterministic";
const suite = defineFile(import.meta, { profile, slots: 1 });
afterAll(suite.flush);

/*
 * ARCH-0080 #crash-safety/#replay/#verb-outcomes/#host-verbs, OF-579/580/581.
 * Binding read at main 65529b62e07209d8faeb0c0fcde7812e3df9cc46:
 * scripts/sdk/agent-verbs.json, both generated SDKs, the server's OpenAPI
 * registration/owner paths, facade host doors, MCP argument/result DTOs and CLI.
 * EngineFixture captures runtime OpenAPI as a binding diagnostic, not an oracle.
 * hooks-scenarios pins canon and independent fixture facts for all seven IDs.
 *
 * The public pack format carries HOOK.md, intent.md and body.js. Those bodies
 * run in serve's checked-in quickjs-hook.wasm, not a JS host or alternate engine.
 * The plan's pack-carried Wasm fixture has no public input; it is on FIX-LIST.
 * No build, server, interpreter CLI, typecheck or test runs in this Mac lane.
 * G01 TODOs below are mandatory BLOCKED rows, never partial passing coverage.
 */

interface Corpus {
  pageBound: number;
  replay: {
    checkpointId: string; anchorId: string; originalId: string; correctionId: string;
    triggerPredicate: string; anchorPredicate: string; outputPredicate: string;
    hookName: string; hookVersion: string; marker: string; anchor: string;
    originalRevision: string; laterRevision: string; packFiles: Record<string, string>;
  };
  redaction: {
    claimId: string; predicate: string; value: { public: string; private: string };
    annotation: string; packFiles: Record<string, string>;
  };
}
async function packInput(catalog: FixtureCatalog, entries: Record<string, string>): Promise<Facade.PackPutRequest> {
  return { files: await Promise.all(Object.entries(entries).map(async ([path, id]) => ({
    path, text: new TextDecoder().decode(await catalog.readArchive(id)),
  }))) };
}

// The shared MCP client intentionally returns protocol bodies. This local
// typed envelope reader supplies no authority, retries, paging or verb fallback.
type HookMcpVerb = "vault.packs.put" | "vault.claims.upsert" | "vault.claims.list"
  | "vault.receipts" | "vault.hooks.replay";
interface ToolCatalog {
  tools: { name: string; inputSchema: { properties: { schema_version: { const: string } } } }[];
}
interface ToolReply<T> {
  isError: boolean;
  structuredContent: { output: T; meta: { end: string } };
}
async function mcpCall<V extends HookMcpVerb>(
  client: McpClient, tools: ToolCatalog, verb: V, input: FacadeInput<V>,
): Promise<FacadeResult<V>> {
  const tool = tools.tools.find(item => item.name === verb);
  if (!tool) throw new Error(`Required typed MCP tool is absent: ${verb}`);
  const reply = await client.callTool(verb, {
    schema_version: tool.inputSchema.properties.schema_version.const,
    consent: { policy_ref: "policy:hooks-e2e", purpose: "runtime hook public journey" },
    arguments: { spec: input },
  }) as ToolReply<FacadeResult<V>>;
  expect(reply.isError).toBe(false);
  expect(reply.structuredContent).toBeDefined();
  // Never claim a truncated before/after snapshot as a complete vault read.
  expect(reply.structuredContent.meta.end).toBe("Complete");
  return reply.structuredContent.output;
}
function receiptField(receipt: Facade.MemoryReceipt, name: string): string {
  const value = receipt.fields?.[name];
  if (value === undefined) throw new Error(`Hook receipt lacks ${name}`);
  return value;
}
function byClaimId(rows: Facade.ClaimView[]): Facade.ClaimView[] {
  return [...rows].sort((a, b) => a.claim_ref.localeCompare(b.claim_ref));
}
function byReceiptId(rows: Facade.MemoryReceipt[]): Facade.MemoryReceipt[] {
  return [...rows].sort((a, b) => a.receipt_ref.localeCompare(b.receipt_ref));
}

/* HOOKS-01 — Fact hook commit and restart catchup should work. OF-579.
 * Canon: ARCH-0080 #fact-inputs/#fact-sources/#crash-safety/#hook-grant.
 * Install: vault.packs.put({files:[{path,text}]}) -> PackPutReceipt.
 * Canonical grant, not an invented callable verb:
 *   HookGrant { reader: EntityRef, reader_class: Human|Agent|System,
 *               predicates: PredicateGlob[], worlds: WorldRef[] }
 * The owner assigns it to a binding; a fact hook has no writer session.
 * Current owner hooks GET returns {id,binding}[], not the effective grant;
 * set_hook_grant exists only in the library, not HTTP/MCP/generated SDK/CLI.
 *
 * Once typed grant assignment/read exist, install the claim.landed fixture
 * with a narrow author grant. Commit two matching writes in known order,
 * interleaved with wrong predicate/world/class writes. Observe each public
 * write receipt before SIGKILL, restart the same EngineFixture, then await
 * Hook receipts and exactly one landed effect per envelope. Check per-source
 * commit order, author and Generated provenance, then restart again and require
 * unchanged effect ids/counts. A restart may deliver again, never land twice.
 * Do not fake a queue drain, grant record, cursor reset or crash transaction.
 * G09: use claim.landed only; no requirement for later source families is made.
 */
suite.todo(test, "HOOKS-01", "waits on typed hook grant assignment and effective-grant read — Fact hook commit and restart catchup should work");

suite.test(test, "HOOKS-02", "Hook replay lands nothing should work", async () => {
  const catalog = await loadFixtures();
  const data = await catalog.readJson<Corpus>("hooks-scenarios");
  const spec = data.replay;
  const engine = await EngineFixture.start({ id: "HOOKS-02", profile });
  await engine.mcp.initialize();
  const tools = await engine.mcp.listTools() as ToolCatalog;
  const call = <V extends HookMcpVerb>(verb: V, input: FacadeInput<V>) =>
    mcpCall(engine.mcp, tools, verb, input);
  const subject = engine.pairedActor.principalRef;
  const upsert = (id: string, predicate: string, value: unknown) => call("vault.claims.upsert", {
    id, subject_ref: subject, predicate, value, confidence: 1, source: "user_stated",
  });
  const readClaims = async () => {
    const reply = await call("vault.claims.list", { subject_ref: subject, limit: data.pageBound });
    expect(reply.value.length).toBeLessThan(data.pageBound);
    return byClaimId(reply.value);
  };
  const hookReceipts = async () => {
    const rows = await call("vault.receipts", { kinds: ["hook"], limit: data.pageBound });
    expect(rows.length).toBeLessThan(data.pageBound);
    return rows.filter(row => row.fields?.hook === `local/${spec.hookName}`);
  };

  await upsert(spec.anchorId, spec.anchorPredicate, spec.anchor);
  const installed = await call("vault.packs.put", await packInput(catalog, spec.packFiles));
  expect(installed.outcome).toBe("installed");
  expect(installed.receipt?.pack_name).toBe("local");
  expect(installed.receipt?.status).toBe("active");
  // Canon lists hooks as subscription claims on CODE, not a private-store read.
  const subscriptions = await call("vault.claims.list", {
    predicate: "agent.connector_subscription", lifecycle: "active", limit: data.pageBound,
  });
  expect(subscriptions.value.length).toBeLessThan(data.pageBound);
  const bindings = subscriptions.value.filter(row => {
    if (typeof row.value !== "string") return false;
    const binding = JSON.parse(row.value) as { pack?: string; hook?: string };
    return binding.pack === "local" && binding.hook === spec.hookName;
  });
  expect(bindings).toHaveLength(1);
  const binding = bindings[0]!.claim_ref;

  // Obtain a real predecessor cursor; never fabricate a zero cursor or use time.
  await upsert(spec.checkpointId, spec.triggerPredicate, { revision: "checkpoint" });
  const checkpointRows = await awaitPublic(hookReceipts,
    rows => rows.some(row => row.fields?.trigger_ref === spec.checkpointId),
    { label: "HOOKS-02 checkpoint Hook receipt" });
  const checkpoint = checkpointRows.find(row => row.fields?.trigger_ref === spec.checkpointId)!;
  expect(checkpoint.outcome).toBe("nothing");
  expect(receiptField(checkpoint, "source")).toBe("claim_changelog");
  const since = `${receiptField(checkpoint, "source")}:${receiptField(checkpoint, "position")}`;

  const beforeDispatch = Date.now();
  await upsert(spec.originalId, spec.triggerPredicate, {
    revision: spec.originalRevision, anchor: spec.anchorId,
  });
  const recordedRows = await awaitPublic(hookReceipts,
    rows => rows.some(row => row.fields?.trigger_ref === spec.originalId),
    { label: "HOOKS-02 original Hook receipt" });
  const afterDispatch = Date.now();
  const recorded = recordedRows.find(row => row.fields?.trigger_ref === spec.originalId)!;
  expect(recorded.outcome).toBe("propose");
  expect(receiptField(recorded, "hook_version")).toBe(spec.hookVersion);
  expect(Number(receiptField(recorded, "rows_read"))).toBeGreaterThan(0);
  const pinnedNow = Number(receiptField(recorded, "now"));
  expect(Number.isSafeInteger(pinnedNow)).toBe(true);
  expect(pinnedNow).toBeGreaterThanOrEqual(Math.floor(beforeDispatch / 1_000) * 1_000);
  expect(pinnedNow).toBeLessThanOrEqual(afterDispatch);
  const expectedValue = {
    marker: spec.marker, revision: spec.originalRevision, anchor: spec.anchor,
    hook_version: spec.hookVersion, now: pinnedNow, clock: pinnedNow,
  };
  const landed = await awaitPublic(readClaims,
    rows => rows.some(row => row.predicate === spec.outputPredicate),
    { label: "HOOKS-02 original proposed effect" });
  const observations = landed.filter(row => row.predicate === spec.outputPredicate);
  expect(observations).toHaveLength(1);
  expect(observations[0]!.value).toEqual(expectedValue);
  expect(observations[0]!.source).toBe("generated");
  expect(observations[0]!.approval).toBe("proposed");

  // Superseding the triggering source changes its stored lifecycle and value
  // history. The separately read anchor stays intact, so history is retained.
  await upsert(spec.correctionId, spec.triggerPredicate, {
    revision: spec.laterRevision, anchor: spec.anchorId,
  });
  const correctedRows = await awaitPublic(hookReceipts,
    rows => rows.some(row => row.fields?.trigger_ref === spec.correctionId),
    { label: "HOOKS-02 correction Hook receipt" });
  expect(correctedRows.find(row => row.fields?.trigger_ref === spec.correctionId)!.outcome).toBe("nothing");
  const before = await readClaims();
  expect(before.find(row => row.claim_ref === spec.originalId)?.lifecycle).toBe("superseded");
  expect(before.find(row => row.claim_ref === spec.correctionId)?.value).toEqual({
    revision: spec.laterRevision, anchor: spec.anchorId,
  });
  const receiptsBefore = byReceiptId(await hookReceipts());
  expect(receiptsBefore).toHaveLength(3);

  // Repeat the actual dry run. Returned Propose is data, not permission to land.
  for (let replay = 0; replay < 2; replay += 1) {
    const rows = await call("vault.hooks.replay", { binding, since, limit: data.pageBound });
    expect(rows).toHaveLength(2);
    const original = rows.find(row => row.case.on === "fact" && row.case.entity === spec.originalId);
    expect(original).toBeDefined();
    expect(original!.case).toEqual({
      on: "fact", source: "claim_changelog", kind: "claim.landed", entity: spec.originalId,
      position: `claim_changelog:${receiptField(recorded, "position")}`,
    });
    const result = original!.result;
    if (result.status !== "ran") throw new Error("Retained hook inputs must replay, not lose history");
    expect(result.from_memo).toBe(true);
    expect(result.reads_live).toBe(false);
    expect(result.compare).toBe("same");
    expect(result.outcome).toBe("propose");
    expect(result.recorded).toBe("propose");
    const expectedOutcome = { kind: "propose", claim: {
      subject, predicate: spec.outputPredicate, confidence: 1, value: expectedValue,
    } };
    expect(JSON.parse(result.outcome_json!)).toEqual(expectedOutcome);
    expect(JSON.parse(result.recorded_outcome_json!)).toEqual(expectedOutcome);
    const correction = rows.find(row => row.case.on === "fact" && row.case.entity === spec.correctionId);
    expect(correction?.result).toEqual(expect.objectContaining({
      status: "ran", outcome: "nothing", from_memo: true, reads_live: false, compare: "same",
    }));
    expect(await readClaims()).toEqual(before);
    expect(byReceiptId(await hookReceipts())).toEqual(receiptsBefore);
    await engine.artifacts.json(`replay-${replay}.json`, rows);
  }
});

/* HOOKS-03 — Before-hook rewrite and durable ask should work. OF-580.
 * Canon: ARCH-0080 #verb-outcomes/#ask-continuation, one logical invocation.
 * Existing typed carrier input: vault.claims.upsert(ClaimInput).
 * Existing outcomes: Rewrite {kind:"rewrite",args:ClaimInput}, then
 * Ask {kind:"ask",question:string}; Pending carries invocation + ask handle.
 * Existing tasks.answer({handle:{group_ref},word:TaskAskWord}) and the SDK's
 * retry(pending, verb, originalInput) are real; they are NOT the missing doors.
 *
 * The required canonical caller/claim scope names world, facet, relationship
 * and project explicitly. ClaimInput currently exposes scope?:unknown and
 * optional world_ref/relationship_ref, not that typed contract. A core:write
 * token is not proof of a bounded session's four-axis row authority.
 * Once available, pair the same scoped actor for HTTP and MCP, install ordered
 * Rewrite then Ask, and invoke the same verb on each carrier. Count one pre
 * run per invocation, check rewritten values and validation refusal, then
 * attempt a world/facet/project escape and require current-gate refusal with
 * no landed row. Keep each typed Pending, restart, answer its actual ask once,
 * retry under its saved invocation and observe one resumption/effect. A repeat
 * must return the same ask/result, never a second ask or effect. Also narrow
 * authority before a saved call resumes: a task answer cannot authorize it.
 * Do not use execute_code, caller-authored grants or a raw scope map as G01
 * substitutes for the absent typed scope contract.
 */
suite.todo(test, "HOOKS-03", "waits on typed four-axis caller/session scope for Rewrite re-admission — Before-hook rewrite and durable ask should work");

suite.test(test, "HOOKS-04", "After-hook redaction is monotone should work", async () => {
  const catalog = await loadFixtures();
  const data = await catalog.readJson<Corpus>("hooks-scenarios");
  const spec = data.redaction;
  redactor.add(spec.value.private);
  const engine = await EngineFixture.start({ id: "HOOKS-04", profile });
  const subject = engine.pairedActor.principalRef;
  await engine.client.call("vault.claims.upsert", {
    id: spec.claimId, subject_ref: subject, predicate: spec.predicate,
    value: spec.value, confidence: 1, source: "user_stated",
  });
  const rawBefore = await engine.client.call("vault.claims.history", { claim_ref: spec.claimId });
  expect(rawBefore.value).toHaveLength(1);
  expect(rawBefore.value[0]!.value).toEqual(spec.value);
  const installed = await engine.client.call("vault.packs.put", await packInput(catalog, spec.packFiles));
  expect(installed.outcome).toBe("installed");
  expect(installed.receipt?.status).toBe("active");

  const caller = await engine.client.call("vault.claims.list", {
    subject_ref: subject, predicate: spec.predicate, lifecycle: "active", limit: data.pageBound,
  });
  expect(caller.value).toHaveLength(1);
  expect(caller.value[0]!.claim_ref).toBe(spec.claimId);
  expect(caller.value[0]!.value).toEqual({ public: spec.value.public });
  expect(JSON.stringify(caller)).not.toContain(spec.value.private);
  // This second named read is outside the hooked verb; it is still a real
  // authenticated, scoped public read, not a raw store or storage decoder.
  const rawAfter = await engine.client.call("vault.claims.history", { claim_ref: spec.claimId });
  expect(rawAfter.value).toEqual(rawBefore.value);
  expect(rawAfter.value[0]!.value).toEqual(spec.value);

  const rows = await engine.client.call("vault.receipts", { kinds: ["hook"], limit: data.pageBound });
  expect(rows.length).toBeLessThan(data.pageBound);
  const chain = rows.filter(row => row.fields?.verb === "vault.claims.list");
  expect(chain).toHaveLength(2);
  const redacted = chain.find(row => row.fields?.hook === "local/hide-private")!;
  const annotated = chain.find(row => row.fields?.hook === "local/try-restore")!;
  expect(redacted).toBeDefined();
  expect(annotated).toBeDefined();
  expect(redacted.outcome).toBe("redact");
  expect(annotated.outcome).toBe("annotate");
  expect(receiptField(annotated, "note")).toBe(spec.annotation);
  expect(receiptField(redacted, "invocation")).toBe(receiptField(annotated, "invocation"));
  for (const row of chain) {
    expect(row.actor_ref).toBe(subject);
    expect(receiptField(row, "phase")).toBe("post");
    expect(receiptField(row, "body_hash")).toMatch(/^[a-f0-9]{64}$/);
    expect(Number(receiptField(row, "duration_ms"))).toBeGreaterThanOrEqual(0);
  }
  await engine.artifacts.json("redaction-receipts.json", chain);
});

/* HOOKS-05 — Hook sandbox and author scope should work. OF-579.
 * Canon: ARCH-0080 #hook-world/#authority/#foreign-hooks; ARCH-0069 #handles.
 * Hook world: scoped-read + outcome return (generative facts may ai.verdict),
 * never file/network/secret/verb imports. Propose {claim:{subject,predicate,
 * value,confidence}} leaves as a typed outcome, stamped Generated by the host.
 * A secret handle is a reference, never a permission to hydrate its value.
 *
 * The owner HTTP pack install/bind/qualify routes exist. However the required
 * MCP/generated SDK catalog has no typed publisher admission, pinned hub-pack
 * installation or foreign-author Grant revoke. Local packs.put installs as
 * owner and therefore cannot prove foreign authorship. Do not substitute it.
 * Once those doors exist, install the narrow foreign publisher's pack, replay
 * to qualify, trigger separately checked file/network/secret attempts and an
 * out-of-grant Propose, and inspect typed refusals plus Hook/gate receipts.
 * Revoke the actual publisher Grant before a durable pending effect resumes;
 * restart and require refusal under current authority, no secret exposure or
 * outbound I/O, and no owner-authority laundering. Keep all attempted targets
 * local/synthetic. Neither a fake runtime nor a model provider proves sandboxing.
 */
suite.todo(test, "HOOKS-05", "waits on typed MCP/SDK publisher admission, pinned pack install and author Grant revoke — Hook sandbox and author scope should work");

/* HOOKS-06 — Host compaction wake and budget hooks should work. OF-581.
 * Canon: ARCH-0080 #host-verbs/#verb-outcomes; ARCH-0067 #what.
 * Canonical host args (design, not callable routes):
 *   host.compact(window, keep_list, token_ceiling)
 *   host.wake(wake_kind, queue_head)
 *   host.budget.hit(seat, policy)
 * Skip {kind:"skip",reason} cannot stop compact. Rewrite {kind:"rewrite",
 * args} may only ADD word-for-word keep pins, never remove an existing pin.
 * Wake Skip must retain its reason. Budget Enqueue {kind:"enqueue",task:
 * {title,body,assignee?,due_at?}} must retain the ORIGINAL accounting lineage.
 *
 * Host attach points exist in core, but none of these three has a generated
 * typed HTTP/MCP/SDK trigger/result. CLI wake reads/acks a host inbox, not
 * host.wake; generic consolidation.enqueue does not become compact or budget.
 * On activation install the three hooks, attempt compact Skip, then add the
 * fixture pin and require both old/new pins in the actual compacted result.
 * Trigger quiet-hours wake and inspect its skipped receipt/reason. Reach an
 * explicitly declared public budget cap, observe budget.hit and its enqueued
 * followup, then inspect the original seat/payer/spend/lineage and unchanged
 * cap. Never tick queues privately or lower engine defaults for this flow.
 */
suite.todo(test, "HOOKS-06", "waits on typed host.compact, host.wake and host.budget.hit trigger/results — Host compaction wake and budget hooks should work");

/* HOOKS-07 — Pinned hook update and block scope should work. OF-581/580.
 * Canon: ARCH-0080 #blocks/#updates/#regen; ARCH-0053 #r4b-hubs.
 * Existing hook outcome: AddBlock {kind:"add_block",block:{refs:EntityRef[],
 * session?,branch?,lifetime?,token_cap?}}. Stored block rows retain source hook,
 * source-row provenance/trust, recipient/branch and activation turn.
 * Default lifetime = one BOARD DELIVERY, not one read/retry/other session.
 * Render source rows in existing sections, once each, tail only; never raw
 * prompt text or a new HOOKS section. Read under current recipient scope.
 *
 * Hub pin: {hub_id,ref_string,pin:{type:commit|content_hash|semver|tag,value}}.
 * A wider capability set (reads, reach, grants, outcomes, resources) asks
 * re-consent; hub trust never authorizes it. Main's owner HTTP install/sync
 * paths are not generated typed hub-update/proposal/settlement SDK calls.
 * Hook-typed regen records exist in core but have NO public regeneration door.
 * Canon regen record: intent + hash + golden replay on pinned recent runs;
 * outcome = adopt identical fingerprint | human stamp on diff | rollback on
 * failure. Never cast a lens regen record or replace a failed body with blank.
 *
 * Once those doors exist, install a pinned publisher pack, propose a widening
 * update, verify old pin/provenance until re-consent, emit a claim-backed block,
 * narrow its recipient, render next turn and exclude revoked rows. Check one
 * delivery survives restart but cannot be spent by another session. Regenerate
 * all three cases and inspect typed records, pins and rollback body continuity.
 * Use claim.landed for this flow. Additional source families are NOT selected;
 * if a later design needs them, it separately waits on owner question G09.
 */
suite.todo(test, "HOOKS-07", "waits on typed pinned hub-hook update/re-consent and hook-typed regeneration — Pinned hook update and block scope should work");
