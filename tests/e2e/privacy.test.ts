import { afterAll, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { blake3 } from "@noble/hashes/blake3";
import type { FacadeInput, FacadeResult } from "@oneiron/client";
import { EngineFixture } from "./support/engine.ts";
import { PublicHttpError } from "./support/clients.ts";
import type { PublicHttpClient } from "./support/clients.ts";
import { loadFixtures } from "./support/fixtures.ts";
import { defineFile, redactor } from "./support/run.ts";

const profile = process.env.E2E_PROFILE === "real-small-model"
  ? "real-small-model" : "deterministic";
const suite = defineFile(import.meta, { profile, slots: 1 });
afterAll(suite.flush);

// The suite-plan owns the IDs, registry rows and canon anchors. Bindings were
// read at main 5ecd5af5bea2c70e25760f0583f276790f49fba4; they are not oracles.
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
      ownerEraseState: "erased";
    };
  };
}

type DeleteReceipt = FacadeResult<"vault.records.erase_confirm">["first"];
type Artifact = FacadeResult<"vault.artifacts.put">;

interface RedactionAudit {
  request_id: string;
  scope: { entity_ids: string[]; revision_ids: string[] };
  reason: string;
  requested_at: number;
  soft_complete_at: number;
  hard_purge_complete_at: number;
  sweep_queued_at: number | null;
  sweep_complete_at: number | null;
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
    const version = await client.call("vault.artifacts.append", {
      artifact_ref: record.id_hex,
      content_base64: Buffer.from(bytes).toString("base64"),
      occurred_at,
    });
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
  expect(outcome.first_act ?? null).toBeNull(); // Personal vault: no shared-owner veto.
  expect(outcome.same_bytes).toEqual([]); // Same-bytes fan-out was not requested.
  expect(outcome.first.existed).toBe(true);
  expect(outcome.first.reason).toBe("user_hard_delete");
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
    "hard_purge_complete_at", "sweep_queued_at", "sweep_complete_at",
    "affected_revision_ids", "actor_ref", "room_ref", "room_role", "verification",
  ]);
  expect(Object.keys(body).every(key => allowed.has(key))).toBe(true);
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
    expect(["NOT_FOUND", "INVENTED_REFERENCE"]).toContain(error.error?.code);
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

// PRIVACY-01 — Archive restoration without erasure should work.
// Canon: ARCH-0038 #harderase-v1, ARCH-0053 #r4-lifecycle; OF-449/OF-045.
// Existing HTTP shapes (owner/cleanup.rs, openapi/owner_paths.rs):
//   POST /v1/owner/cleanup
//     {posture?: "propose_first" | "auto_with_digest", task_retention_days?: number}
//   GET /v1/owner/cleanup -> {posture, task_retention_days,
//     proposals: [{id, candidates: [{entity, kind}], impact}], digests,
//     archived: [{entity, kind: "record" | "completed_attempt", archived_at?}]}
//   POST /v1/owner/cleanup/accept {proposal: string} -> {proposal, archived, skipped, digest}
//   POST /v1/owner/cleanup/restore {entity: string, kind?: string} -> review
// Neither review nor maintain runs the Dreamer's archive cron. No typed run
// door exists; manual restore is not the required re-mention restoration.
// Continuation with privacy-scenarios.archive: create an old empty structure
// and a nonempty protected one through their public creation verbs, trigger
// cleanup, accept only the fixture's proposal if propose-first, and assert:
// normal view omits only the empty record; archived view retains that same
// ID/body; a public mention restores that ID, not a duplicate; protected
// records stay normal; receipts contain no delete/erase act. Do not turn
// auto on while the integrity prerequisite is open, or substitute a delete.
suite.todo(test, "PRIVACY-01",
  "waits on typed archive-cleanup run and re-mention restoration doors — Archive restoration without erasure should work");

// PRIVACY-02 — Hard erase across public reads should work.
// Canon: ARCH-0038 #harderase-v1; OF-013/OF-044/OF-283/OF-270.
// Bound request/result types already exist:
//   FacadeInput<"vault.records.erase_preview"> = {record: EntityId}
//   FacadeInput<"vault.records.erase_confirm"> =
//     {record: EntityId, preview_digest: string, also_same_bytes?: boolean}
//   FacadeResult<"vault.records.erase_confirm"> = {first, first_act?, same_bytes}
//   vault.get {entity_ref}, vault.hydrate {refs}, vault.recall
//     {query, effort: "light", limit}, vault.search.bm25 {query, limit},
//   vault.neighbors {entity_ref, opts: {limit}}, vault.refs.resolve {reference},
//   vault.export {format: "archive"}; MCP tools carry these DTOs in arguments.spec.
// The current redaction body has requested_at, hard_purge_complete_at and
// sweep_queued_at, but no deadline. Do not manufacture a deadline by adding
// 30 days to the engine's queued time. Source-linked summary creation also
// lacks a typed fixture door: structural.put is not a summary-authoring API.
// Continuation with privacy-scenarios.hardErase: use a pinned source citation,
// a dependent claim/summary, the independent vector table and phonetic probe.
// First prove each channel finds its fixture and the unrelated control.
// Confirm erase, then immediately (NO awaitReceipt/poll/sweep before reads)
// assert ID/hydrate, lexical/vector/phonetic/hybrid recall, edges, short ID,
// MCP reads and every decompressed export member reveal no source or derived
// text. The unrelated control must still work. Inspect an opaque-only audit
// and the separately queued historical sweep's explicit <=30-day deadline.
suite.todo(test, "PRIVACY-02",
  "waits on typed source-linked summary creation and historical-sweep deadline read — Hard erase across public reads should work");

// PRIVACY-03 — Erasure resists offline replay should work.
// Canon: ARCH-0038 #harderase-v1, ARCH-0023b #two-planes; OF-282/OF-143.
// Existing get/hydrate/recall/erase DTOs above are reusable. The missing
// binding is authenticated document-key/fork sync, not a fabricated facade
// verb such as sync.replay. A replay fixture must be captured from the real
// same-build wire, including valid peer grants and acknowledgments.
// Continuation with privacy-scenarios.offlineReplay: create source and every
// entity-document fork, sync A/B, capture a valid B update, disconnect B,
// erase at A, reconnect B and replay exactly that captured update. Hydrate
// and recall must remain empty for the source AND every fork on both peers.
// Observe the wire acknowledgment, restart A and repeat those public reads.
// No tombstone/LMDB/Loro editing. The pinned plan assigns this file one slot;
// EngineFixture.start({peers:1}) needs two. The coordinator must resolve that
// declaration before enabling this multi-peer flow; this writer cannot edit it.
suite.todo(test, "PRIVACY-03",
  "waits on typed entity-document/fork sync replay and a two-slot peer allocation — Erasure resists offline replay should work");

suite.test(test, "PRIVACY-04", "Shared blobs survive one record erasure should work", async () => {
  const catalog = await loadFixtures();
  const data = await catalog.readJson<PrivacyFixtures>("privacy-scenarios");
  const versions = await Promise.all(data.sharedBlobs.versions.map(id => catalog.readArchive(id)));
  for (const bytes of versions) redactor.add(new TextDecoder().decode(bytes));
  const engine = await EngineFixture.start({ id: "PRIVACY-04", profile });
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
  } finally {
    await engine.close();
  }
});

suite.test(test, "PRIVACY-05", "Legal hold narrows delete should work", async () => {
  const catalog = await loadFixtures();
  const data = await catalog.readJson<PrivacyFixtures>("privacy-scenarios");
  const spec = data.legalHold;
  const bytes = await catalog.readArchive("privacy-blob-v1");
  redactor.add(new TextDecoder().decode(bytes));
  const engine = await EngineFixture.start({ id: "PRIVACY-05", profile });
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
    const liftInput = { records: [record.id_hex] } satisfies FacadeInput<"vault.legal_holds.lift_and_erase">;
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
    expect(erased.records[0]?.status.state).toBe(spec.expected.ownerEraseState);
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
    const status = erased.records[0]!.status;
    if (status.state !== "erased") throw new Error("Owner confirm did not erase the held record");
    await readAudit(engine.client, status.receipt_ref, record.id_hex,
      [spec.name, new TextDecoder().decode(bytes)]);
  } finally {
    await engine.close();
  }
});

// PRIVACY-06 — Off-record session discard should work.
// Canon: ARCH-0052 #target, ARCH-0032 #writers, ARCH-0069 #handles; OF-326/OF-597.
// Existing owner HTTP shapes (owner/off_record.rs):
//   POST /v1/owner/off-record {session_ref, mode: "off_record", backend: "local"}
//   POST /v1/owner/off-record/witness {session_ref, turn: WitnessTurn, summary?}
//   GET /v1/owner/off-record?session_ref=... ->
//     {session_ref, mode, backend, entered_at, promoted_turns, closing}
//   POST /v1/owner/off-record/close {session_ref} ->
//     {session_ref, turns_dropped, context_receipts_dropped,
//      emit_receipts_dropped, emit_receipts_kept, promoted_turns_kept}
// x-oneiron-session already binds receipt/reference-refusal context; it is
// NOT proof that vault.recall/claims/notes or an MCP executor uses the overlay.
// No shipped typed route binds a run to the session. Do not send ordinary
// durable note/claim/tool writes with that header and call them off-record.
// Continuation with privacy-scenarios.overlay: witness durable memory first,
// enter off-record, then bind note, claim and spilling MCP tool-output writes
// to the session. Own union reads must find base AND overlay; ordinary owner
// reads must find base only. Decode a real full-vault export, backup and sync
// capture while the session is LIVE and assert no overlay/spill body bytes.
// Close without saving, restart, assert session-not-found, absent overlay
// content/receipts/spill handles, and unchanged durable memory. No floor event
// is provoked here, so there is no floor-receipt exception to those assertions.
suite.todo(test, "PRIVACY-06",
  "waits on typed session-bound note/claim/MCP executor and union-read doors — Off-record session discard should work");

// PRIVACY-07 — Off-record save from the middle should work.
// Canon: ARCH-0052 #d5-notice/#d5-save-grant, ARCH-0040 #mcp-actor-ceilings; OF-326.
// HTTP already exists in api/off_record_rooms.rs; generated FacadeInputs and
// SDKs do NOT yet name these calls. G01 forbids replacing their typed SDK
// calls with arbitrary facade names or an execute_code escape hatch.
// Current typed HTTP request/result design to carry into that projection:
//   Start = {room: EntityId, session_ref: string, backend: "local" | "remote_provider"}
//   Stretch = {room: EntityId, session_ref: string}
//   Witness = Stretch & {turn: WitnessTurn, summary?: string | null}
//   Room = {session_ref, room, started_by, mode, backend, entered_at, closing,
//     notices: [{act, by, at}], waiting_suggestions: [{by, at}]}
//   Saved = {saved: [{turn, replayed: EntityId[], short_ids: [{room, vault}]}]}
//   Export = {session_ref, room, exported_at,
//     turns: [{turn, speaker, occurred_at, saved, messages}]}
// POST /v1/core/off-record/start -> Room; /witness -> WitnessReceipt;
// /save and /confirm-save -> Saved; /save-from-here, /suggest-save and
// /decline-save -> Room; /export -> Export attachment; GET -> Room (NO talk).
// No request names a destination vault. Credentials/grants/roster are separate.
// Continuation with privacy-scenarios.room, one room and FOUR own credentials:
// 1. Person holder starts; speak only in live membership windows. A propose-only
//    agent suggests; assert zero persisted turns, and waiting_suggestions.
// 2. Decline as a holder, assert zero writes and content-free save_declined;
//    suggest again, confirm as a holder, then assert only visible full turns
//    persist. Hidden reasoning, summaries and out-of-window speech stay out.
// 3. Person holder and vault-agent holder EACH save a new whole-talk segment
//    and EACH use save-from-here; only subsequent admitted turns land in base.
//    Saving authority is the LIVE vault write grant, never human versus agent.
// 4. Human guest exports only their visible talk as an attachment, writes no
//    vault and gets 403 attempting save. Propose-only agent's save gets 403.
// 5. Revoke saver write grant OR leave, then witness. The lapse refuses that
//    landing, later speech stays off-record and saving_stopped names the act.
//    Rejoin/regrant without a new save-from-here MUST NOT resume persistence.
//    Read public base data after every boundary, not just save responses.
// 6. Notices name actor+act+time only, never quote content; close removes the
//    notices. This multi-person room is NOT the quiet companion 1:1 exception.
suite.todo(test, "PRIVACY-07",
  "waits on generated typed off-record room save/suggest/export SDK calls — Off-record save from the middle should work");

// PRIVACY-08 — Anonymous chat has no memory should work.
// Canon: OF-500, ARCH-0040 #mcp-actor-ceilings; G10 is RULED B, not unresolved.
// api/anonymous_chat.rs already serves POST /v1/ai/anonymous-chat outside
// idempotency/wire receipts. It has no generated typed SDK call or OpenAPI
// operation yet. Preserve its real DTO, not an invented anonymous facade:
//   Request = {text: string, target?: "house_mind" | "plain_model", model?: ModelId}
//   Reply = {type: "reply", content, notices, skipped_checks, model_notices}
//   Block = {type: "blocked", input: boolean, notice, preceding_notices,
//     reason: "policy" | "human_review_unavailable", model_notices}
// Each notice has audience=user_and_model and an explained policy row. This
// response explanation is ephemeral: it does NOT justify any durable receipt.
// Continuation with privacy-scenarios.anonymous: author a deterministic owner
// policy via vault.shape.plan/apply and public manifest data, route the real
// model wire to ScriptedProviders (two independent single-turn responses),
// retain separate normal memory, send the unique anonymous input, and make a
// NEW request with followUp. Inspect provider inputs: no previous anonymous
// text and no durable memory may enter that new request. Do not treat the
// fake model's answer as proof of forgetting. Search memory/receipt surfaces
// and decoded export content for input/output sentinels; assert NONE, then
// provoke the fixture policy block and inspect both user/model notice channels.
// No input reaches the responder on an input block. Search/export again after
// block and restart. Normal session memory stays retrievable throughout.
// G10: ZERO anonymous transcript, memory, telemetry or receipts, including
// hash-only safety receipts. No owner-question TODO and no promotion/flip.
suite.todo(test, "PRIVACY-08",
  "waits on typed anonymous-chat OpenAPI and SDK call — Anonymous chat has no memory should work");
