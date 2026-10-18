import { afterAll, expect, test } from "bun:test";
import type { Facade, FacadeInput } from "@oneiron/client";
import { EngineFixture } from "./support/engine.ts";
import { loadFixtures } from "./support/fixtures.ts";
import { defineFile } from "./support/run.ts";

const profile = process.env.E2E_PROFILE === "real-small-model"
  ? "real-small-model" : "deterministic";
const suite = defineFile(import.meta, { profile, slots: 1 });
afterAll(suite.flush);

/*
 * Operations and recovery. Binding readback: origin/main and this worktree at
 * 81565dffccd302d7e9c5a28f60a4ac07d7ff540e. Read the generated HTTP/JS SDKs,
 * OpenAPI registry and owner-path augmentation, owner handlers, and public CLI.
 * Runtime OpenAPI is captured by EngineFixture, not an expected-value oracle.
 *
 * Fixtures: operations-cases and operations-generic-pack, hash-pinned under
 * fixtures/operations/manifest.json. They carry independent synthetic inputs,
 * canon pins, planned assertions and the missing fixture/door prerequisites.
 * No live provider, customer content, private queue tick or engine import.
 *
 * G01: a complete flow without its typed HTTP AND SDK calls stays test.todo
 * (suite.todo records BLOCKED, not passing coverage). Canonical signatures
 * below are design notes, not invented routes or casts to FacadeVerb. Existing
 * partial doors are called out explicitly. Do not arm these with execute_code,
 * structural puts, opaque policy bodies, private seeds or fabricated receipts.
 */

/* OPERATIONS-01 — Typed diagnostics and scoped Coach repair should work.
 * OF-033, OF-068, OF-298, OF-418, OF-568. Canon: ARCH-0066 #grammar/#coach,
 * ARCH-0026 #run-tree, ARCH-0040 #mcp-actor-ceilings. Oracle: OPERATIONS-01.
 *
 * Canonical self.report_blocked(category, detail) is a SelfEffect. Category
 * is its closed four-value enum; detail is the escaped, UNTRUSTED leaf on the
 * blocked run receipt, never a planner instruction. A DiagnosticEvent has
 * engine-authored who/what, expected/actual/delta, evidence and replay refs;
 * expected/actual/delta contain only nil, bool, number or arrays of those.
 * Its untrusted_detail is nil under the current H4 ruling. Do not require a
 * diagnostic to repeat the hostile provider message, even in an escaped leaf.
 *
 * Configure ScriptedProviders behind the real production adapter with three
 * 503 failures carrying the fixture's malicious quoted text. Start the agent,
 * observe its actual failure receipts, call report_blocked through both typed
 * HTTP and MCP on that SAME run, and read the correlated diagnostic/run tree.
 * Assert the typed grammar and engine-resolved who/what/replay/evidence; foreign
 * text appears nowhere in authority fields or diagnostic values. If quoted on
 * the blocked receipt, it remains only its fenced detail. Neither path grants
 * authority, widens scope, self-clears or completes the failed task.
 *
 * Inspect Coach's actual ScopedRead working set: the linked diagnostic band
 * and relevant traces, never the unrelated private control. Read its skill,
 * prompt or environment repair proposal, actor/source, healed_by trace and
 * gate result. The proposal repairs the AGENT, never performs its task; its
 * own effect/criticality governs consent, not the triggering event's severity.
 * Read the OF-568 concern card and owner delivery with logged scratchpad-read
 * reason; it surfaces the agent and does not stop it. A model's draft alone
 * is not evidence that these records landed.
 *
 * Main has owner healer oversight/failure-group/drill reads and concern-card
 * calls. self.report_blocked is code-run-only, absent from the typed facade;
 * its Issues/failure-ladder bridge, typed diagnostic read and Coach working-set
 * /repair inspection do not form this complete public journey.
 */
suite.todo(test, "OPERATIONS-01",
  "waits on typed self.report_blocked HTTP/SDK/MCP, diagnostic read and scoped Coach repair inspection — Typed diagnostics and scoped Coach repair should work");

/* OPERATIONS-02 — Custom versus publisher failure routing should work.
 * OF-401, OF-381, OF-299. Canon: ARCH-0053 #r4-lifecycle,
 * ARCH-0003 #learning; publisher routing is specified by OF-401.
 *
 * Failure evidence stays in the vault. The semantic IssueSignature is closed
 * category + artifact id/version + registered model id + count + pattern
 * hashes, never text. Owner-authored -> owner triage; shipped -> its resolved
 * publisher. Publisher identity comes from admission provenance, not an error
 * message. The local review binds ended attempt, run, result and receipt refs.
 *
 * Install the authored custom agent and a pinned shipped pack through public
 * authoring/hub admission; run the SAME scripted failure for each. Inspect
 * custom-agent local grouping/drill and the publisher's loopback sink. Require
 * local owner triage for the custom artifact and no publisher upload of its
 * text; any permitted platform counts remain content-free with kind=custom.
 * Require exactly the shipped artifact's signature at its actual publisher,
 * with strict allowed fields, correct version/model/count and no private text.
 *
 * Offer fixture v2 back from that publisher. It follows the existing candidate
 * /admission/consent path, retaining v1 evidence and lineage. No automatic code
 * patch, engine rewrite, change of owner artifact, or task completion occurs.
 * A code/schema fix remains a human-ratified release, not a production repair.
 *
 * Main has report({subject_ref, category, ...}) -> ReportReceipt with
 * route=owner_inbox|publisher, owner healer failures/drill, HTTP pack import
 * /sync, and GET /v1/owner/reports/{issue}/outbound. There is no typed hub
 * registration/publisher transport and returned-update HTTP+SDK journey.
 * Reading that outbound projection or faking a configured hub id would not
 * prove delivery or admission.
 */
suite.todo(test, "OPERATIONS-02",
  "waits on typed publisher-channel delivery and hub/update admission setup — Custom versus publisher failure routing should work");

/* OPERATIONS-03 — Feedback with and without vault text should work.
 * OF-537, OF-538, OF-420, OF-380. Canon: ARCH-0044 #part-a,
 * ARCH-0069 #handles, ARCH-0066 #coach-proposals. G01 = typed call or wait.
 *
 * Existing typed input: ReportRequest {subject_ref, category, kind?, note?,
 * evidence_refs?, why?, proposal?:{problem,fix}} -> ReportReceipt
 * {issue_ref, already_submitted, status, route, disclosure, ...}.
 * Identity is (exact subject_ref, category, host-bound actor), NOT request_id
 * or note text. Lasting CallReceipt {receipt_ref, verb, actor_ref, outcome,
 * request_digest, ...} is looked up with vault.receipts.get({receipt_ref}).
 *
 * Cause a real failed call, keep its transport receipt_ref, and report it once
 * over HTTP and once over tool-first MCP (arguments.spec) as the same actor.
 * Require one issue/count, first already_submitted=false then true, same issue
 * and exact failed-call binding; read it again after restart. No provider call,
 * spend or budget debit for reporting. Distinguish the report call's own wire
 * receipt from the failed call it reports. Never invent a receipt_ref in setup.
 *
 * Send metadata-only feedback on that subject to its admitted publisher under
 * the declared text-free policy. Inspect the sink's strict content-free shape.
 * Then propose a SEPARATE disclosure of the fixture's quoted private note,
 * with subject, exact text digest, destination/publisher and scope shown before
 * approval. Do not change a duplicate report's note and assume dedup edits it.
 * No upload before approval. Approve once, send exactly the shown bytes once,
 * and verify consent/provenance receipts. An unrelated publisher or changed
 * text cannot spend this approval. Automatic telemetry remains text-free.
 *
 * report and lasting receipt reads exist. Owner /reports/{issue}/disclosure
 * accepts {choice:approve_once|stop_asking_for_publisher|deny}; its /outbound
 * read is a payload projection, not delivery. Neither has a generated SDK row.
 * feedback.send has no typed facade/SDK call. Owner feedback preview/send
 * accepts no subject_ref, refuses written notes pending in-vault redaction,
 * and is not the agent publisher-send flow. A proposal is no quoted-note bypass.
 */
suite.todo(test, "OPERATIONS-03",
  "waits on typed subject-bound feedback.send and scoped quoted-note disclosure HTTP/SDK calls — Feedback with and without vault text should work");

/* OPERATIONS-04 — Paused agent resumes from SLIM should work.
 * OF-446, OF-447, OF-467. Canon: ARCH-0019 #storage-invariants,
 * ARCH-0026 #run-tree. Oracle: OPERATIONS-04.
 *
 * Canonical host idle(next_wake) never exits. FULL -> SLIM keeps the serving
 * process, its own outbound connection and journaled resume step; rebuildable
 * structures may be shed, then lazily rebuilt. No RSS/heap-size assertion.
 *
 * Witness the authored memory and start a publicly created agent task. Hold
 * the production provider call at its external barrier. Read the declared
 * idle policy and await the PUBLIC SLIM/idle state, with the same live server
 * instance and run/session/call refs; health must still answer. A pending
 * HTTP socket alone is not proof of SLIM. Release the call, recall the original
 * memory and finish with one settled task/call outcome. Re-read saved session,
 * checkpoint and memory, then restart this vault and read them again. No lost
 * message, repeated effect or replacement session is allowed.
 *
 * Main's health response has no public SLIM/lifecycle state. No typed idle
 * policy/read or resume-state inspection door supplies this hosted scenario.
 * Waiting for an arbitrary timer, sending a private control Shed frame or
 * calling a Rust slim helper cannot substitute for observing the transition.
 */
suite.todo(test, "OPERATIONS-04",
  "waits on public SLIM idle policy/state and saved resume-step HTTP/SDK reads — Paused agent resumes from SLIM should work");

interface TurnFixture {
  conversation_ref: string;
  turn_ref: string;
  message_ref: string;
  content: string;
  query: string;
}
interface SeededCase {
  occurred_at: number;
  before: TurnFixture;
  after: TurnFixture;
  required_capabilities: string[];
  pack_name: string;
  extension: { id: string; predicate: string; value: { color: string; marker: string }; query: string };
}
interface OperationsCases { cases: { "OPERATIONS-05": SeededCase } }
interface Discovery {
  feature_flags: { capabilities: string[] };
  predicate_namespaces: string[];
}
function witnessInput(turn: TurnFixture, at: number): FacadeInput<"vault.witness"> {
  return { conversation_ref: turn.conversation_ref, turn_ref: turn.turn_ref, occurred_at: at,
    messages: [{ id: turn.message_ref, author: "user", message_type: "dialogue",
      content: turn.content, is_visible: true, order: 0 }] };
}
function assertRecalledTurn(pack: Facade.MemoryPack, turn: TurnFixture, receipt: Facade.WitnessReceipt): void {
  const recalled = pack.items.find(item => item.short_id === receipt.turn_short_id);
  expect(recalled).toBeDefined();
  expect(recalled!.value_text).toContain(turn.content);
  expect(recalled!.cited_messages).toEqual(expect.arrayContaining([
    expect.objectContaining({ short_id: receipt.message_short_ids[0], value_text: turn.content }),
  ]));
  expect(pack.narrowing.applied.deny_all).toBe(false);
}

// OF-274/024: public pack-free behavior and reopen correctness, not a source
// layout/product-name scan or proof of twelve internal port traits. The fresh
// default init supplies no optional product pack or model endpoint. Generic
// base seeds are permitted; their inventory is not a fixed product-name list.
suite.test(test, "OPERATIONS-05", "Default seeded engine needs no product pack should work", async () => {
  const catalog = await loadFixtures();
  const data = (await catalog.readJson<OperationsCases>("operations-cases")).cases["OPERATIONS-05"];
  const packText = new TextDecoder().decode(await catalog.readArchive("operations-generic-pack"));
  const engine = await EngineFixture.start({ id: "OPERATIONS-05", profile });
  await engine.requireHttpDoor("/api/core/discover", "GET");
  await engine.requireHttpDoor("/v1/owner/packs", "GET");
  const initialPacks = (await engine.client.request<Facade.PackInstallReceipt[]>("GET", "/v1/owner/packs")).body;
  expect(initialPacks.some(pack => pack.pack_name === data.pack_name)).toBe(false);

  const first = await engine.cli.call("vault.witness", witnessInput(data.before, data.occurred_at));
  expect(first.message_short_ids).toHaveLength(1);
  // A witness receipt_ref is a structural write marker, not a gate-ledger ref.
  const recallInput = (query: string): FacadeInput<"vault.recall"> => ({ query, effort: "light", limit: 20, as_of: data.occurred_at });
  assertRecalledTurn(await engine.client.call("vault.recall", recallInput(data.before.query)), data.before, first);
  const discovered = await engine.cli.json<Discovery>(["api", "discover"]);
  expect(discovered.feature_flags.capabilities).toEqual(expect.arrayContaining(data.required_capabilities));

  const put = await engine.client.call("vault.packs.put", { files: [{ path: "PACK.md", text: packText }] });
  expect(put.outcome).toBe("installed");
  const installation = put.receipt;
  if (!installation) throw new Error("Pack install returned no public installation receipt");
  expect(installation).toEqual(expect.objectContaining({ pack_name: data.pack_name,
    kind: "capability", status: "active", predicates: [data.extension.predicate], skills: [], kinds: [] }));
  expect(installation.permissions.grants).toEqual([]);
  expect(installation.permissions.hooks).toEqual([]);
  expect(installation.permissions.organs).toEqual([]);
  const installedPacks = (await engine.client.request<Facade.PackInstallReceipt[]>("GET", "/v1/owner/packs")).body;
  expect(installedPacks.map(pack => pack.pack_name).sort()).toEqual(
    [...initialPacks.map(pack => pack.pack_name), data.pack_name].sort());

  const second = await engine.client.call("vault.witness", witnessInput(data.after, data.occurred_at + 1));
  expect(second.message_short_ids).toHaveLength(1);
  const claim = await engine.client.call("vault.claims.upsert", {
    id: data.extension.id, subject_ref: data.after.turn_ref, predicate: data.extension.predicate,
    value: data.extension.value, confidence: 1, source: "user_stated", occurred_at: data.occurred_at + 1,
  });
  expect(claim.approval).toBe("auto");
  await engine.awaitReceipt(claim.receipt_ref);
  const afterDiscovery = (await engine.client.request<Discovery>("GET", "/api/core/discover")).body;
  expect(afterDiscovery.feature_flags.capabilities).toEqual(expect.arrayContaining(data.required_capabilities));
  expect(afterDiscovery.predicate_namespaces).toContain(data.extension.predicate.split(".")[0]!);

  assertRecalledTurn(await engine.client.call("vault.recall", recallInput(data.before.query)), data.before, first);
  assertRecalledTurn(await engine.client.call("vault.recall", recallInput(data.after.query)), data.after, second);

  // Both original memory and the generic extension survive an actual reopen.
  await engine.restart();
  assertRecalledTurn(await engine.client.call("vault.recall", recallInput(data.before.query)), data.before, first);
  assertRecalledTurn(await engine.client.call("vault.recall", recallInput(data.after.query)), data.after, second);
  const extension = await engine.client.call("vault.recall", recallInput(data.extension.query));
  const recalledClaim = extension.items.find(item => item.short_id === claim.claim_short_id);
  expect(recalledClaim).toEqual(expect.objectContaining({ predicate: data.extension.predicate,
    provenance: expect.objectContaining({ source: "user_stated" }) }));
  expect(recalledClaim!.value_text).toContain(data.extension.value.color);
  expect(recalledClaim!.value_text).toContain(data.extension.value.marker);
  const persisted = await engine.client.call("vault.claims.list", {
    subject_ref: data.after.turn_ref, predicate: data.extension.predicate, limit: 10,
  });
  expect(persisted.value).toEqual([expect.objectContaining({ claim_ref: data.extension.id,
    predicate: data.extension.predicate, value: data.extension.value, source: "user_stated", approval: "auto", lifecycle: "active" })]);
  const reopenedPacks = (await engine.client.request<Facade.PackInstallReceipt[]>("GET", "/v1/owner/packs")).body;
  expect(reopenedPacks).toEqual(expect.arrayContaining([expect.objectContaining({
    pack_name: data.pack_name, content_hash: installation.content_hash, status: "active",
  })]));
});

/* OPERATIONS-06 — Surface health burst and queue recovery should work.
 * OF-520/521, ARCH-0044 #part-a/C5, ARCH-0040 #mcp-actor-ceilings.
 * G08 = C: bounded correctness only; no fleet-load target, latency or benchmark.
 *
 * Configure a low PUBLIC detection/admission row for four authorized fixture
 * intents; retain its declared bound in the scenario, without changing engine
 * defaults. Use production providers with a hold/release barrier. Inspect the
 * health question: closed answer choices bot|valid_burst, evidence/crossing,
 * ladder provenance and eventual outcome label. Existing health CheckState is
 * held | asked{question,unit} | answered{answer,probability,by,at,question,unit}.
 * A held HEALTH CHECK is not authority to refuse or hold the triggering act.
 * Admission waits are separate, fair queues, not threshold-based drops.
 *
 * While admission is held, each accepted intent has a durable public handle
 * and queued/held status, not an empty success. Release the barrier and settle
 * the verdict. Compare the authored set of four intent keys with final receipt
 * membership: exactly one outcome per accepted intent, no duplicates or loss;
 * a failed intent has a typed visible refusal/reason, never vanishes. Inspect
 * the original memory/effects rather than counting provider responses as
 * commits. No arbitrary sleeps, private drain or in-memory queue inspection.
 *
 * Main has [limits] queued permits, GET /v1/owner/wire-health and outcome
 * recording, plus typed decision-ask answers. These do not expose a typed
 * durable per-intent admission/status ledger. Call receipts arrive at wire
 * settlement; they cannot stand in for observing accepted held work. No
 * high-rate burst is used to reach production-scale default thresholds.
 */
suite.todo(test, "OPERATIONS-06",
  "waits on typed durable admission intent and queued/held status receipts — Surface health burst and queue recovery should work");

/* OPERATIONS-07 — Automatic failure report contains no real text should work.
 * OF-380/401. Canon: ARCH-0053 #r4-lifecycle, ARCH-0069 #handles,
 * ARCH-0066 #coach-proposals, and OF-380's 2026-10-16 FIX6-SCOPE ruling.
 *
 * Automatic counts have only {failure_class, agent_kind, agent@version,
 * model@version, engine@version, ts_bucket, count}. The code-fix lane exports
 * only Coach-invented note/conversation repros verified by replay and the
 * in-vault scrubber, plus fixed|not_fixed shadow-replay results. No real chat
 * or verbatim spans; training consent is independent. Private-world automatic
 * exports are COUNTS ONLY. Self-host defaults off; explicitly enable the
 * fixture's permitted automatic lane through public policy for this flow.
 *
 * Witness the synthetic private conversation, trigger the actual failure and
 * public code-fix report flow, then inspect the separate loopback automatic
 * sink. Strictly allow only the declared count/repro/result schema, and reject
 * the fixture's real private names, place, fact and complete message spans in
 * all payloads, including nested fields. Require invented provenance, replay
 * verification and scrub receipt, not a renamed/redacted transcript. Exercise
 * fixed and not_fixed independently with fixture-authored replay outcomes.
 *
 * Finally offer a distinct owner-reviewed digest. Before approval its sink
 * is empty. Approve only the displayed digest/destination/scope and send it
 * separately, once, with consent and provenance linking its exact source.
 * That explicit disclosure must never authorize automatic transcript export.
 * Do not use a quoted-note proposal to bypass the missing disclosure door.
 *
 * Main's failure-signal export is counts-only. No typed public Coach-invented
 * repro/verification or candidate-fix shadow-replay export exists. Owner
 * feedback proposal preview is deliberate feedback, not automatic reporting
 * or the typed consented-digest publisher flow. Do not pretend fixture JSON
 * uploaded by the test client is an engine-produced failure report.
 */
suite.todo(test, "OPERATIONS-07",
  "waits on typed automatic invented-repro/shadow-replay export and consented publisher digest — Automatic failure report contains no real text should work");
