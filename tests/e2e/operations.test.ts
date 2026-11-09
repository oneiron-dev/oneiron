import { afterAll, expect, test } from "bun:test";
import type { Facade, FacadeInput, FacadeResult } from "@oneiron/client";
import { PublicHttpClient, credentialParts } from "./support/clients.ts";
import { EngineFixture, awaitPublic } from "./support/engine.ts";
import { loadFixtures, ownerBaseClaimScope } from "./support/fixtures.ts";
import { ScriptedProviders, openaiText } from "./support/providers.ts";
import { defineFile, ownResource, secretHex } from "./support/run.ts";

const profile = process.env.E2E_PROFILE === "real-small-model"
  ? "real-small-model" : "deterministic";
const suite = defineFile(import.meta, { profile, slots: 1 });
afterAll(suite.flush);

type Refusal = { status: number; code: string };
/** A facade call the server must refuse: its status and code. */
async function refusal(client: PublicHttpClient, verb: string, input: unknown, headers?: HeadersInit): Promise<Refusal> {
  const reply = await client.raw<{ error: { code: string } }>("POST", `/v1/core/facade/${verb}`, input, headers);
  expect(reply.status).toBeGreaterThanOrEqual(400);
  expect(reply.status).toBeLessThan(500);
  return { status: reply.status, code: reply.body.error.code };
}
/** The owner's own slip with one harmless caveat: still the owner, no longer owner grade. */
async function caveatedOwner(engine: EngineFixture): Promise<PublicHttpClient> {
  const { seed } = credentialParts(engine.pairedActor.credential);
  const narrowed = await engine.client.call("self.credential.attenuate", {
    holder_seed: [...Buffer.from(seed, "hex")], caveat: { ttl_secs: 3600 },
  });
  const credential = `v2.cred.${narrowed.token.slice("v2.slip.".length)}.${seed}`;
  credentialParts(credential);
  return new PublicHttpClient(engine.url, { credential, artifacts: engine.artifacts });
}
const ownerOnly: Refusal = { status: 403, code: "FORBIDDEN" };

// One configured chat model behind the scripted provider, for one durable
// owner model step held at a barrier. The checker role arms no other seat.
const STEP_MODEL = "ops-chat";
const stepConfig = (endpoint: string): string => `
[models.providers.ops]
kind = "local-openai-compat"
base_url = "${endpoint}"
revision = "e2e-v1"
[models.roles.checker]
model = "ops:${STEP_MODEL}"
`;
function heldStep(id: string, barrier: string) {
  return {
    id, origin: "ops", role: "checker", purpose: "durable owner model step held for operations",
    request: { method: "POST" as const, path: "/v1/chat/completions", model: STEP_MODEL },
    barrier,
    response: openaiText(id, STEP_MODEL, "Held step answered.", { inputTokens: 16, outputTokens: 4 }),
  };
}
function stepSubmit(stepKey: string): FacadeInput<"ai.steps.submit"> {
  return {
    step_key: stepKey,
    request: {
      model: `ops/${STEP_MODEL}@e2e-v1`,
      envelope: { purpose: "answer_gen", class: { kind: "best_effort" }, tier: { global_default: "answer" },
        response_format: { format: "text" }, locality: "own_server" },
      messages: [{ role: "user", content: [{ kind: "text", text: "Hold this durable step for the operations flow." }] }],
    },
    retry: { max_attempts: 1 },
  };
}
async function startHeldProviders(id: string, barrier: string): Promise<ScriptedProviders> {
  const providers = await ScriptedProviders.start({ id, steps: [heldStep(`${id}-step`, barrier)] });
  // Released and closed at flow end; close fails on any unscripted or repeated call.
  ownResource(async () => { providers.releaseBarrier(barrier); await providers.close(); });
  return providers;
}
async function witnessedMemory(engine: EngineFixture, content: string, at: number): Promise<void> {
  const conversation = await engine.client.call("vault.conversations.create", {
    body: {}, occurred_start: at, occurred_end: at, learned_at: at,
  });
  const witnessed = await engine.client.call("vault.witness", {
    conversation_ref: conversation.id, occurred_at: at,
    messages: [{ author: "user", message_type: "text", content, is_visible: true, order: 0 }],
  });
  // The answer carries a write marker, not a gate receipt: read the message back.
  expect(witnessed.message_short_ids).toHaveLength(1);
  expect((await engine.client.call("vault.get", { entity_ref: witnessed.message_short_ids[0]! })).value).not.toBeNull();
}
async function recalls(engine: EngineFixture, query: string, content: string): Promise<void> {
  await awaitPublic(() => engine.client.call("vault.recall", { query, effort: "light", limit: 10 }),
    pack => pack.items.some(item => item.value_text.includes(content)
      || item.cited_messages?.some(message => message.value_text.includes(content))),
    { label: `recall ${query}` });
}

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
 * Main e79eb76df3e (OPUS-E2E-2, 9 Nov): self.report_blocked is now a typed
 * host facade row taking LiveRunRequest {live_run, spec:{category, detail}},
 * and vault.diagnostics.list/get and vault.coach.inspect exist. Two pieces
 * are still missing. (1) The live run: its only public setup is agents.spawn,
 * pairing the agent holder and self.run.attach while the run keeps its lease;
 * attaching while the model entry holds its barrier is not deterministic
 * (MEMORY-07's note). (2) The Coach repair proposal comes only from the
 * background Coach Issues job, with no typed trigger or completion read, so
 * the repair, healed_by trace and gate result cannot be awaited publicly.
 */
suite.todo(test, "OPERATIONS-01",
  "waits on a deterministic leased live-run attach fixture for self.report_blocked and a typed trigger or completion read for the Coach Issues repair job — Typed diagnostics and scoped Coach repair should work");

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
 * Written by OPUS-E2E-2 on main e79eb76df3e through report, vault.reports.*,
 * feedback.preview/.send and vault.receipts.get, against a loopback [feedback]
 * collector, after the owner's external:send grant on its channel (a send
 * before the grant is held). Not proved here: the tool-first MCP leg (the CLI is the second
 * surface), consent/provenance receipt reads for the approval, and an
 * unrelated publisher trying to spend it (a changed digest is tested).
 */
/* Doors: report, vault.reports.route/.disclosure/.outbound, feedback.preview,
 * feedback.send, vault.receipts.get. The publisher sink is a loopback
 * [feedback] collector; HTTP is allowed there only because it is loopback. */
interface FeedbackPost { bundleDigest: string | null; signatureDigest: string | null; body: Buffer }
function feedbackCollector(): { endpoint: string; posts: FeedbackPost[] } {
  const posts: FeedbackPost[] = [];
  const server = Bun.serve({
    hostname: "127.0.0.1", port: 0,
    fetch: async request => {
      posts.push({ bundleDigest: request.headers.get("x-oneiron-bundle-digest"),
        signatureDigest: request.headers.get("x-oneiron-signature-digest"), body: Buffer.from(await request.arrayBuffer()) });
      return new Response(null, { status: 202 });
    },
  });
  ownResource(() => server.stop(true));
  if (!server.port) throw new Error("Feedback collector bound no port");
  return { endpoint: `http://127.0.0.1:${server.port}/feedback`, posts };
}

/** Appends the owner's grant of external:send on the feedback collector
 * channel to the default policy manifest, under its body-hash check. */
async function grantFeedbackChannel(engine: EngineFixture): Promise<void> {
  const owner = engine.pairedActor.principalRef;
  const policy = await engine.client.call("vault.gate.policy.get", {});
  const view = policy.manifests.find(entry => entry.manifest_ref === policy.default_manifest_ref);
  if (!view) throw new Error("Default policy manifest is absent");
  const grant: Facade.PolicyScopedGrantRow = {
    actor_ref: owner, effector: "external:send",
    scope: { worlds: { kind: "all" }, facets: { kind: "all" }, bands: { kind: "all" }, audience: { kind: "all" },
      verbs: { kind: "some", values: ["effect"] }, sensitivity: { kind: "all" } },
    selectors: { kind: "map", value: [{ key: { kind: "string", value: "channel" },
      value: { kind: "string", value: "feedback_collector" } }] },
    receipt_required: false,
  };
  const ceilings = view.manifest.actor_ceilings.some(row => row.actor_ref === owner) ? view.manifest.actor_ceilings
    : [...view.manifest.actor_ceilings, { actor_class: "human", actor_ref: owner, ceiling: "auto" } as Facade.ActorCeiling];
  await engine.client.call("vault.gate.policy.put", {
    manifest_ref: view.manifest_ref, expected_body_hash: view.body_hash,
    manifest: { ...view.manifest, actor_ceilings: ceilings, scoped_grants: [...(view.manifest.scoped_grants ?? []), grant] },
  });
}

suite.test(test, "OPERATIONS-03", "Feedback with and without vault text should work", async () => {
  const collector = feedbackCollector();
  const engine = await EngineFixture.start({ id: "OPERATIONS-03", profile,
    serverConfig: `[feedback]\ndestination = "collector"\nendpoint = ${JSON.stringify(collector.endpoint)}\n` });
  const quotedNote = "Private: the boathouse alarm code is on the blue card behind the clock.";
  const noteBytes = Buffer.from(quotedNote);
  const bundles = () => collector.posts.filter(post => post.bundleDigest !== null);

  // A real failed call, and its lasting receipt as the report's subject.
  const failed = await engine.client.raw<{ error: { code: string; receiptRef?: string } }>(
    "POST", "/v1/core/facade/vault.get", { entity_ref: "not a ref" });
  expect(failed.status).toBe(400);
  const subject = failed.body.error.receiptRef;
  if (!subject) throw new Error("A refused facade call carried no lasting receipt");
  await engine.awaitReceipt(subject);
  expect(await engine.client.call("vault.receipts.get", { receipt_ref: subject })).toMatchObject({
    receipt_ref: subject, verb: "vault.get", actor_ref: engine.pairedActor.principalRef,
    transport: "http_facade", outcome: { refused: { code: "BAD_REQUEST" } },
  });

  // Route the subject to its publisher, then report it once with private text.
  const publisher = "operations-03-publisher";
  await engine.client.call("vault.reports.route",
    { subject_ref: subject, route: { destination: "publisher", publisher_ref: publisher } });
  const report: FacadeInput<"report"> = { subject_ref: subject, category: "execution_lapse", note: quotedNote };
  const first = await engine.client.call("report", report);
  expect(first).toMatchObject({ already_submitted: false, disclosure: "needs_approval",
    route: { destination: "publisher", publisher_ref: publisher } });
  // The same actor, subject and category through the CLI is the same issue;
  // a different note does not edit it.
  const second = await engine.cli.call("report", { ...report, note: "A second note never edits the first." });
  expect(second).toMatchObject({ issue_ref: first.issue_ref, already_submitted: true });
  await engine.restart();
  expect(await engine.client.call("report", report)).toMatchObject({ issue_ref: first.issue_ref, already_submitted: true });
  expect(await engine.client.call("vault.receipts.get", { receipt_ref: subject })).toMatchObject({ receipt_ref: subject });

  // While the text waits on disclosure the outbound projection is content-free.
  const waiting = await engine.client.call("vault.reports.outbound", { issue_ref: first.issue_ref });
  expect(waiting.payload?.signature).toMatchObject({ issue_ref: first.issue_ref, category: "execution_lapse", kind: "problem" });
  expect(waiting.payload?.disclosed).toBeNull();
  expect(JSON.stringify(waiting)).not.toContain(quotedNote);
  expect(JSON.stringify(waiting)).not.toContain(subject);

  // Until the owner's policy grants the feedback channel, an approved send is
  // held and nothing reaches the publisher.
  const ungranted = await engine.client.call("feedback.preview", { issue_ref: first.issue_ref, category: "bug" });
  const held = await engine.client.call("feedback.send", { issue_ref: first.issue_ref, category: "bug",
    digest: ungranted.digest, approval: ungranted.approval, previewed_at: ungranted.previewed_at });
  expect(held.outcome).toBe("held");
  expect(bundles()).toHaveLength(0);
  await grantFeedbackChannel(engine);

  // Metadata-only feedback: the preview shows the bytes, the send ships them once.
  const plain = await engine.client.call("feedback.preview", { issue_ref: first.issue_ref, category: "bug" });
  expect(plain).toMatchObject({ issue_ref: first.issue_ref, subject_ref: subject, publisher_ref: publisher,
    includes_text: false, destination: collector.endpoint });
  expect(JSON.stringify(plain.bundle)).not.toContain(quotedNote);
  const plainSend: FacadeInput<"feedback.send"> = { issue_ref: first.issue_ref, category: "bug",
    digest: plain.digest, approval: plain.approval, previewed_at: plain.previewed_at };
  const sent = await engine.client.call("feedback.send", plainSend);
  expect(sent).toMatchObject({ issue_ref: first.issue_ref, outcome: "delivered_to_channel", digest: plain.digest });
  expect(bundles().map(post => post.bundleDigest)).toEqual([plain.digest]);
  expect(bundles()[0]!.body.includes(noteBytes)).toBe(false);
  // The same approved send again is the same one send.
  expect((await engine.client.call("feedback.send", plainSend)).logical_send_ref).toBe(sent.logical_send_ref);
  expect(bundles()).toHaveLength(1);

  // The quoted note needs its own disclosure: before approval it never leaves.
  const textPreview = await engine.client.call("feedback.preview",
    { issue_ref: first.issue_ref, category: "bug", include_text: true });
  expect(textPreview).toMatchObject({ includes_text: true, disclosure: "needs_approval" });
  const textSend = (preview: typeof textPreview): FacadeInput<"feedback.send"> => ({ issue_ref: first.issue_ref,
    category: "bug", include_text: true, digest: preview.digest, approval: preview.approval, previewed_at: preview.previewed_at });
  const badRequest: Refusal = { status: 400, code: "BAD_REQUEST" };
  expect(await refusal(engine.client, "feedback.send", textSend(textPreview))).toEqual(badRequest);
  expect(bundles()).toHaveLength(1);

  // Approve once: the shown bytes leave once, carrying the original note.
  const decided = await engine.client.call("vault.reports.disclosure", { issue_ref: first.issue_ref, choice: "approve_once" });
  expect(decided.disclosure).toBe("approved");
  expect(decided.request.note).toBe(quotedNote);
  expect((await engine.client.call("vault.reports.outbound", { issue_ref: first.issue_ref })).payload?.disclosed?.note)
    .toBe(quotedNote);
  const shown = await engine.client.call("feedback.preview", { issue_ref: first.issue_ref, category: "bug", include_text: true });
  expect(shown).toMatchObject({ includes_text: true, disclosure: "approved" });
  expect(JSON.stringify(shown.bundle)).toContain(quotedNote);
  // A send naming bytes other than those shown cannot spend the approval.
  expect(await refusal(engine.client, "feedback.send", { ...textSend(shown), digest: plain.digest })).toEqual(badRequest);
  const textSent = await engine.client.call("feedback.send", textSend(shown));
  expect(textSent.outcome).toBe("delivered_to_channel");
  expect(bundles().map(post => post.bundleDigest)).toEqual([plain.digest, shown.digest]);
  expect(bundles()[1]!.body.includes(noteBytes)).toBe(true);
  // Automatic signatures, if any were sent, stay text-free.
  for (const post of collector.posts.filter(post => post.signatureDigest !== null)) {
    expect(post.body.includes(noteBytes)).toBe(false);
  }

  // Only the owner previews, discloses or sends.
  const caveated = await caveatedOwner(engine);
  expect(await refusal(caveated, "feedback.preview", { issue_ref: first.issue_ref, category: "bug" })).toEqual(ownerOnly);
  expect(await refusal(caveated, "vault.reports.disclosure", { issue_ref: first.issue_ref, choice: "deny" })).toEqual(ownerOnly);
  expect(await refusal(caveated, "feedback.send", plainSend)).toEqual(ownerOnly);
  expect(bundles()).toHaveLength(2);
});

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
 * Written by OPUS-E2E-2 on main e79eb76df3e through vault.slim.* and
 * ai.steps.submit/.receipt. The paused work is the owner's durable model
 * step, the one outbound step SLIM keeps; no public door gives an agent task
 * a deterministic SLIM-held step. Not proved here: an agent session and its
 * call refs across SLIM. RETRIEVAL-08 holds the graph-parity side.
 */
/* Doors: vault.slim.policy, .state, .drop_heavy, .resume_step, .resume, with
 * ai.steps.submit and ai.steps.receipt for the held durable model step.
 * RETRIEVAL-08 proves graph parity across SLIM; this case proves the paused
 * step and the memory survive a restart and nothing is repeated. */
suite.test(test, "OPERATIONS-04", "Paused agent resumes from SLIM should work", async () => {
  const barrier = "operations-04-held";
  const providers = await startHeldProviders("operations-04", barrier);
  const engine = await EngineFixture.start({ id: "OPERATIONS-04", profile, serverConfig: stepConfig(providers.urls.ops!) });
  const policy = await engine.client.call("vault.slim.policy", {});
  expect(policy.exits_on_idle).toBe(false);
  expect(policy.lazy_rebuild).toBe(true);
  expect(policy.long_outbound_wait_secs).toBeGreaterThan(0);
  // With nothing outbound pending, a shed is refused, not queued.
  const idle = await engine.client.call("vault.slim.drop_heavy", { cause: "memory_pressure", waited_secs: 1 });
  expect(idle.outcome).toEqual({ status: "refused", blocker: { kind: "no_pending_outbound_step" } });

  const at = Date.parse("2026-10-01T09:00:00Z") / 1000;
  const content = "operations04lantern: the night ferry keeps its logbook in the wheelhouse drawer.";
  await witnessedMemory(engine, content, at);
  await recalls(engine, "operations04lantern wheelhouse logbook", content);
  const before = await engine.client.call("vault.slim.state", {});
  expect(before.state).toEqual({ residency: "full" });

  // The agent's durable model step waits on its provider: the one outbound step SLIM keeps.
  const submit = stepSubmit("operations-04-slim-step");
  const pending = engine.client.call("ai.steps.submit", submit);
  void pending.catch(() => {}); // Awaited and asserted after the barrier is released.
  await providers.awaitBarrier(barrier);
  const started = Date.now();
  await awaitPublic(async () => Date.now() - started, elapsed => elapsed >= 1000, { label: "observed held wait" });
  const waited = Math.floor((Date.now() - started) / 1000);
  const dropped = await engine.client.call("vault.slim.drop_heavy", { cause: "long_outbound_wait", waited_secs: waited });
  expect(dropped.process_id).toBe(before.process_id);
  if (dropped.outcome.status !== "entered") throw new Error(`Expected SLIM entry, got ${dropped.outcome.status}`);
  const slim = await engine.client.call("vault.slim.state", {});
  expect(slim.process_id).toBe(before.process_id);
  if (slim.state.residency !== "slim") throw new Error("Expected the vault in SLIM");
  const step = slim.state.residue.step;
  if (step.kind !== "model") throw new Error("Expected the held model step as the SLIM residue");
  // The same live server still answers health while SLIM.
  expect((await engine.client.raw("GET", "/api/health")).status).toBe(200);
  const saved = await engine.client.call("vault.slim.resume_step",
    { kind: "model", attempt_id: step.attempt_id, step_hash: step.step_hash });
  expect(saved).toMatchObject({ kind: "model", attempt_id: step.attempt_id, checkpoint: { progression: "started" } });
  const resumed = await engine.client.call("vault.slim.resume", {});
  expect(resumed.process_id).toBe(before.process_id);
  expect(resumed.outcome.status).toBe("resumed");
  expect((await engine.client.call("vault.slim.resume", {})).outcome).toEqual({ status: "already_full" });
  await recalls(engine, "operations04lantern wheelhouse logbook", content);

  // The provider answers once; the step finishes once.
  expect(providers.seenFixtureCalls).toHaveLength(1);
  providers.releaseBarrier(barrier);
  const delivered = await pending;
  expect(delivered).toMatchObject({ step_ref: step.attempt_id, step_hash: step.step_hash, result: { status: "finished" } });

  // After a restart the session, its result and the memory are the same,
  // and submitting the step again resumes it without a second model call.
  await engine.restart();
  const afterRestart = await engine.client.call("vault.slim.state", {});
  expect(afterRestart.state).toEqual({ residency: "full" });
  expect(afterRestart.process_id === before.process_id).toBe(false);
  expect(await engine.client.call("ai.steps.receipt", { step_key: submit.step_key }))
    .toMatchObject({ step_ref: delivered.step_ref, step_hash: delivered.step_hash, result: { status: "finished" } });
  expect(await engine.client.call("ai.steps.submit", submit))
    .toMatchObject({ step_ref: delivered.step_ref, step_hash: delivered.step_hash, result: { status: "finished" } });
  expect(providers.seenFixtureCalls).toHaveLength(1);
  await recalls(engine, "operations04lantern wheelhouse logbook", content);

  // Only the owner sheds, reads or resumes residency.
  const caveated = await caveatedOwner(engine);
  expect(await refusal(caveated, "vault.slim.drop_heavy", { cause: "memory_pressure", waited_secs: 1 })).toEqual(ownerOnly);
  expect(await refusal(caveated, "vault.slim.state", {})).toEqual(ownerOnly);
});

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
  feature_flags: { groups: Record<string, { count: number; capabilities: string[] }> };
  predicate_namespaces: string[];
}
/** Discovery groups its capability tokens by family; this is every token. */
const capabilities = (discovery: Discovery): string[] =>
  Object.values(discovery.feature_flags.groups).flatMap(group => group.capabilities);
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
  expect(capabilities(discovered)).toEqual(expect.arrayContaining(data.required_capabilities));

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
    scope: await ownerBaseClaimScope(engine.client, engine.pairedActor.principalRef),
    id: data.extension.id, subject_ref: data.after.turn_ref, predicate: data.extension.predicate,
    value: data.extension.value, confidence: 1, source: "user_stated", occurred_at: data.occurred_at + 1,
  });
  expect(claim.approval).toBe("auto");
  await engine.awaitReceipt(claim.receipt_ref);
  const afterDiscovery = (await engine.client.request<Discovery>("GET", "/api/core/discover")).body;
  expect(capabilities(afterDiscovery)).toEqual(expect.arrayContaining(data.required_capabilities));
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
 * Written by OPUS-E2E-2 on main e79eb76df3e: self.admission.status and
 * self.admission.receipts are the durable per-intent ledger, keyed by the
 * caller's own x-oneiron-invocation. Not proved here: the health question
 * itself (bot|valid_burst, no typed read) and fair-queue ordering under
 * contention (queued is timing-dependent). No high-rate burst is used.
 */
/* Doors: vault.wire_health.thresholds.get/.set, self.admission.status and
 * self.admission.receipts. Each intent is a caller-owned x-oneiron-invocation;
 * its durable admission receipt is the public handle. A held model step,
 * then a kill, gives the restart an intent it must report, not drop. */
suite.test(test, "OPERATIONS-06", "Surface health burst and queue recovery should work", async () => {
  const barrier = "operations-06-held";
  const providers = await startHeldProviders("operations-06", barrier);
  const engine = await EngineFixture.start({ id: "OPERATIONS-06", profile, serverConfig: stepConfig(providers.urls.ops!) });

  // A deliberately low detection row: crossings ask health questions, never refuse.
  const defaults = await engine.client.call("vault.wire_health.thresholds.get", {});
  const low = { window_secs: 60, per_verb: 1, per_actor: 1 };
  const installed = await engine.client.call("vault.wire_health.thresholds.set", low);
  expect(installed).toEqual({ previous: defaults, thresholds: low });
  expect(await engine.client.call("vault.wire_health.thresholds.get", {})).toEqual(low);
  expect(await refusal(engine.client, "vault.wire_health.thresholds.set", { ...low, per_verb: 0 }))
    .toEqual({ status: 400, code: "BAD_REQUEST" });

  // Four authored intents, each under its own invocation id.
  const intent = { put: secretHex(16), refused: secretHex(16), held: secretHex(16), read: secretHex(16) };
  const invoke = (verb: string, input: unknown, key: string) =>
    engine.client.raw<{ error?: { code: string } }>("POST", `/v1/core/facade/${verb}`, input, { "x-oneiron-invocation": key });
  const address = { namespace: ["operations-06"], key: "burst" };
  const accepted = { text: "accepted once" };
  // The owner states the value; an unsourced keyed write would wait on review.
  const put = { ...address, value: accepted, request_id: "operations-06-put", source: "user_stated" };
  expect((await invoke("vault.kv.put", put, intent.put)).status).toBe(200);
  expect((await invoke("vault.get", { entity_ref: "not a ref" }, intent.refused)).status).toBe(400);
  const held = invoke("ai.steps.submit", stepSubmit("operations-06-held-step"), intent.held);
  void held.catch(() => {}); // The server is killed under it below.
  await providers.awaitBarrier(barrier);
  expect((await invoke("vault.kv.get", address, intent.read)).status).toBe(200);
  // A retried intent replays its first answer; it is not a second write.
  expect((await invoke("vault.kv.put", put, intent.put)).status).toBe(200);

  const status = async (key: string) => (await engine.client.call("self.admission.status", { intent_key: key }))?.state;
  expect(await status(intent.put)).toMatchObject({ status: "completed" });
  expect(await status(intent.refused)).toMatchObject({ status: "refused", code: "BAD_REQUEST" });
  expect(await status(intent.held)).toEqual({ status: "held", reason: null });
  expect(await status(intent.read)).toMatchObject({ status: "completed" });
  expect(await engine.client.call("self.admission.status", { intent_key: secretHex(16) })).toBeNull();
  const authored = [intent.put, intent.refused, intent.held, intent.read];
  const reconcile = () => engine.client.call("self.admission.receipts",
    { intent_keys: [...authored, intent.put, secretHex(16)] });
  const live = await reconcile();
  expect(live.map(row => row.intent_key)).toEqual(authored);
  const putDigest = (live[0]!.state as { result_digest?: string }).result_digest;

  // The host dies with the model step in flight. After restart that intent
  // is reported interrupted; every other outcome stands; nothing replays it.
  await engine.kill();
  // Its requester is dead: let the scripted provider finish its held answer
  // while the fixture is still open, then restart.
  providers.releaseBarrier(barrier);
  await engine.restart();
  const recovered = await reconcile();
  expect(recovered.map(row => row.intent_key)).toEqual(authored);
  expect(recovered.map(row => row.state.status)).toEqual(["completed", "refused", "interrupted", "completed"]);
  expect((recovered[0]!.state as { result_digest?: string }).result_digest).toBe(putDigest);
  expect(recovered[2]).toMatchObject({ verb: "ai.steps.submit" });
  expect((recovered[2]!.state as { reason?: string }).reason).toMatch(/^host restarted before settlement was observed/);
  expect((await engine.client.call("vault.kv.get", address))?.value).toEqual(accepted);
  expect(await engine.client.call("vault.wire_health.thresholds.get", {})).toEqual(low);
  expect(providers.seenFixtureCalls).toHaveLength(1);
  // Malformed keys and an empty set are refused.
  const badRequest: Refusal = { status: 400, code: "BAD_REQUEST" };
  expect(await refusal(engine.client, "self.admission.status", { intent_key: "not-an-invocation" })).toEqual(badRequest);
  expect(await refusal(engine.client, "self.admission.receipts", { intent_keys: [] })).toEqual(badRequest);
  // Only the owner sets thresholds.
  expect(await refusal(await caveatedOwner(engine), "vault.wire_health.thresholds.set", low)).toEqual(ownerOnly);
});

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
